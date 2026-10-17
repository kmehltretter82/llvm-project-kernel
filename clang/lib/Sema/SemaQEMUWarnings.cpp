//===- SemaQEMUWarnings.cpp - QEMU semantic diagnostics ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements opt-in diagnostics for QEMU execution-context and
// Error API contracts.
//
//===----------------------------------------------------------------------===//

#include "SemaQEMUWarnings.h"
#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DynamicRecursiveASTVisitor.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Stmt.h"
#include "clang/Analysis/Analyses/UninitializedValues.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Analysis/CFG.h"
#include "clang/Analysis/CFGBackEdges.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/DiagnosticSema.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/Sema/Sema.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSwitch.h"
#include <algorithm>
#include <cstdint>
#include <deque>

using namespace clang;

namespace {

static bool hasQEMUAnnotation(const Decl *D, StringRef Annotation) {
  if (!D)
    return false;
  for (const auto *A : D->specific_attrs<AnnotateAttr>())
    if (A->getAnnotation() == Annotation)
      return true;
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return false;
  const FunctionDecl *Canonical = FD->getCanonicalDecl();
  for (const FunctionDecl *Redecl : Canonical->redecls())
    for (const auto *A : Redecl->specific_attrs<AnnotateAttr>())
      if (A->getAnnotation() == Annotation)
        return true;
  return false;
}

static bool isNamedTypedef(QualType Type, StringRef Name) {
  while (!Type.isNull()) {
    if (const auto *TT = dyn_cast<TypedefType>(Type.getTypePtr())) {
      if (TT->getDecl()->getName() == Name)
        return true;
      Type = TT->desugar();
      continue;
    }
    if (const auto *AT = dyn_cast<AttributedType>(Type.getTypePtr())) {
      Type = AT->getModifiedType();
      continue;
    }
    return false;
  }
  return false;
}

enum class QEMUDiscardKind { Used, Implicit, Explicit };

static bool isTransparentResultWrapper(const Expr *E) {
  return isa<ParenExpr, ImplicitCastExpr, ExprWithCleanups,
             CXXBindTemporaryExpr, MaterializeTemporaryExpr, ConstantExpr,
             StmtExpr>(E);
}

/// Determine whether a call's value is discarded as a statement.  An explicit
/// cast to void is a deliberate suppression; an unadorned expression statement
/// is not.  Keep result propagation through parentheses, conditional operators,
/// comma operators, and GNU statement expressions precise enough for QEMU's C
/// idioms rather than warning merely because a call appears somewhere inside a
/// discarded expression.
static QEMUDiscardKind getQEMUDiscardKind(ArrayRef<const Stmt *> Ancestors,
                                          const CallExpr *Call) {
  if (Ancestors.empty() || Ancestors.back() != Call)
    return QEMUDiscardKind::Used;

  const Stmt *Current = Call;
  for (size_t Index = Ancestors.size() - 1; Index != 0;) {
    const Stmt *Parent = Ancestors[--Index];

    if (const auto *ECE = dyn_cast<ExplicitCastExpr>(Parent)) {
      if (ECE->getSubExpr() == Current && ECE->getTypeAsWritten()->isVoidType())
        return QEMUDiscardKind::Explicit;
      return QEMUDiscardKind::Used;
    }

    if (const auto *E = dyn_cast<Expr>(Parent)) {
      if (isTransparentResultWrapper(E)) {
        Current = Parent;
        continue;
      }
      if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
        if (BO->getOpcode() != BO_Comma)
          return QEMUDiscardKind::Used;
        if (BO->getLHS() == Current)
          return QEMUDiscardKind::Implicit;
        if (BO->getRHS() == Current) {
          Current = Parent;
          continue;
        }
        return QEMUDiscardKind::Used;
      }
      if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
        if (CO->getCond() == Current)
          return QEMUDiscardKind::Used;
        if (CO->getTrueExpr() == Current || CO->getFalseExpr() == Current) {
          Current = Parent;
          continue;
        }
        return QEMUDiscardKind::Used;
      }
      if (const auto *BCO = dyn_cast<BinaryConditionalOperator>(E)) {
        if (BCO->getFalseExpr() == Current) {
          Current = Parent;
          continue;
        }
        return QEMUDiscardKind::Used;
      }
      return QEMUDiscardKind::Used;
    }

    if (const auto *CS = dyn_cast<CompoundStmt>(Parent)) {
      if (Index != 0 && isa<StmtExpr>(Ancestors[Index - 1]) &&
          !CS->body_empty() && CS->body_back() == Current) {
        Current = CS;
        continue;
      }
      return QEMUDiscardKind::Implicit;
    }

    if (isa<LabelStmt, AttributedStmt>(Parent)) {
      Current = Parent;
      continue;
    }

    if (const auto *IS = dyn_cast<IfStmt>(Parent))
      return IS->getCond() == Current ? QEMUDiscardKind::Used
                                      : QEMUDiscardKind::Implicit;
    if (const auto *WS = dyn_cast<WhileStmt>(Parent))
      return WS->getCond() == Current ? QEMUDiscardKind::Used
                                      : QEMUDiscardKind::Implicit;
    if (const auto *DS = dyn_cast<DoStmt>(Parent))
      return DS->getCond() == Current ? QEMUDiscardKind::Used
                                      : QEMUDiscardKind::Implicit;
    if (const auto *SS = dyn_cast<SwitchStmt>(Parent))
      return SS->getCond() == Current ? QEMUDiscardKind::Used
                                      : QEMUDiscardKind::Implicit;
    if (const auto *FS = dyn_cast<ForStmt>(Parent))
      return FS->getCond() == Current ? QEMUDiscardKind::Used
                                      : QEMUDiscardKind::Implicit;

    return QEMUDiscardKind::Used;
  }
  return QEMUDiscardKind::Used;
}

static bool hasQEMUOutputContract(const FunctionDecl *FD) {
  if (!FD)
    return false;
  const FunctionDecl *Canonical = FD->getCanonicalDecl();
  for (const FunctionDecl *Redecl : Canonical->redecls())
    for (const ParmVarDecl *P : Redecl->parameters())
      if (hasQEMUAnnotation(P, "qemu::output_on_success"))
        return true;
  return false;
}

static bool qemuArgumentAddressesVariable(const Expr *E, const VarDecl *VD) {
  if (!E || !VD)
    return false;
  E = E->IgnoreParenImpCasts();
  const auto *UO = dyn_cast<UnaryOperator>(E);
  if (!UO || UO->getOpcode() != UO_AddrOf)
    return false;
  E = UO->getSubExpr()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  return DRE && DRE->getDecl() == VD;
}

static bool qemuArgumentMatches(const CallExpr *Call, const VarDecl *VD,
                                unsigned Index) {
  return Index < Call->getNumArgs() &&
         qemuArgumentAddressesVariable(Call->getArg(Index), VD);
}

static bool qemuAnnotatedOutputArgument(const FunctionDecl *FD,
                                        const CallExpr *Call,
                                        const VarDecl *VD) {
  if (!FD)
    return false;
  for (const FunctionDecl *Redecl : FD->getCanonicalDecl()->redecls()) {
    unsigned Count = std::min(Redecl->getNumParams(), Call->getNumArgs());
    for (unsigned I = 0; I != Count; ++I)
      if (hasQEMUAnnotation(Redecl->getParamDecl(I),
                            "qemu::output_on_success") &&
          qemuArgumentMatches(Call, VD, I))
        return true;
  }
  return false;
}

static bool qemuMacroStackContains(Sema &S, SourceLocation Loc,
                                   StringRef Prefix) {
  SourceManager &SM = S.getSourceManager();
  while (Loc.isMacroID()) {
    StringRef Name = Lexer::getImmediateMacroName(Loc, SM, S.getLangOpts());
    if (Name.starts_with(Prefix))
      return true;
    Loc = SM.getImmediateMacroCallerLoc(Loc);
  }
  return false;
}

static bool isQEMUBuiltinMustCheck(const FunctionDecl *FD) {
  if (!FD || !FD->getIdentifier())
    return false;
  return llvm::StringSwitch<bool>(FD->getName())
      .Cases({"qemu_strtoi", "qemu_strtoui", "qemu_strtol", "qemu_strtoul",
              "qemu_strtoi64", "qemu_strtou64", "qemu_strtod",
              "qemu_strtod_finite", "qemu_strtosz", "qemu_strtosz_MiB",
              "qemu_strtosz_metric", "parse_uint", "parse_uint_full"},
             true)
      .Default(false);
}

static const ParmVarDecl *getDirectParameter(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    return dyn_cast<ParmVarDecl>(DRE->getDecl());
  return nullptr;
}

static const ParmVarDecl *getDereferencedParameter(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  const auto *UO = dyn_cast<UnaryOperator>(E);
  if (!UO || UO->getOpcode() != UO_Deref)
    return nullptr;
  return getDirectParameter(UO->getSubExpr());
}

static bool isQEMUErrorDoublePointer(QualType Type) {
  if (!Type->isPointerType())
    return false;
  QualType Pointee = Type->getPointeeType();
  if (!Pointee->isPointerType())
    return false;
  QualType ErrorType = Pointee->getPointeeType().getCanonicalType();
  const auto *RT = ErrorType->getAs<RecordType>();
  return RT && RT->getDecl()->getName() == "Error";
}

static bool isQEMUErrorPointer(QualType Type) {
  if (!Type->isPointerType())
    return false;
  QualType ErrorType = Type->getPointeeType().getCanonicalType();
  const auto *RT = ErrorType->getAs<RecordType>();
  return RT && RT->getDecl()->getName() == "Error";
}

static bool isQEMUErrorImplementationFunction(const FunctionDecl *FD) {
  if (!FD || !FD->getIdentifier())
    return false;
  return llvm::StringSwitch<bool>(FD->getName())
      .Cases({"error_handle", "error_setv", "error_set_internal",
              "error_setg_internal", "error_setg_errno_internal",
              "error_setg_win32_internal", "error_setg_file_open_internal",
              "error_vprepend", "error_prepend", "error_append_hint",
              "error_free_or_abort"},
             true)
      .Default(false);
}

static bool isOptionalQEMUErrorParameter(const ParmVarDecl *P) {
  // QEMU's documented optional Error ** convention applies to the conventional
  // public parameter name `errp`.  Other Error ** parameters (for example
  // local_err, reasonp, and internal plumbing) often have different contracts.
  return P && P->getName() == "errp" && isQEMUErrorDoublePointer(P->getType());
}

class QEMUGuardFinder : public DynamicRecursiveASTVisitor {
public:
  bool Found = false;

  bool VisitVarDecl(VarDecl *VD) override {
    // ERRP_GUARD() deliberately gives this helper a reserved fixed name.
    if (VD->getName() == "_auto_errp_prop")
      Found = true;
    return !Found;
  }
};

class QEMUWarningsVisitor : public DynamicRecursiveASTVisitor {
  Sema &S;
  const FunctionDecl *CurrentFunction;
  llvm::SmallPtrSet<const ParmVarDecl *, 2> ErrorParameters;
  llvm::SmallVector<const Stmt *, 32> Ancestors;
  bool HasErrpGuard = false;

  bool isErrorParameter(const ParmVarDecl *P) const {
    return P && ErrorParameters.contains(P);
  }

  void noteContext(const FunctionDecl *FD, bool Coroutine) {
    S.Diag(FD->getLocation(), diag::note_qemu_context_annotation)
        << FD << (Coroutine ? 0 : 1);
  }

public:
  QEMUWarningsVisitor(Sema &S, const FunctionDecl *FD)
      : S(S), CurrentFunction(FD) {
    if (!isQEMUErrorImplementationFunction(FD))
      for (const ParmVarDecl *P : FD->parameters())
        if (isOptionalQEMUErrorParameter(P))
          ErrorParameters.insert(P);
    QEMUGuardFinder Finder;
    Finder.TraverseStmt(FD->getBody());
    HasErrpGuard = Finder.Found;
  }

  bool dataTraverseStmtPre(Stmt *St) override {
    Ancestors.push_back(St);
    return true;
  }

  bool dataTraverseStmtPost(Stmt *St) override {
    assert(!Ancestors.empty() && Ancestors.back() == St);
    Ancestors.pop_back();
    return true;
  }

  bool VisitCallExpr(CallExpr *Call) override {
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee)
      return true;

    QEMUDiscardKind Discard = QEMUDiscardKind::Used;
    const DiagnosticsEngine &Diags = S.getDiagnostics();
    bool CheckResults = !Diags.isIgnored(
        diag::warn_qemu_required_result_discarded, Call->getExprLoc());
    bool CheckMemTx = !Diags.isIgnored(diag::warn_qemu_memtx_result_discarded,
                                       Call->getExprLoc());
    if (CheckResults || CheckMemTx)
      Discard = getQEMUDiscardKind(Ancestors, Call);
    if (Discard == QEMUDiscardKind::Implicit) {
      if (CheckMemTx && isNamedTypedef(Call->getType(), "MemTxResult"))
        S.Diag(Call->getExprLoc(), diag::warn_qemu_memtx_result_discarded)
            << Callee;
      else if (CheckResults &&
               (hasQEMUAnnotation(Callee, "qemu::result_must_be_checked") ||
                hasQEMUOutputContract(Callee) ||
                isQEMUBuiltinMustCheck(Callee)))
        S.Diag(Call->getExprLoc(), diag::warn_qemu_required_result_discarded)
            << Callee;
    }

    bool CallerCoroutine = hasQEMUAnnotation(CurrentFunction, "coroutine_fn");
    bool CallerNoCoroutine =
        hasQEMUAnnotation(CurrentFunction, "no_coroutine_fn");
    bool CallerMixed = hasQEMUAnnotation(CurrentFunction, "coroutine_mixed_fn");
    bool CalleeCoroutine = hasQEMUAnnotation(Callee, "coroutine_fn");
    bool CalleeNoCoroutine = hasQEMUAnnotation(Callee, "no_coroutine_fn");
    bool CalleeMixed = hasQEMUAnnotation(Callee, "coroutine_mixed_fn");

    if (CalleeCoroutine && !CalleeMixed && !CallerCoroutine && !CallerMixed) {
      unsigned CallerKind = CallerNoCoroutine ? 1 : 0;
      S.Diag(Call->getExprLoc(), diag::warn_qemu_noncoroutine_call)
          << CallerKind << CurrentFunction << Callee;
      noteContext(Callee, true);
    }
    if (CallerCoroutine && CalleeNoCoroutine && !CalleeMixed) {
      S.Diag(Call->getExprLoc(), diag::warn_qemu_coroutine_calls_no_coroutine)
          << CurrentFunction << Callee;
      noteContext(Callee, false);
    }

    if (!HasErrpGuard && Call->getNumArgs()) {
      StringRef Name = Callee->getName();
      bool NeedsGuard =
          llvm::StringSwitch<bool>(Name)
              .Cases({"error_prepend", "error_vprepend", "error_append_hint"},
                     true)
              .Default(false);
      const ParmVarDecl *P = getDirectParameter(Call->getArg(0));
      if (NeedsGuard && isErrorParameter(P)) {
        S.Diag(Call->getExprLoc(), diag::warn_qemu_errp_helper_without_guard)
            << Name << P;
        S.Diag(P->getLocation(), diag::note_qemu_error_parameter_here);
      }
    }
    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *UO) override {
    if (HasErrpGuard || UO->getOpcode() != UO_Deref)
      return true;
    const ParmVarDecl *P = getDirectParameter(UO->getSubExpr());
    if (!isErrorParameter(P))
      return true;
    S.Diag(UO->getOperatorLoc(), diag::warn_qemu_errp_dereference_without_guard)
        << P;
    S.Diag(P->getLocation(), diag::note_qemu_error_parameter_here);
    return true;
  }
};

class QEMUErrorSuccessChecker {
  Sema &S;
  const CFG &Cfg;
  ASTContext &Ctx;
  llvm::SmallPtrSet<const ParmVarDecl *, 2> ErrorParameters;
  llvm::SmallPtrSet<const ReturnStmt *, 8> Reported;

  enum class ReturnContract {
    None,
    TrueOnSuccess,
    FalseOnSuccess,
    NonnegativeOnSuccess,
    ZeroOnSuccess,
    NonnullOnSuccess,
  } Contract = ReturnContract::None;

  enum StateBits : uint8_t { Unreached = 0, NoError = 1, ErrorSet = 2 };

  struct State {
    uint8_t Bits = Unreached;
    const CallExpr *Origin = nullptr;
  };

  bool isErrorParameter(const ParmVarDecl *P) const {
    return P && ErrorParameters.contains(P);
  }

  const ParmVarDecl *setterParameter(const CallExpr *Call) const {
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee || !Callee->getIdentifier() || !Call->getNumArgs())
      return nullptr;
    bool Sets =
        llvm::StringSwitch<bool>(Callee->getName())
            .Cases({"error_set_internal", "error_setg_internal",
                    "error_setg_errno_internal", "error_setg_win32_internal",
                    "error_setg_file_open_internal"},
                   true)
            .Default(false);
    if (!Sets)
      return nullptr;
    const ParmVarDecl *P = getDirectParameter(Call->getArg(0));
    return isErrorParameter(P) ? P : nullptr;
  }

  const ParmVarDecl *clearedParameter(const BinaryOperator *BO) const {
    if (!BO->isAssignmentOp() || BO->getOpcode() != BO_Assign)
      return nullptr;
    const ParmVarDecl *P = getDereferencedParameter(BO->getLHS());
    const Expr *Value = BO->getRHS();
    bool IsNull =
        Value->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNotNull);
    // QEMU's NULL definitions and explicit cleanup commonly use a casted
    // integer zero.  An explicit non-void pointer cast is not classified as a
    // null pointer constant by isNullPointerConstant(), so inspect its operand.
    if (!IsNull)
      if (const auto *Cast = dyn_cast<CastExpr>(Value->IgnoreParens()))
        if (std::optional<llvm::APSInt> Constant =
                Cast->getSubExpr()->getIntegerConstantExpr(Ctx))
          IsNull = Constant->isZero();
    if (!isErrorParameter(P) || !IsNull)
      return nullptr;
    return P;
  }

  bool isKnownSuccess(const ReturnStmt *RS) const {
    const Expr *Value = RS->getRetValue();
    if (!Value || Value->isValueDependent())
      return false;
    if (Contract == ReturnContract::NonnullOnSuccess) {
      Value = Value->IgnoreParenImpCasts();
      return isa<StringLiteral>(Value) ||
             (isa<UnaryOperator>(Value) &&
              cast<UnaryOperator>(Value)->getOpcode() == UO_AddrOf);
    }
    std::optional<llvm::APSInt> Constant = Value->getIntegerConstantExpr(Ctx);
    if (!Constant)
      return false;
    switch (Contract) {
    case ReturnContract::TrueOnSuccess:
      return !Constant->isZero();
    case ReturnContract::FalseOnSuccess:
    case ReturnContract::ZeroOnSuccess:
      return Constant->isZero();
    case ReturnContract::NonnegativeOnSuccess:
      return !Constant->isNegative();
    case ReturnContract::None:
    case ReturnContract::NonnullOnSuccess:
      return false;
    }
    llvm_unreachable("unknown QEMU return contract");
  }

  void transfer(const Stmt *St, State &Current) {
    if (const auto *Call = dyn_cast<CallExpr>(St)) {
      if (setterParameter(Call)) {
        Current.Bits = ErrorSet;
        Current.Origin = Call;
      }
      return;
    }
    if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
      if (clearedParameter(BO)) {
        Current.Bits = NoError;
        Current.Origin = nullptr;
      }
      return;
    }
    const auto *RS = dyn_cast<ReturnStmt>(St);
    if (!RS || !(Current.Bits & ErrorSet) || !isKnownSuccess(RS) ||
        !Reported.insert(RS).second)
      return;
    const ParmVarDecl *P = nullptr;
    if (Current.Origin)
      P = setterParameter(Current.Origin);
    if (!P)
      return;
    S.Diag(RS->getReturnLoc(), diag::warn_qemu_success_after_error_set) << P;
    S.Diag(Current.Origin->getExprLoc(), diag::note_qemu_error_set_here);
  }

  static bool merge(State &Destination, const State &Source) {
    uint8_t OldBits = Destination.Bits;
    Destination.Bits |= Source.Bits;
    if (!Destination.Origin && (Source.Bits & ErrorSet))
      Destination.Origin = Source.Origin;
    return OldBits != Destination.Bits;
  }

public:
  QEMUErrorSuccessChecker(Sema &S, const FunctionDecl *FD, const CFG &Cfg)
      : S(S), Cfg(Cfg), Ctx(S.Context) {
    if (!isQEMUErrorImplementationFunction(FD))
      for (const ParmVarDecl *P : FD->parameters())
        if (isOptionalQEMUErrorParameter(P))
          ErrorParameters.insert(P);

    if (hasQEMUAnnotation(FD, "qemu::returns_true_on_success"))
      Contract = ReturnContract::TrueOnSuccess;
    else if (hasQEMUAnnotation(FD, "qemu::returns_false_on_success"))
      Contract = ReturnContract::FalseOnSuccess;
    else if (hasQEMUAnnotation(FD, "qemu::returns_nonnegative_on_success"))
      Contract = ReturnContract::NonnegativeOnSuccess;
    else if (hasQEMUAnnotation(FD, "qemu::returns_zero_on_success"))
      Contract = ReturnContract::ZeroOnSuccess;
    else if (hasQEMUAnnotation(FD, "qemu::returns_nonnull_on_success"))
      Contract = ReturnContract::NonnullOnSuccess;
  }

  void run() {
    if (ErrorParameters.empty() || Contract == ReturnContract::None)
      return;

    llvm::SmallVector<State, 32> In(Cfg.getNumBlockIDs());
    std::deque<const CFGBlock *> Worklist;
    In[Cfg.getEntry().getBlockID()].Bits = NoError;
    Worklist.push_back(&Cfg.getEntry());

    while (!Worklist.empty()) {
      const CFGBlock *Block = Worklist.front();
      Worklist.pop_front();
      State Current = In[Block->getBlockID()];
      for (const CFGElement &Element : *Block)
        if (auto CS = Element.getAs<CFGStmt>())
          transfer(CS->getStmt(), Current);

      for (CFGBlock::const_succ_iterator I = Block->succ_begin(),
                                         E = Block->succ_end();
           I != E; ++I) {
        const CFGBlock *Successor = I->getReachableBlock();
        if (!Successor)
          continue;
        if (merge(In[Successor->getBlockID()], Current))
          Worklist.push_back(Successor);
      }
    }
  }
};

class QEMUErrorVariableFinder : public DynamicRecursiveASTVisitor {
  llvm::SmallPtrSetImpl<const VarDecl *> &Variables;
  llvm::SmallPtrSetImpl<const DeclRefExpr *> &AssignmentTargets;

public:
  explicit QEMUErrorVariableFinder(
      llvm::SmallPtrSetImpl<const VarDecl *> &Variables,
      llvm::SmallPtrSetImpl<const DeclRefExpr *> &AssignmentTargets)
      : Variables(Variables), AssignmentTargets(AssignmentTargets) {}

  bool VisitVarDecl(VarDecl *VD) override {
    if (isQEMUErrorPointer(VD->getType()))
      Variables.insert(VD);
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) override {
    if (BO->getOpcode() == BO_Assign)
      if (const auto *DRE =
              dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts()))
        AssignmentTargets.insert(DRE);
    return true;
  }
};

class QEMUConsumedErrorChecker {
  Sema &S;
  const CFG &Cfg;
  llvm::SmallPtrSet<const VarDecl *, 16> ErrorVariables;
  llvm::SmallPtrSet<const DeclRefExpr *, 16> AssignmentTargets;
  llvm::SmallVector<std::pair<const VarDecl *, SourceLocation>, 16> Reported;

  enum StateBits : uint8_t { Unreached = 0, Valid = 1, Consumed = 2 };

  struct VariableState {
    uint8_t Bits = Unreached;
    const CallExpr *Origin = nullptr;
  };
  using State = llvm::DenseMap<const VarDecl *, VariableState>;

  class UseFinder : public DynamicRecursiveASTVisitor {
    QEMUConsumedErrorChecker &Checker;
    State &Current;

  public:
    UseFinder(QEMUConsumedErrorChecker &Checker, State &Current)
        : Checker(Checker), Current(Current) {}

    bool VisitDeclRefExpr(DeclRefExpr *DRE) override {
      const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
      if (VD && Checker.ErrorVariables.contains(VD) &&
          !Checker.AssignmentTargets.contains(DRE))
        Checker.reportUse(DRE, VD, Current);
      return true;
    }
  };

  const VarDecl *directErrorVariable(const Expr *E) const {
    if (!E)
      return nullptr;
    E = E->IgnoreParenImpCasts();
    const auto *DRE = dyn_cast<DeclRefExpr>(E);
    const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
    return VD && ErrorVariables.contains(VD) ? VD : nullptr;
  }

  const VarDecl *addressedErrorVariable(const Expr *E) const {
    if (!E)
      return nullptr;
    E = E->IgnoreParenImpCasts();
    const auto *UO = dyn_cast<UnaryOperator>(E);
    if (!UO || UO->getOpcode() != UO_AddrOf)
      return nullptr;
    return directErrorVariable(UO->getSubExpr());
  }

  struct Consumer {
    unsigned Argument;
    bool ClearsVariable;
  };

  std::optional<Consumer> consumer(const CallExpr *Call) const {
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee || !Callee->getIdentifier())
      return std::nullopt;
    int Argument =
        llvm::StringSwitch<int>(Callee->getName())
            .Cases({"error_free", "error_report_err", "warn_report_err"}, 0)
            .Cases({"error_propagate", "error_propagate_prepend",
                    "warn_report_err_once_cond"},
                   1)
            .Default(-1);
    if (Argument >= 0)
      return Consumer{static_cast<unsigned>(Argument), false};
    if (Callee->getName() == "error_free_or_abort")
      return Consumer{0, true};
    return std::nullopt;
  }

  void reportUse(const Expr *Use, const VarDecl *VD, State &Current) {
    VariableState &VS = Current[VD];
    if (!(VS.Bits & Consumed))
      return;
    SourceLocation Location = Use->getExprLoc();
    for (const auto &[ReportedVD, ReportedLocation] : Reported)
      if (ReportedVD == VD && ReportedLocation == Location)
        return;
    Reported.emplace_back(VD, Location);
    S.Diag(Use->getExprLoc(), diag::warn_qemu_error_use_after_consume)
        << (VS.Bits & Valid ? 1 : 0) << VD;
    if (VS.Origin) {
      const FunctionDecl *Callee = VS.Origin->getDirectCallee();
      S.Diag(VS.Origin->getExprLoc(), diag::note_qemu_error_consumed_here)
          << Callee;
    }
  }

  void scanUses(const Stmt *St, State &Current) {
    if (St)
      UseFinder(*this, Current).TraverseStmt(const_cast<Stmt *>(St));
  }

  void transfer(const Stmt *St, State &Current) {
    if (const auto *DS = dyn_cast<DeclStmt>(St)) {
      for (const Decl *D : DS->decls()) {
        const auto *VD = dyn_cast<VarDecl>(D);
        if (!VD)
          continue;
        scanUses(VD->getInit(), Current);
        if (ErrorVariables.contains(VD))
          Current[VD] = VariableState{Valid, nullptr};
      }
      return;
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
      if (BO->getOpcode() == BO_Assign) {
        const VarDecl *VD = directErrorVariable(BO->getLHS());
        if (VD) {
          scanUses(BO->getRHS(), Current);
          Current[VD] = VariableState{Valid, nullptr};
          return;
        }
      }
    }

    if (const auto *Call = dyn_cast<CallExpr>(St)) {
      std::optional<Consumer> Consumes = consumer(Call);
      if (Consumes && Consumes->Argument < Call->getNumArgs()) {
        const Expr *Argument = Call->getArg(Consumes->Argument);
        const VarDecl *VD = Consumes->ClearsVariable
                                ? addressedErrorVariable(Argument)
                                : directErrorVariable(Argument);
        if (VD) {
          for (unsigned I = 0; I != Call->getNumArgs(); ++I)
            if (I != Consumes->Argument)
              scanUses(Call->getArg(I), Current);
          reportUse(Argument, VD, Current);
          Current[VD] = Consumes->ClearsVariable
                            ? VariableState{Valid, nullptr}
                            : VariableState{Consumed, Call};
          return;
        }
      }
    }

    scanUses(St, Current);
  }

  static bool merge(State &Destination, const State &Source) {
    bool Changed = false;
    for (const auto &[VD, SourceState] : Source) {
      VariableState &DestState = Destination[VD];
      uint8_t OldBits = DestState.Bits;
      DestState.Bits |= SourceState.Bits;
      if (!DestState.Origin && (SourceState.Bits & Consumed))
        DestState.Origin = SourceState.Origin;
      Changed |= OldBits != DestState.Bits;
    }
    return Changed;
  }

public:
  QEMUConsumedErrorChecker(Sema &S, const FunctionDecl *FD, const CFG &Cfg)
      : S(S), Cfg(Cfg) {
    for (const ParmVarDecl *P : FD->parameters())
      if (isQEMUErrorPointer(P->getType()))
        ErrorVariables.insert(P);
    QEMUErrorVariableFinder Finder(ErrorVariables, AssignmentTargets);
    Finder.TraverseStmt(FD->getBody());
  }

  void run() {
    if (ErrorVariables.empty())
      return;

    // This lightweight checker does not model loop iteration state.  Feeding a
    // consumed state around a backedge therefore makes an earlier use in the
    // next analysis iteration look like a source-level use-after-consume.  Do
    // not propagate over backedges; same-iteration bugs are still diagnosed.
    const auto BackEdges = findCFGBackEdges(Cfg);
    llvm::SmallVector<State, 32> In(Cfg.getNumBlockIDs());
    State &Entry = In[Cfg.getEntry().getBlockID()];
    for (const VarDecl *VD : ErrorVariables)
      Entry[VD] = VariableState{Valid, nullptr};

    std::deque<const CFGBlock *> Worklist;
    Worklist.push_back(&Cfg.getEntry());
    while (!Worklist.empty()) {
      const CFGBlock *Block = Worklist.front();
      Worklist.pop_front();
      State Current = In[Block->getBlockID()];
      for (const CFGElement &Element : *Block)
        if (auto CS = Element.getAs<CFGStmt>())
          transfer(CS->getStmt(), Current);

      for (CFGBlock::const_succ_iterator I = Block->succ_begin(),
                                         E = Block->succ_end();
           I != E; ++I) {
        const CFGBlock *Successor = I->getReachableBlock();
        if (Successor && BackEdges.lookup(Block) != Successor &&
            merge(In[Successor->getBlockID()], Current))
          Worklist.push_back(Successor);
      }
    }
  }
};

static bool shouldRunQEMUWarnings(const Sema &S, SourceLocation Loc) {
  const DiagnosticsEngine &Diags = S.getDiagnostics();
  return !Diags.isIgnored(diag::warn_qemu_noncoroutine_call, Loc) ||
         !Diags.isIgnored(diag::warn_qemu_coroutine_calls_no_coroutine, Loc) ||
         !Diags.isIgnored(diag::warn_qemu_required_result_discarded, Loc) ||
         !Diags.isIgnored(diag::warn_qemu_memtx_result_discarded, Loc) ||
         !Diags.isIgnored(diag::warn_qemu_errp_dereference_without_guard,
                          Loc) ||
         !Diags.isIgnored(diag::warn_qemu_errp_helper_without_guard, Loc);
}

} // namespace

UninitOutputParamContract
clang::sema::getQEMUOutputParamContract(const CallExpr *Call,
                                        const VarDecl *VD) {
  const FunctionDecl *Callee = Call ? Call->getDirectCallee() : nullptr;
  if (!Callee || !Callee->getIdentifier() || !VD)
    return UninitOutputParamContract::None;

  if (qemuAnnotatedOutputArgument(Callee, Call, VD)) {
    if (hasQEMUAnnotation(Callee, "qemu::returns_true_on_success"))
      return UninitOutputParamContract::TrueOnSuccess;
    if (hasQEMUAnnotation(Callee, "qemu::returns_nonnegative_on_success"))
      return UninitOutputParamContract::NonnegativeOnSuccess;
    return UninitOutputParamContract::ZeroOnSuccess;
  }

  StringRef Name = Callee->getName();
  if (Name == "v7m_stack_read" && qemuArgumentMatches(Call, VD, 1))
    return UninitOutputParamContract::TrueOnSuccess;
  if (Name == "strstart" && qemuArgumentMatches(Call, VD, 2))
    return UninitOutputParamContract::TrueOnSuccess;

  if (Name == "nbd_co_receive_return_code" && qemuArgumentMatches(Call, VD, 2))
    return UninitOutputParamContract::NonnegativeOnSuccess;
  if (Name == "nbd_co_receive_cmdread_reply" &&
      qemuArgumentMatches(Call, VD, 4))
    return UninitOutputParamContract::NonnegativeOnSuccess;
  if (Name == "nbd_co_receive_blockstatus_reply" &&
      (qemuArgumentMatches(Call, VD, 3) || qemuArgumentMatches(Call, VD, 4)))
    return UninitOutputParamContract::NonnegativeOnSuccess;
  if (Name == "bdrv_snapshot_list" && qemuArgumentMatches(Call, VD, 1))
    return UninitOutputParamContract::NonnegativeOnSuccess;

  if ((Name == "bdrv_co_block_status" || Name == "bdrv_block_status") &&
      (qemuArgumentMatches(Call, VD, 3) || qemuArgumentMatches(Call, VD, 4) ||
       qemuArgumentMatches(Call, VD, 5)))
    return UninitOutputParamContract::Always;
  if ((Name == "bdrv_co_block_status_above" ||
       Name == "bdrv_block_status_above" ||
       Name == "blk_co_block_status_above") &&
      (qemuArgumentMatches(Call, VD, 4) || qemuArgumentMatches(Call, VD, 5) ||
       qemuArgumentMatches(Call, VD, 6)))
    return UninitOutputParamContract::Always;
  if ((Name == "bdrv_co_is_allocated" || Name == "bdrv_is_allocated") &&
      qemuArgumentMatches(Call, VD, 3))
    return UninitOutputParamContract::Always;
  if ((Name == "bdrv_co_is_allocated_above" ||
       Name == "bdrv_is_allocated_above" ||
       Name == "blk_co_is_allocated_above") &&
      qemuArgumentMatches(Call, VD, 5))
    return UninitOutputParamContract::Always;
  if (Name == "bdrv_round_to_subclusters" &&
      (qemuArgumentMatches(Call, VD, 3) || qemuArgumentMatches(Call, VD, 4)))
    return UninitOutputParamContract::Always;

  if (isQEMUBuiltinMustCheck(Callee) && Call->getNumArgs() &&
      qemuArgumentMatches(Call, VD, Call->getNumArgs() - 1))
    return UninitOutputParamContract::Always;

  return UninitOutputParamContract::None;
}

bool clang::sema::isQEMUKnownNonNullCall(Sema &S, const CallExpr *Call) {
  const FunctionDecl *Callee = Call ? Call->getDirectCallee() : nullptr;
  if (!Callee || !Callee->getIdentifier())
    return false;
  if (Callee->hasAttr<ReturnsNonNullAttr>())
    return true;

  StringRef Name = Callee->getName();
  if (Name == "graph_lockable_auto_lock" || Name == "rcu_read_auto_lock")
    return true;
  return Name == "qemu_lockable_auto_lock" &&
         qemuMacroStackContains(S, Call->getExprLoc(), "WITH_QEMU_LOCK_GUARD");
}

void clang::sema::IssueQEMUWarnings(Sema &S, const FunctionDecl *FD) {
  if (!FD || !FD->getBody() || !shouldRunQEMUWarnings(S, FD->getBeginLoc()))
    return;
  QEMUWarningsVisitor(S, FD).TraverseStmt(FD->getBody());
}

bool clang::sema::wantsQEMUFlowWarnings(Sema &S, const FunctionDecl *FD) {
  if (!FD || !FD->getBody())
    return false;
  const DiagnosticsEngine &Diags = S.getDiagnostics();
  return !Diags.isIgnored(diag::warn_qemu_success_after_error_set,
                          FD->getBeginLoc()) ||
         !Diags.isIgnored(diag::warn_qemu_error_use_after_consume,
                          FD->getBeginLoc());
}

void clang::sema::IssueQEMUFlowWarnings(Sema &S, const FunctionDecl *FD,
                                        AnalysisDeclContext &AC) {
  if (!wantsQEMUFlowWarnings(S, FD))
    return;
  if (const CFG *Cfg = AC.getCFG()) {
    const DiagnosticsEngine &Diags = S.getDiagnostics();
    if (!Diags.isIgnored(diag::warn_qemu_success_after_error_set,
                         FD->getBeginLoc()))
      QEMUErrorSuccessChecker(S, FD, *Cfg).run();
    if (!Diags.isIgnored(diag::warn_qemu_error_use_after_consume,
                         FD->getBeginLoc()))
      QEMUConsumedErrorChecker(S, FD, *Cfg).run();
  }
}
