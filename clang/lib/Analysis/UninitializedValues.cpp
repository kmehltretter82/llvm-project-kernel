//===- UninitializedValues.cpp - Find Uninitialized Values ----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements uninitialized values analysis for source-level CFGs.
//
//===----------------------------------------------------------------------===//

#include "clang/Analysis/Analyses/UninitializedValues.h"
#include "clang/Analysis/Analyses/Dominators.h"
#include "clang/Basic/Builtins.h"
#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclBase.h"
#include "clang/AST/Expr.h"
#include "clang/AST/OperationKinds.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/StmtObjC.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/Type.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Analysis/CFG.h"
#include "clang/Analysis/DomainSpecific/ObjCNoReturn.h"
#include "clang/Analysis/FlowSensitive/DataflowWorklist.h"
#include "clang/Basic/LLVM.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/PackedVector.h"
#include "llvm/ADT/SmallBitVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSwitch.h"
#include <algorithm>
#include <cassert>
#include <optional>

using namespace clang;

#define DEBUG_LOGGING 0

static bool recordIsNotEmpty(const RecordDecl *RD) {
  // We consider a record decl to be empty if it contains only unnamed bit-
  // fields, zero-width fields, and fields of empty record type.
  for (const auto *FD : RD->fields()) {
    if (FD->isUnnamedBitField())
      continue;
    if (FD->isZeroSize(FD->getASTContext()))
      continue;
    // The only case remaining to check is for a field declaration of record
    // type and whether that record itself is empty.
    if (const auto *FieldRD = FD->getType()->getAsRecordDecl();
        !FieldRD || recordIsNotEmpty(FieldRD))
      return true;
  }
  return false;
}

static bool isTrackedVar(const VarDecl *vd, const DeclContext *dc) {
  if (vd->isLocalVarDecl() && !vd->hasGlobalStorage() &&
      !vd->isExceptionVariable() && !vd->isInitCapture() && !vd->isImplicit() &&
      vd->getDeclContext() == dc) {
    // "register unsigned long sp asm("r30");" names a machine register.
    // Reading the variable reads the register, which is how code for GCC
    // gets at the stack pointer or the global pointer.
    if (vd->getStorageClass() == SC_Register && vd->hasAttr<AsmLabelAttr>())
      return false;
    QualType ty = vd->getType();
    if (const auto *RD = ty->getAsRecordDecl())
      return recordIsNotEmpty(RD);
    return ty->isScalarType() || ty->isVectorType() || ty->isRVVSizelessBuiltinType();
  }
  return false;
}

//------------------------------------------------------------------------====//
// DeclToIndex: a mapping from Decls we track to value indices.
//====------------------------------------------------------------------------//

namespace {

class DeclToIndex {
  llvm::DenseMap<const VarDecl *, unsigned> map;

public:
  DeclToIndex() = default;

  /// Compute the actual mapping from declarations to bits.
  void computeMap(const DeclContext &dc);

  /// Return the number of declarations in the map.
  unsigned size() const { return map.size(); }

  /// Returns the bit vector index for a given declaration.
  std::optional<unsigned> getValueIndex(const VarDecl *d) const;
};

} // namespace

void DeclToIndex::computeMap(const DeclContext &dc) {
  unsigned count = 0;
  DeclContext::specific_decl_iterator<VarDecl> I(dc.decls_begin()),
                                               E(dc.decls_end());
  for ( ; I != E; ++I) {
    const VarDecl *vd = *I;
    if (isTrackedVar(vd, &dc))
      map[vd] = count++;
  }
}

std::optional<unsigned> DeclToIndex::getValueIndex(const VarDecl *d) const {
  llvm::DenseMap<const VarDecl *, unsigned>::const_iterator I = map.find(d);
  if (I == map.end())
    return std::nullopt;
  return I->second;
}

//------------------------------------------------------------------------====//
// CFGBlockValues: dataflow values for CFG blocks.
//====------------------------------------------------------------------------//

// These values are defined in such a way that a merge can be done using
// a bitwise OR.
enum Value { Unknown = 0x0,         /* 00 */
             Initialized = 0x1,     /* 01 */
             Uninitialized = 0x2,   /* 10 */
             MayUninitialized = 0x3 /* 11 */ };

static bool isUninitialized(const Value v) {
  return v >= Uninitialized;
}

static bool isAlwaysUninit(const Value v) {
  return v == Uninitialized;
}

namespace {

using ValueVector = llvm::PackedVector<Value, 2, llvm::SmallBitVector>;

class CFGBlockValues {
  const CFG &cfg;
  SmallVector<ValueVector, 8> vals;
  ValueVector scratch;
  DeclToIndex declToIndex;

public:
  CFGBlockValues(const CFG &cfg);

  unsigned getNumEntries() const { return declToIndex.size(); }

  void computeSetOfDeclarations(const DeclContext &dc);

  ValueVector &getValueVector(const CFGBlock *block) {
    return vals[block->getBlockID()];
  }

  void setAllScratchValues(Value V);
  void mergeIntoScratch(ValueVector const &source, bool isFirst);
  bool updateValueVectorWithScratch(const CFGBlock *block);

  bool hasNoDeclarations() const {
    return declToIndex.size() == 0;
  }

  void resetScratch();

  ValueVector::reference operator[](const VarDecl *vd);

  Value getValue(const CFGBlock *block, const VarDecl *vd) {
    std::optional<unsigned> idx = declToIndex.getValueIndex(vd);
    return getValueVector(block)[*idx];
  }
};

} // namespace

CFGBlockValues::CFGBlockValues(const CFG &c) : cfg(c), vals(0) {}

void CFGBlockValues::computeSetOfDeclarations(const DeclContext &dc) {
  declToIndex.computeMap(dc);
  unsigned decls = declToIndex.size();
  scratch.resize(decls);
  unsigned n = cfg.getNumBlockIDs();
  if (!n)
    return;
  vals.resize(n);
  for (auto &val : vals)
    val.resize(decls);
}

#if DEBUG_LOGGING
static void printVector(const CFGBlock *block, ValueVector &bv,
                        unsigned num) {
  llvm::errs() << block->getBlockID() << " :";
  for (const auto &i : bv)
    llvm::errs() << ' ' << i;
  llvm::errs() << " : " << num << '\n';
}
#endif

void CFGBlockValues::setAllScratchValues(Value V) {
  for (unsigned I = 0, E = scratch.size(); I != E; ++I)
    scratch[I] = V;
}

void CFGBlockValues::mergeIntoScratch(ValueVector const &source,
                                      bool isFirst) {
  if (isFirst)
    scratch = source;
  else
    scratch |= source;
}

bool CFGBlockValues::updateValueVectorWithScratch(const CFGBlock *block) {
  ValueVector &dst = getValueVector(block);
  bool changed = (dst != scratch);
  if (changed)
    dst = scratch;
#if DEBUG_LOGGING
  printVector(block, scratch, 0);
#endif
  return changed;
}

void CFGBlockValues::resetScratch() {
  scratch.reset();
}

ValueVector::reference CFGBlockValues::operator[](const VarDecl *vd) {
  return scratch[*declToIndex.getValueIndex(vd)];
}

//------------------------------------------------------------------------====//
// Classification of DeclRefExprs as use or initialization.
//====------------------------------------------------------------------------//

namespace {

class FindVarResult {
  const VarDecl *vd;
  const DeclRefExpr *dr;

public:
  FindVarResult(const VarDecl *vd, const DeclRefExpr *dr) : vd(vd), dr(dr) {}

  const DeclRefExpr *getDeclRefExpr() const { return dr; }
  const VarDecl *getDecl() const { return vd; }
};

} // namespace

static const Expr *stripCasts(ASTContext &C, const Expr *Ex) {
  while (Ex) {
    Ex = Ex->IgnoreParenNoopCasts(C);
    if (const auto *CE = dyn_cast<CastExpr>(Ex)) {
      if (CE->getCastKind() == CK_LValueBitCast) {
        Ex = CE->getSubExpr();
        continue;
      }
    }
    break;
  }
  return Ex;
}

/// If E is an expression comprising a reference to a single variable, find that
/// variable.
static FindVarResult findVar(const Expr *E, const DeclContext *DC) {
  if (const auto *DRE =
          dyn_cast<DeclRefExpr>(stripCasts(DC->getParentASTContext(), E)))
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      if (isTrackedVar(VD, DC))
        return FindVarResult(VD, DRE);
  return FindVarResult(nullptr, nullptr);
}

namespace {

/// Classify each DeclRefExpr as an initialization or a use. Any
/// DeclRefExpr which isn't explicitly classified will be assumed to have
/// escaped the analysis and will be treated as an initialization.
class ClassifyRefs : public ConstStmtVisitor<ClassifyRefs> {
public:
  enum Class { Init, Use, SelfInit, ConstRefUse, ConstPtrUse, Ignore };

private:
  const DeclContext *DC;
  llvm::DenseMap<const DeclRefExpr *, Class> Classification;

  bool isTrackedVar(const VarDecl *VD) const {
    return ::isTrackedVar(VD, DC);
  }

  void classify(const Expr *E, Class C);

public:
  ClassifyRefs(AnalysisDeclContext &AC) : DC(cast<DeclContext>(AC.getDecl())) {}

  void VisitDeclStmt(const DeclStmt *DS);
  void VisitUnaryOperator(const UnaryOperator *UO);
  void VisitBinaryOperator(const BinaryOperator *BO);
  void VisitCallExpr(const CallExpr *CE);
  void VisitCastExpr(const CastExpr *CE);
  void VisitOMPExecutableDirective(const OMPExecutableDirective *ED);

  void operator()(const Stmt *S) { Visit(S); }

  Class get(const DeclRefExpr *DRE) const {
    llvm::DenseMap<const DeclRefExpr*, Class>::const_iterator I
        = Classification.find(DRE);
    if (I != Classification.end())
      return I->second;

    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD || !isTrackedVar(VD))
      return Ignore;

    return Init;
  }
};

} // namespace

static const DeclRefExpr *getSelfInitExpr(const VarDecl *VD) {
  if (VD->getType()->isRecordType())
    return nullptr;
  if (const Expr *Init = VD->getInit()) {
    const auto *DRE =
        dyn_cast<DeclRefExpr>(stripCasts(VD->getASTContext(), Init));
    if (DRE && DRE->getDecl() == VD)
      return DRE;
  }
  return nullptr;
}

void ClassifyRefs::classify(const Expr *E, Class C) {
  // The result of a ?: could also be an lvalue.
  E = E->IgnoreParens();
  if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
    classify(CO->getTrueExpr(), C);
    classify(CO->getFalseExpr(), C);
    return;
  }

  if (const auto *BCO = dyn_cast<BinaryConditionalOperator>(E)) {
    classify(BCO->getFalseExpr(), C);
    return;
  }

  if (const auto *OVE = dyn_cast<OpaqueValueExpr>(E)) {
    classify(OVE->getSourceExpr(), C);
    return;
  }

  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(ME->getMemberDecl())) {
      if (!VD->isStaticDataMember())
        classify(ME->getBase(), C);
    }
    return;
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    switch (BO->getOpcode()) {
    case BO_PtrMemD:
    case BO_PtrMemI:
      classify(BO->getLHS(), C);
      return;
    case BO_Comma:
      classify(BO->getRHS(), C);
      return;
    default:
      return;
    }
  }

  FindVarResult Var = findVar(E, DC);
  if (const DeclRefExpr *DRE = Var.getDeclRefExpr()) {
    auto &Class = Classification[DRE];
    Class = std::max(Class, C);
  }
}

void ClassifyRefs::VisitDeclStmt(const DeclStmt *DS) {
  for (auto *DI : DS->decls()) {
    auto *VD = dyn_cast<VarDecl>(DI);
    if (VD && isTrackedVar(VD))
      if (const DeclRefExpr *DRE = getSelfInitExpr(VD))
        Classification[DRE] = SelfInit;
  }
}

void ClassifyRefs::VisitBinaryOperator(const BinaryOperator *BO) {
  // Ignore the evaluation of a DeclRefExpr on the LHS of an assignment. If this
  // is not a compound-assignment, we will treat it as initializing the variable
  // when TransferFunctions visits it. A compound-assignment does not affect
  // whether a variable is uninitialized, and there's no point counting it as a
  // use.
  if (BO->isCompoundAssignmentOp())
    classify(BO->getLHS(), Use);
  else if (BO->getOpcode() == BO_Assign || BO->getOpcode() == BO_Comma)
    classify(BO->getLHS(), Ignore);
}

void ClassifyRefs::VisitUnaryOperator(const UnaryOperator *UO) {
  // Increment and decrement are uses despite there being no lvalue-to-rvalue
  // conversion.
  if (UO->isIncrementDecrementOp())
    classify(UO->getSubExpr(), Use);
}

void ClassifyRefs::VisitOMPExecutableDirective(
    const OMPExecutableDirective *ED) {
  for (Stmt *S : OMPExecutableDirective::used_clauses_children(ED->clauses()))
    classify(cast<Expr>(S), Use);
}

static bool isPointerToConst(const QualType &QT) {
  return QT->isAnyPointerType() && QT->getPointeeType().isConstQualified();
}

static bool hasTrivialBody(const CallExpr *CE) {
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    if (const FunctionTemplateDecl *FTD = FD->getPrimaryTemplate())
      return FTD->getTemplatedDecl()->hasTrivialBody();
    return FD->hasTrivialBody();
  }
  return false;
}

void ClassifyRefs::VisitCallExpr(const CallExpr *CE) {
  // Classify arguments to std::move as used.
  if (CE->isCallToStdMove()) {
    // RecordTypes are handled in SemaDeclCXX.cpp.
    if (!CE->getArg(0)->getType()->isRecordType())
      classify(CE->getArg(0), Use);
    return;
  }
  bool isTrivialBody = hasTrivialBody(CE);
  // If a value is passed by const pointer to a function,
  // we should not assume that it is initialized by the call, and we
  // conservatively do not assume that it is used.
  // If a value is passed by const reference to a function,
  // it should already be initialized.
  for (const Expr *Argument : CE->arguments()) {
    if (Argument->isGLValue()) {
      if (Argument->getType().isConstQualified())
        classify(Argument, isTrivialBody ? Ignore : ConstRefUse);
    } else if (isPointerToConst(Argument->getType())) {
      const Expr *Ex = stripCasts(DC->getParentASTContext(), Argument);
      const auto *UO = dyn_cast<UnaryOperator>(Ex);
      if (UO && UO->getOpcode() == UO_AddrOf)
        classify(UO->getSubExpr(), isTrivialBody ? Ignore : ConstPtrUse);
    }
  }
}

void ClassifyRefs::VisitCastExpr(const CastExpr *CE) {
  if (CE->getCastKind() == CK_LValueToRValue)
    classify(CE->getSubExpr(), Use);
  else if (const auto *CSE = dyn_cast<CStyleCastExpr>(CE)) {
    if (CSE->getType()->isVoidType()) {
      // Squelch any detected load of an uninitialized value if
      // we cast it to void.
      // e.g. (void) x;
      classify(CSE->getSubExpr(), Ignore);
    }
  }
}

//------------------------------------------------------------------------====//
// Pruning of 'may be uninitialized' uses guarded by correlated conditions.
//====------------------------------------------------------------------------//

namespace {

/// Decides whether a use that the dataflow analysis reports as "may be
/// uninitialized" is only reachable, with the variable still uninitialized,
/// along paths that contradict themselves.
///
/// The check replays the function over its CFG and tracks a few facts per
/// path: whether the variable has been initialized, the constant values of
/// some local scalars that occur in branch conditions, and the outcome of
/// some side-effect-free branch conditions.  A path that would have to take a
/// branch against a fact it established earlier is dropped.  If no remaining
/// path reaches the use without initializing the variable, the use is guarded
/// by conditions that are correlated with the initialization, as in
///
///   if (flag)
///     x = f();
///   ...
///   if (flag)
///     use(x);
///
/// Facts are tracked only for conditions that dominate the use or one of the
/// initializations, which keeps the state small.  The check is conservative:
/// calls and stores through memory forget conditions that read memory, and
/// the use is reported as before whenever the search exceeds its budget.
class CorrelatedUninitPruner {
  static constexpr unsigned MaxVars = 8;
  static constexpr unsigned MaxPreds = 24;
  static constexpr unsigned MaxStatesPerBlock = 64;
  /// Budget for one use: block visits plus statements, and stored states.
  static constexpr unsigned MaxSteps = 100000;
  static constexpr unsigned MaxStates = 16384;
  /// Budget for all uses in one function.  Functions with thousands of
  /// branches, typically generated by macros, would otherwise make the
  /// compile time quadratic.
  static constexpr unsigned MaxFunctionSteps = 2000000;

  const CFG &Cfg;
  AnalysisDeclContext &AC;
  ASTContext &Ctx;
  const ClassifyRefs &Classification;
  const DeclContext *DC;

  bool Prepared = false;
  llvm::SmallPtrSet<const VarDecl *, 16> AddressTaken;
  std::unique_ptr<CFGDomTree> DomTree;
  /// The blocks that initialize each tracked variable.
  llvm::DenseMap<const VarDecl *, SmallVector<const CFGBlock *, 4>> InitBlocks;
  unsigned FunctionSteps = 0;

  struct Pred {
    /// The condition, or null for "EqVar == EqValue", which stands for a
    /// case of a switch on EqVar.
    const Expr *Cond = nullptr;
    const VarDecl *EqVar = nullptr;
    llvm::APSInt EqValue;
    llvm::FoldingSetNodeID ID;
    SmallVector<const VarDecl *, 2> Locals;
    bool ReadsMemory = false;
  };

  struct Value {
    enum KindTy : uint8_t { Top, Const, NonZero };
    KindTy Kind = Top;
    uint64_t Bits = 0;

    bool operator==(const Value &O) const {
      return Kind == O.Kind && (Kind != Const || Bits == O.Bits);
    }
  };

  struct State {
    bool XInit = false;
    /// The path has dereferenced a pointer that it knows to be null.
    bool Dead = false;
    Value Vals[MaxVars];
    uint32_t Known = 0;
    uint32_t Truth = 0;

    bool operator==(const State &O) const {
      if (XInit != O.XInit || Known != O.Known ||
          (Truth & Known) != (O.Truth & O.Known))
        return false;
      for (unsigned I = 0; I != MaxVars; ++I)
        if (!(Vals[I] == O.Vals[I]))
          return false;
      return true;
    }
  };

  // Per query.
  const VarDecl *X = nullptr;
  const Expr *Use = nullptr;
  SmallVector<const VarDecl *, MaxVars> Vars;
  SmallVector<Pred, MaxPreds> Preds;
  unsigned Steps = 0;
  unsigned States = 0;
  bool UseReachedUninit = false;
  bool GaveUp = false;

  void collectAddressTaken(const Stmt *S) {
    if (!S)
      return;
    if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
      if (UO->getOpcode() == UO_AddrOf)
        if (const auto *DRE =
                dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParens()))
          if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
            AddressTaken.insert(VD);
    } else if (const auto *AS = dyn_cast<GCCAsmStmt>(S)) {
      for (unsigned I = 0, E = AS->getNumOutputs(); I != E; ++I)
        if (const auto *DRE = dyn_cast<DeclRefExpr>(
                AS->getOutputExpr(I)->IgnoreParenCasts()))
          if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
            AddressTaken.insert(VD);
    }
    for (const Stmt *Child : S->children())
      collectAddressTaken(Child);
  }

  void prepare() {
    if (Prepared)
      return;
    Prepared = true;
    collectAddressTaken(AC.getBody());
    DomTree = std::make_unique<CFGDomTree>(const_cast<CFG *>(&Cfg));

    auto Record = [&](const VarDecl *VD, const CFGBlock *B) {
      if (!VD)
        return;
      SmallVectorImpl<const CFGBlock *> &Blocks = InitBlocks[VD];
      if (Blocks.empty() || Blocks.back() != B)
        Blocks.push_back(B);
    };
    for (const CFGBlock *B : Cfg) {
      for (const CFGElement &Elem : *B) {
        std::optional<CFGStmt> CS = Elem.getAs<CFGStmt>();
        if (!CS)
          continue;
        const Stmt *S = CS->getStmt();
        if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
          if (BO->getOpcode() == BO_Assign)
            Record(::findVar(BO->getLHS(), DC).getDecl(), B);
        } else if (const auto *DS = dyn_cast<DeclStmt>(S)) {
          for (const Decl *D : DS->decls())
            if (const auto *VD = dyn_cast<VarDecl>(D))
              if (VD->getInit() && !getSelfInitExpr(VD))
                Record(VD, B);
        } else if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
          if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
            if (Classification.get(DRE) == ClassifyRefs::Init)
              Record(VD, B);
        } else if (const auto *AS = dyn_cast<GCCAsmStmt>(S)) {
          for (unsigned I = 0, E = AS->getNumOutputs(); I != E; ++I)
            Record(::findVar(AS->getOutputExpr(I), DC).getDecl(), B);
        }
      }
    }
  }

  bool isTrackableLocal(const VarDecl *VD) const {
    if (!VD || !VD->hasLocalStorage() || VD->getDeclContext() != DC ||
        AddressTaken.count(VD))
      return false;
    QualType T = VD->getType();
    if (T.isVolatileQualified())
      return false;
    return T->isIntegralOrEnumerationType() || T->isPointerType();
  }

  int varIndex(const VarDecl *VD) const {
    for (unsigned I = 0, E = Vars.size(); I != E; ++I)
      if (Vars[I] == VD)
        return I;
    return -1;
  }

  static const VarDecl *asVarRef(const Expr *E) {
    if (!E)
      return nullptr;
    const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts());
    return DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  }

  /// Strip the wrappers that do not change which values make a condition
  /// true, and fold logical negations into \p Negated.
  const Expr *stripCondition(const Expr *E, bool &Negated) const {
    while (E) {
      E = E->IgnoreParens();
      if (const auto *ICE = dyn_cast<ImplicitCastExpr>(E)) {
        CastKind K = ICE->getCastKind();
        if (K == CK_IntegralToBoolean || K == CK_PointerToBoolean ||
            K == CK_NoOp ||
            (K == CK_IntegralCast &&
             ICE->getSubExpr()->isKnownToHaveBooleanValue())) {
          E = ICE->getSubExpr();
          continue;
        }
        break;
      }
      if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
        if (UO->getOpcode() == UO_LNot) {
          Negated = !Negated;
          E = UO->getSubExpr();
          continue;
        }
        break;
      }
      if (const auto *CE = dyn_cast<CallExpr>(E)) {
        unsigned ID = CE->getBuiltinCallee();
        if ((ID == Builtin::BI__builtin_expect ||
             ID == Builtin::BI__builtin_expect_with_probability) &&
            CE->getNumArgs() >= 1) {
          E = CE->getArg(0);
          continue;
        }
      }
      break;
    }
    return E;
  }

  /// Collect what a condition reads.  Returns false if evaluating it could
  /// have a side effect or its value cannot be assumed to be stable.
  bool scanCondition(const Stmt *S, Pred &P,
                     SmallVectorImpl<const VarDecl *> &Scalars) const {
    if (!S)
      return true;
    if (const auto *E = dyn_cast<Expr>(S))
      if (E->getType().isVolatileQualified())
        return false;

    switch (S->getStmtClass()) {
    case Stmt::DeclRefExprClass: {
      const auto *VD = dyn_cast<VarDecl>(cast<DeclRefExpr>(S)->getDecl());
      if (!VD)
        return true;
      if (isTrackableLocal(VD)) {
        if (!llvm::is_contained(P.Locals, VD))
          P.Locals.push_back(VD);
        if (!llvm::is_contained(Scalars, VD))
          Scalars.push_back(VD);
      } else {
        P.ReadsMemory = true;
      }
      return true;
    }
    case Stmt::MemberExprClass:
    case Stmt::ArraySubscriptExprClass:
      P.ReadsMemory = true;
      break;
    case Stmt::UnaryOperatorClass: {
      const auto *UO = cast<UnaryOperator>(S);
      if (UO->isIncrementDecrementOp())
        return false;
      if (UO->getOpcode() == UO_Deref)
        P.ReadsMemory = true;
      break;
    }
    case Stmt::BinaryOperatorClass:
      if (cast<BinaryOperator>(S)->isAssignmentOp())
        return false;
      break;
    case Stmt::CallExprClass: {
      const auto *CE = cast<CallExpr>(S);
      unsigned ID = CE->getBuiltinCallee();
      if (ID != Builtin::BI__builtin_expect &&
          ID != Builtin::BI__builtin_expect_with_probability &&
          ID != Builtin::BI__builtin_constant_p) {
        const FunctionDecl *FD = CE->getDirectCallee();
        if (!FD || !(FD->hasAttr<ConstAttr>() || FD->hasAttr<PureAttr>()))
          return false;
        if (FD->hasAttr<PureAttr>())
          P.ReadsMemory = true;
      }
      break;
    }
    case Stmt::CompoundAssignOperatorClass:
    case Stmt::StmtExprClass:
    case Stmt::VAArgExprClass:
    case Stmt::AtomicExprClass:
    case Stmt::ConditionalOperatorClass:
    case Stmt::BinaryConditionalOperatorClass:
      return false;
    default:
      break;
    }
    for (const Stmt *Child : S->children())
      if (!scanCondition(Child, P, Scalars))
        return false;
    return true;
  }

  /// Compute the key of a condition.  The relational comparisons of two
  /// operands share one key, that of "a < b": "b > a" is the same condition
  /// and "a >= b" and "b <= a" are its negation.  Returns true if \p E is
  /// the negation of the condition that the key stands for.
  bool profileCondition(const Expr *E, llvm::FoldingSetNodeID &ID) const {
    const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts());
    if (!BO || !BO->isRelationalOp()) {
      E->Profile(ID, Ctx, /*Canonical=*/true);
      return false;
    }
    const Expr *L = BO->getLHS();
    const Expr *R = BO->getRHS();
    bool Flip = BO->getOpcode() == BO_GE || BO->getOpcode() == BO_LE;
    if (BO->getOpcode() == BO_GT || BO->getOpcode() == BO_LE)
      std::swap(L, R);
    ID.AddInteger(static_cast<unsigned>(BO_LT));
    L->Profile(ID, Ctx, /*Canonical=*/true);
    R->Profile(ID, Ctx, /*Canonical=*/true);
    return Flip;
  }

  /// Find the tracked condition with the key of \p Stripped.  \p Flip says
  /// whether \p Stripped is the negation of what is recorded for it.
  int predIndex(const Expr *Stripped, bool &Flip) const {
    llvm::FoldingSetNodeID ID;
    Flip = profileCondition(Stripped, ID);
    for (unsigned I = 0, E = Preds.size(); I != E; ++I)
      if (Preds[I].Cond && Preds[I].ID == ID)
        return I;
    return -1;
  }

  void addCondition(const Expr *Cond) {
    bool Negated = false;
    const Expr *E = stripCondition(Cond, Negated);
    if (!E)
      return;
    Pred P;
    SmallVector<const VarDecl *, 4> Scalars;
    bool Pure = scanCondition(E, P, Scalars);
    for (const VarDecl *VD : Scalars)
      if (Vars.size() < MaxVars && varIndex(VD) < 0)
        Vars.push_back(VD);
    bool Flip;
    if (!Pure || Preds.size() >= MaxPreds || predIndex(E, Flip) >= 0)
      return;
    P.Cond = E;
    profileCondition(E, P.ID);
    Preds.push_back(std::move(P));
  }

  static bool isConditionalBranch(const CFGBlock *B) {
    const Stmt *Term = B->getTerminatorStmt();
    return Term && B->succ_size() == 2 && !isa<SwitchStmt>(Term) &&
           !isa<GCCAsmStmt>(Term) &&
           isa_and_nonnull<Expr>(B->getTerminatorCondition());
  }

  /// The condition that decides which way \p B branches.  A block that ends
  /// in "if (a && b)" evaluates only b: a is the condition of an earlier
  /// block, and this block is reached with the outcome of a that leaves the
  /// result open.  The condition of "do ... while (a && b)" is computed like
  /// the value of any other expression, and the block that ends the loop
  /// branches on the whole of it.
  static const Expr *getBranchCondition(const CFGBlock *B) {
    const Expr *Cond = cast<Expr>(B->getTerminatorCondition());
    if (B->getLastCondition() == Cond->IgnoreParens())
      return Cond;
    for (;;) {
      const auto *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParens());
      if (!BO || !BO->isLogicalOp())
        return Cond;
      Cond = BO->getRHS();
    }
  }

  /// The local variable that \p SS switches on, if it can be tracked.
  const VarDecl *getSwitchVariable(const SwitchStmt *SS) const {
    const VarDecl *VD = asVarRef(SS->getCond());
    return VD && isTrackableLocal(VD) ? VD : nullptr;
  }

  /// Track the variable of a switch and, as conditions, its first cases, so
  /// that "none of these" on the default edge is not lost.
  void addSwitch(const SwitchStmt *SS) {
    const VarDecl *VD = getSwitchVariable(SS);
    if (!VD)
      return;
    if (varIndex(VD) < 0) {
      if (Vars.size() >= MaxVars)
        return;
      Vars.push_back(VD);
    }
    unsigned Added = 0;
    for (const SwitchCase *SC = SS->getSwitchCaseList(); SC && Added < 6;
         SC = SC->getNextSwitchCase()) {
      const auto *CS = dyn_cast<CaseStmt>(SC);
      if (!CS || CS->getRHS() || Preds.size() >= MaxPreds)
        continue;
      llvm::APSInt K = CS->getLHS()->EvaluateKnownConstInt(Ctx);
      if (llvm::any_of(Preds, [&](const Pred &P) {
            return !P.Cond && P.EqVar == VD &&
                   llvm::APSInt::isSameValue(P.EqValue, K);
          }))
        continue;
      Pred P;
      P.EqVar = VD;
      P.EqValue = K;
      P.Locals.push_back(VD);
      Preds.push_back(std::move(P));
      ++Added;
    }
  }

  /// If \p P is "Vars[I] == K" or "Vars[I] != K", return K and which it is.
  bool isEqualityWith(const Pred &P, unsigned I, llvm::APSInt &K,
                      bool &IsNE) const {
    IsNE = false;
    if (!P.Cond) {
      K = P.EqValue;
      return P.EqVar == Vars[I];
    }
    const auto *BO = dyn_cast<BinaryOperator>(P.Cond->IgnoreParenImpCasts());
    if (!BO || !BO->isEqualityOp())
      return false;
    const Expr *Other = BO->getRHS();
    if (asVarRef(BO->getLHS()) != Vars[I]) {
      if (asVarRef(BO->getRHS()) != Vars[I])
        return false;
      Other = BO->getLHS();
    }
    State Empty;
    std::optional<llvm::APSInt> Value = evalInt(Other, Empty);
    if (!Value)
      return false;
    K = *Value;
    IsNE = BO->getOpcode() == BO_NE;
    return true;
  }

  void addDominatingConditions(const CFGBlock *B) {
    llvm::SmallPtrSet<const CFGBlock *, 16> Seen;
    while (B && Seen.insert(B).second) {
      if (isConditionalBranch(B))
        addCondition(getBranchCondition(B));
      else if (const auto *SS =
                   dyn_cast_or_null<SwitchStmt>(B->getTerminatorStmt()))
        addSwitch(SS);
      DomTreeNode *N = DomTree->getBase().getNode(const_cast<CFGBlock *>(B));
      DomTreeNode *IDom = N ? N->getIDom() : nullptr;
      B = IDom ? IDom->getBlock() : nullptr;
    }
  }

  bool initializesX(const Stmt *S) const {
    if (const auto *BO = dyn_cast<BinaryOperator>(S))
      return BO->getOpcode() == BO_Assign &&
             ::findVar(BO->getLHS(), DC).getDecl() == X;
    if (const auto *DS = dyn_cast<DeclStmt>(S)) {
      for (const Decl *D : DS->decls())
        if (D == X && X->getInit() && !getSelfInitExpr(X))
          return true;
      return false;
    }
    if (const auto *DRE = dyn_cast<DeclRefExpr>(S))
      return DRE->getDecl() == X &&
             Classification.get(DRE) == ClassifyRefs::Init;
    if (const auto *AS = dyn_cast<GCCAsmStmt>(S)) {
      for (unsigned I = 0, E = AS->getNumOutputs(); I != E; ++I)
        if (::findVar(AS->getOutputExpr(I), DC).getDecl() == X)
          return true;
    }
    return false;
  }

  llvm::APSInt makeValue(QualType T, uint64_t Bits) const {
    unsigned Width =
        T->isPointerType() ? Ctx.getTypeSize(T) : Ctx.getIntWidth(T);
    bool Unsigned = T->isPointerType() || T->isUnsignedIntegerOrEnumerationType();
    return llvm::APSInt(
        llvm::APInt(Width, Bits, /*isSigned=*/false, /*implicitTrunc=*/true),
        Unsigned);
  }

  /// Evaluate \p E to an integer if the facts of \p St determine it.
  std::optional<llvm::APSInt> evalInt(const Expr *E, const State &St) const {
    E = E->IgnoreParens();
    QualType T = E->getType();
    if (!T->isIntegralOrEnumerationType() && !T->isPointerType())
      return std::nullopt;

    if (const auto *CE = dyn_cast<CastExpr>(E)) {
      const Expr *Sub = CE->getSubExpr();
      switch (CE->getCastKind()) {
      case CK_LValueToRValue:
      case CK_NoOp:
        return evalInt(Sub, St);
      case CK_IntegralCast: {
        std::optional<llvm::APSInt> V = evalInt(Sub, St);
        if (!V)
          return std::nullopt;
        llvm::APSInt R = V->extOrTrunc(Ctx.getIntWidth(T));
        R.setIsUnsigned(T->isUnsignedIntegerOrEnumerationType());
        return R;
      }
      case CK_IntegralToBoolean:
      case CK_PointerToBoolean: {
        std::optional<bool> B = evalTruth(Sub, St);
        if (!B)
          return std::nullopt;
        return makeValue(T, *B);
      }
      case CK_NullToPointer:
        return makeValue(T, 0);
      default:
        return std::nullopt;
      }
    }

    if (const VarDecl *VD = asVarRef(E)) {
      int I = varIndex(VD);
      if (I >= 0) {
        if (St.Vals[I].Kind == Value::Const)
          return makeValue(VD->getType(), St.Vals[I].Bits);
        return std::nullopt;
      }
    }

    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_LNot) {
        std::optional<bool> B = evalTruth(UO->getSubExpr(), St);
        if (!B)
          return std::nullopt;
        return makeValue(T, !*B);
      }
      if (UO->getOpcode() == UO_Minus || UO->getOpcode() == UO_Plus) {
        std::optional<llvm::APSInt> V = evalInt(UO->getSubExpr(), St);
        if (!V)
          return std::nullopt;
        return UO->getOpcode() == UO_Minus ? -*V : *V;
      }
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_Comma)
        return evalInt(BO->getRHS(), St);
      if (BO->isLogicalOp()) {
        // One false operand decides "&&" and one true operand decides "||".
        bool IsAnd = BO->getOpcode() == BO_LAnd;
        std::optional<bool> L = evalTruth(BO->getLHS(), St);
        std::optional<bool> R = evalTruth(BO->getRHS(), St);
        if ((L && *L != IsAnd) || (R && *R != IsAnd))
          return makeValue(T, !IsAnd);
        if (L && R)
          return makeValue(T, IsAnd);
        return std::nullopt;
      }
      if (BO->isComparisonOp()) {
        std::optional<llvm::APSInt> L = evalInt(BO->getLHS(), St);
        std::optional<llvm::APSInt> R = evalInt(BO->getRHS(), St);
        if (L && R) {
          int C = llvm::APSInt::compareValues(*L, *R);
          bool Result = false;
          switch (BO->getOpcode()) {
          case BO_LT: Result = C < 0; break;
          case BO_GT: Result = C > 0; break;
          case BO_LE: Result = C <= 0; break;
          case BO_GE: Result = C >= 0; break;
          case BO_EQ: Result = C == 0; break;
          case BO_NE: Result = C != 0; break;
          default: return std::nullopt;
          }
          return makeValue(T, Result);
        }
        // A value known to be nonzero still decides a test against zero.
        if (BO->isEqualityOp()) {
          const Expr *Other = nullptr;
          if (R && R->isZero())
            Other = BO->getLHS();
          else if (L && L->isZero())
            Other = BO->getRHS();
          if (Other)
            if (std::optional<bool> B = evalTruth(Other, St))
              if (*B)
                return makeValue(T, BO->getOpcode() == BO_NE);
        }
        return std::nullopt;
      }
    }

    Expr::EvalResult Result;
    if (!E->isValueDependent() && E->EvaluateAsInt(Result, Ctx))
      return Result.Val.getInt();
    if (T->isPointerType() &&
        E->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNotNull))
      return makeValue(T, 0);
    return std::nullopt;
  }

  /// Decide whether \p E is true if the facts of \p St determine it.
  std::optional<bool> evalTruth(const Expr *E, const State &St) const {
    bool Negated = false;
    E = stripCondition(E, Negated);
    if (!E)
      return std::nullopt;

    if (const VarDecl *VD = asVarRef(E)) {
      int I = varIndex(VD);
      if (I >= 0 && St.Vals[I].Kind == Value::Const)
        return (makeValue(VD->getType(), St.Vals[I].Bits) != 0) != Negated;
      if (I >= 0 && St.Vals[I].Kind == Value::NonZero)
        return !Negated;
    }
    if (std::optional<llvm::APSInt> V = evalInt(E, St))
      return (*V != 0) != Negated;
    if (isa<StringLiteral>(E->IgnoreParenImpCasts()))
      return !Negated;
    if (isNonNullAddress(E))
      return !Negated;

    bool Flip;
    int P = predIndex(E, Flip);
    if (P >= 0 && (St.Known & (1u << P)))
      return (bool(St.Truth & (1u << P)) != Flip) != Negated;
    return std::nullopt;
  }

  /// The address of an object or function, as in "table = some_array".
  bool isNonNullAddress(const Expr *E) const {
    E = E->IgnoreParenCasts();
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() != UO_AddrOf)
        return false;
      E = UO->getSubExpr()->IgnoreParens();
    } else if (!E->getType()->isArrayType() &&
               !E->getType()->isFunctionType()) {
      return false;
    }
    const auto *DRE = dyn_cast<DeclRefExpr>(E);
    return DRE && isa<VarDecl, FunctionDecl>(DRE->getDecl()) &&
           !DRE->getDecl()->isWeak();
  }

  /// Record that the branch condition \p Cond evaluated to \p Outcome.
  void assume(const Expr *Cond, bool Outcome, State &St) const {
    bool Negated = false;
    const Expr *E = stripCondition(Cond, Negated);
    if (!E)
      return;
    if (Negated)
      Outcome = !Outcome;

    // "a && b" is true only if both are, and "a || b" false only if both
    // are.
    if (const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts());
        BO && BO->isLogicalOp() &&
        (BO->getOpcode() == BO_LAnd) == Outcome) {
      assume(BO->getLHS(), Outcome, St);
      assume(BO->getRHS(), Outcome, St);
    }

    if (const VarDecl *VD = asVarRef(E)) {
      int I = varIndex(VD);
      if (I >= 0) {
        if (!Outcome) {
          St.Vals[I].Kind = Value::Const;
          St.Vals[I].Bits = 0;
        } else if (St.Vals[I].Kind == Value::Top) {
          St.Vals[I].Kind = Value::NonZero;
        }
        return;
      }
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts())) {
      if (BO->isEqualityOp()) {
        const VarDecl *VD = asVarRef(BO->getLHS());
        const Expr *Other = BO->getRHS();
        if (!VD || varIndex(VD) < 0) {
          VD = asVarRef(BO->getRHS());
          Other = BO->getLHS();
        }
        int I = VD ? varIndex(VD) : -1;
        if (I >= 0) {
          State Empty;
          if (std::optional<llvm::APSInt> K = evalInt(Other, Empty)) {
            bool Equal = (BO->getOpcode() == BO_EQ) == Outcome;
            if (Equal) {
              St.Vals[I].Kind = Value::Const;
              St.Vals[I].Bits = K->extOrTrunc(64).getZExtValue();
              return;
            }
            // "Not equal" is not a value.  Zero aside, it can only be kept
            // as the outcome of the condition itself, below.
            if (K->isZero() && St.Vals[I].Kind == Value::Top)
              St.Vals[I].Kind = Value::NonZero;
          }
        }
      }
    }

    bool Flip;
    int P = predIndex(E, Flip);
    if (P >= 0) {
      St.Known |= 1u << P;
      if (Outcome != Flip)
        St.Truth |= 1u << P;
      else
        St.Truth &= ~(1u << P);
    }
  }

  void forgetLocal(const VarDecl *VD, State &St) const {
    for (unsigned I = 0, E = Preds.size(); I != E; ++I)
      if (llvm::is_contained(Preds[I].Locals, VD))
        St.Known &= ~(1u << I);
  }

  void forgetMemory(State &St) const {
    for (unsigned I = 0, E = Preds.size(); I != E; ++I)
      if (Preds[I].ReadsMemory)
        St.Known &= ~(1u << I);
  }

  void store(const VarDecl *VD, const Expr *RHS, State &St) const {
    int I = varIndex(VD);
    if (I >= 0) {
      Value V;
      if (RHS) {
        if (std::optional<llvm::APSInt> K = evalInt(RHS, St)) {
          V.Kind = Value::Const;
          V.Bits = K->extOrTrunc(64).getZExtValue();
        } else if (std::optional<bool> B = evalTruth(RHS, St)) {
          if (*B)
            V.Kind = Value::NonZero;
        }
      }
      St.Vals[I] = V;
    }
    forgetLocal(VD, St);
  }

  /// \p E is read or written.  If that goes through a tracked pointer, the
  /// pointer is not null from here on, and a path that knows it to be null
  /// ends here.
  void noteAccess(const Expr *E, State &St) const {
    for (;;) {
      E = E->IgnoreParens();
      const Expr *Pointer = nullptr;
      if (const auto *ME = dyn_cast<MemberExpr>(E)) {
        if (!ME->isArrow()) {
          E = ME->getBase();
          continue;
        }
        Pointer = ME->getBase();
      } else if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
        if (UO->getOpcode() != UO_Deref)
          return;
        Pointer = UO->getSubExpr();
      } else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
        const Expr *Base = ASE->getBase()->IgnoreParens();
        if (const auto *ICE = dyn_cast<ImplicitCastExpr>(Base);
            ICE && ICE->getCastKind() == CK_ArrayToPointerDecay) {
          E = ICE->getSubExpr();
          continue;
        }
        Pointer = Base;
      } else {
        return;
      }
      const VarDecl *VD = asVarRef(Pointer);
      int I = VD && VD->getType()->isPointerType() ? varIndex(VD) : -1;
      if (I < 0)
        return;
      Value &V = St.Vals[I];
      if (V.Kind == Value::Const && V.Bits == 0)
        St.Dead = true;
      else if (V.Kind == Value::Top)
        V.Kind = Value::NonZero;
      return;
    }
  }

  void transfer(const Stmt *S, State &St) {
    if (S == Use && !St.XInit) {
      UseReachedUninit = true;
      return;
    }
    if (initializesX(S))
      St.XInit = true;

    if (const auto *ICE = dyn_cast<ImplicitCastExpr>(S)) {
      if (ICE->getCastKind() == CK_LValueToRValue)
        noteAccess(ICE->getSubExpr(), St);
      return;
    }

    if (const auto *DS = dyn_cast<DeclStmt>(S)) {
      for (const Decl *D : DS->decls()) {
        const auto *VD = dyn_cast<VarDecl>(D);
        if (!VD)
          continue;
        if (VD == X && !(X->getInit() && !getSelfInitExpr(X)))
          St.XInit = false;
        if (VD->hasLocalStorage())
          store(VD, VD->getInit(), St);
      }
      return;
    }
    if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
      if (!BO->isAssignmentOp())
        return;
      noteAccess(BO->getLHS(), St);
      if (const VarDecl *VD = asVarRef(BO->getLHS());
          VD && VD->hasLocalStorage() && !AddressTaken.count(VD))
        store(VD, BO->getOpcode() == BO_Assign ? BO->getRHS() : nullptr, St);
      else
        forgetMemory(St);
      return;
    }
    if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
      if (!UO->isIncrementDecrementOp())
        return;
      if (const VarDecl *VD = asVarRef(UO->getSubExpr());
          VD && VD->hasLocalStorage() && !AddressTaken.count(VD))
        store(VD, nullptr, St);
      else
        forgetMemory(St);
      return;
    }
    if (const auto *CE = dyn_cast<CallExpr>(S)) {
      unsigned ID = CE->getBuiltinCallee();
      if (ID == Builtin::BI__builtin_expect ||
          ID == Builtin::BI__builtin_expect_with_probability ||
          ID == Builtin::BI__builtin_constant_p)
        return;
      const FunctionDecl *FD = CE->getDirectCallee();
      if (FD && (FD->hasAttr<ConstAttr>() || FD->hasAttr<PureAttr>()))
        return;
      forgetMemory(St);
      return;
    }
    if (const auto *AS = dyn_cast<GCCAsmStmt>(S)) {
      for (unsigned I = 0, E = AS->getNumOutputs(); I != E; ++I)
        if (const VarDecl *VD = asVarRef(AS->getOutputExpr(I)))
          store(VD, nullptr, St);
      forgetMemory(St);
    }
  }

  using StateMap = llvm::DenseMap<unsigned, SmallVector<State, 2>>;

  /// Whether the value \p V selects the case \p CS.
  bool matchesCase(const CaseStmt *CS, const llvm::APSInt &V) const {
    llvm::APSInt Low = CS->getLHS()->EvaluateKnownConstInt(Ctx);
    if (!CS->getRHS())
      return llvm::APSInt::isSameValue(Low, V);
    llvm::APSInt High = CS->getRHS()->EvaluateKnownConstInt(Ctx);
    return llvm::APSInt::compareValues(Low, V) <= 0 &&
           llvm::APSInt::compareValues(V, High) <= 0;
  }

  /// Refine \p St for the edge from a switch on the tracked variable with
  /// index \p I to its successor \p Next.  Returns false if the edge cannot
  /// be taken with the value the variable is known to have.
  bool assumeSwitchEdge(const SwitchStmt *SS, const CFGBlock *Next, unsigned I,
                        State &St) const {
    const CaseStmt *Taken = nullptr;
    if (const auto *CS = dyn_cast_or_null<CaseStmt>(Next->getLabel()))
      for (const SwitchCase *SC = SS->getSwitchCaseList(); SC;
           SC = SC->getNextSwitchCase())
        if (SC == CS)
          Taken = CS;

    Value &V = St.Vals[I];
    QualType T = Vars[I]->getType();
    auto SelectsSomeCase = [&](const llvm::APSInt &Known) {
      for (const SwitchCase *SC = SS->getSwitchCaseList(); SC;
           SC = SC->getNextSwitchCase())
        if (const auto *CS = dyn_cast<CaseStmt>(SC))
          if (matchesCase(CS, Known))
            return true;
      return false;
    };

    if (!Taken) {
      // The default label, or the statement after a switch without one.  The
      // variable has none of the case values here.
      if (V.Kind == Value::Const)
        return !SelectsSomeCase(makeValue(T, V.Bits));
      if (V.Kind == Value::Top && SelectsSomeCase(makeValue(T, 0)))
        V.Kind = Value::NonZero;
      for (unsigned P = 0, E = Preds.size(); P != E; ++P) {
        llvm::APSInt K;
        bool IsNE;
        if (!isEqualityWith(Preds[P], I, K, IsNE) || !SelectsSomeCase(K))
          continue;
        St.Known |= 1u << P;
        if (IsNE)
          St.Truth |= 1u << P;
        else
          St.Truth &= ~(1u << P);
      }
      return true;
    }

    if (V.Kind == Value::Const)
      return matchesCase(Taken, makeValue(T, V.Bits));
    if (Taken->getRHS())
      return true;
    llvm::APSInt K = Taken->getLHS()->EvaluateKnownConstInt(Ctx);
    if (V.Kind == Value::NonZero && K.isZero())
      return false;
    // An earlier default edge or test may have excluded this value.
    for (unsigned P = 0, E = Preds.size(); P != E; ++P) {
      llvm::APSInt Other;
      bool IsNE;
      if (!(St.Known & (1u << P)) ||
          !isEqualityWith(Preds[P], I, Other, IsNE) ||
          !llvm::APSInt::isSameValue(Other, K))
        continue;
      bool Holds = St.Truth & (1u << P);
      if (Holds == IsNE)
        return false;
    }
    V.Kind = Value::Const;
    V.Bits = K.extOrTrunc(64).getZExtValue();
    return true;
  }

  bool addState(StateMap &In, const CFGBlock *B, const State &St) {
    SmallVectorImpl<State> &Set = In[B->getBlockID()];
    if (llvm::is_contained(Set, St))
      return false;
    if (Set.size() >= MaxStatesPerBlock || ++States > MaxStates) {
      GaveUp = true;
      return false;
    }
    Set.push_back(St);
    return true;
  }

public:
  CorrelatedUninitPruner(const CFG &Cfg, AnalysisDeclContext &AC,
                         const ClassifyRefs &Classification)
      : Cfg(Cfg), AC(AC), Ctx(AC.getASTContext()),
        Classification(Classification),
        DC(cast<DeclContext>(AC.getDecl())) {}

  /// Returns true if \p UseExpr cannot be reached with \p VD uninitialized
  /// without contradicting a condition established earlier on the path.
  bool isUseInfeasible(const VarDecl *VD, const Expr *UseExpr,
                       const CFGBlock *UseBlock) {
    if (FunctionSteps > MaxFunctionSteps)
      return false;
    prepare();
    X = VD;
    Use = UseExpr;
    Vars.clear();
    Preds.clear();
    Steps = 0;
    States = 0;
    UseReachedUninit = false;
    GaveUp = false;

    // Choose the conditions to track: those that decide whether the use or
    // an initialization is reached.
    addDominatingConditions(UseBlock);
    auto Inits = InitBlocks.find(X);
    if (Inits != InitBlocks.end())
      for (const CFGBlock *B : Inits->second)
        addDominatingConditions(B);
    if (Vars.empty() && Preds.empty())
      return false;

    StateMap In;
    llvm::DenseMap<unsigned, unsigned> Done;
    SmallVector<const CFGBlock *, 32> Worklist;

    const CFGBlock *Entry = &Cfg.getEntry();
    In[Entry->getBlockID()].push_back(State());
    Worklist.push_back(Entry);

    while (!Worklist.empty()) {
      const CFGBlock *B = Worklist.pop_back_val();
      unsigned ID = B->getBlockID();
      while (Done[ID] < In[ID].size()) {
        State St = In[ID][Done[ID]++];
        ++FunctionSteps;
        if (++Steps > MaxSteps)
          return false;
        for (const CFGElement &Elem : *B) {
          if (std::optional<CFGStmt> CS = Elem.getAs<CFGStmt>())
            transfer(CS->getStmt(), St);
          ++FunctionSteps;
          if (UseReachedUninit || ++Steps > MaxSteps)
            return false;
          if (St.Dead)
            break;
        }
        if (St.Dead)
          continue;
        if (const auto *AS = dyn_cast_or_null<GCCAsmStmt>(B->getTerminatorStmt()))
          transfer(AS, St);

        if (isConditionalBranch(B)) {
          const Expr *Cond = getBranchCondition(B);
          std::optional<bool> Known = evalTruth(Cond, St);
          unsigned Index = 0;
          for (const CFGBlock::AdjacentBlock &Succ : B->succs()) {
            bool Outcome = Index++ == 0;
            const CFGBlock *Next = Succ.getReachableBlock();
            if (!Next || (Known && *Known != Outcome))
              continue;
            State Refined = St;
            if (!Known)
              assume(Cond, Outcome, Refined);
            if (addState(In, Next, Refined))
              Worklist.push_back(Next);
          }
        } else {
          // A switch on a tracked variable takes only the case that its
          // known value selects, and each case edge makes the value known.
          const auto *SS = dyn_cast_or_null<SwitchStmt>(B->getTerminatorStmt());
          int Switched = SS ? varIndex(getSwitchVariable(SS)) : -1;
          for (const CFGBlock::AdjacentBlock &Succ : B->succs()) {
            const CFGBlock *Next = Succ.getReachableBlock();
            if (!Next)
              continue;
            State Refined = St;
            if (Switched >= 0 && !assumeSwitchEdge(SS, Next, Switched, Refined))
              continue;
            if (addState(In, Next, Refined))
              Worklist.push_back(Next);
          }
        }
        if (GaveUp)
          return false;
      }
    }
    return true;
  }
};

} // namespace

//------------------------------------------------------------------------====//
// Transfer function for uninitialized values analysis.
//====------------------------------------------------------------------------//

namespace {

class TransferFunctions : public ConstStmtVisitor<TransferFunctions> {
  CFGBlockValues &vals;
  const CFG &cfg;
  const CFGBlock *block;
  AnalysisDeclContext &ac;
  const ClassifyRefs &classification;
  ObjCNoReturn objCNoRet;
  UninitVariablesHandler &handler;
  CorrelatedUninitPruner *pruner;

public:
  TransferFunctions(CFGBlockValues &vals, const CFG &cfg,
                    const CFGBlock *block, AnalysisDeclContext &ac,
                    const ClassifyRefs &classification,
                    UninitVariablesHandler &handler,
                    CorrelatedUninitPruner *pruner)
      : vals(vals), cfg(cfg), block(block), ac(ac),
        classification(classification), objCNoRet(ac.getASTContext()),
        handler(handler), pruner(pruner) {}

  void reportUse(const Expr *ex, const VarDecl *vd);
  void reportCleanup(const VarDecl *vd, const Stmt *leave);
  void reportConstRefUse(const Expr *ex, const VarDecl *vd);
  void reportConstPtrUse(const Expr *ex, const VarDecl *vd);

  void VisitBinaryOperator(const BinaryOperator *bo);
  void VisitBlockExpr(const BlockExpr *be);
  void VisitCallExpr(const CallExpr *ce);
  void VisitDeclRefExpr(const DeclRefExpr *dr);
  void VisitDeclStmt(const DeclStmt *ds);
  void VisitGCCAsmStmt(const GCCAsmStmt *as);
  void VisitObjCForCollectionStmt(const ObjCForCollectionStmt *FS);
  void VisitObjCMessageExpr(const ObjCMessageExpr *ME);
  void VisitOMPExecutableDirective(const OMPExecutableDirective *ED);

  bool isTrackedVar(const VarDecl *vd) {
    return ::isTrackedVar(vd, cast<DeclContext>(ac.getDecl()));
  }

  FindVarResult findVar(const Expr *ex) {
    return ::findVar(ex, cast<DeclContext>(ac.getDecl()));
  }

  UninitUse getUninitUse(const Expr *ex, const VarDecl *vd, Value v) {
    UninitUse Use(ex, isAlwaysUninit(v));

    assert(isUninitialized(v));
    if (Use.getKind() == UninitUse::Always)
      return Use;

    // If an edge which leads unconditionally to this use did not initialize
    // the variable, we can say something stronger than 'may be uninitialized':
    // we can say 'either it's used uninitialized or you have dead code'.
    //
    // We track the number of successors of a node which have been visited, and
    // visit a node once we have visited all of its successors. Only edges where
    // the variable might still be uninitialized are followed. Since a variable
    // can't transfer from being initialized to being uninitialized, this will
    // trace out the subgraph which inevitably leads to the use and does not
    // initialize the variable. We do not want to skip past loops, since their
    // non-termination might be correlated with the initialization condition.
    //
    // For example:
    //
    //         void f(bool a, bool b) {
    // block1:   int n;
    //           if (a) {
    // block2:     if (b)
    // block3:       n = 1;
    // block4:   } else if (b) {
    // block5:     while (!a) {
    // block6:       do_work(&a);
    //               n = 2;
    //             }
    //           }
    // block7:   if (a)
    // block8:     g();
    // block9:   return n;
    //         }
    //
    // Starting from the maybe-uninitialized use in block 9:
    //  * Block 7 is not visited because we have only visited one of its two
    //    successors.
    //  * Block 8 is visited because we've visited its only successor.
    // From block 8:
    //  * Block 7 is visited because we've now visited both of its successors.
    // From block 7:
    //  * Blocks 1, 2, 4, 5, and 6 are not visited because we didn't visit all
    //    of their successors (we didn't visit 4, 3, 5, 6, and 5, respectively).
    //  * Block 3 is not visited because it initializes 'n'.
    // Now the algorithm terminates, having visited blocks 7 and 8, and having
    // found the frontier is blocks 2, 4, and 5.
    //
    // 'n' is definitely uninitialized for two edges into block 7 (from blocks 2
    // and 4), so we report that any time either of those edges is taken (in
    // each case when 'b == false'), 'n' is used uninitialized.
    SmallVector<const CFGBlock*, 32> Queue;
    SmallVector<unsigned, 32> SuccsVisited(cfg.getNumBlockIDs(), 0);
    Queue.push_back(block);
    // Specify that we've already visited all successors of the starting block.
    // This has the dual purpose of ensuring we never add it to the queue, and
    // of marking it as not being a candidate element of the frontier.
    SuccsVisited[block->getBlockID()] = block->succ_size();
    while (!Queue.empty()) {
      const CFGBlock *B = Queue.pop_back_val();

      // If the use is always reached from the entry block, make a note of that.
      if (B == &cfg.getEntry())
        Use.setUninitAfterCall();

      for (CFGBlock::const_pred_iterator I = B->pred_begin(), E = B->pred_end();
           I != E; ++I) {
        const CFGBlock *Pred = *I;
        if (!Pred)
          continue;

        Value AtPredExit = vals.getValue(Pred, vd);
        if (AtPredExit == Initialized)
          // This block initializes the variable.
          continue;
        if (AtPredExit == MayUninitialized &&
            vals.getValue(B, vd) == Uninitialized) {
          // This block declares the variable (uninitialized), and is reachable
          // from a block that initializes the variable. We can't guarantee to
          // give an earlier location for the diagnostic (and it appears that
          // this code is intended to be reachable) so give a diagnostic here
          // and go no further down this path.
          Use.setUninitAfterDecl();
          continue;
        }

        unsigned &SV = SuccsVisited[Pred->getBlockID()];
        if (!SV) {
          // When visiting the first successor of a block, mark all NULL
          // successors as having been visited.
          for (CFGBlock::const_succ_iterator SI = Pred->succ_begin(),
                                             SE = Pred->succ_end();
               SI != SE; ++SI)
            if (!*SI)
              ++SV;
        }

        if (++SV == Pred->succ_size())
          // All paths from this block lead to the use and don't initialize the
          // variable.
          Queue.push_back(Pred);
      }
    }

    // Scan the frontier, looking for blocks where the variable was
    // uninitialized.
    for (const auto *Block : cfg) {
      if (vals.getValue(Block, vd) != Uninitialized)
        continue;
      unsigned BlockID = Block->getBlockID();
      const Stmt *Term = Block->getTerminatorStmt();
      if (SuccsVisited[BlockID] && SuccsVisited[BlockID] < Block->succ_size() &&
          Term) {
        // This block inevitably leads to the use. If we have an edge from here
        // to a post-dominator block, and the variable is uninitialized on that
        // edge, we have found a bug.
        for (CFGBlock::const_succ_iterator I = Block->succ_begin(),
             E = Block->succ_end(); I != E; ++I) {
          const CFGBlock *Succ = *I;
          if (Succ && SuccsVisited[Succ->getBlockID()] >= Succ->succ_size()) {
            // Switch cases are a special case: report the label to the caller
            // as the 'terminator', not the switch statement itself. Suppress
            // situations where no label matched: we can't be sure that's
            // possible.
            if (isa<SwitchStmt>(Term)) {
              const Stmt *Label = Succ->getLabel();
              if (!Label || !isa<SwitchCase>(Label))
                // Might not be possible.
                continue;
              UninitUse::Branch Branch;
              Branch.Terminator = Label;
              Branch.Output = 0; // Ignored.
              Use.addUninitBranch(Branch);
            } else {
              UninitUse::Branch Branch;
              Branch.Terminator = Term;
              Branch.Output = I - Block->succ_begin();
              Use.addUninitBranch(Branch);
            }
          }
        }
      }
    }

    return Use;
  }
};

} // namespace

void TransferFunctions::reportUse(const Expr *ex, const VarDecl *vd) {
  Value v = vals[vd];
  if (!isUninitialized(v))
    return;
  UninitUse Use = getUninitUse(ex, vd, v);
  if (pruner && Use.getKind() == UninitUse::Maybe &&
      pruner->isUseInfeasible(vd, ex, block))
    Use.setCorrelated();
  handler.handleUseOfUninitVariable(vd, Use);
}

/// Whether \p FD does nothing but overwrite the object that its parameter
/// points to, as a function that wipes a key does.  Such a cleanup function
/// does not read the variable.
static bool onlyOverwritesArgument(const FunctionDecl *FD) {
  const FunctionDecl *Def = nullptr;
  if (!FD || !FD->hasBody(Def) || Def->getNumParams() != 1)
    return false;
  const auto *Body = dyn_cast<CompoundStmt>(Def->getBody());
  if (!Body || Body->body_empty())
    return false;
  for (const Stmt *S : Body->body()) {
    const auto *E = dyn_cast<Expr>(S);
    const auto *Call =
        dyn_cast_or_null<CallExpr>(E ? E->IgnoreParenImpCasts() : nullptr);
    const FunctionDecl *Callee = Call ? Call->getDirectCallee() : nullptr;
    if (!Callee || !Callee->getIdentifier() || Call->getNumArgs() < 1)
      return false;
    if (!llvm::StringSwitch<bool>(Callee->getName())
             .Cases({"memset", "__builtin_memset", "bzero", "__builtin_bzero"},
                    true)
             .Cases({"explicit_bzero", "memset_explicit", "memset_s",
                     "memzero_explicit"},
                    true)
             .Default(false))
      return false;
    const auto *Arg = dyn_cast<DeclRefExpr>(Call->getArg(0)->IgnoreParenCasts());
    if (!Arg || Arg->getDecl() != Def->getParamDecl(0))
      return false;
  }
  return true;
}

/// The cleanup function of \p vd runs here.  It is handed the address of the
/// variable and reads it, so an uninitialized variable is used.
void TransferFunctions::reportCleanup(const VarDecl *vd, const Stmt *leave) {
  if (!handler.wantsCleanupUses() || !isTrackedVar(vd))
    return;
  if (const auto *A = vd->getAttr<CleanupAttr>())
    if (onlyOverwritesArgument(A->getFunctionDecl()))
      return;
  Value v = vals[vd];
  if (isUninitialized(v))
    handler.handleUninitCleanup(vd, isAlwaysUninit(v), leave);
}

void TransferFunctions::reportConstRefUse(const Expr *ex, const VarDecl *vd) {
  Value v = vals[vd];
  if (isAlwaysUninit(v)) {
    auto use = getUninitUse(ex, vd, v);
    use.setConstRefUse();
    handler.handleUseOfUninitVariable(vd, use);
  }
}

void TransferFunctions::reportConstPtrUse(const Expr *ex, const VarDecl *vd) {
  Value v = vals[vd];
  if (isAlwaysUninit(v)) {
    auto use = getUninitUse(ex, vd, v);
    use.setConstPtrUse();
    handler.handleUseOfUninitVariable(vd, use);
  }
}

void TransferFunctions::VisitObjCForCollectionStmt(
    const ObjCForCollectionStmt *FS) {
  // This represents an initialization of the 'element' value.
  if (const auto *DS = dyn_cast<DeclStmt>(FS->getElement())) {
    const auto *VD = cast<VarDecl>(DS->getSingleDecl());
    if (isTrackedVar(VD))
      vals[VD] = Initialized;
  }
}

void TransferFunctions::VisitOMPExecutableDirective(
    const OMPExecutableDirective *ED) {
  for (const Stmt *S :
       OMPExecutableDirective::used_clauses_children(ED->clauses())) {
    assert(S && "Expected non-null used-in-clause child.");
    Visit(S);
  }
  if (!ED->isStandaloneDirective())
    Visit(ED->getStructuredBlock());
}

void TransferFunctions::VisitBlockExpr(const BlockExpr *be) {
  const BlockDecl *bd = be->getBlockDecl();
  for (const auto &I : bd->captures()) {
    const VarDecl *vd = I.getVariable();
    if (!isTrackedVar(vd))
      continue;
    if (I.isByRef()) {
      vals[vd] = Initialized;
      continue;
    }
    reportUse(be, vd);
  }
}

void TransferFunctions::VisitCallExpr(const CallExpr *ce) {
  if (const Decl *Callee = ce->getCalleeDecl()) {
    if (Callee->hasAttr<ReturnsTwiceAttr>()) {
      // After a call to a function like setjmp or vfork, any variable which is
      // initialized anywhere within this function may now be initialized. For
      // now, just assume such a call initializes all variables.  FIXME: Only
      // mark variables as initialized if they have an initializer which is
      // reachable from here.
      vals.setAllScratchValues(Initialized);
    }
    else if (Callee->hasAttr<AnalyzerNoReturnAttr>()) {
      // Functions labeled like "analyzer_noreturn" are often used to denote
      // "panic" functions that in special debug situations can still return,
      // but for the most part should not be treated as returning.  This is a
      // useful annotation borrowed from the static analyzer that is useful for
      // suppressing branch-specific false positives when we call one of these
      // functions but keep pretending the path continues (when in reality the
      // user doesn't care).
      vals.setAllScratchValues(Unknown);
    }
  }
}

void TransferFunctions::VisitDeclRefExpr(const DeclRefExpr *dr) {
  switch (classification.get(dr)) {
  case ClassifyRefs::Ignore:
    break;
  case ClassifyRefs::Use:
    reportUse(dr, cast<VarDecl>(dr->getDecl()));
    break;
  case ClassifyRefs::Init:
    vals[cast<VarDecl>(dr->getDecl())] = Initialized;
    break;
  case ClassifyRefs::SelfInit:
    handler.handleSelfInit(cast<VarDecl>(dr->getDecl()));
    break;
  case ClassifyRefs::ConstRefUse:
    reportConstRefUse(dr, cast<VarDecl>(dr->getDecl()));
    break;
  case ClassifyRefs::ConstPtrUse:
    reportConstPtrUse(dr, cast<VarDecl>(dr->getDecl()));
    break;
  }
}

void TransferFunctions::VisitBinaryOperator(const BinaryOperator *BO) {
  if (BO->getOpcode() == BO_Assign) {
    FindVarResult Var = findVar(BO->getLHS());
    if (const VarDecl *VD = Var.getDecl())
      vals[VD] = Initialized;
  }
}

void TransferFunctions::VisitDeclStmt(const DeclStmt *DS) {
  for (const Decl *DI : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(DI);
    if (VD && isTrackedVar(VD)) {
      if (getSelfInitExpr(VD)) {
        // If the initializer consists solely of a reference to itself, we
        // explicitly mark the variable as uninitialized. This allows code
        // like the following:
        //
        //   int x = x;
        //
        // to deliberately leave a variable uninitialized. Different analysis
        // clients can detect this pattern and adjust their reporting
        // appropriately, but we need to continue to analyze subsequent uses
        // of the variable.
        vals[VD] = Uninitialized;
      } else if (VD->getInit()) {
        // Treat the new variable as initialized.
        vals[VD] = Initialized;
      } else {
        // No initializer: the variable is now uninitialized. This matters
        // for cases like:
        //   while (...) {
        //     int n;
        //     use(n);
        //     n = 0;
        //   }
        // FIXME: Mark the variable as uninitialized whenever its scope is
        // left, since its scope could be re-entered by a jump over the
        // declaration.
        vals[VD] = Uninitialized;
      }
    }
  }
}

void TransferFunctions::VisitGCCAsmStmt(const GCCAsmStmt *as) {
  // An "asm goto" statement is a terminator that may initialize some variables.
  if (!as->isAsmGoto())
    return;

  ASTContext &C = ac.getASTContext();
  for (const Expr *O : as->outputs()) {
    const Expr *Ex = stripCasts(C, O);

    // Strip away any unary operators. Invalid l-values are reported by other
    // semantic analysis passes.
    while (const auto *UO = dyn_cast<UnaryOperator>(Ex))
      Ex = stripCasts(C, UO->getSubExpr());

    // Mark the variable as potentially uninitialized for those cases where
    // it's used on an indirect path, where it's not guaranteed to be
    // defined.
    if (const VarDecl *VD = findVar(Ex).getDecl())
      if (vals[VD] != Initialized)
        vals[VD] = MayUninitialized;
  }
}

void TransferFunctions::VisitObjCMessageExpr(const ObjCMessageExpr *ME) {
  // If the Objective-C message expression is an implicit no-return that
  // is not modeled in the CFG, set the tracked dataflow values to Unknown.
  if (objCNoRet.isImplicitNoReturn(ME)) {
    vals.setAllScratchValues(Unknown);
  }
}

//------------------------------------------------------------------------====//
// High-level "driver" logic for uninitialized values analysis.
//====------------------------------------------------------------------------//

static bool runOnBlock(const CFGBlock *block, const CFG &cfg,
                       AnalysisDeclContext &ac, CFGBlockValues &vals,
                       const ClassifyRefs &classification,
                       llvm::BitVector &wasAnalyzed,
                       UninitVariablesHandler &handler,
                       CorrelatedUninitPruner *pruner = nullptr) {
  wasAnalyzed[block->getBlockID()] = true;
  vals.resetScratch();
  // Merge in values of predecessor blocks.
  bool isFirst = true;
  for (CFGBlock::const_pred_iterator I = block->pred_begin(),
       E = block->pred_end(); I != E; ++I) {
    const CFGBlock *pred = *I;
    if (!pred)
      continue;
    if (wasAnalyzed[pred->getBlockID()]) {
      vals.mergeIntoScratch(vals.getValueVector(pred), isFirst);
      isFirst = false;
    }
  }
  // Apply the transfer function.
  TransferFunctions tf(vals, cfg, block, ac, classification, handler, pruner);
  // The statement that leaves the scopes whose cleanup functions follow it.
  const Stmt *leave = nullptr;
  if (const Stmt *term = block->getTerminatorStmt())
    if (isa<GotoStmt, BreakStmt, ContinueStmt>(term))
      leave = term;
  for (const auto &I : *block) {
    if (std::optional<CFGStmt> cs = I.getAs<CFGStmt>()) {
      tf.Visit(const_cast<Stmt *>(cs->getStmt()));
      if (isa<ReturnStmt>(cs->getStmt()))
        leave = cs->getStmt();
    } else if (std::optional<CFGCleanupFunction> cf =
                   I.getAs<CFGCleanupFunction>()) {
      tf.reportCleanup(cf->getVarDecl(), leave);
    }
  }
  CFGTerminator terminator = block->getTerminator();
  if (auto *as = dyn_cast_or_null<GCCAsmStmt>(terminator.getStmt()))
    if (as->isAsmGoto())
      tf.Visit(as);
  return vals.updateValueVectorWithScratch(block);
}

namespace {

/// PruneBlocksHandler is a special UninitVariablesHandler that is used
/// to detect when a CFGBlock has any *potential* use of an uninitialized
/// variable.  It is mainly used to prune out work during the final
/// reporting pass.
struct PruneBlocksHandler : public UninitVariablesHandler {
  /// Records if a CFGBlock had a potential use of an uninitialized variable.
  llvm::BitVector hadUse;

  /// Records if any CFGBlock had a potential use of an uninitialized variable.
  bool hadAnyUse = false;

  /// The current block to scribble use information.
  unsigned currentBlock = 0;

  /// Whether the handler that this one stands in for wants cleanup uses.
  bool cleanupUses = false;

  PruneBlocksHandler(unsigned numBlocks) : hadUse(numBlocks, false) {}

  ~PruneBlocksHandler() override = default;

  bool wantsCleanupUses() const override { return cleanupUses; }

  void handleUninitCleanup(const VarDecl *vd, bool alwaysUninit,
                           const Stmt *leave) override {
    hadUse[currentBlock] = true;
    hadAnyUse = true;
  }

  void handleUseOfUninitVariable(const VarDecl *vd,
                                 const UninitUse &use) override {
    hadUse[currentBlock] = true;
    hadAnyUse = true;
  }

  /// Called when the uninitialized variable analysis detects the
  /// idiom 'int x = x'.  All other uses of 'x' within the initializer
  /// are handled by handleUseOfUninitVariable.
  void handleSelfInit(const VarDecl *vd) override {
    hadUse[currentBlock] = true;
    hadAnyUse = true;
  }
};

} // namespace

void clang::runUninitializedVariablesAnalysis(
    const DeclContext &dc,
    const CFG &cfg,
    AnalysisDeclContext &ac,
    UninitVariablesHandler &handler,
    UninitVariablesAnalysisStats &stats) {
  CFGBlockValues vals(cfg);
  vals.computeSetOfDeclarations(dc);
  if (vals.hasNoDeclarations())
    return;

  stats.NumVariablesAnalyzed = vals.getNumEntries();

  // Precompute which expressions are uses and which are initializations.
  ClassifyRefs classification(ac);
  cfg.VisitBlockStmts(classification);

  // Mark all variables uninitialized at the entry.
  const CFGBlock &entry = cfg.getEntry();
  ValueVector &vec = vals.getValueVector(&entry);
  const unsigned n = vals.getNumEntries();
  for (unsigned j = 0; j < n; ++j) {
    vec[j] = Uninitialized;
  }

  // Proceed with the workist.
  ForwardDataflowWorklist worklist(cfg, ac);
  llvm::BitVector previouslyVisited(cfg.getNumBlockIDs());
  worklist.enqueueSuccessors(&cfg.getEntry());
  llvm::BitVector wasAnalyzed(cfg.getNumBlockIDs(), false);
  wasAnalyzed[cfg.getEntry().getBlockID()] = true;
  PruneBlocksHandler PBH(cfg.getNumBlockIDs());
  PBH.cleanupUses = handler.wantsCleanupUses();

  while (const CFGBlock *block = worklist.dequeue()) {
    PBH.currentBlock = block->getBlockID();

    // Did the block change?
    bool changed = runOnBlock(block, cfg, ac, vals,
                              classification, wasAnalyzed, PBH);
    ++stats.NumBlockVisits;
    if (changed || !previouslyVisited[block->getBlockID()])
      worklist.enqueueSuccessors(block);
    previouslyVisited[block->getBlockID()] = true;
  }

  if (!PBH.hadAnyUse)
    return;

  // Run through the blocks one more time, and report uninitialized variables.
  std::optional<CorrelatedUninitPruner> pruner;
  if (handler.wantsCorrelationPruning())
    pruner.emplace(cfg, ac, classification);
  for (const auto *block : cfg)
    if (PBH.hadUse[block->getBlockID()]) {
      runOnBlock(block, cfg, ac, vals, classification, wasAnalyzed, handler,
                 pruner ? &*pruner : nullptr);
      ++stats.NumBlockVisits;
    }
}

UninitVariablesHandler::~UninitVariablesHandler() = default;
