//===- QEMUGuestMemorySafetyChecker.cpp -------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This experimental checker discovers QEMU input callbacks and successful
// guest-buffer reads, preserves their provenance through common request and
// byte-order helpers, and relates tainted indexes and memory-operation lengths
// to host object extents. A Level A report has no feasible in-bounds state. A
// Level B report has both in-bounds and out-of-bounds states and needs manual
// review.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DynamicRecursiveASTVisitor.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/DynamicExtent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace clang;
using namespace ento;

REGISTER_MAP_WITH_PROGRAMSTATE(QEMUPendingAllocationSizes, const Expr *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUSavedTaintedScalars, const VarRegion *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUPersistentFieldSources, SymbolRef,
                               const FieldDecl *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUPersistentLocalSources, const VarRegion *,
                               const FieldDecl *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInputClasses, SymbolRef, unsigned)
REGISTER_SET_WITH_PROGRAMSTATE(QEMUVirtqueueElements, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(QEMUVirtqueueIovecs, const MemRegion *)

namespace {

enum class InputClass {
  MMIO,
  PIO,
  DMA,
  Migration,
  Network,
  DiskImage,
  Virtio,
  Virtqueue,
  Mixed
};

struct CallbackInfo {
  uint64_t ParameterMask = 0;
  uint64_t PointeeMask = 0;
  InputClass Source = InputClass::MMIO;
  std::optional<uint64_t> AddressLimit;
  std::optional<unsigned> AddressParameter;
  std::optional<unsigned> AccessSizeParameter;
  std::optional<uint64_t> AccessSizeLimit;
  std::optional<unsigned> DataParameter;
  std::optional<uint64_t> DataMaximum;
};

struct BoundStates {
  ProgramStateRef Safe;
  ProgramStateRef Unsafe;
};

struct ShiftedBoundPredicate {
  unsigned Parameter;
  unsigned Shift;
  uint64_t ExclusiveLimit;
};

struct ValidatedFieldBound {
  const FieldDecl *LimitField;
  bool Inclusive;
};

static const InitListExpr *semanticInitList(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  while (const auto *CE = dyn_cast<ConstantExpr>(E))
    E = CE->getSubExpr()->IgnoreParenImpCasts();
  const auto *ILE = dyn_cast<InitListExpr>(E);
  if (!ILE)
    return nullptr;
  if (!ILE->isSemanticForm())
    if (const InitListExpr *Semantic = ILE->getSemanticForm())
      ILE = Semantic;
  return ILE;
}

static const Expr *fieldInitializer(const InitListExpr *ILE, StringRef Name) {
  ILE = semanticInitList(ILE);
  if (!ILE)
    return nullptr;
  const RecordDecl *RD = ILE->getType()->getAsRecordDecl();
  if (!RD)
    return nullptr;

  unsigned Index = 0;
  for (const FieldDecl *FD : RD->fields()) {
    if (FD->getName() == Name)
      return Index < ILE->getNumInits() ? ILE->getInit(Index) : nullptr;
    ++Index;
  }
  return nullptr;
}

static const FunctionDecl *referencedFunction(const Expr *E) {
  if (!E || isa<ImplicitValueInitExpr>(E))
    return nullptr;
  E = E->IgnoreParenImpCasts();
  while (true) {
    if (const auto *CE = dyn_cast<ConstantExpr>(E)) {
      E = CE->getSubExpr()->IgnoreParenImpCasts();
      continue;
    }
    if (const auto *Cast = dyn_cast<CastExpr>(E)) {
      E = Cast->getSubExpr()->IgnoreParenImpCasts();
      continue;
    }
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_AddrOf) {
        E = UO->getSubExpr()->IgnoreParenImpCasts();
        continue;
      }
    }
    break;
  }
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    if (const auto *FD = dyn_cast<FunctionDecl>(DRE->getDecl()))
      return FD->getCanonicalDecl();
  return nullptr;
}

static const VarDecl *referencedVariable(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  while (true) {
    if (const auto *CE = dyn_cast<ConstantExpr>(E)) {
      E = CE->getSubExpr()->IgnoreParenImpCasts();
      continue;
    }
    if (const auto *Cast = dyn_cast<CastExpr>(E)) {
      E = Cast->getSubExpr()->IgnoreParenImpCasts();
      continue;
    }
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_AddrOf) {
        E = UO->getSubExpr()->IgnoreParenImpCasts();
        continue;
      }
    }
    break;
  }
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      return VD->getCanonicalDecl();
  return nullptr;
}

static StringRef inputClassName(InputClass Source) {
  switch (Source) {
  case InputClass::MMIO:
    return "MMIO";
  case InputClass::PIO:
    return "PIO";
  case InputClass::DMA:
    return "DMA";
  case InputClass::Migration:
    return "migration";
  case InputClass::Network:
    return "network receive";
  case InputClass::DiskImage:
    return "disk-image read";
  case InputClass::Virtio:
    return "virtio configuration";
  case InputClass::Virtqueue:
    return "virtqueue request";
  case InputClass::Mixed:
    return "mixed guest input";
  }
  llvm_unreachable("unknown QEMU input class");
}

static std::string valueRange(ProgramStateRef State, SVal Value,
                              SValBuilder &SVB) {
  const llvm::APSInt *Minimum = SVB.getMinValue(State, Value);
  const llvm::APSInt *Maximum = SVB.getMaxValue(State, Value);
  if (!Minimum || !Maximum)
    return "unknown";
  llvm::SmallString<64> Buffer;
  llvm::raw_svector_ostream OS(Buffer);
  if (*Minimum == *Maximum)
    OS << *Minimum;
  else
    OS << '[' << *Minimum << ", " << *Maximum << ']';
  return std::string(OS.str());
}

static std::optional<BoundStates> compare(ProgramStateRef State, SVal Left,
                                          BinaryOperatorKind Op, SVal Right,
                                          SValBuilder &SVB) {
  SVal Condition =
      SVB.evalBinOp(State, Op, Left, Right, SVB.getContext().BoolTy);
  auto Defined = Condition.getAs<DefinedOrUnknownSVal>();
  if (!Defined || Condition.isUnknown())
    return std::nullopt;
  auto [TrueState, FalseState] = State->assume(*Defined);
  return BoundStates{TrueState, FalseState};
}

static std::optional<BoundStates>
compareSourceCondition(ProgramStateRef State, SVal Left, BinaryOperatorKind Op,
                       SVal Right, SValBuilder &SVB) {
  SVal Condition = SVB.evalBinOp(State, Op, Left, Right,
                                 SVB.getContext().getLogicalOperationType());
  auto Defined = Condition.getAs<DefinedOrUnknownSVal>();
  if (!Defined || Condition.isUnknown())
    return std::nullopt;
  auto [TrueState, FalseState] = State->assume(*Defined);
  return BoundStates{TrueState, FalseState};
}

static bool hasUsableExtent(ProgramStateRef State, SVal Extent,
                            SValBuilder &SVB) {
  const llvm::APSInt *Minimum = SVB.getMinValue(State, Extent);
  const llvm::APSInt *Maximum = SVB.getMaxValue(State, Extent);
  return Minimum && Maximum && !Minimum->isNegative() &&
         (!Maximum->isAllOnes() || *Minimum == *Maximum);
}

class QEMUGuestMemorySafetyChecker
    : public Checker<check::ASTDecl<TranslationUnitDecl>, check::BeginFunction,
                     check::EndFunction, check::PreCall, check::PostCall,
                     check::Bind, check::LiveSymbols, check::DeadSymbols,
                     check::PostStmt<ImplicitCastExpr>,
                     check::PreStmt<ArraySubscriptExpr>> {
  mutable llvm::DenseMap<const FunctionDecl *, CallbackInfo> Callbacks;
  using FieldPath = llvm::SmallVector<const FieldDecl *, 4>;
  mutable llvm::DenseMap<const FieldDecl *, FieldPath> DynamicArrayCounts;
  mutable llvm::DenseSet<const FieldDecl *> AmbiguousDynamicArrays;
  mutable llvm::DenseMap<const FunctionDecl *, ShiftedBoundPredicate>
      ShiftedBoundPredicates;
  mutable llvm::DenseMap<const FieldDecl *, InputClass> PersistentGuestFields;
  mutable llvm::DenseSet<const FieldDecl *> MigrationGuestFields;
  mutable llvm::DenseMap<const FieldDecl *, ValidatedFieldBound>
      MigrationValidatedFieldBounds;
  mutable llvm::DenseMap<const FieldDecl *, uint64_t>
      MigrationPostLoadFieldMaximums;
  mutable llvm::DenseSet<const FieldDecl *> MigrationPostLoadUnvalidatedFields;
  mutable llvm::DenseSet<const FunctionDecl *> MigrationPostLoadFunctions;
  mutable llvm::DenseMap<const FieldDecl *, uint64_t>
      PersistentGuestFieldMaximums;
  mutable llvm::DenseSet<const FieldDecl *> UnboundedPersistentGuestFields;
  mutable std::unique_ptr<BugType> LevelABug;
  mutable std::unique_ptr<BugType> LevelBBug;

  void
  addCallback(const Expr *Initializer, InputClass Source,
              std::initializer_list<unsigned> Parameters,
              std::initializer_list<unsigned> Pointees = {},
              std::optional<unsigned> AddressParameter = std::nullopt,
              std::optional<unsigned> AccessSizeParameter = std::nullopt,
              std::optional<uint64_t> AccessSizeLimit = std::nullopt) const {
    const FunctionDecl *FD = referencedFunction(Initializer);
    if (!FD)
      return;
    CallbackInfo &Info = Callbacks[FD];
    if (Info.ParameterMask && Info.Source != Source)
      Info.Source = InputClass::Mixed;
    else
      Info.Source = Source;
    for (unsigned Parameter : Parameters)
      if (Parameter < 64)
        Info.ParameterMask |= uint64_t(1) << Parameter;
    for (unsigned Parameter : Pointees)
      if (Parameter < 64)
        Info.PointeeMask |= uint64_t(1) << Parameter;
    if (AddressParameter && AccessSizeParameter) {
      if ((!Info.AddressParameter ||
           *Info.AddressParameter == *AddressParameter) &&
          (!Info.AccessSizeParameter ||
           *Info.AccessSizeParameter == *AccessSizeParameter)) {
        Info.AddressParameter = AddressParameter;
        Info.AccessSizeParameter = AccessSizeParameter;
      } else {
        Info.AddressParameter.reset();
        Info.AccessSizeParameter.reset();
      }
    }
    if (AccessSizeLimit)
      Info.AccessSizeLimit =
          std::max(Info.AccessSizeLimit.value_or(0), *AccessSizeLimit);
  }

  void discoverCallbackAssignment(const BinaryOperator *Assignment) const {
    if (!Assignment || Assignment->getOpcode() != BO_Assign)
      return;
    const auto *Member =
        dyn_cast<MemberExpr>(Assignment->getLHS()->IgnoreParenImpCasts());
    const auto *Field =
        Member ? dyn_cast<FieldDecl>(Member->getMemberDecl()) : nullptr;
    const auto *Parent =
        Field ? dyn_cast<RecordDecl>(Field->getDeclContext()) : nullptr;
    if (!Field || !Parent || Parent->getName() != "VirtioDeviceClass" ||
        Field->getName() != "set_config")
      return;
    addCallback(Assignment->getRHS(), InputClass::Virtio, {}, {1});
  }

  void addPersistentGuestField(const FieldDecl *Field,
                               InputClass Source) const {
    Field = Field->getCanonicalDecl();
    auto [Found, Inserted] = PersistentGuestFields.try_emplace(Field, Source);
    if (!Inserted && Found->second != Source)
      Found->second = InputClass::Mixed;
    if (Source == InputClass::Migration)
      MigrationGuestFields.insert(Field);
  }

  static bool sameSimpleExpression(const Expr *Left, const Expr *Right) {
    if (!Left || !Right)
      return false;
    Left = Left->IgnoreParenImpCasts();
    Right = Right->IgnoreParenImpCasts();
    if (Left == Right)
      return true;
    const auto *LeftRef = dyn_cast<DeclRefExpr>(Left);
    const auto *RightRef = dyn_cast<DeclRefExpr>(Right);
    return LeftRef && RightRef &&
           LeftRef->getDecl()->getCanonicalDecl() ==
               RightRef->getDecl()->getCanonicalDecl();
  }

  static std::optional<uint64_t> literalUpperBound(const Expr *E) {
    if (!E)
      return std::nullopt;
    E = E->IgnoreParenImpCasts();
    while (const auto *Constant = dyn_cast<ConstantExpr>(E))
      E = Constant->getSubExpr()->IgnoreParenImpCasts();
    if (const auto *Literal = dyn_cast<IntegerLiteral>(E)) {
      if (Literal->getValue().getActiveBits() <= 64)
        return Literal->getValue().getZExtValue();
      return std::nullopt;
    }
    if (const auto *Cast = dyn_cast<CastExpr>(E))
      return literalUpperBound(Cast->getSubExpr());
    if (const auto *And = dyn_cast<BinaryOperator>(E))
      if (And->getOpcode() == BO_And) {
        std::optional<uint64_t> Left = literalUpperBound(And->getLHS());
        std::optional<uint64_t> Right = literalUpperBound(And->getRHS());
        if (Left && Right)
          return std::min(*Left, *Right);
        if (Left)
          return Left;
        if (Right)
          return Right;
      }
    return std::nullopt;
  }

  static std::optional<uint64_t> persistentAssignmentMaximum(const Expr *E) {
    if (!E)
      return std::nullopt;
    E = E->IgnoreParenImpCasts();
    if (std::optional<uint64_t> Literal = literalUpperBound(E))
      return Literal;
    const auto *Conditional = dyn_cast<ConditionalOperator>(E);
    if (!Conditional)
      return std::nullopt;
    const auto *Comparison =
        dyn_cast<BinaryOperator>(Conditional->getCond()->IgnoreParenImpCasts());
    if (!Comparison)
      return std::nullopt;

    std::optional<uint64_t> TrueMaximum;
    if (sameSimpleExpression(Conditional->getTrueExpr(),
                             Comparison->getLHS())) {
      std::optional<uint64_t> Limit = literalUpperBound(Comparison->getRHS());
      if (Limit && Comparison->getOpcode() == BO_LT && *Limit > 0)
        TrueMaximum = *Limit - 1;
      else if (Limit && Comparison->getOpcode() == BO_LE)
        TrueMaximum = *Limit;
    }
    if (!TrueMaximum)
      TrueMaximum = literalUpperBound(Conditional->getTrueExpr());
    std::optional<uint64_t> FalseMaximum =
        literalUpperBound(Conditional->getFalseExpr());
    if (!TrueMaximum || !FalseMaximum)
      return std::nullopt;
    return std::max(*TrueMaximum, *FalseMaximum);
  }

  static std::optional<uint64_t> comparisonUpperBound(const Expr *Condition,
                                                      const Expr *Value) {
    if (!Condition || !Value)
      return std::nullopt;
    Condition = Condition->IgnoreParenImpCasts();
    if (const auto *Logical = dyn_cast<BinaryOperator>(Condition)) {
      if (Logical->getOpcode() == BO_LAnd) {
        if (std::optional<uint64_t> Left =
                comparisonUpperBound(Logical->getLHS(), Value))
          return Left;
        return comparisonUpperBound(Logical->getRHS(), Value);
      }
    }
    const auto *Comparison = dyn_cast<BinaryOperator>(Condition);
    if (!Comparison)
      return std::nullopt;

    const Expr *LimitExpression = nullptr;
    bool Strict = false;
    if (sameSimpleExpression(Value, Comparison->getLHS())) {
      if (Comparison->getOpcode() == BO_LT) {
        LimitExpression = Comparison->getRHS();
        Strict = true;
      } else if (Comparison->getOpcode() == BO_LE) {
        LimitExpression = Comparison->getRHS();
      }
    } else if (sameSimpleExpression(Value, Comparison->getRHS())) {
      if (Comparison->getOpcode() == BO_GT) {
        LimitExpression = Comparison->getLHS();
        Strict = true;
      } else if (Comparison->getOpcode() == BO_GE) {
        LimitExpression = Comparison->getLHS();
      }
    }
    std::optional<uint64_t> Limit = literalUpperBound(LimitExpression);
    if (!Limit || (Strict && *Limit == 0))
      return std::nullopt;
    return Strict ? *Limit - 1 : *Limit;
  }

  static std::optional<uint64_t>
  enclosingGuardMaximum(const BinaryOperator *Assignment, ASTContext &Context) {
    if (!Assignment)
      return std::nullopt;
    DynTypedNode Child = DynTypedNode::create(*Assignment);
    for (unsigned Depth = 0; Depth < 16; ++Depth) {
      auto Parents = Context.getParents(Child);
      if (Parents.size() != 1)
        return std::nullopt;
      DynTypedNode Parent = Parents[0];
      if (const auto *If = Parent.get<IfStmt>()) {
        const Stmt *ChildStatement = Child.get<Stmt>();
        if (ChildStatement && If->getThen() == ChildStatement)
          if (std::optional<uint64_t> Maximum =
                  comparisonUpperBound(If->getCond(), Assignment->getRHS()))
            return Maximum;
      }
      Child = Parent;
    }
    return std::nullopt;
  }

  static std::optional<uint64_t> unsignedFieldMaximum(const FieldDecl *Field,
                                                      ASTContext &Context) {
    QualType Type = Field->getType();
    if (!Type->isUnsignedIntegerType())
      return std::nullopt;
    unsigned Width = Context.getIntWidth(Type);
    if (!Width || Width > 64)
      return std::nullopt;
    return Width == 64 ? std::numeric_limits<uint64_t>::max()
                       : (uint64_t(1) << Width) - 1;
  }

  static std::optional<uint64_t>
  storedAssignmentMaximum(const BinaryOperator *Assignment,
                          const FieldDecl *Field, ASTContext &Context) {
    if (!Assignment || Assignment->getOpcode() != BO_Assign)
      return std::nullopt;
    if (std::optional<uint64_t> Maximum =
            persistentAssignmentMaximum(Assignment->getRHS()))
      return Maximum;
    if (std::optional<uint64_t> Maximum =
            enclosingGuardMaximum(Assignment, Context))
      return Maximum;
    return unsignedFieldMaximum(Field, Context);
  }

  static bool expressionReferencesCallbackInput(const Expr *E,
                                                const FunctionDecl *FD,
                                                const CallbackInfo &Info) {
    if (!E || !FD)
      return false;
    class InputReferenceVisitor : public DynamicRecursiveASTVisitor {
      const FunctionDecl *FD;
      uint64_t Mask;
      llvm::DenseSet<const VarDecl *> ExpandedLocals;

    public:
      bool Found = false;

      InputReferenceVisitor(const FunctionDecl *FD, uint64_t Mask)
          : FD(FD), Mask(Mask) {}

      bool VisitDeclRefExpr(DeclRefExpr *DRE) override {
        const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
        if (!VD)
          return true;
        if (const auto *Parameter = dyn_cast<ParmVarDecl>(VD)) {
          for (unsigned I = 0; I < FD->getNumParams() && I < 64; ++I)
            if ((Mask & (uint64_t(1) << I)) &&
                FD->getParamDecl(I)->getCanonicalDecl() ==
                    Parameter->getCanonicalDecl()) {
              Found = true;
              return false;
            }
          return true;
        }
        if (VD->isLocalVarDecl() && VD->hasInit() &&
            ExpandedLocals.insert(VD->getCanonicalDecl()).second)
          TraverseStmt(const_cast<Expr *>(VD->getInit()));
        return !Found;
      }
    } Visitor(FD, Info.ParameterMask | Info.PointeeMask);
    Visitor.TraverseStmt(const_cast<Expr *>(E));
    return Visitor.Found;
  }

  static const MemberExpr *destinationMember(const Expr *E) {
    if (!E)
      return nullptr;
    E = E->IgnoreParenImpCasts();
    while (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() != UO_AddrOf)
        break;
      E = UO->getSubExpr()->IgnoreParenImpCasts();
    }
    return dyn_cast<MemberExpr>(E);
  }

  static const FieldDecl *destinationField(const Expr *E) {
    const MemberExpr *Member = destinationMember(E);
    const auto *Field =
        Member ? dyn_cast<FieldDecl>(Member->getMemberDecl()) : nullptr;
    return Field ? Field->getCanonicalDecl() : nullptr;
  }

  void discoverPersistentGuestAssignment(const BinaryOperator *Assignment,
                                         const FunctionDecl *FD) const {
    if (!Assignment || !Assignment->isAssignmentOp() || !FD)
      return;
    auto Callback = Callbacks.find(FD->getCanonicalDecl());
    if (Callback == Callbacks.end() ||
        !expressionReferencesCallbackInput(Assignment->getRHS(), FD,
                                           Callback->second))
      return;
    if (const FieldDecl *Field = destinationField(Assignment->getLHS()))
      addPersistentGuestField(Field, Callback->second.Source);
  }

  void discoverPersistentGuestCopy(const CallExpr *Call,
                                   const FunctionDecl *FD) const {
    if (!Call || !FD || Call->getNumArgs() < 3)
      return;
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee || !Callee->getIdentifier() ||
        (Callee->getName() != "memcpy" && Callee->getName() != "memmove" &&
         Callee->getName() != "__builtin_memcpy" &&
         Callee->getName() != "__builtin_memmove"))
      return;
    auto Callback = Callbacks.find(FD->getCanonicalDecl());
    if (Callback == Callbacks.end() ||
        !expressionReferencesCallbackInput(Call->getArg(1), FD,
                                           Callback->second))
      return;
    if (const FieldDecl *Field = destinationField(Call->getArg(0)))
      addPersistentGuestField(Field, Callback->second.Source);
  }

  void discoverVMStateField(const InitListExpr *ILE) const {
    ILE = semanticInitList(ILE);
    if (!ILE)
      return;
    const RecordDecl *RD = ILE->getType()->getAsRecordDecl();
    if (!RD || RD->getName() != "VMStateField")
      return;

    class OffsetVisitor : public DynamicRecursiveASTVisitor {
      const QEMUGuestMemorySafetyChecker &Checker;

    public:
      explicit OffsetVisitor(const QEMUGuestMemorySafetyChecker &Checker)
          : Checker(Checker) {}

      bool VisitOffsetOfExpr(OffsetOfExpr *Offset) override {
        for (unsigned I = 0; I < Offset->getNumComponents(); ++I) {
          const OffsetOfNode &Component = Offset->getComponent(I);
          if (Component.getKind() != OffsetOfNode::Field)
            continue;
          const FieldDecl *Field = Component.getField();
          if (Field->getType()->isIntegerType())
            Checker.addPersistentGuestField(Field, InputClass::Migration);
        }
        return true;
      }
    } Visitor(*this);
    Visitor.TraverseStmt(const_cast<InitListExpr *>(ILE));
  }

  void discoverVMStateValidation(const InitListExpr *ILE,
                                 ASTContext &Context) const {
    ILE = semanticInitList(ILE);
    if (!ILE)
      return;
    const RecordDecl *RD = ILE->getType()->getAsRecordDecl();
    if (!RD || RD->getName() != "VMStateField")
      return;

    const Expr *Flags = fieldInitializer(ILE, "flags");
    Expr::EvalResult FlagsResult;
    if (!Flags ||
        !Flags->EvaluateAsInt(FlagsResult, Context, Expr::SE_NoSideEffects))
      return;
    const llvm::APSInt &FlagsValue = FlagsResult.Val.getInt();
    // QEMU's VMSTATE_VALIDATE entries are the only VMState fields carrying
    // both VMS_MUST_EXIST and VMS_NO_STATE.  Other field_exists predicates
    // decide whether data is present and must not be treated as validators.
    constexpr uint64_t ValidationFlags = 0x1000 | 0x080;
    if (FlagsValue.isNegative() || FlagsValue.getActiveBits() > 64 ||
        (FlagsValue.getZExtValue() & ValidationFlags) != ValidationFlags)
      return;

    const FunctionDecl *Predicate =
        referencedFunction(fieldInitializer(ILE, "field_exists"));
    if (!Predicate || !Predicate->doesThisDeclarationHaveABody())
      return;
    const auto *Body = dyn_cast<CompoundStmt>(Predicate->getBody());
    if (!Body)
      return;
    const ReturnStmt *Return = nullptr;
    for (const Stmt *Statement : Body->body()) {
      if (const auto *Candidate = dyn_cast<ReturnStmt>(Statement)) {
        if (Return)
          return;
        Return = Candidate;
      } else if (!isa<DeclStmt>(Statement)) {
        return;
      }
    }
    const Expr *Value = Return ? Return->getRetValue() : nullptr;
    Value = Value ? Value->IgnoreParenImpCasts() : nullptr;
    const auto *Comparison = dyn_cast_or_null<BinaryOperator>(Value);
    if (!Comparison ||
        (Comparison->getOpcode() != BO_LE && Comparison->getOpcode() != BO_LT))
      return;

    const MemberExpr *FieldMember =
        destinationMember(Comparison->getLHS()->IgnoreParenImpCasts());
    const MemberExpr *LimitMember =
        destinationMember(Comparison->getRHS()->IgnoreParenImpCasts());
    if (!FieldMember || !LimitMember ||
        !sameSimpleExpression(FieldMember->getBase(), LimitMember->getBase()))
      return;
    const FieldDecl *Field = destinationField(FieldMember);
    const FieldDecl *Limit = destinationField(LimitMember);
    if (!Field || !Limit || Field == Limit)
      return;
    Field = Field->getCanonicalDecl();
    Limit = Limit->getCanonicalDecl();

    ValidatedFieldBound Bound{Limit, Comparison->getOpcode() == BO_LE};
    auto [Found, Inserted] =
        MigrationValidatedFieldBounds.try_emplace(Field, Bound);
    if (!Inserted && (Found->second.LimitField != Bound.LimitField ||
                      Found->second.Inclusive != Bound.Inclusive))
      MigrationValidatedFieldBounds.erase(Field);
  }

  static bool returnsNonZero(const Stmt *Statement, ASTContext &Context) {
    const ReturnStmt *Return = dyn_cast_or_null<ReturnStmt>(Statement);
    if (!Return)
      if (const auto *Compound = dyn_cast_or_null<CompoundStmt>(Statement))
        if (Compound->size() == 1)
          Return = dyn_cast<ReturnStmt>(*Compound->body_begin());
    const Expr *Value = Return ? Return->getRetValue() : nullptr;
    if (!Value)
      return false;
    Expr::EvalResult Result;
    return Value->EvaluateAsInt(Result, Context, Expr::SE_NoSideEffects) &&
           Result.Val.getInt() != 0;
  }

  static void collectRejectedBounds(
      const Expr *Condition, ASTContext &Context,
      llvm::DenseMap<const FieldDecl *, uint64_t> &UpperBounds,
      llvm::DenseSet<const FieldDecl *> &NonNegativeFields) {
    if (!Condition)
      return;
    Condition = Condition->IgnoreParenImpCasts();
    const auto *Operation = dyn_cast<BinaryOperator>(Condition);
    if (!Operation)
      return;
    if (Operation->getOpcode() == BO_LOr) {
      collectRejectedBounds(Operation->getLHS(), Context, UpperBounds,
                            NonNegativeFields);
      collectRejectedBounds(Operation->getRHS(), Context, UpperBounds,
                            NonNegativeFields);
      return;
    }

    auto IsConstant = [&](const Expr *Expression, int Value) {
      Expr::EvalResult Result;
      if (!Expression->EvaluateAsInt(Result, Context, Expr::SE_NoSideEffects))
        return false;
      const llvm::APSInt &Integer = Result.Val.getInt();
      if (Value == 0)
        return Integer.isZero();
      return Value == -1 && Integer.isSigned() && Integer.isNegative() &&
             Integer.isAllOnes();
    };
    const FieldDecl *NonNegativeField = nullptr;
    switch (Operation->getOpcode()) {
    case BO_LT:
      if (IsConstant(Operation->getRHS(), 0))
        NonNegativeField = destinationField(Operation->getLHS());
      break;
    case BO_LE:
      if (IsConstant(Operation->getRHS(), -1))
        NonNegativeField = destinationField(Operation->getLHS());
      break;
    case BO_GT:
      if (IsConstant(Operation->getLHS(), 0))
        NonNegativeField = destinationField(Operation->getRHS());
      break;
    case BO_GE:
      if (IsConstant(Operation->getLHS(), -1))
        NonNegativeField = destinationField(Operation->getRHS());
      break;
    default:
      break;
    }
    if (NonNegativeField)
      NonNegativeFields.insert(NonNegativeField->getCanonicalDecl());

    const Expr *FieldExpression = nullptr;
    const Expr *LimitExpression = nullptr;
    bool InclusiveMaximum = true;
    switch (Operation->getOpcode()) {
    case BO_GT:
      FieldExpression = Operation->getLHS();
      LimitExpression = Operation->getRHS();
      break;
    case BO_GE:
      FieldExpression = Operation->getLHS();
      LimitExpression = Operation->getRHS();
      InclusiveMaximum = false;
      break;
    case BO_LT:
      FieldExpression = Operation->getRHS();
      LimitExpression = Operation->getLHS();
      break;
    case BO_LE:
      FieldExpression = Operation->getRHS();
      LimitExpression = Operation->getLHS();
      InclusiveMaximum = false;
      break;
    default:
      return;
    }

    const FieldDecl *Field = destinationField(FieldExpression);
    if (!Field)
      return;
    Expr::EvalResult LimitResult;
    if (!LimitExpression->EvaluateAsInt(LimitResult, Context,
                                        Expr::SE_NoSideEffects))
      return;
    const llvm::APSInt &Limit = LimitResult.Val.getInt();
    if (Limit.isNegative() || Limit.getActiveBits() > 64)
      return;
    uint64_t Maximum = Limit.getZExtValue();
    if (!InclusiveMaximum) {
      if (Maximum == 0)
        return;
      --Maximum;
    }
    Field = Field->getCanonicalDecl();
    auto [Found, Inserted] = UpperBounds.try_emplace(Field, Maximum);
    if (!Inserted)
      Found->second = std::min(Found->second, Maximum);
  }

  void discoverVMStatePostLoadBounds(const InitListExpr *ILE,
                                     ASTContext &Context) const {
    ILE = semanticInitList(ILE);
    if (!ILE)
      return;
    const RecordDecl *RD = ILE->getType()->getAsRecordDecl();
    if (!RD || RD->getName() != "VMStateDescription")
      return;

    llvm::DenseSet<const FieldDecl *> MigratedFields;
    class OffsetVisitor : public DynamicRecursiveASTVisitor {
      llvm::DenseSet<const FieldDecl *> &Fields;

    public:
      explicit OffsetVisitor(llvm::DenseSet<const FieldDecl *> &Fields)
          : Fields(Fields) {}

      bool VisitOffsetOfExpr(OffsetOfExpr *Offset) override {
        for (unsigned I = 0; I < Offset->getNumComponents(); ++I) {
          const OffsetOfNode &Component = Offset->getComponent(I);
          if (Component.getKind() != OffsetOfNode::Field)
            continue;
          const FieldDecl *Field = Component.getField();
          if (Field->getType()->isIntegerType())
            Fields.insert(Field->getCanonicalDecl());
        }
        return true;
      }
    } FieldVisitor(MigratedFields);
    if (const Expr *Fields = fieldInitializer(ILE, "fields"))
      FieldVisitor.TraverseStmt(const_cast<Expr *>(Fields));
    if (MigratedFields.empty())
      return;

    auto MarkUnvalidated = [&] {
      for (const FieldDecl *Field : MigratedFields)
        MigrationPostLoadUnvalidatedFields.insert(Field);
    };
    const FunctionDecl *PostLoad =
        referencedFunction(fieldInitializer(ILE, "post_load"));
    if (!PostLoad || !PostLoad->doesThisDeclarationHaveABody()) {
      MarkUnvalidated();
      return;
    }
    PostLoad = PostLoad->getCanonicalDecl();
    MigrationPostLoadFunctions.insert(PostLoad);
    const auto *Body = dyn_cast<CompoundStmt>(PostLoad->getBody());
    if (!Body) {
      MarkUnvalidated();
      return;
    }

    llvm::DenseMap<const FieldDecl *, uint64_t> UpperBounds;
    llvm::DenseSet<const FieldDecl *> NonNegativeFields;
    for (const Stmt *Statement : Body->body()) {
      const auto *If = dyn_cast<IfStmt>(Statement);
      if (!If || !returnsNonZero(If->getThen(), Context))
        continue;
      collectRejectedBounds(If->getCond(), Context, UpperBounds,
                            NonNegativeFields);
    }
    for (const FieldDecl *Field : MigratedFields) {
      auto Bound = UpperBounds.find(Field);
      bool HasLowerBound = Field->getType()->isUnsignedIntegerType() ||
                           NonNegativeFields.contains(Field);
      if (Bound == UpperBounds.end() || !HasLowerBound) {
        MigrationPostLoadUnvalidatedFields.insert(Field);
        continue;
      }
      auto [Found, Inserted] =
          MigrationPostLoadFieldMaximums.try_emplace(Field, Bound->second);
      if (!Inserted)
        Found->second = std::max(Found->second, Bound->second);
    }
  }

  struct PersistentFieldInfo {
    const FieldDecl *Field;
    InputClass Source;
  };

  std::optional<PersistentFieldInfo> persistentGuestField(const Expr *E) const {
    if (!E || PersistentGuestFields.empty())
      return std::nullopt;
    class FieldVisitor : public DynamicRecursiveASTVisitor {
      const llvm::DenseMap<const FieldDecl *, InputClass> &Fields;
      llvm::DenseSet<const VarDecl *> ExpandedLocals;

    public:
      std::optional<PersistentFieldInfo> Result;
      bool Ambiguous = false;

      explicit FieldVisitor(
          const llvm::DenseMap<const FieldDecl *, InputClass> &Fields)
          : Fields(Fields) {}

      bool VisitMemberExpr(MemberExpr *ME) override {
        const auto *Field = dyn_cast<FieldDecl>(ME->getMemberDecl());
        if (!Field)
          return true;
        auto Found = Fields.find(Field->getCanonicalDecl());
        if (Found != Fields.end()) {
          if (Result && Result->Field != Found->first) {
            Result.reset();
            Ambiguous = true;
            return false;
          }
          Result = PersistentFieldInfo{Found->first, Found->second};
        }
        return true;
      }

      bool VisitDeclRefExpr(DeclRefExpr *DRE) override {
        const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
        if (VD && VD->isLocalVarDecl() && VD->hasInit() &&
            ExpandedLocals.insert(VD->getCanonicalDecl()).second)
          TraverseStmt(const_cast<Expr *>(VD->getInit()));
        return !Ambiguous;
      }
    } Visitor(PersistentGuestFields);
    Visitor.TraverseStmt(const_cast<Expr *>(E));
    if (Visitor.Ambiguous)
      return std::nullopt;
    return Visitor.Result;
  }

  static const FieldDecl *directReferencedField(const Expr *E,
                                                unsigned Depth = 0) {
    if (!E || Depth > 8)
      return nullptr;
    E = E->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
      if (VD && VD->isLocalVarDecl() && !isa<ParmVarDecl>(VD) && VD->hasInit())
        return directReferencedField(VD->getInit(), Depth + 1);
    }
    return destinationField(E);
  }

  static const MemberExpr *directReferencedMember(const Expr *E,
                                                  unsigned Depth = 0) {
    if (!E || Depth > 8)
      return nullptr;
    E = E->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
      if (VD && VD->isLocalVarDecl() && !isa<ParmVarDecl>(VD) && VD->hasInit())
        return directReferencedMember(VD->getInit(), Depth + 1);
    }
    return destinationMember(E);
  }

  static std::optional<uint64_t> indexMaximumFromField(const Expr *E,
                                                       const FieldDecl *Field,
                                                       uint64_t Maximum) {
    if (!E)
      return std::nullopt;
    E = E->IgnoreParenImpCasts();
    if (destinationField(E) == Field)
      return Maximum;
    const auto *Operation = dyn_cast<UnaryOperator>(E);
    if (!Operation || destinationField(Operation->getSubExpr()) != Field)
      return std::nullopt;
    switch (Operation->getOpcode()) {
    case UO_PreDec:
      return Maximum == 0 ? 0 : Maximum - 1;
    case UO_PostDec:
    case UO_PostInc:
      return Maximum;
    case UO_PreInc:
      return Maximum == std::numeric_limits<uint64_t>::max() ? Maximum
                                                             : Maximum + 1;
    default:
      return std::nullopt;
    }
  }

  static const FieldDecl *addressedField(const Expr *E) {
    if (!E)
      return nullptr;
    E = E->IgnoreParenImpCasts();
    const auto *Address = dyn_cast<UnaryOperator>(E);
    if (!Address || Address->getOpcode() != UO_AddrOf)
      return nullptr;
    return destinationField(Address->getSubExpr());
  }

  void computePersistentGuestFieldMaximums(const TranslationUnitDecl *TU,
                                           ASTContext &Context) const {
    PersistentGuestFieldMaximums.clear();
    UnboundedPersistentGuestFields.clear();
    for (const FieldDecl *Field : MigrationGuestFields)
      UnboundedPersistentGuestFields.insert(Field);
    for (const auto &Entry : PersistentGuestFields)
      if (!Context.getSourceManager().isWrittenInMainFile(
              Entry.first->getLocation()))
        UnboundedPersistentGuestFields.insert(Entry.first);

    class FieldWriteVisitor : public DynamicRecursiveASTVisitor {
      const QEMUGuestMemorySafetyChecker &Checker;
      ASTContext &Context;

      bool isPersistent(const FieldDecl *Field) const {
        return Field && Checker.PersistentGuestFields.contains(
                            Field->getCanonicalDecl());
      }

      void markUnbounded(const FieldDecl *Field) {
        Field = Field->getCanonicalDecl();
        Checker.PersistentGuestFieldMaximums.erase(Field);
        Checker.UnboundedPersistentGuestFields.insert(Field);
      }

      void recordMaximum(const FieldDecl *Field,
                         std::optional<uint64_t> Maximum) {
        Field = Field->getCanonicalDecl();
        if (Checker.UnboundedPersistentGuestFields.contains(Field))
          return;
        if (!Maximum) {
          markUnbounded(Field);
          return;
        }
        auto [Bound, Inserted] =
            Checker.PersistentGuestFieldMaximums.try_emplace(Field, *Maximum);
        if (!Inserted)
          Bound->second = std::max(Bound->second, *Maximum);
      }

    public:
      FieldWriteVisitor(const QEMUGuestMemorySafetyChecker &Checker,
                        ASTContext &Context)
          : Checker(Checker), Context(Context) {}

      bool VisitBinaryOperator(BinaryOperator *Assignment) override {
        if (!Assignment->isAssignmentOp())
          return true;
        const FieldDecl *Field = QEMUGuestMemorySafetyChecker::destinationField(
            Assignment->getLHS());
        if (!isPersistent(Field))
          return true;
        recordMaximum(Field,
                      QEMUGuestMemorySafetyChecker::storedAssignmentMaximum(
                          Assignment, Field, Context));
        return true;
      }

      bool VisitUnaryOperator(UnaryOperator *Operation) override {
        if (!Operation->isIncrementDecrementOp())
          return true;
        const FieldDecl *Field = QEMUGuestMemorySafetyChecker::destinationField(
            Operation->getSubExpr());
        if (isPersistent(Field))
          markUnbounded(Field);
        return true;
      }

      bool VisitCallExpr(CallExpr *Call) override {
        const FunctionDecl *Callee = Call->getDirectCallee();
        for (unsigned I = 0; I < Call->getNumArgs(); ++I) {
          const FieldDecl *Field =
              QEMUGuestMemorySafetyChecker::addressedField(Call->getArg(I));
          if (!isPersistent(Field))
            continue;
          bool ReadOnly = false;
          if (Callee && I < Callee->getNumParams()) {
            QualType ParameterType = Callee->getParamDecl(I)->getType();
            ReadOnly = ParameterType->isPointerType() &&
                       ParameterType->getPointeeType().isConstQualified();
          }
          if (!ReadOnly)
            markUnbounded(Field);
        }
        return true;
      }
    } Visitor(*this, Context);
    Visitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));

    for (const FieldDecl *Field : UnboundedPersistentGuestFields)
      if (std::optional<uint64_t> Maximum =
              unsignedFieldMaximum(Field, Context))
        PersistentGuestFieldMaximums[Field] = *Maximum;
  }

  void discoverOperationTable(const InitListExpr *ILE) const {
    ILE = semanticInitList(ILE);
    if (!ILE)
      return;
    const RecordDecl *RD = ILE->getType()->getAsRecordDecl();
    if (!RD)
      return;
    StringRef Name = RD->getName();
    if (Name == "MemoryRegionOps") {
      std::optional<uint64_t> ExplicitAccessSize;
      if (const InitListExpr *Impl =
              semanticInitList(fieldInitializer(ILE, "impl"))) {
        std::optional<uint64_t> Minimum =
            literalUpperBound(fieldInitializer(Impl, "min_access_size"));
        std::optional<uint64_t> Maximum =
            literalUpperBound(fieldInitializer(Impl, "max_access_size"));
        if (Minimum || Maximum)
          ExplicitAccessSize =
              std::max(Minimum.value_or(0), Maximum.value_or(0));
      }
      uint64_t AccessSizeLimit = ExplicitAccessSize.value_or(8);
      addCallback(fieldInitializer(ILE, "read"), InputClass::MMIO, {1, 2}, {},
                  1, 2, AccessSizeLimit);
      addCallback(fieldInitializer(ILE, "write"), InputClass::MMIO, {1, 2, 3},
                  {}, 1, 3, AccessSizeLimit);
      addCallback(fieldInitializer(ILE, "read_with_attrs"), InputClass::MMIO,
                  {1, 3, 4}, {}, 1, 3, AccessSizeLimit);
      addCallback(fieldInitializer(ILE, "write_with_attrs"), InputClass::MMIO,
                  {1, 2, 3, 4}, {}, 1, 3, AccessSizeLimit);
      if (const InitListExpr *Valid =
              semanticInitList(fieldInitializer(ILE, "valid")))
        addCallback(fieldInitializer(Valid, "accepts"), InputClass::MMIO,
                    {1, 2, 3, 4}, {}, 1, 2, 8);
      if (ExplicitAccessSize && *ExplicitAccessSize > 0 &&
          *ExplicitAccessSize < 8) {
        uint64_t DataMaximum = (uint64_t(1) << (*ExplicitAccessSize * 8)) - 1;
        auto SetDataMaximum = [&](const Expr *Initializer) {
          const FunctionDecl *FD = referencedFunction(Initializer);
          if (!FD)
            return;
          CallbackInfo &Info = Callbacks[FD->getCanonicalDecl()];
          if (Info.DataParameter && *Info.DataParameter != 2) {
            Info.DataParameter.reset();
            Info.DataMaximum.reset();
            return;
          }
          Info.DataParameter = 2;
          Info.DataMaximum =
              std::max(Info.DataMaximum.value_or(0), DataMaximum);
        };
        SetDataMaximum(fieldInitializer(ILE, "write"));
        SetDataMaximum(fieldInitializer(ILE, "write_with_attrs"));
      }
      return;
    }
    if (Name == "MemoryRegionPortio") {
      addCallback(fieldInitializer(ILE, "read"), InputClass::PIO, {1});
      addCallback(fieldInitializer(ILE, "write"), InputClass::PIO, {1, 2});
      return;
    }
    if (Name == "NetClientInfo") {
      addCallback(fieldInitializer(ILE, "receive"), InputClass::Network, {2},
                  {1});
    }
  }

  void collectMemoryRegionCallbacks(
      const InitListExpr *ILE,
      llvm::SmallVectorImpl<const FunctionDecl *> &Result) const {
    ILE = semanticInitList(ILE);
    if (!ILE)
      return;
    const RecordDecl *RD = ILE->getType()->getAsRecordDecl();
    if (!RD || RD->getName() != "MemoryRegionOps")
      return;

    llvm::DenseSet<const FunctionDecl *> Seen;
    auto Add = [&](const Expr *E) {
      if (const FunctionDecl *FD = referencedFunction(E)) {
        FD = FD->getCanonicalDecl();
        if (Seen.insert(FD).second)
          Result.push_back(FD);
      }
    };
    Add(fieldInitializer(ILE, "read"));
    Add(fieldInitializer(ILE, "write"));
    Add(fieldInitializer(ILE, "read_with_attrs"));
    Add(fieldInitializer(ILE, "write_with_attrs"));
    if (const InitListExpr *Valid =
            semanticInitList(fieldInitializer(ILE, "valid")))
      Add(fieldInitializer(Valid, "accepts"));
  }

  void setAddressLimit(const FunctionDecl *FD, uint64_t Limit) const {
    auto Found = Callbacks.find(FD->getCanonicalDecl());
    if (Found != Callbacks.end())
      Found->second.AddressLimit = Limit;
  }

  void discoverDynamicArrayAllocation(const BinaryOperator *Assignment) const {
    if (!Assignment || !Assignment->isAssignmentOp())
      return;
    const auto *Member =
        dyn_cast<MemberExpr>(Assignment->getLHS()->IgnoreParenImpCasts());
    const auto *PointerField =
        Member ? dyn_cast<FieldDecl>(Member->getMemberDecl()) : nullptr;
    if (!PointerField || !PointerField->getType()->isPointerType())
      return;

    class AllocationVisitor : public DynamicRecursiveASTVisitor {
    public:
      bool HasAllocation = false;
      llvm::DenseSet<const FieldDecl *> IntegerFields;
      FieldPath IntegerFieldPath;
      const Expr *IntegerFieldRoot = nullptr;
      bool AmbiguousPath = false;

      bool VisitCallExpr(CallExpr *Call) override {
        const FunctionDecl *FD = Call->getDirectCallee();
        if (!FD || !FD->getIdentifier())
          return true;
        StringRef Name = FD->getName();
        HasAllocation |= Name == "malloc" || Name == "realloc" ||
                         Name == "g_malloc" || Name == "g_malloc0" ||
                         Name == "g_malloc_n" || Name == "g_malloc0_n" ||
                         Name == "g_realloc" || Name == "g_realloc_n" ||
                         Name == "g_try_malloc" || Name == "g_try_malloc0" ||
                         Name == "g_try_malloc_n" ||
                         Name == "g_try_malloc0_n" || Name == "g_try_realloc" ||
                         Name == "g_try_realloc_n";
        return true;
      }

      bool VisitMemberExpr(MemberExpr *ME) override {
        const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
        if (FD && FD->getType()->isIntegerType()) {
          IntegerFields.insert(FD);
          FieldPath Path;
          const Expr *Root = ME;
          while (const auto *Member =
                     dyn_cast<MemberExpr>(Root->IgnoreParenImpCasts())) {
            const auto *PathField =
                dyn_cast<FieldDecl>(Member->getMemberDecl());
            if (!PathField) {
              Path.clear();
              break;
            }
            Path.push_back(PathField);
            Root = Member->getBase();
          }
          std::reverse(Path.begin(), Path.end());
          Root = Root->IgnoreParenImpCasts();
          if (IntegerFieldPath.empty()) {
            IntegerFieldPath = std::move(Path);
            IntegerFieldRoot = Root;
          } else if (IntegerFieldPath != Path ||
                     !sameSimpleExpression(IntegerFieldRoot, Root)) {
            AmbiguousPath = true;
          }
        }
        return true;
      }
    } Visitor;
    Visitor.TraverseStmt(const_cast<Expr *>(Assignment->getRHS()));
    if (!Visitor.HasAllocation || Visitor.IntegerFields.size() != 1 ||
        Visitor.IntegerFieldPath.empty() || Visitor.AmbiguousPath ||
        !sameSimpleExpression(Member->getBase(), Visitor.IntegerFieldRoot))
      return;

    if (AmbiguousDynamicArrays.contains(PointerField))
      return;
    auto [Found, Inserted] = DynamicArrayCounts.try_emplace(
        PointerField, std::move(Visitor.IntegerFieldPath));
    if (!Inserted && Found->second != Visitor.IntegerFieldPath) {
      DynamicArrayCounts.erase(PointerField);
      AmbiguousDynamicArrays.insert(PointerField);
    }
  }

  void discoverShiftedBoundPredicate(const FunctionDecl *FD,
                                     ASTContext &Context) const {
    if (!FD || !FD->doesThisDeclarationHaveABody())
      return;
    const auto *Body = dyn_cast<CompoundStmt>(FD->getBody());
    if (!Body || Body->size() != 1)
      return;
    const auto *Return = dyn_cast<ReturnStmt>(*Body->body_begin());
    const Expr *Value = Return ? Return->getRetValue() : nullptr;
    Value = Value ? Value->IgnoreParenImpCasts() : nullptr;
    const auto *Comparison = dyn_cast_or_null<BinaryOperator>(Value);
    if (!Comparison || Comparison->getOpcode() != BO_LT)
      return;

    const Expr *Left = Comparison->getLHS()->IgnoreParenImpCasts();
    const auto *Shift = dyn_cast<BinaryOperator>(Left);
    if (!Shift || Shift->getOpcode() != BO_Shr)
      return;
    const auto *Parameter =
        dyn_cast<DeclRefExpr>(Shift->getLHS()->IgnoreParenImpCasts());
    const auto *PVD =
        Parameter ? dyn_cast<ParmVarDecl>(Parameter->getDecl()) : nullptr;
    if (!PVD)
      return;

    auto ConstantValue = [&Context](const Expr *E) -> std::optional<uint64_t> {
      Expr::EvalResult Result;
      if (!E->EvaluateAsInt(Result, Context, Expr::SE_NoSideEffects))
        return std::nullopt;
      const llvm::APSInt &Value = Result.Val.getInt();
      if (Value.isNegative() || Value.getActiveBits() > 64)
        return std::nullopt;
      return Value.getZExtValue();
    };
    std::optional<uint64_t> ShiftAmount = ConstantValue(Shift->getRHS());
    std::optional<uint64_t> Limit = ConstantValue(Comparison->getRHS());
    if (!ShiftAmount || *ShiftAmount >= 64 || !Limit)
      return;

    unsigned ParameterIndex = 0;
    while (ParameterIndex < FD->getNumParams() &&
           FD->getParamDecl(ParameterIndex)->getCanonicalDecl() !=
               PVD->getCanonicalDecl())
      ++ParameterIndex;
    if (ParameterIndex == FD->getNumParams())
      return;

    ShiftedBoundPredicates[FD->getCanonicalDecl()] = ShiftedBoundPredicate{
        ParameterIndex, static_cast<unsigned>(*ShiftAmount), *Limit};
  }

  static std::optional<SVal> pointeeValue(ProgramStateRef State, SVal Pointer) {
    auto Location = Pointer.getAs<Loc>();
    if (!Location)
      return std::nullopt;
    ASTContext &Ctx = State->getStateManager().getContext();
    QualType Type = Location->getType(Ctx);
    if (Type->isPointerType() && Type->getPointeeType()->isVoidType())
      return State->getSVal(*Location, Ctx.CharTy);
    return State->getSVal(*Location);
  }

  static const NoteTag *sourceNote(CheckerContext &C, ProgramStateRef State,
                                   SVal Value, InputClass Source,
                                   StringRef Detail) {
    std::vector<SymbolRef> Symbols = taint::getTaintedSymbols(State, Value);
    std::string Message = inputClassName(Source).str() + " " + Detail.str();
    return C.getNoteTag(
        [Symbols = std::move(Symbols), Message = std::move(Message)](
            PathSensitiveBugReport &Report) -> std::string {
          for (SymbolRef Symbol : Symbols) {
            if (!Report.isInteresting(Symbol))
              continue;
            Report.markInteresting(Symbol);
            return Message;
          }
          return "";
        });
  }

  static const NoteTag *propagationNote(CheckerContext &C,
                                        ProgramStateRef State, SVal Output,
                                        SVal Input, InputClass Source,
                                        StringRef Detail) {
    std::vector<SymbolRef> Outputs = taint::getTaintedSymbols(State, Output);
    std::vector<SymbolRef> Inputs = taint::getTaintedSymbols(State, Input);
    std::string Message = inputClassName(Source).str() + " " + Detail.str();
    return C.getNoteTag([Outputs = std::move(Outputs),
                         Inputs = std::move(Inputs),
                         Message = std::move(Message)](
                            PathSensitiveBugReport &Report) -> std::string {
      for (SymbolRef Symbol : Outputs) {
        if (!Report.isInteresting(Symbol))
          continue;
        for (SymbolRef Input : Inputs)
          Report.markInteresting(Input);
        return Message;
      }
      return "";
    });
  }

  static ProgramStateRef addInputTaint(ProgramStateRef State, SVal Value,
                                       InputClass Source) {
    State = taint::addTaint(State, Value);
    for (SymbolRef Symbol : taint::getTaintedSymbols(State, Value)) {
      const unsigned *Previous = State->get<QEMUInputClasses>(Symbol);
      InputClass Merged =
          Previous && static_cast<InputClass>(*Previous) != Source
              ? InputClass::Mixed
              : Source;
      State =
          State->set<QEMUInputClasses>(Symbol, static_cast<unsigned>(Merged));
    }
    return State;
  }

  static std::optional<InputClass> inputClassForValue(ProgramStateRef State,
                                                      SVal Value) {
    std::optional<InputClass> Result;
    for (SymbolRef Symbol : taint::getTaintedSymbols(State, Value)) {
      const unsigned *Stored = State->get<QEMUInputClasses>(Symbol);
      if (!Stored)
        continue;
      InputClass Source = static_cast<InputClass>(*Stored);
      if (Result && *Result != Source)
        return InputClass::Mixed;
      Result = Source;
    }
    if (!Result && taint::isTainted(State, Value))
      return InputClass::Mixed;
    return Result;
  }

  static std::optional<unsigned> endianScalarArgument(StringRef Name,
                                                      unsigned ArgumentCount) {
    if ((Name == "virtio_tswap16" || Name == "virtio_tswap32" ||
         Name == "virtio_tswap64") &&
        ArgumentCount >= 2)
      return 1;
    if (ArgumentCount < 1)
      return std::nullopt;
    if (Name == "__builtin_bswap16" || Name == "__builtin_bswap32" ||
        Name == "__builtin_bswap64" || Name == "bswap16" || Name == "bswap24" ||
        Name == "bswap32" || Name == "bswap64" || Name == "le16_to_cpu" ||
        Name == "le32_to_cpu" || Name == "le64_to_cpu" ||
        Name == "be16_to_cpu" || Name == "be32_to_cpu" ||
        Name == "be64_to_cpu" || Name == "cpu_to_le16" ||
        Name == "cpu_to_le32" || Name == "cpu_to_le64" ||
        Name == "cpu_to_be16" || Name == "cpu_to_be32" || Name == "cpu_to_be64")
      return 0;
    return std::nullopt;
  }

  static std::optional<unsigned>
  endianLoadPointerArgument(StringRef Name, unsigned ArgumentCount) {
    if (Name.starts_with("virtio_ld") && Name.ends_with("_p") &&
        ArgumentCount >= 2)
      return 1;
    if (Name.starts_with("ld") && Name.ends_with("_p") && ArgumentCount >= 1)
      return 0;
    return std::nullopt;
  }

  static bool isMigrationScalarSource(StringRef Name) {
    return Name == "qemu_get_byte" || Name == "qemu_get_ubyte" ||
           Name == "qemu_get_sbe16" || Name == "qemu_get_sbe32" ||
           Name == "qemu_get_sbe64" || Name == "qemu_get_be16" ||
           Name == "qemu_get_be32" || Name == "qemu_get_be64";
  }

  static std::optional<uint64_t> migrationScalarMaximum(StringRef Name) {
    if (Name == "qemu_get_byte" || Name == "qemu_get_ubyte")
      return 0xff;
    if (Name == "qemu_get_be16")
      return 0xffff;
    return std::nullopt;
  }

  static bool isMigrationPointerSource(StringRef Name) {
    return Name == "qemu_get_8s" || Name == "qemu_get_s8s" ||
           Name == "qemu_get_be16s" || Name == "qemu_get_be32s" ||
           Name == "qemu_get_be64s" || Name == "qemu_get_sbe16s" ||
           Name == "qemu_get_sbe32s" || Name == "qemu_get_sbe64s";
  }

  struct BufferSource {
    unsigned BufferArgument;
    InputClass Source;
    enum SuccessKind { Always, ReturnZero, ReturnEqualsArgument } Success;
    unsigned CompareArgument = 0;
  };

  static std::optional<BufferSource> bufferSource(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier())
      return std::nullopt;
    StringRef Name = FD->getName();
    if ((Name == "address_space_read" || Name == "address_space_read_full") &&
        Call.getNumArgs() >= 5)
      return BufferSource{3, InputClass::DMA, BufferSource::ReturnZero};
    if ((Name == "dma_memory_read" || Name == "pci_dma_read") &&
        Call.getNumArgs() >= 4)
      return BufferSource{2, InputClass::DMA, BufferSource::ReturnZero};
    if (Name == "cpu_physical_memory_read" && Call.getNumArgs() >= 3)
      return BufferSource{1, InputClass::DMA, BufferSource::Always};
    if (Name == "physical_memory_read" && Call.getNumArgs() >= 3)
      return BufferSource{1, InputClass::DMA, BufferSource::Always};
    if (Name == "qemu_get_buffer" && Call.getNumArgs() >= 3)
      return BufferSource{1, InputClass::Migration,
                          BufferSource::ReturnEqualsArgument, 2};
    if (isMigrationPointerSource(Name) && Call.getNumArgs() >= 2)
      return BufferSource{1, InputClass::Migration, BufferSource::Always};
    if (Name == "bdrv_pread" && Call.getNumArgs() >= 5)
      return BufferSource{3, InputClass::DiskImage, BufferSource::ReturnZero};
    return std::nullopt;
  }

  static bool modelRangeCoversByte(const CallEvent &Call, CheckerContext &C) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() || FD->getName() != "range_covers_byte" ||
        Call.getNumArgs() != 3)
      return false;

    ProgramStateRef State = C.getState();
    SVal Zero = C.getSValBuilder().makeZeroVal(FD->getReturnType());
    std::optional<BoundStates> ReturnedTrue = compareSourceCondition(
        State, Call.getReturnValue(), BO_NE, Zero, C.getSValBuilder());
    if (!ReturnedTrue)
      return false;

    ProgramStateRef Covered = ReturnedTrue->Safe;
    ProgramStateRef NotCovered = ReturnedTrue->Unsafe;
    if (!Covered)
      return false;

    SVal Offset = Call.getArgSVal(0);
    SVal Length = Call.getArgSVal(1);
    SVal Byte = Call.getArgSVal(2);
    QualType ArithmeticType = Call.getArgExpr(0)->getType();
    SVal One = C.getSValBuilder().makeIntVal(1, ArithmeticType);
    SVal Last = C.getSValBuilder().evalBinOp(Covered, BO_Add, Offset, Length,
                                             ArithmeticType);
    Last = C.getSValBuilder().evalBinOp(Covered, BO_Sub, Last, One,
                                        ArithmeticType);
    if (Last.isUnknownOrUndef())
      return false;

    std::optional<BoundStates> AtOrAboveOffset = compareSourceCondition(
        Covered, Offset, BO_LE, Byte, C.getSValBuilder());
    if (!AtOrAboveOffset || !AtOrAboveOffset->Safe)
      return false;
    Covered = AtOrAboveOffset->Safe;

    std::optional<BoundStates> AtOrBelowLast =
        compareSourceCondition(Covered, Byte, BO_LE, Last, C.getSValBuilder());
    if (!AtOrBelowLast || !AtOrBelowLast->Safe)
      return false;
    Covered = AtOrBelowLast->Safe;

    if (NotCovered)
      C.addTransition(NotCovered);
    C.addTransition(Covered);
    return true;
  }

  bool modelShiftedBoundPredicate(const CallEvent &Call,
                                  CheckerContext &C) const {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD)
      return false;
    auto Found = ShiftedBoundPredicates.find(FD->getCanonicalDecl());
    if (Found == ShiftedBoundPredicates.end() ||
        Found->second.Parameter >= Call.getNumArgs())
      return false;

    ProgramStateRef State = C.getState();
    SVal Zero = C.getSValBuilder().makeZeroVal(FD->getReturnType());
    std::optional<BoundStates> ReturnedTrue = compareSourceCondition(
        State, Call.getReturnValue(), BO_NE, Zero, C.getSValBuilder());
    if (!ReturnedTrue || !ReturnedTrue->Safe)
      return false;

    ProgramStateRef InRange = ReturnedTrue->Safe;
    ProgramStateRef OutOfRange = ReturnedTrue->Unsafe;
    const Expr *Argument = Call.getArgExpr(Found->second.Parameter);
    QualType ArgumentType = Argument->getType();
    SVal Shift =
        C.getSValBuilder().makeIntVal(Found->second.Shift, ArgumentType);
    SVal Index = C.getSValBuilder().evalBinOp(
        InRange, BO_Shr, Call.getArgSVal(Found->second.Parameter), Shift,
        ArgumentType);
    SVal Limit = C.getSValBuilder().makeIntVal(Found->second.ExclusiveLimit,
                                               ArgumentType);
    if (Index.isUnknownOrUndef())
      return false;
    std::optional<BoundStates> BelowLimit = compareSourceCondition(
        InRange, Index, BO_LT, Limit, C.getSValBuilder());
    if (!BelowLimit || !BelowLimit->Safe)
      return false;

    if (OutOfRange)
      C.addTransition(OutOfRange);
    C.addTransition(BelowLimit->Safe);
    return true;
  }

  BugType &bugType(bool Definite) const {
    std::unique_ptr<BugType> &BT = Definite ? LevelABug : LevelBBug;
    if (!BT)
      BT = std::make_unique<BugType>(
          this,
          Definite ? "Level A guest-controlled host-memory violation"
                   : "Level B guest-controlled host-memory bound not proven",
          "QEMU guest memory safety");
    return *BT;
  }

  void report(CheckerContext &C, ProgramStateRef Safe, ProgramStateRef Unsafe,
              SVal TaintedValue, const Expr *Where, StringRef Sink,
              SVal ExtentOrCount, bool Elements,
              StringRef SourceDetail = {}) const {
    if (!Unsafe)
      return;
    bool Definite = !Safe;
    if (Safe)
      C.addTransition(Safe);
    ExplodedNode *Node = C.generateErrorNode(Unsafe);
    if (!Node)
      return;

    llvm::SmallString<256> Buffer;
    llvm::raw_svector_ostream Message(Buffer);
    Message << (Definite ? "Level A: guest-controlled "
                         : "Level B: guest-controlled ")
            << Sink << (Definite ? " exceeds " : " may exceed ")
            << "the host object " << (Elements ? "element count" : "extent")
            << " (value "
            << valueRange(Unsafe, TaintedValue, C.getSValBuilder()) << ", "
            << (Elements ? "elements " : "bytes ")
            << valueRange(Unsafe, ExtentOrCount, C.getSValBuilder());
    if (!SourceDetail.empty())
      Message << ", source " << SourceDetail;
    Message << ')';

    auto Report = std::make_unique<PathSensitiveBugReport>(bugType(Definite),
                                                           Message.str(), Node);
    if (Where)
      Report->addRange(Where->getSourceRange());
    for (SymbolRef Sym : taint::getTaintedSymbols(Unsafe, TaintedValue))
      Report->markInteresting(Sym);
    C.emitReport(std::move(Report));
  }

  static std::string
  persistentSourceDescription(const PersistentFieldInfo &Info) {
    return inputClassName(Info.Source).str() + "-stored field '" +
           Info.Field->getNameAsString() + "'";
  }

  std::optional<PersistentFieldInfo>
  persistentGuestFieldFromTaint(ProgramStateRef State, SVal Value) const {
    const FieldDecl *Field = nullptr;
    bool Found = false;
    for (SymbolRef Symbol : taint::getTaintedSymbols(State, Value)) {
      const FieldDecl *const *Mapped =
          State->get<QEMUPersistentFieldSources>(Symbol);
      // Do not attribute a composite value to one field when any of its
      // tainted roots has another or unknown origin.
      if (!Mapped || !*Mapped)
        return std::nullopt;
      if (Found && Field != *Mapped)
        return std::nullopt;
      Field = *Mapped;
      Found = true;
    }
    if (!Found)
      return std::nullopt;
    auto Source = PersistentGuestFields.find(Field);
    if (Source == PersistentGuestFields.end())
      return std::nullopt;
    return PersistentFieldInfo{Field, Source->second};
  }

  static const Expr *bindingSourceExpression(const Stmt *S,
                                             const VarDecl *Destination) {
    if (!S)
      return nullptr;
    if (const auto *Assignment = dyn_cast<BinaryOperator>(S))
      if (Assignment->isAssignmentOp()) {
        if (Assignment->getOpcode() == BO_Assign)
          return Assignment->getRHS();
        return Assignment;
      }
    if (const auto *Declaration = dyn_cast<DeclStmt>(S))
      for (const Decl *D : Declaration->decls())
        if (const auto *Variable = dyn_cast<VarDecl>(D))
          if (Variable->getCanonicalDecl() == Destination->getCanonicalDecl())
            return Variable->getInit();
    return dyn_cast<Expr>(S);
  }

  std::optional<PersistentFieldInfo>
  persistentGuestFieldFromAliases(const Expr *E, ProgramStateRef State,
                                  CheckerContext &C, SVal Value) const {
    if (!E)
      return std::nullopt;

    class LocalSourceVisitor : public DynamicRecursiveASTVisitor {
      ProgramStateRef State;
      const StackFrameContext *Frame;
      const llvm::DenseMap<const FieldDecl *, InputClass> &PersistentFields;

      bool addField(const FieldDecl *Candidate) {
        if (Found && Field != Candidate) {
          Ambiguous = true;
          return false;
        }
        Field = Candidate;
        Found = true;
        return true;
      }

    public:
      const FieldDecl *Field = nullptr;
      bool Found = false;
      bool Ambiguous = false;
      bool HasScalarParameter = false;

      LocalSourceVisitor(
          ProgramStateRef State, const StackFrameContext *Frame,
          const llvm::DenseMap<const FieldDecl *, InputClass> &PersistentFields)
          : State(State), Frame(Frame), PersistentFields(PersistentFields) {}

      bool VisitMemberExpr(MemberExpr *ME) override {
        const auto *Candidate = dyn_cast<FieldDecl>(ME->getMemberDecl());
        if (!Candidate)
          return true;
        Candidate = Candidate->getCanonicalDecl();
        if (!PersistentFields.contains(Candidate))
          return true;
        return addField(Candidate);
      }

      bool VisitDeclRefExpr(DeclRefExpr *DRE) override {
        const auto *Variable = dyn_cast<VarDecl>(DRE->getDecl());
        if (!Variable)
          return true;
        if (isa<ParmVarDecl>(Variable) && Variable->getType()->isIntegerType())
          HasScalarParameter = true;
        if (!Variable->isLocalVarDecl())
          return true;
        const VarRegion *Region = State->getRegion(Variable, Frame);
        const FieldDecl *const *Mapped =
            State->get<QEMUPersistentLocalSources>(Region);
        if (!Mapped || !*Mapped)
          return true;
        return addField(*Mapped);
      }
    } Visitor(State, C.getStackFrame(), PersistentGuestFields);
    Visitor.TraverseStmt(const_cast<Expr *>(E));
    if (Visitor.Ambiguous)
      return std::nullopt;
    if (Visitor.Found) {
      auto Source = PersistentGuestFields.find(Visitor.Field);
      if (Source != PersistentGuestFields.end())
        return PersistentFieldInfo{Visitor.Field, Source->second};
      return std::nullopt;
    }

    // An inlined callee's scalar parameter keeps the caller's symbolic
    // value, but has no ordinary assignment in the callee to record.  Use
    // symbol provenance only for that narrow case.  This avoids attributing
    // unrelated unknown local values to an earlier tainted field.
    if (Visitor.HasScalarParameter)
      return persistentGuestFieldFromTaint(State, Value);
    return std::nullopt;
  }

  struct MemorySink {
    unsigned BufferArgument;
    unsigned LengthArgument;
    StringRef Description;
  };

  static std::optional<MemorySink>
  destinationMemorySink(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier())
      return std::nullopt;
    StringRef Name = FD->getName();
    if ((Name == "memcpy" || Name == "memmove" || Name == "memset" ||
         Name == "__builtin_memcpy" || Name == "__builtin_memmove" ||
         Name == "__builtin_memset") &&
        Call.getNumArgs() >= 3)
      return MemorySink{0, 2, "memory-operation length"};
    if (Name == "iov_to_buf" && Call.getNumArgs() >= 5)
      return MemorySink{3, 4, "memory-operation length"};
    if (Name == "qemu_iovec_to_buf" && Call.getNumArgs() >= 4)
      return MemorySink{2, 3, "memory-operation length"};
    if ((Name == "address_space_read" || Name == "address_space_read_full") &&
        Call.getNumArgs() >= 5)
      return MemorySink{3, 4, "memory-operation length"};
    if ((Name == "dma_memory_read" || Name == "pci_dma_read") &&
        Call.getNumArgs() >= 4)
      return MemorySink{2, 3, "memory-operation length"};
    if (Name == "cpu_physical_memory_read" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "memory-operation length"};
    if (Name == "physical_memory_read" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "memory-operation length"};
    if (Name == "qemu_get_buffer" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "memory-operation length"};
    if (Name == "bdrv_pread" && Call.getNumArgs() >= 5)
      return MemorySink{3, 2, "memory-operation length"};
    return std::nullopt;
  }

  static std::optional<MemorySink> sourceMemorySink(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier())
      return std::nullopt;
    StringRef Name = FD->getName();
    if ((Name == "memcpy" || Name == "memmove" || Name == "__builtin_memcpy" ||
         Name == "__builtin_memmove") &&
        Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "memory-operation source length"};
    if ((Name == "iov_from_buf" && Call.getNumArgs() >= 5))
      return MemorySink{3, 4, "memory-operation source length"};
    if (Name == "qemu_iovec_from_buf" && Call.getNumArgs() >= 4)
      return MemorySink{2, 3, "memory-operation source length"};
    if ((Name == "qemu_send_packet" || Name == "qemu_send_packet_raw" ||
         Name == "qemu_send_packet_async") &&
        Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "packet length"};
    if ((Name == "dma_memory_write" || Name == "pci_dma_write") &&
        Call.getNumArgs() >= 4)
      return MemorySink{2, 3, "DMA source length"};
    if (Name == "cpu_physical_memory_write" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "DMA source length"};
    if (Name == "qemu_put_buffer" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "migration-output source length"};
    if (Name == "bdrv_pwrite" && Call.getNumArgs() >= 5)
      return MemorySink{3, 2, "block-write source length"};
    return std::nullopt;
  }

  static std::optional<unsigned> allocationSizeArgument(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier())
      return std::nullopt;
    StringRef Name = FD->getName();
    if ((Name == "malloc" || Name == "g_malloc" || Name == "g_malloc0" ||
         Name == "g_try_malloc" || Name == "g_try_malloc0") &&
        Call.getNumArgs() >= 1)
      return 0;
    if ((Name == "realloc" || Name == "g_realloc" || Name == "g_try_realloc" ||
         Name == "qemu_memalign") &&
        Call.getNumArgs() >= 2)
      return 1;
    return std::nullopt;
  }

  static const BinaryOperator *sizeArithmetic(const Expr *E) {
    if (!E)
      return nullptr;
    E = E->IgnoreParenImpCasts();
    while (const auto *Cast = dyn_cast<CastExpr>(E))
      E = Cast->getSubExpr()->IgnoreParenImpCasts();
    const auto *BO = dyn_cast<BinaryOperator>(E);
    if (!BO || (BO->getOpcode() != BO_Add && BO->getOpcode() != BO_Mul) ||
        !BO->getType()->isUnsignedIntegerType())
      return nullptr;
    return BO;
  }

  static SVal expressionValue(const Expr *E, CheckerContext &C) {
    const Expr *Core = E->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Core))
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        const VarRegion *Region =
            C.getState()->getRegion(VD, C.getStackFrame());
        SVal Value = C.getState()->getSVal(Region);
        if (!Value.isUnknownOrUndef())
          return Value;
        if (const SVal *Saved =
                C.getState()->get<QEMUSavedTaintedScalars>(Region))
          return *Saved;
        return Value;
      }
    return C.getSVal(E);
  }

  static SVal storedExpressionValue(const Expr *E, CheckerContext &C) {
    const Expr *Core = E->IgnoreParenImpCasts();
    if (const auto *ME = dyn_cast<MemberExpr>(Core))
      if (ME->isArrow())
        if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
          SVal Object = storedExpressionValue(ME->getBase(), C);
          SVal FieldLocation = C.getState()->getLValue(FD, Object);
          if (auto Location = FieldLocation.getAs<Loc>())
            return C.getState()->getSVal(*Location);
        }
    return expressionValue(E, C);
  }

  static SVal pointerValue(const Expr *E, CheckerContext &C) {
    const Expr *Core = E->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Core))
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
        if (VD->getType()->isArrayType())
          return C.getState()->getLValue(VD, C.getStackFrame());
    return C.getSVal(E);
  }

  static const MemRegion *pointerBaseRegion(SVal Value) {
    const MemRegion *Region = Value.getAsRegion();
    return Region ? Region->getBaseRegion() : nullptr;
  }

  static bool isTrackedVirtqueueIovec(ProgramStateRef State, SVal Value) {
    const MemRegion *Region = pointerBaseRegion(Value);
    return Region && State->contains<QEMUVirtqueueIovecs>(Region);
  }

  static bool isVirtqueueOutIovecValue(ProgramStateRef State, SVal Value) {
    const auto *Pointer = dyn_cast_or_null<SymbolicRegion>(Value.getAsRegion());
    const auto *Stored =
        Pointer ? dyn_cast<SymbolRegionValue>(Pointer->getSymbol()) : nullptr;
    const auto *Field =
        Stored ? dyn_cast<FieldRegion>(Stored->getRegion()) : nullptr;
    const FieldDecl *Declaration = Field ? Field->getDecl() : nullptr;
    const auto *Parent =
        Declaration ? dyn_cast<RecordDecl>(Declaration->getDeclContext())
                    : nullptr;
    if (!Field || !Declaration || !Parent ||
        Parent->getName() != "VirtQueueElement" ||
        Declaration->getName() != "out_sg")
      return false;
    return State->contains<QEMUVirtqueueElements>(Field->getBaseRegion());
  }

  static bool isVirtqueueIovec(const CallEvent &Call, unsigned Argument,
                               ProgramStateRef State) {
    return Argument < Call.getNumArgs() &&
           (isTrackedVirtqueueIovec(State, Call.getArgSVal(Argument)) ||
            isVirtqueueOutIovecValue(State, Call.getArgSVal(Argument)));
  }

  struct IntegerRange {
    uint64_t Minimum;
    uint64_t Maximum;
  };

  static std::optional<IntegerRange>
  integerConstantRange(const llvm::APSInt &Value) {
    if (Value.isNegative() || Value.getBitWidth() > 64)
      return std::nullopt;
    uint64_t Constant = Value.getZExtValue();
    return IntegerRange{Constant, Constant};
  }

  static std::optional<IntegerRange>
  applyIntegerBinaryRange(IntegerRange Left, IntegerRange Right,
                          BinaryOperatorKind Opcode) {
    switch (Opcode) {
    case BO_Add:
      if (Left.Maximum > std::numeric_limits<uint64_t>::max() - Right.Maximum)
        return std::nullopt;
      return IntegerRange{Left.Minimum + Right.Minimum,
                          Left.Maximum + Right.Maximum};
    case BO_Sub:
      if (Left.Minimum < Right.Maximum)
        return std::nullopt;
      return IntegerRange{Left.Minimum - Right.Maximum,
                          Left.Maximum - Right.Minimum};
    case BO_Mul:
      if (Right.Maximum &&
          Left.Maximum > std::numeric_limits<uint64_t>::max() / Right.Maximum)
        return std::nullopt;
      return IntegerRange{Left.Minimum * Right.Minimum,
                          Left.Maximum * Right.Maximum};
    case BO_Div:
      if (Right.Minimum == 0)
        return std::nullopt;
      return IntegerRange{Left.Minimum / Right.Maximum,
                          Left.Maximum / Right.Minimum};
    case BO_Rem:
      if (Right.Minimum == 0)
        return std::nullopt;
      return IntegerRange{0, std::min(Left.Maximum, Right.Maximum - 1)};
    case BO_Shr:
      if (Right.Maximum >= 64)
        return std::nullopt;
      return IntegerRange{Left.Minimum >> Right.Maximum,
                          Left.Maximum >> Right.Minimum};
    case BO_And:
      if (Right.Minimum == Right.Maximum)
        return IntegerRange{0, std::min(Left.Maximum, Right.Maximum)};
      if (Left.Minimum == Left.Maximum)
        return IntegerRange{0, std::min(Right.Maximum, Left.Maximum)};
      return std::nullopt;
    default:
      return std::nullopt;
    }
  }

  static std::optional<IntegerRange>
  constrainRangeToType(IntegerRange Range, QualType Type, ASTContext &Context) {
    if (!Type->isUnsignedIntegerType())
      return Range;
    unsigned Width = Context.getIntWidth(Type);
    if (Width >= 64)
      return Range;
    uint64_t Maximum = (uint64_t(1) << Width) - 1;
    if (Range.Maximum <= Maximum)
      return Range;
    return IntegerRange{0, Maximum};
  }

  static std::optional<IntegerRange> symbolicIntegerRange(const SymExpr *Symbol,
                                                          ProgramStateRef State,
                                                          SValBuilder &SVB,
                                                          unsigned Depth = 0) {
    if (!Symbol || Depth > 12)
      return std::nullopt;
    if (const auto *Cast = dyn_cast<SymbolCast>(Symbol)) {
      std::optional<IntegerRange> Operand =
          symbolicIntegerRange(Cast->getOperand(), State, SVB, Depth + 1);
      if (!Operand)
        return std::nullopt;
      return constrainRangeToType(*Operand, Cast->getType(), SVB.getContext());
    }
    if (const auto *Expression = dyn_cast<SymIntExpr>(Symbol)) {
      std::optional<IntegerRange> Left =
          symbolicIntegerRange(Expression->getLHS(), State, SVB, Depth + 1);
      std::optional<IntegerRange> Right =
          integerConstantRange(*Expression->getRHS());
      if (!Left || !Right)
        return std::nullopt;
      std::optional<IntegerRange> Result =
          applyIntegerBinaryRange(*Left, *Right, Expression->getOpcode());
      return Result ? constrainRangeToType(*Result, Expression->getType(),
                                           SVB.getContext())
                    : std::nullopt;
    }
    if (const auto *Expression = dyn_cast<IntSymExpr>(Symbol)) {
      std::optional<IntegerRange> Left =
          integerConstantRange(*Expression->getLHS());
      std::optional<IntegerRange> Right =
          symbolicIntegerRange(Expression->getRHS(), State, SVB, Depth + 1);
      if (!Left || !Right)
        return std::nullopt;
      std::optional<IntegerRange> Result =
          applyIntegerBinaryRange(*Left, *Right, Expression->getOpcode());
      return Result ? constrainRangeToType(*Result, Expression->getType(),
                                           SVB.getContext())
                    : std::nullopt;
    }
    if (const auto *Expression = dyn_cast<SymSymExpr>(Symbol)) {
      std::optional<IntegerRange> Left =
          symbolicIntegerRange(Expression->getLHS(), State, SVB, Depth + 1);
      std::optional<IntegerRange> Right =
          symbolicIntegerRange(Expression->getRHS(), State, SVB, Depth + 1);
      if (!Left || !Right)
        return std::nullopt;
      std::optional<IntegerRange> Result =
          applyIntegerBinaryRange(*Left, *Right, Expression->getOpcode());
      return Result ? constrainRangeToType(*Result, Expression->getType(),
                                           SVB.getContext())
                    : std::nullopt;
    }

    SVal Value = nonloc::SymbolVal(Symbol);
    const llvm::APSInt *Minimum = SVB.getMinValue(State, Value);
    const llvm::APSInt *Maximum = SVB.getMaxValue(State, Value);
    if (!Minimum || !Maximum || Minimum->isNegative() ||
        Minimum->getBitWidth() > 64 || Maximum->getBitWidth() > 64)
      return std::nullopt;
    return IntegerRange{Minimum->getZExtValue(), Maximum->getZExtValue()};
  }

  static std::optional<IntegerRange>
  symbolicIntegerRange(SVal Value, ProgramStateRef State, SValBuilder &SVB) {
    if (const auto Concrete = Value.getAs<nonloc::ConcreteInt>())
      return integerConstantRange(*Concrete->getValue());
    if (const auto Symbol = Value.getAs<nonloc::SymbolVal>())
      return symbolicIntegerRange(Symbol->getSymbol(), State, SVB);
    return std::nullopt;
  }

  static std::optional<IntegerRange> unsignedTypeRange(QualType Type,
                                                       ASTContext &Context) {
    if (!Type->isUnsignedIntegerType())
      return std::nullopt;
    unsigned Width = Context.getIntWidth(Type);
    if (!Width || Width > 64)
      return std::nullopt;
    uint64_t Maximum = Width == 64 ? std::numeric_limits<uint64_t>::max()
                                   : (uint64_t(1) << Width) - 1;
    return IntegerRange{0, Maximum};
  }

  static std::optional<IntegerRange>
  integerRange(const Expr *E, CheckerContext &C, unsigned Depth = 0) {
    if (!E || Depth > 8)
      return std::nullopt;
    E = E->IgnoreParenImpCasts();
    if (const auto *Literal = dyn_cast<IntegerLiteral>(E)) {
      if (Literal->getValue().getActiveBits() > 64)
        return std::nullopt;
      uint64_t Value = Literal->getValue().getZExtValue();
      return IntegerRange{Value, Value};
    }
    if (isa<DeclRefExpr>(E) || isa<ArraySubscriptExpr>(E) ||
        isa<MemberExpr>(E)) {
      std::optional<IntegerRange> InitializerRange;
      if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
        if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
          if (VD->isLocalVarDecl() && !isa<ParmVarDecl>(VD) && VD->hasInit())
            InitializerRange = integerRange(VD->getInit(), C, Depth + 1);
      auto IntersectInitializer = [&](IntegerRange Range) {
        if (!InitializerRange)
          return Range;
        return IntegerRange{std::max(Range.Minimum, InitializerRange->Minimum),
                            std::min(Range.Maximum, InitializerRange->Maximum)};
      };
      SVal Value = expressionValue(E, C);
      if (std::optional<IntegerRange> Range =
              symbolicIntegerRange(Value, C.getState(), C.getSValBuilder()))
        if (std::optional<IntegerRange> Constrained =
                constrainRangeToType(*Range, E->getType(), C.getASTContext()))
          return IntersectInitializer(*Constrained);
      const llvm::APSInt *Minimum =
          C.getSValBuilder().getMinValue(C.getState(), Value);
      const llvm::APSInt *Maximum =
          C.getSValBuilder().getMaxValue(C.getState(), Value);
      if (!Minimum || !Maximum || Minimum->isNegative() ||
          Minimum->getBitWidth() > 64 || Maximum->getBitWidth() > 64) {
        if (std::optional<IntegerRange> TypeRange =
                unsignedTypeRange(E->getType(), C.getASTContext()))
          return IntersectInitializer(*TypeRange);
        else
          return InitializerRange;
      }
      uint64_t Low = Minimum->getZExtValue();
      uint64_t High = Maximum->getZExtValue();
      QualType Type = E->getType();
      if (Type->isUnsignedIntegerType()) {
        unsigned Width = C.getASTContext().getIntWidth(Type);
        if (Width < 64)
          High = std::min(High, (uint64_t(1) << Width) - 1);
      }
      return IntersectInitializer(IntegerRange{Low, High});
    }
    if (const auto *Cast = dyn_cast<CastExpr>(E)) {
      std::optional<IntegerRange> Operand =
          integerRange(Cast->getSubExpr(), C, Depth + 1);
      if (!Operand)
        return std::nullopt;
      QualType Type = Cast->getType();
      if (!Type->isUnsignedIntegerType())
        return Operand;
      unsigned Width = C.getASTContext().getIntWidth(Type);
      if (Width >= 64)
        return Operand;
      uint64_t Maximum = (uint64_t(1) << Width) - 1;
      if (Operand->Maximum <= Maximum)
        return Operand;
      return IntegerRange{0, Maximum};
    }
    const auto *BO = dyn_cast<BinaryOperator>(E);
    if (!BO)
      return std::nullopt;
    std::optional<IntegerRange> Left = integerRange(BO->getLHS(), C, Depth + 1);
    std::optional<IntegerRange> Right =
        integerRange(BO->getRHS(), C, Depth + 1);
    if (!Left || !Right)
      return std::nullopt;
    return applyIntegerBinaryRange(*Left, *Right, BO->getOpcode());
  }

  static const Expr *resolveLocalInitializer(const Expr *E,
                                             unsigned Depth = 0) {
    if (!E || Depth > 8)
      return E;
    E = E->IgnoreParenImpCasts();
    const auto *DRE = dyn_cast<DeclRefExpr>(E);
    const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
    if (!VD || !VD->isLocalVarDecl() || isa<ParmVarDecl>(VD) || !VD->hasInit())
      return E;
    return resolveLocalInitializer(VD->getInit(), Depth + 1);
  }

  static bool sameValueExpression(const Expr *Left, const Expr *Right,
                                  unsigned Depth = 0) {
    if (!Left || !Right || Depth > 8)
      return false;
    Left = resolveLocalInitializer(Left, Depth)->IgnoreParenImpCasts();
    Right = resolveLocalInitializer(Right, Depth)->IgnoreParenImpCasts();
    if (Left == Right)
      return true;
    if (const auto *LeftRef = dyn_cast<DeclRefExpr>(Left))
      if (const auto *RightRef = dyn_cast<DeclRefExpr>(Right))
        return LeftRef->getDecl()->getCanonicalDecl() ==
               RightRef->getDecl()->getCanonicalDecl();
    const auto *LeftMember = dyn_cast<MemberExpr>(Left);
    const auto *RightMember = dyn_cast<MemberExpr>(Right);
    return LeftMember && RightMember &&
           LeftMember->getMemberDecl() == RightMember->getMemberDecl() &&
           LeftMember->isArrow() == RightMember->isArrow() &&
           sameValueExpression(LeftMember->getBase(), RightMember->getBase(),
                               Depth + 1);
  }

  struct ScaledAddressIndex {
    const Expr *Address;
    const Expr *Base;
    unsigned Shift;
  };

  static std::optional<ScaledAddressIndex>
  scaledAddressIndex(const Expr *E, ASTContext &Context, unsigned Depth = 0) {
    if (!E || Depth > 8)
      return std::nullopt;
    E = resolveLocalInitializer(E, Depth)->IgnoreParenImpCasts();

    if (const auto *Subtract = dyn_cast<BinaryOperator>(E))
      if (Subtract->getOpcode() == BO_Sub) {
        const Expr *Left =
            resolveLocalInitializer(Subtract->getLHS(), Depth + 1)
                ->IgnoreParenImpCasts();
        const Expr *Right = Subtract->getRHS();
        if (const auto *Add = dyn_cast<BinaryOperator>(Left))
          if (Add->getOpcode() == BO_Add) {
            if (sameValueExpression(Add->getLHS(), Right, Depth + 1))
              return scaledAddressIndex(Add->getRHS(), Context, Depth + 1);
            if (sameValueExpression(Add->getRHS(), Right, Depth + 1))
              return scaledAddressIndex(Add->getLHS(), Context, Depth + 1);
          }
      }

    const auto *Shift = dyn_cast<BinaryOperator>(E);
    if (!Shift || Shift->getOpcode() != BO_Shr)
      return std::nullopt;
    Expr::EvalResult ShiftResult;
    if (!Shift->getRHS()->EvaluateAsInt(ShiftResult, Context,
                                        Expr::SE_NoSideEffects))
      return std::nullopt;
    const llvm::APSInt &Amount = ShiftResult.Val.getInt();
    if (Amount.isNegative() || Amount.getActiveBits() > 6 ||
        Amount.getZExtValue() >= 64)
      return std::nullopt;

    const Expr *Numerator = resolveLocalInitializer(Shift->getLHS(), Depth + 1)
                                ->IgnoreParenImpCasts();
    if (const auto *Subtract = dyn_cast<BinaryOperator>(Numerator))
      if (Subtract->getOpcode() == BO_Sub)
        return ScaledAddressIndex{Subtract->getLHS(), Subtract->getRHS(),
                                  static_cast<unsigned>(Amount.getZExtValue())};
    return ScaledAddressIndex{Numerator, nullptr,
                              static_cast<unsigned>(Amount.getZExtValue())};
  }

  static bool scaledAddressIndexCoveredByGuard(const Expr *Index,
                                               const FieldDecl *CountField,
                                               SVal Count, CheckerContext &C) {
    std::optional<ScaledAddressIndex> Pattern =
        scaledAddressIndex(Index, C.getASTContext());
    if (!Pattern)
      return false;

    ProgramStateRef State = C.getState();
    SVal Address = storedExpressionValue(Pattern->Address, C);
    if (Address.isUnknownOrUndef() || !taint::isTainted(State, Address))
      return false;

    SValBuilder &SVB = C.getSValBuilder();
    QualType CountType = CountField->getType();
    SVal ShiftAmount = SVB.makeIntVal(Pattern->Shift, CountType);
    SVal ScaledCount =
        SVB.evalBinOp(State, BO_Shl, Count, ShiftAmount, CountType);
    if (ScaledCount.isUnknownOrUndef())
      return false;

    SVal UpperBound = ScaledCount;
    QualType BoundType = CountType;
    if (Pattern->Base) {
      SVal Base = storedExpressionValue(Pattern->Base, C);
      if (Base.isUnknownOrUndef())
        return false;
      QualType BaseType = Pattern->Base->IgnoreParenImpCasts()->getType();
      SVal ConvertedCount = SVB.evalCast(ScaledCount, BaseType, CountType);
      UpperBound = SVB.evalBinOp(State, BO_Add, Base, ConvertedCount, BaseType);
      BoundType = BaseType;

      QualType AddressType = Pattern->Address->IgnoreParenImpCasts()->getType();
      SVal ConvertedBase = SVB.evalCast(Base, AddressType, BaseType);
      std::optional<BoundStates> AtOrAboveBase =
          compareSourceCondition(State, Address, BO_GE, ConvertedBase, SVB);
      if (!AtOrAboveBase || !AtOrAboveBase->Safe || AtOrAboveBase->Unsafe)
        return false;
    }

    QualType AddressType = Pattern->Address->IgnoreParenImpCasts()->getType();
    SVal ConvertedUpper = SVB.evalCast(UpperBound, AddressType, BoundType);
    std::optional<BoundStates> Outside =
        compareSourceCondition(State, Address, BO_GE, ConvertedUpper, SVB);
    return Outside && !Outside->Safe && Outside->Unsafe;
  }

  struct AddressIndex {
    const Expr *Address;
    const Expr *Base;
    uint64_t Scale;
  };

  static std::optional<uint64_t> constantUnsignedValue(const Expr *E,
                                                       ASTContext &Context) {
    Expr::EvalResult Result;
    if (!E->EvaluateAsInt(Result, Context, Expr::SE_NoSideEffects))
      return std::nullopt;
    const llvm::APSInt &Value = Result.Val.getInt();
    if (Value.isNegative() || Value.getActiveBits() > 64)
      return std::nullopt;
    return Value.getZExtValue();
  }

  static std::optional<AddressIndex>
  addressIndex(const Expr *E, ASTContext &Context, unsigned Depth = 0) {
    if (!E || Depth > 8)
      return std::nullopt;
    E = resolveLocalInitializer(E, Depth)->IgnoreParenImpCasts();

    if (const auto *Subtract = dyn_cast<BinaryOperator>(E))
      if (Subtract->getOpcode() == BO_Sub) {
        const Expr *Left =
            resolveLocalInitializer(Subtract->getLHS(), Depth + 1)
                ->IgnoreParenImpCasts();
        const Expr *Right = Subtract->getRHS();
        if (const auto *Add = dyn_cast<BinaryOperator>(Left))
          if (Add->getOpcode() == BO_Add) {
            if (sameValueExpression(Add->getLHS(), Right, Depth + 1))
              return addressIndex(Add->getRHS(), Context, Depth + 1);
            if (sameValueExpression(Add->getRHS(), Right, Depth + 1))
              return addressIndex(Add->getLHS(), Context, Depth + 1);
          }
      }

    uint64_t Scale = 1;
    const Expr *Numerator = E;
    if (const auto *Arithmetic = dyn_cast<BinaryOperator>(E)) {
      std::optional<uint64_t> Amount =
          constantUnsignedValue(Arithmetic->getRHS(), Context);
      if (Arithmetic->getOpcode() == BO_Shr && Amount && *Amount < 64) {
        Scale = uint64_t(1) << *Amount;
        Numerator = Arithmetic->getLHS();
      } else if (Arithmetic->getOpcode() == BO_Div && Amount && *Amount > 0) {
        Scale = *Amount;
        Numerator = Arithmetic->getLHS();
      }
    }

    Numerator =
        resolveLocalInitializer(Numerator, Depth + 1)->IgnoreParenImpCasts();
    if (const auto *Mask = dyn_cast<BinaryOperator>(Numerator))
      if (Mask->getOpcode() == BO_And) {
        if (constantUnsignedValue(Mask->getRHS(), Context))
          Numerator = Mask->getLHS()->IgnoreParenImpCasts();
        else if (constantUnsignedValue(Mask->getLHS(), Context))
          Numerator = Mask->getRHS()->IgnoreParenImpCasts();
      }

    if (const auto *Subtract = dyn_cast<BinaryOperator>(Numerator))
      if (Subtract->getOpcode() == BO_Sub)
        return AddressIndex{Subtract->getLHS(), Subtract->getRHS(), Scale};
    return AddressIndex{Numerator, nullptr, Scale};
  }

  static bool addressIndexCoveredByGuard(const Expr *Index, SVal Count,
                                         CheckerContext &C) {
    std::optional<AddressIndex> Pattern =
        addressIndex(Index, C.getASTContext());
    if (!Pattern)
      return false;

    ProgramStateRef State = C.getState();
    SVal Address = storedExpressionValue(Pattern->Address, C);
    if (Address.isUnknownOrUndef() || !taint::isTainted(State, Address))
      return false;

    SValBuilder &SVB = C.getSValBuilder();
    QualType CountType = Count.getType(C.getASTContext());
    if (CountType.isNull() || !CountType->isIntegerType())
      return false;
    SVal Scale = SVB.makeIntVal(Pattern->Scale, CountType);
    SVal ScaledCount = SVB.evalBinOp(State, BO_Mul, Count, Scale, CountType);
    if (ScaledCount.isUnknownOrUndef())
      return false;

    SVal UpperBound = ScaledCount;
    QualType BoundType = CountType;
    QualType AddressType = Pattern->Address->IgnoreParenImpCasts()->getType();
    if (Pattern->Base) {
      SVal Base = storedExpressionValue(Pattern->Base, C);
      if (Base.isUnknownOrUndef())
        if (std::optional<uint64_t> Constant =
                constantUnsignedValue(Pattern->Base, C.getASTContext()))
          Base = SVB.makeIntVal(
              *Constant, Pattern->Base->IgnoreParenImpCasts()->getType());
      if (Base.isUnknownOrUndef())
        return false;
      QualType BaseType = Pattern->Base->IgnoreParenImpCasts()->getType();
      SVal ConvertedCount = SVB.evalCast(ScaledCount, BaseType, CountType);
      UpperBound = SVB.evalBinOp(State, BO_Add, Base, ConvertedCount, BaseType);
      BoundType = BaseType;

      SVal ConvertedBase = SVB.evalCast(Base, AddressType, BaseType);
      std::optional<BoundStates> SourceLower =
          compareSourceCondition(State, Address, BO_GE, ConvertedBase, SVB);
      std::optional<BoundStates> AnalyzerLower =
          compare(State, Address, BO_GE, ConvertedBase, SVB);
      bool LowerProven =
          (SourceLower && SourceLower->Safe && !SourceLower->Unsafe) ||
          (AnalyzerLower && AnalyzerLower->Safe && !AnalyzerLower->Unsafe);
      if (!LowerProven)
        return false;
    }

    SVal ConvertedUpper = SVB.evalCast(UpperBound, AddressType, BoundType);
    std::optional<BoundStates> SourceOutside =
        compareSourceCondition(State, Address, BO_GE, ConvertedUpper, SVB);
    std::optional<BoundStates> AnalyzerOutside =
        compare(State, Address, BO_GE, ConvertedUpper, SVB);
    return (SourceOutside && !SourceOutside->Safe && SourceOutside->Unsafe) ||
           (AnalyzerOutside && !AnalyzerOutside->Safe &&
            AnalyzerOutside->Unsafe);
  }

  bool indexCoveredByCallbackAccess(const Expr *Index,
                                    const llvm::APSInt &ElementCount,
                                    CheckerContext &C) const {
    if (!C.inTopFrame() || ElementCount.isNegative() ||
        ElementCount.getBitWidth() > 64)
      return false;
    const auto *FD = dyn_cast<FunctionDecl>(C.getStackFrame()->getDecl());
    if (!FD)
      return false;
    auto Found = Callbacks.find(FD->getCanonicalDecl());
    if (Found == Callbacks.end() || !Found->second.AddressLimit ||
        !Found->second.AddressParameter || !Found->second.AccessSizeParameter ||
        *Found->second.AddressLimit != ElementCount.getZExtValue())
      return false;

    const auto *Add = dyn_cast<BinaryOperator>(Index->IgnoreParenImpCasts());
    if (!Add || Add->getOpcode() != BO_Add)
      return false;
    unsigned AddressIndex = *Found->second.AddressParameter;
    unsigned SizeIndex = *Found->second.AccessSizeParameter;
    if (AddressIndex >= FD->getNumParams() || SizeIndex >= FD->getNumParams())
      return false;

    const ParmVarDecl *AddressParameter = FD->getParamDecl(AddressIndex);
    auto IsAddress = [AddressParameter](const Expr *E) {
      E = E->IgnoreParenImpCasts();
      const auto *DRE = dyn_cast<DeclRefExpr>(E);
      return DRE && DRE->getDecl()->getCanonicalDecl() ==
                        AddressParameter->getCanonicalDecl();
    };
    const Expr *Offset = nullptr;
    if (IsAddress(Add->getLHS()))
      Offset = Add->getRHS();
    else if (IsAddress(Add->getRHS()))
      Offset = Add->getLHS();
    if (!Offset)
      return false;

    ProgramStateRef State = C.getState();
    SVal OffsetValue = expressionValue(Offset, C);
    const llvm::APSInt *Minimum =
        C.getSValBuilder().getMinValue(State, OffsetValue);
    if (!Minimum || Minimum->isNegative())
      return false;

    const ParmVarDecl *SizeParameter = FD->getParamDecl(SizeIndex);
    const MemRegion *SizeRegion =
        State->getRegion(SizeParameter, C.getStackFrame());
    SVal AccessSize = State->getSVal(SizeRegion);
    std::optional<BoundStates> BelowAccessSize =
        compare(State, OffsetValue, BO_LT, AccessSize, C.getSValBuilder());
    return BelowAccessSize && BelowAccessSize->Safe && !BelowAccessSize->Unsafe;
  }

  bool memorySinkCoveredByCallbackAccess(const Expr *Offset, const Expr *Length,
                                         SVal BaseExtent,
                                         CheckerContext &C) const {
    if (!C.inTopFrame())
      return false;
    const auto *FD = dyn_cast<FunctionDecl>(C.getStackFrame()->getDecl());
    if (!FD)
      return false;
    auto Found = Callbacks.find(FD->getCanonicalDecl());
    if (Found == Callbacks.end() || !Found->second.AddressLimit ||
        !Found->second.AddressParameter || !Found->second.AccessSizeParameter)
      return false;

    const llvm::APSInt *KnownExtent =
        C.getSValBuilder().getKnownValue(C.getState(), BaseExtent);
    if (!KnownExtent || KnownExtent->isNegative() ||
        KnownExtent->getBitWidth() > 64 ||
        KnownExtent->getZExtValue() != *Found->second.AddressLimit)
      return false;

    unsigned AddressIndex = *Found->second.AddressParameter;
    unsigned SizeIndex = *Found->second.AccessSizeParameter;
    if (AddressIndex >= FD->getNumParams() || SizeIndex >= FD->getNumParams())
      return false;
    auto ReferencesParameter = [](const Expr *E, const ParmVarDecl *Parameter) {
      E = E->IgnoreParenImpCasts();
      const auto *DRE = dyn_cast<DeclRefExpr>(E);
      return DRE && DRE->getDecl()->getCanonicalDecl() ==
                        Parameter->getCanonicalDecl();
    };
    return ReferencesParameter(Offset, FD->getParamDecl(AddressIndex)) &&
           ReferencesParameter(Length, FD->getParamDecl(SizeIndex));
  }

  static SVal allocationSizeValue(const CallEvent &Call, unsigned SizeIndex,
                                  CheckerContext &C) {
    const Expr *Argument = Call.getArgExpr(SizeIndex);
    SVal Value = expressionValue(Argument, C);
    QualType UnpromotedType = Argument->IgnoreParenImpCasts()->getType();
    if (!UnpromotedType->isUnsignedIntegerType())
      return Value;

    llvm::APSInt StaticMaximum =
        C.getSValBuilder().getBasicValueFactory().getMaxValue(UnpromotedType);
    const llvm::APSInt *DynamicMaximum =
        C.getSValBuilder().getMaxValue(C.getState(), Value);
    bool ExceedsStaticMaximum = !DynamicMaximum;
    if (DynamicMaximum) {
      unsigned Width =
          DynamicMaximum->getBitWidth() > StaticMaximum.getBitWidth()
              ? DynamicMaximum->getBitWidth()
              : StaticMaximum.getBitWidth();
      ExceedsStaticMaximum = DynamicMaximum->zextOrTrunc(Width).ugt(
          StaticMaximum.zextOrTrunc(Width));
    }
    if (Value.isUnknownOrUndef() || ExceedsStaticMaximum)
      return C.getSValBuilder().makeIntVal(StaticMaximum);
    return Value;
  }

  struct OverflowResult {
    bool MayOverflow;
    bool MustOverflow;
  };

  static std::optional<OverflowResult>
  overflowRange(ProgramStateRef State, SVal Left, SVal Right,
                BinaryOperatorKind Opcode, unsigned Width, SValBuilder &SVB) {
    const llvm::APSInt *LeftMin = SVB.getMinValue(State, Left);
    const llvm::APSInt *LeftMax = SVB.getMaxValue(State, Left);
    const llvm::APSInt *RightMin = SVB.getMinValue(State, Right);
    const llvm::APSInt *RightMax = SVB.getMaxValue(State, Right);
    if (!LeftMin || !LeftMax || !RightMin || !RightMax || Width == 0 ||
        Width > 256 || LeftMin->isNegative() || RightMin->isNegative())
      return std::nullopt;

    unsigned WideWidth = Opcode == BO_Mul ? Width * 2 : Width + 1;
    llvm::APInt Limit = llvm::APInt::getMaxValue(Width).zext(WideWidth);
    auto Evaluate = [Opcode, WideWidth](const llvm::APSInt &A,
                                        const llvm::APSInt &B) {
      llvm::APInt WideA = A.zextOrTrunc(WideWidth);
      llvm::APInt WideB = B.zextOrTrunc(WideWidth);
      return Opcode == BO_Mul ? WideA * WideB : WideA + WideB;
    };
    bool May = Evaluate(*LeftMax, *RightMax).ugt(Limit);
    bool Must = Evaluate(*LeftMin, *RightMin).ugt(Limit);
    return OverflowResult{May, Must};
  }

  void checkAllocationOverflow(const CallEvent &Call, CheckerContext &C) const {
    std::optional<unsigned> SizeIndex = allocationSizeArgument(Call);
    if (!SizeIndex)
      return;
    const BinaryOperator *Arithmetic =
        sizeArithmetic(Call.getArgExpr(*SizeIndex));
    if (!Arithmetic)
      return;

    ProgramStateRef State = C.getState();
    SVal Left = expressionValue(Arithmetic->getLHS(), C);
    SVal Right = expressionValue(Arithmetic->getRHS(), C);
    SVal Size = Call.getArgSVal(*SizeIndex);
    if (!taint::isTainted(State, Left) && !taint::isTainted(State, Right) &&
        !taint::isTainted(State, Size))
      return;

    unsigned Width = C.getASTContext().getIntWidth(Arithmetic->getType());
    std::optional<OverflowResult> Result = overflowRange(
        State, Left, Right, Arithmetic->getOpcode(), Width, C.getSValBuilder());
    if (!Result || !Result->MayOverflow)
      return;

    ExplodedNode *Node = C.generateNonFatalErrorNode();
    if (!Node)
      return;
    llvm::SmallString<256> Buffer;
    llvm::raw_svector_ostream Message(Buffer);
    Message << (Result->MustOverflow
                    ? "Level A: guest-controlled allocation-size arithmetic "
                      "overflows"
                    : "Level B: guest-controlled allocation-size arithmetic "
                      "may overflow")
            << " before the allocation (left "
            << valueRange(State, Left, C.getSValBuilder()) << ", right "
            << valueRange(State, Right, C.getSValBuilder()) << ')';
    auto Report = std::make_unique<PathSensitiveBugReport>(
        bugType(Result->MustOverflow), Message.str(), Node);
    Report->addRange(Arithmetic->getSourceRange());
    for (SVal Value : {Left, Right, Size})
      for (SymbolRef Sym : taint::getTaintedSymbols(State, Value))
        Report->markInteresting(Sym);
    C.emitReport(std::move(Report));
  }

  void checkMemorySink(const CallEvent &Call, const MemorySink &Sink,
                       CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    SVal Length = Call.getArgSVal(Sink.LengthArgument);
    const Expr *LengthExpression = Call.getArgExpr(Sink.LengthArgument);
    std::optional<PersistentFieldInfo> Persistent =
        persistentGuestField(LengthExpression);
    if (!taint::isTainted(State, Length)) {
      if (!Persistent)
        return;
      State = addInputTaint(State, Length, Persistent->Source);
    }
    if (!Persistent)
      Persistent =
          persistentGuestFieldFromAliases(LengthExpression, State, C, Length);
    std::string SourceDetail;
    if (Persistent)
      SourceDetail = persistentSourceDescription(*Persistent);

    SVal Required = Length;
    SVal BoundRequired =
        expressionValue(Call.getArgExpr(Sink.LengthArgument), C);
    if (BoundRequired.isUnknownOrUndef())
      BoundRequired = Required;
    SVal Extent =
        getDynamicExtentWithOffset(State, Call.getArgSVal(Sink.BufferArgument));
    StringRef SinkDescription = Sink.Description;
    bool HasOffset = false;

    const Expr *Buffer =
        Call.getArgExpr(Sink.BufferArgument)->IgnoreParenImpCasts();
    auto StaticExtent = [&C](const Expr *E) -> std::optional<uint64_t> {
      E = E ? E->IgnoreParenImpCasts() : nullptr;
      if (!E)
        return std::nullopt;
      if (const ConstantArrayType *Array =
              C.getASTContext().getAsConstantArrayType(E->getType())) {
        if (Array->getSize().getActiveBits() > 64)
          return std::nullopt;
        uint64_t Elements = Array->getSize().getZExtValue();
        uint64_t ElementBytes = C.getASTContext()
                                    .getTypeSizeInChars(Array->getElementType())
                                    .getQuantity();
        if (ElementBytes &&
            Elements > std::numeric_limits<uint64_t>::max() / ElementBytes)
          return std::nullopt;
        return Elements * ElementBytes;
      }
      const auto *Address = dyn_cast<UnaryOperator>(E);
      if (!Address || Address->getOpcode() != UO_AddrOf)
        return std::nullopt;
      QualType ObjectType = Address->getSubExpr()->getType();
      if (ObjectType->isIncompleteType())
        return std::nullopt;
      return C.getASTContext().getTypeSizeInChars(ObjectType).getQuantity();
    };
    if (!hasUsableExtent(State, Extent, C.getSValBuilder()))
      if (std::optional<uint64_t> Bytes = StaticExtent(Buffer))
        Extent = C.getSValBuilder().makeIntVal(*Bytes,
                                               C.getASTContext().getSizeType());
    const Expr *Pointer = nullptr;
    const Expr *Offset = nullptr;
    if (const auto *Add = dyn_cast<BinaryOperator>(Buffer)) {
      if (Add->getOpcode() == BO_Add) {
        if (Add->getLHS()->getType()->isPointerType()) {
          Pointer = Add->getLHS();
          Offset = Add->getRHS();
        } else if (Add->getRHS()->getType()->isPointerType()) {
          Pointer = Add->getRHS();
          Offset = Add->getLHS();
        }
      }
    } else if (const auto *Address = dyn_cast<UnaryOperator>(Buffer)) {
      if (Address->getOpcode() == UO_AddrOf)
        if (const auto *Subscript = dyn_cast<ArraySubscriptExpr>(
                Address->getSubExpr()->IgnoreParenImpCasts())) {
          Pointer = Subscript->getBase()->IgnoreParenImpCasts();
          Offset = Subscript->getIdx();
        }
    }
    if (Pointer) {
      QualType Pointee;
      if (Pointer->getType()->isPointerType())
        Pointee = Pointer->getType()->getPointeeType();
      else if (const ArrayType *Array =
                   C.getASTContext().getAsArrayType(Pointer->getType()))
        Pointee = Array->getElementType();
      if (!Pointee.isNull() && !Pointee->isVoidType() &&
          !Pointee->isIncompleteType()) {
        SVal BaseExtent =
            getDynamicExtentWithOffset(State, pointerValue(Pointer, C));
        if (!hasUsableExtent(State, BaseExtent, C.getSValBuilder()))
          if (std::optional<uint64_t> Bytes = StaticExtent(Pointer))
            BaseExtent = C.getSValBuilder().makeIntVal(
                *Bytes, C.getASTContext().getSizeType());
        SVal OffsetValue = expressionValue(Offset, C);
        uint64_t ElementBytes =
            C.getASTContext().getTypeSizeInChars(Pointee).getQuantity();
        if (ElementBytes == 1 &&
            memorySinkCoveredByCallbackAccess(
                Offset, Call.getArgExpr(Sink.LengthArgument), BaseExtent, C))
          return;
        SVal Scale = C.getSValBuilder().makeIntVal(
            ElementBytes, C.getASTContext().getSizeType());
        SVal ByteOffset = C.getSValBuilder().evalBinOp(
            State, BO_Mul, OffsetValue, Scale, C.getASTContext().getSizeType());
        SVal Total;
        const Expr *LengthExpr =
            Call.getArgExpr(Sink.LengthArgument)->IgnoreParenImpCasts();
        const auto *Remaining = dyn_cast<BinaryOperator>(LengthExpr);
        if (ElementBytes == 1 && Remaining &&
            Remaining->getOpcode() == BO_Sub &&
            sameSimpleExpression(Remaining->getRHS(), Offset)) {
          std::optional<llvm::APSInt> StartingExtent =
              Remaining->getLHS()->getIntegerConstantExpr(C.getASTContext());
          const llvm::APSInt *KnownBaseExtent =
              C.getSValBuilder().getKnownValue(State, BaseExtent);
          std::optional<IntegerRange> OffsetRange = integerRange(Offset, C);
          if (StartingExtent && KnownBaseExtent && OffsetRange &&
              !StartingExtent->isNegative() && !KnownBaseExtent->isNegative() &&
              StartingExtent->getBitWidth() <= 64 &&
              KnownBaseExtent->getBitWidth() <= 64 &&
              StartingExtent->getZExtValue() ==
                  KnownBaseExtent->getZExtValue() &&
              OffsetRange->Maximum <= KnownBaseExtent->getZExtValue())
            Total = BaseExtent;
        }
        if (Total.isUnknownOrUndef())
          Total =
              C.getSValBuilder().evalBinOp(State, BO_Add, Length, ByteOffset,
                                           C.getASTContext().getSizeType());
        if (!Total.isUnknown() &&
            hasUsableExtent(State, BaseExtent, C.getSValBuilder())) {
          Required = Total;
          BoundRequired = Total;
          Extent = BaseExtent;
          HasOffset = true;
          SinkDescription = Sink.Description == "packet length"
                                ? "packet offset plus length"
                                : "memory-operation offset plus length";
        }
      }
    }
    if (!hasUsableExtent(State, Extent, C.getSValBuilder()))
      return;
    if (!HasOffset)
      if (const llvm::APSInt *KnownExtent =
              C.getSValBuilder().getKnownValue(State, Extent))
        if (!KnownExtent->isNegative() && KnownExtent->getBitWidth() <= 64) {
          QualType UnpromotedType = Call.getArgExpr(Sink.LengthArgument)
                                        ->IgnoreParenImpCasts()
                                        ->getType();
          if (UnpromotedType->isUnsignedIntegerType()) {
            llvm::APSInt Maximum =
                C.getSValBuilder().getBasicValueFactory().getMaxValue(
                    UnpromotedType);
            unsigned Width =
                std::max(Maximum.getBitWidth(), KnownExtent->getBitWidth());
            if (Maximum.zextOrTrunc(Width).ule(KnownExtent->zextOrTrunc(Width)))
              return;
          }
          if (std::optional<IntegerRange> Range =
                  integerRange(Call.getArgExpr(Sink.LengthArgument), C))
            if (Range->Maximum <= KnownExtent->getZExtValue())
              return;
        }
    std::optional<BoundStates> Bounds =
        compare(State, BoundRequired, BO_LE, Extent, C.getSValBuilder());
    if (!Bounds || !Bounds->Unsafe)
      return;
    report(C, Bounds->Safe, Bounds->Unsafe, Required,
           Call.getArgExpr(Sink.LengthArgument), SinkDescription, Extent, false,
           SourceDetail);
  }

public:
  void checkASTDecl(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                    BugReporter &BR) const {
    class OperationTableVisitor : public DynamicRecursiveASTVisitor {
      const QEMUGuestMemorySafetyChecker &Checker;
      ASTContext &Context;
      llvm::DenseSet<const InitListExpr *> Seen;
      llvm::DenseSet<const InitListExpr *> MemoryRegionInitializers;
      llvm::DenseSet<const InitListExpr *> NamedTableInitializers;
      llvm::DenseSet<const VarDecl *> Tables;
      llvm::DenseMap<const VarDecl *,
                     llvm::SmallVector<const FunctionDecl *, 4>>
          TableCallbacks;
      llvm::DenseMap<const VarDecl *, unsigned> ReferenceCounts;
      llvm::DenseMap<const VarDecl *, unsigned> RegistrationCounts;
      llvm::DenseMap<const VarDecl *, llvm::SmallVector<uint64_t, 2>>
          RegionSizes;

      static bool isMemoryRegionOps(const InitListExpr *ILE) {
        ILE = semanticInitList(ILE);
        if (!ILE)
          return false;
        const RecordDecl *RD = ILE->getType()->getAsRecordDecl();
        return RD && RD->getName() == "MemoryRegionOps";
      }

    public:
      explicit OperationTableVisitor(
          const QEMUGuestMemorySafetyChecker &Checker, ASTContext &Context)
          : Checker(Checker), Context(Context) {}

      bool VisitVarDecl(VarDecl *VD) override {
        const InitListExpr *ILE = semanticInitList(VD->getInit());
        if (!isMemoryRegionOps(ILE))
          return true;
        const VarDecl *Canonical = VD->getCanonicalDecl();
        Tables.insert(Canonical);
        NamedTableInitializers.insert(ILE);
        Checker.collectMemoryRegionCallbacks(ILE, TableCallbacks[Canonical]);
        return true;
      }

      bool VisitInitListExpr(InitListExpr *ILE) override {
        const InitListExpr *Semantic = semanticInitList(ILE);
        if (Semantic && Seen.insert(Semantic).second) {
          Checker.discoverOperationTable(Semantic);
          Checker.discoverVMStateField(Semantic);
          Checker.discoverVMStateValidation(Semantic, Context);
          Checker.discoverVMStatePostLoadBounds(Semantic, Context);
          if (isMemoryRegionOps(Semantic))
            MemoryRegionInitializers.insert(Semantic);
        }
        return true;
      }

      bool VisitBinaryOperator(BinaryOperator *BO) override {
        Checker.discoverCallbackAssignment(BO);
        Checker.discoverDynamicArrayAllocation(BO);
        return true;
      }

      bool VisitFunctionDecl(FunctionDecl *FD) override {
        Checker.discoverShiftedBoundPredicate(FD, Context);
        return true;
      }

      bool VisitDeclRefExpr(DeclRefExpr *DRE) override {
        const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
        if (!VD)
          return true;
        const VarDecl *Canonical = VD->getCanonicalDecl();
        if (Tables.contains(Canonical))
          ++ReferenceCounts[Canonical];
        return true;
      }

      bool VisitCallExpr(CallExpr *Call) override {
        const FunctionDecl *Callee = Call->getDirectCallee();
        if (!Callee || !Callee->getIdentifier() ||
            Callee->getName() != "memory_region_init_io" ||
            Call->getNumArgs() < 6)
          return true;
        const VarDecl *Table = referencedVariable(Call->getArg(2));
        if (!Table)
          return true;
        ++RegistrationCounts[Table];

        Expr::EvalResult Result;
        if (!Call->getArg(5)->EvaluateAsInt(Result, Context,
                                            Expr::SE_NoSideEffects))
          return true;
        llvm::APSInt Size = Result.Val.getInt();
        if (Size.isNegative() || Size.getActiveBits() > 64)
          return true;
        RegionSizes[Table].push_back(Size.getZExtValue());
        return true;
      }

      void applyAddressLimits() {
        struct Aggregate {
          bool Seen = false;
          bool Complete = true;
          uint64_t Limit = 0;
        };
        llvm::DenseMap<const FunctionDecl *, Aggregate> Bounds;

        for (const auto &Entry : TableCallbacks) {
          const VarDecl *Table = Entry.first;
          unsigned References = ReferenceCounts.lookup(Table);
          unsigned Registrations = RegistrationCounts.lookup(Table);
          auto Sizes = RegionSizes.find(Table);
          bool Complete = Table->getFormalLinkage() == Linkage::Internal &&
                          References > 0 && References == Registrations &&
                          Sizes != RegionSizes.end() &&
                          Sizes->second.size() == Registrations;
          uint64_t Limit = 0;
          if (Complete)
            for (uint64_t Size : Sizes->second)
              Limit = std::max(Limit, Size);

          for (const FunctionDecl *FD : Entry.second) {
            Aggregate &Bound = Bounds[FD];
            Bound.Seen = true;
            Bound.Complete &= Complete &&
                              FD->getFormalLinkage() == Linkage::Internal &&
                              Limit != 0;
            Bound.Limit = std::max(Bound.Limit, Limit);
          }
        }

        for (const InitListExpr *ILE : MemoryRegionInitializers) {
          if (NamedTableInitializers.contains(ILE))
            continue;
          llvm::SmallVector<const FunctionDecl *, 4> Functions;
          Checker.collectMemoryRegionCallbacks(ILE, Functions);
          for (const FunctionDecl *FD : Functions) {
            Aggregate &Bound = Bounds[FD];
            Bound.Seen = true;
            Bound.Complete = false;
          }
        }

        for (const auto &Entry : Bounds)
          if (Entry.second.Seen && Entry.second.Complete)
            Checker.setAddressLimit(Entry.first, Entry.second.Limit);
      }
    } Visitor(*this, Mgr.getASTContext());
    Visitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));
    Visitor.applyAddressLimits();

    class PersistentFieldVisitor : public DynamicRecursiveASTVisitor {
      const QEMUGuestMemorySafetyChecker &Checker;
      const FunctionDecl *CurrentFunction = nullptr;

    public:
      explicit PersistentFieldVisitor(
          const QEMUGuestMemorySafetyChecker &Checker)
          : Checker(Checker) {}

      bool TraverseFunctionDecl(FunctionDecl *FD) override {
        const FunctionDecl *Previous = CurrentFunction;
        CurrentFunction = FD ? FD->getCanonicalDecl() : nullptr;
        bool Result = DynamicRecursiveASTVisitor::TraverseFunctionDecl(FD);
        CurrentFunction = Previous;
        return Result;
      }

      bool VisitBinaryOperator(BinaryOperator *BO) override {
        Checker.discoverPersistentGuestAssignment(BO, CurrentFunction);
        return true;
      }

      bool VisitCallExpr(CallExpr *Call) override {
        Checker.discoverPersistentGuestCopy(Call, CurrentFunction);
        return true;
      }
    } PersistentVisitor(*this);
    PersistentVisitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));
    computePersistentGuestFieldMaximums(TU, Mgr.getASTContext());
  }

  void checkBeginFunction(CheckerContext &C) const {
    if (!C.inTopFrame())
      return;
    const auto *FD = dyn_cast<FunctionDecl>(C.getStackFrame()->getDecl());
    if (!FD)
      return;
    auto Found = Callbacks.find(FD->getCanonicalDecl());
    if (Found == Callbacks.end())
      return;

    ProgramStateRef State = C.getState();
    if (Found->second.DataParameter && Found->second.DataMaximum &&
        *Found->second.DataParameter < FD->getNumParams()) {
      const ParmVarDecl *DataParameter =
          FD->getParamDecl(*Found->second.DataParameter);
      const MemRegion *DataRegion =
          State->getRegion(DataParameter, C.getStackFrame());
      SVal Data = State->getSVal(DataRegion);
      SVal Maximum = C.getSValBuilder().makeIntVal(*Found->second.DataMaximum,
                                                   DataParameter->getType());
      std::optional<BoundStates> WithinMaximum =
          compare(State, Data, BO_LE, Maximum, C.getSValBuilder());
      if (WithinMaximum) {
        if (!WithinMaximum->Safe)
          return;
        State = WithinMaximum->Safe;
      }
    }
    if (Found->second.AccessSizeLimit && Found->second.AccessSizeParameter &&
        *Found->second.AccessSizeParameter < FD->getNumParams()) {
      unsigned SizeIndex = *Found->second.AccessSizeParameter;
      const ParmVarDecl *SizeParameter = FD->getParamDecl(SizeIndex);
      const MemRegion *SizeRegion =
          State->getRegion(SizeParameter, C.getStackFrame());
      SVal Size = State->getSVal(SizeRegion);
      SVal Zero = C.getSValBuilder().makeZeroVal(SizeParameter->getType());
      SVal Limit = C.getSValBuilder().makeIntVal(*Found->second.AccessSizeLimit,
                                                 SizeParameter->getType());
      std::optional<BoundStates> Positive =
          compare(State, Size, BO_GT, Zero, C.getSValBuilder());
      if (Positive) {
        if (!Positive->Safe)
          return;
        State = Positive->Safe;
      }
      std::optional<BoundStates> WithinLimit =
          compare(State, Size, BO_LE, Limit, C.getSValBuilder());
      if (WithinLimit) {
        if (!WithinLimit->Safe)
          return;
        State = WithinLimit->Safe;
      }
    }
    if (Found->second.AddressLimit && Found->second.AddressParameter &&
        *Found->second.AddressParameter < FD->getNumParams()) {
      unsigned AddressIndex = *Found->second.AddressParameter;
      const ParmVarDecl *AddressParameter = FD->getParamDecl(AddressIndex);
      const MemRegion *AddressRegion =
          State->getRegion(AddressParameter, C.getStackFrame());
      SVal Address = State->getSVal(AddressRegion);
      SVal AddressLimit = C.getSValBuilder().makeIntVal(
          *Found->second.AddressLimit, AddressParameter->getType());

      if (Found->second.AccessSizeParameter &&
          *Found->second.AccessSizeParameter < FD->getNumParams()) {
        unsigned SizeIndex = *Found->second.AccessSizeParameter;
        const ParmVarDecl *SizeParameter = FD->getParamDecl(SizeIndex);
        const MemRegion *SizeRegion =
            State->getRegion(SizeParameter, C.getStackFrame());
        SVal Size = State->getSVal(SizeRegion);
        SVal Zero = C.getSValBuilder().makeZeroVal(SizeParameter->getType());
        SVal SizeLimit = C.getSValBuilder().makeIntVal(
            *Found->second.AddressLimit, SizeParameter->getType());
        std::optional<BoundStates> Positive =
            compare(State, Size, BO_GT, Zero, C.getSValBuilder());
        if (Positive) {
          if (!Positive->Safe)
            return;
          State = Positive->Safe;
        }
        std::optional<BoundStates> Fits =
            compare(State, Size, BO_LE, SizeLimit, C.getSValBuilder());
        if (Fits) {
          if (!Fits->Safe)
            return;
          State = Fits->Safe;
        }

        SVal ConvertedSize = C.getSValBuilder().evalCast(
            Size, AddressParameter->getType(), SizeParameter->getType());
        SVal LastStart = C.getSValBuilder().evalBinOp(
            State, BO_Sub, AddressLimit, ConvertedSize,
            AddressParameter->getType());
        std::optional<BoundStates> InRegion =
            compare(State, Address, BO_LE, LastStart, C.getSValBuilder());
        if (InRegion) {
          if (!InRegion->Safe)
            return;
          State = InRegion->Safe;
        }
        std::optional<BoundStates> StartsInRegion =
            compare(State, Address, BO_LT, AddressLimit, C.getSValBuilder());
        if (StartsInRegion) {
          if (!StartsInRegion->Safe)
            return;
          State = StartsInRegion->Safe;
        }
      } else {
        std::optional<BoundStates> InRegion =
            compare(State, Address, BO_LT, AddressLimit, C.getSValBuilder());
        if (InRegion) {
          if (!InRegion->Safe)
            return;
          State = InRegion->Safe;
        }
      }
    }

    struct SourceValue {
      SVal Value;
      std::string Name;
    };
    std::vector<SourceValue> Sources;
    for (unsigned Index = 0; Index < FD->getNumParams() && Index < 64;
         ++Index) {
      uint64_t Bit = uint64_t(1) << Index;
      if (!(Found->second.ParameterMask & Bit) &&
          !(Found->second.PointeeMask & Bit))
        continue;
      const ParmVarDecl *Parameter = FD->getParamDecl(Index);
      const MemRegion *Region = State->getRegion(Parameter, C.getStackFrame());
      SVal Value = State->getSVal(Region);
      if (Found->second.ParameterMask & Bit) {
        State = addInputTaint(State, Value, Found->second.Source);
        Sources.push_back({Value, Parameter->getNameAsString()});
      }
      if (Found->second.PointeeMask & Bit)
        if (std::optional<SVal> Pointee = pointeeValue(State, Value)) {
          State = addInputTaint(State, *Pointee, Found->second.Source);
          Sources.push_back({*Pointee, Parameter->getNameAsString()});
        }
    }
    if (State == C.getState())
      return;

    std::string Class = inputClassName(Found->second.Source).str();
    const NoteTag *Tag =
        C.getNoteTag([Sources = std::move(Sources), Class = std::move(Class)](
                         PathSensitiveBugReport &Report) -> std::string {
          for (const SourceValue &Source : Sources) {
            if (!Report.isInteresting(Source.Value))
              continue;
            return Class + " callback parameter '" + Source.Name +
                   "' is guest-controlled";
          }
          return "";
        });
    C.addTransition(State, Tag);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    if (std::optional<unsigned> SizeIndex = allocationSizeArgument(Call)) {
      SVal Size = allocationSizeValue(Call, *SizeIndex, C);
      if (!Size.isUnknownOrUndef()) {
        State =
            State->set<QEMUPendingAllocationSizes>(Call.getOriginExpr(), Size);
        C.addTransition(State);
      }
    }
    checkAllocationOverflow(Call, C);
    if (std::optional<MemorySink> Sink = destinationMemorySink(Call))
      checkMemorySink(Call, *Sink, C);
    if (std::optional<MemorySink> Sink = sourceMemorySink(Call))
      checkMemorySink(Call, *Sink, C);
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    if (std::optional<unsigned> SizeIndex = allocationSizeArgument(Call)) {
      ProgramStateRef State = C.getState();
      const SVal *SavedSize =
          State->get<QEMUPendingAllocationSizes>(Call.getOriginExpr());
      SVal Size =
          SavedSize ? *SavedSize : allocationSizeValue(Call, *SizeIndex, C);
      State = State->remove<QEMUPendingAllocationSizes>(Call.getOriginExpr());
      if (const MemRegion *Region = Call.getReturnValue().getAsRegion())
        if (auto DefinedSize = Size.getAs<DefinedOrUnknownSVal>()) {
          State = setDynamicExtent(State, Region, *DefinedSize);
        }
      C.addTransition(State);
      return;
    }
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier())
      return;
    StringRef Name = FD->getName();
    if (modelRangeCoversByte(Call, C))
      return;
    if (modelShiftedBoundPredicate(Call, C))
      return;
    std::optional<SVal> ConvertedInput;
    if (std::optional<unsigned> Argument =
            endianScalarArgument(Name, Call.getNumArgs())) {
      ConvertedInput = Call.getArgSVal(*Argument);
    } else if (std::optional<unsigned> Argument =
                   endianLoadPointerArgument(Name, Call.getNumArgs())) {
      ConvertedInput = pointeeValue(C.getState(), Call.getArgSVal(*Argument));
    }
    if (ConvertedInput) {
      std::optional<InputClass> Source =
          inputClassForValue(C.getState(), *ConvertedInput);
      if (Source) {
        ProgramStateRef State =
            addInputTaint(C.getState(), Call.getReturnValue(), *Source);
        const NoteTag *Tag = propagationNote(
            C, State, Call.getReturnValue(), *ConvertedInput, *Source,
            "value remains guest-controlled after byte-order conversion");
        C.addTransition(State, Tag);
        return;
      }
    }
    if ((Name == "g_free" || Name == "free") && Call.getNumArgs() >= 1) {
      if (const MemRegion *Region = pointerBaseRegion(Call.getArgSVal(0))) {
        ProgramStateRef State = C.getState()
                                    ->remove<QEMUVirtqueueElements>(Region)
                                    ->remove<QEMUVirtqueueIovecs>(Region);
        if (State != C.getState())
          C.addTransition(State);
      }
      return;
    }
    if ((Name == "virtqueue_push" || Name == "virtqueue_detach_element" ||
         Name == "virtqueue_unpop") &&
        Call.getNumArgs() >= 2) {
      if (const MemRegion *Element = pointerBaseRegion(Call.getArgSVal(1))) {
        ProgramStateRef State =
            C.getState()->remove<QEMUVirtqueueElements>(Element);
        if (State != C.getState())
          C.addTransition(State);
      }
      return;
    }
    if (Name == "virtqueue_pop" && Call.getNumArgs() >= 2) {
      if (const MemRegion *Element = pointerBaseRegion(Call.getReturnValue())) {
        ProgramStateRef State =
            C.getState()->add<QEMUVirtqueueElements>(Element);
        C.addTransition(State);
      }
      return;
    }
    if ((Name == "g_memdup2" || Name == "g_memdup") && Call.getNumArgs() >= 2 &&
        isVirtqueueIovec(Call, 0, C.getState())) {
      if (const MemRegion *Iovec = pointerBaseRegion(Call.getReturnValue())) {
        ProgramStateRef State = C.getState()->add<QEMUVirtqueueIovecs>(Iovec);
        C.addTransition(State);
      }
      return;
    }
    if (Name == "iov_copy" && Call.getNumArgs() >= 6 &&
        isVirtqueueIovec(Call, 2, C.getState())) {
      if (const MemRegion *Iovec = pointerBaseRegion(Call.getArgSVal(0))) {
        ProgramStateRef State = C.getState()->add<QEMUVirtqueueIovecs>(Iovec);
        C.addTransition(State);
      }
      return;
    }
    if ((Name == "iov_to_buf" || Name == "iov_to_buf_full") &&
        Call.getNumArgs() >= 5 && isVirtqueueIovec(Call, 0, C.getState())) {
      ProgramStateRef State = C.getState();
      std::optional<BoundStates> Result =
          compare(State, Call.getReturnValue(), BO_EQ, Call.getArgSVal(4),
                  C.getSValBuilder());
      if (!Result)
        return;
      if (Result->Unsafe)
        C.addTransition(Result->Unsafe);
      if (!Result->Safe)
        return;
      std::optional<SVal> Pointee =
          pointeeValue(Result->Safe, Call.getArgSVal(3));
      if (!Pointee)
        return;
      ProgramStateRef Tainted =
          addInputTaint(Result->Safe, *Pointee, InputClass::Virtqueue);
      const NoteTag *Tag =
          sourceNote(C, Tainted, *Pointee, InputClass::Virtqueue,
                     "populated guest-controlled data here");
      C.addTransition(Tainted, Tag);
      return;
    }
    if (isMigrationScalarSource(Name)) {
      ProgramStateRef State = addInputTaint(C.getState(), Call.getReturnValue(),
                                            InputClass::Migration);
      if (std::optional<uint64_t> Maximum = migrationScalarMaximum(Name)) {
        SVal Zero = C.getSValBuilder().makeZeroVal(FD->getReturnType());
        SVal Upper =
            C.getSValBuilder().makeIntVal(*Maximum, FD->getReturnType());
        std::optional<BoundStates> NonNegative = compare(
            State, Call.getReturnValue(), BO_GE, Zero, C.getSValBuilder());
        if (!NonNegative || !NonNegative->Safe)
          return;
        std::optional<BoundStates> AtMostMaximum =
            compare(NonNegative->Safe, Call.getReturnValue(), BO_LE, Upper,
                    C.getSValBuilder());
        if (!AtMostMaximum || !AtMostMaximum->Safe)
          return;
        State = AtMostMaximum->Safe;
      }
      const NoteTag *Tag =
          sourceNote(C, State, Call.getReturnValue(), InputClass::Migration,
                     "scalar is guest-controlled");
      C.addTransition(State, Tag);
      return;
    }

    std::optional<BufferSource> Source = bufferSource(Call);
    if (!Source)
      return;
    ProgramStateRef Success = C.getState();
    ProgramStateRef Failure;
    if (Source->Success != BufferSource::Always) {
      SVal Expected;
      if (Source->Success == BufferSource::ReturnZero)
        Expected = C.getSValBuilder().makeZeroVal(FD->getReturnType());
      else
        Expected = Call.getArgSVal(Source->CompareArgument);
      std::optional<BoundStates> Result = compare(
          Success, Call.getReturnValue(), BO_EQ, Expected, C.getSValBuilder());
      if (!Result)
        return;
      Success = Result->Safe;
      Failure = Result->Unsafe;
    }
    if (Failure)
      C.addTransition(Failure);
    if (!Success)
      return;

    std::optional<SVal> Pointee =
        pointeeValue(Success, Call.getArgSVal(Source->BufferArgument));
    if (!Pointee)
      return;
    ProgramStateRef Tainted = addInputTaint(Success, *Pointee, Source->Source);
    const NoteTag *Tag = sourceNote(C, Tainted, *Pointee, Source->Source,
                                    "populated guest-controlled data here");
    C.addTransition(Tainted, Tag);
  }

  void checkPostStmt(const ImplicitCastExpr *Cast, CheckerContext &C) const {
    if (Cast->getCastKind() != CK_LValueToRValue)
      return;
    std::optional<PersistentFieldInfo> Persistent =
        persistentGuestField(Cast->getSubExpr());
    if (!Persistent)
      return;

    // A VMState entry makes the field of the migrated device object
    // untrusted, not every automatic object that happens to have the same
    // record type.  This distinction matters for temporary request and event
    // records whose fields are populated from already-validated state.
    if (const MemRegion *Region = C.getSVal(Cast->getSubExpr()).getAsRegion())
      if (const auto *Base = dyn_cast<VarRegion>(Region->getBaseRegion()))
        if (Base->getDecl()->hasLocalStorage())
          return;

    SVal Value = C.getSVal(Cast);
    ProgramStateRef State = C.getState();
    if (Value.isUnknownOrUndef() || taint::isTainted(State, Value))
      return;
    State = addInputTaint(State, Value, Persistent->Source);
    for (SymbolRef Symbol : taint::getTaintedSymbols(State, Value)) {
      const FieldDecl *const *Previous =
          State->get<QEMUPersistentFieldSources>(Symbol);
      const FieldDecl *Field = Persistent->Field;
      if (Previous && *Previous != Field)
        Field = nullptr;
      State = State->set<QEMUPersistentFieldSources>(Symbol, Field);
    }
    std::string Detail = "stored field '" +
                         Persistent->Field->getNameAsString() +
                         "' is guest-controlled";
    const NoteTag *Tag =
        sourceNote(C, State, Value, Persistent->Source, Detail);
    C.addTransition(State, Tag);
  }

  void checkBind(SVal Location, SVal Value, const Stmt *S, bool AtDeclInit,
                 CheckerContext &C) const {
    const auto *Region = dyn_cast_or_null<VarRegion>(Location.getAsRegion());
    if (!Region)
      return;
    ProgramStateRef State = C.getState();
    const Expr *SourceExpression =
        bindingSourceExpression(S, Region->getDecl());
    if (const MemRegion *Iovec = pointerBaseRegion(Value))
      if (isTrackedVirtqueueIovec(State, Value) ||
          isVirtqueueOutIovecValue(State, Value))
        State = State->add<QEMUVirtqueueIovecs>(Iovec);
    if (!Region->getValueType()->isIntegerType()) {
      if (State != C.getState())
        C.addTransition(State);
      return;
    }
    std::optional<PersistentFieldInfo> Source =
        persistentGuestFieldFromAliases(SourceExpression, State, C, Value);
    if (!Value.isUnknownOrUndef() && taint::isTainted(State, Value)) {
      State = State->set<QEMUSavedTaintedScalars>(Region, Value);
    } else {
      State = State->remove<QEMUSavedTaintedScalars>(Region);
    }
    if (Source)
      State = State->set<QEMUPersistentLocalSources>(Region, Source->Field);
    else
      State = State->remove<QEMUPersistentLocalSources>(Region);
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    auto Saved = State->get<QEMUSavedTaintedScalars>();
    for (const auto &Entry : Saved)
      if (!SymReaper.isLiveRegion(Entry.first))
        State = State->remove<QEMUSavedTaintedScalars>(Entry.first);
    auto Sources = State->get<QEMUPersistentFieldSources>();
    for (const auto &Entry : Sources)
      if (SymReaper.isDead(Entry.first))
        State = State->remove<QEMUPersistentFieldSources>(Entry.first);
    for (const MemRegion *Region : State->get<QEMUVirtqueueElements>())
      if (!SymReaper.isLiveRegion(Region))
        State = State->remove<QEMUVirtqueueElements>(Region);
    for (const MemRegion *Region : State->get<QEMUVirtqueueIovecs>())
      if (!SymReaper.isLiveRegion(Region))
        State = State->remove<QEMUVirtqueueIovecs>(Region);
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkLiveSymbols(ProgramStateRef State, SymbolReaper &SymReaper) const {
    for (const MemRegion *Region : State->get<QEMUVirtqueueElements>())
      SymReaper.markLive(Region);
    for (const MemRegion *Region : State->get<QEMUVirtqueueIovecs>())
      SymReaper.markLive(Region);
  }

  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    const StackFrameContext *Frame = C.getStackFrame();
    auto LocalSources = State->get<QEMUPersistentLocalSources>();
    for (const auto &Entry : LocalSources)
      if (Entry.first->getStackFrame() == Frame)
        State = State->remove<QEMUPersistentLocalSources>(Entry.first);
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    // Preserve the range of byte-sized and other narrow source values.  The
    // usual integer promotion can otherwise turn a uint8_t index into an
    // unconstrained int and invent an impossible index >= 256 path.
    SVal Index = expressionValue(ASE->getIdx(), C);
    const Expr *IndexExpression = ASE->getIdx();
    std::optional<PersistentFieldInfo> Persistent =
        persistentGuestField(IndexExpression);
    if (!taint::isTainted(State, Index)) {
      if (!Persistent)
        return;
      State = addInputTaint(State, Index, Persistent->Source);
    }
    if (!Persistent)
      Persistent =
          persistentGuestFieldFromAliases(IndexExpression, State, C, Index);
    std::string SourceDetail;
    if (Persistent)
      SourceDetail = persistentSourceDescription(*Persistent);
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    const auto *Member = dyn_cast<MemberExpr>(Base);
    const auto *PointerField =
        Member ? dyn_cast<FieldDecl>(Member->getMemberDecl()) : nullptr;
    auto DynamicCount = PointerField ? DynamicArrayCounts.find(PointerField)
                                     : DynamicArrayCounts.end();
    SVal Count = getDynamicElementCountWithOffset(
        State, C.getSVal(ASE->getBase()), ASE->getType());
    if (!hasUsableExtent(State, Count, C.getSValBuilder())) {
      const ConstantArrayType *Array =
          C.getASTContext().getAsConstantArrayType(Base->getType());
      if (Array && Array->getSize().getActiveBits() <= 64) {
        Count =
            C.getSValBuilder().makeArrayIndex(Array->getSize().getZExtValue());
      } else {
        if (!Member || !Member->isArrow() ||
            DynamicCount == DynamicArrayCounts.end())
          return;
        SVal CountObject = expressionValue(Member->getBase(), C);
        for (const FieldDecl *Field : DynamicCount->second) {
          SVal CountLocation = State->getLValue(Field, CountObject);
          auto Location = CountLocation.getAs<Loc>();
          if (!Location)
            return;
          CountObject = CountLocation;
        }
        auto Location = CountObject.getAs<Loc>();
        if (!Location)
          return;
        Count = State->getSVal(*Location);
        if (Count.isUnknownOrUndef())
          return;
      }
    }
    const Expr *UnpromotedIndex = ASE->getIdx()->IgnoreParenImpCasts();
    QualType IndexType = UnpromotedIndex->getType();
    const llvm::APSInt *KnownCount =
        C.getSValBuilder().getKnownValue(State, Count);
    const auto *CurrentFunction =
        dyn_cast<FunctionDecl>(C.getCurrentAnalysisDeclContext()->getDecl());
    bool InPostLoad =
        CurrentFunction && MigrationPostLoadFunctions.contains(
                               CurrentFunction->getCanonicalDecl());
    if (Persistent && Persistent->Source == InputClass::Migration &&
        !InPostLoad &&
        !MigrationPostLoadUnvalidatedFields.contains(Persistent->Field) &&
        KnownCount && !KnownCount->isNegative() &&
        KnownCount->getBitWidth() <= 64) {
      auto Validated = MigrationPostLoadFieldMaximums.find(Persistent->Field);
      if (Validated != MigrationPostLoadFieldMaximums.end())
        if (std::optional<uint64_t> Maximum = indexMaximumFromField(
                ASE->getIdx(), Persistent->Field, Validated->second)) {
          uint64_t ElementCount = KnownCount->getZExtValue();
          if (*Maximum < ElementCount)
            return;
          if (*Maximum == ElementCount) {
            std::optional<BoundStates> NotAtLimit =
                compare(State, Index, BO_NE, Count, C.getSValBuilder());
            if (NotAtLimit && NotAtLimit->Safe && !NotAtLimit->Unsafe)
              return;
          }
        }
    }
    const MemberExpr *IndexMember = directReferencedMember(ASE->getIdx());
    if (Persistent && Member && IndexMember &&
        sameSimpleExpression(Member->getBase(), IndexMember->getBase()) &&
        DynamicCount != DynamicArrayCounts.end() &&
        directReferencedField(ASE->getIdx()) == Persistent->Field) {
      auto Validated = MigrationValidatedFieldBounds.find(Persistent->Field);
      if (Validated != MigrationValidatedFieldBounds.end() &&
          Validated->second.LimitField == DynamicCount->second.back()) {
        if (!Validated->second.Inclusive)
          return;
        std::optional<BoundStates> NotAtLimit =
            compare(State, Index, BO_NE, Count, C.getSValBuilder());
        if (NotAtLimit && NotAtLimit->Safe && !NotAtLimit->Unsafe)
          return;
      }
    }
    if (Persistent && KnownCount && !KnownCount->isNegative() &&
        KnownCount->getBitWidth() <= 64 &&
        directReferencedField(ASE->getIdx()) == Persistent->Field) {
      auto Maximum = PersistentGuestFieldMaximums.find(Persistent->Field);
      if (Maximum != PersistentGuestFieldMaximums.end() &&
          Maximum->second < KnownCount->getZExtValue())
        return;
    }
    if (DynamicCount != DynamicArrayCounts.end() &&
        scaledAddressIndexCoveredByGuard(ASE->getIdx(),
                                         DynamicCount->second.back(), Count, C))
      return;
    if (addressIndexCoveredByGuard(ASE->getIdx(), Count, C))
      return;
    if (KnownCount &&
        indexCoveredByCallbackAccess(ASE->getIdx(), *KnownCount, C))
      return;
    if (KnownCount && !KnownCount->isNegative() &&
        IndexType->isUnsignedIntegerType()) {
      llvm::APSInt Maximum =
          C.getSValBuilder().getBasicValueFactory().getMaxValue(IndexType);
      unsigned Width = Maximum.getBitWidth() > KnownCount->getBitWidth()
                           ? Maximum.getBitWidth()
                           : KnownCount->getBitWidth();
      if (Maximum.zextOrTrunc(Width).ult(KnownCount->zextOrTrunc(Width)))
        return;
    }
    if (KnownCount && !KnownCount->isNegative() &&
        KnownCount->getBitWidth() <= 64) {
      if (std::optional<IntegerRange> Range = integerRange(ASE->getIdx(), C)) {
        uint64_t ElementCount = KnownCount->getZExtValue();
        if (Range->Maximum < ElementCount)
          return;
        if (Range->Maximum == ElementCount) {
          std::optional<BoundStates> NotEqual =
              compare(State, Index, BO_NE, Count, C.getSValBuilder());
          if (NotEqual && NotEqual->Safe && !NotEqual->Unsafe)
            return;
        }
      }
    }
    if (DynamicCount != DynamicArrayCounts.end()) {
      std::optional<BoundStates> Outside = compareSourceCondition(
          State, Index, BO_GE, Count, C.getSValBuilder());
      if (!Outside || !Outside->Safe)
        return;
      report(C, Outside->Unsafe, Outside->Safe, Index, ASE->getIdx(),
             "array index", Count, true, SourceDetail);
      return;
    }

    std::optional<BoundStates> Inside =
        compare(State, Index, BO_LT, Count, C.getSValBuilder());
    if (!Inside || !Inside->Unsafe)
      return;
    report(C, Inside->Safe, Inside->Unsafe, Index, ASE->getIdx(), "array index",
           Count, true, SourceDetail);
  }
};

} // namespace

void ento::registerQEMUGuestMemorySafetyChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<QEMUGuestMemorySafetyChecker>();
}

bool ento::shouldRegisterQEMUGuestMemorySafetyChecker(
    const CheckerManager &Mgr) {
  return true;
}
