//===- QEMUGuestMemorySafetyChecker.cpp -------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This experimental checker discovers QEMU MMIO and PIO callbacks from their
// operation tables, marks guest-controlled callback arguments as tainted, and
// relates tainted array indexes and memory-operation lengths to host object
// extents.  A Level A report has no feasible in-bounds state.  A Level B
// report has both in-bounds and out-of-bounds states and needs manual review.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DynamicRecursiveASTVisitor.h"
#include "clang/AST/Expr.h"
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

namespace {

enum class InputClass { MMIO, PIO, DMA, Migration, Network, DiskImage, Mixed };

struct CallbackInfo {
  uint64_t ParameterMask = 0;
  uint64_t PointeeMask = 0;
  InputClass Source = InputClass::MMIO;
  std::optional<uint64_t> AddressLimit;
  std::optional<unsigned> AddressParameter;
  std::optional<unsigned> AccessSizeParameter;
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
  case InputClass::Mixed:
    return "MMIO/PIO";
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
                     check::PreCall, check::PostCall, check::Bind,
                     check::DeadSymbols, check::PreStmt<ArraySubscriptExpr>> {
  mutable llvm::DenseMap<const FunctionDecl *, CallbackInfo> Callbacks;
  mutable llvm::DenseMap<const FieldDecl *, const FieldDecl *>
      DynamicArrayCounts;
  mutable llvm::DenseSet<const FieldDecl *> AmbiguousDynamicArrays;
  mutable llvm::DenseMap<const FunctionDecl *, ShiftedBoundPredicate>
      ShiftedBoundPredicates;
  mutable std::unique_ptr<BugType> LevelABug;
  mutable std::unique_ptr<BugType> LevelBBug;

  void addCallback(
      const Expr *Initializer, InputClass Source,
      std::initializer_list<unsigned> Parameters,
      std::initializer_list<unsigned> Pointees = {},
      std::optional<unsigned> AddressParameter = std::nullopt,
      std::optional<unsigned> AccessSizeParameter = std::nullopt) const {
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
      addCallback(fieldInitializer(ILE, "read"), InputClass::MMIO, {1, 2}, {},
                  1, 2);
      addCallback(fieldInitializer(ILE, "write"), InputClass::MMIO, {1, 2, 3},
                  {}, 1, 3);
      addCallback(fieldInitializer(ILE, "read_with_attrs"), InputClass::MMIO,
                  {1, 3, 4}, {}, 1, 3);
      addCallback(fieldInitializer(ILE, "write_with_attrs"), InputClass::MMIO,
                  {1, 2, 3, 4}, {}, 1, 3);
      if (const InitListExpr *Valid =
              semanticInitList(fieldInitializer(ILE, "valid")))
        addCallback(fieldInitializer(Valid, "accepts"), InputClass::MMIO,
                    {1, 2, 3, 4}, {}, 1, 2);
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
        if (FD && FD->getType()->isIntegerType())
          IntegerFields.insert(FD);
        return true;
      }
    } Visitor;
    Visitor.TraverseStmt(const_cast<Expr *>(Assignment->getRHS()));
    if (!Visitor.HasAllocation || Visitor.IntegerFields.size() != 1)
      return;

    const FieldDecl *CountField = *Visitor.IntegerFields.begin();
    if (AmbiguousDynamicArrays.contains(PointerField))
      return;
    auto [Found, Inserted] =
        DynamicArrayCounts.try_emplace(PointerField, CountField);
    if (!Inserted && Found->second != CountField) {
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
              SVal ExtentOrCount, bool Elements) const {
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
            << valueRange(Unsafe, ExtentOrCount, C.getSValBuilder()) << ')';

    auto Report = std::make_unique<PathSensitiveBugReport>(bugType(Definite),
                                                           Message.str(), Node);
    if (Where)
      Report->addRange(Where->getSourceRange());
    for (SymbolRef Sym : taint::getTaintedSymbols(Unsafe, TaintedValue))
      Report->markInteresting(Sym);
    C.emitReport(std::move(Report));
  }

  struct MemorySink {
    unsigned DestinationArgument;
    unsigned LengthArgument;
  };

  static std::optional<MemorySink> memorySink(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier())
      return std::nullopt;
    StringRef Name = FD->getName();
    if ((Name == "memcpy" || Name == "memmove" || Name == "memset" ||
         Name == "__builtin_memcpy" || Name == "__builtin_memmove" ||
         Name == "__builtin_memset") &&
        Call.getNumArgs() >= 3)
      return MemorySink{0, 2};
    if (Name == "iov_to_buf" && Call.getNumArgs() >= 5)
      return MemorySink{3, 4};
    if (Name == "qemu_iovec_to_buf" && Call.getNumArgs() >= 4)
      return MemorySink{2, 3};
    if ((Name == "address_space_read" || Name == "address_space_read_full") &&
        Call.getNumArgs() >= 5)
      return MemorySink{3, 4};
    if ((Name == "dma_memory_read" || Name == "pci_dma_read") &&
        Call.getNumArgs() >= 4)
      return MemorySink{2, 3};
    if (Name == "cpu_physical_memory_read" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2};
    if (Name == "physical_memory_read" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2};
    if (Name == "qemu_get_buffer" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2};
    if (Name == "bdrv_pread" && Call.getNumArgs() >= 5)
      return MemorySink{3, 2};
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
      SVal Value = expressionValue(E, C);
      if (std::optional<IntegerRange> Range =
              symbolicIntegerRange(Value, C.getState(), C.getSValBuilder()))
        return constrainRangeToType(*Range, E->getType(), C.getASTContext());
      const llvm::APSInt *Minimum =
          C.getSValBuilder().getMinValue(C.getState(), Value);
      const llvm::APSInt *Maximum =
          C.getSValBuilder().getMaxValue(C.getState(), Value);
      if (!Minimum || !Maximum || Minimum->isNegative() ||
          Minimum->getBitWidth() > 64 || Maximum->getBitWidth() > 64)
        return std::nullopt;
      uint64_t Low = Minimum->getZExtValue();
      uint64_t High = Maximum->getZExtValue();
      QualType Type = E->getType();
      if (Type->isUnsignedIntegerType()) {
        unsigned Width = C.getASTContext().getIntWidth(Type);
        if (Width < 64)
          High = std::min(High, (uint64_t(1) << Width) - 1);
      }
      return IntegerRange{Low, High};
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
          if (isMemoryRegionOps(Semantic))
            MemoryRegionInitializers.insert(Semantic);
        }
        return true;
      }

      bool VisitBinaryOperator(BinaryOperator *BO) override {
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
        State = taint::addTaint(State, Value);
        Sources.push_back({Value, Parameter->getNameAsString()});
      }
      if (Found->second.PointeeMask & Bit)
        if (std::optional<SVal> Pointee = pointeeValue(State, Value)) {
          State = taint::addTaint(State, *Pointee);
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
    std::optional<MemorySink> Sink = memorySink(Call);
    if (!Sink)
      return;
    SVal Length = Call.getArgSVal(Sink->LengthArgument);
    if (!taint::isTainted(State, Length))
      return;
    SVal Required = Length;
    SVal Extent = getDynamicExtentWithOffset(
        State, Call.getArgSVal(Sink->DestinationArgument));
    StringRef SinkDescription = "memory-operation length";

    const Expr *Destination =
        Call.getArgExpr(Sink->DestinationArgument)->IgnoreParenImpCasts();
    if (const auto *Add = dyn_cast<BinaryOperator>(Destination)) {
      if (Add->getOpcode() == BO_Add) {
        const Expr *Pointer = nullptr;
        const Expr *Offset = nullptr;
        if (Add->getLHS()->getType()->isPointerType()) {
          Pointer = Add->getLHS();
          Offset = Add->getRHS();
        } else if (Add->getRHS()->getType()->isPointerType()) {
          Pointer = Add->getRHS();
          Offset = Add->getLHS();
        }
        if (Pointer) {
          QualType Pointee = Pointer->getType()->getPointeeType();
          if (!Pointee->isVoidType() && !Pointee->isIncompleteType()) {
            SVal BaseExtent =
                getDynamicExtentWithOffset(State, pointerValue(Pointer, C));
            SVal OffsetValue = expressionValue(Offset, C);
            uint64_t ElementBytes =
                C.getASTContext().getTypeSizeInChars(Pointee).getQuantity();
            SVal Scale = C.getSValBuilder().makeIntVal(
                ElementBytes, C.getASTContext().getSizeType());
            SVal ByteOffset =
                C.getSValBuilder().evalBinOp(State, BO_Mul, OffsetValue, Scale,
                                             C.getASTContext().getSizeType());
            SVal Total =
                C.getSValBuilder().evalBinOp(State, BO_Add, Length, ByteOffset,
                                             C.getASTContext().getSizeType());
            if (!Total.isUnknown() &&
                hasUsableExtent(State, BaseExtent, C.getSValBuilder())) {
              Required = Total;
              Extent = BaseExtent;
              SinkDescription = "memory-operation offset plus length";
            }
          }
        }
      }
    }
    if (!hasUsableExtent(State, Extent, C.getSValBuilder()))
      return;
    std::optional<BoundStates> Bounds =
        compare(State, Required, BO_LE, Extent, C.getSValBuilder());
    if (!Bounds || !Bounds->Unsafe)
      return;
    report(C, Bounds->Safe, Bounds->Unsafe, Required,
           Call.getArgExpr(Sink->LengthArgument), SinkDescription, Extent,
           false);
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
    if (isMigrationScalarSource(Name)) {
      ProgramStateRef State =
          taint::addTaint(C.getState(), Call.getReturnValue());
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
    ProgramStateRef Tainted = taint::addTaint(Success, *Pointee);
    const NoteTag *Tag = sourceNote(C, Tainted, *Pointee, Source->Source,
                                    "populated guest-controlled data here");
    C.addTransition(Tainted, Tag);
  }

  void checkBind(SVal Location, SVal Value, const Stmt *S, bool AtDeclInit,
                 CheckerContext &C) const {
    const auto *Region = dyn_cast_or_null<VarRegion>(Location.getAsRegion());
    if (!Region || !Region->getValueType()->isIntegerType())
      return;
    ProgramStateRef State = C.getState();
    if (!Value.isUnknownOrUndef() && taint::isTainted(State, Value))
      State = State->set<QEMUSavedTaintedScalars>(Region, Value);
    else
      State = State->remove<QEMUSavedTaintedScalars>(Region);
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    auto Saved = State->get<QEMUSavedTaintedScalars>();
    for (const auto &Entry : Saved)
      if (!SymReaper.isLiveRegion(Entry.first))
        State = State->remove<QEMUSavedTaintedScalars>(Entry.first);
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    // Preserve the range of byte-sized and other narrow source values.  The
    // usual integer promotion can otherwise turn a uint8_t index into an
    // unconstrained int and invent an impossible index >= 256 path.
    SVal Index = expressionValue(ASE->getIdx(), C);
    if (!taint::isTainted(State, Index))
      return;
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
        SVal Object = expressionValue(Member->getBase(), C);
        SVal CountLocation = State->getLValue(DynamicCount->second, Object);
        auto Location = CountLocation.getAs<Loc>();
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
    if (DynamicCount != DynamicArrayCounts.end() &&
        scaledAddressIndexCoveredByGuard(ASE->getIdx(), DynamicCount->second,
                                         Count, C))
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
        KnownCount->getBitWidth() <= 64)
      if (std::optional<IntegerRange> Range = integerRange(ASE->getIdx(), C))
        if (Range->Maximum < KnownCount->getZExtValue())
          return;
    if (DynamicCount != DynamicArrayCounts.end()) {
      std::optional<BoundStates> Outside = compareSourceCondition(
          State, Index, BO_GE, Count, C.getSValBuilder());
      if (!Outside || !Outside->Safe)
        return;
      report(C, Outside->Unsafe, Outside->Safe, Index, ASE->getIdx(),
             "array index", Count, true);
      return;
    }

    std::optional<BoundStates> Inside =
        compare(State, Index, BO_LT, Count, C.getSValBuilder());
    if (!Inside || !Inside->Unsafe)
      return;
    report(C, Inside->Safe, Inside->Unsafe, Index, ASE->getIdx(), "array index",
           Count, true);
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
