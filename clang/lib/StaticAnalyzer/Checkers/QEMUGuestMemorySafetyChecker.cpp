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
// to host object extents. It also models the returned extent, unmap contract,
// and lifetime of QEMU's direct DMA mappings. A Level A report has no feasible
// in-bounds state. A Level B report has both in-bounds and out-of-bounds states
// and needs manual review. An optional Level C mode reports unbounded
// guest-controlled requests to allocators that terminate QEMU on allocation
// failure.
//
//===----------------------------------------------------------------------===//

#include "QEMUContractCatalog.inc"
#include "QEMUSharedState.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DynamicRecursiveASTVisitor.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/StmtCXX.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
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
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Base64.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/VirtualFileSystem.h"
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
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUPendingAllocationRelationKinds, const Expr *,
                               unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUPendingAllocationRelationLeft, const Expr *,
                               SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUPendingAllocationRelationRight, const Expr *,
                               SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUAllocationRelationKinds, SymbolRef, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUAllocationRelationLeft, SymbolRef, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUAllocationRelationRight, SymbolRef, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUPendingIovecSourceSizes, const Expr *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUPendingDMAMapRequestedExtents, const Expr *,
                               SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUPendingDMAMapDirections, const Expr *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUPendingDMAMapOwners, const Expr *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUPendingUSBPacketCopyDirections, const Expr *,
                               unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUPendingInitializedByteBulkDestinations,
                               const Expr *, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(QEMUPendingInitializedBytePreciseBinds,
                               const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUFailedCompletionScopeOwners,
                               const StackFrame *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUDMAMappedDirections, SymbolRef, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUDMARetiredOrigins, SymbolRef, const Expr *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUSavedTaintedScalars, const VarRegion *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUPersistentFieldSources, SymbolRef,
                               const FieldDecl *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUPersistentLocalSources, const VarRegion *,
                               const FieldDecl *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInputClasses, SymbolRef, unsigned)
REGISTER_SET_WITH_PROGRAMSTATE(QEMUVirtqueueElements, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(QEMUVirtqueueIovecs, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInputIovecs, const MemRegion *, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInputBufferLengths, const MemRegion *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInputBufferClasses, const MemRegion *,
                               unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInputBufferParameters, const MemRegion *,
                               const ParmVarDecl *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInputBufferLengthParameters,
                               const MemRegion *, const ParmVarDecl *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInputBufferReadConditions, const MemRegion *,
                               SVal)
REGISTER_SET_WITH_PROGRAMSTATE(QEMUNonNegativeUSBScalars, const VarRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUUSBScalarLowZeroBits, const VarRegion *,
                               unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInvalidUSBSetupLengthValues,
                               const FieldRegion *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInvalidUSBSetupLengthOrigins,
                               const FieldRegion *, const Expr *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInvalidUSBSetupLengthFrames,
                               const FieldRegion *, const StackFrame *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInvalidUSBSetupLengthKinds,
                               const FieldRegion *, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInvalidUSBSetupLengthDefinite,
                               const FieldRegion *, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInitializedByteRangeLengths,
                               const MemRegion *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInitializedByteObjectExtents,
                               const MemRegion *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInitializedByteObjectPrecisions,
                               const MemRegion *, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInitializedByteRangeOrigins,
                               const MemRegion *, const Expr *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInitializedByteRangeKinds, const MemRegion *,
                               unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInitializedByteRangeClasses,
                               const MemRegion *, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUKnownNULTerminatorOffsets, const MemRegion *,
                               SVal)

namespace {

static constexpr qemu::facts::ModelIDRef
    GuestMemorySafetyModelID("qemu-gms-v3-v1");
static constexpr qemu::facts::RuleIDRef
    DirectDMAContractRuleID("qemu.direct-dma.contract");
static constexpr qemu::facts::RuleIDRef
    DirectDMALifetimeRuleID("qemu.direct-dma.lifetime");
static constexpr qemu::facts::RuleIDRef
    DMATransferResultRuleID("qemu.dma-transfer-result");
static constexpr qemu::facts::RuleIDRef
    FailedCompletionPublicationRuleID("qemu.failed-completion-publication");
static constexpr qemu::facts::RuleIDRef
    GuestMemoryBoundsRuleID("qemu.guest-memory.bounds");
static constexpr qemu::facts::RuleIDRef
    USBSetupLengthRuleID("qemu.usb.setup-length");
static constexpr qemu::facts::RuleIDRef
    InitializedBytesDisclosureRuleID("qemu.initialized-bytes.disclosure");
static constexpr qemu::facts::RuleIDRef
    CallbackBufferBoundsRuleID("qemu.callback-buffer.bounds");
static constexpr qemu::facts::RuleIDRef
    AllocationSizeOverflowRuleID("qemu.allocation-size.overflow");
static constexpr qemu::facts::RuleIDRef
    AllocationUnboundedRuleID("qemu.allocation.unbounded");

static_assert(
    qemu::facts::isValidPersistentToken(GuestMemorySafetyModelID.value()) &&
    qemu::facts::isValidPersistentToken(DirectDMAContractRuleID.value()) &&
    qemu::facts::isValidPersistentToken(DirectDMALifetimeRuleID.value()) &&
    qemu::facts::isValidPersistentToken(DMATransferResultRuleID.value()) &&
    qemu::facts::isValidPersistentToken(
        FailedCompletionPublicationRuleID.value()) &&
    qemu::facts::isValidPersistentToken(GuestMemoryBoundsRuleID.value()) &&
    qemu::facts::isValidPersistentToken(USBSetupLengthRuleID.value()) &&
    qemu::facts::isValidPersistentToken(
        InitializedBytesDisclosureRuleID.value()) &&
    qemu::facts::isValidPersistentToken(CallbackBufferBoundsRuleID.value()) &&
    qemu::facts::isValidPersistentToken(AllocationSizeOverflowRuleID.value()) &&
    qemu::facts::isValidPersistentToken(AllocationUnboundedRuleID.value()));

template <typename Tag>
static StringRef stableID(qemu::facts::StableIDRef<Tag> ID) {
  std::string_view Value = ID.value();
  return StringRef(Value.data(), Value.size());
}

enum class InputClass {
  MMIO,
  PIO,
  DMA,
  Migration,
  Network,
  DiskImage,
  Virtio,
  Virtqueue,
  PCIConfig,
  DeviceRequest,
  USB,
  Mixed
};

enum class CallbackBufferLengthKind {
  Parameter,
  Fixed,
  VirtioConfigLength,
  SCSICommandLength,
};

struct CallbackBufferInfo {
  unsigned BufferParameter;
  CallbackBufferLengthKind LengthKind;
  unsigned LengthParameter = 0;
  uint64_t FixedLength = 0;
  std::optional<unsigned> SelectorParameter;
  uint64_t SelectorMask = 0;
  uint64_t SelectorValue = 0;
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
  uint64_t IovecMask = 0;
  llvm::SmallVector<CallbackBufferInfo, 1> Buffers;
  llvm::SmallVector<const qemu_contracts_generated::CallbackEntryInputRecord *,
                    4>
      MemberInputs;
};

enum class CallbackSignature {
  VirtioSetFeaturesEx,
  VirtioSetFeatures,
  VirtioSetConfig,
  VirtioSetStatus,
  VirtioQueueIndex,
  PCIConfigWrite,
  NetReceive,
  NetReceiveIovec,
  NetFilterReceiveIovec,
  SCSIParseCDB,
  SCSISendCommand,
};

struct CallbackFieldSpec {
  const char *RecordName;
  const char *FieldName;
  InputClass Source;
  uint64_t ParameterMask;
  uint64_t PointeeMask;
  uint64_t IovecMask;
  CallbackSignature Signature;
  int AddressParameter = -1;
  int AccessSizeParameter = -1;
  uint64_t AccessSizeLimit = 0;
};

struct BoundStates {
  ProgramStateRef Safe;
  ProgramStateRef Unsafe;
};

enum class BoundUnit { Bytes, Elements, Bits };

enum class USBSetupLengthViolation : unsigned {
  Negative = 1,
  ExceedsCapacity = 2,
};

enum class USBPacketCopyBoundsViolation : unsigned {
  NegativeActualLength,
  RangeExceedsCapacity,
  ActualLengthUpdateNotRepresentable,
};

enum class InitializedByteKind : unsigned {
  InitialUninitialized,
  ZeroInitialized,
  QEMUGetBuffer,
  GInputReadAll,
  DMATransfer,
  USBPacketCopy,
  Copy,
  Memset,
};

enum class InitializedBytePrecision : unsigned {
  Exact,
  Abandoned,
};

enum class InitializedCoverageKind : unsigned {
  ExactCoverage,
  KnownGap,
  Unknown,
};

struct InitializedCoverage {
  InitializedCoverageKind Kind;
  SVal Length;
  const MemRegion *RangeStart = nullptr;
  bool IncludesAdjacentNUL = false;
};

enum class AllocationRelationKind : unsigned {
  NonOverflowingAdd,
  WrappedAdd,
  CheckedMultiply,
};

enum class AllocationAccessRelation { Unknown, Covered, Exceeds };

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
  case InputClass::PCIConfig:
    return "PCI configuration";
  case InputClass::DeviceRequest:
    return "device request";
  case InputClass::USB:
    return "USB";
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
  // Numeric checker predicates must not accidentally mix an unevaluated
  // lvalue with an integer bound.  SimpleSValBuilder treats that combination
  // as pointer arithmetic, which is invalid for our relational operations.
  if (Left.getAs<Loc>().has_value() != Right.getAs<Loc>().has_value())
    return std::nullopt;
  SVal Condition =
      SVB.evalBinOp(State, Op, Left, Right, SVB.getContext().BoolTy);
  auto Defined = Condition.getAs<DefinedOrUnknownSVal>();
  if (!Defined || Condition.isUnknown())
    return std::nullopt;
  auto [TrueState, FalseState] = State->assume(*Defined);
  return BoundStates{TrueState, FalseState};
}

static bool isDefinitelyTrue(ProgramStateRef State, SVal Left,
                             BinaryOperatorKind Op, SVal Right,
                             SValBuilder &SVB) {
  std::optional<BoundStates> Result = compare(State, Left, Op, Right, SVB);
  return Result && Result->Safe && !Result->Unsafe;
}

static std::optional<BoundStates>
compareSourceCondition(ProgramStateRef State, SVal Left, BinaryOperatorKind Op,
                       SVal Right, SValBuilder &SVB) {
  // This helper is only for integer source predicates.  A MemberExpr queried
  // before its lvalue-to-rvalue conversion may still be represented as a Loc.
  // Passing that accidental lvalue together with an integer bound to
  // evalBinOp() enters the Loc/NonLoc pointer-arithmetic path, where relational
  // integer operations are not valid.  Fail closed instead of manufacturing a
  // guard (or crashing the analyzer).
  if (!Left.getAs<NonLoc>() || !Right.getAs<NonLoc>())
    return std::nullopt;
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
                     check::EndFunction, check::EndOfTranslationUnit,
                     check::PreCall, check::PostCall, check::Location,
                     check::Bind, check::LiveSymbols, check::DeadSymbols,
                     check::RegionChanges, check::PostStmt<ImplicitCastExpr>,
                     check::PostStmt<DeclStmt>, check::PreStmt<CallExpr>,
                     check::PostStmt<CallExpr>,
                     check::PreStmt<ArraySubscriptExpr>> {
  mutable llvm::DenseMap<const FunctionDecl *, CallbackInfo> Callbacks;
  mutable llvm::DenseMap<const FunctionDecl *, std::string>
      CallbackRegistrations;
  mutable llvm::DenseSet<const FunctionDecl *> AmbiguousCallbackRegistrations;
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
  mutable std::unique_ptr<BugType> LevelCBug;
  mutable std::unique_ptr<BugType> DirectDMAContractBug;
  mutable std::unique_ptr<BugType> DirectDMALifetimeBug;
  mutable std::unique_ptr<BugType> DMATransferResultBug;
  mutable std::unique_ptr<BugType> FailedCompletionPublicationBug;
  mutable std::unique_ptr<BugType> UninitializedDataDisclosureBug;
  mutable std::unique_ptr<BugType> USBPacketCopyBoundsBug;
  bool ReportLevelC = false;
  bool EmitStructuredWitness = false;
  bool EnableInitializedByteTracking = false;
  bool EnableDMATransferResultDiagnostics = false;
  bool EnableFailedCompletionPublicationDiagnostics = false;
  unsigned MaxInitializedRangesPerObject = 8;
  std::string QEMUSourceRoot;

  enum class SelectiveSummaryDirection { FromDevice, ToDevice };
  enum class SelectiveSummaryEffect { ResultAndExtentOnly, FullTransfer };

  struct SelectiveDMASummary {
    std::string Function;
    std::string LookupName;
    std::string Prototype;
    std::string Header;
    std::string PrototypeSHA256;
    unsigned DeclarationLine;
    unsigned DeclarationColumn;
    SelectiveSummaryDirection Direction;
    SelectiveSummaryEffect Effect;
  };

  std::string SelectiveSummaryManifest;
  unsigned SelectiveSummaryFormat = 0;
  llvm::SmallVector<SelectiveDMASummary, 3> SelectiveSummaries;
  mutable llvm::SmallDenseSet<const Expr *, 16> SelectiveSummaryMatchedCalls;
  mutable llvm::SmallDenseSet<const Expr *, 16> SelectiveSummaryConsumedCalls;
  mutable llvm::SmallDenseSet<const Expr *, 16>
      SelectiveSummaryUnsupportedCalls;

  static bool isNamedRecordPointer(QualType Type, StringRef Name) {
    if (!Type->isPointerType())
      return false;
    const RecordDecl *Record =
        Type->getPointeeType().getUnqualifiedType()->getAsRecordDecl();
    return Record && Record->getName() == Name;
  }

  static bool isBytePointer(QualType Type, ASTContext &Context) {
    if (!Type->isPointerType())
      return false;
    QualType Pointee = Type->getPointeeType().getUnqualifiedType();
    return Pointee->isIntegerType() && Context.getIntWidth(Pointee) == 8;
  }

  static bool isVoidPointer(QualType Type) {
    return Type->isPointerType() &&
           Type->getPointeeType().getUnqualifiedType()->isVoidType();
  }

  static bool isIntegerWidth(QualType Type, unsigned Width,
                             ASTContext &Context) {
    return Type->isIntegralOrEnumerationType() &&
           Context.getIntWidth(Type) == Width;
  }

  static bool isInteger(QualType Type) {
    return Type->isIntegralOrEnumerationType();
  }

  static const FieldDecl *namedField(const RecordDecl *Record, StringRef Name) {
    if (!Record)
      return nullptr;
    for (const FieldDecl *Field : Record->fields())
      if (Field->getName() == Name)
        return Field;
    return nullptr;
  }

  static std::optional<uint64_t>
  usbDeviceDataBufferCapacity(const RecordDecl *Record, ASTContext &Context) {
    if (!Record || Record->getName() != "USBDevice")
      return std::nullopt;
    const FieldDecl *SetupBuffer = namedField(Record, "setup_buf");
    const FieldDecl *DataBuffer = namedField(Record, "data_buf");
    const FieldDecl *SetupLength = namedField(Record, "setup_len");
    if (!SetupBuffer || !DataBuffer || !SetupLength ||
        !isIntegerWidth(SetupLength->getType(), 32, Context))
      return std::nullopt;

    const ConstantArrayType *SetupArray =
        Context.getAsConstantArrayType(SetupBuffer->getType());
    const ConstantArrayType *DataArray =
        Context.getAsConstantArrayType(DataBuffer->getType());
    if (!SetupArray || !DataArray ||
        SetupArray->getSize().getActiveBits() > 64 ||
        SetupArray->getSize().getZExtValue() != 8 ||
        !SetupArray->getElementType()->isUnsignedIntegerType() ||
        !DataArray->getElementType()->isUnsignedIntegerType() ||
        Context.getIntWidth(SetupArray->getElementType()) != 8 ||
        Context.getIntWidth(DataArray->getElementType()) != 8)
      return std::nullopt;

    CharUnits Capacity = Context.getTypeSizeInChars(DataBuffer->getType());
    if (Capacity.isZero() || Capacity.getQuantity() < 0)
      return std::nullopt;
    return static_cast<uint64_t>(Capacity.getQuantity());
  }

  static bool isUSBSetupBufferElement(const MemRegion *Region,
                                      ASTContext &Context) {
    const auto *Element = dyn_cast_or_null<ElementRegion>(Region);
    const auto *Field =
        Element ? dyn_cast<FieldRegion>(Element->getSuperRegion()) : nullptr;
    const FieldDecl *Declaration = Field ? Field->getDecl() : nullptr;
    const RecordDecl *Record = Declaration ? Declaration->getParent() : nullptr;
    return Declaration && Declaration->getName() == "setup_buf" &&
           usbDeviceDataBufferCapacity(Record, Context).has_value();
  }

  static std::optional<uint64_t>
  usbSetupLengthCapacity(const FieldRegion *Region, ASTContext &Context) {
    const FieldDecl *Field = Region ? Region->getDecl() : nullptr;
    if (!Field || Field->getName() != "setup_len")
      return std::nullopt;
    return usbDeviceDataBufferCapacity(Field->getParent(), Context);
  }

  static bool isUSBDeviceObjectRegion(const MemRegion *Region,
                                      ASTContext &Context) {
    if (!Region)
      return false;
    Region = Region->StripCasts();
    QualType Type;
    if (const auto *Typed = dyn_cast<TypedValueRegion>(Region))
      Type = Typed->getValueType();
    else if (const auto *Symbolic = dyn_cast<SymbolicRegion>(Region))
      Type = Symbolic->getPointeeStaticType();
    const RecordDecl *Record =
        Type.isNull() ? nullptr : Type.getUnqualifiedType()->getAsRecordDecl();
    return usbDeviceDataBufferCapacity(Record, Context).has_value();
  }

  static const FieldRegion *usbSetupLengthRegion(const MemRegion *Object,
                                                 CheckerContext &C) {
    if (!Object)
      return nullptr;
    Object = Object->StripCasts();
    const auto *Super = dyn_cast<SubRegion>(Object);
    if (!Super)
      return nullptr;
    QualType Type;
    if (const auto *Typed = dyn_cast<TypedValueRegion>(Object))
      Type = Typed->getValueType();
    else if (const auto *Symbolic = dyn_cast<SymbolicRegion>(Object))
      Type = Symbolic->getPointeeStaticType();
    const RecordDecl *Record =
        Type.isNull() ? nullptr : Type.getUnqualifiedType()->getAsRecordDecl();
    if (!usbDeviceDataBufferCapacity(Record, C.getASTContext()))
      return nullptr;
    const FieldDecl *SetupLength = namedField(Record, "setup_len");
    return SetupLength ? C.getSValBuilder().getRegionManager().getFieldRegion(
                             SetupLength, Super)
                       : nullptr;
  }

  static bool isZeroAggregateInitializer(const Expr *Expression,
                                         ASTContext &Context,
                                         unsigned Depth = 0) {
    if (!Expression || Depth > 16)
      return false;
    const Expr *E = Expression->IgnoreParenImpCasts();
    if (const auto *Compound = dyn_cast<CompoundLiteralExpr>(E))
      return isZeroAggregateInitializer(Compound->getInitializer(), Context,
                                        Depth + 1);
    if (isa<ImplicitValueInitExpr>(E))
      return true;
    if (const auto *Initializer = dyn_cast<InitListExpr>(E)) {
      for (const Expr *Element : Initializer->inits())
        if (!isZeroAggregateInitializer(Element, Context, Depth + 1))
          return false;
      return true;
    }
    if (std::optional<llvm::APSInt> Constant =
            E->getIntegerConstantExpr(Context))
      return Constant->isZero();
    return false;
  }

  static bool usbLengthExpressionKnownNonNegative(const Expr *Expression,
                                                  ProgramStateRef State,
                                                  CheckerContext &C,
                                                  unsigned Depth = 0) {
    if (!Expression || Depth > 16)
      return false;

    const Expr *E = Expression->IgnoreParens();
    ASTContext &Context = C.getASTContext();
    if (const auto *Cast = dyn_cast<CastExpr>(E)) {
      QualType Destination = Cast->getType();
      QualType Source = Cast->getSubExpr()->getType();
      if (Destination->isUnsignedIntegerOrEnumerationType())
        return true;
      if (!Destination->isSignedIntegerOrEnumerationType() ||
          !Source->isIntegralOrEnumerationType())
        return false;
      if (Source->isUnsignedIntegerOrEnumerationType())
        return Context.getIntWidth(Destination) > Context.getIntWidth(Source);
      if (!Source->isSignedIntegerOrEnumerationType() ||
          Context.getIntWidth(Destination) < Context.getIntWidth(Source))
        return false;
      return usbLengthExpressionKnownNonNegative(Cast->getSubExpr(), State, C,
                                                 Depth + 1);
    }
    if (E->getType()->isUnsignedIntegerOrEnumerationType() ||
        E->isKnownToHaveBooleanValue())
      return true;
    if (std::optional<llvm::APSInt> Constant =
            E->getIntegerConstantExpr(Context))
      return !Constant->isNegative();
    if (const auto *Reference = dyn_cast<DeclRefExpr>(E)) {
      const auto *Variable = dyn_cast<VarDecl>(Reference->getDecl());
      if (!Variable)
        return false;
      const VarRegion *Region = State->getRegion(Variable, C.getStackFrame());
      return State->contains<QEMUNonNegativeUSBScalars>(Region);
    }
    if (const auto *Unary = dyn_cast<UnaryOperator>(E)) {
      if (Unary->getOpcode() == UO_LNot)
        return true;
      if (Unary->getOpcode() == UO_Plus)
        return usbLengthExpressionKnownNonNegative(Unary->getSubExpr(), State,
                                                   C, Depth + 1);
      return false;
    }
    if (const auto *Conditional = dyn_cast<ConditionalOperator>(E))
      return usbLengthExpressionKnownNonNegative(Conditional->getTrueExpr(),
                                                 State, C, Depth + 1) &&
             usbLengthExpressionKnownNonNegative(Conditional->getFalseExpr(),
                                                 State, C, Depth + 1);
    const auto *Binary = dyn_cast<BinaryOperator>(E);
    if (!Binary)
      return false;
    if (Binary->isComparisonOp() || Binary->getOpcode() == BO_LAnd ||
        Binary->getOpcode() == BO_LOr)
      return true;
    if (Binary->getOpcode() == BO_Or)
      return usbLengthExpressionKnownNonNegative(Binary->getLHS(), State, C,
                                                 Depth + 1) &&
             usbLengthExpressionKnownNonNegative(Binary->getRHS(), State, C,
                                                 Depth + 1);
    if (Binary->getOpcode() == BO_And) {
      for (const Expr *Operand : {Binary->getLHS(), Binary->getRHS()})
        if (std::optional<llvm::APSInt> Mask =
                Operand->getIntegerConstantExpr(Context))
          if (!Mask->isNegative())
            return true;
      return false;
    }
    if (Binary->getOpcode() == BO_Shr)
      return usbLengthExpressionKnownNonNegative(Binary->getLHS(), State, C,
                                                 Depth + 1);
    if (Binary->getOpcode() != BO_Shl ||
        !usbLengthExpressionKnownNonNegative(Binary->getLHS(), State, C,
                                             Depth + 1))
      return false;
    std::optional<llvm::APSInt> Shift =
        Binary->getRHS()->getIntegerConstantExpr(Context);
    QualType ResultType = Binary->getType();
    QualType SourceType = Binary->getLHS()->IgnoreParenImpCasts()->getType();
    if (!Shift || Shift->isNegative() || Shift->getActiveBits() > 64 ||
        !ResultType->isIntegerType() || !SourceType->isIntegerType())
      return false;
    uint64_t ShiftAmount = Shift->getZExtValue();
    uint64_t ResultWidth = Context.getIntWidth(ResultType);
    uint64_t SourceWidth = Context.getIntWidth(SourceType);
    return ShiftAmount < ResultWidth && SourceWidth + ShiftAmount < ResultWidth;
  }

  static bool usbStoredLengthKnownNonNegative(const Expr *Expression,
                                              QualType Destination,
                                              ProgramStateRef State,
                                              CheckerContext &C) {
    if (!Expression || !Destination->isIntegralOrEnumerationType())
      return false;
    if (Destination->isUnsignedIntegerOrEnumerationType())
      return true;

    const Expr *Input = Expression->IgnoreParens();
    if (const auto *Conversion = dyn_cast<CastExpr>(Input))
      if (C.getASTContext().hasSameUnqualifiedType(Conversion->getType(),
                                                   Destination))
        Input = Conversion->getSubExpr();
    if (!usbLengthExpressionKnownNonNegative(Input, State, C))
      return false;

    QualType Source = Input->getType();
    if (!Destination->isSignedIntegerOrEnumerationType() ||
        !Source->isIntegralOrEnumerationType())
      return false;
    if (Source->isUnsignedIntegerOrEnumerationType()) {
      if (C.getASTContext().getIntWidth(Destination) >
          C.getASTContext().getIntWidth(Source))
        return true;

      SVal SourceValue = expressionValue(Input, C);
      const llvm::APSInt *DynamicMaximum =
          C.getSValBuilder().getMaxValue(State, SourceValue);
      if (!DynamicMaximum || DynamicMaximum->isNegative())
        return false;
      llvm::APSInt DestinationMaximum =
          C.getSValBuilder().getBasicValueFactory().getMaxValue(Destination);
      unsigned Width = std::max(DynamicMaximum->getBitWidth(),
                                DestinationMaximum.getBitWidth());
      return DynamicMaximum->zextOrTrunc(Width).ule(
          DestinationMaximum.zextOrTrunc(Width));
    }
    return Source->isSignedIntegerOrEnumerationType() &&
           C.getASTContext().getIntWidth(Destination) >=
               C.getASTContext().getIntWidth(Source);
  }

  static unsigned usbKnownLowZeroBits(const Expr *Expression,
                                      ProgramStateRef State, CheckerContext &C,
                                      unsigned Depth = 0) {
    if (!Expression || Depth > 16)
      return 0;
    const Expr *E = Expression->IgnoreParens();
    ASTContext &Context = C.getASTContext();
    if (const auto *Cast = dyn_cast<CastExpr>(E)) {
      if (!Cast->getType()->isIntegralOrEnumerationType())
        return 0;
      return std::min(
          Context.getIntWidth(Cast->getType()),
          usbKnownLowZeroBits(Cast->getSubExpr(), State, C, Depth + 1));
    }
    if (const auto *Reference = dyn_cast<DeclRefExpr>(E)) {
      const auto *Variable = dyn_cast<VarDecl>(Reference->getDecl());
      if (Variable) {
        const VarRegion *Region = State->getRegion(Variable, C.getStackFrame());
        if (const unsigned *Bits = State->get<QEMUUSBScalarLowZeroBits>(Region))
          return *Bits;
      }
      return 0;
    }
    if (const auto *Literal = dyn_cast<IntegerLiteral>(E)) {
      unsigned Width = Context.getIntWidth(Literal->getType());
      return Literal->getValue().isZero()
                 ? Width
                 : std::min(Width, Literal->getValue().countTrailingZeros());
    }
    if (const auto *Unary = dyn_cast<UnaryOperator>(E)) {
      if (Unary->getOpcode() == UO_Plus || Unary->getOpcode() == UO_Minus)
        return usbKnownLowZeroBits(Unary->getSubExpr(), State, C, Depth + 1);
      return 0;
    }
    const auto *Binary = dyn_cast<BinaryOperator>(E);
    if (!Binary || !Binary->getType()->isUnsignedIntegerType())
      return 0;
    unsigned Width = Context.getIntWidth(Binary->getType());
    unsigned Left = usbKnownLowZeroBits(Binary->getLHS(), State, C, Depth + 1);
    unsigned Right = usbKnownLowZeroBits(Binary->getRHS(), State, C, Depth + 1);
    if (Binary->getOpcode() == BO_Shl) {
      std::optional<llvm::APSInt> Shift =
          Binary->getRHS()->getIntegerConstantExpr(Context);
      if (!Shift || Shift->isNegative() || Shift->getActiveBits() > 64 ||
          Shift->getZExtValue() >= Width)
        return 0;
      return std::min<uint64_t>(Width, Left + Shift->getZExtValue());
    }
    if (Binary->getOpcode() == BO_Mul)
      return std::min(Width, Left + Right);
    if (Binary->getOpcode() == BO_And)
      return std::max(Left, Right);
    if (Binary->getOpcode() == BO_Or || Binary->getOpcode() == BO_Xor)
      return std::min(Left, Right);
    return 0;
  }

  static bool usbNarrowingConversionKnownZero(const Expr *Expression,
                                              QualType Destination,
                                              ProgramStateRef State,
                                              CheckerContext &C) {
    if (!Expression || !Destination->isIntegralOrEnumerationType())
      return false;
    ASTContext &Context = C.getASTContext();
    const auto *Conversion = dyn_cast<CastExpr>(Expression->IgnoreParens());
    if (!Conversion ||
        !Conversion->getSubExpr()->getType()->isIntegralOrEnumerationType())
      return false;
    unsigned DestinationWidth = Context.getIntWidth(Destination);
    if (Context.getIntWidth(Conversion->getSubExpr()->getType()) <=
        DestinationWidth)
      return false;
    return usbKnownLowZeroBits(Conversion->getSubExpr(), State, C) >=
           DestinationWidth;
  }

  static ProgramStateRef clearInvalidUSBSetupLength(ProgramStateRef State,
                                                    const FieldRegion *Field) {
    return State->remove<QEMUInvalidUSBSetupLengthValues>(Field)
        ->remove<QEMUInvalidUSBSetupLengthOrigins>(Field)
        ->remove<QEMUInvalidUSBSetupLengthFrames>(Field)
        ->remove<QEMUInvalidUSBSetupLengthKinds>(Field)
        ->remove<QEMUInvalidUSBSetupLengthDefinite>(Field);
  }

  static ProgramStateRef
  clearInvalidUSBSetupLengthsWithin(ProgramStateRef State,
                                    const MemRegion *Object) {
    if (!Object)
      return State;
    Object = Object->StripCasts();
    auto InvalidUSBSetupLengths = State->get<QEMUInvalidUSBSetupLengthValues>();
    for (const auto &Entry : InvalidUSBSetupLengths)
      if (Entry.first->isSubRegionOf(Object))
        State = clearInvalidUSBSetupLength(State, Entry.first);
    return State;
  }

  static const FieldRegion *
  invalidUSBSetupLengthWithin(ProgramStateRef State, const MemRegion *Object) {
    if (!Object)
      return nullptr;
    Object = Object->StripCasts();
    for (const auto &Entry : State->get<QEMUInvalidUSBSetupLengthValues>())
      if (Entry.first->isSubRegionOf(Object))
        return Entry.first;
    return nullptr;
  }

  static ProgramStateRef
  markInvalidUSBSetupLength(ProgramStateRef State, const FieldRegion *Field,
                            SVal Value, const Expr *Origin,
                            const StackFrame *Frame,
                            USBSetupLengthViolation Kind, bool Definite) {
    return State->set<QEMUInvalidUSBSetupLengthValues>(Field, Value)
        ->set<QEMUInvalidUSBSetupLengthOrigins>(Field, Origin)
        ->set<QEMUInvalidUSBSetupLengthFrames>(Field, Frame)
        ->set<QEMUInvalidUSBSetupLengthKinds>(Field,
                                              static_cast<unsigned>(Kind))
        ->set<QEMUInvalidUSBSetupLengthDefinite>(Field, Definite ? 1U : 0U);
  }

  static ProgramStateRef
  copyInvalidUSBSetupLength(ProgramStateRef State, const FieldRegion *Source,
                            const FieldRegion *Destination,
                            const StackFrame *Frame) {
    if (!Destination)
      return State;

    std::optional<SVal> Value;
    const Expr *Origin = nullptr;
    unsigned Kind = 0;
    unsigned Definite = 0;
    if (Source) {
      if (const SVal *Stored =
              State->get<QEMUInvalidUSBSetupLengthValues>(Source))
        Value = *Stored;
      if (const Expr *const *Stored =
              State->get<QEMUInvalidUSBSetupLengthOrigins>(Source))
        Origin = *Stored;
      if (const unsigned *Stored =
              State->get<QEMUInvalidUSBSetupLengthKinds>(Source))
        Kind = *Stored;
      if (const unsigned *Stored =
              State->get<QEMUInvalidUSBSetupLengthDefinite>(Source))
        Definite = *Stored;
    }

    State = clearInvalidUSBSetupLength(State, Destination);
    if (!Value || !Origin ||
        (Kind != static_cast<unsigned>(USBSetupLengthViolation::Negative) &&
         Kind !=
             static_cast<unsigned>(USBSetupLengthViolation::ExceedsCapacity)))
      return State;
    return markInvalidUSBSetupLength(State, Destination, *Value, Origin, Frame,
                                     static_cast<USBSetupLengthViolation>(Kind),
                                     Definite != 0);
  }

  static bool callbackSignatureMatches(const FunctionDecl *FD,
                                       CallbackSignature Signature) {
    if (!FD || FD->isVariadic())
      return false;
    ASTContext &Context = FD->getASTContext();
    auto HasParameters = [&](unsigned Count) {
      return FD->getNumParams() == Count;
    };
    auto Parameter = [&](unsigned Index) {
      return FD->getParamDecl(Index)->getType();
    };
    auto ReturnsVoid = [&] { return FD->getReturnType()->isVoidType(); };
    auto ReturnsInteger = [&] { return isInteger(FD->getReturnType()); };

    switch (Signature) {
    case CallbackSignature::VirtioSetFeaturesEx:
      return HasParameters(2) && ReturnsVoid() &&
             isNamedRecordPointer(Parameter(0), "VirtIODevice") &&
             Parameter(1)->isPointerType() &&
             isIntegerWidth(Parameter(1)->getPointeeType(), 64, Context);
    case CallbackSignature::VirtioSetFeatures:
      return HasParameters(2) && ReturnsVoid() &&
             isNamedRecordPointer(Parameter(0), "VirtIODevice") &&
             isIntegerWidth(Parameter(1), 64, Context);
    case CallbackSignature::VirtioSetConfig:
      return HasParameters(2) && ReturnsVoid() &&
             isNamedRecordPointer(Parameter(0), "VirtIODevice") &&
             isBytePointer(Parameter(1), Context);
    case CallbackSignature::VirtioSetStatus:
      return HasParameters(2) && ReturnsInteger() &&
             isNamedRecordPointer(Parameter(0), "VirtIODevice") &&
             isIntegerWidth(Parameter(1), 8, Context);
    case CallbackSignature::VirtioQueueIndex:
      return HasParameters(2) && ReturnsVoid() &&
             isNamedRecordPointer(Parameter(0), "VirtIODevice") &&
             isIntegerWidth(Parameter(1), 32, Context);
    case CallbackSignature::PCIConfigWrite:
      return HasParameters(4) && ReturnsVoid() &&
             isNamedRecordPointer(Parameter(0), "PCIDevice") &&
             isIntegerWidth(Parameter(1), 32, Context) &&
             isIntegerWidth(Parameter(2), 32, Context) &&
             isInteger(Parameter(3));
    case CallbackSignature::NetReceive:
      return HasParameters(3) && ReturnsInteger() &&
             isNamedRecordPointer(Parameter(0), "NetClientState") &&
             isBytePointer(Parameter(1), Context) && isInteger(Parameter(2));
    case CallbackSignature::NetReceiveIovec:
      return HasParameters(3) && ReturnsInteger() &&
             isNamedRecordPointer(Parameter(0), "NetClientState") &&
             isNamedRecordPointer(Parameter(1), "iovec") &&
             isInteger(Parameter(2));
    case CallbackSignature::NetFilterReceiveIovec:
      return HasParameters(6) && ReturnsInteger() &&
             isNamedRecordPointer(Parameter(0), "NetFilterState") &&
             isNamedRecordPointer(Parameter(1), "NetClientState") &&
             isInteger(Parameter(2)) &&
             isNamedRecordPointer(Parameter(3), "iovec") &&
             isInteger(Parameter(4)) && Parameter(5)->isPointerType() &&
             Parameter(5)->getPointeeType()->isFunctionProtoType();
    case CallbackSignature::SCSIParseCDB:
      return HasParameters(5) && ReturnsInteger() &&
             isNamedRecordPointer(Parameter(0), "SCSIDevice") &&
             isNamedRecordPointer(Parameter(1), "SCSICommand") &&
             isBytePointer(Parameter(2), Context) && isInteger(Parameter(3)) &&
             isVoidPointer(Parameter(4));
    case CallbackSignature::SCSISendCommand:
      return HasParameters(2) && ReturnsInteger() &&
             isNamedRecordPointer(Parameter(0), "SCSIRequest") &&
             isBytePointer(Parameter(1), Context);
    }
    llvm_unreachable("unknown QEMU callback signature");
  }

  static const CallbackFieldSpec *callbackFieldSpec(StringRef RecordName,
                                                    StringRef FieldName) {
    static constexpr CallbackFieldSpec Specs[] = {
        {"VirtioDeviceClass", "set_features_ex", InputClass::Virtio, 0, 0, 0,
         CallbackSignature::VirtioSetFeaturesEx},
        {"VirtioDeviceClass", "set_features", InputClass::Virtio,
         uint64_t(1) << 1, 0, 0, CallbackSignature::VirtioSetFeatures},
        {"VirtioDeviceClass", "set_config", InputClass::Virtio, 0, 0, 0,
         CallbackSignature::VirtioSetConfig},
        {"VirtioDeviceClass", "set_status", InputClass::Virtio,
         uint64_t(1) << 1, 0, 0, CallbackSignature::VirtioSetStatus},
        {"VirtioDeviceClass", "queue_reset", InputClass::Virtio,
         uint64_t(1) << 1, 0, 0, CallbackSignature::VirtioQueueIndex},
        {"VirtioDeviceClass", "queue_enable", InputClass::Virtio,
         uint64_t(1) << 1, 0, 0, CallbackSignature::VirtioQueueIndex},
        {"PCIDeviceClass", "config_write", InputClass::PCIConfig,
         (uint64_t(1) << 1) | (uint64_t(1) << 2) | (uint64_t(1) << 3), 0, 0,
         CallbackSignature::PCIConfigWrite, 1, 3, 4},
        {"NetClientInfo", "receive", InputClass::Network, uint64_t(1) << 2, 0,
         0, CallbackSignature::NetReceive},
        {"NetClientInfo", "receive_iov", InputClass::Network, uint64_t(1) << 2,
         0, uint64_t(1) << 1, CallbackSignature::NetReceiveIovec},
        {"NetFilterClass", "receive_iov", InputClass::Network,
         (uint64_t(1) << 2) | (uint64_t(1) << 4), 0, uint64_t(1) << 3,
         CallbackSignature::NetFilterReceiveIovec},
        {"SCSIBusInfo", "parse_cdb", InputClass::DeviceRequest,
         uint64_t(1) << 3, 0, 0, CallbackSignature::SCSIParseCDB},
        {"SCSIDeviceClass", "parse_cdb", InputClass::DeviceRequest,
         uint64_t(1) << 3, 0, 0, CallbackSignature::SCSIParseCDB},
        {"SCSIReqOps", "send_command", InputClass::DeviceRequest, 0, 0, 0,
         CallbackSignature::SCSISendCommand},
    };
    for (const CallbackFieldSpec &Spec : Specs)
      if (RecordName == Spec.RecordName && FieldName == Spec.FieldName)
        return &Spec;
    return nullptr;
  }

  static std::optional<CallbackBufferInfo>
  callbackBufferInfo(CallbackSignature Signature) {
    switch (Signature) {
    case CallbackSignature::VirtioSetFeaturesEx:
      // QEMU's VIRTIO_FEATURES_NU64S is asserted to be two in virtio.c.
      return CallbackBufferInfo{1, CallbackBufferLengthKind::Fixed, 0, 16};
    case CallbackSignature::VirtioSetConfig:
      return CallbackBufferInfo{1,
                                CallbackBufferLengthKind::VirtioConfigLength};
    case CallbackSignature::NetReceive:
      return CallbackBufferInfo{1, CallbackBufferLengthKind::Parameter, 2};
    case CallbackSignature::SCSIParseCDB:
      return CallbackBufferInfo{2, CallbackBufferLengthKind::Parameter, 3};
    case CallbackSignature::SCSISendCommand:
      return CallbackBufferInfo{1, CallbackBufferLengthKind::SCSICommandLength};
    case CallbackSignature::VirtioSetFeatures:
    case CallbackSignature::VirtioSetStatus:
    case CallbackSignature::VirtioQueueIndex:
    case CallbackSignature::PCIConfigWrite:
    case CallbackSignature::NetReceiveIovec:
    case CallbackSignature::NetFilterReceiveIovec:
      return std::nullopt;
    }
    llvm_unreachable("unknown QEMU callback signature");
  }

  void
  addCallback(const FunctionDecl *FD, InputClass Source, uint64_t ParameterMask,
              uint64_t PointeeMask = 0, uint64_t IovecMask = 0,
              std::optional<unsigned> AddressParameter = std::nullopt,
              std::optional<unsigned> AccessSizeParameter = std::nullopt,
              std::optional<uint64_t> AccessSizeLimit = std::nullopt) const {
    if (!FD)
      return;
    FD = FD->getCanonicalDecl();
    CallbackInfo &Info = Callbacks[FD];
    if ((Info.ParameterMask || Info.PointeeMask || Info.IovecMask ||
         !Info.Buffers.empty() || !Info.MemberInputs.empty()) &&
        Info.Source != Source)
      Info.Source = InputClass::Mixed;
    else
      Info.Source = Source;
    Info.ParameterMask |= ParameterMask;
    Info.PointeeMask |= PointeeMask;
    Info.IovecMask |= IovecMask;
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

  void
  addCallback(const Expr *Initializer, InputClass Source,
              std::initializer_list<unsigned> Parameters,
              std::initializer_list<unsigned> Pointees = {},
              std::optional<unsigned> AddressParameter = std::nullopt,
              std::optional<unsigned> AccessSizeParameter = std::nullopt,
              std::optional<uint64_t> AccessSizeLimit = std::nullopt) const {
    uint64_t ParameterMask = 0;
    for (unsigned Parameter : Parameters)
      if (Parameter < 64)
        ParameterMask |= uint64_t(1) << Parameter;
    uint64_t PointeeMask = 0;
    for (unsigned Parameter : Pointees)
      if (Parameter < 64)
        PointeeMask |= uint64_t(1) << Parameter;
    addCallback(referencedFunction(Initializer), Source, ParameterMask,
                PointeeMask, 0, AddressParameter, AccessSizeParameter,
                AccessSizeLimit);
  }

  void addCallback(const Expr *Initializer,
                   const CallbackFieldSpec &Spec) const {
    const FunctionDecl *FD = referencedFunction(Initializer);
    if (!callbackSignatureMatches(FD, Spec.Signature))
      return;
    std::optional<unsigned> AddressParameter;
    std::optional<unsigned> AccessSizeParameter;
    std::optional<uint64_t> AccessSizeLimit;
    if (Spec.AddressParameter >= 0)
      AddressParameter = static_cast<unsigned>(Spec.AddressParameter);
    if (Spec.AccessSizeParameter >= 0)
      AccessSizeParameter = static_cast<unsigned>(Spec.AccessSizeParameter);
    if (Spec.AccessSizeLimit)
      AccessSizeLimit = Spec.AccessSizeLimit;
    addCallback(FD, Spec.Source, Spec.ParameterMask, Spec.PointeeMask,
                Spec.IovecMask, AddressParameter, AccessSizeParameter,
                AccessSizeLimit);
    if (std::optional<CallbackBufferInfo> Buffer =
            callbackBufferInfo(Spec.Signature)) {
      CallbackInfo &Info = Callbacks[FD->getCanonicalDecl()];
      bool Duplicate = llvm::any_of(Info.Buffers, [&](const auto &Existing) {
        return Existing.BufferParameter == Buffer->BufferParameter &&
               Existing.LengthKind == Buffer->LengthKind &&
               Existing.LengthParameter == Buffer->LengthParameter &&
               Existing.FixedLength == Buffer->FixedLength &&
               Existing.SelectorParameter == Buffer->SelectorParameter &&
               Existing.SelectorMask == Buffer->SelectorMask &&
               Existing.SelectorValue == Buffer->SelectorValue;
      });
      if (!Duplicate)
        Info.Buffers.push_back(*Buffer);
    }
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
    if (!Field || !Parent)
      return;
    const CallbackFieldSpec *Spec =
        callbackFieldSpec(Parent->getName(), Field->getName());
    if (Spec)
      addCallback(Assignment->getRHS(), *Spec);
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
    for (const FieldDecl *Field : RD->fields())
      if (const CallbackFieldSpec *Spec =
              callbackFieldSpec(Name, Field->getName()))
        addCallback(fieldInitializer(ILE, Field->getName()), *Spec);
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

  void collectOperationTableCallbacks(
      const InitListExpr *ILE,
      llvm::SmallVectorImpl<const FunctionDecl *> &Result) const {
    ILE = semanticInitList(ILE);
    if (!ILE)
      return;
    const RecordDecl *RD = ILE->getType()->getAsRecordDecl();
    if (!RD)
      return;

    llvm::DenseSet<const FunctionDecl *> Seen;
    auto Add = [&](const Expr *E) {
      if (const FunctionDecl *FD = referencedFunction(E)) {
        FD = FD->getCanonicalDecl();
        if (Seen.insert(FD).second)
          Result.push_back(FD);
      }
    };
    StringRef RecordName = RD->getName();
    for (const FieldDecl *Field : RD->fields())
      if (const CallbackFieldSpec *Spec =
              callbackFieldSpec(RecordName, Field->getName()))
        if (const FunctionDecl *FD =
                referencedFunction(fieldInitializer(ILE, Field->getName())))
          if (callbackSignatureMatches(FD, Spec->Signature))
            Add(fieldInitializer(ILE, Field->getName()));

    if (RecordName == "MemoryRegionOps") {
      Add(fieldInitializer(ILE, "read"));
      Add(fieldInitializer(ILE, "write"));
      Add(fieldInitializer(ILE, "read_with_attrs"));
      Add(fieldInitializer(ILE, "write_with_attrs"));
      if (const InitListExpr *Valid =
              semanticInitList(fieldInitializer(ILE, "valid")))
        Add(fieldInitializer(Valid, "accepts"));
    } else if (RecordName == "MemoryRegionPortio") {
      Add(fieldInitializer(ILE, "read"));
      Add(fieldInitializer(ILE, "write"));
    }
  }

  void recordCallbackRegistration(const FunctionDecl *FD,
                                  StringRef Registration) const {
    if (!FD || Registration.empty())
      return;
    FD = FD->getCanonicalDecl();
    if (AmbiguousCallbackRegistrations.contains(FD))
      return;
    auto Found = CallbackRegistrations.find(FD);
    if (Found == CallbackRegistrations.end()) {
      CallbackRegistrations[FD] = Registration.str();
      return;
    }
    if (Found->second != Registration) {
      CallbackRegistrations.erase(Found);
      AmbiguousCallbackRegistrations.insert(FD);
    }
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

  static bool isDirectBlockRead(const FunctionDecl *FD, StringRef Name) {
    if (!FD || FD->isVariadic() || FD->getNumParams() != 5 ||
        FD->getName() != Name ||
        !isIntegerWidth(FD->getReturnType(), 32, FD->getASTContext()))
      return false;
    StringRef ObjectType = Name == "blk_pread" ? "BlockBackend" : "BdrvChild";
    return isNamedRecordPointer(FD->getParamDecl(0)->getType(), ObjectType) &&
           isIntegerWidth(FD->getParamDecl(1)->getType(), 64,
                          FD->getASTContext()) &&
           isIntegerWidth(FD->getParamDecl(2)->getType(), 64,
                          FD->getASTContext()) &&
           isVoidPointer(FD->getParamDecl(3)->getType()) &&
           isInteger(FD->getParamDecl(4)->getType());
  }

  struct IovecCopy {
    unsigned IovecArgument;
    unsigned BufferArgument;
    unsigned LengthArgument;
    bool ToBuffer;
  };

  static std::optional<IovecCopy> iovecCopy(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() || FD->isVariadic() ||
        !isInteger(FD->getReturnType()))
      return std::nullopt;
    StringRef Name = FD->getName();
    bool ToBuffer;
    if (Name == "iov_to_buf" || Name == "iov_to_buf_full" ||
        Name == "qemu_iovec_to_buf")
      ToBuffer = true;
    else if (Name == "iov_from_buf" || Name == "iov_from_buf_full" ||
             Name == "qemu_iovec_from_buf")
      ToBuffer = false;
    else
      return std::nullopt;

    bool QEMUIovec = Name.starts_with("qemu_iovec_");
    unsigned ExpectedArguments = QEMUIovec ? 4 : 5;
    if (FD->getNumParams() != ExpectedArguments ||
        Call.getNumArgs() != ExpectedArguments)
      return std::nullopt;
    StringRef IovecType = QEMUIovec ? "QEMUIOVector" : "iovec";
    if (!isNamedRecordPointer(FD->getParamDecl(0)->getType(), IovecType))
      return std::nullopt;
    unsigned BufferArgument = QEMUIovec ? 2 : 3;
    unsigned LengthArgument = QEMUIovec ? 3 : 4;
    if (!isVoidPointer(FD->getParamDecl(BufferArgument)->getType()) ||
        !isInteger(FD->getParamDecl(1)->getType()) ||
        !isInteger(FD->getParamDecl(LengthArgument)->getType()) ||
        (!QEMUIovec && !isInteger(FD->getParamDecl(2)->getType())))
      return std::nullopt;
    if (FD->getReturnType().getCanonicalType() !=
        FD->getParamDecl(LengthArgument)->getType().getCanonicalType())
      return std::nullopt;
    return IovecCopy{0, BufferArgument, LengthArgument, ToBuffer};
  }

  struct IovecAlias {
    enum class SourceExtentKind { None, NonEmpty, BytesAfterOffset, Range };

    unsigned DestinationArgument;
    unsigned SourceArgument;
    bool RequiresPositiveReturn;
    bool ReplacesDestination;
    std::optional<unsigned> RequiredPositiveArgument;
    SourceExtentKind SourceExtent = SourceExtentKind::None;
    std::optional<unsigned> SourceOffsetArgument;
    std::optional<unsigned> SourceLengthArgument;
  };

  static std::optional<IovecAlias> iovecAlias(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() || FD->isVariadic())
      return std::nullopt;
    StringRef Name = FD->getName();
    unsigned ExpectedArguments;
    StringRef DestinationType;
    StringRef SourceType;
    unsigned SourceArgument;
    if (Name == "iov_copy") {
      ExpectedArguments = 6;
      DestinationType = "iovec";
      SourceType = "iovec";
      SourceArgument = 2;
    } else if (Name == "qemu_iovec_init_external") {
      ExpectedArguments = 3;
      DestinationType = "QEMUIOVector";
      SourceType = "iovec";
      SourceArgument = 1;
    } else if (Name == "qemu_iovec_init_slice" || Name == "qemu_iovec_concat") {
      ExpectedArguments = 4;
      DestinationType = "QEMUIOVector";
      SourceType = "QEMUIOVector";
      SourceArgument = 1;
    } else if (Name == "qemu_iovec_concat_iov") {
      ExpectedArguments = 5;
      DestinationType = "QEMUIOVector";
      SourceType = "iovec";
      SourceArgument = 1;
    } else if (Name == "qemu_iovec_clone") {
      ExpectedArguments = 3;
      DestinationType = "QEMUIOVector";
      SourceType = "QEMUIOVector";
      SourceArgument = 1;
    } else {
      return std::nullopt;
    }
    if (FD->getNumParams() != ExpectedArguments ||
        Call.getNumArgs() != ExpectedArguments ||
        !isNamedRecordPointer(FD->getParamDecl(0)->getType(),
                              DestinationType) ||
        !isNamedRecordPointer(FD->getParamDecl(SourceArgument)->getType(),
                              SourceType))
      return std::nullopt;
    bool ReturnsCount = Name == "iov_copy" || Name == "qemu_iovec_concat_iov";
    if ((ReturnsCount && !isInteger(FD->getReturnType())) ||
        (!ReturnsCount && !FD->getReturnType()->isVoidType()))
      return std::nullopt;
    for (unsigned Index = 1; Index != ExpectedArguments; ++Index) {
      if (Index == SourceArgument || (Name == "qemu_iovec_clone" && Index == 2))
        continue;
      if (!isInteger(FD->getParamDecl(Index)->getType()))
        return std::nullopt;
    }
    if (Name == "qemu_iovec_clone" &&
        !isVoidPointer(FD->getParamDecl(2)->getType()))
      return std::nullopt;
    std::optional<unsigned> RequiredPositiveArgument;
    if (Name == "iov_copy")
      RequiredPositiveArgument = 5;
    else if (Name == "qemu_iovec_init_external")
      RequiredPositiveArgument = 2;
    else if (Name == "qemu_iovec_init_slice" || Name == "qemu_iovec_concat")
      RequiredPositiveArgument = 3;
    IovecAlias::SourceExtentKind SourceExtent =
        IovecAlias::SourceExtentKind::None;
    std::optional<unsigned> SourceOffsetArgument;
    std::optional<unsigned> SourceLengthArgument;
    if (Name == "qemu_iovec_init_slice") {
      SourceExtent = IovecAlias::SourceExtentKind::Range;
      SourceOffsetArgument = 2;
      SourceLengthArgument = 3;
    } else if (Name == "qemu_iovec_concat") {
      SourceExtent = IovecAlias::SourceExtentKind::BytesAfterOffset;
      SourceOffsetArgument = 2;
    } else if (Name == "qemu_iovec_clone") {
      SourceExtent = IovecAlias::SourceExtentKind::NonEmpty;
    }
    return IovecAlias{0,
                      SourceArgument,
                      Name == "iov_copy" || Name == "qemu_iovec_concat_iov",
                      Name == "qemu_iovec_init_external" ||
                          Name == "qemu_iovec_init_slice",
                      RequiredPositiveArgument,
                      SourceExtent,
                      SourceOffsetArgument,
                      SourceLengthArgument};
  }

  static std::optional<BufferSource> bufferSource(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier())
      return std::nullopt;
    StringRef Name = FD->getName();
    if (Name == "address_space_read_full" && Call.getNumArgs() >= 5)
      return BufferSource{3, InputClass::DMA, BufferSource::ReturnZero};
    if (Name == "pci_dma_read" && Call.getNumArgs() >= 4)
      return BufferSource{2, InputClass::DMA, BufferSource::ReturnZero};
    if (Name == "physical_memory_read" && Call.getNumArgs() >= 3)
      return BufferSource{1, InputClass::DMA, BufferSource::Always};
    if (Name == "qemu_get_buffer" && Call.getNumArgs() >= 3)
      return BufferSource{1, InputClass::Migration,
                          BufferSource::ReturnEqualsArgument, 2};
    if (isMigrationPointerSource(Name) && Call.getNumArgs() >= 2)
      return BufferSource{1, InputClass::Migration, BufferSource::Always};
    if ((isDirectBlockRead(FD, "bdrv_pread") ||
         isDirectBlockRead(FD, "bdrv_co_pread") ||
         isDirectBlockRead(FD, "blk_pread")) &&
        Call.getNumArgs() == 5)
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

  static StringRef witnessProvenanceClass(InputClass Source) {
    switch (Source) {
    case InputClass::MMIO:
      return "mmio";
    case InputClass::PIO:
      return "pio";
    case InputClass::DMA:
      return "dma";
    case InputClass::Migration:
      return "migration";
    case InputClass::Network:
      return "network";
    case InputClass::DiskImage:
      return "disk-image";
    case InputClass::Virtio:
      return "virtio-config";
    case InputClass::Virtqueue:
      return "virtqueue";
    case InputClass::USB:
      return "usb";
    case InputClass::PCIConfig:
    case InputClass::DeviceRequest:
    case InputClass::Mixed:
      return "unknown";
    }
    llvm_unreachable("unknown QEMU input class");
  }

  static StringRef witnessReproducerKind(InputClass Source) {
    switch (Source) {
    case InputClass::Migration:
      return "migration";
    case InputClass::Network:
      return "packet";
    case InputClass::DMA:
    case InputClass::DiskImage:
    case InputClass::Virtio:
    case InputClass::Virtqueue:
    case InputClass::DeviceRequest:
      return "descriptor";
    case InputClass::USB:
      return "qtest";
    case InputClass::MMIO:
    case InputClass::PIO:
    case InputClass::PCIConfig:
    case InputClass::Mixed:
      return "qtest";
    }
    llvm_unreachable("unknown QEMU input class");
  }

  struct ArrayAccessSink {
    StringRef Direction;
    const Expr *Expression;
  };

  static std::optional<ArrayAccessSink>
  arrayAccessSink(const ArraySubscriptExpr *Subscript, ASTContext &Context) {
    DynTypedNode Child = DynTypedNode::create(*Subscript);
    const Expr *Expression = Subscript;
    for (unsigned Depth = 0; Depth < 8; ++Depth) {
      auto Parents = Context.getParents(Child);
      if (Parents.size() != 1)
        return std::nullopt;
      DynTypedNode Parent = Parents[0];
      if (const auto *Cast = Parent.get<ImplicitCastExpr>()) {
        if (Cast->getCastKind() == CK_LValueToRValue)
          return ArrayAccessSink{"host-read", Expression};
        Expression = Cast;
        Child = Parent;
        continue;
      }
      if (const auto *Paren = Parent.get<ParenExpr>()) {
        Expression = Paren;
        Child = Parent;
        continue;
      }
      if (const auto *Member = Parent.get<MemberExpr>()) {
        if (Member->getBase()->IgnoreParenImpCasts() !=
            Expression->IgnoreParenImpCasts())
          return std::nullopt;
        Expression = Member;
        Child = Parent;
        continue;
      }
      if (const auto *Assignment = Parent.get<BinaryOperator>())
        if (Assignment->isAssignmentOp() &&
            Assignment->getLHS()->IgnoreParenImpCasts() ==
                Expression->IgnoreParenImpCasts())
          return ArrayAccessSink{"host-write", Expression};
      if (const auto *Unary = Parent.get<UnaryOperator>())
        if (Unary->isIncrementDecrementOp() &&
            Unary->getSubExpr()->IgnoreParenImpCasts() ==
                Expression->IgnoreParenImpCasts())
          return ArrayAccessSink{"host-write", Expression};
      return std::nullopt;
    }
    return std::nullopt;
  }

  static std::optional<std::string>
  singletonValue(ProgramStateRef State, SVal Value, SValBuilder &SVB) {
    const llvm::APSInt *Minimum = SVB.getMinValue(State, Value);
    const llvm::APSInt *Maximum = SVB.getMaxValue(State, Value);
    if (!Minimum || !Maximum || *Minimum != *Maximum)
      return std::nullopt;
    llvm::SmallString<64> Buffer;
    llvm::raw_svector_ostream OS(Buffer);
    OS << *Minimum;
    return std::string(OS.str());
  }

  static bool witnessStringValid(StringRef Value, size_t MaximumLength = 4096) {
    if (Value.empty() || Value.size() > MaximumLength)
      return false;
    return llvm::none_of(Value, [](char Character) {
      return static_cast<unsigned char>(Character) < 0x20;
    });
  }

  std::optional<std::string>
  qemuRelativePath(const PathSensitiveBugReport &Report,
                   const SourceManager &SM) const {
    if (QEMUSourceRoot.empty())
      return std::nullopt;
    PresumedLoc Presumed = SM.getPresumedLoc(Report.getLocation().asLocation());
    if (Presumed.isInvalid())
      return std::nullopt;
    StringRef Filename = Presumed.getFilename();
    StringRef Root = QEMUSourceRoot;
    while (Root.ends_with("/"))
      Root = Root.drop_back();
    if (Root.empty() || !Filename.consume_front(Root) ||
        !Filename.consume_front("/") || Filename.empty() ||
        Filename.starts_with("/") || Filename.contains('\\'))
      return std::nullopt;
    SmallVector<StringRef, 16> Components;
    Filename.split(Components, '/', -1, true);
    for (StringRef Component : Components)
      if (Component.empty() || Component == "." || Component == "..")
        return std::nullopt;
    if (!witnessStringValid(Filename))
      return std::nullopt;
    return Filename.str();
  }

  static std::string witnessExpression(const Expr *Expression,
                                       ASTContext &Context) {
    if (!Expression)
      return {};
    std::string Text;
    llvm::raw_string_ostream OS(Text);
    Expression->printPretty(OS, nullptr, Context.getPrintingPolicy());
    OS.flush();
    for (char &Character : Text)
      if (static_cast<unsigned char>(Character) < 0x20)
        Character = ' ';
    return Text;
  }

  struct WitnessCallbackContext {
    std::string Callback;
    std::optional<std::string> Registration;
  };

  std::optional<WitnessCallbackContext>
  callbackContext(const ExplodedNode *Node) const {
    const FunctionDecl *Fallback = nullptr;
    for (const StackFrame &Frame : Node->stackframes()) {
      const auto *FD = dyn_cast<FunctionDecl>(Frame.getDecl());
      if (!FD)
        continue;
      if (!Fallback)
        Fallback = FD;
      FD = FD->getCanonicalDecl();
      if (Callbacks.contains(FD)) {
        auto Registration = CallbackRegistrations.find(FD);
        return WitnessCallbackContext{
            FD->getQualifiedNameAsString(),
            Registration == CallbackRegistrations.end()
                ? std::nullopt
                : std::optional<std::string>(Registration->second)};
      }
    }
    if (Fallback) {
      Fallback = Fallback->getCanonicalDecl();
      auto Registration = CallbackRegistrations.find(Fallback);
      return WitnessCallbackContext{
          Fallback->getQualifiedNameAsString(),
          Registration == CallbackRegistrations.end()
              ? std::nullopt
              : std::optional<std::string>(Registration->second)};
    }
    return std::nullopt;
  }

  void addStructuredWitness(
      PathSensitiveBugReport &Report, CheckerContext &C, ProgramStateRef State,
      StringRef Message, qemu::facts::RuleIDRef RuleID,
      std::optional<InputClass> Source, StringRef SourceDetail,
      StringRef Constraint, SVal ConcreteValue, StringRef SinkDirection,
      StringRef AddressOrOffset, StringRef AccessSize, StringRef ObjectExtent,
      StringRef MissingRelationship, SourceLocation DiagnosticLocation = {},
      StringRef BoundaryLabel = "extent",
      StringRef BoundaryValue = "object extent") const {
    if (!EmitStructuredWitness)
      return;
    std::optional<std::string> QEMUPath =
        qemuRelativePath(Report, C.getSourceManager());
    std::optional<WitnessCallbackContext> Callback =
        callbackContext(Report.getErrorNode());
    if (!QEMUPath || !Callback)
      return;

    const SourceManager &SM = C.getSourceManager();
    SourceLocation RawReportLocation = Report.getLocation().asLocation();
    SourceLocation ReportLocation = SM.getFileLoc(RawReportLocation);
    if (RawReportLocation.isMacroID()) {
      // Match Clang's diagnostic location rule: macro arguments use their
      // spelling location while macro-body tokens use the expansion site.
      DiagnosticLocation = ReportLocation;
    } else if (DiagnosticLocation.isInvalid() ||
               !DiagnosticLocation.isFileID()) {
      DiagnosticLocation = ReportLocation;
    } else {
      PresumedLoc ReportPresumed = SM.getPresumedLoc(ReportLocation);
      PresumedLoc AlternativePresumed = SM.getPresumedLoc(DiagnosticLocation);
      // Path diagnostics normally use ReportLocation.  A multiline enclosing
      // expression can instead be rendered at the accessed subexpression; use
      // that location only when it identifies a different source line.  This
      // preserves operator locations for same-line stores.
      if (ReportPresumed.isInvalid() || AlternativePresumed.isInvalid() ||
          StringRef(ReportPresumed.getFilename()) !=
              AlternativePresumed.getFilename() ||
          ReportPresumed.getLine() == AlternativePresumed.getLine())
        DiagnosticLocation = ReportLocation;
    }
    PresumedLoc Presumed = SM.getPresumedLoc(DiagnosticLocation);
    if (Presumed.isInvalid())
      return;
    InputClass EffectiveSource = Source.value_or(InputClass::Mixed);
    StringRef Provenance = witnessProvenanceClass(EffectiveSource);
    StringRef Reproducer = witnessReproducerKind(EffectiveSource);
    std::string ProvenanceSource = SourceDetail.empty()
                                       ? inputClassName(EffectiveSource).str()
                                       : SourceDetail.str();
    std::optional<std::string> Concrete =
        singletonValue(State, ConcreteValue, C.getSValBuilder());
    bool IsParser = EffectiveSource == InputClass::DiskImage ||
                    EffectiveSource == InputClass::DeviceRequest;
    if (!witnessStringValid(Message, 8192) ||
        !witnessStringValid(Callback->Callback) ||
        (Callback->Registration &&
         !witnessStringValid(*Callback->Registration)) ||
        !witnessStringValid(stableID(RuleID)) ||
        !witnessStringValid(stableID(GuestMemorySafetyModelID)) ||
        !witnessStringValid(ProvenanceSource) ||
        !witnessStringValid(Constraint) ||
        (Concrete && !witnessStringValid(*Concrete)) ||
        !witnessStringValid(AddressOrOffset) ||
        !witnessStringValid(AccessSize) || !witnessStringValid(ObjectExtent) ||
        !witnessStringValid(MissingRelationship) ||
        !witnessStringValid(BoundaryLabel) ||
        !witnessStringValid(BoundaryValue))
      return;

    llvm::SmallString<2048> JSONBuffer;
    llvm::raw_svector_ostream JSONStream(JSONBuffer);
    llvm::json::OStream JSON(JSONStream, 0);
    JSON.object([&] {
      JSON.attributeArray("boundary_values", [&] {
        auto EmitBoundary = [&](StringRef Label, StringRef Value) {
          JSON.object([&] {
            JSON.attribute("label", Label);
            JSON.attribute("value", Value);
          });
        };
        EmitBoundary(BoundaryLabel.str() + "-minus-one",
                     BoundaryValue.str() + " - 1");
        EmitBoundary(BoundaryLabel, BoundaryValue);
        EmitBoundary(BoundaryLabel.str() + "-plus-one",
                     BoundaryValue.str() + " + 1");
      });
      JSON.attributeBegin("concrete_value");
      if (Concrete)
        JSON.value(*Concrete);
      else
        JSON.value(nullptr);
      JSON.attributeEnd();
      JSON.attributeArray("constraints", [&] { JSON.value(Constraint); });
      JSON.attributeObject("context", [&] {
        JSON.attribute("callback", Callback->Callback);
        JSON.attributeBegin("parser");
        if (IsParser)
          JSON.value(Callback->Callback);
        else
          JSON.value(nullptr);
        JSON.attributeEnd();
        JSON.attribute("qom_type", nullptr);
        JSON.attributeBegin("registration");
        if (Callback->Registration)
          JSON.value(*Callback->Registration);
        else
          JSON.value(nullptr);
        JSON.attributeEnd();
      });
      JSON.attributeObject("diagnostic", [&] {
        JSON.attribute("checker", "alpha.qemu.GuestMemorySafety");
        JSON.attribute("column", int64_t(Presumed.getColumn()));
        JSON.attribute("line", int64_t(Presumed.getLine()));
        JSON.attribute("message", Message);
        JSON.attribute("qemu_path", *QEMUPath);
      });
      JSON.attributeObject("identity", [&] {
        JSON.attribute("catalog_format",
                       int64_t(qemu_contracts_generated::CatalogFormat));
        JSON.attribute("catalog_model_version",
                       qemu_contracts_generated::ModelVersion);
        JSON.attribute("catalog_sha256",
                       qemu_contracts_generated::CatalogSHA256);
        JSON.attribute("model_version", stableID(GuestMemorySafetyModelID));
        JSON.attribute("rule_id", stableID(RuleID));
      });
      JSON.attribute("kind", "qemu-gms-witness");
      JSON.attributeObject("provenance", [&] {
        JSON.attribute("class", Provenance);
        JSON.attribute("source", ProvenanceSource);
      });
      JSON.attributeObject("reproducer", [&] {
        JSON.attribute("device", nullptr);
        JSON.attribute("interface", Provenance);
        JSON.attribute("kind", Reproducer);
        JSON.attribute("machine", nullptr);
      });
      JSON.attribute("schema_version", 2);
      JSON.attributeObject("sink", [&] {
        JSON.attribute("access_size", AccessSize);
        JSON.attribute("address_or_offset", AddressOrOffset);
        JSON.attribute("direction", SinkDirection);
        JSON.attribute("object_extent", ObjectExtent);
      });
      JSON.attributeObject("validation", [&] {
        JSON.attribute("missing_relationship", MissingRelationship);
        JSON.attribute("status", "unproven");
      });
    });
    JSON.flush();
    std::string Marker =
        "QEMU_GMS_WITNESS_V2=" + llvm::encodeBase64(JSONBuffer.str());
    Report.addNote(Marker, Report.getLocation());
  }

  void addStructuredWitnessNotApplicable(PathSensitiveBugReport &Report,
                                         CheckerContext &C, StringRef Message,
                                         qemu::facts::RuleIDRef RuleID,
                                         StringRef Reason) const {
    if (!EmitStructuredWitness)
      return;
    std::optional<std::string> QEMUPath =
        qemuRelativePath(Report, C.getSourceManager());
    if (!QEMUPath)
      return;
    PresumedLoc Presumed =
        C.getSourceManager().getPresumedLoc(Report.getLocation().asLocation());
    if (Presumed.isInvalid() || !witnessStringValid(Message, 8192) ||
        !witnessStringValid(stableID(RuleID)) ||
        !witnessStringValid(stableID(GuestMemorySafetyModelID)) ||
        !witnessStringValid(Reason))
      return;

    llvm::SmallString<1024> JSONBuffer;
    llvm::raw_svector_ostream JSONStream(JSONBuffer);
    llvm::json::OStream JSON(JSONStream, 0);
    JSON.object([&] {
      JSON.attributeObject("diagnostic", [&] {
        JSON.attribute("checker", "alpha.qemu.GuestMemorySafety");
        JSON.attribute("column", int64_t(Presumed.getColumn()));
        JSON.attribute("line", int64_t(Presumed.getLine()));
        JSON.attribute("message", Message);
        JSON.attribute("qemu_path", *QEMUPath);
      });
      JSON.attributeObject("identity", [&] {
        JSON.attribute("catalog_format",
                       int64_t(qemu_contracts_generated::CatalogFormat));
        JSON.attribute("catalog_model_version",
                       qemu_contracts_generated::ModelVersion);
        JSON.attribute("catalog_sha256",
                       qemu_contracts_generated::CatalogSHA256);
        JSON.attribute("model_version", stableID(GuestMemorySafetyModelID));
        JSON.attribute("rule_id", stableID(RuleID));
      });
      JSON.attribute("kind", "qemu-gms-witness-not-applicable");
      JSON.attribute("reason", Reason);
      JSON.attribute("schema_version", 2);
    });
    JSON.flush();
    std::string Marker =
        "QEMU_GMS_WITNESS_NA_V2=" + llvm::encodeBase64(JSONBuffer.str());
    Report.addNote(Marker, Report.getLocation());
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

  BugType &directDMAContractBugType() const {
    if (!DirectDMAContractBug)
      DirectDMAContractBug = std::make_unique<BugType>(
          this, "Direct DMA map/unmap contract violation",
          "QEMU guest memory safety");
    return *DirectDMAContractBug;
  }

  bool reportDirectDMAContract(CheckerContext &C, ProgramStateRef State,
                               const Expr *Where, StringRef Message,
                               SVal First = UnknownVal(),
                               SVal Second = UnknownVal()) const {
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return false;
    auto Report = std::make_unique<PathSensitiveBugReport>(
        directDMAContractBugType(), Message, Node);
    if (Where)
      Report->addRange(Where->getSourceRange());
    for (SVal Value : {First, Second})
      for (SymbolRef Symbol : Value.symbols())
        Report->markInteresting(Symbol);
    addStructuredWitnessNotApplicable(
        *Report, C, Message, DirectDMAContractRuleID, "dma-map-unmap-contract");
    C.emitReport(std::move(Report));
    return true;
  }

  BugType &dmaTransferResultBugType() const {
    if (!DMATransferResultBug)
      DMATransferResultBug = std::make_unique<BugType>(
          this, "Ignored DMA transfer failure", "QEMU DMA transfer results");
    return *DMATransferResultBug;
  }

  BugType &failedCompletionPublicationBugType() const {
    if (!FailedCompletionPublicationBug)
      FailedCompletionPublicationBug = std::make_unique<BugType>(
          this, "Failed DMA transfer published as complete",
          "QEMU completion publication");
    return *FailedCompletionPublicationBug;
  }

  BugType &directDMALifetimeBugType() const {
    if (!DirectDMALifetimeBug)
      DirectDMALifetimeBug = std::make_unique<BugType>(
          this, "Direct DMA mapping lifetime violation",
          "QEMU guest memory safety");
    return *DirectDMALifetimeBug;
  }

  bool reportDirectDMAUseAfterUnmap(
      CheckerContext &C, ProgramStateRef State, SVal Location,
      const Expr *Where, StringRef Direction, SVal AccessSize, SVal PriorExtent,
      const Expr *UnmapOrigin, SourceLocation DiagnosticLocation = {}) const {
    ExplodedNode *Node = C.generateErrorNode(State);
    if (!Node)
      return false;

    StringRef Message =
        "direct DMA mapped buffer is accessed after it was unmapped";
    auto Report = std::make_unique<PathSensitiveBugReport>(
        directDMALifetimeBugType(), Message, Node);
    if (Where)
      Report->addRange(Where->getSourceRange());
    if (UnmapOrigin)
      Report->addNote("DMA mapping unmapped here",
                      {UnmapOrigin, C.getSourceManager(), C.getStackFrame()});
    for (SymbolRef Symbol : Location.symbols())
      Report->markInteresting(Symbol);
    for (SymbolRef Symbol : AccessSize.symbols())
      Report->markInteresting(Symbol);

    std::string Address = "effective address '" +
                          witnessExpression(Where, C.getASTContext()) + "'";
    addStructuredWitness(
        *Report, C, State, Message, DirectDMALifetimeRuleID, InputClass::DMA,
        "direct DMA mapping returned by map API",
        "nonzero memory access occurs after direct DMA unmap", AccessSize,
        Direction, Address,
        "bytes " + valueRange(State, AccessSize, C.getSValBuilder()),
        "bytes " + valueRange(State, PriorExtent, C.getSValBuilder()),
        "memory access must precede direct DMA unmap", DiagnosticLocation);
    C.emitReport(std::move(Report));
    return true;
  }

  struct MemoryAccessWitness {
    StringRef Direction;
    std::string Address;
    SVal AccessSize;
    std::optional<SVal> ByteOffset = std::nullopt;
    std::string Base = {};
    std::string Source = {};
    std::optional<InputClass> Input = std::nullopt;
    SourceLocation DiagnosticLocation = {};
  };

  static std::optional<MemoryAccessWitness>
  arrayAccessWitness(const ArraySubscriptExpr *Subscript, CheckerContext &C) {
    std::optional<ArrayAccessSink> Sink =
        arrayAccessSink(Subscript, C.getASTContext());
    // An address-only or unresolved use still gets its human bounds report,
    // but does not establish a memory access for the witness contract.
    if (!Sink)
      return std::nullopt;
    // A bit-field has no addressable C object whose byte width is its declared
    // integer type size.  Do not turn the type's sizeof-like width into a
    // fabricated memory-access width; retain the bounds diagnostic with an
    // explicit unsupported-geometry outcome instead.
    if (Sink->Expression->refersToBitField())
      return std::nullopt;
    QualType AccessType = Sink->Expression->getType();
    if (AccessType->isIncompleteType() ||
        AccessType->isVariablyModifiedType() || AccessType->isDependentType())
      return std::nullopt;
    uint64_t AccessBytes =
        C.getASTContext().getTypeSizeInChars(AccessType).getQuantity();
    if (!AccessBytes)
      return std::nullopt;
    return MemoryAccessWitness{
        Sink->Direction, witnessExpression(Sink->Expression, C.getASTContext()),
        C.getSValBuilder().makeIntVal(AccessBytes,
                                      C.getASTContext().getSizeType())};
  }

  static bool isAddressComputationOnly(const ArraySubscriptExpr *Subscript,
                                       ASTContext &Context) {
    DynTypedNode Child = DynTypedNode::create(*Subscript);
    for (unsigned Depth = 0; Depth < 8; ++Depth) {
      auto Parents = Context.getParents(Child);
      if (Parents.size() != 1)
        return false;
      DynTypedNode Parent = Parents[0];
      if (Parent.get<ParenExpr>()) {
        Child = Parent;
        continue;
      }
      if (Parent.get<ImplicitCastExpr>()) {
        Child = Parent;
        continue;
      }
      if (const auto *Outer = Parent.get<ArraySubscriptExpr>())
        return Outer->getBase()->IgnoreParenImpCasts() == Subscript;
      const auto *Unary = Parent.get<UnaryOperator>();
      return Unary && Unary->getOpcode() == UO_AddrOf &&
             Unary->getSubExpr()->IgnoreParenImpCasts() == Subscript;
    }
    return false;
  }

  void report(CheckerContext &C, ProgramStateRef Safe, ProgramStateRef Unsafe,
              SVal TaintedValue, const Expr *Where, StringRef Sink,
              SVal ExtentOrCount, BoundUnit Unit, StringRef SourceDetail = {},
              std::optional<MemoryAccessWitness> Witness = std::nullopt,
              StringRef WitnessNotApplicableReason = {}) const {
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
    StringRef BoundDescription;
    StringRef Units;
    switch (Unit) {
    case BoundUnit::Bytes:
      BoundDescription = "extent";
      Units = "bytes ";
      break;
    case BoundUnit::Elements:
      BoundDescription = "element count";
      Units = "elements ";
      break;
    case BoundUnit::Bits:
      BoundDescription = "bit capacity";
      Units = "bits ";
      break;
    }
    Message << (Definite ? "Level A: guest-controlled "
                         : "Level B: guest-controlled ")
            << Sink << (Definite ? " exceeds " : " may exceed ")
            << "the host object " << BoundDescription << " (value "
            << valueRange(Unsafe, TaintedValue, C.getSValBuilder()) << ", "
            << Units << valueRange(Unsafe, ExtentOrCount, C.getSValBuilder());
    if (!SourceDetail.empty())
      Message << ", source " << SourceDetail;
    Message << ')';

    auto Report = std::make_unique<PathSensitiveBugReport>(bugType(Definite),
                                                           Message.str(), Node);
    if (Where)
      Report->addRange(Where->getSourceRange());
    for (SymbolRef Sym : taint::getTaintedSymbols(Unsafe, TaintedValue))
      Report->markInteresting(Sym);
    if (Witness && (Witness->Direction == "host-read" ||
                    Witness->Direction == "host-write")) {
      // AccessSize is the actual transfer width in target C bytes.  The
      // compared index or offset-plus-length is only the bound predicate.
      std::string AccessSize =
          "bytes " +
          valueRange(Unsafe, Witness->AccessSize, C.getSValBuilder());
      std::string ObjectExtent =
          Units.str() + valueRange(Unsafe, ExtentOrCount, C.getSValBuilder());
      std::string Constraint = Sink.str() +
                               (Unit == BoundUnit::Bytes ? " > " : " >= ") +
                               "host object " + BoundDescription.str();
      std::string MissingRelationship =
          Sink.str() + (Unit == BoundUnit::Bytes ? " <= " : " < ") +
          "host object " + BoundDescription.str();
      std::string Expression = witnessExpression(Where, C.getASTContext());
      std::optional<InputClass> Source =
          Witness->Input ? Witness->Input
                         : inputClassForValue(Unsafe, TaintedValue);
      std::string WitnessSource =
          SourceDetail.empty()
              ? (Expression.empty()
                     ? inputClassName(Source.value_or(InputClass::Mixed)).str()
                     : "expression '" + Expression + "'")
              : SourceDetail.str();
      if (!Witness->Source.empty())
        WitnessSource = Witness->Source;
      std::string AddressOrOffset = Witness->Address;
      if (Witness->ByteOffset)
        AddressOrOffset +=
            ", byte offset " +
            valueRange(Unsafe, *Witness->ByteOffset, C.getSValBuilder()) +
            " from base '" + Witness->Base + "'";
      addStructuredWitness(*Report, C, Unsafe, Message.str(),
                           GuestMemoryBoundsRuleID, Source, WitnessSource,
                           Constraint, TaintedValue, Witness->Direction,
                           AddressOrOffset, AccessSize, ObjectExtent,
                           MissingRelationship, Witness->DiagnosticLocation);
    } else {
      StringRef Reason = WitnessNotApplicableReason.empty()
                             ? "memory-access-geometry-unresolved"
                             : WitnessNotApplicableReason;
      addStructuredWitnessNotApplicable(*Report, C, Message.str(),
                                        GuestMemoryBoundsRuleID, Reason);
    }
    C.emitReport(std::move(Report));
  }

  bool reportInvalidUSBSetupLength(CheckerContext &C, ProgramStateRef State,
                                   SVal Value, const Expr *Origin,
                                   uint64_t Capacity,
                                   USBSetupLengthViolation Kind,
                                   bool Definite) const {
    ExplodedNode *Node = C.generateErrorNode(State);
    if (!Node)
      return false;

    llvm::SmallString<256> Buffer;
    llvm::raw_svector_ostream Message(Buffer);
    Message << (Definite ? "Level A: guest-controlled "
                         : "Level B: guest-controlled ")
            << "USB setup length state ";
    if (Kind == USBSetupLengthViolation::Negative) {
      Message << (Definite ? "is negative" : "may be negative") << " (value "
              << valueRange(State, Value, C.getSValBuilder()) << ", minimum 0";
    } else {
      Message << (Definite ? "exceeds " : "may exceed ")
              << "the host object extent (value "
              << valueRange(State, Value, C.getSValBuilder()) << ", bytes "
              << Capacity;
    }
    Message << ", source USB setup packet field 'setup_buf')";

    auto Report = std::make_unique<PathSensitiveBugReport>(bugType(Definite),
                                                           Message.str(), Node);
    if (Origin)
      Report->addRange(Origin->getSourceRange());
    for (SymbolRef Symbol : taint::getTaintedSymbols(State, Value))
      Report->markInteresting(Symbol);
    addStructuredWitnessNotApplicable(*Report, C, Message.str(),
                                      USBSetupLengthRuleID,
                                      "usb-state-capacity-contract");
    C.emitReport(std::move(Report));
    return true;
  }

  BugType &usbPacketCopyBoundsBugType() const {
    if (!USBPacketCopyBoundsBug)
      USBPacketCopyBoundsBug = std::make_unique<BugType>(
          this, "Invalid USB packet copy range", "QEMU guest memory safety");
    return *USBPacketCopyBoundsBug;
  }

  bool reportUSBPacketCopyBounds(CheckerContext &C, ProgramStateRef State,
                                 const Expr *Origin, SVal ActualLength,
                                 SVal RequestedLength, SVal Capacity,
                                 qemu::facts::USBPacketBufferKind BufferKind,
                                 USBPacketCopyBoundsViolation Kind) const {
    ExplodedNode *Node = C.generateErrorNode(State);
    if (!Node)
      return false;

    StringRef Buffer = BufferKind == qemu::facts::USBPacketBufferKind::Direct
                           ? "direct"
                           : "combined";
    llvm::SmallString<256> Storage;
    llvm::raw_svector_ostream Message(Storage);
    if (Kind == USBPacketCopyBoundsViolation::NegativeActualLength) {
      Message << "Level A: USB packet actual_length is negative (value "
              << valueRange(State, ActualLength, C.getSValBuilder())
              << ", selected " << Buffer << " iovec capacity "
              << valueRange(State, Capacity, C.getSValBuilder()) << ')';
    } else if (Kind == USBPacketCopyBoundsViolation::
                           ActualLengthUpdateNotRepresentable) {
      QualType ActualType = ActualLength.getType(C.getASTContext());
      llvm::APSInt Maximum =
          C.getSValBuilder().getBasicValueFactory().getMaxValue(ActualType);
      Message << "Level A: USB packet actual_length update exceeds its "
                 "destination type (actual_length "
              << valueRange(State, ActualLength, C.getSValBuilder())
              << ", bytes "
              << valueRange(State, RequestedLength, C.getSValBuilder())
              << ", maximum " << Maximum << ')';
    } else {
      Message << "Level A: USB packet copy range exceeds the selected "
              << Buffer << " iovec capacity (actual_length "
              << valueRange(State, ActualLength, C.getSValBuilder())
              << ", bytes "
              << valueRange(State, RequestedLength, C.getSValBuilder())
              << ", capacity "
              << valueRange(State, Capacity, C.getSValBuilder()) << ')';
    }

    auto Report = std::make_unique<PathSensitiveBugReport>(
        usbPacketCopyBoundsBugType(), Message.str(), Node);
    if (Origin)
      Report->addRange(Origin->getSourceRange());
    for (SVal Value : {ActualLength, RequestedLength, Capacity})
      for (SymbolRef Symbol : Value.symbols())
        Report->markInteresting(Symbol);
    // The current packet-copy catalog entry names its initialized-byte rule.
    // Until the catalog supports multiple rule identities per effect, retain
    // this capacity diagnostic under the existing generic bounds rule.  A
    // dedicated packet-copy rule belongs in the next catalog revision.
    addStructuredWitnessNotApplicable(*Report, C, Message.str(),
                                      GuestMemoryBoundsRuleID,
                                      "usb-transaction-capacity-contract");
    C.emitReport(std::move(Report));
    return true;
  }

  struct InitializedBytePosition {
    const MemRegion *Start;
    const MemRegion *Base;
    std::optional<uint64_t> ByteOffset;
  };

  static std::optional<InitializedBytePosition>
  initializedBytePosition(SVal Pointer, ASTContext &Context) {
    const MemRegion *Region = Pointer.getAsRegion();
    if (!Region)
      return std::nullopt;
    Region = Region->StripCasts();
    const MemRegion *Base = Region->getBaseRegion();
    if (!Base)
      return std::nullopt;

    std::optional<uint64_t> ByteOffset;
    RegionOffset Offset = Region->getAsOffset();
    unsigned CharWidth = Context.getCharWidth();
    if (Offset.isValid() && Offset.getRegion() == Base &&
        !Offset.hasSymbolicOffset() && CharWidth && Offset.getOffset() >= 0 &&
        Offset.getOffset() % CharWidth == 0)
      ByteOffset = uint64_t(Offset.getOffset()) / CharWidth;

    // Array-to-pointer decay and &array[0] commonly produce an ElementRegion
    // at offset zero.  Canonicalize that case to the object region so ranges
    // recorded through either spelling meet.
    const MemRegion *Start = ByteOffset && *ByteOffset == 0 ? Base : Region;
    return InitializedBytePosition{Start, Base, ByteOffset};
  }

  static std::optional<SVal>
  initializedByteOffsetValue(const InitializedBytePosition &Position,
                             ProgramStateRef State, CheckerContext &C) {
    QualType SizeType = C.getASTContext().getSizeType();
    if (Position.ByteOffset)
      return C.getSValBuilder().makeIntVal(*Position.ByteOffset, SizeType);

    // Preserve the symbolic index for the common byte-array form
    // buffer[index].  This is needed for code that writes a terminator at a
    // producer-supplied length and then consumes the buffer as a C string.
    const auto *Element = dyn_cast<ElementRegion>(Position.Start);
    if (!Element ||
        Element->getSuperRegion()->getBaseRegion() != Position.Base ||
        Element->getElementType()->isIncompleteType() ||
        C.getASTContext()
                .getTypeSizeInChars(Element->getElementType())
                .getQuantity() != 1)
      return std::nullopt;
    QualType IndexType = Element->getIndex().getType(C.getASTContext());
    if (IndexType.isNull() || !IndexType->isIntegerType())
      return std::nullopt;
    if (IndexType->isSignedIntegerOrEnumerationType()) {
      SVal Zero = C.getSValBuilder().makeZeroVal(IndexType);
      if (!isDefinitelyTrue(State, Element->getIndex(), BO_GE, Zero,
                            C.getSValBuilder()))
        return std::nullopt;
    }
    SVal Offset =
        C.getSValBuilder().evalCast(Element->getIndex(), SizeType, IndexType);
    if (Offset.isUnknownOrUndef())
      return std::nullopt;
    return Offset;
  }

  static std::optional<uint64_t>
  staticallyInitializedExtent(const Expr *Expression, ASTContext &Context) {
    if (!Expression)
      return std::nullopt;
    const Expr *E = Expression->IgnoreParenImpCasts();
    while (true) {
      if (const auto *Address = dyn_cast<UnaryOperator>(E)) {
        if (Address->getOpcode() == UO_AddrOf) {
          E = Address->getSubExpr()->IgnoreParenImpCasts();
          continue;
        }
      }
      if (const auto *Subscript = dyn_cast<ArraySubscriptExpr>(E)) {
        E = Subscript->getBase()->IgnoreParenImpCasts();
        continue;
      }
      break;
    }

    QualType Type;
    if (const auto *Literal = dyn_cast<StringLiteral>(E))
      Type = Literal->getType();
    else if (const auto *Reference = dyn_cast<DeclRefExpr>(E)) {
      const auto *Variable = dyn_cast<VarDecl>(Reference->getDecl());
      if (!Variable || !Variable->hasGlobalStorage() || !Variable->hasInit())
        return std::nullopt;
      Type = Variable->getType();
    } else {
      return std::nullopt;
    }

    const ConstantArrayType *Array = Context.getAsConstantArrayType(Type);
    if (!Array || Array->getSize().getActiveBits() > 64 ||
        Array->getElementType()->isIncompleteType())
      return std::nullopt;
    uint64_t Elements = Array->getSize().getZExtValue();
    uint64_t ElementBytes =
        Context.getTypeSizeInChars(Array->getElementType()).getQuantity();
    if (!ElementBytes ||
        Elements > std::numeric_limits<uint64_t>::max() / ElementBytes)
      return std::nullopt;
    return Elements * ElementBytes;
  }

  static ProgramStateRef clearInitializedByteObject(ProgramStateRef State,
                                                    const MemRegion *Base) {
    if (!Base)
      return State;
    Base = Base->getBaseRegion();
    auto Ranges = State->get<QEMUInitializedByteRangeLengths>();
    for (const auto &Entry : Ranges) {
      if (Entry.first->getBaseRegion() != Base)
        continue;
      State = State->remove<QEMUInitializedByteRangeLengths>(Entry.first)
                  ->remove<QEMUInitializedByteRangeOrigins>(Entry.first)
                  ->remove<QEMUInitializedByteRangeKinds>(Entry.first)
                  ->remove<QEMUInitializedByteRangeClasses>(Entry.first);
    }
    return State->remove<QEMUInitializedByteObjectExtents>(Base)
        ->remove<QEMUInitializedByteObjectPrecisions>(Base)
        ->remove<QEMUKnownNULTerminatorOffsets>(Base)
        ->remove<QEMUPendingInitializedBytePreciseBinds>(Base);
  }

  static ProgramStateRef abandonInitializedByteObject(ProgramStateRef State,
                                                      const MemRegion *Base) {
    if (!Base)
      return State;
    Base = Base->getBaseRegion();
    auto Ranges = State->get<QEMUInitializedByteRangeLengths>();
    for (const auto &Entry : Ranges) {
      if (Entry.first->getBaseRegion() != Base)
        continue;
      State = State->remove<QEMUInitializedByteRangeLengths>(Entry.first)
                  ->remove<QEMUInitializedByteRangeOrigins>(Entry.first)
                  ->remove<QEMUInitializedByteRangeKinds>(Entry.first)
                  ->remove<QEMUInitializedByteRangeClasses>(Entry.first);
    }
    State = State->remove<QEMUPendingInitializedBytePreciseBinds>(Base);
    if (!State->get<QEMUInitializedByteObjectExtents>(Base))
      return State;
    return State
        ->set<QEMUInitializedByteObjectPrecisions>(
            Base, static_cast<unsigned>(InitializedBytePrecision::Abandoned))
        ->remove<QEMUKnownNULTerminatorOffsets>(Base);
  }

  static bool initializedByteObjectIsExact(ProgramStateRef State,
                                           const MemRegion *Base) {
    if (!Base || !State->get<QEMUInitializedByteObjectExtents>(Base))
      return false;
    const unsigned *Precision =
        State->get<QEMUInitializedByteObjectPrecisions>(Base->getBaseRegion());
    return Precision &&
           *Precision == static_cast<unsigned>(InitializedBytePrecision::Exact);
  }

  static ProgramStateRef
  restoreInitializedByteObjectExact(ProgramStateRef State,
                                    const MemRegion *Base) {
    if (!Base)
      return State;
    Base = Base->getBaseRegion();
    if (!State->get<QEMUInitializedByteObjectExtents>(Base))
      return State;
    State = abandonInitializedByteObject(State, Base);
    return State->set<QEMUInitializedByteObjectPrecisions>(
        Base, static_cast<unsigned>(InitializedBytePrecision::Exact));
  }

  static ProgramStateRef recordInitializedByteObject(ProgramStateRef State,
                                                     const MemRegion *Base,
                                                     SVal Extent) {
    if (!Base || Extent.isUnknownOrUndef())
      return State;
    Base = Base->getBaseRegion();
    return State->set<QEMUInitializedByteObjectExtents>(Base, Extent)
        ->set<QEMUInitializedByteObjectPrecisions>(
            Base, static_cast<unsigned>(InitializedBytePrecision::Exact));
  }

  ProgramStateRef recordInitializedByteRange(
      ProgramStateRef State, const InitializedBytePosition &Position,
      SVal Length, InitializedByteKind Kind, const Expr *Origin,
      std::optional<InputClass> Source, CheckerContext &C) const {
    if (Length.isUnknownOrUndef() ||
        !initializedByteObjectIsExact(State, Position.Base))
      return State;

    const llvm::APSInt *NewLength =
        C.getSValBuilder().getKnownValue(State, Length);
    if (NewLength && (NewLength->isNegative() || NewLength->getBitWidth() > 64))
      return abandonInitializedByteObject(State, Position.Base);
    if (NewLength && NewLength->getZExtValue() == 0)
      return State;

    // Symbolic lengths in exact state are unsigned size/count values.  New
    // producers with signed or otherwise unsafe symbolic lengths must first
    // constrain them, or abandon exact tracking, before calling this helper.

    if (const SVal *Existing =
            State->get<QEMUInitializedByteRangeLengths>(Position.Start)) {
      const llvm::APSInt *KnownExisting =
          C.getSValBuilder().getKnownValue(State, *Existing);
      if (KnownExisting &&
          (KnownExisting->isNegative() || KnownExisting->getBitWidth() > 64))
        return abandonInitializedByteObject(State, Position.Base);
      if (isDefinitelyTrue(State, *Existing, BO_GE, Length,
                           C.getSValBuilder())) {
        // Preserve the longer coverage interval, but never retain provenance
        // for bytes that a new write replaced.  Equal-size writes completely
        // replace the metadata; shorter writes leave mixed provenance.
        if (isDefinitelyTrue(State, Length, BO_GE, *Existing,
                             C.getSValBuilder())) {
          State = State->set<QEMUInitializedByteRangeKinds>(
              Position.Start, static_cast<unsigned>(Kind));
          if (Origin)
            State = State->set<QEMUInitializedByteRangeOrigins>(Position.Start,
                                                                Origin);
          else
            State =
                State->remove<QEMUInitializedByteRangeOrigins>(Position.Start);
          if (Source)
            State = State->set<QEMUInitializedByteRangeClasses>(
                Position.Start, static_cast<unsigned>(*Source));
          else
            State =
                State->remove<QEMUInitializedByteRangeClasses>(Position.Start);
        } else {
          State = State
                      ->set<QEMUInitializedByteRangeKinds>(
                          Position.Start,
                          static_cast<unsigned>(InitializedByteKind::Copy))
                      ->remove<QEMUInitializedByteRangeOrigins>(Position.Start)
                      ->remove<QEMUInitializedByteRangeClasses>(Position.Start);
        }
        return State;
      }
      // An exact set cannot silently choose one of two incomparable symbolic
      // lengths stored at the same canonical start.
      if (!isDefinitelyTrue(State, Length, BO_GE, *Existing,
                            C.getSValBuilder()))
        return abandonInitializedByteObject(State, Position.Base);
    }

    InitializedBytePosition Recorded = Position;
    SVal RecordedLength = Length;
    InitializedByteKind RecordedKind = Kind;
    const Expr *RecordedOrigin = Origin;
    std::optional<InputClass> RecordedSource = Source;

    // Canonicalize concrete ranges before enforcing the state-size cap.
    // Adjacent byte stores therefore remain one interval rather than causing
    // an otherwise artificial precision loss.
    std::optional<uint64_t> NewBegin = initializedRangeOffset(
        Position.Start, Position.Base, C.getASTContext());
    if (NewBegin && NewLength &&
        NewLength->getZExtValue() >
            std::numeric_limits<uint64_t>::max() - *NewBegin)
      return abandonInitializedByteObject(State, Position.Base);
    if (NewBegin && NewLength) {
      uint64_t NewEnd = *NewBegin + NewLength->getZExtValue();
      if (NewEnd == *NewBegin)
        return State;
      auto ExistingRanges = State->get<QEMUInitializedByteRangeLengths>();
      for (const auto &Entry : ExistingRanges) {
        if (Entry.first->getBaseRegion() != Position.Base)
          continue;
        std::optional<uint64_t> Begin = initializedRangeOffset(
            Entry.first, Position.Base, C.getASTContext());
        const llvm::APSInt *ExistingLength =
            C.getSValBuilder().getKnownValue(State, Entry.second);
        if (!Begin || !ExistingLength || ExistingLength->isNegative() ||
            ExistingLength->getBitWidth() > 64 ||
            ExistingLength->getZExtValue() >
                std::numeric_limits<uint64_t>::max() - *Begin)
          continue;
        uint64_t End = *Begin + ExistingLength->getZExtValue();
        if (End < *NewBegin || *Begin > NewEnd)
          continue;

        const Expr *ExistingOrigin = nullptr;
        if (const Expr *const *Saved =
                State->get<QEMUInitializedByteRangeOrigins>(Entry.first))
          ExistingOrigin = *Saved;
        if (ExistingOrigin != RecordedOrigin)
          RecordedOrigin = nullptr;
        if (const unsigned *Saved =
                State->get<QEMUInitializedByteRangeKinds>(Entry.first)) {
          if (*Saved != static_cast<unsigned>(RecordedKind))
            RecordedKind = InitializedByteKind::Copy;
        } else {
          RecordedKind = InitializedByteKind::Copy;
        }
        std::optional<InputClass> ExistingSource;
        if (const unsigned *Saved =
                State->get<QEMUInitializedByteRangeClasses>(Entry.first))
          if (*Saved <= static_cast<unsigned>(InputClass::Mixed))
            ExistingSource = static_cast<InputClass>(*Saved);
        if (ExistingSource != RecordedSource)
          RecordedSource = std::nullopt;

        *NewBegin = std::min(*NewBegin, *Begin);
        NewEnd = std::max(NewEnd, End);
        State = removeInitializedByteRange(State, Entry.first);
      }
      const MemRegion *Start =
          initializedRangeStart(Position.Base, *NewBegin, C);
      if (!Start)
        return abandonInitializedByteObject(State, Position.Base);
      Recorded = InitializedBytePosition{Start, Position.Base, *NewBegin};
      RecordedLength = C.getSValBuilder().makeIntVal(
          NewEnd - *NewBegin, C.getASTContext().getSizeType());
    }

    unsigned RangeCount = 0;
    bool ReplacesExisting = false;
    for (const auto &Entry : State->get<QEMUInitializedByteRangeLengths>()) {
      if (Entry.first->getBaseRegion() != Position.Base)
        continue;
      ++RangeCount;
      ReplacesExisting |= Entry.first == Recorded.Start;
    }
    if (!ReplacesExisting && RangeCount >= MaxInitializedRangesPerObject)
      return abandonInitializedByteObject(State, Position.Base);

    State = State
                ->set<QEMUInitializedByteRangeLengths>(Recorded.Start,
                                                       RecordedLength)
                ->set<QEMUInitializedByteRangeKinds>(
                    Recorded.Start, static_cast<unsigned>(RecordedKind));
    if (RecordedOrigin)
      State = State->set<QEMUInitializedByteRangeOrigins>(Recorded.Start,
                                                          RecordedOrigin);
    else
      State = State->remove<QEMUInitializedByteRangeOrigins>(Recorded.Start);
    if (RecordedSource)
      State = State->set<QEMUInitializedByteRangeClasses>(
          Recorded.Start, static_cast<unsigned>(*RecordedSource));
    else
      State = State->remove<QEMUInitializedByteRangeClasses>(Recorded.Start);
    return State;
  }

  static ProgramStateRef removeInitializedByteRange(ProgramStateRef State,
                                                    const MemRegion *Start) {
    return State->remove<QEMUInitializedByteRangeLengths>(Start)
        ->remove<QEMUInitializedByteRangeOrigins>(Start)
        ->remove<QEMUInitializedByteRangeKinds>(Start)
        ->remove<QEMUInitializedByteRangeClasses>(Start);
  }

  static const MemRegion *initializedRangeStart(const MemRegion *Base,
                                                uint64_t ByteOffset,
                                                CheckerContext &C) {
    if (!Base)
      return nullptr;
    Base = Base->getBaseRegion();
    if (!ByteOffset)
      return Base;
    const auto *Super = dyn_cast<SubRegion>(Base);
    if (!Super)
      return nullptr;
    NonLoc Index = C.getSValBuilder().makeArrayIndex(ByteOffset);
    return C.getSValBuilder().getRegionManager().getElementRegion(
        C.getASTContext().UnsignedCharTy, Index, Super, C.getASTContext());
  }

  ProgramStateRef
  overwriteInitializedByteRange(ProgramStateRef State,
                                const InitializedBytePosition &Destination,
                                SVal WriteLength, CheckerContext &C) const {
    if (!initializedByteObjectIsExact(State, Destination.Base))
      return State;
    std::optional<SVal> WriteOffset =
        initializedByteOffsetValue(Destination, State, C);
    const llvm::APSInt *KnownLength =
        C.getSValBuilder().getKnownValue(State, WriteLength);
    if (!WriteOffset || !KnownLength || KnownLength->isNegative() ||
        KnownLength->getBitWidth() > 64)
      return abandonInitializedByteObject(State, Destination.Base);
    uint64_t Length = KnownLength->getZExtValue();
    if (!Length)
      return State;

    if (!Destination.ByteOffset) {
      QualType SizeType = C.getASTContext().getSizeType();
      llvm::APSInt Maximum =
          C.getSValBuilder().getBasicValueFactory().getMaxValue(SizeType);
      if (Maximum.getActiveBits() > 64 || Length > Maximum.getZExtValue())
        return abandonInitializedByteObject(State, Destination.Base);
      SVal MaximumWriteOffset = C.getSValBuilder().makeIntVal(
          Maximum.getZExtValue() - Length, SizeType);
      if (!isDefinitelyTrue(State, *WriteOffset, BO_LE, MaximumWriteOffset,
                            C.getSValBuilder()))
        return abandonInitializedByteObject(State, Destination.Base);
      SVal LengthValue = C.getSValBuilder().makeIntVal(Length, SizeType);
      SVal WriteEnd = C.getSValBuilder().evalBinOp(State, BO_Add, *WriteOffset,
                                                   LengthValue, SizeType);
      if (WriteEnd.isUnknownOrUndef())
        return abandonInitializedByteObject(State, Destination.Base);

      // With a symbolic destination we cannot split an intersected interval.
      // Preserve the model only when every existing interval is provably
      // disjoint; otherwise widen the whole object's initializedness to
      // unknown so a later sink cannot become a false definite report.
      for (const auto &Entry : State->get<QEMUInitializedByteRangeLengths>()) {
        if (Entry.first->getBaseRegion() != Destination.Base)
          continue;
        std::optional<uint64_t> Begin = initializedRangeOffset(
            Entry.first, Destination.Base, C.getASTContext());
        if (!Begin)
          return abandonInitializedByteObject(State, Destination.Base);
        if (*Begin > Maximum.getZExtValue())
          return abandonInitializedByteObject(State, Destination.Base);
        SVal MaximumRangeLength = C.getSValBuilder().makeIntVal(
            Maximum.getZExtValue() - *Begin, SizeType);
        if (!isDefinitelyTrue(State, Entry.second, BO_LE, MaximumRangeLength,
                              C.getSValBuilder()))
          return abandonInitializedByteObject(State, Destination.Base);
        SVal BeginValue = C.getSValBuilder().makeIntVal(*Begin, SizeType);
        SVal End = C.getSValBuilder().evalBinOp(State, BO_Add, BeginValue,
                                                Entry.second, SizeType);
        if (End.isUnknownOrUndef())
          return abandonInitializedByteObject(State, Destination.Base);
        bool ExistingBeforeWrite = isDefinitelyTrue(
            State, End, BO_LE, *WriteOffset, C.getSValBuilder());
        bool WriteBeforeExisting = isDefinitelyTrue(
            State, WriteEnd, BO_LE, BeginValue, C.getSValBuilder());
        if (!ExistingBeforeWrite && !WriteBeforeExisting)
          return abandonInitializedByteObject(State, Destination.Base);
      }
      return State->remove<QEMUKnownNULTerminatorOffsets>(Destination.Base);
    }

    uint64_t WriteBegin = *Destination.ByteOffset;
    if (Length > std::numeric_limits<uint64_t>::max() - WriteBegin)
      return abandonInitializedByteObject(State, Destination.Base);
    uint64_t WriteEnd = WriteBegin + Length;

    auto Ranges = State->get<QEMUInitializedByteRangeLengths>();
    for (const auto &Entry : Ranges) {
      if (Entry.first->getBaseRegion() != Destination.Base)
        continue;
      std::optional<uint64_t> Begin = initializedRangeOffset(
          Entry.first, Destination.Base, C.getASTContext());
      const llvm::APSInt *RangeLength =
          C.getSValBuilder().getKnownValue(State, Entry.second);
      if (!Begin || !RangeLength || RangeLength->isNegative() ||
          RangeLength->getBitWidth() > 64 ||
          RangeLength->getZExtValue() >
              std::numeric_limits<uint64_t>::max() - Begin.value_or(0)) {
        return abandonInitializedByteObject(State, Destination.Base);
      }
      uint64_t End = *Begin + RangeLength->getZExtValue();
      if (End <= WriteBegin || *Begin >= WriteEnd)
        continue;

      const Expr *Origin = nullptr;
      if (const Expr *const *Saved =
              State->get<QEMUInitializedByteRangeOrigins>(Entry.first))
        Origin = *Saved;
      InitializedByteKind Kind = InitializedByteKind::Copy;
      if (const unsigned *Saved =
              State->get<QEMUInitializedByteRangeKinds>(Entry.first))
        Kind = static_cast<InitializedByteKind>(*Saved);
      std::optional<InputClass> Source;
      if (const unsigned *Saved =
              State->get<QEMUInitializedByteRangeClasses>(Entry.first))
        if (*Saved <= static_cast<unsigned>(InputClass::Mixed))
          Source = static_cast<InputClass>(*Saved);
      State = removeInitializedByteRange(State, Entry.first);

      auto Preserve = [&](uint64_t PreservedBegin, uint64_t PreservedEnd) {
        if (PreservedBegin >= PreservedEnd)
          return;
        const MemRegion *Start =
            initializedRangeStart(Destination.Base, PreservedBegin, C);
        if (!Start)
          return;
        SVal PreservedLength = C.getSValBuilder().makeIntVal(
            PreservedEnd - PreservedBegin, C.getASTContext().getSizeType());
        State = recordInitializedByteRange(
            State,
            InitializedBytePosition{Start, Destination.Base, PreservedBegin},
            PreservedLength, Kind, Origin, Source, C);
      };
      Preserve(*Begin, std::min(End, WriteBegin));
      Preserve(std::max(*Begin, WriteEnd), End);
    }

    if (const SVal *Terminator =
            State->get<QEMUKnownNULTerminatorOffsets>(Destination.Base)) {
      const llvm::APSInt *KnownTerminator =
          C.getSValBuilder().getKnownValue(State, *Terminator);
      if (!KnownTerminator || KnownTerminator->isNegative() ||
          KnownTerminator->getBitWidth() > 64 ||
          (KnownTerminator->getZExtValue() >= WriteBegin &&
           KnownTerminator->getZExtValue() < WriteEnd))
        State = State->remove<QEMUKnownNULTerminatorOffsets>(Destination.Base);
    }
    return State;
  }

  static std::optional<uint64_t> initializedRangeOffset(const MemRegion *Range,
                                                        const MemRegion *Base,
                                                        ASTContext &Context) {
    if (!Range || Range->getBaseRegion() != Base)
      return std::nullopt;
    RegionOffset Offset = Range->getAsOffset();
    unsigned CharWidth = Context.getCharWidth();
    if (!Offset.isValid() || Offset.getRegion() != Base ||
        Offset.hasSymbolicOffset() || !CharWidth || Offset.getOffset() < 0 ||
        Offset.getOffset() % CharWidth)
      return std::nullopt;
    return uint64_t(Offset.getOffset()) / CharWidth;
  }

  static InitializedCoverage
  initializedCoverage(ProgramStateRef State,
                      const InitializedBytePosition &Position,
                      CheckerContext &C) {
    auto Unknown = [] {
      return InitializedCoverage{InitializedCoverageKind::Unknown,
                                 UnknownVal()};
    };
    if (!initializedByteObjectIsExact(State, Position.Base))
      return Unknown();

    struct Interval {
      uint64_t Begin;
      uint64_t End;
      const MemRegion *Start;
    };
    llvm::SmallVector<Interval, 8> Intervals;
    unsigned ObjectRanges = 0;
    unsigned UnrepresentableRanges = 0;
    auto Ranges = State->get<QEMUInitializedByteRangeLengths>();
    for (const auto &Entry : Ranges) {
      if (Entry.first->getBaseRegion() != Position.Base)
        continue;
      ++ObjectRanges;
      std::optional<uint64_t> Begin =
          initializedRangeOffset(Entry.first, Position.Base, C.getASTContext());
      const llvm::APSInt *KnownLength =
          C.getSValBuilder().getKnownValue(State, Entry.second);
      if (!Begin || !KnownLength || KnownLength->isNegative() ||
          KnownLength->getBitWidth() > 64) {
        ++UnrepresentableRanges;
        continue;
      }
      uint64_t Length = KnownLength->getZExtValue();
      if (Length > std::numeric_limits<uint64_t>::max() - *Begin) {
        ++UnrepresentableRanges;
        continue;
      }
      Intervals.push_back({*Begin, *Begin + Length, Entry.first});
    }
    std::sort(Intervals.begin(), Intervals.end(),
              [](const Interval &Left, const Interval &Right) {
                return Left.Begin < Right.Begin ||
                       (Left.Begin == Right.Begin && Left.End < Right.End);
              });

    if (Position.ByteOffset) {
      uint64_t Begin = *Position.ByteOffset;
      uint64_t End = Begin;
      const MemRegion *RangeStart = nullptr;
      bool Found = false;
      for (const Interval &Current : Intervals) {
        if (Current.End <= Begin)
          continue;
        if (!Found) {
          if (Current.Begin > Begin)
            break;
          End = std::max(End, Current.End);
          RangeStart = Current.Start;
          Found = true;
          continue;
        }
        if (Current.Begin > End)
          break;
        End = std::max(End, Current.End);
      }
      if (Found) {
        if (UnrepresentableRanges)
          return Unknown();
        return {InitializedCoverageKind::ExactCoverage,
                C.getSValBuilder().makeIntVal(End - Begin,
                                              C.getASTContext().getSizeType()),
                RangeStart};
      }
    }

    // A symbolic-offset access can still be checked when the same symbolic
    // region was the start of the initializing operation.
    if (const SVal *Direct =
            State->get<QEMUInitializedByteRangeLengths>(Position.Start)) {
      if (ObjectRanges != 1) {
        std::optional<SVal> QueryBegin =
            initializedByteOffsetValue(Position, State, C);
        if (!QueryBegin)
          return Unknown();
        QualType SizeType = C.getASTContext().getSizeType();
        SVal DirectEnd = C.getSValBuilder().evalBinOp(
            State, BO_Add, *QueryBegin, *Direct, SizeType);
        if (DirectEnd.isUnknownOrUndef())
          return Unknown();
        for (const auto &Entry : Ranges) {
          if (Entry.first == Position.Start ||
              Entry.first->getBaseRegion() != Position.Base)
            continue;
          std::optional<uint64_t> Begin = initializedRangeOffset(
              Entry.first, Position.Base, C.getASTContext());
          if (!Begin)
            return Unknown();
          SVal BeginValue = C.getSValBuilder().makeIntVal(*Begin, SizeType);
          SVal End = C.getSValBuilder().evalBinOp(State, BO_Add, BeginValue,
                                                  Entry.second, SizeType);
          if (End.isUnknownOrUndef())
            return Unknown();
          bool BeforeQuery = isDefinitelyTrue(State, End, BO_LE, *QueryBegin,
                                              C.getSValBuilder());
          bool AfterGap = isDefinitelyTrue(State, DirectEnd, BO_LT, BeginValue,
                                           C.getSValBuilder());
          if (!BeforeQuery && !AfterGap)
            return Unknown();
        }
      }
      const llvm::APSInt *KnownDirect =
          C.getSValBuilder().getKnownValue(State, *Direct);
      if (KnownDirect &&
          (KnownDirect->isNegative() || KnownDirect->getBitWidth() > 64))
        return Unknown();
      return {InitializedCoverageKind::ExactCoverage, *Direct, Position.Start};
    }

    // For a concrete interior pointer, derive the remaining initialized
    // length from a symbolic range that begins earlier in the same object.
    if (Position.ByteOffset) {
      for (const auto &Entry : Ranges) {
        std::optional<uint64_t> RangeBegin = initializedRangeOffset(
            Entry.first, Position.Base, C.getASTContext());
        if (!RangeBegin || *RangeBegin > *Position.ByteOffset)
          continue;
        uint64_t Delta = *Position.ByteOffset - *RangeBegin;
        QualType Type = Entry.second.getType(C.getASTContext());
        if (Type.isNull() || !Type->isIntegerType())
          continue;
        SVal DeltaValue = C.getSValBuilder().makeIntVal(Delta, Type);
        if (!isDefinitelyTrue(State, Entry.second, BO_GE, DeltaValue,
                              C.getSValBuilder()))
          continue;
        SVal Remaining = C.getSValBuilder().evalBinOp(
            State, BO_Sub, Entry.second, DeltaValue, Type);
        if (!Remaining.isUnknownOrUndef()) {
          if (ObjectRanges != 1)
            return Unknown();
          return {InitializedCoverageKind::ExactCoverage, Remaining,
                  Entry.first};
        }
      }
    }
    if (!Position.ByteOffset || UnrepresentableRanges)
      return Unknown();
    return {InitializedCoverageKind::KnownGap,
            C.getSValBuilder().makeZeroVal(C.getASTContext().getSizeType()),
            nullptr};
  }

  static InitializedCoverage initializedCoverageIncludingAdjacentNUL(
      ProgramStateRef State, const InitializedBytePosition &Position,
      CheckerContext &C) {
    InitializedCoverage Coverage = initializedCoverage(State, Position, C);
    if (Coverage.Kind == InitializedCoverageKind::Unknown ||
        !Position.ByteOffset || *Position.ByteOffset != 0)
      return Coverage;
    const SVal *Terminator =
        State->get<QEMUKnownNULTerminatorOffsets>(Position.Base);
    if (!Terminator || !isDefinitelyTrue(State, *Terminator, BO_EQ,
                                         Coverage.Length, C.getSValBuilder()))
      return Coverage;

    // Keep the extended coverage in the terminator expression's identity.
    // Although the solver proved Terminator == Coverage.Length above, it does
    // not necessarily re-associate separately constructed `value + 1`
    // expressions through that equality.  C-string sinks construct their
    // read length from Terminator, so doing the same here preserves the
    // proven relation without weakening the bounds check.
    QualType Type = Terminator->getType(C.getASTContext());
    if (Type.isNull() || !Type->isIntegerType())
      return {InitializedCoverageKind::Unknown, UnknownVal(), nullptr};
    llvm::APSInt Maximum =
        C.getSValBuilder().getBasicValueFactory().getMaxValue(Type);
    SVal MaximumValue = C.getSValBuilder().makeIntVal(Maximum);
    if (!isDefinitelyTrue(State, *Terminator, BO_LT, MaximumValue,
                          C.getSValBuilder()))
      return {InitializedCoverageKind::Unknown, UnknownVal(), nullptr};
    SVal One = C.getSValBuilder().makeIntVal(1, Type);
    SVal Extended =
        C.getSValBuilder().evalBinOp(State, BO_Add, *Terminator, One, Type);
    if (Extended.isUnknownOrUndef())
      return {InitializedCoverageKind::Unknown, UnknownVal(), nullptr};
    const SVal *Extent =
        State->get<QEMUInitializedByteObjectExtents>(Position.Base);
    if (!Extent ||
        !isDefinitelyTrue(State, Extended, BO_LE, *Extent, C.getSValBuilder()))
      return {InitializedCoverageKind::Unknown, UnknownVal(), nullptr};
    // The final byte came from a host store rather than the range producer, so
    // do not attribute the complete coverage to the range's input class.
    return {InitializedCoverageKind::ExactCoverage, Extended, nullptr,
            /*IncludesAdjacentNUL=*/true};
  }

  BugType &uninitializedDataDisclosureBugType() const {
    if (!UninitializedDataDisclosureBug)
      UninitializedDataDisclosureBug = std::make_unique<BugType>(
          this, "Read may expose bytes not initialized by the producer",
          "QEMU guest memory safety");
    return *UninitializedDataDisclosureBug;
  }

  bool reportUninitializedRead(CheckerContext &C, ProgramStateRef Safe,
                               ProgramStateRef Unsafe, SVal AccessLength,
                               SVal InitializedLength, const Expr *Where,
                               const InitializedBytePosition &Position,
                               StringRef Description,
                               std::optional<InputClass> Source = std::nullopt,
                               bool ForcePossible = false) const {
    if (!Unsafe)
      return false;
    bool Definite = !Safe && !ForcePossible;
    if (Safe)
      C.addTransition(Safe);
    ExplodedNode *Node = C.generateErrorNode(Unsafe);
    if (!Node)
      return false;

    llvm::SmallString<256> Buffer;
    llvm::raw_svector_ostream Message(Buffer);
    Message << (Definite ? "Level A: " : "Level B: ");
    if (Description == "C string read")
      Message << "C string read" << (Definite ? " reaches " : " may reach ")
              << "bytes beyond the initialized byte prefix";
    else
      Message << Description << (Definite ? " exceeds " : " may exceed ")
              << "the initialized byte prefix";
    Message << " (read bytes "
            << valueRange(Unsafe, AccessLength, C.getSValBuilder())
            << ", initialized bytes "
            << valueRange(Unsafe, InitializedLength, C.getSValBuilder()) << ')';
    auto Report = std::make_unique<PathSensitiveBugReport>(
        uninitializedDataDisclosureBugType(), Message.str(), Node);
    if (Where)
      Report->addRange(Where->getSourceRange());
    for (SymbolRef Symbol : AccessLength.symbols())
      Report->markInteresting(Symbol);
    for (SymbolRef Symbol : InitializedLength.symbols())
      Report->markInteresting(Symbol);

    std::string Address = "effective address '" +
                          witnessExpression(Where, C.getASTContext()) + "'";
    if (Position.ByteOffset)
      Address += ", byte offset " + std::to_string(*Position.ByteOffset);
    std::string Initialized =
        valueRange(Unsafe, InitializedLength, C.getSValBuilder());
    std::string ObjectExtent = "unknown";
    if (const SVal *Extent =
            Unsafe->get<QEMUInitializedByteObjectExtents>(Position.Base))
      ObjectExtent = valueRange(Unsafe, *Extent, C.getSValBuilder());
    addStructuredWitness(
        *Report, C, Unsafe, Message.str(), InitializedBytesDisclosureRuleID,
        Source, "initialized-byte producer contract",
        "host read exceeds contiguous initialized bytes " + Initialized,
        InitializedLength, "host-read", Address,
        "bytes " + valueRange(Unsafe, AccessLength, C.getSValBuilder()),
        "bytes " + ObjectExtent,
        "host-read length <= contiguous initialized length", {},
        "initialized-prefix", "initialized byte prefix");
    C.emitReport(std::move(Report));
    return true;
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
      const StackFrame *Frame;
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
          ProgramStateRef State, const StackFrame *Frame,
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
    StringRef Direction;
  };

  enum class MemorySinkResult {
    NotReported,
    Reported,
    LifetimePathSplit,
  };

  struct DirectDMAMapDescriptor {
    std::optional<unsigned> OwnerArgument;
    unsigned LengthPointerArgument;
    unsigned DirectionArgument;
    bool BooleanDirection;
  };

  struct DirectDMAUnmapDescriptor {
    std::optional<unsigned> OwnerArgument;
    unsigned BufferArgument;
    unsigned LengthArgument;
    unsigned DirectionArgument;
    unsigned AccessLengthArgument;
    bool BooleanDirection;
  };

  enum class TransferBufferDirection {
    HostRead,
    HostWrite,
  };

  struct DMATransferDescriptor {
    const qemu_contracts_generated::ContractRecord *Contract;
    unsigned OwnerArgument;
    unsigned GuestAddressArgument;
    unsigned BufferArgument;
    unsigned LengthArgument;
    std::optional<unsigned> DirectionArgument;
  };

  struct USBPacketCopyDescriptor {
    const qemu_contracts_generated::ContractRecord *Contract;
    unsigned PacketArgument;
    unsigned HostBufferArgument;
    unsigned LengthArgument;
    const qemu_contracts_generated::OperandRecord *Direction;
    const qemu_contracts_generated::OperandRecord *AccessOffset;
    const qemu_contracts_generated::OperandRecord *CapacitySelector;
    const qemu_contracts_generated::OperandRecord *PrimaryCapacity;
    const qemu_contracts_generated::OperandRecord *AlternateCapacity;
    const qemu_contracts_generated::OperandRecord *Status;
    const qemu_contracts_generated::OperandRecord *EndpointType;
    const qemu_contracts_generated::OperandRecord *SetupParameter;
  };

  struct FailedCompletionProtocolDescriptor {
    const qemu_contracts_generated::ProtocolRecord *Protocol;
    const qemu_contracts_generated::ProtocolBindingRecord *Owner;
    const qemu_contracts_generated::ProtocolBindingRecord *Queue;
    const qemu_contracts_generated::ProtocolBindingRecord *Attempt;
    const qemu_contracts_generated::ProtocolBindingRecord *Slot;
    const qemu_contracts_generated::ProtocolBindingRecord *Vector;
    const qemu_contracts_generated::ProtocolBindingRecord *Result;
    const qemu_contracts_generated::ProtocolEventRecord *DescriptorFailed;
    const qemu_contracts_generated::ProtocolEventRecord *RingAdvanced;
    const qemu_contracts_generated::ProtocolEventRecord *CompletionPublished;
  };

  struct FailedCompletionIdentity {
    SVal OwnerValue;
    const MemRegion *Owner;
    SVal Queue;
    SVal Slot;
    SVal Vector;
  };

  static const qemu_contracts_generated::ProtocolBindingRecord *
  protocolBinding(const qemu_contracts_generated::ProtocolRecord &Protocol,
                  StringRef Role) {
    if (Protocol.BindingBegin >
            qemu_contracts_generated::ProtocolBindingRecordCount ||
        Protocol.BindingCount >
            qemu_contracts_generated::ProtocolBindingRecordCount -
                Protocol.BindingBegin)
      return nullptr;
    const qemu_contracts_generated::ProtocolBindingRecord *Found = nullptr;
    for (unsigned I = Protocol.BindingBegin,
                  E = Protocol.BindingBegin + Protocol.BindingCount;
         I != E; ++I) {
      const auto &Binding = qemu_contracts_generated::ProtocolBindings[I];
      if (StringRef(Binding.ProtocolID) != Protocol.ID)
        return nullptr;
      if (StringRef(Binding.Role) != Role)
        continue;
      if (Found)
        return nullptr;
      Found = &Binding;
    }
    return Found;
  }

  static const qemu_contracts_generated::ProtocolEventRecord *
  protocolEvent(const qemu_contracts_generated::ProtocolRecord &Protocol,
                StringRef Stage) {
    if (Protocol.EventBegin >
            qemu_contracts_generated::ProtocolEventRecordCount ||
        Protocol.EventCount >
            qemu_contracts_generated::ProtocolEventRecordCount -
                Protocol.EventBegin)
      return nullptr;
    const qemu_contracts_generated::ProtocolEventRecord *Found = nullptr;
    for (unsigned I = Protocol.EventBegin,
                  E = Protocol.EventBegin + Protocol.EventCount;
         I != E; ++I) {
      const auto &Event = qemu_contracts_generated::ProtocolEvents[I];
      if (StringRef(Event.ProtocolID) != Protocol.ID)
        return nullptr;
      if (StringRef(Event.Stage) != Stage)
        continue;
      if (Found)
        return nullptr;
      Found = &Event;
    }
    return Found;
  }

  static bool protocolSelectorRangeIsValid(
      const qemu_contracts_generated::ProtocolRecord &Protocol,
      const qemu_contracts_generated::ProtocolEventRecord &Event) {
    if (StringRef(Event.ProtocolID) != Protocol.ID ||
        Event.SelectorBegin >
            qemu_contracts_generated::ProtocolSelectorRecordCount ||
        Event.SelectorCount >
            qemu_contracts_generated::ProtocolSelectorRecordCount -
                Event.SelectorBegin)
      return false;
    for (unsigned I = Event.SelectorBegin,
                  E = Event.SelectorBegin + Event.SelectorCount;
         I != E; ++I) {
      const auto &Selector = qemu_contracts_generated::ProtocolSelectors[I];
      if (StringRef(Selector.ProtocolID) != Protocol.ID ||
          StringRef(Selector.Stage) != Event.Stage)
        return false;
    }
    return true;
  }

  static const qemu_contracts_generated::ContractRecord *
  contractByID(StringRef ID) {
    const qemu_contracts_generated::ContractRecord *Found = nullptr;
    for (unsigned I = 0; I != qemu_contracts_generated::ContractRecordCount;
         ++I) {
      const auto &Contract = qemu_contracts_generated::Contracts[I];
      if (StringRef(Contract.ID) != ID)
        continue;
      if (Found)
        return nullptr;
      Found = &Contract;
    }
    return Found;
  }

  static std::optional<FailedCompletionProtocolDescriptor>
  failedCompletionProtocolDescriptor(
      const qemu_contracts_generated::ProtocolRecord &Protocol) {
    if (StringRef(Protocol.RuleID) !=
            stableID(FailedCompletionPublicationRuleID) ||
        Protocol.BindingCount != 6 || Protocol.EventCount != 3 ||
        StringRef(Protocol.ScopeName).empty() ||
        StringRef(Protocol.ScopeSource).empty() ||
        StringRef(Protocol.ScopePrototype).empty())
      return std::nullopt;

    const auto *Owner = protocolBinding(Protocol, "owner");
    const auto *Queue = protocolBinding(Protocol, "queue");
    const auto *Attempt = protocolBinding(Protocol, "attempt");
    const auto *Slot = protocolBinding(Protocol, "slot");
    const auto *Vector = protocolBinding(Protocol, "vector");
    const auto *Result = protocolBinding(Protocol, "result");
    const auto *DescriptorFailed = protocolEvent(Protocol, "descriptor-failed");
    const auto *RingAdvanced = protocolEvent(Protocol, "ring-advanced");
    const auto *CompletionPublished =
        protocolEvent(Protocol, "interrupt-published");
    if (!Owner || !Queue || !Attempt || !Slot || !Vector || !Result ||
        !DescriptorFailed || !RingAdvanced || !CompletionPublished ||
        StringRef(Owner->Source) != "scope-argument" ||
        Owner->ArgumentIndex < 0 || Owner->HasIntegerValue ||
        StringRef(Queue->Source) != "integer-constant" ||
        !Queue->HasIntegerValue || Queue->ArgumentIndex != -1 ||
        StringRef(Attempt->Source) != "transfer-result" ||
        Attempt->ArgumentIndex != -1 || Attempt->HasIntegerValue ||
        StringRef(Slot->Source) != "member-value-pre" ||
        Slot->ArgumentIndex != -1 || Slot->HasIntegerValue ||
        StringRef(Slot->RecordType).empty() || StringRef(Slot->Field).empty() ||
        StringRef(Vector->Source) != "integer-constant" ||
        !Vector->HasIntegerValue || Vector->ArgumentIndex != -1 ||
        StringRef(Result->Source) != "transfer-result" ||
        Result->ArgumentIndex != -1 || Result->HasIntegerValue)
      return std::nullopt;

    if (!protocolSelectorRangeIsValid(Protocol, *DescriptorFailed) ||
        !protocolSelectorRangeIsValid(Protocol, *RingAdvanced) ||
        !protocolSelectorRangeIsValid(Protocol, *CompletionPublished) ||
        DescriptorFailed->SelectorCount == 0 ||
        RingAdvanced->SelectorCount != 1 ||
        CompletionPublished->SelectorCount != 1)
      return std::nullopt;

    for (unsigned I = DescriptorFailed->SelectorBegin,
                  E = I + DescriptorFailed->SelectorCount;
         I != E; ++I) {
      const auto &Selector = qemu_contracts_generated::ProtocolSelectors[I];
      const auto *Contract = contractByID(Selector.ContractID);
      if (!Contract || StringRef(Contract->Kind) != "transfer" ||
          StringRef(Selector.Kind) != "transfer-call" ||
          StringRef(Selector.Phase) != "post-call" ||
          StringRef(Selector.ResultPath) != "failure" ||
          Selector.ExpectedCount == 0 || !StringRef(Selector.Name).empty() ||
          !StringRef(Selector.Prototype).empty() ||
          !StringRef(Selector.RecordType).empty() ||
          !StringRef(Selector.Field).empty() ||
          !StringRef(Selector.Operation).empty())
        return std::nullopt;
    }

    const auto &Ring =
        qemu_contracts_generated::ProtocolSelectors[RingAdvanced
                                                        ->SelectorBegin];
    if (StringRef(Ring.Kind) != "member-update" ||
        StringRef(Ring.RecordType) != Slot->RecordType ||
        StringRef(Ring.Field) != Slot->Field ||
        StringRef(Ring.Operation) != "post-decrement" ||
        StringRef(Ring.Phase) != "bind" || Ring.ExpectedCount == 0 ||
        !StringRef(Ring.ContractID).empty() || !StringRef(Ring.Name).empty() ||
        !StringRef(Ring.Prototype).empty() ||
        !StringRef(Ring.ResultPath).empty())
      return std::nullopt;

    const auto &Completion =
        qemu_contracts_generated::ProtocolSelectors[CompletionPublished
                                                        ->SelectorBegin];
    if (StringRef(Completion.Kind) != "function-call" ||
        StringRef(Completion.Name).empty() ||
        StringRef(Completion.Prototype).empty() ||
        StringRef(Completion.Phase) != "pre-call" ||
        Completion.ExpectedCount == 0 ||
        !StringRef(Completion.ContractID).empty() ||
        !StringRef(Completion.RecordType).empty() ||
        !StringRef(Completion.Field).empty() ||
        !StringRef(Completion.Operation).empty() ||
        !StringRef(Completion.ResultPath).empty())
      return std::nullopt;

    return FailedCompletionProtocolDescriptor{
        &Protocol,    Owner,
        Queue,        Attempt,
        Slot,         Vector,
        Result,       DescriptorFailed,
        RingAdvanced, CompletionPublished};
  }

  static bool protocolSourceMatches(const FunctionDecl *FD, StringRef Expected,
                                    const SourceManager &SM) {
    PresumedLoc Location = SM.getPresumedLoc(FD->getLocation());
    if (Location.isInvalid())
      return false;
    std::string File = Location.getFilename();
    std::replace(File.begin(), File.end(), '\\', '/');
    StringRef Normalized(File);
    return Normalized == Expected ||
           (Normalized.size() > Expected.size() &&
            Normalized.ends_with(Expected) &&
            Normalized[Normalized.size() - Expected.size() - 1] == '/');
  }

  static std::optional<FailedCompletionProtocolDescriptor>
  failedCompletionProtocolForFunction(const FunctionDecl *FD,
                                      const SourceManager &SM) {
    if (!FD || !FD->getIdentifier() || !FD->doesThisDeclarationHaveABody())
      return std::nullopt;
    std::optional<FailedCompletionProtocolDescriptor> Found;
    for (unsigned I = 0; I != qemu_contracts_generated::ProtocolRecordCount;
         ++I) {
      const auto &Protocol = qemu_contracts_generated::Protocols[I];
      if (StringRef(Protocol.ScopeName) != FD->getName() ||
          !directDMATypeMatches(FD->getType(), Protocol.ScopePrototype) ||
          !protocolSourceMatches(FD, Protocol.ScopeSource, SM))
        continue;
      std::optional<FailedCompletionProtocolDescriptor> Candidate =
          failedCompletionProtocolDescriptor(Protocol);
      if (!Candidate || Found)
        return std::nullopt;
      unsigned OwnerArgument =
          static_cast<unsigned>(Candidate->Owner->ArgumentIndex);
      if (OwnerArgument >= FD->getNumParams() ||
          !isNamedRecordPointer(FD->getParamDecl(OwnerArgument)->getType(),
                                Candidate->Slot->RecordType))
        return std::nullopt;
      Found = *Candidate;
    }
    return Found;
  }

  static std::optional<FailedCompletionProtocolDescriptor>
  activeFailedCompletionProtocol(CheckerContext &C) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(
        C.getStackFrame() ? C.getStackFrame()->getDecl() : nullptr);
    return failedCompletionProtocolForFunction(FD, C.getSourceManager());
  }

  static SVal protocolIntegerConstant(long long Value, CheckerContext &C) {
    llvm::APSInt Integer(llvm::APInt(64, static_cast<uint64_t>(Value)),
                         /*isUnsigned=*/false);
    return C.getSValBuilder().makeIntVal(Integer);
  }

  static std::optional<FailedCompletionIdentity> failedCompletionOwnerIdentity(
      const FailedCompletionProtocolDescriptor &Protocol, ProgramStateRef State,
      CheckerContext &C) {
    const auto *FD =
        dyn_cast_or_null<FunctionDecl>(C.getStackFrame()->getDecl());
    unsigned OwnerArgument =
        static_cast<unsigned>(Protocol.Owner->ArgumentIndex);
    if (!FD || OwnerArgument >= FD->getNumParams())
      return std::nullopt;
    const SVal *Captured =
        State->get<QEMUFailedCompletionScopeOwners>(C.getStackFrame());
    if (!Captured || Captured->isUnknownOrUndef())
      return std::nullopt;
    SVal Object = *Captured;
    const MemRegion *Owner = directDMAOwner(Object);
    if (!Owner)
      return std::nullopt;
    return FailedCompletionIdentity{
        Object, Owner, protocolIntegerConstant(Protocol.Queue->IntegerValue, C),
        UnknownVal(),
        protocolIntegerConstant(Protocol.Vector->IntegerValue, C)};
  }

  static std::optional<FailedCompletionIdentity>
  failedCompletionIdentity(const FailedCompletionProtocolDescriptor &Protocol,
                           ProgramStateRef State, CheckerContext &C) {
    std::optional<FailedCompletionIdentity> Identity =
        failedCompletionOwnerIdentity(Protocol, State, C);
    if (!Identity)
      return std::nullopt;
    const auto *FD =
        dyn_cast_or_null<FunctionDecl>(C.getStackFrame()->getDecl());
    unsigned OwnerArgument =
        static_cast<unsigned>(Protocol.Owner->ArgumentIndex);
    if (!FD || OwnerArgument >= FD->getNumParams())
      return std::nullopt;
    const ParmVarDecl *Parameter = FD->getParamDecl(OwnerArgument);
    SVal Object = Identity->OwnerValue;
    const FieldDecl *SlotField =
        namedField(Parameter->getType(), Protocol.Slot->Field);
    if (!SlotField ||
        SlotField->getParent()->getName() != Protocol.Slot->RecordType)
      return std::nullopt;
    SVal SlotLocation = State->getLValue(SlotField, Object);
    auto SlotLoc = SlotLocation.getAs<Loc>();
    if (!SlotLoc)
      return std::nullopt;
    SVal Slot = State->getSVal(*SlotLoc);
    if (Slot.isUnknownOrUndef())
      return std::nullopt;
    Identity->Slot = Slot;
    return Identity;
  }

  static bool protocolMatchesFailedTransfer(
      const FailedCompletionProtocolDescriptor &Protocol,
      const qemu_contracts_generated::ContractRecord &Contract) {
    bool Found = false;
    for (unsigned I = Protocol.DescriptorFailed->SelectorBegin,
                  E = I + Protocol.DescriptorFailed->SelectorCount;
         I != E; ++I) {
      const auto &Selector = qemu_contracts_generated::ProtocolSelectors[I];
      if (StringRef(Selector.ContractID) != Contract.ID)
        continue;
      if (Found)
        return false;
      Found = true;
    }
    return Found;
  }

  static const qemu::state::CompletionPublicationState *
  uniqueFailedCompletionPublication(ProgramStateRef State,
                                    const FailedCompletionIdentity &Identity,
                                    std::optional<SVal> RequiredSlot,
                                    bool RequireRingAdvanced) {
    const qemu::state::CompletionPublicationState *Found = nullptr;
    for (const auto &Entry :
         State->get<qemu::state::CompletionPublicationMap>()) {
      const auto &Publication = Entry.second;
      if (Publication.getOwner() != Identity.Owner ||
          Publication.getQueueID() != Identity.Queue ||
          Publication.getVector() != Identity.Vector ||
          !Publication.hasStage(
              qemu::facts::CompletionPublicationStage::DescriptorFailed) ||
          (RequiredSlot && Publication.getSlot() != *RequiredSlot) ||
          (RequireRingAdvanced &&
           !Publication.hasStage(
               qemu::facts::CompletionPublicationStage::RingAdvanced)))
        continue;
      if (Found)
        return nullptr;
      Found = &Publication;
    }
    return Found;
  }

  static ProgramStateRef
  removeFailedCompletionFactsForResult(ProgramStateRef State,
                                       SymbolRef Result) {
    State = qemu::state::removeCompletionPublicationsForResult(State, Result);
    State = qemu::state::removeValueResultState(State, Result);
    return qemu::state::removeTransferOperation(State, Result);
  }

  static ProgramStateRef
  removeFailedCompletionFactsForOwner(ProgramStateRef State,
                                      const MemRegion *Owner) {
    llvm::SmallVector<SymbolRef, 4> Results;
    for (const auto &Entry :
         State->get<qemu::state::CompletionPublicationMap>())
      if (Entry.second.getOwner() == Owner)
        Results.push_back(Entry.second.getResult());
    for (SymbolRef Result : Results)
      State = removeFailedCompletionFactsForResult(State, Result);
    return State;
  }

  static std::string normalizeDirectDMAContractType(StringRef Type) {
    std::string Normalized;
    Normalized.reserve(Type.size());
    for (size_t I = 0; I != Type.size();) {
      if (llvm::isSpace(Type[I])) {
        ++I;
        continue;
      }
      if (Type.substr(I).starts_with("_Bool")) {
        size_t End = I + StringRef("_Bool").size();
        bool BeginsToken =
            I == 0 || (!llvm::isAlnum(Type[I - 1]) && Type[I - 1] != '_');
        bool EndsToken = End == Type.size() ||
                         (!llvm::isAlnum(Type[End]) && Type[End] != '_');
        if (BeginsToken && EndsToken) {
          Normalized += "bool";
          I = End;
          continue;
        }
      }
      Normalized.push_back(Type[I++]);
    }
    return Normalized;
  }

  static bool jsonStringIs(const llvm::json::Object &Object, StringRef Key,
                           StringRef Expected) {
    std::optional<StringRef> Value = Object.getString(Key);
    return Value && *Value == Expected;
  }

  static bool jsonIntegerIs(const llvm::json::Object &Object, StringRef Key,
                            int64_t Expected) {
    std::optional<int64_t> Value = Object.getInteger(Key);
    return Value && *Value == Expected;
  }

  static bool jsonSingleStringArrayIs(const llvm::json::Object &Object,
                                      StringRef Key, StringRef Expected) {
    const llvm::json::Array *Values = Object.getArray(Key);
    if (!Values || Values->size() != 1)
      return false;
    std::optional<StringRef> Value = (*Values)[0].getAsString();
    return Value && *Value == Expected;
  }

  bool loadSelectiveSummaryManifest(StringRef Path, CheckerManager &Mgr) {
    SelectiveSummaryManifest.clear();
    SelectiveSummaryFormat = 0;
    SelectiveSummaries.clear();
    if (Path.empty())
      return true;

    auto Invalid = [&](StringRef Reason) {
      SelectiveSummaryManifest.clear();
      SelectiveSummaryFormat = 0;
      SelectiveSummaries.clear();
      Mgr.reportInvalidCheckerOptionValue(
          this, "SelectiveSummaryManifest",
          ("the exact sealed D10 selective-summary manifest (" + Reason + ")")
              .str());
      return false;
    };

    auto &VFS = Mgr.getASTContext()
                    .getSourceManager()
                    .getFileManager()
                    .getVirtualFileSystem();
    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> Buffer =
        VFS.getBufferForFile(Path);
    if (Buffer.getError())
      return Invalid("file cannot be read");

    StringRef Bytes = Buffer.get()->getBuffer();
    llvm::Expected<llvm::json::Value> Parsed = llvm::json::parse(Bytes);
    if (!Parsed) {
      llvm::consumeError(Parsed.takeError());
      return Invalid("JSON is malformed");
    }
    const llvm::json::Object *Root = Parsed->getAsObject();
    if (!Root)
      return Invalid("root is not an object");

    std::optional<int64_t> Format = Root->getInteger("format");
    if (!Format || (*Format != 1 && *Format != 2) ||
        !jsonStringIs(*Root, "kind", "qemu-selective-ctu-summary") ||
        !jsonStringIs(*Root, "result", "pass"))
      return Invalid("format, kind, or result differs");
    bool IsV2 = *Format == 2;

    const llvm::json::Object *QEMU = Root->getObject("qemu");
    if (!QEMU ||
        !jsonStringIs(*QEMU, "revision",
                      "d73149283205645625bfa9fe029cfb68e4c4a9ae") ||
        QEMU->getBoolean("dirty") != std::optional<bool>(false))
      return Invalid("exact QEMU revision or clean-state identity differs");

    const llvm::json::Object *Coverage = Root->getObject("coverage");
    int64_t ExpectedSummaryCount = IsV2 ? 3 : 2;
    if (!Coverage ||
        !jsonIntegerIs(*Coverage, "requested", ExpectedSummaryCount) ||
        !jsonIntegerIs(*Coverage, "exact", ExpectedSummaryCount) ||
        !jsonIntegerIs(*Coverage, "unsupported", 0))
      return Invalid("producer coverage differs");

    const llvm::json::Object *Scope = Root->getObject("scope");
    if (!Scope)
      return Invalid("bounded producer scope differs");
    if (!IsV2) {
      const llvm::json::Array *Allowlist = Scope->getArray("allowlist");
      if (!Allowlist || Allowlist->size() != 2 ||
          (*Allowlist)[0].getAsString() !=
              std::optional<StringRef>("dma_buf_read") ||
          (*Allowlist)[1].getAsString() !=
              std::optional<StringRef>("dma_buf_write") ||
          !jsonStringIs(*Scope, "claim",
                        "transfer-result-and-extent-only") ||
          !jsonStringIs(*Scope, "helper", "dma_buf_rw") ||
          !jsonStringIs(*Scope, "leaf", "dma_memory_rw") ||
          !jsonStringIs(*Scope, "model", "qemu.dma.transfer-result/v1") ||
          !jsonIntegerIs(*Scope, "max_depth", 3))
        return Invalid("bounded producer scope differs");
    } else {
      const llvm::json::Array *Families = Scope->getArray("families");
      const llvm::json::Object *DMABufFamily =
          Families && Families->size() == 2 ? (*Families)[0].getAsObject()
                                           : nullptr;
      const llvm::json::Object *PCIFamily =
          Families && Families->size() == 2 ? (*Families)[1].getAsObject()
                                           : nullptr;
      const llvm::json::Array *DMABufAllowlist =
          DMABufFamily ? DMABufFamily->getArray("allowlist") : nullptr;
      const llvm::json::Array *PCIAllowlist =
          PCIFamily ? PCIFamily->getArray("allowlist") : nullptr;
      if (!DMABufFamily || !PCIFamily || !DMABufAllowlist ||
          DMABufAllowlist->size() != 2 ||
          (*DMABufAllowlist)[0].getAsString() !=
              std::optional<StringRef>("dma_buf_read") ||
          (*DMABufAllowlist)[1].getAsString() !=
              std::optional<StringRef>("dma_buf_write") ||
          !jsonStringIs(*DMABufFamily, "id", "qemu.dma-buf") ||
          !jsonStringIs(*DMABufFamily, "claim",
                        "transfer-result-and-extent-only") ||
          !jsonStringIs(*DMABufFamily, "helper", "dma_buf_rw") ||
          !PCIAllowlist || PCIAllowlist->size() != 1 ||
          (*PCIAllowlist)[0].getAsString() !=
              std::optional<StringRef>("pci_dma_read") ||
          !jsonStringIs(*PCIFamily, "id", "qemu.pci-dma-read") ||
          !jsonStringIs(*PCIFamily, "claim", "full-transfer-effect") ||
          !jsonStringIs(*PCIFamily, "helper", "pci_dma_rw") ||
          !jsonStringIs(*Scope, "leaf", "dma_memory_rw") ||
          !jsonStringIs(*Scope, "model", "qemu.dma.transfer-result/v2") ||
          !jsonIntegerIs(*Scope, "max_depth", 3))
        return Invalid("bounded producer scope differs");
    }

    const llvm::json::Object *Inputs = Root->getObject("inputs");
    const llvm::json::Object *Header =
        Inputs ? Inputs->getObject("header") : nullptr;
    const llvm::json::Object *Source =
        Inputs ? Inputs->getObject("source") : nullptr;
    const llvm::json::Object *PCIHeader =
        Inputs ? Inputs->getObject("pci_header") : nullptr;
    const llvm::json::Object *PCIAnchor =
        Inputs ? Inputs->getObject("pci_anchor") : nullptr;
    const llvm::json::Object *Dependencies =
        Inputs ? Inputs->getObject("dependencies") : nullptr;
    const llvm::json::Object *PCIDependencies =
        Inputs ? Inputs->getObject("pci_dependencies") : nullptr;
    const llvm::json::Object *Leaf =
        Inputs ? Inputs->getObject("leaf_contract") : nullptr;
    const llvm::json::Object *Catalog =
        Inputs ? Inputs->getObject("catalog") : nullptr;
    const llvm::json::Object *CatalogSchema =
        Inputs ? Inputs->getObject("catalog_schema") : nullptr;
    bool InvalidPCIInputs =
        IsV2 &&
        (!PCIHeader ||
         !jsonStringIs(*PCIHeader, "path", "include/hw/pci/pci_device.h") ||
         !jsonIntegerIs(*PCIHeader, "bytes", 11649) ||
         !jsonStringIs(*PCIHeader, "sha256",
                       "27c4e2437bc9f1a2b202d8f433ebf7e9a9bb45d2bb6d7216115441f"
                       "b96c89e3e") ||
         !PCIAnchor ||
         !jsonStringIs(*PCIAnchor, "path", "hw/net/e1000e_core.c") ||
         !jsonIntegerIs(*PCIAnchor, "bytes", 107421) ||
         !jsonStringIs(*PCIAnchor, "sha256",
                       "afa1fd76b8a24f3055a85b1ab043fd5a5a3009dec7463b70f2e5257"
                       "e35d2ec43") ||
         !PCIDependencies ||
         !jsonIntegerIs(*PCIDependencies, "count", 467) ||
         !jsonStringIs(*PCIDependencies, "manifest_sha256",
                       "1c4c17fa6f77e6d5dc71ff70016630b03ed4df22b82a211ac81bbcbb"
                       "58954132"));
    if (!Catalog ||
        !jsonStringIs(*Catalog, "path", "QEMUContractCatalog.json") ||
        !jsonIntegerIs(*Catalog, "bytes", 48051) ||
        !jsonIntegerIs(*Catalog, "format",
                       qemu_contracts_generated::CatalogFormat) ||
        !jsonStringIs(*Catalog, "normalized_sha256",
                      qemu_contracts_generated::CatalogSHA256) ||
        !jsonStringIs(*Catalog, "sha256",
                      "c2d0df195f76e50a0069cc0a2431f343c173c8f2b8602fffd2c6c"
                      "ea8946095a0") ||
        !CatalogSchema ||
        !jsonStringIs(*CatalogSchema, "path",
                      "QEMUContractCatalog.schema.json") ||
        !jsonIntegerIs(*CatalogSchema, "bytes", 21988) ||
        !jsonStringIs(*CatalogSchema, "sha256",
                      "3ce99b26b5bf117cb6cbb13676be43c76eedac28f13203b521c396"
                      "f685aa8d42") ||
        StringRef(qemu_contracts_generated::ModelVersion) !=
            "qemu-v3-io-contracts-v8" ||
        StringRef(qemu_contracts_generated::SchemaSHA256) !=
            "09a169d61f4b526431cb22ab6c219adcbf263aa7f5f3abfd46701731c"
            "bee166d" ||
        !Header || !jsonStringIs(*Header, "path", "include/system/dma.h") ||
        !jsonIntegerIs(*Header, "bytes", 11848) ||
        !jsonStringIs(*Header, "sha256",
                      "14e4c2820bd96a1aac072a0c636ee77be22be00067c3cc0f77612385"
                      "cf8dd136") ||
        !Source || !jsonStringIs(*Source, "path", "system/dma-helpers.c") ||
        !jsonIntegerIs(*Source, "bytes", 10023) ||
        !jsonStringIs(*Source, "sha256",
                      "b7b281a47eeeb60ea8719e5ea30807afb0c5861362c571c8c1325c54"
                      "4d55ef45") ||
        !Dependencies || !jsonIntegerIs(*Dependencies, "count", 418) ||
        !jsonStringIs(*Dependencies, "manifest_sha256",
                      "6946e6ba1c5bc57b669f3835838f4b1fc122b4da1ca22b7314c29661"
                      "5d11b0ac") ||
        InvalidPCIInputs ||
        !Leaf || !jsonStringIs(*Leaf, "id", "qemu.transfer.dma-memory.rw") ||
        !jsonStringIs(*Leaf, "prototype",
                      "MemTxResult(AddressSpace*,dma_addr_t,void*,dma_addr_t,"
                      "DMADirection,MemTxAttrs)"))
      return Invalid("catalog, source, header, or leaf identity differs");

    unsigned CompiledLeafCount = 0;
    for (const auto &Contract : qemu_contracts_generated::Contracts)
      if (StringRef(Contract.ID) == "qemu.transfer.dma-memory.rw" &&
          normalizeDirectDMAContractType(Contract.Prototype) ==
              normalizeDirectDMAContractType(
                  "MemTxResult(AddressSpace*,dma_addr_t,void*,dma_addr_t,"
                  "DMADirection,MemTxAttrs)"))
        ++CompiledLeafCount;
    if (CompiledLeafCount != 1)
      return Invalid("compiled leaf contract identity differs");

    const llvm::json::Array *Summaries = Root->getArray("summaries");
    if (!Summaries || Summaries->size() !=
                          static_cast<size_t>(ExpectedSummaryCount))
      return Invalid("summary inventory differs");

    constexpr llvm::StringLiteral Prototype =
        "MemTxResult (void *, dma_addr_t, dma_addr_t *, QEMUSGList *, "
        "MemTxAttrs)";
    constexpr llvm::StringLiteral PrototypeSHA =
        "24871fbaeed4addcdf0df1ffc664bb6a0f0f84d24f9f2b1a23691f3cb39021b8";
    for (unsigned Index = 0; Index != 2; ++Index) {
      const llvm::json::Object *Summary = (*Summaries)[Index].getAsObject();
      StringRef Function = Index == 0 ? "dma_buf_read" : "dma_buf_write";
      std::string LookupName = ("c:@F@" + Function).str();
      StringRef Direction =
          Index == 0 ? "DMA_DIRECTION_FROM_DEVICE" : "DMA_DIRECTION_TO_DEVICE";
      unsigned Line = Index == 0 ? 302 : 304;
      if (!Summary || !jsonStringIs(*Summary, "function", Function) ||
          !jsonStringIs(*Summary, "lookup_name", LookupName) ||
          !jsonStringIs(*Summary, "status", "exact") ||
          !jsonStringIs(*Summary, "prototype", Prototype) ||
          !jsonStringIs(*Summary, "prototype_sha256", PrototypeSHA) ||
          !jsonIntegerIs(*Summary, "observed_depth", 2))
        return Invalid("summary identity differs");

      const llvm::json::Array *Closure = Summary->getArray("closure");
      if (!Closure || Closure->size() != 3 ||
          (*Closure)[0].getAsString() != std::optional<StringRef>(Function) ||
          (*Closure)[1].getAsString() !=
              std::optional<StringRef>("dma_buf_rw") ||
          (*Closure)[2].getAsString() !=
              std::optional<StringRef>("dma_memory_rw"))
        return Invalid("summary closure differs");

      const llvm::json::Object *Declaration = Summary->getObject("declaration");
      if (!Declaration ||
          !jsonStringIs(*Declaration, "path", "include/system/dma.h") ||
          !jsonIntegerIs(*Declaration, "line", Line) ||
          !jsonIntegerIs(*Declaration, "column", 13) ||
          !jsonStringIs(*Declaration, "prototype_sha256", PrototypeSHA))
        return Invalid("summary declaration differs");

      const llvm::json::Object *Effect = Summary->getObject("effect");
      const llvm::json::Object *Return =
          Effect ? Effect->getObject("return_value") : nullptr;
      const llvm::json::Object *Initial =
          Return ? Return->getObject("initial") : nullptr;
      const llvm::json::Array *Terms =
          Return ? Return->getArray("terms") : nullptr;
      const llvm::json::Object *Term =
          Terms && Terms->size() == 1 ? (*Terms)[0].getAsObject() : nullptr;
      if (!Return || !Initial || !Term ||
          !jsonIntegerIs(*Initial, "integer", 0) ||
          !jsonStringIs(*Initial, "spelling", "MEMTX_OK") ||
          !jsonStringIs(*Return, "op", "bitwise-or") ||
          !jsonStringIs(*Term, "call_result", "dma_memory_rw") ||
          !jsonStringIs(*Term, "cardinality", "each-sg-entry"))
        return Invalid("summary result semantics differ");

      const llvm::json::Object *Transfer =
          Effect ? Effect->getObject("transfer") : nullptr;
      const llvm::json::Object *HostBuffer =
          Transfer ? Transfer->getObject("host_buffer") : nullptr;
      const llvm::json::Object *Attributes =
          Transfer ? Transfer->getObject("attributes") : nullptr;
      const llvm::json::Object *TransferDirection =
          Transfer ? Transfer->getObject("direction") : nullptr;
      const llvm::json::Object *Extent =
          Transfer ? Transfer->getObject("extent") : nullptr;
      const llvm::json::Object *LHS =
          Extent ? Extent->getObject("lhs") : nullptr;
      const llvm::json::Object *RHS =
          Extent ? Extent->getObject("rhs") : nullptr;
      const llvm::json::Object *ExtentField =
          RHS ? RHS->getObject("field") : nullptr;
      const llvm::json::Object *GuestAddress =
          Transfer ? Transfer->getObject("guest_address") : nullptr;
      const llvm::json::Object *Owner =
          Transfer ? Transfer->getObject("owner") : nullptr;
      const llvm::json::Object *OwnerField =
          Owner ? Owner->getObject("field") : nullptr;
      if (!HostBuffer || !Attributes || !TransferDirection || !Extent || !LHS ||
          !ExtentField || !GuestAddress || !OwnerField ||
          !jsonIntegerIs(*HostBuffer, "argument", 0) ||
          !jsonIntegerIs(*Attributes, "argument", 4) ||
          !jsonStringIs(*TransferDirection, "enum", Direction) ||
          !jsonStringIs(*Extent, "op", "min") ||
          !jsonIntegerIs(*LHS, "argument", 1) ||
          !jsonIntegerIs(*ExtentField, "argument", 3) ||
          !jsonSingleStringArrayIs(*ExtentField, "path", "size") ||
          !jsonIntegerIs(*OwnerField, "argument", 3) ||
          !jsonSingleStringArrayIs(*OwnerField, "path", "as") ||
          !jsonStringIs(*GuestAddress, "unknown",
                        "scatter-gather-entry-base") ||
          !jsonStringIs(*GuestAddress, "claim",
                        "not-contiguous-and-not-summarized"))
        return Invalid("summary transfer semantics differ");

      const llvm::json::Object *Residual =
          Effect ? Effect->getObject("residual") : nullptr;
      if (!Residual || !jsonIntegerIs(*Residual, "argument", 2) ||
          !jsonStringIs(*Residual, "writeback",
                        "recognized-but-not-imported-by-this-model"))
        return Invalid("summary residual semantics differ");

      SelectiveSummaries.push_back(SelectiveDMASummary{
          Function.str(), LookupName, Prototype.str(), "include/system/dma.h",
          PrototypeSHA.str(), Line, 13,
          Index == 0 ? SelectiveSummaryDirection::FromDevice
                     : SelectiveSummaryDirection::ToDevice,
          SelectiveSummaryEffect::ResultAndExtentOnly});
    }

    if (!IsV2) {
      if (Bytes.size() != 92246 ||
          llvm::toHex(llvm::SHA256::hash(
                          llvm::arrayRefFromStringRef(Bytes)),
                      /*LowerCase=*/true) !=
              "c7e7c8b42859f405eb9e0bbcc5ff6018dec8ae4e9fb342eca089aaf598"
              "12e676") {
        SelectiveSummaries.clear();
        return Invalid("sealed byte identity differs");
      }
      SelectiveSummaryManifest = Path.str();
      SelectiveSummaryFormat = 1;
      return true;
    }

    const llvm::json::Object *PCISummary = (*Summaries)[2].getAsObject();
    constexpr llvm::StringLiteral PCIPrototype =
        "MemTxResult (PCIDevice *, dma_addr_t, void *, dma_addr_t)";
    constexpr llvm::StringLiteral PCIPrototypeSHA =
        "11c10047376ac209e09b080cb72f3364d7290ad421f90862a591ef7133ac5efe";
    if (!PCISummary ||
        !jsonStringIs(*PCISummary, "function", "pci_dma_read") ||
        !jsonStringIs(*PCISummary, "lookup_name",
                      "static-inline:include/hw/pci/pci_device.h:"
                      "pci_dma_read") ||
        !jsonStringIs(*PCISummary, "status", "exact") ||
        !jsonStringIs(*PCISummary, "prototype", PCIPrototype) ||
        !jsonStringIs(*PCISummary, "prototype_sha256", PCIPrototypeSHA) ||
        !jsonIntegerIs(*PCISummary, "observed_depth", 2))
      return Invalid("PCI summary identity differs");

    const llvm::json::Array *PCIClosure = PCISummary->getArray("closure");
    if (!PCIClosure || PCIClosure->size() != 4 ||
        (*PCIClosure)[0].getAsString() !=
            std::optional<StringRef>("pci_dma_read") ||
        (*PCIClosure)[1].getAsString() !=
            std::optional<StringRef>("pci_dma_rw") ||
        (*PCIClosure)[2].getAsString() !=
            std::optional<StringRef>("pci_get_address_space") ||
        (*PCIClosure)[3].getAsString() !=
            std::optional<StringRef>("dma_memory_rw"))
      return Invalid("PCI summary closure differs");

    const llvm::json::Object *PCISupportingDefinitions =
        PCISummary->getObject("supporting_definitions");
    const llvm::json::Object *PCIHelperDefinition =
        PCISupportingDefinitions
            ? PCISupportingDefinitions->getObject("pci_dma_rw")
            : nullptr;
    const llvm::json::Object *PCIGetterDefinition =
        PCISupportingDefinitions
            ? PCISupportingDefinitions->getObject("pci_get_address_space")
            : nullptr;
    if (!PCISupportingDefinitions || PCISupportingDefinitions->size() != 2 ||
        !PCIHelperDefinition ||
        !jsonStringIs(*PCIHelperDefinition, "path",
                      "include/hw/pci/pci_device.h") ||
        !jsonIntegerIs(*PCIHelperDefinition, "line", 256) ||
        !jsonIntegerIs(*PCIHelperDefinition, "column", 27) ||
        !jsonStringIs(*PCIHelperDefinition, "prototype_sha256",
                      "4c6af3c284dffc68fc46105ad95e32b5d78efad45ba557de78d58a06a"
                      "d5d1b86") ||
        !jsonStringIs(*PCIHelperDefinition, "body_sha256",
                      "eebb141180711f8ec8b4cc3ddab8b752e70e6dc673eece7b7cfeadbea"
                      "23653af") ||
        !PCIGetterDefinition ||
        !jsonStringIs(*PCIGetterDefinition, "path",
                      "include/hw/pci/pci_device.h") ||
        !jsonIntegerIs(*PCIGetterDefinition, "line", 238) ||
        !jsonIntegerIs(*PCIGetterDefinition, "column", 29) ||
        !jsonStringIs(*PCIGetterDefinition, "prototype_sha256",
                      "9eced98b15c220cd79ae8f180d95e84346e586194c82729d36e97af9a4"
                      "c6807b") ||
        !jsonStringIs(*PCIGetterDefinition, "body_sha256",
                      "7d3645cee9fa7c2531fe7ac6bcff3b4def9c8166113701b5a4ac7996ad"
                      "e30b72"))
      return Invalid("PCI supporting definition identity differs");

    const llvm::json::Object *PCIDeclaration =
        PCISummary->getObject("declaration");
    if (!PCIDeclaration ||
        !jsonStringIs(*PCIDeclaration, "path",
                      "include/hw/pci/pci_device.h") ||
        !jsonIntegerIs(*PCIDeclaration, "line", 276) ||
        !jsonIntegerIs(*PCIDeclaration, "column", 27) ||
        !jsonStringIs(*PCIDeclaration, "prototype_sha256", PCIPrototypeSHA))
      return Invalid("PCI summary declaration differs");

    const llvm::json::Object *PCIEffect = PCISummary->getObject("effect");
    const llvm::json::Object *PCIReturn =
        PCIEffect ? PCIEffect->getObject("return_value") : nullptr;
    const llvm::json::Object *PCITransfer =
        PCIEffect ? PCIEffect->getObject("transfer") : nullptr;
    const llvm::json::Object *PCIImport =
        PCIEffect ? PCIEffect->getObject("import") : nullptr;
    const llvm::json::Object *PCIOwner =
        PCITransfer ? PCITransfer->getObject("owner") : nullptr;
    const llvm::json::Object *PCIOwnerField =
        PCIOwner ? PCIOwner->getObject("field") : nullptr;
    const llvm::json::Object *PCIGuestAddress =
        PCITransfer ? PCITransfer->getObject("guest_address") : nullptr;
    const llvm::json::Object *PCIHostBuffer =
        PCITransfer ? PCITransfer->getObject("host_buffer") : nullptr;
    const llvm::json::Object *PCIExtent =
        PCITransfer ? PCITransfer->getObject("extent") : nullptr;
    const llvm::json::Object *PCIDirection =
        PCITransfer ? PCITransfer->getObject("direction") : nullptr;
    const llvm::json::Object *PCIAttributes =
        PCITransfer ? PCITransfer->getObject("attributes") : nullptr;
    const llvm::json::Array *PCILosses =
        PCIImport ? PCIImport->getArray("losses") : nullptr;
    const llvm::json::Object *PCIBufferInitialization =
        PCIEffect ? PCIEffect->getObject("buffer_initialization") : nullptr;
    const llvm::json::Object *PCIInitializationExtent =
        PCIBufferInitialization
            ? PCIBufferInitialization->getObject("extent")
            : nullptr;
    const llvm::json::Object *PCIInitializationSuccess =
        PCIBufferInitialization
            ? PCIBufferInitialization->getObject("success")
            : nullptr;
    const llvm::json::Object *PCIInitializationFailure =
        PCIBufferInitialization
            ? PCIBufferInitialization->getObject("failure")
            : nullptr;
    const llvm::json::Object *PCIInitializationPrerequisite =
        PCIBufferInitialization
            ? PCIBufferInitialization->getObject("prerequisite")
            : nullptr;
    if (!PCIReturn ||
        !jsonStringIs(*PCIReturn, "op", "identity") ||
        !jsonStringIs(*PCIReturn, "call_result", "dma_memory_rw") ||
        !PCITransfer || !PCIOwnerField || !PCIGuestAddress || !PCIHostBuffer ||
        !PCIExtent || !PCIDirection || !PCIAttributes || !PCIImport ||
        !jsonIntegerIs(*PCIOwnerField, "argument", 0) ||
        !jsonSingleStringArrayIs(*PCIOwnerField, "path", "bus_master_as") ||
        PCIOwnerField->getBoolean("address_of") !=
            std::optional<bool>(true) ||
        !jsonIntegerIs(*PCIGuestAddress, "argument", 1) ||
        !jsonIntegerIs(*PCIHostBuffer, "argument", 2) ||
        !jsonIntegerIs(*PCIExtent, "argument", 3) ||
        !jsonStringIs(*PCIDirection, "enum", "DMA_DIRECTION_TO_DEVICE") ||
        !jsonStringIs(*PCIAttributes, "constant",
                      "MEMTXATTRS_UNSPECIFIED") ||
        PCIImport->getBoolean("value_result_state") !=
            std::optional<bool>(true) ||
        PCIImport->getBoolean("transfer_operation") !=
            std::optional<bool>(true) ||
        !PCILosses || !PCILosses->empty() || !PCIBufferInitialization ||
        !PCIInitializationExtent ||
        !jsonIntegerIs(*PCIInitializationExtent, "argument", 3) ||
        !PCIInitializationSuccess ||
        PCIInitializationSuccess->getBoolean("initialized") !=
            std::optional<bool>(true) ||
        !jsonStringIs(*PCIInitializationSuccess, "provenance", "guest-dma") ||
        !PCIInitializationFailure ||
        PCIInitializationFailure->getBoolean("initialized") !=
            std::optional<bool>(true) ||
        !jsonStringIs(*PCIInitializationFailure, "provenance",
                      "deterministic-or-unknown") ||
        !PCIInitializationPrerequisite ||
        !jsonStringIs(*PCIInitializationPrerequisite, "attributes",
                      "MEMTXATTRS_UNSPECIFIED") ||
        !jsonIntegerIs(*PCIInitializationPrerequisite, "memory", 0))
      return Invalid("PCI summary effect differs");

    SelectiveSummaries.push_back(SelectiveDMASummary{
        "pci_dma_read",
        "static-inline:include/hw/pci/pci_device.h:pci_dma_read",
        PCIPrototype.str(), "include/hw/pci/pci_device.h",
        PCIPrototypeSHA.str(), 276, 27, SelectiveSummaryDirection::ToDevice,
        SelectiveSummaryEffect::FullTransfer});

    if (Bytes.size() != 189228 ||
        llvm::toHex(llvm::SHA256::hash(llvm::arrayRefFromStringRef(Bytes)),
                    /*LowerCase=*/true) != "32269e160a6180c60c9e2eb2ea7d8ba3812"
                                           "0e2ff47d4daf1891b38c3753716fa") {
      SelectiveSummaries.clear();
      return Invalid("sealed byte identity differs");
    }

    SelectiveSummaryManifest = Path.str();
    SelectiveSummaryFormat = 2;
    return true;
  }

  static bool directDMATypeMatches(QualType Actual, StringRef Expected) {
    return normalizeDirectDMAContractType(Actual.getAsString()) ==
           normalizeDirectDMAContractType(Expected);
  }

  static bool catalogDeclarationSourceMatches(const Decl *Declaration,
                                              StringRef Expected,
                                              const SourceManager &SM) {
    if (!Declaration || Expected.empty())
      return false;
    PresumedLoc Location = SM.getPresumedLoc(Declaration->getLocation());
    if (Location.isInvalid())
      return false;
    std::string File = Location.getFilename();
    std::replace(File.begin(), File.end(), '\\', '/');
    StringRef Normalized(File);
    return Normalized == Expected ||
           (Normalized.size() > Expected.size() &&
            Normalized.ends_with(Expected) &&
            Normalized[Normalized.size() - Expected.size() - 1] == '/');
  }

  static bool catalogRangeIsValid(unsigned Begin, unsigned Count,
                                  unsigned Total) {
    return Begin <= Total && Count <= Total - Begin;
  }

  static bool callbackBindingIsWellFormed(
      const qemu_contracts_generated::CallbackBindingRecord &Binding) {
    if (StringRef(Binding.ID).empty() || StringRef(Binding.Family) != "usb" ||
        StringRef(Binding.SlotRecordType).empty() ||
        StringRef(Binding.SlotField).empty() ||
        StringRef(Binding.SlotHeader).empty() ||
        StringRef(Binding.SlotImplementation).empty() ||
        StringRef(Binding.Prototype).empty() ||
        StringRef(Binding.RegistrationRecordType).empty() ||
        StringRef(Binding.RegistrationField).empty() ||
        StringRef(Binding.RegistrationHeader).empty() ||
        StringRef(Binding.RegistrationVariable).empty() ||
        StringRef(Binding.RegistrationInitializer).empty() ||
        StringRef(Binding.RegistrationPrototype).empty() ||
        Binding.RuleCount == 0 || Binding.ParameterCount == 0 ||
        Binding.EntryInputCount == 0 ||
        !catalogRangeIsValid(
            Binding.RuleBegin, Binding.RuleCount,
            qemu_contracts_generated::CallbackRuleRecordCount) ||
        !catalogRangeIsValid(
            Binding.ParameterBegin, Binding.ParameterCount,
            qemu_contracts_generated::CallbackParameterRecordCount) ||
        !catalogRangeIsValid(
            Binding.EntryInputBegin, Binding.EntryInputCount,
            qemu_contracts_generated::CallbackEntryInputRecordCount) ||
        !catalogRangeIsValid(
            Binding.InputBufferBegin, Binding.InputBufferCount,
            qemu_contracts_generated::CallbackInputBufferRecordCount))
      return false;

    bool HasGuestMemoryBounds = false;
    bool HasCallbackBufferBounds = false;
    for (unsigned I = Binding.RuleBegin,
                  E = Binding.RuleBegin + Binding.RuleCount;
         I != E; ++I) {
      const auto &Rule = qemu_contracts_generated::CallbackRules[I];
      if (StringRef(Rule.CallbackID) != Binding.ID ||
          StringRef(Rule.RuleID).empty())
        return false;
      if (StringRef(Rule.RuleID) == stableID(GuestMemoryBoundsRuleID))
        HasGuestMemoryBounds = true;
      if (StringRef(Rule.RuleID) == stableID(CallbackBufferBoundsRuleID))
        HasCallbackBufferBounds = true;
      for (unsigned Previous = Binding.RuleBegin; Previous != I; ++Previous)
        if (StringRef(
                qemu_contracts_generated::CallbackRules[Previous].RuleID) ==
            Rule.RuleID)
          return false;
    }
    if (!HasGuestMemoryBounds ||
        HasCallbackBufferBounds != (Binding.InputBufferCount != 0))
      return false;

    for (unsigned I = 0; I != Binding.ParameterCount; ++I) {
      const auto &Parameter =
          qemu_contracts_generated::CallbackParameters[Binding.ParameterBegin +
                                                       I];
      if (StringRef(Parameter.CallbackID) != Binding.ID ||
          Parameter.Index != I || StringRef(Parameter.Name).empty() ||
          StringRef(Parameter.Type).empty())
        return false;
    }

    for (unsigned I = Binding.EntryInputBegin,
                  E = Binding.EntryInputBegin + Binding.EntryInputCount;
         I != E; ++I) {
      const auto &Input = qemu_contracts_generated::CallbackEntryInputs[I];
      if (StringRef(Input.CallbackID) != Binding.ID ||
          StringRef(Input.Role).empty() ||
          Input.ArgumentIndex >= Binding.ParameterCount)
        return false;
      for (unsigned Previous = Binding.EntryInputBegin; Previous != I;
           ++Previous)
        if (StringRef(
                qemu_contracts_generated::CallbackEntryInputs[Previous].Role) ==
            Input.Role)
          return false;

      StringRef Source = Input.Source;
      if (Source == "argument") {
        if (Input.MemberStepBegin != 0 || Input.MemberStepCount != 0)
          return false;
        continue;
      }
      if (Source != "argument_member" || Input.MemberStepCount == 0 ||
          !catalogRangeIsValid(
              Input.MemberStepBegin, Input.MemberStepCount,
              qemu_contracts_generated::CallbackMemberStepRecordCount))
        return false;
      for (unsigned StepIndex = Input.MemberStepBegin,
                    StepEnd = StepIndex + Input.MemberStepCount;
           StepIndex != StepEnd; ++StepIndex) {
        const auto &Step =
            qemu_contracts_generated::CallbackMemberSteps[StepIndex];
        if (StringRef(Step.CallbackID) != Binding.ID ||
            StringRef(Step.InputRole) != Input.Role ||
            StringRef(Step.RecordType).empty() ||
            StringRef(Step.Field).empty() || StringRef(Step.Type).empty() ||
            StringRef(Step.Header).empty())
          return false;
      }
    }

    for (unsigned I = Binding.InputBufferBegin,
                  E = Binding.InputBufferBegin + Binding.InputBufferCount;
         I != E; ++I) {
      const auto &Buffer = qemu_contracts_generated::CallbackInputBuffers[I];
      if (StringRef(Buffer.CallbackID) != Binding.ID ||
          Buffer.BufferArgumentIndex >= Binding.ParameterCount ||
          Buffer.LengthArgumentIndex >= Binding.ParameterCount ||
          Buffer.SelectorArgumentIndex >= Binding.ParameterCount ||
          Buffer.SelectorMask == 0 ||
          (Buffer.SelectorValue & ~Buffer.SelectorMask) != 0)
        return false;
      bool HasLengthInput = false;
      bool HasSelectorInput = false;
      for (unsigned
               InputIndex = Binding.EntryInputBegin,
               InputEnd = Binding.EntryInputBegin + Binding.EntryInputCount;
           InputIndex != InputEnd; ++InputIndex) {
        const auto &Input =
            qemu_contracts_generated::CallbackEntryInputs[InputIndex];
        if (StringRef(Input.Source) != "argument")
          continue;
        HasLengthInput |= Input.ArgumentIndex == Buffer.LengthArgumentIndex;
        HasSelectorInput |= Input.ArgumentIndex == Buffer.SelectorArgumentIndex;
      }
      if (!HasLengthInput || !HasSelectorInput)
        return false;
      for (unsigned Previous = Binding.InputBufferBegin; Previous != I;
           ++Previous) {
        const auto &Earlier =
            qemu_contracts_generated::CallbackInputBuffers[Previous];
        if (Earlier.BufferArgumentIndex == Buffer.BufferArgumentIndex)
          return false;
      }
    }
    return true;
  }

  static bool callbackFunctionPrototypeMatches(
      const FunctionDecl *FD,
      const qemu_contracts_generated::CallbackBindingRecord &Binding) {
    if (!FD || !FD->getDeclContext()->getRedeclContext()->isTranslationUnit() ||
        !FD->getLexicalDeclContext()->getRedeclContext()->isTranslationUnit() ||
        FD->isVariadic() || FD->getNumParams() != Binding.ParameterCount ||
        !directDMATypeMatches(FD->getType(), Binding.Prototype))
      return false;
    for (unsigned I = 0; I != Binding.ParameterCount; ++I) {
      const auto &Parameter =
          qemu_contracts_generated::CallbackParameters[Binding.ParameterBegin +
                                                       I];
      if (!directDMATypeMatches(FD->getParamDecl(I)->getType(), Parameter.Type))
        return false;
    }
    return true;
  }

  static bool catalogFunctionPointerMatches(QualType Type,
                                            StringRef Prototype) {
    return !Type.isNull() && Type->isPointerType() &&
           Type->getPointeeType()->isFunctionProtoType() &&
           directDMATypeMatches(Type->getPointeeType(), Prototype);
  }

  static const RecordDecl *exactCatalogRecord(QualType Type,
                                              StringRef RecordName,
                                              StringRef Header,
                                              const SourceManager &SM) {
    const RecordDecl *Record = catalogRecord(Type, RecordName);
    return catalogDeclarationSourceMatches(Record, Header, SM) ? Record
                                                               : nullptr;
  }

  static const ValueDecl *exactCatalogField(const RecordDecl *Record,
                                            StringRef FieldName,
                                            StringRef FieldType,
                                            StringRef Header,
                                            const SourceManager &SM) {
    if (!Record)
      return nullptr;
    const ValueDecl *Found = nullptr;
    auto Consider = [&](const ValueDecl *Candidate) {
      if (!Candidate || Candidate->getName() != FieldName || Found ||
          (!FieldType.empty() &&
           !directDMATypeMatches(Candidate->getType(), FieldType)) ||
          !catalogDeclarationSourceMatches(Candidate, Header, SM))
        return false;
      if (const auto *Indirect = dyn_cast<IndirectFieldDecl>(Candidate))
        for (const NamedDecl *Element : Indirect->chain())
          if (!catalogDeclarationSourceMatches(cast<FieldDecl>(Element), Header,
                                               SM))
            return false;
      Found = Candidate;
      return true;
    };

    for (const FieldDecl *Field : Record->fields())
      if (Field->getName() == FieldName && !Consider(Field))
        return nullptr;
    for (const Decl *Declaration : Record->decls())
      if (const auto *Indirect = dyn_cast<IndirectFieldDecl>(Declaration))
        if (Indirect->getName() == FieldName && !Consider(Indirect))
          return nullptr;
    return Found;
  }

  static SVal catalogFieldLValue(ProgramStateRef State, const ValueDecl *Field,
                                 SVal Object) {
    if (const auto *Direct = dyn_cast<FieldDecl>(Field))
      return State->getLValue(Direct, Object);
    return State->getLValue(cast<IndirectFieldDecl>(Field), Object);
  }

  static bool callbackMemberInputsMatch(
      const FunctionDecl *FD,
      const qemu_contracts_generated::CallbackBindingRecord &Binding,
      const SourceManager &SM) {
    for (unsigned I = Binding.EntryInputBegin,
                  E = Binding.EntryInputBegin + Binding.EntryInputCount;
         I != E; ++I) {
      const auto &Input = qemu_contracts_generated::CallbackEntryInputs[I];
      if (StringRef(Input.Source) != "argument_member")
        continue;
      QualType ObjectType = FD->getParamDecl(Input.ArgumentIndex)->getType();
      for (unsigned StepIndex = Input.MemberStepBegin,
                    StepEnd = StepIndex + Input.MemberStepCount;
           StepIndex != StepEnd; ++StepIndex) {
        const auto &Step =
            qemu_contracts_generated::CallbackMemberSteps[StepIndex];
        const RecordDecl *Record =
            exactCatalogRecord(ObjectType, Step.RecordType, Step.Header, SM);
        const ValueDecl *Field =
            exactCatalogField(Record, Step.Field, Step.Type, Step.Header, SM);
        if (!Field)
          return false;
        ObjectType = Field->getType();
        if (StepIndex + 1 != StepEnd && !ObjectType->isPointerType() &&
            !ObjectType->isRecordType())
          return false;
      }
    }
    return true;
  }

  static const FunctionDecl *catalogClassInitRoot(
      const VarDecl *VD,
      const qemu_contracts_generated::CallbackBindingRecord &Binding,
      const SourceManager &SM) {
    if (!VD || !callbackBindingIsWellFormed(Binding) ||
        !VD->getDeclContext()->getRedeclContext()->isTranslationUnit() ||
        !VD->getLexicalDeclContext()->getRedeclContext()->isTranslationUnit())
      return nullptr;
    const InitListExpr *Initializer = semanticInitList(VD->getInit());
    if (!Initializer)
      return nullptr;
    const RecordDecl *Record = exactCatalogRecord(
        Initializer->getType(), Binding.RegistrationRecordType,
        Binding.RegistrationHeader, SM);
    const FieldDecl *Field = dyn_cast_or_null<FieldDecl>(
        exactCatalogField(Record, Binding.RegistrationField, StringRef(),
                          Binding.RegistrationHeader, SM));
    if (!Field || !catalogFunctionPointerMatches(Field->getType(),
                                                 Binding.RegistrationPrototype))
      return nullptr;
    const FunctionDecl *FD = referencedFunction(
        fieldInitializer(Initializer, Binding.RegistrationField));
    if (!FD || !FD->getDeclContext()->getRedeclContext()->isTranslationUnit() ||
        !FD->getLexicalDeclContext()->getRedeclContext()->isTranslationUnit() ||
        FD->isVariadic() ||
        !directDMATypeMatches(FD->getType(), Binding.RegistrationPrototype) ||
        !FD->getDefinition())
      return nullptr;
    return FD->getCanonicalDecl();
  }

  static std::optional<
      std::pair<const FunctionDecl *,
                const qemu_contracts_generated::CallbackBindingRecord *>>
  catalogCallbackAssignment(
      const BinaryOperator *Assignment,
      ArrayRef<const qemu_contracts_generated::CallbackBindingRecord *>
          AllowedBindings,
      const SourceManager &SM) {
    if (!Assignment || Assignment->getOpcode() != BO_Assign)
      return std::nullopt;
    const auto *Member =
        dyn_cast<MemberExpr>(Assignment->getLHS()->IgnoreParenImpCasts());
    const auto *Field =
        Member ? dyn_cast<FieldDecl>(Member->getMemberDecl()) : nullptr;
    const auto *Parent =
        Field ? dyn_cast<RecordDecl>(Field->getDeclContext()) : nullptr;
    if (!Field || !Parent)
      return std::nullopt;
    if (const RecordDecl *Definition = Parent->getDefinition())
      Parent = Definition;

    const FunctionDecl *FD = referencedFunction(Assignment->getRHS());
    const qemu_contracts_generated::CallbackBindingRecord *Found = nullptr;
    for (const auto *Binding : AllowedBindings) {
      if (!Binding || !callbackBindingIsWellFormed(*Binding) ||
          StringRef(Binding->SlotRecordType) != Parent->getName() ||
          StringRef(Binding->SlotField) != Field->getName() ||
          !catalogDeclarationSourceMatches(Parent, Binding->SlotHeader, SM) ||
          !catalogDeclarationSourceMatches(Field, Binding->SlotHeader, SM) ||
          !catalogFunctionPointerMatches(Field->getType(),
                                         Binding->Prototype) ||
          exactCatalogRecord(Member->getBase()->getType(),
                             Binding->SlotRecordType, Binding->SlotHeader,
                             SM) != Parent ||
          !callbackFunctionPrototypeMatches(FD, *Binding) ||
          !callbackMemberInputsMatch(FD, *Binding, SM))
        continue;
      if (Found)
        return std::nullopt;
      Found = Binding;
    }
    if (!Found)
      return std::nullopt;
    return std::make_pair(FD->getCanonicalDecl(), Found);
  }

  void addCatalogCallback(
      const FunctionDecl *FD,
      const qemu_contracts_generated::CallbackBindingRecord &Binding) const {
    uint64_t ParameterMask = 0;
    llvm::SmallVector<
        const qemu_contracts_generated::CallbackEntryInputRecord *, 8>
        MemberInputs;
    for (unsigned I = Binding.EntryInputBegin,
                  E = Binding.EntryInputBegin + Binding.EntryInputCount;
         I != E; ++I) {
      const auto *Input = &qemu_contracts_generated::CallbackEntryInputs[I];
      if (StringRef(Input->Source) == "argument") {
        if (Input->ArgumentIndex >= 64)
          return;
        ParameterMask |= uint64_t(1) << Input->ArgumentIndex;
      } else if (StringRef(Input->Source) == "argument_member") {
        MemberInputs.push_back(Input);
      } else {
        return;
      }
    }

    llvm::SmallVector<CallbackBufferInfo, 2> InputBuffers;
    for (unsigned I = Binding.InputBufferBegin,
                  E = Binding.InputBufferBegin + Binding.InputBufferCount;
         I != E; ++I) {
      const auto &Buffer = qemu_contracts_generated::CallbackInputBuffers[I];
      if (StringRef(Buffer.CallbackID) != Binding.ID ||
          Buffer.BufferArgumentIndex >= FD->getNumParams() ||
          Buffer.LengthArgumentIndex >= FD->getNumParams() ||
          Buffer.SelectorArgumentIndex >= FD->getNumParams())
        return;
      QualType BufferType =
          FD->getParamDecl(Buffer.BufferArgumentIndex)->getType();
      QualType LengthType =
          FD->getParamDecl(Buffer.LengthArgumentIndex)->getType();
      QualType SelectorType =
          FD->getParamDecl(Buffer.SelectorArgumentIndex)->getType();
      QualType ElementType = BufferType->isPointerType()
                                 ? BufferType->getPointeeType()
                                 : QualType();
      ASTContext &Context = FD->getASTContext();
      if (ElementType.isNull() || !ElementType->isIntegerType() ||
          Context.getTypeSize(ElementType) != 8 ||
          !LengthType->isIntegerType() || !SelectorType->isIntegerType())
        return;
      unsigned SelectorWidth = Context.getIntWidth(SelectorType);
      if (SelectorWidth > 64 ||
          (SelectorWidth < 64 &&
           ((Buffer.SelectorMask >> SelectorWidth) != 0 ||
            (Buffer.SelectorValue >> SelectorWidth) != 0)))
        return;
      InputBuffers.push_back(
          {Buffer.BufferArgumentIndex, CallbackBufferLengthKind::Parameter,
           Buffer.LengthArgumentIndex, 0, Buffer.SelectorArgumentIndex,
           Buffer.SelectorMask, Buffer.SelectorValue});
    }

    FD = FD->getCanonicalDecl();
    addCallback(FD, InputClass::USB, ParameterMask);
    CallbackInfo &Info = Callbacks[FD];
    for (const auto *Input : MemberInputs)
      if (!llvm::any_of(Info.MemberInputs, [&](const auto *Existing) {
            return Existing == Input;
          }))
        Info.MemberInputs.push_back(Input);
    for (const CallbackBufferInfo &Buffer : InputBuffers) {
      bool Duplicate = llvm::any_of(Info.Buffers, [&](const auto &Existing) {
        return Existing.BufferParameter == Buffer.BufferParameter &&
               Existing.LengthKind == Buffer.LengthKind &&
               Existing.LengthParameter == Buffer.LengthParameter &&
               Existing.FixedLength == Buffer.FixedLength &&
               Existing.SelectorParameter == Buffer.SelectorParameter &&
               Existing.SelectorMask == Buffer.SelectorMask &&
               Existing.SelectorValue == Buffer.SelectorValue;
      });
      if (!Duplicate)
        Info.Buffers.push_back(Buffer);
    }
    recordCallbackRegistration(FD, Binding.ID);
  }

  static std::optional<SVal> callbackMemberValue(
      const FunctionDecl *FD,
      const qemu_contracts_generated::CallbackEntryInputRecord &Input,
      ProgramStateRef State, const StackFrame *Frame, const SourceManager &SM) {
    if (!FD || StringRef(Input.Source) != "argument_member" ||
        Input.ArgumentIndex >= FD->getNumParams() ||
        Input.MemberStepCount == 0 ||
        !catalogRangeIsValid(
            Input.MemberStepBegin, Input.MemberStepCount,
            qemu_contracts_generated::CallbackMemberStepRecordCount))
      return std::nullopt;

    const ParmVarDecl *Parameter = FD->getParamDecl(Input.ArgumentIndex);
    SVal Object = State->getSVal(State->getRegion(Parameter, Frame));
    QualType ObjectType = Parameter->getType();
    for (unsigned I = Input.MemberStepBegin,
                  E = Input.MemberStepBegin + Input.MemberStepCount;
         I != E; ++I) {
      const auto &Step = qemu_contracts_generated::CallbackMemberSteps[I];
      if (StringRef(Step.CallbackID) != Input.CallbackID ||
          StringRef(Step.InputRole) != Input.Role)
        return std::nullopt;
      const RecordDecl *Record =
          exactCatalogRecord(ObjectType, Step.RecordType, Step.Header, SM);
      const ValueDecl *Field =
          exactCatalogField(Record, Step.Field, Step.Type, Step.Header, SM);
      if (!Field)
        return std::nullopt;
      SVal FieldLocation = catalogFieldLValue(State, Field, Object);
      auto Location = FieldLocation.getAs<Loc>();
      if (!Location)
        return std::nullopt;
      if (I + 1 == E) {
        SVal Value = State->getSVal(*Location);
        return Value.isUnknownOrUndef() ? std::nullopt
                                        : std::optional<SVal>(Value);
      }

      ObjectType = Field->getType();
      if (ObjectType->isPointerType()) {
        Object = State->getSVal(*Location);
        if (!Object.getAs<Loc>())
          return std::nullopt;
      } else if (ObjectType->isRecordType()) {
        Object = FieldLocation;
      } else {
        return std::nullopt;
      }
    }
    return std::nullopt;
  }

  static std::string callbackMemberName(
      const FunctionDecl *FD,
      const qemu_contracts_generated::CallbackEntryInputRecord &Input) {
    std::string Name = FD->getParamDecl(Input.ArgumentIndex)->getNameAsString();
    for (unsigned I = Input.MemberStepBegin,
                  E = Input.MemberStepBegin + Input.MemberStepCount;
         I != E; ++I) {
      Name += ".";
      Name += qemu_contracts_generated::CallbackMemberSteps[I].Field;
    }
    return Name;
  }

  static bool directDMAPrototypeMatches(
      const FunctionDecl *FD,
      const qemu_contracts_generated::ContractRecord &Contract) {
    if (!FD->getDeclContext()->getRedeclContext()->isTranslationUnit() ||
        !FD->getLexicalDeclContext()->getRedeclContext()->isTranslationUnit() ||
        FD->isVariadic() || FD->getNumParams() != Contract.ParameterCount ||
        !directDMATypeMatches(FD->getReturnType(), Contract.ReturnType) ||
        Contract.ParameterBegin + Contract.ParameterCount >
            qemu_contracts_generated::ParameterRecordCount)
      return false;

    for (unsigned I = 0; I != Contract.ParameterCount; ++I) {
      const auto &Parameter =
          qemu_contracts_generated::Parameters[Contract.ParameterBegin + I];
      if (StringRef(Parameter.ContractID) != Contract.ID ||
          Parameter.Index != I ||
          !directDMATypeMatches(FD->getParamDecl(I)->getType(), Parameter.Type))
        return false;
    }
    return true;
  }

  static const qemu_contracts_generated::ContractRecord *
  directDMAContract(const FunctionDecl *FD, StringRef Kind) {
    if (!FD || !FD->getIdentifier())
      return nullptr;
    for (const auto &Contract : qemu_contracts_generated::Contracts)
      if (StringRef(Contract.Kind) == Kind &&
          StringRef(Contract.SelectorName) == FD->getName() &&
          directDMAPrototypeMatches(FD, Contract))
        return &Contract;
    return nullptr;
  }

  static bool contractHasOnlyAdditionalRule(
      const qemu_contracts_generated::ContractRecord &Contract,
      qemu::facts::RuleIDRef RuleID) {
    if (Contract.AdditionalRuleCount != 1 ||
        Contract.AdditionalRuleBegin >=
            qemu_contracts_generated::ContractAdditionalRuleRecordCount)
      return false;
    const auto &Additional = qemu_contracts_generated::ContractAdditionalRules
        [Contract.AdditionalRuleBegin];
    return StringRef(Additional.ContractID) == Contract.ID &&
           StringRef(Additional.RuleID) == stableID(RuleID);
  }

  static const qemu_contracts_generated::OperandRecord *
  contractOperand(const qemu_contracts_generated::ContractRecord &Contract,
                  StringRef Role) {
    if (Contract.OperandBegin > qemu_contracts_generated::OperandRecordCount ||
        Contract.OperandCount > qemu_contracts_generated::OperandRecordCount -
                                    Contract.OperandBegin)
      return nullptr;
    const qemu_contracts_generated::OperandRecord *Result = nullptr;
    for (unsigned I = Contract.OperandBegin,
                  E = Contract.OperandBegin + Contract.OperandCount;
         I != E; ++I) {
      const auto &Operand = qemu_contracts_generated::Operands[I];
      if (StringRef(Operand.ContractID) != Contract.ID)
        return nullptr;
      if (StringRef(Operand.Role) != Role)
        continue;
      if (Result)
        return nullptr;
      Result = &Operand;
    }
    return Result;
  }

  static std::optional<unsigned>
  directDMAArgument(const qemu_contracts_generated::ContractRecord &Contract,
                    StringRef Role, StringRef Source,
                    StringRef Phase = StringRef()) {
    const auto *Operand = contractOperand(Contract, Role);
    if (!Operand || StringRef(Operand->Source) != Source ||
        (!Phase.empty() && StringRef(Operand->Phase) != Phase) ||
        Operand->ArgumentIndex < 0)
      return std::nullopt;
    return static_cast<unsigned>(Operand->ArgumentIndex);
  }

  static const qemu_contracts_generated::OperandRecord *
  catalogMemberOperand(const qemu_contracts_generated::ContractRecord &Contract,
                       StringRef Role, unsigned Argument) {
    const auto *Operand = contractOperand(Contract, Role);
    if (!Operand || StringRef(Operand->Source) != "argument_member" ||
        StringRef(Operand->Phase) != "pre" || Operand->ArgumentIndex < 0 ||
        static_cast<unsigned>(Operand->ArgumentIndex) != Argument ||
        Operand->MemberStepCount == 0 ||
        Operand->MemberStepBegin >
            qemu_contracts_generated::MemberStepRecordCount ||
        Operand->MemberStepCount >
            qemu_contracts_generated::MemberStepRecordCount -
                Operand->MemberStepBegin)
      return nullptr;
    for (unsigned I = Operand->MemberStepBegin,
                  E = I + Operand->MemberStepCount;
         I != E; ++I) {
      const auto &Step = qemu_contracts_generated::MemberSteps[I];
      if (StringRef(Step.ContractID) != Contract.ID ||
          StringRef(Step.OperandRole) != Role ||
          StringRef(Step.RecordType).empty() || StringRef(Step.Field).empty() ||
          StringRef(Step.Type).empty() || StringRef(Step.Header).empty())
        return nullptr;
    }
    return Operand;
  }

  static const RecordDecl *catalogRecord(QualType Type,
                                         StringRef ExpectedName) {
    if (Type.isNull())
      return nullptr;
    if (Type->isPointerType())
      Type = Type->getPointeeType();
    const RecordDecl *Record = Type.getUnqualifiedType()->getAsRecordDecl();
    if (!Record)
      return nullptr;
    if (const RecordDecl *Definition = Record->getDefinition())
      Record = Definition;
    return Record->getName() == ExpectedName ? Record : nullptr;
  }

  static const FieldDecl *catalogField(const RecordDecl *Record,
                                       StringRef Name) {
    if (!Record)
      return nullptr;
    const FieldDecl *Found = nullptr;
    for (const FieldDecl *Field : Record->fields()) {
      if (Field->getName() != Name)
        continue;
      if (Found)
        return nullptr;
      Found = Field;
    }
    return Found;
  }

  struct CatalogMemberLocation {
    Loc Location;
    QualType Type;
  };

  static std::optional<CatalogMemberLocation>
  catalogMemberLocation(const CallEvent &Call,
                        const qemu_contracts_generated::OperandRecord &Operand,
                        ProgramStateRef State) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || Operand.ArgumentIndex < 0 ||
        static_cast<unsigned>(Operand.ArgumentIndex) >= Call.getNumArgs() ||
        static_cast<unsigned>(Operand.ArgumentIndex) >= FD->getNumParams() ||
        Operand.MemberStepCount == 0 ||
        Operand.MemberStepBegin >
            qemu_contracts_generated::MemberStepRecordCount ||
        Operand.MemberStepCount >
            qemu_contracts_generated::MemberStepRecordCount -
                Operand.MemberStepBegin)
      return std::nullopt;

    SVal Object = Call.getArgSVal(Operand.ArgumentIndex);
    QualType ObjectType = FD->getParamDecl(Operand.ArgumentIndex)->getType();
    for (unsigned I = Operand.MemberStepBegin, E = I + Operand.MemberStepCount;
         I != E; ++I) {
      const auto &Step = qemu_contracts_generated::MemberSteps[I];
      if (StringRef(Step.ContractID) != Operand.ContractID ||
          StringRef(Step.OperandRole) != Operand.Role)
        return std::nullopt;
      const RecordDecl *Record = catalogRecord(ObjectType, Step.RecordType);
      const FieldDecl *Field = catalogField(Record, Step.Field);
      if (!Field || !directDMATypeMatches(Field->getType(), Step.Type))
        return std::nullopt;
      SVal FieldLocation = State->getLValue(Field, Object);
      auto Location = FieldLocation.getAs<Loc>();
      if (!Location)
        return std::nullopt;
      if (I + 1 == E)
        return CatalogMemberLocation{*Location, Field->getType()};

      ObjectType = Field->getType();
      if (ObjectType->isPointerType()) {
        Object = State->getSVal(*Location);
        if (!Object.getAs<Loc>())
          return std::nullopt;
      } else if (ObjectType->isRecordType()) {
        Object = FieldLocation;
      } else {
        return std::nullopt;
      }
    }
    return std::nullopt;
  }

  static std::optional<SVal>
  catalogMemberValue(const CallEvent &Call,
                     const qemu_contracts_generated::OperandRecord &Operand,
                     ProgramStateRef State) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || Operand.ArgumentIndex < 0 ||
        static_cast<unsigned>(Operand.ArgumentIndex) >= Call.getNumArgs() ||
        static_cast<unsigned>(Operand.ArgumentIndex) >= FD->getNumParams() ||
        Operand.MemberStepCount == 0 ||
        Operand.MemberStepBegin >
            qemu_contracts_generated::MemberStepRecordCount ||
        Operand.MemberStepCount >
            qemu_contracts_generated::MemberStepRecordCount -
                Operand.MemberStepBegin)
      return std::nullopt;

    SVal Object = Call.getArgSVal(Operand.ArgumentIndex);
    QualType ObjectType = FD->getParamDecl(Operand.ArgumentIndex)->getType();
    for (unsigned I = Operand.MemberStepBegin, E = I + Operand.MemberStepCount;
         I != E; ++I) {
      const auto &Step = qemu_contracts_generated::MemberSteps[I];
      if (StringRef(Step.ContractID) != Operand.ContractID ||
          StringRef(Step.OperandRole) != Operand.Role)
        return std::nullopt;
      const RecordDecl *Record = catalogRecord(ObjectType, Step.RecordType);
      const FieldDecl *Field = catalogField(Record, Step.Field);
      if (!Field || !directDMATypeMatches(Field->getType(), Step.Type))
        return std::nullopt;
      SVal FieldLocation = State->getLValue(Field, Object);
      auto Location = FieldLocation.getAs<Loc>();
      if (!Location)
        return std::nullopt;
      if (I + 1 == E) {
        SVal Value = State->getSVal(*Location);
        return Value.isUnknownOrUndef() ? std::nullopt
                                        : std::optional<SVal>(Value);
      }

      ObjectType = Field->getType();
      if (ObjectType->isPointerType()) {
        Object = State->getSVal(*Location);
        if (!Object.getAs<Loc>())
          return std::nullopt;
      } else if (ObjectType->isRecordType()) {
        Object = FieldLocation;
      } else {
        return std::nullopt;
      }
    }
    return std::nullopt;
  }

  static std::optional<USBPacketCopyDescriptor>
  usbPacketCopyDescriptor(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() || !FD->getReturnType()->isVoidType())
      return std::nullopt;
    const auto *Contract = directDMAContract(FD, "packet-copy");
    if (!Contract || StringRef(Contract->Family) != "usb" ||
        StringRef(Contract->RuleID) !=
            stableID(InitializedBytesDisclosureRuleID) ||
        !contractHasOnlyAdditionalRule(*Contract, GuestMemoryBoundsRuleID) ||
        StringRef(Contract->DirectionEncoding) != "usb-token-pid" ||
        StringRef(Contract->SuccessPredicateJSON) != "{\"constant\":true}" ||
        StringRef(Contract->PartialSuccessPredicateJSON) !=
            "{\"constant\":false}" ||
        StringRef(Contract->FailurePredicateJSON) != "{\"constant\":false}" ||
        Contract->OperandCount != 11 || Contract->EffectCount != 1 ||
        Contract->EffectBegin >= qemu_contracts_generated::EffectRecordCount)
      return std::nullopt;

    const auto &Effect =
        qemu_contracts_generated::Effects[Contract->EffectBegin];
    if (StringRef(Effect.ContractID) != Contract->ID ||
        StringRef(Effect.Kind) != "packet-copy" ||
        StringRef(Effect.When) != "success" ||
        StringRef(Effect.Target) != "host_buffer" ||
        StringRef(Effect.Extent) != "transfer_length" ||
        StringRef(Effect.Direction) != "direction" ||
        StringRef(Effect.Owner) != "owner" ||
        StringRef(Effect.Offset) != "access_offset" ||
        StringRef(Effect.CapacitySelector) != "capacity_selector" ||
        StringRef(Effect.PrimaryCapacity) != "primary_capacity" ||
        StringRef(Effect.AlternateCapacity) != "alternate_capacity" ||
        !StringRef(Effect.RequestedExtent).empty() ||
        !StringRef(Effect.AccessExtent).empty() ||
        !StringRef(Effect.Epoch).empty())
      return std::nullopt;

    std::optional<unsigned> PacketArgument =
        directDMAArgument(*Contract, "owner", "argument", "pre");
    std::optional<unsigned> HostBufferArgument =
        directDMAArgument(*Contract, "host_buffer", "argument", "pre");
    std::optional<unsigned> LengthArgument =
        directDMAArgument(*Contract, "transfer_length", "argument", "pre");
    if (!PacketArgument || !HostBufferArgument || !LengthArgument ||
        *PacketArgument >= Contract->ParameterCount ||
        *HostBufferArgument >= Contract->ParameterCount ||
        *LengthArgument >= Contract->ParameterCount ||
        Call.getNumArgs() != Contract->ParameterCount)
      return std::nullopt;

    USBPacketCopyDescriptor Descriptor{
        Contract,
        *PacketArgument,
        *HostBufferArgument,
        *LengthArgument,
        catalogMemberOperand(*Contract, "direction", *PacketArgument),
        catalogMemberOperand(*Contract, "access_offset", *PacketArgument),
        catalogMemberOperand(*Contract, "capacity_selector", *PacketArgument),
        catalogMemberOperand(*Contract, "primary_capacity", *PacketArgument),
        catalogMemberOperand(*Contract, "alternate_capacity", *PacketArgument),
        catalogMemberOperand(*Contract, "status", *PacketArgument),
        catalogMemberOperand(*Contract, "endpoint_type", *PacketArgument),
        catalogMemberOperand(*Contract, "setup_parameter", *PacketArgument)};
    if (!Descriptor.Direction || !Descriptor.AccessOffset ||
        !Descriptor.CapacitySelector || !Descriptor.PrimaryCapacity ||
        !Descriptor.AlternateCapacity || !Descriptor.Status ||
        !Descriptor.EndpointType || !Descriptor.SetupParameter)
      return std::nullopt;
    return Descriptor;
  }

  static std::optional<qemu::facts::USBPacketDirection>
  usbPacketCopyDirection(const CallEvent &Call,
                         const USBPacketCopyDescriptor &Descriptor,
                         ProgramStateRef State, CheckerContext &C) {
    std::optional<SVal> PID =
        catalogMemberValue(Call, *Descriptor.Direction, State);
    if (!PID)
      return std::nullopt;
    QualType PIDType = PID->getType(C.getASTContext());
    if (PIDType.isNull() || !PIDType->isIntegerType())
      return std::nullopt;
    auto IsPID = [&](uint64_t Value) {
      SVal Token = C.getSValBuilder().makeIntVal(Value, PIDType);
      return isDefinitelyTrue(State, *PID, BO_EQ, Token, C.getSValBuilder());
    };
    if (IsPID(0x69))
      return qemu::facts::USBPacketDirection::DeviceToHost;
    if (IsPID(0xe1))
      return qemu::facts::USBPacketDirection::HostToDevice;
    if (IsPID(0x2d))
      return qemu::facts::USBPacketDirection::Setup;
    return std::nullopt;
  }

  struct USBPacketCapacity {
    SVal Value;
    qemu::facts::USBPacketBufferKind Buffer;
  };

  static std::optional<USBPacketCapacity>
  usbPacketCapacity(const CallEvent &Call,
                    const USBPacketCopyDescriptor &Descriptor,
                    ProgramStateRef State) {
    std::optional<SVal> Selector =
        catalogMemberValue(Call, *Descriptor.CapacitySelector, State);
    if (!Selector)
      return std::nullopt;
    auto Defined = Selector->getAs<DefinedOrUnknownSVal>();
    if (!Defined)
      return std::nullopt;
    auto [NonNull, Null] = State->assume(*Defined);
    const qemu_contracts_generated::OperandRecord *CapacityOperand = nullptr;
    qemu::facts::USBPacketBufferKind Buffer;
    if (Null && !NonNull) {
      CapacityOperand = Descriptor.PrimaryCapacity;
      Buffer = qemu::facts::USBPacketBufferKind::Direct;
    } else if (NonNull && !Null) {
      CapacityOperand = Descriptor.AlternateCapacity;
      Buffer = qemu::facts::USBPacketBufferKind::Combined;
    } else {
      return std::nullopt;
    }
    std::optional<SVal> Capacity =
        catalogMemberValue(Call, *CapacityOperand, State);
    if (!Capacity)
      return std::nullopt;
    return USBPacketCapacity{*Capacity, Buffer};
  }

  static ProgramStateRef recordUSBPacketTransaction(
      const CallEvent &Call, const USBPacketCopyDescriptor &Descriptor,
      qemu::facts::USBPacketDirection Direction, ProgramStateRef State) {
    const MemRegion *Packet =
        Call.getArgSVal(Descriptor.PacketArgument).getAsRegion();
    if (!Packet)
      return State;
    std::optional<USBPacketCapacity> Capacity =
        usbPacketCapacity(Call, Descriptor, State);
    std::optional<SVal> ActualLength =
        catalogMemberValue(Call, *Descriptor.AccessOffset, State);
    std::optional<SVal> Status =
        catalogMemberValue(Call, *Descriptor.Status, State);
    std::optional<SVal> EndpointType =
        catalogMemberValue(Call, *Descriptor.EndpointType, State);
    std::optional<SVal> SetupParameter =
        catalogMemberValue(Call, *Descriptor.SetupParameter, State);
    if (!Capacity || !ActualLength || !Status || !EndpointType ||
        !SetupParameter)
      return qemu::state::removeUSBTransaction(State, Packet);
    return qemu::state::setUSBTransaction(
        State, Packet, Call.getArgSVal(Descriptor.HostBufferArgument),
        Call.getArgSVal(Descriptor.LengthArgument), Capacity->Value,
        *ActualLength, *Status, *EndpointType, *SetupParameter, Direction,
        Capacity->Buffer, Call.getOriginExpr());
  }

  bool validateUSBPacketCopyBounds(const CallEvent &Call,
                                   const USBPacketCopyDescriptor &Descriptor,
                                   ProgramStateRef &State,
                                   CheckerContext &C) const {
    const MemRegion *Packet =
        Call.getArgSVal(Descriptor.PacketArgument).getAsRegion();
    const qemu::state::USBTransaction *Transaction =
        qemu::state::getUSBTransaction(State, Packet);
    if (!Transaction)
      return false;

    SVal ActualLength = Transaction->getActualLength();
    SVal RequestedLength = Transaction->getRequestedLength();
    SVal Capacity = Transaction->getCapacity();
    const auto Buffer = Transaction->getBuffer();
    ASTContext &Context = C.getASTContext();
    SValBuilder &SVB = C.getSValBuilder();
    QualType ActualType = ActualLength.getType(Context);
    QualType RequestedType = RequestedLength.getType(Context);
    QualType CapacityType = Capacity.getType(Context);
    QualType SizeType = Context.getSizeType();

    const auto Abandon = [&] {
      State = qemu::state::removeUSBTransaction(State, Packet);
    };
    if (ActualType.isNull() || RequestedType.isNull() ||
        CapacityType.isNull() || !ActualType->isIntegerType() ||
        !RequestedType->isIntegerType() || !CapacityType->isIntegerType()) {
      Abandon();
      return false;
    }

    enum class Proof { Proved, Violated, Unresolved };
    const auto Require = [&](SVal Left, BinaryOperatorKind Operation,
                             SVal Right,
                             USBPacketCopyBoundsViolation Violation) -> Proof {
      std::optional<BoundStates> Bounds =
          compare(State, Left, Operation, Right, SVB);
      if (!Bounds)
        return Proof::Unresolved;
      if (!Bounds->Safe) {
        reportUSBPacketCopyBounds(C, Bounds->Unsafe, Call.getOriginExpr(),
                                  ActualLength, RequestedLength, Capacity,
                                  Buffer, Violation);
        return Proof::Violated;
      }
      // A maybe-invalid relationship is intentionally not reported.  Retiring
      // the transaction below prevents an unproved range from being consumed
      // as a safe packet-copy summary.
      if (Bounds->Unsafe)
        return Proof::Unresolved;
      State = Bounds->Safe;
      return Proof::Proved;
    };

    Proof NonNegative =
        Require(ActualLength, BO_GE, SVB.makeZeroVal(ActualType),
                USBPacketCopyBoundsViolation::NegativeActualLength);
    if (NonNegative == Proof::Violated)
      return true;
    if (NonNegative == Proof::Unresolved) {
      Abandon();
      return false;
    }

    SVal UnsignedActual = SVB.evalCast(ActualLength, SizeType, ActualType);
    SVal UnsignedRequested =
        SVB.evalCast(RequestedLength, SizeType, RequestedType);
    SVal UnsignedCapacity = SVB.evalCast(Capacity, SizeType, CapacityType);
    if (UnsignedActual.isUnknownOrUndef() ||
        UnsignedRequested.isUnknownOrUndef() ||
        UnsignedCapacity.isUnknownOrUndef()) {
      Abandon();
      return false;
    }

    Proof OffsetWithin =
        Require(UnsignedActual, BO_LE, UnsignedCapacity,
                USBPacketCopyBoundsViolation::RangeExceedsCapacity);
    if (OffsetWithin == Proof::Violated)
      return true;
    if (OffsetWithin == Proof::Unresolved) {
      Abandon();
      return false;
    }

    // Subtraction expresses both requirements without evaluating a possibly
    // wrapping actual_length + bytes expression: actual_length is within the
    // selected capacity, and bytes must fit in the remaining suffix.
    SVal Remaining = SVB.evalBinOp(State, BO_Sub, UnsignedCapacity,
                                   UnsignedActual, SizeType);
    if (Remaining.isUnknownOrUndef()) {
      Abandon();
      return false;
    }
    Proof RequestedFits =
        Require(UnsignedRequested, BO_LE, Remaining,
                USBPacketCopyBoundsViolation::RangeExceedsCapacity);
    if (RequestedFits == Proof::Violated)
      return true;
    if (RequestedFits == Proof::Unresolved) {
      Abandon();
      return false;
    }

    // The helper stores the size_t sum back into the signed actual_length
    // field.  Prove that this conversion is representable as well as proving
    // that the size_t addition does not wrap.  Express the relation by
    // subtraction so the analyzer never has to evaluate an overflowing sum.
    llvm::APSInt ActualMaximum =
        SVB.getBasicValueFactory().getMaxValue(ActualType);
    SVal Maximum = SVB.makeIntVal(ActualMaximum);
    SVal UnsignedMaximum = SVB.evalCast(Maximum, SizeType, ActualType);
    if (UnsignedMaximum.isUnknownOrUndef()) {
      Abandon();
      return false;
    }
    SVal RepresentableRemaining =
        SVB.evalBinOp(State, BO_Sub, UnsignedMaximum, UnsignedActual, SizeType);
    if (RepresentableRemaining.isUnknownOrUndef()) {
      Abandon();
      return false;
    }
    Proof UpdateRepresentable = Require(
        UnsignedRequested, BO_LE, RepresentableRemaining,
        USBPacketCopyBoundsViolation::ActualLengthUpdateNotRepresentable);
    if (UpdateRepresentable == Proof::Violated)
      return true;
    if (UpdateRepresentable == Proof::Unresolved)
      Abandon();
    return false;
  }

  static ProgramStateRef
  advanceUSBPacketActualLength(const CallEvent &Call,
                               const USBPacketCopyDescriptor &Descriptor,
                               const qemu::state::USBTransaction &Transaction,
                               ProgramStateRef State, CheckerContext &C) {
    std::optional<CatalogMemberLocation> ActualLocation =
        catalogMemberLocation(Call, *Descriptor.AccessOffset, State);
    if (!ActualLocation || ActualLocation->Type.isNull() ||
        !ActualLocation->Type->isIntegerType())
      return State;

    ASTContext &Context = C.getASTContext();
    SValBuilder &SVB = C.getSValBuilder();
    SVal ActualLength = Transaction.getActualLength();
    SVal RequestedLength = Transaction.getRequestedLength();
    QualType ActualType = ActualLength.getType(Context);
    QualType RequestedType = RequestedLength.getType(Context);
    QualType SizeType = Context.getSizeType();
    if (ActualType.isNull() || RequestedType.isNull() ||
        !ActualType->isIntegerType() || !RequestedType->isIntegerType())
      return State;

    SVal UnsignedActual = SVB.evalCast(ActualLength, SizeType, ActualType);
    SVal UnsignedRequested =
        SVB.evalCast(RequestedLength, SizeType, RequestedType);
    if (UnsignedActual.isUnknownOrUndef() ||
        UnsignedRequested.isUnknownOrUndef())
      return State;
    SVal Advanced = SVB.evalBinOp(State, BO_Add, UnsignedActual,
                                  UnsignedRequested, SizeType);
    if (Advanced.isUnknownOrUndef())
      return State;
    SVal Stored = SVB.evalCast(Advanced, ActualLocation->Type, SizeType);
    if (Stored.isUnknownOrUndef())
      return State;
    SVal RoundTrip = SVB.evalCast(Stored, SizeType, ActualLocation->Type);
    if (RoundTrip.isUnknownOrUndef() ||
        !isDefinitelyTrue(State, RoundTrip, BO_EQ, Advanced, SVB))
      return State;
    return State->bindLoc(ActualLocation->Location, Stored, C.getStackFrame());
  }

  static std::optional<bool> directDMABooleanDirection(
      const qemu_contracts_generated::ContractRecord &Contract) {
    StringRef Encoding = Contract.DirectionEncoding;
    if (Encoding == "bool-is-write")
      return true;
    if (Encoding == "dma-direction")
      return false;
    return std::nullopt;
  }

  static std::optional<DirectDMAMapDescriptor>
  directDMAMapDescriptor(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() || !isVoidPointer(FD->getReturnType()))
      return std::nullopt;

    const auto *Contract = directDMAContract(FD, "map");
    if (!Contract)
      return std::nullopt;
    std::optional<unsigned> OwnerArgument =
        directDMAArgument(*Contract, "owner", "argument");
    std::optional<unsigned> LengthPointerArgument =
        directDMAArgument(*Contract, "mapped_length", "argument_pointee");
    std::optional<unsigned> DirectionArgument =
        directDMAArgument(*Contract, "direction", "argument");
    std::optional<bool> BooleanDirection = directDMABooleanDirection(*Contract);
    if (!LengthPointerArgument || !DirectionArgument || !BooleanDirection ||
        *LengthPointerArgument >= Contract->ParameterCount ||
        *DirectionArgument >= Contract->ParameterCount)
      return std::nullopt;
    if (OwnerArgument && *OwnerArgument >= Contract->ParameterCount)
      return std::nullopt;
    unsigned ParameterCount = Contract->ParameterCount;
    if (FD->getNumParams() != ParameterCount ||
        Call.getNumArgs() != ParameterCount)
      return std::nullopt;
    QualType LengthPointer =
        FD->getParamDecl(*LengthPointerArgument)->getType();
    if (!LengthPointer->isPointerType() ||
        !LengthPointer->getPointeeType()->isIntegerType())
      return std::nullopt;
    QualType Direction = FD->getParamDecl(*DirectionArgument)->getType();
    if (!Direction->isIntegralOrEnumerationType() ||
        Direction->isBooleanType() != *BooleanDirection)
      return std::nullopt;
    return DirectDMAMapDescriptor{OwnerArgument, *LengthPointerArgument,
                                  *DirectionArgument, *BooleanDirection};
  }

  static std::optional<DirectDMAUnmapDescriptor>
  directDMAUnmapDescriptor(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() || !FD->getReturnType()->isVoidType())
      return std::nullopt;
    const auto *Contract = directDMAContract(FD, "unmap");
    if (!Contract)
      return std::nullopt;
    std::optional<unsigned> OwnerArgument =
        directDMAArgument(*Contract, "owner", "argument");
    std::optional<unsigned> BufferArgument =
        directDMAArgument(*Contract, "mapped_buffer", "argument");
    std::optional<unsigned> LengthArgument =
        directDMAArgument(*Contract, "mapped_length", "argument");
    std::optional<unsigned> DirectionArgument =
        directDMAArgument(*Contract, "direction", "argument");
    std::optional<unsigned> AccessLengthArgument =
        directDMAArgument(*Contract, "access_length", "argument");
    std::optional<bool> BooleanDirection = directDMABooleanDirection(*Contract);
    if (!BufferArgument || !LengthArgument || !DirectionArgument ||
        !AccessLengthArgument || !BooleanDirection)
      return std::nullopt;
    unsigned ParameterCount = Contract->ParameterCount;
    if (*BufferArgument >= ParameterCount ||
        *LengthArgument >= ParameterCount ||
        *DirectionArgument >= ParameterCount ||
        *AccessLengthArgument >= ParameterCount)
      return std::nullopt;
    if (OwnerArgument && *OwnerArgument >= ParameterCount)
      return std::nullopt;
    DirectDMAUnmapDescriptor Descriptor{
        OwnerArgument,      *BufferArgument,       *LengthArgument,
        *DirectionArgument, *AccessLengthArgument, *BooleanDirection};
    if (FD->getNumParams() != ParameterCount ||
        Call.getNumArgs() != ParameterCount)
      return std::nullopt;
    QualType Length = FD->getParamDecl(Descriptor.LengthArgument)->getType();
    QualType Direction =
        FD->getParamDecl(Descriptor.DirectionArgument)->getType();
    QualType AccessLength =
        FD->getParamDecl(Descriptor.AccessLengthArgument)->getType();
    if (!Length->isIntegerType() || !AccessLength->isIntegerType() ||
        !Direction->isIntegralOrEnumerationType() ||
        Direction->isBooleanType() != Descriptor.BooleanDirection)
      return std::nullopt;
    return Descriptor;
  }

  static std::optional<DMATransferDescriptor>
  dmaTransferDescriptor(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() ||
        !FD->getReturnType()->isIntegralOrEnumerationType())
      return std::nullopt;
    const auto *Contract = directDMAContract(FD, "transfer");
    if (!Contract ||
        StringRef(Contract->RuleID) != stableID(DMATransferResultRuleID) ||
        StringRef(Contract->SuccessPredicateJSON) !=
            "{\"operand\":\"result\",\"operator\":\"eq\",\"rhs\":{\"integer\":"
            "0}}" ||
        StringRef(Contract->PartialSuccessPredicateJSON) !=
            "{\"constant\":false}" ||
        StringRef(Contract->FailurePredicateJSON) !=
            "{\"operand\":\"result\",\"operator\":\"ne\",\"rhs\":{\"integer\":"
            "0}}" ||
        Contract->EffectCount != 1 ||
        Contract->EffectBegin >= qemu_contracts_generated::EffectRecordCount)
      return std::nullopt;

    const auto &Effect =
        qemu_contracts_generated::Effects[Contract->EffectBegin];
    if (StringRef(Effect.ContractID) != Contract->ID ||
        StringRef(Effect.Kind) != "transfer" ||
        StringRef(Effect.When) != "success" ||
        StringRef(Effect.Target) != "host_buffer" ||
        StringRef(Effect.Extent) != "transfer_length" ||
        StringRef(Effect.RequestedExtent) != "" ||
        StringRef(Effect.AccessExtent) != "" ||
        StringRef(Effect.Owner) != "owner" || StringRef(Effect.Epoch) != "")
      return std::nullopt;

    const auto *ResultOperand = contractOperand(*Contract, "result");
    if (!ResultOperand || StringRef(ResultOperand->Source) != "return" ||
        StringRef(ResultOperand->Phase) != "post" ||
        ResultOperand->ArgumentIndex != -1)
      return std::nullopt;
    std::optional<unsigned> OwnerArgument =
        directDMAArgument(*Contract, "owner", "argument", "pre");
    std::optional<unsigned> GuestAddressArgument =
        directDMAArgument(*Contract, "guest_address", "argument", "pre");
    std::optional<unsigned> BufferArgument =
        directDMAArgument(*Contract, "host_buffer", "argument", "pre");
    std::optional<unsigned> LengthArgument =
        directDMAArgument(*Contract, "transfer_length", "argument", "pre");
    std::optional<unsigned> AttributesArgument =
        directDMAArgument(*Contract, "attributes", "argument", "pre");
    if (!OwnerArgument || !GuestAddressArgument || !BufferArgument ||
        !LengthArgument || !AttributesArgument)
      return std::nullopt;

    StringRef Encoding = Contract->DirectionEncoding;
    std::optional<unsigned> DirectionArgument;
    if (Encoding == "bool-is-write" || Encoding == "dma-direction") {
      DirectionArgument =
          directDMAArgument(*Contract, "direction", "argument", "pre");
      if (!DirectionArgument || StringRef(Effect.Direction) != "direction" ||
          Contract->OperandCount != 7)
        return std::nullopt;
    } else if (Encoding != "fixed-to-device" &&
               Encoding != "fixed-from-device") {
      return std::nullopt;
    } else if (contractOperand(*Contract, "direction") ||
               !StringRef(Effect.Direction).empty() ||
               Contract->OperandCount != 6) {
      return std::nullopt;
    }

    for (unsigned Argument :
         {*OwnerArgument, *GuestAddressArgument, *BufferArgument,
          *LengthArgument, *AttributesArgument})
      if (Argument >= Contract->ParameterCount)
        return std::nullopt;
    if (DirectionArgument && *DirectionArgument >= Contract->ParameterCount)
      return std::nullopt;
    if (Call.getNumArgs() != Contract->ParameterCount)
      return std::nullopt;
    return DMATransferDescriptor{
        Contract,        *OwnerArgument,  *GuestAddressArgument,
        *BufferArgument, *LengthArgument, DirectionArgument};
  }

  static bool dmaTransferResultIsDefinitelyDiscarded(const CallEvent &Call,
                                                     ASTContext &Context) {
    const Expr *Origin = Call.getOriginExpr();
    if (!Origin)
      return false;

    DynTypedNode Child = DynTypedNode::create(*Origin);
    for (unsigned Depth = 0; Depth < 16; ++Depth) {
      DynTypedNodeList Parents = Context.getParents(Child);
      if (Parents.size() != 1)
        return false;
      DynTypedNode Parent = Parents[0];
      if (Parent.get<CompoundStmt>())
        return true;

      if (const auto *Cast = Parent.get<CastExpr>()) {
        // An explicit `(void)` is an intentional suppression.  Other casts
        // merely carry the transfer result into their enclosing expression.
        if (Cast->getCastKind() == CK_ToVoid)
          return false;
        Child = Parent;
        continue;
      }
      if (Parent.get<ParenExpr>() || Parent.get<ExprWithCleanups>() ||
          Parent.get<CXXBindTemporaryExpr>() ||
          Parent.get<MaterializeTemporaryExpr>()) {
        Child = Parent;
        continue;
      }
      if (const auto *Binary = Parent.get<BinaryOperator>()) {
        if (Binary->getOpcode() != BO_Comma)
          return false;
        const Stmt *ChildStatement = Child.get<Stmt>();
        if (!ChildStatement)
          return false;
        if (Binary->getLHS() == ChildStatement)
          return true;
        if (Binary->getRHS() != ChildStatement)
          return false;
        Child = Parent;
        continue;
      }

      const Stmt *ChildStatement = Child.get<Stmt>();
      if (const auto *If = Parent.get<IfStmt>()) {
        // An expression used directly as an unbraced branch body is still a
        // discarded-value expression.  Do not confuse it with the condition,
        // an initializer, or a condition-variable declaration.
        return ChildStatement && (If->getThen() == ChildStatement ||
                                  If->getElse() == ChildStatement);
      }
      if (const auto *Switch = Parent.get<SwitchCase>()) {
        // CaseStmt and DefaultStmt wrap their first substatement.  Calls in
        // case labels cannot reach this arm because they are not the wrapped
        // substatement.
        return ChildStatement && Switch->getSubStmt() == ChildStatement;
      }
      if (const auto *Label = Parent.get<LabelStmt>()) {
        // A label likewise wraps, rather than consumes, its substatement.
        return ChildStatement && Label->getSubStmt() == ChildStatement;
      }
      if (const auto *While = Parent.get<WhileStmt>())
        return ChildStatement && While->getBody() == ChildStatement;
      if (const auto *Do = Parent.get<DoStmt>())
        return ChildStatement && Do->getBody() == ChildStatement;
      if (const auto *For = Parent.get<ForStmt>())
        return ChildStatement && For->getBody() == ChildStatement;
      if (const auto *RangeFor = Parent.get<CXXForRangeStmt>())
        return ChildStatement && RangeFor->getBody() == ChildStatement;

      // Initializers, assignments, comparisons, conditions, returns, outer
      // call arguments, and ambiguous statement-expression contexts all
      // count as observed.  Harder assigned-but-unchecked cases are handled
      // by a later consequence-tracking rule, not guessed here.
      return false;
    }
    return false;
  }

  const SelectiveDMASummary *selectiveDMASummary(const CallEvent &Call,
                                                 CheckerContext &C) const {
    if (SelectiveSummaries.empty())
      return nullptr;
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() || FD->isVariadic() ||
        !FD->getDeclContext()->getRedeclContext()->isTranslationUnit() ||
        !FD->getLexicalDeclContext()->getRedeclContext()->isTranslationUnit())
      return nullptr;

    const SelectiveDMASummary *Found = nullptr;
    for (const SelectiveDMASummary &Summary : SelectiveSummaries) {
      if (FD->getName() != Summary.Function)
        continue;
      if (Found)
        return nullptr;
      Found = &Summary;
    }
    if (!Found || FD->getNumParams() != Call.getNumArgs() ||
        !directDMATypeMatches(FD->getType(), Found->Prototype))
      return nullptr;

    const SourceManager &SM = C.getSourceManager();
    const FunctionDecl *Declaration = FD->getCanonicalDecl();
    if (!catalogDeclarationSourceMatches(Declaration, Found->Header, SM))
      return nullptr;
    PresumedLoc Location = SM.getPresumedLoc(Declaration->getLocation());
    if (Location.isInvalid() || Location.getLine() != Found->DeclarationLine ||
        Location.getColumn() != Found->DeclarationColumn)
      return nullptr;

    if (Found->Effect == SelectiveSummaryEffect::FullTransfer) {
      if (FD->getNumParams() != 4 ||
          !isNamedRecordPointer(FD->getParamDecl(0)->getType(), "PCIDevice") ||
          !directDMATypeMatches(FD->getParamDecl(1)->getType(),
                                "dma_addr_t") ||
          !isVoidPointer(FD->getParamDecl(2)->getType()) ||
          !directDMATypeMatches(FD->getParamDecl(3)->getType(),
                                "dma_addr_t"))
        return nullptr;
      const RecordDecl *PCIRecord = FD->getParamDecl(0)
                                        ->getType()
                                        ->getPointeeType()
                                        .getUnqualifiedType()
                                        ->getAsRecordDecl();
      if (PCIRecord)
        if (const RecordDecl *Definition = PCIRecord->getDefinition())
          PCIRecord = Definition;
      const FieldDecl *BusMasterAddressSpace =
          namedField(PCIRecord, "bus_master_as");
      if (!PCIRecord || !BusMasterAddressSpace ||
          !catalogDeclarationSourceMatches(PCIRecord, Found->Header, SM) ||
          !catalogDeclarationSourceMatches(BusMasterAddressSpace,
                                           Found->Header, SM) ||
          !directDMATypeMatches(BusMasterAddressSpace->getType(),
                                "AddressSpace"))
        return nullptr;
      return Found;
    }

    if (FD->getNumParams() != 5)
      return nullptr;
    QualType SGType = FD->getParamDecl(3)->getType();
    const RecordDecl *SGRecord =
        SGType->isPointerType()
            ? SGType->getPointeeType().getUnqualifiedType()->getAsRecordDecl()
            : nullptr;
    if (!SGRecord || SGRecord->getName() != "QEMUSGList")
      return nullptr;
    if (const RecordDecl *Definition = SGRecord->getDefinition())
      SGRecord = Definition;
    const FieldDecl *Size = namedField(SGRecord, "size");
    const FieldDecl *AddressSpace = namedField(SGRecord, "as");
    if (!Size || !AddressSpace ||
        !catalogDeclarationSourceMatches(SGRecord, Found->Header, SM) ||
        !catalogDeclarationSourceMatches(Size, Found->Header, SM) ||
        !catalogDeclarationSourceMatches(AddressSpace, Found->Header, SM) ||
        !directDMATypeMatches(Size->getType(), "dma_addr_t") ||
        !directDMATypeMatches(AddressSpace->getType(), "AddressSpace *"))
      return nullptr;
    return Found;
  }

  static TransferBufferDirection
  selectiveSummaryDirection(const SelectiveDMASummary &Summary) {
    return Summary.Direction == SelectiveSummaryDirection::FromDevice
               ? TransferBufferDirection::HostRead
               : TransferBufferDirection::HostWrite;
  }

  void recordSelectiveSummaryMatch(const CallEvent &Call,
                                   const SelectiveDMASummary &Summary,
                                   bool Consumed) const {
    const Expr *Origin = Call.getOriginExpr();
    if (!Origin)
      return;
    SelectiveSummaryMatchedCalls.insert(Origin);
    // The scatter-gather summaries import the result predicate exactly but do
    // not manufacture a contiguous guest address.  The PCI summary has an
    // exact address and extent and therefore imports the full transfer facts.
    if (Summary.Effect == SelectiveSummaryEffect::ResultAndExtentOnly)
      SelectiveSummaryUnsupportedCalls.insert(Origin);
    if (Consumed)
      SelectiveSummaryConsumedCalls.insert(Origin);
  }

  bool reportIgnoredSelectiveSummaryFailure(
      CheckerContext &C, ProgramStateRef State, const CallEvent &Call,
      const SelectiveDMASummary &Summary) const {
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return false;

    llvm::SmallString<160> MessageBuffer;
    llvm::raw_svector_ostream Message(MessageBuffer);
    Message << "Level B: DMA transfer failure from '" << Summary.Function
            << "' is ignored";
    auto Report = std::make_unique<PathSensitiveBugReport>(
        dmaTransferResultBugType(), Message.str(), Node);
    const Expr *Origin = Call.getOriginExpr();
    if (Origin) {
      Report->addRange(Origin->getSourceRange());
      Report->addNote(
          "The summarized MemTxResult is discarded, so transfer completion "
          "is not established",
          {Origin, C.getSourceManager(), C.getStackFrame()});
      if (Summary.Effect == SelectiveSummaryEffect::ResultAndExtentOnly)
        Report->addNote(
            "This result-only consumer does not import the summarized "
            "min(requested_len, sg->size) extent, scatter-gather guest "
            "address, transfer effect, owner, direction, or residual "
            "writeback",
            {Origin, C.getSourceManager(), C.getStackFrame()});
    }
    for (SVal Value : {Call.getReturnValue(), Call.getArgSVal(0),
                       Call.getArgSVal(1), Call.getArgSVal(3)})
      for (SymbolRef Symbol : Value.symbols())
        Report->markInteresting(Symbol);
    llvm::SmallString<224> ReasonBuffer;
    llvm::raw_svector_ostream Reason(ReasonBuffer);
    std::string SummaryContractID = Summary.Function;
    std::replace(SummaryContractID.begin(), SummaryContractID.end(), '_', '-');
    Reason << "dma-transfer-result-discarded:qemu.selective-summary."
           << SummaryContractID << ':'
           << transferDirectionName(selectiveSummaryDirection(Summary));
    addStructuredWitnessNotApplicable(*Report, C, Message.str(),
                                      DMATransferResultRuleID, Reason.str());
    C.emitReport(std::move(Report));
    return true;
  }

  bool checkSelectiveSummaryPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
    const SelectiveDMASummary *Summary = selectiveDMASummary(Call, C);
    if (!Summary)
      return false;
    recordSelectiveSummaryMatch(Call, *Summary, /*Consumed=*/false);
    if (Summary->Effect == SelectiveSummaryEffect::FullTransfer) {
      MemorySink Sink{/*BufferArgument=*/2, /*LengthArgument=*/3,
                      "memory-operation length", "host-write"};
      (void)checkMemorySink(Call, Sink, C);
    }
    return true;
  }

  bool checkSelectiveSummaryPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
    const SelectiveDMASummary *Summary = selectiveDMASummary(Call, C);
    if (!Summary)
      return false;
    recordSelectiveSummaryMatch(Call, *Summary, /*Consumed=*/true);

    const auto *FD = cast<FunctionDecl>(Call.getDecl());
    bool ReportDiscardedFailure =
        EnableDMATransferResultDiagnostics &&
        dmaTransferResultIsDefinitelyDiscarded(Call, C.getASTContext());
    if (Summary->Effect == SelectiveSummaryEffect::ResultAndExtentOnly &&
        !ReportDiscardedFailure)
      return true;

    ProgramStateRef InitialState = C.getState();
    SVal Zero = C.getSValBuilder().makeZeroVal(FD->getReturnType());
    std::optional<BoundStates> Result =
        compare(InitialState, Call.getReturnValue(), BO_EQ, Zero,
                C.getSValBuilder());
    if (!Result)
      return true;

    if (Summary->Effect == SelectiveSummaryEffect::ResultAndExtentOnly) {
      if (Result->Unsafe && !reportIgnoredSelectiveSummaryFailure(
                                C, Result->Unsafe, Call, *Summary))
        C.addTransition(Result->Unsafe);
      if (Result->Safe)
        C.addTransition(Result->Safe);
      return true;
    }

    SymbolRef ResultSymbol = Call.getReturnValue().getAsSymbol();
    SVal OwnerValue = Call.getArgSVal(0);
    SVal GuestAddress = Call.getArgSVal(1);
    SVal Buffer = Call.getArgSVal(2);
    SVal Length = Call.getArgSVal(3);
    QualType LengthType = Call.getArgExpr(3)->getType();
    SVal Begin = C.getSValBuilder().makeZeroVal(LengthType);
    const RecordDecl *PCIRecord = FD->getParamDecl(0)
                                      ->getType()
                                      ->getPointeeType()
                                      .getUnqualifiedType()
                                      ->getAsRecordDecl();
    if (PCIRecord)
      if (const RecordDecl *Definition = PCIRecord->getDefinition())
        PCIRecord = Definition;
    const FieldDecl *BusMasterAddressSpace =
        namedField(PCIRecord, "bus_master_as");
    SVal OwnerLocation = BusMasterAddressSpace
                             ? InitialState->getLValue(BusMasterAddressSpace,
                                                       OwnerValue)
                             : UnknownVal();
    const MemRegion *Owner = directDMAOwner(OwnerLocation);
    if (ResultSymbol) {
      llvm::SmallDenseSet<SymbolRef, 8> Dependencies;
      auto AddDependencies = [&](SVal Value) {
        for (SymbolRef Symbol : Value.symbols())
          if (Symbol != ResultSymbol)
            Dependencies.insert(Symbol);
      };
      AddDependencies(OwnerValue);
      AddDependencies(OwnerLocation);
      AddDependencies(GuestAddress);
      AddDependencies(Buffer);
      AddDependencies(Begin);
      AddDependencies(Length);
      if (const SymbolicRegion *OwnerBase =
              Owner ? Owner->getSymbolicBase() : nullptr)
        if (OwnerBase->getSymbol() != ResultSymbol)
          Dependencies.insert(OwnerBase->getSymbol());
      for (SymbolRef Dependency : Dependencies)
        C.getSymbolManager().addSymbolDependency(ResultSymbol, Dependency);
    }

    auto Propagate = [&](ProgramStateRef ResultPath, bool Succeeded) {
      if (!ResultPath)
        return;
      ProgramStateRef State = ResultPath;
      if (ResultSymbol) {
        State = qemu::state::setValueResultState(
            State, ResultSymbol,
            Succeeded ? qemu::facts::ResultStateKind::Complete
                      : qemu::facts::ResultStateKind::Rejected);
        std::optional<SVal> ActualLength;
        if (Succeeded)
          ActualLength = Length;
        State = qemu::state::setTransferOperation(
            State, ResultSymbol, Buffer, Owner, GuestAddress, Begin, Length,
            ActualLength, qemu::facts::AccessDirection::HostWrite);
      }

      const NoteTag *Tag = nullptr;
      if (Succeeded) {
        if (std::optional<SVal> Pointee = pointeeValue(State, Buffer)) {
          State = addInputTaint(State, *Pointee, InputClass::DMA);
          for (SymbolRef Symbol : Pointee->symbols())
            State = qemu::state::setValueProvenance(
                State, Symbol, qemu::facts::ProvenanceKind::DMA);
          Tag = sourceNote(C, State, *Pointee, InputClass::DMA,
                           "populated guest-controlled data here");
        }
      }
      // This exact pci_dma_read() wrapper hardcodes MEMTXATTRS_UNSPECIFIED
      // (attrs.memory == 0).  That excludes the flatview access-denied return
      // which can leave the buffer untouched; the remaining direct or
      // dispatched read steps write every requested output byte even when a
      // MemTxResult error is accumulated.  Failure bytes are initialized but
      // are not assigned guest/DMA provenance.
      if (EnableInitializedByteTracking) {
        std::optional<InitializedBytePosition> Position =
            initializedBytePosition(Buffer, C.getASTContext());
        if (Position && State->get<QEMUInitializedByteObjectExtents>(
                            Position->Base)) {
          State =
              State->remove<QEMUKnownNULTerminatorOffsets>(Position->Base);
          State = overwriteInitializedByteRange(State, *Position, Length, C);
          State = recordInitializedByteRange(
              State, *Position, Length, InitializedByteKind::DMATransfer,
              Call.getOriginExpr(),
              Succeeded ? std::optional<InputClass>(InputClass::DMA)
                        : std::nullopt,
              C);
        }
      }

      if (!Succeeded && ReportDiscardedFailure &&
          reportIgnoredSelectiveSummaryFailure(C, State, Call, *Summary))
        return;
      C.addTransition(State, Tag);
    };

    Propagate(Result->Unsafe, /*Succeeded=*/false);
    Propagate(Result->Safe, /*Succeeded=*/true);
    return true;
  }

  static TransferBufferDirection
  fixedTransferBufferDirection(const DMATransferDescriptor &Transfer) {
    return StringRef(Transfer.Contract->DirectionEncoding) ==
                   "fixed-from-device"
               ? TransferBufferDirection::HostRead
               : TransferBufferDirection::HostWrite;
  }

  static StringRef transferDirectionName(TransferBufferDirection Direction) {
    return Direction == TransferBufferDirection::HostRead ? "host-read"
                                                          : "host-write";
  }

  bool
  reportIgnoredDMATransferFailure(CheckerContext &C, ProgramStateRef State,
                                  const CallEvent &Call,
                                  const DMATransferDescriptor &Transfer,
                                  TransferBufferDirection Direction) const {
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return false;

    const auto *FD = cast<FunctionDecl>(Call.getDecl());
    llvm::SmallString<160> MessageBuffer;
    llvm::raw_svector_ostream Message(MessageBuffer);
    Message << "Level B: DMA transfer failure from '" << FD->getName()
            << "' is ignored";
    auto Report = std::make_unique<PathSensitiveBugReport>(
        dmaTransferResultBugType(), Message.str(), Node);
    const Expr *Origin = Call.getOriginExpr();
    if (Origin) {
      Report->addRange(Origin->getSourceRange());
      Report->addNote(
          "The MemTxResult is discarded, so transfer completion is not "
          "established",
          {Origin, C.getSourceManager(), C.getStackFrame()});
    }
    for (SVal Value :
         {Call.getReturnValue(), Call.getArgSVal(Transfer.GuestAddressArgument),
          Call.getArgSVal(Transfer.BufferArgument),
          Call.getArgSVal(Transfer.LengthArgument)})
      for (SymbolRef Symbol : Value.symbols())
        Report->markInteresting(Symbol);

    llvm::SmallString<192> ReasonBuffer;
    llvm::raw_svector_ostream Reason(ReasonBuffer);
    Reason << "dma-transfer-result-discarded:" << Transfer.Contract->ID << ':'
           << transferDirectionName(Direction);
    addStructuredWitnessNotApplicable(*Report, C, Message.str(),
                                      DMATransferResultRuleID, Reason.str());
    C.emitReport(std::move(Report));
    return true;
  }

  static ProgramStateRef
  startFailedCompletionPublication(ProgramStateRef State, const CallEvent &Call,
                                   const DMATransferDescriptor &Transfer,
                                   SymbolRef Result, CheckerContext &C) {
    if (!Result)
      return State;
    std::optional<FailedCompletionProtocolDescriptor> Protocol =
        activeFailedCompletionProtocol(C);
    if (!Protocol ||
        !protocolMatchesFailedTransfer(*Protocol, *Transfer.Contract))
      return State;
    std::optional<FailedCompletionIdentity> Identity =
        failedCompletionIdentity(*Protocol, State, C);
    if (!Identity)
      return State;
    return qemu::state::startCompletionPublication(
        State, Identity->Owner, Identity->Queue, Call.getReturnValue(),
        Identity->Slot, Identity->Vector, Result,
        qemu::facts::CompletionPublicationStage::DescriptorFailed,
        Call.getOriginExpr());
  }

  bool reportFailedCompletionPublication(
      CheckerContext &C, ProgramStateRef State, const CallEvent &Call,
      const FailedCompletionProtocolDescriptor &Protocol,
      const qemu::state::CompletionPublicationState &Publication) const {
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return false;

    StringRef Message =
        "failed DMA transfer advances device completion state and reaches "
        "transfer completion";
    auto Report = std::make_unique<PathSensitiveBugReport>(
        failedCompletionPublicationBugType(), Message, Node);
    if (const Expr *Origin = Call.getOriginExpr())
      Report->addRange(Origin->getSourceRange());
    if (const Stmt *Origin = Publication.getStageOrigin(
            qemu::facts::CompletionPublicationStage::DescriptorFailed))
      Report->addNote("DMA transfer failed here",
                      {Origin, C.getSourceManager(), C.getStackFrame()});
    if (const Stmt *Origin = Publication.getStageOrigin(
            qemu::facts::CompletionPublicationStage::RingAdvanced))
      Report->addNote("device completion state advanced here",
                      {Origin, C.getSourceManager(), C.getStackFrame()});
    Report->markInteresting(Publication.getResult());
    for (SymbolRef Symbol : Publication.getSlot().symbols())
      Report->markInteresting(Symbol);

    llvm::SmallString<192> ReasonBuffer;
    llvm::raw_svector_ostream Reason(ReasonBuffer);
    Reason << "failed-completion-publication:" << Protocol.Protocol->ID;
    addStructuredWitnessNotApplicable(
        *Report, C, Message, FailedCompletionPublicationRuleID, Reason.str());
    C.emitReport(std::move(Report));
    return true;
  }

  bool checkFailedCompletionRingAdvance(SVal Location, const Stmt *S,
                                        CheckerContext &C) const {
    std::optional<FailedCompletionProtocolDescriptor> Protocol =
        activeFailedCompletionProtocol(C);
    if (!Protocol)
      return false;
    const auto &Selector =
        qemu_contracts_generated::ProtocolSelectors[Protocol->RingAdvanced
                                                        ->SelectorBegin];
    const auto *Operation = dyn_cast_or_null<UnaryOperator>(S);
    const auto *Field = dyn_cast_or_null<FieldRegion>(Location.getAsRegion());
    if (!Operation || Operation->getOpcode() != UO_PostDec || !Field ||
        Field->getDecl()->getName() != Selector.Field ||
        Field->getDecl()->getParent()->getName() != Selector.RecordType)
      return false;

    ProgramStateRef State = C.getState();
    std::optional<FailedCompletionIdentity> Identity =
        failedCompletionIdentity(*Protocol, State, C);
    if (!Identity || Field->getSuperRegion()->StripCasts() != Identity->Owner)
      return false;
    auto FieldLocation = Location.getAs<Loc>();
    if (!FieldLocation)
      return false;
    SVal PreviousSlot = State->getSVal(*FieldLocation);
    if (PreviousSlot.isUnknownOrUndef() || PreviousSlot != Identity->Slot)
      return false;
    const auto *Publication = uniqueFailedCompletionPublication(
        State, *Identity, PreviousSlot, /*RequireRingAdvanced=*/false);
    if (!Publication ||
        Publication->hasStage(
            qemu::facts::CompletionPublicationStage::RingAdvanced))
      return false;

    ProgramStateRef Updated = qemu::state::observeCompletionPublicationStage(
        State, Publication->getOwner(), Publication->getQueueID(),
        Publication->getAttemptID(), Publication->getSlot(),
        Publication->getVector(), Publication->getResult(),
        qemu::facts::CompletionPublicationStage::RingAdvanced, S);
    if (Updated == State)
      return false;
    C.addTransition(Updated);
    return true;
  }

  bool checkFailedCompletionPublication(const CallEvent &Call,
                                        CheckerContext &C) const {
    std::optional<FailedCompletionProtocolDescriptor> Protocol =
        activeFailedCompletionProtocol(C);
    if (!Protocol)
      return false;
    const auto &Selector = qemu_contracts_generated::ProtocolSelectors
        [Protocol->CompletionPublished->SelectorBegin];
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() || Call.getNumArgs() != 1 ||
        FD->getName() != Selector.Name ||
        !directDMATypeMatches(FD->getType(), Selector.Prototype))
      return false;

    ProgramStateRef State = C.getState();
    std::optional<FailedCompletionIdentity> Identity =
        failedCompletionOwnerIdentity(*Protocol, State, C);
    if (!Identity ||
        !isDefinitelyTrue(State, Call.getArgSVal(0), BO_EQ,
                          Identity->OwnerValue, C.getSValBuilder()))
      return false;
    const auto *Publication = uniqueFailedCompletionPublication(
        State, *Identity, std::nullopt, /*RequireRingAdvanced=*/false);
    if (!Publication)
      return false;

    ProgramStateRef Updated = qemu::state::observeCompletionPublicationStage(
        State, Publication->getOwner(), Publication->getQueueID(),
        Publication->getAttemptID(), Publication->getSlot(),
        Publication->getVector(), Publication->getResult(),
        qemu::facts::CompletionPublicationStage::InterruptPublished,
        Call.getOriginExpr());
    const qemu::state::CompletionPublicationState *Published =
        qemu::state::getCompletionPublication(
            Updated, Publication->getOwner(), Publication->getQueueID(),
            Publication->getAttemptID(), Publication->getSlot());
    std::optional<qemu::state::CompletionPublicationState> PublishedCopy;
    if (qemu::state::isFailedDMACompletionPublished(Updated, Published))
      PublishedCopy = *Published;

    ProgramStateRef Cleaned =
        removeFailedCompletionFactsForResult(Updated, Publication->getResult());
    if (PublishedCopy && reportFailedCompletionPublication(
                             C, Cleaned, Call, *Protocol, *PublishedCopy))
      return true;
    if (Cleaned != State)
      C.addTransition(Cleaned);
    return true;
  }

  static qemu::facts::AccessDirection
  transferFactDirection(TransferBufferDirection Direction) {
    return Direction == TransferBufferDirection::HostRead
               ? qemu::facts::AccessDirection::HostRead
               : qemu::facts::AccessDirection::HostWrite;
  }

  struct TransferDirectionState {
    ProgramStateRef State;
    TransferBufferDirection Direction;
  };

  static llvm::SmallVector<TransferDirectionState, 2>
  transferDirectionStates(const DMATransferDescriptor &Transfer,
                          const CallEvent &Call, ProgramStateRef State,
                          CheckerContext &C) {
    if (!Transfer.DirectionArgument)
      return {{State, fixedTransferBufferDirection(Transfer)}};

    SVal Direction = Call.getArgSVal(*Transfer.DirectionArgument);
    QualType DirectionType =
        Call.getArgExpr(*Transfer.DirectionArgument)->getType();
    SVal FromDevice = C.getSValBuilder().makeIntVal(1, DirectionType);
    std::optional<BoundStates> IsFromDevice =
        compare(State, Direction, BO_EQ, FromDevice, C.getSValBuilder());
    llvm::SmallVector<TransferDirectionState, 2> Result;
    if (!IsFromDevice)
      return Result;
    if (IsFromDevice->Safe)
      Result.push_back({IsFromDevice->Safe, TransferBufferDirection::HostRead});
    if (IsFromDevice->Unsafe)
      Result.push_back(
          {IsFromDevice->Unsafe, TransferBufferDirection::HostWrite});
    return Result;
  }

  static bool isNestedDirectDMAContract(CheckerContext &C, StringRef Kind) {
    for (const StackFrame *Frame = C.getStackFrame(); Frame;
         Frame = Frame->getParent()) {
      const auto *FD = dyn_cast_or_null<FunctionDecl>(Frame->getDecl());
      if (directDMAContract(FD, Kind))
        return true;
    }
    return false;
  }

  bool isNestedSelectiveFullTransfer(CheckerContext &C) const {
    const SourceManager &SM = C.getSourceManager();
    for (const StackFrame *Frame = C.getStackFrame(); Frame;
         Frame = Frame->getParent()) {
      const auto *FD = dyn_cast_or_null<FunctionDecl>(Frame->getDecl());
      if (!FD || !FD->getIdentifier())
        continue;
      for (const SelectiveDMASummary &Summary : SelectiveSummaries) {
        if (Summary.Effect != SelectiveSummaryEffect::FullTransfer ||
            FD->getName() != Summary.Function ||
            !directDMATypeMatches(FD->getType(), Summary.Prototype))
          continue;
        const FunctionDecl *Declaration = FD->getCanonicalDecl();
        if (!catalogDeclarationSourceMatches(Declaration, Summary.Header, SM))
          continue;
        PresumedLoc Location = SM.getPresumedLoc(Declaration->getLocation());
        if (Location.isValid() &&
            Location.getLine() == Summary.DeclarationLine &&
            Location.getColumn() == Summary.DeclarationColumn)
          return true;
      }
    }
    return false;
  }

  static const MemRegion *directDMAObject(SVal Buffer) {
    // This intentionally models pointer-preserving aliases only.  QEMU code
    // that casts a mapped host pointer to an integer and reconstructs another
    // pointer needs a separate provenance model; treating arbitrary integer
    // arithmetic as an alias here would be too noisy.
    const MemRegion *Region = Buffer.getAsRegion();
    return Region ? Region->getSymbolicBase() : nullptr;
  }

  static const MemRegion *directDMAOwner(SVal Owner) {
    const MemRegion *Region = Owner.getAsRegion();
    return Region ? Region->StripCasts() : nullptr;
  }

  static std::optional<SVal>
  directDMAExtent(ProgramStateRef State, SVal Buffer,
                  qemu::facts::LifetimeState RequiredLifetime) {
    const MemRegion *Object = directDMAObject(Buffer);
    if (!Object)
      return std::nullopt;
    const qemu::state::ObjectLifetime *Lifetime =
        qemu::state::getObjectLifetime(State, Object);
    if (!Lifetime || Lifetime->getState() != RequiredLifetime)
      return std::nullopt;
    if (const qemu::state::ObjectExtent *Extent = qemu::state::getObjectExtent(
            State, Object, qemu::facts::ExtentKind::Mapped))
      return Extent->getLength();
    return std::nullopt;
  }

  static std::optional<SVal> directDMAMappedExtent(ProgramStateRef State,
                                                   SVal Buffer) {
    return directDMAExtent(State, Buffer, qemu::facts::LifetimeState::Live);
  }

  static std::optional<SVal> directDMARetiredExtent(ProgramStateRef State,
                                                    SVal Buffer) {
    return directDMAExtent(State, Buffer, qemu::facts::LifetimeState::Unmapped);
  }

  static ProgramStateRef retireDirectDMAMapping(ProgramStateRef State,
                                                SVal Buffer, SVal AccessLength,
                                                QualType AccessLengthType,
                                                const Expr *Where,
                                                CheckerContext &C) {
    SymbolRef Base = Buffer.getAsSymbol();
    const MemRegion *Object = directDMAObject(Buffer);
    if (!Base || !Object)
      return State;
    const qemu::state::ObjectLifetime *Lifetime =
        qemu::state::getObjectLifetime(State, Object);
    if (!Lifetime || Lifetime->getState() != qemu::facts::LifetimeState::Live)
      return State;

    State = State->remove<QEMUDMAMappedDirections>(Base);
    if (!AccessLength.isUnknownOrUndef()) {
      SVal ExtentBegin = C.getSValBuilder().makeZeroVal(AccessLengthType);
      State = qemu::state::setObjectExtent(
          State, Object, qemu::facts::ExtentKind::ActualTransfer, ExtentBegin,
          AccessLength);
    } else {
      State = qemu::state::removeObjectExtent(
          State, Object, qemu::facts::ExtentKind::ActualTransfer);
    }
    State = qemu::state::setObjectLifetime(
        State, Object, Lifetime->getOwner(), Lifetime->getEpoch(),
        qemu::facts::LifetimeState::Unmapped);
    return Where ? State->set<QEMUDMARetiredOrigins>(Base, Where)
                 : State->remove<QEMUDMARetiredOrigins>(Base);
  }

  static bool isBitmapBitSink(const CallEvent &Call, ASTContext &Context) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() || FD->getNumParams() != 2 ||
        Call.getNumArgs() != 2)
      return false;
    StringRef Name = FD->getName();
    if (Name != "test_bit" && Name != "set_bit" && Name != "clear_bit")
      return false;
    if (!Context.hasSameUnqualifiedType(FD->getParamDecl(0)->getType(),
                                        Context.LongTy))
      return false;
    QualType AddressType = FD->getParamDecl(1)->getType();
    if (!AddressType->isPointerType() ||
        !Context.hasSameUnqualifiedType(AddressType->getPointeeType(),
                                        Context.UnsignedLongTy))
      return false;
    QualType ReturnType = FD->getReturnType();
    return Name == "test_bit"
               ? Context.hasSameUnqualifiedType(ReturnType, Context.IntTy)
               : ReturnType->isVoidType();
  }

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
      return MemorySink{0, 2, "memory-operation length", "host-write"};
    if (Name == "address_space_read_full" && Call.getNumArgs() >= 5)
      return MemorySink{3, 4, "memory-operation length", "host-write"};
    if (Name == "pci_dma_read" && Call.getNumArgs() >= 4)
      return MemorySink{2, 3, "memory-operation length", "host-write"};
    if (Name == "physical_memory_read" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "memory-operation length", "host-write"};
    if (Name == "qemu_get_buffer" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "memory-operation length", "host-write"};
    if ((isDirectBlockRead(FD, "bdrv_pread") ||
         isDirectBlockRead(FD, "bdrv_co_pread") ||
         isDirectBlockRead(FD, "blk_pread")) &&
        Call.getNumArgs() == 5)
      return MemorySink{3, 2, "memory-operation length", "host-write"};
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
      return MemorySink{1, 2, "memory-operation source length", "host-read"};
    if ((Name == "qemu_send_packet" || Name == "qemu_send_packet_raw" ||
         Name == "qemu_send_packet_async") &&
        Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "packet length", "host-read"};
    if (Name == "pci_dma_write" && Call.getNumArgs() >= 4)
      return MemorySink{2, 3, "DMA source length", "host-read"};
    if (Name == "address_space_write_full" && Call.getNumArgs() >= 5)
      return MemorySink{3, 4, "DMA source length", "host-read"};
    if (Name == "physical_memory_write" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "DMA source length", "host-read"};
    if (Name == "qemu_put_buffer" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "migration-output source length", "host-read"};
    if ((Name == "bdrv_pwrite" || Name == "bdrv_co_pwrite" ||
         Name == "blk_pwrite") &&
        Call.getNumArgs() >= 5)
      return MemorySink{3, 2, "block-write source length", "host-read"};
    return std::nullopt;
  }

  static bool isInitializedByteDisclosureSink(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier())
      return false;
    StringRef Name = FD->getName();
    return Name == "qemu_put_buffer" || Name == "qemu_send_packet" ||
           Name == "qemu_send_packet_raw" || Name == "qemu_send_packet_async" ||
           Name == "pci_dma_write" || Name == "address_space_write_full" ||
           Name == "physical_memory_write" || Name == "bdrv_pwrite" ||
           Name == "bdrv_co_pwrite" || Name == "blk_pwrite";
  }

  static bool isInitializedByteBulkFunction(const FunctionDecl *FD,
                                            unsigned ArgumentCount) {
    if (!FD || !FD->getIdentifier() || ArgumentCount < 3 ||
        FD->getNumParams() < 3 ||
        !FD->getParamDecl(0)->getType()->isPointerType() ||
        !FD->getParamDecl(2)->getType()->isIntegerType())
      return false;
    StringRef Name = FD->getName();
    bool Copy = Name == "memcpy" || Name == "memmove" ||
                Name == "__builtin_memcpy" || Name == "__builtin_memmove";
    bool Set = Name == "memset" || Name == "__builtin_memset";
    if (!Copy && !Set)
      return false;
    return Set ? FD->getParamDecl(1)->getType()->isIntegerType()
               : FD->getParamDecl(1)->getType()->isPointerType();
  }

  static bool isQEMUGetBufferInitializedByteProducer(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() || FD->getName() != "qemu_get_buffer" ||
        !FD->getDeclContext()->getRedeclContext()->isTranslationUnit() ||
        FD->getNumParams() != 3 || Call.getNumArgs() != 3 ||
        !isNamedRecordPointer(FD->getParamDecl(0)->getType(), "QEMUFile"))
      return false;
    QualType Buffer = FD->getParamDecl(1)->getType();
    QualType Size = FD->getParamDecl(2)->getType();
    return Buffer->isPointerType() &&
           Buffer->getPointeeType()->isUnsignedIntegerType() &&
           FD->getASTContext().getIntWidth(Buffer->getPointeeType()) == 8 &&
           Size->isUnsignedIntegerType() &&
           FD->getReturnType().getCanonicalType() == Size.getCanonicalType();
  }

  static bool
  isGInputStreamReadAllInitializedByteProducer(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() ||
        FD->getName() != "g_input_stream_read_all" ||
        !FD->getDeclContext()->getRedeclContext()->isTranslationUnit() ||
        FD->getNumParams() != 6 || Call.getNumArgs() != 6 ||
        !isInteger(FD->getReturnType()) ||
        !isNamedRecordPointer(FD->getParamDecl(0)->getType(),
                              "_GInputStream") ||
        !isVoidPointer(FD->getParamDecl(1)->getType()) ||
        !FD->getParamDecl(2)->getType()->isUnsignedIntegerType() ||
        !FD->getParamDecl(3)->getType()->isPointerType() ||
        !isNamedRecordPointer(FD->getParamDecl(4)->getType(),
                              "_GCancellable") ||
        !FD->getParamDecl(5)->getType()->isPointerType())
      return false;
    QualType Size = FD->getParamDecl(2)->getType();
    QualType Actual = FD->getParamDecl(3)->getType()->getPointeeType();
    QualType Error = FD->getParamDecl(5)->getType()->getPointeeType();
    return Actual.getCanonicalType() == Size.getCanonicalType() &&
           Error->isPointerType() && isNamedRecordPointer(Error, "_GError");
  }

  static ProgramStateRef
  abandonInitializedByteDestination(ProgramStateRef State,
                                    const CallEvent &Call, unsigned Argument,
                                    CheckerContext &C) {
    if (Argument >= Call.getNumArgs())
      return State;
    std::optional<InitializedBytePosition> Position =
        initializedBytePosition(Call.getArgSVal(Argument), C.getASTContext());
    if (!Position ||
        !State->get<QEMUInitializedByteObjectExtents>(Position->Base))
      return State;
    return abandonInitializedByteObject(State, Position->Base);
  }

  bool checkInitializedByteSink(const CallEvent &Call, const MemorySink &Sink,
                                CheckerContext &C,
                                ProgramStateRef State = nullptr,
                                bool IsDisclosureSink = false) const {
    if (!IsDisclosureSink && !isInitializedByteDisclosureSink(Call))
      return false;
    if (!State)
      State = C.getState();
    std::optional<InitializedBytePosition> Position = initializedBytePosition(
        Call.getArgSVal(Sink.BufferArgument), C.getASTContext());
    if (!Position ||
        !State->get<QEMUInitializedByteObjectExtents>(Position->Base))
      return false;

    SVal AccessLength = Call.getArgSVal(Sink.LengthArgument);
    QualType LengthType = Call.getArgExpr(Sink.LengthArgument)->getType();
    if (AccessLength.isUnknownOrUndef() || !LengthType->isIntegerType())
      return false;
    SVal RemainingExtent =
        getDynamicExtentWithOffset(State, Call.getArgSVal(Sink.BufferArgument));
    if (hasUsableExtent(State, RemainingExtent, C.getSValBuilder())) {
      std::optional<BoundStates> InBounds = compare(
          State, AccessLength, BO_LE, RemainingExtent, C.getSValBuilder());
      // Spatial violations are more fundamental and already have their own
      // diagnostic.  Diagnose logical initializedness only on a path proved
      // to stay inside the allocated object.
      if (!InBounds || !InBounds->Safe || InBounds->Unsafe)
        return false;
      State = InBounds->Safe;
    }
    InitializedCoverage Coverage =
        initializedCoverageIncludingAdjacentNUL(State, *Position, C);
    if (Coverage.Kind == InitializedCoverageKind::Unknown)
      return false;
    SVal InitializedLength = Coverage.Length;
    std::optional<BoundStates> Covered = compare(
        State, AccessLength, BO_LE, InitializedLength, C.getSValBuilder());
    if (!Covered || !Covered->Unsafe)
      return false;

    std::optional<InputClass> Source;
    if (Coverage.RangeStart)
      if (const unsigned *Class =
              State->get<QEMUInitializedByteRangeClasses>(Coverage.RangeStart))
        if (*Class <= static_cast<unsigned>(InputClass::Mixed))
          Source = static_cast<InputClass>(*Class);
    return reportUninitializedRead(C, Covered->Safe, Covered->Unsafe,
                                   AccessLength, InitializedLength,
                                   Call.getArgExpr(Sink.BufferArgument),
                                   *Position, "host-read length", Source);
  }

  static llvm::SmallVector<unsigned, 2>
  cStringArguments(const CallEvent &Call) {
    llvm::SmallVector<unsigned, 2> Result;
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier())
      return Result;
    if (FD->getName() == "trace_dbus_vmstate_loading" &&
        Call.getNumArgs() >= 1) {
      Result.push_back(0);
      return Result;
    }
    if (FD->getName() != "error_report" || Call.getNumArgs() < 2)
      return Result;
    const Expr *Format = Call.getArgExpr(0)->IgnoreParenImpCasts();
    const auto *Literal = dyn_cast<StringLiteral>(Format);
    if (!Literal)
      return Result;

    StringRef Text = Literal->getString();
    unsigned Argument = 1;
    for (size_t I = 0; I < Text.size();) {
      if (Text[I++] != '%')
        continue;
      if (I >= Text.size())
        return {};
      if (Text[I] == '%') {
        ++I;
        continue;
      }

      // Positional printf arguments need a separate argument map.  Reject
      // such formats rather than associating a string with the wrong value.
      size_t DigitsBegin = I;
      while (I < Text.size() && llvm::isDigit(Text[I]))
        ++I;
      if (I < Text.size() && Text[I] == '$')
        return {};
      I = DigitsBegin;

      while (I < Text.size() && StringRef("-+ #0'I").contains(Text[I]))
        ++I;
      if (I < Text.size() && Text[I] == '*') {
        ++Argument;
        ++I;
        size_t WidthPosition = I;
        while (I < Text.size() && llvm::isDigit(Text[I]))
          ++I;
        if (I != WidthPosition && I < Text.size() && Text[I] == '$')
          return {};
      } else {
        while (I < Text.size() && llvm::isDigit(Text[I]))
          ++I;
      }
      bool HasPrecision = false;
      if (I < Text.size() && Text[I] == '.') {
        HasPrecision = true;
        ++I;
        if (I < Text.size() && Text[I] == '*') {
          ++Argument;
          ++I;
          size_t PrecisionPosition = I;
          while (I < Text.size() && llvm::isDigit(Text[I]))
            ++I;
          if (I != PrecisionPosition && I < Text.size() && Text[I] == '$')
            return {};
        } else {
          while (I < Text.size() && llvm::isDigit(Text[I]))
            ++I;
        }
      }

      bool WideString = false;
      if (I + 1 < Text.size() && ((Text[I] == 'h' && Text[I + 1] == 'h') ||
                                  (Text[I] == 'l' && Text[I + 1] == 'l'))) {
        WideString = Text[I] == 'l';
        I += 2;
      } else if (I < Text.size() && StringRef("hljztLq").contains(Text[I])) {
        WideString = Text[I] == 'l';
        ++I;
      }
      if (I >= Text.size())
        return {};
      char Conversion = Text[I++];
      if (Conversion == '%' || Conversion == 'm')
        continue;
      // A nonnegative printf precision bounds the read; a negative `*`
      // precision is treated as omitted.  Modeling both constant and runtime
      // precisions needs a richer descriptor.  Conservatively skip all
      // precision-bearing `%s` conversions in this slice rather than issue a
      // false-definite diagnostic.
      if (Conversion == 's' && !WideString && !HasPrecision &&
          Argument < Call.getNumArgs())
        Result.push_back(Argument);
      ++Argument;
    }
    return Result;
  }

  bool checkInitializedCStringSink(const CallEvent &Call,
                                   CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    for (unsigned Argument : cStringArguments(Call)) {
      std::optional<InitializedBytePosition> Position =
          initializedBytePosition(Call.getArgSVal(Argument), C.getASTContext());
      if (!Position || !Position->ByteOffset || *Position->ByteOffset != 0)
        continue;
      const SVal *Terminator =
          State->get<QEMUKnownNULTerminatorOffsets>(Position->Base);
      if (!Terminator)
        continue;
      InitializedCoverage Available =
          initializedCoverageIncludingAdjacentNUL(State, *Position, C);
      if (Available.Kind == InitializedCoverageKind::Unknown)
        continue;
      // The helper sets this only after proving that the known NUL is exactly
      // adjacent to the initialized prefix and that the added byte is inside
      // the object.  The C string is therefore fully initialized.  Avoid
      // asking the range solver to rediscover `n <= n + 1`: it can retain an
      // infeasible unsigned-wrap branch even after the required bound was
      // proved while constructing the coverage.
      if (Available.IncludesAdjacentNUL)
        continue;
      std::optional<BoundStates> Covered = compare(
          State, *Terminator, BO_LE, Available.Length, C.getSValBuilder());
      if (!Covered || !Covered->Unsafe)
        continue;
      QualType OffsetType = Terminator->getType(C.getASTContext());
      if (OffsetType.isNull() || !OffsetType->isIntegerType())
        continue;
      llvm::APSInt Maximum =
          C.getSValBuilder().getBasicValueFactory().getMaxValue(OffsetType);
      SVal MaximumValue = C.getSValBuilder().makeIntVal(Maximum);
      if (!isDefinitelyTrue(Covered->Unsafe, *Terminator, BO_LT, MaximumValue,
                            C.getSValBuilder()))
        continue;
      SVal One = C.getSValBuilder().makeIntVal(1, OffsetType);
      SVal ReadLength = C.getSValBuilder().evalBinOp(
          Covered->Unsafe, BO_Add, *Terminator, One, OffsetType);
      if (ReadLength.isUnknownOrUndef())
        continue;
      std::optional<InputClass> Source;
      if (Available.RangeStart)
        if (const unsigned *Class = State->get<QEMUInitializedByteRangeClasses>(
                Available.RangeStart))
          if (*Class <= static_cast<unsigned>(InputClass::Mixed))
            Source = static_cast<InputClass>(*Class);
      if (reportUninitializedRead(C, Covered->Safe, Covered->Unsafe, ReadLength,
                                  Available.Length, Call.getArgExpr(Argument),
                                  *Position, "C string read", Source,
                                  /*ForcePossible=*/true))
        return true;
    }
    return false;
  }

  struct AllocationExtentDescriptor {
    unsigned CountArgument;
    std::optional<unsigned> ElementSizeArgument;
  };

  static std::optional<AllocationExtentDescriptor>
  allocationExtentDescriptor(const CallEvent &Call, ASTContext &Context) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() || !FD->getReturnType()->isPointerType())
      return std::nullopt;

    auto HasSignature = [&](unsigned ParameterCount,
                            std::initializer_list<unsigned> SizeParameters) {
      if (FD->getNumParams() != ParameterCount ||
          Call.getNumArgs() != ParameterCount)
        return false;
      for (unsigned Parameter : SizeParameters)
        if (Parameter >= ParameterCount ||
            !Context.hasSameUnqualifiedType(
                FD->getParamDecl(Parameter)->getType(), Context.getSizeType()))
          return false;
      return true;
    };

    StringRef Name = FD->getName();
    if ((Name == "malloc" || Name == "g_malloc" || Name == "g_malloc0" ||
         Name == "g_try_malloc" || Name == "g_try_malloc0") &&
        HasSignature(1, {0}))
      return AllocationExtentDescriptor{0, std::nullopt};
    if ((Name == "realloc" || Name == "g_realloc" || Name == "g_try_realloc" ||
         Name == "qemu_memalign" || Name == "qemu_try_memalign" ||
         Name == "g_memdup2") &&
        HasSignature(2, {1}))
      return AllocationExtentDescriptor{1, std::nullopt};
    if ((Name == "g_malloc_n" || Name == "g_malloc0_n" ||
         Name == "g_try_malloc_n" || Name == "g_try_malloc0_n" ||
         Name == "calloc") &&
        HasSignature(2, {0, 1}))
      return AllocationExtentDescriptor{0, 1};
    if ((Name == "g_realloc_n" || Name == "g_try_realloc_n") &&
        HasSignature(3, {1, 2}))
      return AllocationExtentDescriptor{1, 2};
    return std::nullopt;
  }

  struct AvailabilityAllocationSink {
    unsigned CountArgument;
    std::optional<unsigned> ElementSizeArgument;
  };

  static std::optional<AvailabilityAllocationSink>
  availabilityAllocationSink(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier())
      return std::nullopt;
    StringRef Name = FD->getName();
    if ((Name == "g_malloc" || Name == "g_malloc0") && Call.getNumArgs() >= 1)
      return AvailabilityAllocationSink{0, std::nullopt};
    if ((Name == "g_realloc" || Name == "qemu_memalign" ||
         Name == "g_memdup2") &&
        Call.getNumArgs() >= 2)
      return AvailabilityAllocationSink{1, std::nullopt};
    if ((Name == "g_malloc_n" || Name == "g_malloc0_n") &&
        Call.getNumArgs() >= 2)
      return AvailabilityAllocationSink{0, 1};
    if (Name == "g_realloc_n" && Call.getNumArgs() >= 3)
      return AvailabilityAllocationSink{1, 2};
    return std::nullopt;
  }

  static const BinaryOperator *sizeArithmetic(const Expr *E) {
    if (!E)
      return nullptr;
    E = resolveLocalInitializer(E)->IgnoreParenImpCasts();
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
        if (const SVal *Saved =
                C.getState()->get<QEMUSavedTaintedScalars>(Region))
          return *Saved;
        return Value;
      }
    return C.getSVal(E);
  }

  static SVal currentOperandValue(const Expr *Operand, CheckerContext &C) {
    const Expr *Core = Operand->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Core))
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        const VarRegion *Region =
            C.getState()->getRegion(VD, C.getStackFrame());
        SVal Current = C.getState()->getSVal(Region);
        if (!Current.isUnknownOrUndef())
          return Current;
      }
    SVal Value = expressionValue(Operand, C);
    if (!Value.isUnknownOrUndef())
      return Value;
    if (std::optional<llvm::APSInt> Constant =
            Operand->getIntegerConstantExpr(C.getASTContext()))
      return C.getSValBuilder().makeIntVal(*Constant);
    return UnknownVal();
  }

  static SVal currentArithmeticValue(const BinaryOperator *Arithmetic,
                                     CheckerContext &C) {
    SVal Left = currentOperandValue(Arithmetic->getLHS(), C);
    SVal Right = currentOperandValue(Arithmetic->getRHS(), C);
    if (Left.isUnknownOrUndef() || Right.isUnknownOrUndef())
      return UnknownVal();
    return C.getSValBuilder().evalBinOp(C.getState(), Arithmetic->getOpcode(),
                                        Left, Right, Arithmetic->getType());
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

  std::optional<InputClass>
  inputClassInScalarExpression(const Expr *E, ProgramStateRef State,
                               CheckerContext &C) const {
    if (!E)
      return std::nullopt;

    class SourceVisitor : public DynamicRecursiveASTVisitor {
      const QEMUGuestMemorySafetyChecker &Checker;
      ProgramStateRef State;
      CheckerContext &C;

      void addSource(InputClass Candidate) {
        if (Source && *Source != Candidate)
          Source = InputClass::Mixed;
        else
          Source = Candidate;
      }

    public:
      std::optional<InputClass> Source;

      SourceVisitor(const QEMUGuestMemorySafetyChecker &Checker,
                    ProgramStateRef State, CheckerContext &C)
          : Checker(Checker), State(State), C(C) {}

      bool VisitDeclRefExpr(DeclRefExpr *DRE) override {
        std::optional<InputClass> Candidate = Checker.inputClassForValue(
            State, QEMUGuestMemorySafetyChecker::expressionValue(DRE, C));
        if (!Candidate)
          return true;
        addSource(*Candidate);
        return true;
      }

      bool VisitArraySubscriptExpr(ArraySubscriptExpr *Subscript) override {
        const Expr *Base = Subscript->getBase()->IgnoreParenImpCasts();
        const auto *Member = dyn_cast<MemberExpr>(Base);
        const auto *Field =
            Member ? dyn_cast<FieldDecl>(Member->getMemberDecl()) : nullptr;
        if (Field && Field->getName() == "setup_buf" &&
            QEMUGuestMemorySafetyChecker::usbDeviceDataBufferCapacity(
                Field->getParent(), C.getASTContext()))
          addSource(InputClass::USB);
        return true;
      }
    } Visitor(*this, State, C);
    Visitor.TraverseStmt(const_cast<Expr *>(E));
    return Visitor.Source;
  }

  static SVal pointerValue(const Expr *E, CheckerContext &C) {
    const Expr *Core = E->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Core))
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
        if (VD->getType()->isArrayType())
          return C.getState()->getLValue(VD, C.getStackFrame());
    return C.getSVal(E);
  }

  static std::optional<uint64_t> staticObjectExtent(const Expr *E,
                                                    ASTContext &Context) {
    E = E ? E->IgnoreParenImpCasts() : nullptr;
    if (!E)
      return std::nullopt;
    if (const ConstantArrayType *Array =
            Context.getAsConstantArrayType(E->getType())) {
      if (Array->getSize().getActiveBits() > 64)
        return std::nullopt;
      uint64_t Elements = Array->getSize().getZExtValue();
      uint64_t ElementBytes =
          Context.getTypeSizeInChars(Array->getElementType()).getQuantity();
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
    return Context.getTypeSizeInChars(ObjectType).getQuantity();
  }

  static SVal flexibleArrayMemberExtent(const Expr *E, ProgramStateRef State,
                                        CheckerContext &C) {
    E = E ? E->IgnoreParenImpCasts() : nullptr;
    if (const auto *Address = dyn_cast_or_null<UnaryOperator>(E))
      if (Address->getOpcode() == UO_AddrOf)
        E = Address->getSubExpr()->IgnoreParenImpCasts();
    const auto *Member = dyn_cast_or_null<MemberExpr>(E);
    const auto *Field =
        Member ? dyn_cast<FieldDecl>(Member->getMemberDecl()) : nullptr;
    if (!Member || !Member->isArrow() || !Field)
      return UnknownVal();

    ASTContext &Context = C.getASTContext();
    const RecordDecl *Record = Field->getParent();
    if (!Context.getAsIncompleteArrayType(Field->getType()) || !Record ||
        !Record->hasFlexibleArrayMember())
      return UnknownVal();

    uint64_t OffsetBits = Context.getASTRecordLayout(Record).getFieldOffset(
        Field->getFieldIndex());
    unsigned CharWidth = Context.getCharWidth();
    if (!CharWidth || OffsetBits % CharWidth)
      return UnknownVal();

    SVal BaseExtent =
        getDynamicExtentWithOffset(State, pointerValue(Member->getBase(), C));
    if (!hasUsableExtent(State, BaseExtent, C.getSValBuilder()))
      return UnknownVal();
    SVal Offset = C.getSValBuilder().makeArrayIndex(OffsetBits / CharWidth);
    return C.getSValBuilder().evalBinOp(State, BO_Sub, BaseExtent, Offset,
                                        C.getSValBuilder().getArrayIndexType());
  }

  static const MemRegion *pointerBaseRegion(SVal Value) {
    const MemRegion *Region = Value.getAsRegion();
    return Region ? Region->getBaseRegion() : nullptr;
  }

  static const FieldDecl *namedField(QualType Type, StringRef Name) {
    if (Type->isPointerType())
      Type = Type->getPointeeType();
    const RecordDecl *Record = Type.getUnqualifiedType()->getAsRecordDecl();
    if (!Record)
      return nullptr;
    if (const RecordDecl *Definition = Record->getDefinition())
      Record = Definition;
    for (const FieldDecl *Field : Record->fields())
      if (Field->getName() == Name)
        return Field;
    return nullptr;
  }

  static std::optional<SVal> qemuIovecSize(ProgramStateRef State, SVal Iovec,
                                           QualType IovecType,
                                           CheckerContext &C) {
    const FieldDecl *Size = namedField(IovecType, "size");
    if (!Size || !Size->getType()->isIntegerType())
      return std::nullopt;
    SVal Location = State->getLValue(Size, Iovec);
    auto SizeLocation = Location.getAs<Loc>();
    if (!SizeLocation)
      return std::nullopt;
    SVal Value = State->getSVal(*SizeLocation);
    if (Value.isUnknownOrUndef())
      return std::nullopt;
    return Value;
  }

  static std::optional<SVal>
  callbackFieldValue(const ParmVarDecl *Parameter,
                     std::initializer_list<StringRef> Path,
                     ProgramStateRef State, CheckerContext &C) {
    const MemRegion *ParameterRegion =
        State->getRegion(Parameter, C.getStackFrame());
    SVal Object = State->getSVal(ParameterRegion);
    QualType ObjectType = Parameter->getType();
    for (StringRef Name : Path) {
      const FieldDecl *Field = namedField(ObjectType, Name);
      if (!Field)
        return std::nullopt;
      SVal FieldLocation = State->getLValue(Field, Object);
      if (!FieldLocation.getAs<Loc>())
        return std::nullopt;
      Object = FieldLocation;
      ObjectType = Field->getType();
    }
    auto Location = Object.getAs<Loc>();
    if (!Location)
      return std::nullopt;
    SVal Value = State->getSVal(*Location);
    if (Value.isUnknownOrUndef())
      return std::nullopt;
    return Value;
  }

  static std::optional<SVal>
  callbackBufferLength(const CallbackBufferInfo &Buffer, const FunctionDecl *FD,
                       ProgramStateRef State, CheckerContext &C) {
    switch (Buffer.LengthKind) {
    case CallbackBufferLengthKind::Parameter: {
      if (Buffer.LengthParameter >= FD->getNumParams())
        return std::nullopt;
      const ParmVarDecl *Length = FD->getParamDecl(Buffer.LengthParameter);
      const MemRegion *Region = State->getRegion(Length, C.getStackFrame());
      SVal Value = State->getSVal(Region);
      if (Value.isUnknownOrUndef())
        return std::nullopt;
      return Value;
    }
    case CallbackBufferLengthKind::Fixed:
      return C.getSValBuilder().makeIntVal(Buffer.FixedLength,
                                           C.getASTContext().getSizeType());
    case CallbackBufferLengthKind::VirtioConfigLength:
      if (FD->getNumParams() < 1)
        return std::nullopt;
      return callbackFieldValue(FD->getParamDecl(0), {"config_len"}, State, C);
    case CallbackBufferLengthKind::SCSICommandLength:
      if (FD->getNumParams() < 1)
        return std::nullopt;
      return callbackFieldValue(FD->getParamDecl(0), {"cmd", "len"}, State, C);
    }
    llvm_unreachable("unknown callback buffer length kind");
  }

  std::optional<std::pair<ProgramStateRef, SVal>>
  callbackBufferOffset(const MemRegion *Region, const MemRegion *Base,
                       ProgramStateRef State, CheckerContext &C) const {
    ASTContext &Context = C.getASTContext();
    SValBuilder &SVB = C.getSValBuilder();
    QualType SizeType = Context.getSizeType();
    SVal Offset = SVB.makeZeroVal(SizeType);
    llvm::APSInt Maximum = SVB.getBasicValueFactory().getMaxValue(SizeType);
    if (Maximum.getBitWidth() > 64)
      return std::nullopt;
    uint64_t MaximumValue = Maximum.getZExtValue();
    SVal MaximumSVal = SVB.makeIntVal(Maximum);

    auto Require = [&](SVal Left, BinaryOperatorKind Operation,
                       SVal Right) -> bool {
      std::optional<BoundStates> Bounds =
          compare(State, Left, Operation, Right, SVB);
      if (!Bounds)
        return false;
      if (Bounds->Unsafe)
        C.addTransition(Bounds->Unsafe);
      State = Bounds->Safe;
      return State != nullptr;
    };

    while (Region != Base) {
      const auto *Sub = dyn_cast<SubRegion>(Region);
      if (!Sub)
        return std::nullopt;
      SVal Delta;
      if (const auto *Element = dyn_cast<ElementRegion>(Region)) {
        QualType IndexType = Element->getIndex().getType(Context);
        if (IndexType.isNull() || !IndexType->isIntegerType())
          return std::nullopt;
        SVal Zero = SVB.makeZeroVal(IndexType);
        if (!Require(Element->getIndex(), BO_GE, Zero))
          return std::nullopt;
        SVal Index = SVB.evalCast(Element->getIndex(), SizeType, IndexType);
        if (Index.isUnknownOrUndef())
          return std::nullopt;
        QualType ElementType = Element->getElementType();
        if (ElementType->isIncompleteType())
          return std::nullopt;
        uint64_t ElementBytes =
            Context.getTypeSizeInChars(ElementType).getQuantity();
        if (!ElementBytes || ElementBytes > MaximumValue)
          return std::nullopt;
        if (ElementBytes > 1) {
          SVal Limit = SVB.makeIntVal(MaximumValue / ElementBytes, SizeType);
          if (!Require(Index, BO_LE, Limit))
            return std::nullopt;
        }
        SVal Scale = SVB.makeIntVal(ElementBytes, SizeType);
        Delta = SVB.evalBinOp(State, BO_Mul, Index, Scale, SizeType);
      } else if (const auto *Field = dyn_cast<FieldRegion>(Region)) {
        const RecordDecl *Record = Field->getDecl()->getParent();
        uint64_t OffsetBits = Context.getASTRecordLayout(Record).getFieldOffset(
            Field->getDecl()->getFieldIndex());
        unsigned CharWidth = Context.getCharWidth();
        if (!CharWidth || OffsetBits % CharWidth)
          return std::nullopt;
        uint64_t FieldBytes = OffsetBits / CharWidth;
        if (FieldBytes > MaximumValue)
          return std::nullopt;
        Delta = SVB.makeIntVal(FieldBytes, SizeType);
      } else {
        return std::nullopt;
      }
      if (Delta.isUnknownOrUndef())
        return std::nullopt;
      SVal Remaining =
          SVB.evalBinOp(State, BO_Sub, MaximumSVal, Offset, SizeType);
      if (Remaining.isUnknownOrUndef() || !Require(Delta, BO_LE, Remaining))
        return std::nullopt;
      Offset = SVB.evalBinOp(State, BO_Add, Offset, Delta, SizeType);
      if (Offset.isUnknownOrUndef())
        return std::nullopt;
      Region = Sub->getSuperRegion();
    }
    return std::make_pair(State, Offset);
  }

  static ProgramStateRef clearCallbackInputBuffer(ProgramStateRef State,
                                                  const MemRegion *Base) {
    return State->remove<QEMUInputBufferLengths>(Base)
        ->remove<QEMUInputBufferClasses>(Base)
        ->remove<QEMUInputBufferParameters>(Base)
        ->remove<QEMUInputBufferLengthParameters>(Base)
        ->remove<QEMUInputBufferReadConditions>(Base);
  }

  static bool directlyReferencesParameter(const Expr *Expression,
                                          const ParmVarDecl *Parameter) {
    if (!Expression || !Parameter)
      return false;
    Expression = Expression->IgnoreParenImpCasts();
    const auto *Reference = dyn_cast<DeclRefExpr>(Expression);
    return Reference && Reference->getDecl()->getCanonicalDecl() ==
                            Parameter->getCanonicalDecl();
  }

  static bool callbackAddressStartsAtLength(const Expr *Expression,
                                            const ParmVarDecl *Parameter) {
    if (!Expression || !Parameter)
      return false;
    Expression = Expression->IgnoreParenImpCasts();
    if (const auto *Address = dyn_cast<UnaryOperator>(Expression)) {
      if (Address->getOpcode() == UO_AddrOf)
        return callbackAddressStartsAtLength(Address->getSubExpr(), Parameter);
      return false;
    }
    if (const auto *Subscript = dyn_cast<ArraySubscriptExpr>(Expression))
      return directlyReferencesParameter(Subscript->getIdx(), Parameter);
    const auto *Add = dyn_cast<BinaryOperator>(Expression);
    if (!Add || Add->getOpcode() != BO_Add)
      return false;
    return (Add->getLHS()->getType()->isPointerType() &&
            directlyReferencesParameter(Add->getRHS(), Parameter)) ||
           (Add->getRHS()->getType()->isPointerType() &&
            directlyReferencesParameter(Add->getLHS(), Parameter));
  }

  // An engaged null state means the condition was modeled but only the
  // inactive path is feasible.  A disengaged optional means that the stored
  // predicate could not be represented, so callers must leave this access to
  // the ordinary analyzer models rather than treating it as unconditional
  // guest input.
  std::optional<ProgramStateRef>
  activateCallbackInputBuffer(ProgramStateRef State, const MemRegion *Base,
                              CheckerContext &C) const {
    const SVal *Condition = State->get<QEMUInputBufferReadConditions>(Base);
    if (!Condition)
      return State;
    auto Defined = Condition->getAs<DefinedOrUnknownSVal>();
    if (!Defined || Condition->isUnknownOrUndef())
      return std::nullopt;

    auto [Active, Inactive] = State->assume(*Defined);
    if (Inactive)
      C.addTransition(clearCallbackInputBuffer(Inactive, Base));
    if (Active)
      Active = Active->remove<QEMUInputBufferReadConditions>(Base);
    return std::optional<ProgramStateRef>(Active);
  }

  void reportCallbackBufferRead(CheckerContext &C, ProgramStateRef Safe,
                                ProgramStateRef Unsafe, SVal Offset,
                                SVal AccessSizeValue, SVal AccessEnd,
                                SVal Length, const Expr *Where,
                                InputClass Source,
                                const MemRegion *BufferBase) const {
    if (!Unsafe)
      return;
    bool Definite = !Safe;
    ExplodedNode *Node = C.generateErrorNode(Unsafe);
    if (!Node)
      return;

    llvm::SmallString<256> Buffer;
    llvm::raw_svector_ostream Message(Buffer);
    Message << (Definite ? "Level A: " : "Level B: ") << inputClassName(Source)
            << " callback buffer read "
            << (Definite ? "exceeds " : "may exceed ")
            << "the available guest-input bytes (access end "
            << valueRange(Unsafe, AccessEnd, C.getSValBuilder()) << ", bytes "
            << valueRange(Unsafe, Length, C.getSValBuilder()) << ')';
    auto Report = std::make_unique<PathSensitiveBugReport>(bugType(Definite),
                                                           Message.str(), Node);
    if (Where)
      Report->addRange(Where->getSourceRange());
    for (SymbolRef Symbol : AccessEnd.symbols())
      Report->markInteresting(Symbol);
    for (SymbolRef Symbol : Length.symbols())
      Report->markInteresting(Symbol);
    Report->markInteresting(BufferBase);
    std::string AccessSize =
        "bytes " + valueRange(Unsafe, AccessSizeValue, C.getSValBuilder());
    std::string ObjectExtent =
        "bytes " + valueRange(Unsafe, Length, C.getSValBuilder());
    std::string BufferExpression = witnessExpression(Where, C.getASTContext());
    std::string SourceDetail =
        BufferExpression.empty()
            ? "callback buffer and length parameters"
            : "callback buffer '" + BufferExpression + "' and length parameter";
    std::string AddressOrOffset =
        "byte offset " + valueRange(Unsafe, Offset, C.getSValBuilder()) +
        " from callback buffer";
    if (const ParmVarDecl *const *Parameter =
            Unsafe->get<QEMUInputBufferParameters>(BufferBase))
      if (!(*Parameter)->getName().empty())
        AddressOrOffset +=
            " parameter '" + (*Parameter)->getNameAsString() + "'";
    addStructuredWitness(*Report, C, Unsafe, Message.str(),
                         CallbackBufferBoundsRuleID, Source, SourceDetail,
                         "access end > available guest-input bytes", AccessEnd,
                         "host-read", AddressOrOffset, AccessSize, ObjectExtent,
                         "access end <= available guest-input bytes");
    C.emitReport(std::move(Report));
  }

  bool checkCallbackBufferMemoryRead(const CallEvent &Call,
                                     unsigned BufferArgument,
                                     unsigned LengthArgument, CheckerContext &C,
                                     ProgramStateRef State = nullptr) const {
    if (BufferArgument >= Call.getNumArgs() ||
        LengthArgument >= Call.getNumArgs())
      return false;
    const MemRegion *Region = Call.getArgSVal(BufferArgument).getAsRegion();
    if (!Region)
      return false;
    const MemRegion *Base = Region->getBaseRegion();
    if (!State)
      State = C.getState();
    const SVal *StoredLength = State->get<QEMUInputBufferLengths>(Base);
    const unsigned *StoredClass = State->get<QEMUInputBufferClasses>(Base);
    if (!StoredLength || !StoredClass)
      return false;
    std::optional<ProgramStateRef> Active =
        activateCallbackInputBuffer(State, Base, C);
    if (!Active)
      return false;
    if (!*Active)
      return true;
    State = *Active;
    StoredLength = State->get<QEMUInputBufferLengths>(Base);
    StoredClass = State->get<QEMUInputBufferClasses>(Base);
    if (!StoredLength || !StoredClass)
      return false;
    std::optional<std::pair<ProgramStateRef, SVal>> OffsetAndState =
        callbackBufferOffset(Region, Base, State, C);
    if (!OffsetAndState)
      return true;
    State = OffsetAndState->first;
    SVal Offset = OffsetAndState->second;
    SVal Length = *StoredLength;
    SVal Access = Call.getArgSVal(LengthArgument);
    ASTContext &Context = C.getASTContext();
    SValBuilder &SVB = C.getSValBuilder();
    QualType LengthType = Length.getType(Context);
    QualType AccessType = Call.getArgExpr(LengthArgument)->getType();
    QualType SizeType = Context.getSizeType();
    if (LengthType.isNull() || !LengthType->isIntegerType() ||
        !AccessType->isIntegerType())
      return true;

    auto Require = [&](SVal Left, BinaryOperatorKind Operation,
                       SVal Right) -> bool {
      std::optional<BoundStates> Bounds =
          compare(State, Left, Operation, Right, SVB);
      if (!Bounds)
        return false;
      if (Bounds->Unsafe)
        C.addTransition(Bounds->Unsafe);
      State = Bounds->Safe;
      return State != nullptr;
    };
    if (!Require(Length, BO_GE, SVB.makeZeroVal(LengthType)) ||
        !Require(Access, BO_GE, SVB.makeZeroVal(AccessType)))
      return true;
    Length = SVB.evalCast(Length, SizeType, LengthType);
    Access = SVB.evalCast(Access, SizeType, AccessType);
    if (Length.isUnknownOrUndef() || Access.isUnknownOrUndef())
      return true;

    // ElementRegion canonicalization is allowed to retain a different
    // integral-cast wrapper from the callback length stored at function
    // entry.  Preserve the exact catalog relationship when the call address
    // starts at that unmodified length parameter.  Explicit casts are not
    // ignored here: a narrowing cast may describe a genuinely different
    // offset and must remain only a possible violation.
    bool StartsAtLength = false;
    if (const ParmVarDecl *const *LengthParameter =
            State->get<QEMUInputBufferLengthParameters>(Base))
      StartsAtLength = callbackAddressStartsAtLength(
          Call.getArgExpr(BufferArgument), *LengthParameter);
    if (StartsAtLength)
      Offset = Length;

    llvm::APSInt Maximum = SVB.getBasicValueFactory().getMaxValue(SizeType);
    SVal MaximumSVal = SVB.makeIntVal(Maximum);
    SVal Remaining =
        SVB.evalBinOp(State, BO_Sub, MaximumSVal, Offset, SizeType);
    if (Remaining.isUnknownOrUndef() || !Require(Access, BO_LE, Remaining))
      return true;
    SVal AccessEnd = SVB.evalBinOp(State, BO_Add, Offset, Access, SizeType);
    if (AccessEnd.isUnknownOrUndef())
      return true;

    // A non-empty read whose first byte is exactly one-past the modeled input
    // is unconditionally out of bounds.  Prove that relationship from the
    // catalog-bound parameter declaration rather than asking the range solver
    // to rediscover equality through host-dependent ElementRegion casts.
    if (StartsAtLength) {
      SVal Zero = SVB.makeZeroVal(SizeType);
      std::optional<BoundStates> Positive =
          compare(State, Access, BO_GT, Zero, SVB);
      if (Positive && Positive->Safe)
        reportCallbackBufferRead(C, nullptr, Positive->Safe, Offset, Access,
                                 AccessEnd, Length,
                                 Call.getArgExpr(BufferArgument),
                                 static_cast<InputClass>(*StoredClass), Base);
      if (Positive && Positive->Unsafe)
        C.addTransition(Positive->Unsafe);
      if (Positive)
        return true;
    }

    std::optional<BoundStates> WithinBuffer =
        compare(State, AccessEnd, BO_LE, Length, SVB);
    if (!WithinBuffer)
      return true;
    InputClass Source = static_cast<InputClass>(*StoredClass);
    if (WithinBuffer->Unsafe)
      reportCallbackBufferRead(C, WithinBuffer->Safe, WithinBuffer->Unsafe,
                               Offset, Access, AccessEnd, Length,
                               Call.getArgExpr(BufferArgument), Source, Base);
    if (WithinBuffer->Safe)
      C.addTransition(WithinBuffer->Safe);
    return true;
  }

  bool modelCallbackBufferLoad(const ImplicitCastExpr *Cast,
                               CheckerContext &C) const {
    const MemRegion *Region = C.getSVal(Cast->getSubExpr()).getAsRegion();
    if (!Region)
      return false;
    const MemRegion *Base = Region->getBaseRegion();
    ProgramStateRef State = C.getState();
    const SVal *StoredLength = State->get<QEMUInputBufferLengths>(Base);
    if (!StoredLength)
      return false;
    const unsigned *StoredClass = State->get<QEMUInputBufferClasses>(Base);
    if (!StoredClass)
      return true;
    std::optional<ProgramStateRef> Active =
        activateCallbackInputBuffer(State, Base, C);
    if (!Active)
      return false;
    if (!*Active)
      return true;
    State = *Active;
    StoredLength = State->get<QEMUInputBufferLengths>(Base);
    StoredClass = State->get<QEMUInputBufferClasses>(Base);
    if (!StoredLength || !StoredClass)
      return false;
    std::optional<std::pair<ProgramStateRef, SVal>> OffsetAndState =
        callbackBufferOffset(Region, Base, State, C);
    if (!OffsetAndState)
      return true;
    State = OffsetAndState->first;
    SVal Offset = OffsetAndState->second;
    SVal Length = *StoredLength;
    ASTContext &Context = C.getASTContext();
    SValBuilder &SVB = C.getSValBuilder();
    QualType LengthType = Length.getType(Context);
    QualType SizeType = Context.getSizeType();
    if (LengthType.isNull() || !LengthType->isIntegerType())
      return true;

    auto Require = [&](SVal Left, BinaryOperatorKind Operation,
                       SVal Right) -> bool {
      std::optional<BoundStates> Bounds =
          compare(State, Left, Operation, Right, SVB);
      if (!Bounds)
        return false;
      if (Bounds->Unsafe)
        C.addTransition(Bounds->Unsafe);
      State = Bounds->Safe;
      return State != nullptr;
    };

    SVal Zero = SVB.makeZeroVal(LengthType);
    if (!Require(Length, BO_GE, Zero))
      return true;
    Length = SVB.evalCast(Length, SizeType, LengthType);
    if (Length.isUnknownOrUndef())
      return true;

    bool StartsAtLength = false;
    if (const ParmVarDecl *const *LengthParameter =
            State->get<QEMUInputBufferLengthParameters>(Base))
      StartsAtLength =
          callbackAddressStartsAtLength(Cast->getSubExpr(), *LengthParameter);
    if (StartsAtLength)
      Offset = Length;

    QualType AccessType = Cast->getType();
    if (AccessType->isIncompleteType())
      return true;
    uint64_t AccessBytes = Context.getTypeSizeInChars(AccessType).getQuantity();
    if (!AccessBytes)
      return true;
    llvm::APSInt Maximum = SVB.getBasicValueFactory().getMaxValue(SizeType);
    if (Maximum.getBitWidth() > 64 || AccessBytes > Maximum.getZExtValue())
      return true;
    SVal LastOffset =
        SVB.makeIntVal(Maximum.getZExtValue() - AccessBytes, SizeType);
    if (!Require(Offset, BO_LE, LastOffset))
      return true;
    SVal Access = SVB.makeIntVal(AccessBytes, SizeType);
    SVal AccessEnd = SVB.evalBinOp(State, BO_Add, Offset, Access, SizeType);
    if (AccessEnd.isUnknownOrUndef())
      return true;
    if (StartsAtLength) {
      reportCallbackBufferRead(C, nullptr, State, Offset, Access, AccessEnd,
                               Length, Cast->getSubExpr(),
                               static_cast<InputClass>(*StoredClass), Base);
      return true;
    }
    std::optional<BoundStates> WithinBuffer =
        compare(State, AccessEnd, BO_LE, Length, SVB);
    if (!WithinBuffer)
      return true;
    InputClass Source = static_cast<InputClass>(*StoredClass);
    if (WithinBuffer->Unsafe)
      reportCallbackBufferRead(C, WithinBuffer->Safe, WithinBuffer->Unsafe,
                               Offset, Access, AccessEnd, Length,
                               Cast->getSubExpr(), Source, Base);
    State = WithinBuffer->Safe;
    if (!State)
      return true;

    SVal Value = C.getSVal(Cast);
    if (Value.isUnknownOrUndef())
      return true;
    ProgramStateRef Tainted = addInputTaint(State, Value, Source);
    std::string Detail = "callback buffer is guest-controlled";
    if (const ParmVarDecl *const *Parameter =
            State->get<QEMUInputBufferParameters>(Base))
      Detail = "callback parameter '" + (*Parameter)->getNameAsString() +
               "' is guest-controlled";
    const NoteTag *Tag = sourceNote(C, Tainted, Value, Source, Detail);
    C.addTransition(Tainted, Tag);
    return true;
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

  static std::optional<InputClass> inputIovecSource(ProgramStateRef State,
                                                    SVal Value) {
    const MemRegion *Region = pointerBaseRegion(Value);
    if (Region)
      if (const unsigned *Stored = State->get<QEMUInputIovecs>(Region))
        return static_cast<InputClass>(*Stored);
    if (isTrackedVirtqueueIovec(State, Value) ||
        isVirtqueueOutIovecValue(State, Value))
      return InputClass::Virtqueue;
    return std::nullopt;
  }

  static ProgramStateRef addInputIovec(ProgramStateRef State, SVal Value,
                                       InputClass Source) {
    const MemRegion *Region = pointerBaseRegion(Value);
    if (!Region)
      return State;
    if (const unsigned *Stored = State->get<QEMUInputIovecs>(Region))
      if (static_cast<InputClass>(*Stored) != Source)
        Source = InputClass::Mixed;
    return State->set<QEMUInputIovecs>(Region, static_cast<unsigned>(Source));
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
    if (const auto *StatementExpression = dyn_cast<StmtExpr>(E)) {
      if (StatementExpression->HasSideEffects(C.getASTContext()))
        return std::nullopt;
      const CompoundStmt *Body = StatementExpression->getSubStmt();
      if (!Body || Body->body_empty())
        return std::nullopt;
      const auto *Result = dyn_cast<Expr>(Body->body_back());
      return Result ? integerRange(Result, C, Depth + 1) : std::nullopt;
    }
    if (const auto *Conditional = dyn_cast<ConditionalOperator>(E)) {
      if (Conditional->HasSideEffects(C.getASTContext()))
        return std::nullopt;
      std::optional<IntegerRange> True =
          integerRange(Conditional->getTrueExpr(), C, Depth + 1);
      std::optional<IntegerRange> False =
          integerRange(Conditional->getFalseExpr(), C, Depth + 1);
      if (!True || !False)
        return std::nullopt;

      enum class Selection {
        Unknown,
        Minimum,
        Maximum
      } Choice = Selection::Unknown;
      if (const auto *Comparison = dyn_cast<BinaryOperator>(
              Conditional->getCond()->IgnoreParenImpCasts())) {
        bool Direct = sameSimpleExpression(Comparison->getLHS(),
                                           Conditional->getTrueExpr()) &&
                      sameSimpleExpression(Comparison->getRHS(),
                                           Conditional->getFalseExpr());
        bool Reversed = sameSimpleExpression(Comparison->getLHS(),
                                             Conditional->getFalseExpr()) &&
                        sameSimpleExpression(Comparison->getRHS(),
                                             Conditional->getTrueExpr());
        if (Direct || Reversed) {
          bool Less = Comparison->getOpcode() == BO_LT ||
                      Comparison->getOpcode() == BO_LE;
          bool Greater = Comparison->getOpcode() == BO_GT ||
                         Comparison->getOpcode() == BO_GE;
          if ((Direct && Less) || (Reversed && Greater))
            Choice = Selection::Minimum;
          else if ((Direct && Greater) || (Reversed && Less))
            Choice = Selection::Maximum;
        }
      }
      if (Choice == Selection::Minimum)
        return IntegerRange{std::min(True->Minimum, False->Minimum),
                            std::min(True->Maximum, False->Maximum)};
      if (Choice == Selection::Maximum)
        return IntegerRange{std::max(True->Minimum, False->Minimum),
                            std::max(True->Maximum, False->Maximum)};
      return IntegerRange{std::min(True->Minimum, False->Minimum),
                          std::max(True->Maximum, False->Maximum)};
    }
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

  static SVal allocationArgumentValue(const CallEvent &Call,
                                      unsigned ArgumentIndex,
                                      CheckerContext &C) {
    const Expr *Argument = Call.getArgExpr(ArgumentIndex);
    SVal Value = expressionValue(Argument, C);
    if (Value.isUnknownOrUndef()) {
      const Expr *Resolved = resolveLocalInitializer(Argument);
      if (Resolved != Argument->IgnoreParenImpCasts())
        Value = expressionValue(Resolved, C);
    }
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

  static std::optional<BoundStates>
  checkedMultiplicationStates(ProgramStateRef State, SVal Left, SVal Right,
                              QualType ProductType, SValBuilder &SVB) {
    unsigned Width = SVB.getContext().getIntWidth(ProductType);
    std::optional<OverflowResult> Range =
        overflowRange(State, Left, Right, BO_Mul, Width, SVB);
    if (!Range)
      return std::nullopt;
    if (!Range->MayOverflow)
      return BoundStates{State, nullptr};
    if (Range->MustOverflow)
      return BoundStates{nullptr, State};

    const llvm::APSInt *LeftValue = SVB.getKnownValue(State, Left);
    const llvm::APSInt *RightValue = SVB.getKnownValue(State, Right);
    SVal Variable;
    const llvm::APSInt *Factor = nullptr;
    if (LeftValue && !LeftValue->isNegative()) {
      Factor = LeftValue;
      Variable = Right;
    } else if (RightValue && !RightValue->isNegative()) {
      Factor = RightValue;
      Variable = Left;
    }
    if (!Factor || Width == 0 || Width > 64 || Factor->getActiveBits() > 64)
      return std::nullopt;
    uint64_t FactorValue = Factor->getZExtValue();
    if (FactorValue == 0)
      return BoundStates{State, nullptr};

    llvm::APSInt Maximum = SVB.getBasicValueFactory().getMaxValue(ProductType);
    uint64_t Limit = Maximum.getZExtValue() / FactorValue;
    SVal LimitValue = SVB.makeIntVal(Limit, ProductType);
    return compare(State, Variable, BO_LE, LimitValue, SVB);
  }

  void savePendingAllocationExtent(const CallEvent &Call,
                                   const AllocationExtentDescriptor &Descriptor,
                                   CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    SVal Count = allocationArgumentValue(Call, Descriptor.CountArgument, C);
    if (Count.isUnknownOrUndef())
      return;

    if (!Descriptor.ElementSizeArgument) {
      const Expr *Origin = Call.getOriginExpr();
      State = State->set<QEMUPendingAllocationSizes>(Origin, Count);
      const BinaryOperator *Arithmetic =
          sizeArithmetic(Call.getArgExpr(Descriptor.CountArgument));
      if (Arithmetic && Arithmetic->getOpcode() == BO_Add) {
        SVal Left = currentOperandValue(Arithmetic->getLHS(), C);
        SVal Right = currentOperandValue(Arithmetic->getRHS(), C);
        SVal ArithmeticValue = currentArithmeticValue(Arithmetic, C);
        if (!Left.isUnknownOrUndef() && !Right.isUnknownOrUndef() &&
            isDefinitelyTrue(State, Count, BO_EQ, ArithmeticValue,
                             C.getSValBuilder())) {
          unsigned Width = C.getASTContext().getIntWidth(Arithmetic->getType());
          std::optional<OverflowResult> Overflow = overflowRange(
              State, Left, Right, BO_Add, Width, C.getSValBuilder());
          std::optional<AllocationRelationKind> Kind;
          if (Overflow && !Overflow->MayOverflow)
            Kind = AllocationRelationKind::NonOverflowingAdd;
          else if (Overflow && Overflow->MustOverflow)
            Kind = AllocationRelationKind::WrappedAdd;
          if (Kind)
            State =
                State
                    ->set<QEMUPendingAllocationRelationKinds>(
                        Origin, static_cast<unsigned>(*Kind))
                    ->set<QEMUPendingAllocationRelationLeft>(Origin, Left)
                    ->set<QEMUPendingAllocationRelationRight>(Origin, Right);
        }
      }
      if (!checkAllocationOverflow(Call, C, State))
        C.addTransition(State);
      return;
    }

    SVal ElementSize =
        allocationArgumentValue(Call, *Descriptor.ElementSizeArgument, C);
    if (ElementSize.isUnknownOrUndef())
      return;
    QualType ProductType = cast<FunctionDecl>(Call.getDecl())
                               ->getParamDecl(Descriptor.CountArgument)
                               ->getType();
    SValBuilder &SVB = C.getSValBuilder();
    SVal ConvertedCount =
        SVB.evalCast(Count, ProductType,
                     Call.getArgExpr(Descriptor.CountArgument)->getType());
    SVal ConvertedElementSize = SVB.evalCast(
        ElementSize, ProductType,
        Call.getArgExpr(*Descriptor.ElementSizeArgument)->getType());
    if (ConvertedCount.isUnknownOrUndef() ||
        ConvertedElementSize.isUnknownOrUndef())
      return;

    std::optional<BoundStates> Multiplication = checkedMultiplicationStates(
        State, ConvertedCount, ConvertedElementSize, ProductType, SVB);
    if (!Multiplication)
      return;
    if (Multiplication->Unsafe)
      C.addTransition(Multiplication->Unsafe);
    if (!Multiplication->Safe)
      return;

    SVal Size = SVB.evalBinOp(Multiplication->Safe, BO_Mul, ConvertedCount,
                              ConvertedElementSize, ProductType);
    if (auto DefinedSize = Size.getAs<DefinedOrUnknownSVal>()) {
      const Expr *Origin = Call.getOriginExpr();
      ProgramStateRef Sized =
          Multiplication->Safe->set<QEMUPendingAllocationSizes>(Origin,
                                                                *DefinedSize);
      Sized =
          Sized
              ->set<QEMUPendingAllocationRelationKinds>(
                  Origin, static_cast<unsigned>(
                              AllocationRelationKind::CheckedMultiply))
              ->set<QEMUPendingAllocationRelationLeft>(Origin, ConvertedCount)
              ->set<QEMUPendingAllocationRelationRight>(Origin,
                                                        ConvertedElementSize);
      C.addTransition(Sized);
    }
  }

  bool checkAllocationOverflow(const CallEvent &Call, CheckerContext &C,
                               ProgramStateRef State) const {
    std::optional<AllocationExtentDescriptor> Descriptor =
        allocationExtentDescriptor(Call, C.getASTContext());
    if (!Descriptor || Descriptor->ElementSizeArgument)
      return false;
    const BinaryOperator *Arithmetic =
        sizeArithmetic(Call.getArgExpr(Descriptor->CountArgument));
    if (!Arithmetic)
      return false;

    SVal Left = currentOperandValue(Arithmetic->getLHS(), C);
    SVal Right = currentOperandValue(Arithmetic->getRHS(), C);
    SVal Size = allocationArgumentValue(Call, Descriptor->CountArgument, C);
    SVal ArithmeticValue = currentArithmeticValue(Arithmetic, C);
    std::optional<BoundStates> StillCurrent =
        compare(State, Size, BO_EQ, ArithmeticValue, C.getSValBuilder());
    // A local initializer is useful only while its value still equals the
    // allocation argument.  Do not diagnose stale initializer arithmetic
    // after the local (or one of its operands) has been reassigned.
    if (!StillCurrent || !StillCurrent->Safe || StillCurrent->Unsafe)
      return false;
    State = StillCurrent->Safe;
    if (!taint::isTainted(State, Left) && !taint::isTainted(State, Right) &&
        !taint::isTainted(State, Size))
      return false;

    unsigned Width = C.getASTContext().getIntWidth(Arithmetic->getType());
    std::optional<OverflowResult> Result = overflowRange(
        State, Left, Right, Arithmetic->getOpcode(), Width, C.getSValBuilder());
    if (!Result || !Result->MayOverflow)
      return false;

    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return false;
    llvm::SmallString<256> Buffer;
    llvm::raw_svector_ostream Message(Buffer);
    Message << (Result->MustOverflow
                    ? "Level B: guest-controlled allocation-size arithmetic "
                      "overflows"
                    : "Level B: guest-controlled allocation-size arithmetic "
                      "may overflow")
            << " before the allocation (left "
            << valueRange(State, Left, C.getSValBuilder()) << ", right "
            << valueRange(State, Right, C.getSValBuilder()) << ')';
    auto Report = std::make_unique<PathSensitiveBugReport>(bugType(false),
                                                           Message.str(), Node);
    Report->addRange(Arithmetic->getSourceRange());
    for (SVal Value : {Left, Right, Size})
      for (SymbolRef Sym : taint::getTaintedSymbols(State, Value))
        Report->markInteresting(Sym);
    // Allocation arithmetic has no memory access width or effective address.
    // Account for it explicitly without fabricating memory-access geometry.
    addStructuredWitnessNotApplicable(*Report, C, Message.str(),
                                      AllocationSizeOverflowRuleID,
                                      "allocation-size-arithmetic");
    C.emitReport(std::move(Report));
    return true;
  }

  static bool isBoundedOnlyByUnsignedType(const Expr *Expression, SVal Value,
                                          ProgramStateRef State,
                                          CheckerContext &C) {
    if (!Expression || Value.isUnknownOrUndef())
      return false;
    QualType Type = Expression->IgnoreParenImpCasts()->getType();
    if (!Type->isUnsignedIntegerType())
      return false;

    llvm::APSInt TypeMaximum =
        C.getSValBuilder().getBasicValueFactory().getMaxValue(Type);
    const llvm::APSInt *DynamicMaximum =
        C.getSValBuilder().getMaxValue(State, Value);
    if (!DynamicMaximum || DynamicMaximum->isNegative())
      return false;
    unsigned Width =
        std::max(TypeMaximum.getBitWidth(), DynamicMaximum->getBitWidth());
    return TypeMaximum.zextOrTrunc(Width) == DynamicMaximum->zextOrTrunc(Width);
  }

  BugType &levelCBugType() const {
    if (!LevelCBug)
      LevelCBug = std::make_unique<BugType>(
          this, "Level C guest-controlled allocation is unbounded",
          "QEMU guest availability");
    return *LevelCBug;
  }

  void checkAvailabilityAllocation(const CallEvent &Call,
                                   CheckerContext &C) const {
    if (!ReportLevelC)
      return;
    std::optional<AvailabilityAllocationSink> Sink =
        availabilityAllocationSink(Call);
    if (!Sink)
      return;

    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD)
      return;
    unsigned Arguments[2] = {
        Sink->CountArgument,
        Sink->ElementSizeArgument.value_or(Sink->CountArgument)};
    unsigned ArgumentCount = Sink->ElementSizeArgument ? 2 : 1;
    for (unsigned I = 0; I < ArgumentCount; ++I) {
      unsigned ArgumentIndex = Arguments[I];
      const Expr *Expression = Call.getArgExpr(ArgumentIndex);
      // The Level A/B arithmetic diagnostic owns explicit addition and
      // multiplication. Keeping it out of Level C prevents duplicate reports.
      if (sizeArithmetic(Expression))
        continue;

      SVal Value = expressionValue(Expression->IgnoreParenImpCasts(), C);
      ProgramStateRef State = C.getState();
      std::optional<PersistentFieldInfo> Persistent =
          persistentGuestField(Expression);
      if (!taint::isTainted(State, Value)) {
        if (!Persistent)
          continue;
        State = addInputTaint(State, Value, Persistent->Source);
      }
      if (!Persistent)
        Persistent =
            persistentGuestFieldFromAliases(Expression, State, C, Value);
      if (!isBoundedOnlyByUnsignedType(Expression, Value, State, C))
        continue;

      std::string SourceDetail;
      if (Persistent)
        SourceDetail = persistentSourceDescription(*Persistent);
      else if (std::optional<InputClass> Source =
                   inputClassForValue(State, Value))
        SourceDetail = inputClassName(*Source).str();

      ExplodedNode *Node = C.generateNonFatalErrorNode(State);
      if (!Node)
        return;
      bool IsElementSize = Sink->ElementSizeArgument && I == 1;
      StringRef Quantity = IsElementSize               ? "element size"
                           : Sink->ElementSizeArgument ? "count"
                                                       : "size";
      llvm::SmallString<320> Buffer;
      llvm::raw_svector_ostream Message(Buffer);
      Message << "Level C: guest-controlled allocation " << Quantity << " in "
              << FD->getName()
              << " has no proven upper bound below its integer type maximum "
                 "(value "
              << valueRange(State, Value, C.getSValBuilder());
      if (Sink->ElementSizeArgument) {
        unsigned OtherIndex =
            IsElementSize ? Sink->CountArgument : *Sink->ElementSizeArgument;
        SVal Other = expressionValue(
            Call.getArgExpr(OtherIndex)->IgnoreParenImpCasts(), C);
        Message << (IsElementSize ? ", count " : ", element bytes ")
                << valueRange(State, Other, C.getSValBuilder());
      }
      if (!SourceDetail.empty())
        Message << ", source " << SourceDetail;
      Message << "); allocation failure can terminate QEMU";

      auto Report = std::make_unique<PathSensitiveBugReport>(
          levelCBugType(), Message.str(), Node);
      Report->addRange(Expression->getSourceRange());
      for (SymbolRef Symbol : taint::getTaintedSymbols(State, Value))
        Report->markInteresting(Symbol);
      // Availability reports do not describe a host memory access.
      addStructuredWitnessNotApplicable(*Report, C, Message.str(),
                                        AllocationUnboundedRuleID,
                                        "allocation-availability");
      C.emitReport(std::move(Report));
      return;
    }
  }

  void checkBitmapBitSink(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    const Expr *IndexExpression = Call.getArgExpr(0);
    SVal Index = expressionValue(IndexExpression, C);
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

    const Expr *BitmapExpression = Call.getArgExpr(1)->IgnoreParenImpCasts();
    SVal Extent = UnknownVal();
    if (C.getASTContext().getAsConstantArrayType(BitmapExpression->getType()))
      if (std::optional<uint64_t> Bytes =
              staticObjectExtent(BitmapExpression, C.getASTContext()))
        Extent = C.getSValBuilder().makeArrayIndex(*Bytes);
    if (!hasUsableExtent(State, Extent, C.getSValBuilder()))
      Extent = getDynamicExtentWithOffset(State, Call.getArgSVal(1));
    if (!hasUsableExtent(State, Extent, C.getSValBuilder()))
      if (std::optional<uint64_t> Bytes =
              staticObjectExtent(BitmapExpression, C.getASTContext()))
        Extent = C.getSValBuilder().makeArrayIndex(*Bytes);
    if (!hasUsableExtent(State, Extent, C.getSValBuilder()))
      Extent = flexibleArrayMemberExtent(BitmapExpression, State, C);

    const llvm::APSInt *KnownExtent =
        C.getSValBuilder().getKnownValue(State, Extent);
    if (!KnownExtent || KnownExtent->isNegative() ||
        KnownExtent->getActiveBits() > 64)
      return;
    uint64_t LongBytes =
        C.getASTContext()
            .getTypeSizeInChars(C.getASTContext().UnsignedLongTy)
            .getQuantity();
    uint64_t LongBits =
        C.getASTContext().getTypeSize(C.getASTContext().UnsignedLongTy);
    if (!LongBytes || !LongBits)
      return;
    uint64_t Words = KnownExtent->getZExtValue() / LongBytes;
    if (Words > std::numeric_limits<uint64_t>::max() / LongBits)
      return;
    SVal Capacity = C.getSValBuilder().makeIntVal(
        Words * LongBits, C.getASTContext().getSizeType());
    SVal UnsignedIndex = C.getSValBuilder().evalCast(
        Index, C.getASTContext().getSizeType(), IndexExpression->getType());
    if (UnsignedIndex.isUnknownOrUndef())
      return;
    std::optional<BoundStates> Inside =
        compare(State, UnsignedIndex, BO_LT, Capacity, C.getSValBuilder());
    if (!Inside || !Inside->Unsafe)
      return;

    std::string SourceDetail;
    if (Persistent)
      SourceDetail = persistentSourceDescription(*Persistent);
    SVal WordIndex = C.getSValBuilder().evalBinOp(
        Inside->Unsafe, BO_Div, UnsignedIndex,
        C.getSValBuilder().makeIntVal(LongBits,
                                      C.getASTContext().getSizeType()),
        C.getASTContext().getSizeType());
    std::string Address =
        "bitmap base '" +
        witnessExpression(BitmapExpression, C.getASTContext()) +
        "', bit index " +
        valueRange(Inside->Unsafe, Index, C.getSValBuilder()) +
        ", word index " +
        valueRange(Inside->Unsafe, WordIndex, C.getSValBuilder()) +
        " (unsigned long, " + std::to_string(LongBits) + " bits per word)";
    const auto *FD = cast<FunctionDecl>(Call.getDecl());
    StringRef Direction =
        FD->getName() == "test_bit" ? "host-read" : "host-write";
    report(
        C, Inside->Safe, Inside->Unsafe, Index, IndexExpression,
        "bitmap bit index", Capacity, BoundUnit::Bits, SourceDetail,
        MemoryAccessWitness{Direction, std::move(Address),
                            C.getSValBuilder().makeIntVal(
                                LongBytes, C.getASTContext().getSizeType())});
  }

  AllocationAccessRelation
  allocationAccessRelation(SVal Buffer, SVal Length,
                           const Expr *LengthExpression, ProgramStateRef State,
                           CheckerContext &C) const {
    SymbolRef Allocation = Buffer.getLocSymbolInBase();
    if (!Allocation)
      return AllocationAccessRelation::Unknown;
    const unsigned *StoredKind =
        State->get<QEMUAllocationRelationKinds>(Allocation);
    const SVal *Left = State->get<QEMUAllocationRelationLeft>(Allocation);
    const SVal *Right = State->get<QEMUAllocationRelationRight>(Allocation);
    if (!StoredKind || !Left || !Right)
      return AllocationAccessRelation::Unknown;

    AllocationRelationKind Kind =
        static_cast<AllocationRelationKind>(*StoredKind);
    SValBuilder &SVB = C.getSValBuilder();
    if (Kind == AllocationRelationKind::NonOverflowingAdd) {
      if (isDefinitelyTrue(State, Length, BO_LE, *Left, SVB) ||
          isDefinitelyTrue(State, Length, BO_LE, *Right, SVB))
        return AllocationAccessRelation::Covered;
      return AllocationAccessRelation::Unknown;
    }
    if (Kind == AllocationRelationKind::WrappedAdd) {
      if (isDefinitelyTrue(State, Length, BO_GE, *Left, SVB) ||
          isDefinitelyTrue(State, Length, BO_GE, *Right, SVB))
        return AllocationAccessRelation::Exceeds;
      return AllocationAccessRelation::Unknown;
    }

    const Expr *Core = LengthExpression->IgnoreParenImpCasts();
    while (const auto *Cast = dyn_cast<CastExpr>(Core))
      Core = Cast->getSubExpr()->IgnoreParenImpCasts();
    const auto *Multiply = dyn_cast<BinaryOperator>(Core);
    if (!Multiply || Multiply->getOpcode() != BO_Mul ||
        !Multiply->getType()->isUnsignedIntegerType() ||
        C.getASTContext().getIntWidth(Multiply->getType()) !=
            C.getASTContext().getIntWidth(C.getASTContext().getSizeType()))
      return AllocationAccessRelation::Unknown;

    SVal CurrentLeft = currentOperandValue(Multiply->getLHS(), C);
    SVal CurrentRight = currentOperandValue(Multiply->getRHS(), C);
    if (CurrentLeft.isUnknownOrUndef() || CurrentRight.isUnknownOrUndef())
      return AllocationAccessRelation::Unknown;
    CurrentLeft = SVB.evalCast(CurrentLeft, C.getASTContext().getSizeType(),
                               Multiply->getLHS()->getType());
    CurrentRight = SVB.evalCast(CurrentRight, C.getASTContext().getSizeType(),
                                Multiply->getRHS()->getType());
    bool Direct = isDefinitelyTrue(State, CurrentLeft, BO_EQ, *Left, SVB) &&
                  isDefinitelyTrue(State, CurrentRight, BO_EQ, *Right, SVB);
    bool Reversed = isDefinitelyTrue(State, CurrentLeft, BO_EQ, *Right, SVB) &&
                    isDefinitelyTrue(State, CurrentRight, BO_EQ, *Left, SVB);
    return Direct || Reversed ? AllocationAccessRelation::Covered
                              : AllocationAccessRelation::Unknown;
  }

  MemorySinkResult checkMemorySink(const CallEvent &Call,
                                   const MemorySink &Sink, CheckerContext &C,
                                   ProgramStateRef State = nullptr) const {
    if (!State)
      State = C.getState();
    SVal Length = Call.getArgSVal(Sink.LengthArgument);
    SVal BufferValue = Call.getArgSVal(Sink.BufferArgument);
    if (std::optional<SVal> RetiredExtent =
            directDMARetiredExtent(State, BufferValue)) {
      QualType LengthType = Call.getArgExpr(Sink.LengthArgument)->getType();
      SVal Zero = C.getSValBuilder().makeZeroVal(LengthType);
      std::optional<BoundStates> Positive =
          compare(State, Length, BO_GT, Zero, C.getSValBuilder());
      if (Positive && Positive->Safe) {
        // A zero-byte memory operation does not dereference its pointer and
        // remains a valid cleanup idiom.  Stop the positive path at the
        // temporal error so it cannot cascade into a spatial diagnostic.
        if (Positive->Unsafe)
          C.addTransition(Positive->Unsafe);
        SymbolRef Base = BufferValue.getLocSymbolInBase();
        const Expr *Origin = Base && State->get<QEMUDMARetiredOrigins>(Base)
                                 ? *State->get<QEMUDMARetiredOrigins>(Base)
                                 : nullptr;
        reportDirectDMAUseAfterUnmap(C, Positive->Safe, BufferValue,
                                     Call.getArgExpr(Sink.BufferArgument),
                                     Sink.Direction, Length, *RetiredExtent,
                                     Origin);
        return MemorySinkResult::LifetimePathSplit;
      }
    }
    const Expr *LengthExpression = Call.getArgExpr(Sink.LengthArgument);
    std::optional<PersistentFieldInfo> Persistent =
        persistentGuestField(LengthExpression);
    bool GuestControlled = taint::isTainted(State, Length);
    if (!GuestControlled && Persistent) {
      State = addInputTaint(State, Length, Persistent->Source);
      GuestControlled = taint::isTainted(State, Length);
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
    std::optional<SVal> MappedExtent =
        directDMAMappedExtent(State, BufferValue);
    bool IsDirectDMAMapping = MappedExtent.has_value();
    SVal Extent = MappedExtent ? *MappedExtent
                               : getDynamicExtentWithOffset(State, BufferValue);
    StringRef SinkDescription = Sink.Description;
    bool HasOffset = false;

    const Expr *Buffer =
        Call.getArgExpr(Sink.BufferArgument)->IgnoreParenImpCasts();
    MemoryAccessWitness Witness{
        Sink.Direction,
        "effective address '" + witnessExpression(Buffer, C.getASTContext()) +
            "'",
        Length};
    Witness.Input = inputClassForValue(State, Length);
    if (!hasUsableExtent(State, Extent, C.getSValBuilder()))
      if (std::optional<uint64_t> Bytes =
              staticObjectExtent(Buffer, C.getASTContext()))
        Extent = C.getSValBuilder().makeIntVal(*Bytes,
                                               C.getASTContext().getSizeType());
    if (!hasUsableExtent(State, Extent, C.getSValBuilder()))
      Extent = flexibleArrayMemberExtent(Buffer, State, C);
    const Expr *Pointer = nullptr;
    const Expr *Offset = nullptr;
    bool SelectedArrayElement = false;
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
          SelectedArrayElement = true;
        }
    }
    if (Pointer) {
      // getDynamicExtentWithOffset() may describe only the selected array
      // element for expressions such as &object->bytes[index].  That
      // one-element extent is not the bound for the pointer passed to a byte
      // operation; only diagnose after reconstructing the base-array tail.
      if (SelectedArrayElement)
        Extent = UnknownVal();
      QualType Pointee;
      if (Pointer->getType()->isPointerType())
        Pointee = Pointer->getType()->getPointeeType();
      else if (const ArrayType *Array =
                   C.getASTContext().getAsArrayType(Pointer->getType()))
        Pointee = Array->getElementType();
      if (!Pointee.isNull() && !Pointee->isVoidType() &&
          !Pointee->isIncompleteType()) {
        std::optional<SVal> MappedBaseExtent =
            directDMAMappedExtent(State, pointerValue(Pointer, C));
        // At PreCall the analyzer may have evaluated the complete pointer
        // argument without retaining an SVal for its pointer-valued operand.
        // If the complete addition is a known mapping, it has the same base
        // symbol as the pointer operand and therefore the same full extent.
        if (!MappedBaseExtent && MappedExtent)
          MappedBaseExtent = MappedExtent;
        if (MappedBaseExtent)
          IsDirectDMAMapping = true;
        SVal BaseExtent =
            MappedBaseExtent
                ? *MappedBaseExtent
                : getDynamicExtentWithOffset(State, pointerValue(Pointer, C));
        if (!hasUsableExtent(State, BaseExtent, C.getSValBuilder()))
          if (std::optional<uint64_t> Bytes =
                  staticObjectExtent(Pointer, C.getASTContext()))
            BaseExtent = C.getSValBuilder().makeIntVal(
                *Bytes, C.getASTContext().getSizeType());
        if (!hasUsableExtent(State, BaseExtent, C.getSValBuilder()))
          BaseExtent = flexibleArrayMemberExtent(Pointer, State, C);
        SVal OffsetValue = expressionValue(Offset, C);
        std::optional<PersistentFieldInfo> OffsetPersistent =
            persistentGuestField(Offset);
        if (!taint::isTainted(State, OffsetValue) && OffsetPersistent)
          State = addInputTaint(State, OffsetValue, OffsetPersistent->Source);
        if (!OffsetPersistent)
          OffsetPersistent =
              persistentGuestFieldFromAliases(Offset, State, C, OffsetValue);
        if (taint::isTainted(State, OffsetValue)) {
          GuestControlled = true;
          // The bound arithmetic may simplify to a constant on a constrained
          // path.  Preserve the controlling input's class before that step.
          if (std::optional<InputClass> Source =
                  inputClassForValue(State, OffsetValue))
            Witness.Input = Witness.Input && *Witness.Input != *Source
                                ? InputClass::Mixed
                                : *Source;
          if (SourceDetail.empty()) {
            if (OffsetPersistent)
              SourceDetail = persistentSourceDescription(*OffsetPersistent);
            else
              Witness.Source = "offset expression '" +
                               witnessExpression(Offset, C.getASTContext()) +
                               "'";
          }
        }
        uint64_t ElementBytes =
            C.getASTContext().getTypeSizeInChars(Pointee).getQuantity();
        if (ElementBytes == 1 &&
            memorySinkCoveredByCallbackAccess(
                Offset, Call.getArgExpr(Sink.LengthArgument), BaseExtent, C))
          return MemorySinkResult::NotReported;
        SVal Scale = C.getSValBuilder().makeIntVal(
            ElementBytes, C.getASTContext().getSizeType());
        SVal ConvertedOffset = C.getSValBuilder().evalCast(
            OffsetValue, C.getASTContext().getSizeType(),
            Offset->IgnoreParenImpCasts()->getType());
        SVal ByteOffset =
            C.getSValBuilder().evalBinOp(State, BO_Mul, ConvertedOffset, Scale,
                                         C.getASTContext().getSizeType());
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
          Witness.ByteOffset = ByteOffset;
          Witness.Base = witnessExpression(Pointer, C.getASTContext());
          SinkDescription = Sink.Description == "packet length"
                                ? "packet offset plus length"
                                : "memory-operation offset plus length";
        }
      }
    }
    if (!GuestControlled && !IsDirectDMAMapping)
      return MemorySinkResult::NotReported;
    if (IsDirectDMAMapping) {
      SinkDescription = HasOffset
                            ? "direct DMA mapped-buffer offset plus access size"
                            : "direct DMA mapped-buffer access size";
      if (SourceDetail.empty())
        SourceDetail = "DMA map returned length";
      Witness.Input = InputClass::DMA;
    }
    AllocationAccessRelation AllocationRelation = allocationAccessRelation(
        BufferValue, Length, LengthExpression, State, C);
    if (!HasOffset && AllocationRelation == AllocationAccessRelation::Covered)
      return MemorySinkResult::NotReported;
    if (AllocationRelation == AllocationAccessRelation::Exceeds) {
      report(C, nullptr, State, Required, LengthExpression, SinkDescription,
             Extent, BoundUnit::Bytes, SourceDetail, Witness);
      return MemorySinkResult::Reported;
    }
    if (!hasUsableExtent(State, Extent, C.getSValBuilder()))
      return MemorySinkResult::NotReported;
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
              return MemorySinkResult::NotReported;
          }
          if (std::optional<IntegerRange> Range =
                  integerRange(Call.getArgExpr(Sink.LengthArgument), C))
            if (Range->Maximum <= KnownExtent->getZExtValue())
              return MemorySinkResult::NotReported;
        }
    std::optional<BoundStates> Bounds =
        compare(State, BoundRequired, BO_LE, Extent, C.getSValBuilder());
    if (!Bounds || !Bounds->Unsafe)
      return MemorySinkResult::NotReported;
    report(C, Bounds->Safe, Bounds->Unsafe, Required,
           Call.getArgExpr(Sink.LengthArgument), SinkDescription, Extent,
           BoundUnit::Bytes, SourceDetail, Witness);
    return MemorySinkResult::Reported;
  }

  bool checkDMATransferPreCall(const CallEvent &Call, CheckerContext &C) const {
    std::optional<DMATransferDescriptor> Transfer = dmaTransferDescriptor(Call);
    if (!Transfer)
      return false;

    // The public transfer helpers are layered on top of one another.  Model
    // the outermost catalog contract once instead of treating the delegated
    // implementation call as a second guest-memory operation.
    if (isNestedDirectDMAContract(C, "transfer") ||
        isNestedSelectiveFullTransfer(C))
      return true;

    ProgramStateRef InitialState = C.getState();
    llvm::SmallVector<TransferDirectionState, 2> Directions =
        transferDirectionStates(*Transfer, Call, InitialState, C);
    for (const TransferDirectionState &Path : Directions) {
      MemorySink Sink{Transfer->BufferArgument, Transfer->LengthArgument,
                      Path.Direction == TransferBufferDirection::HostRead
                          ? "DMA source length"
                          : "memory-operation length",
                      transferDirectionName(Path.Direction)};

      if (Path.Direction == TransferBufferDirection::HostRead) {
        if (EnableInitializedByteTracking &&
            checkInitializedByteSink(Call, Sink, C, Path.State,
                                     /*IsDisclosureSink=*/true))
          continue;
        if (checkCallbackBufferMemoryRead(Call, Transfer->BufferArgument,
                                          Transfer->LengthArgument, C,
                                          Path.State))
          continue;
      }

      if (checkMemorySink(Call, Sink, C, Path.State) !=
          MemorySinkResult::NotReported)
        continue;
      if (Path.State != InitialState)
        C.addTransition(Path.State);
    }
    return true;
  }

  bool checkDMATransferPostCall(const CallEvent &Call,
                                CheckerContext &C) const {
    std::optional<DMATransferDescriptor> Transfer = dmaTransferDescriptor(Call);
    if (!Transfer)
      return false;
    if (isNestedDirectDMAContract(C, "transfer") ||
        isNestedSelectiveFullTransfer(C))
      return true;

    // A default-mode, fixed host read has no post-call memory effect.  If its
    // result is syntactically discarded, splitting success from failure would
    // only retain constraints and shared facts keyed by an unobservable return
    // symbol.  In loops that creates duplicate downstream diagnostics.  Keep
    // the split whenever another current consumer can observe it: initialized
    // byte tracking, result diagnostics, dynamic direction, a host write, or
    // any use of the return expression.
    if (!EnableInitializedByteTracking && !EnableDMATransferResultDiagnostics &&
        !EnableFailedCompletionPublicationDiagnostics &&
        !Transfer->DirectionArgument &&
        fixedTransferBufferDirection(*Transfer) ==
            TransferBufferDirection::HostRead &&
        dmaTransferResultIsDefinitelyDiscarded(Call, C.getASTContext()))
      return true;

    ProgramStateRef InitialState = C.getState();
    const auto *FD = cast<FunctionDecl>(Call.getDecl());
    SVal Returned = Call.getReturnValue();
    SVal Zero = C.getSValBuilder().makeZeroVal(FD->getReturnType());
    std::optional<BoundStates> Result =
        compare(InitialState, Returned, BO_EQ, Zero, C.getSValBuilder());
    if (!Result)
      return true;

    SymbolRef ResultSymbol = Returned.getAsSymbol();
    SVal Buffer = Call.getArgSVal(Transfer->BufferArgument);
    SVal GuestAddress = Call.getArgSVal(Transfer->GuestAddressArgument);
    SVal Length = Call.getArgSVal(Transfer->LengthArgument);
    QualType LengthType = Call.getArgExpr(Transfer->LengthArgument)->getType();
    SVal Begin = C.getSValBuilder().makeZeroVal(LengthType);
    const MemRegion *Owner =
        directDMAOwner(Call.getArgSVal(Transfer->OwnerArgument));
    bool ReportDiscardedFailure =
        EnableDMATransferResultDiagnostics &&
        dmaTransferResultIsDefinitelyDiscarded(Call, C.getASTContext());
    if (ResultSymbol) {
      llvm::SmallDenseSet<SymbolRef, 8> Dependencies;
      auto AddDependencies = [&](SVal Value) {
        for (SymbolRef Symbol : Value.symbols())
          if (Symbol != ResultSymbol)
            Dependencies.insert(Symbol);
      };
      AddDependencies(Buffer);
      AddDependencies(GuestAddress);
      AddDependencies(Begin);
      AddDependencies(Length);
      if (const SymbolicRegion *OwnerBase =
              Owner ? Owner->getSymbolicBase() : nullptr)
        if (OwnerBase->getSymbol() != ResultSymbol)
          Dependencies.insert(OwnerBase->getSymbol());
      for (SymbolRef Dependency : Dependencies)
        C.getSymbolManager().addSymbolDependency(ResultSymbol, Dependency);
    }

    auto Propagate = [&](ProgramStateRef ResultPath, bool Succeeded) {
      if (!ResultPath)
        return;
      llvm::SmallVector<TransferDirectionState, 2> Directions =
          transferDirectionStates(*Transfer, Call, ResultPath, C);
      for (const TransferDirectionState &DirectionPath : Directions) {
        ProgramStateRef State = DirectionPath.State;
        if (ResultSymbol) {
          State = qemu::state::setValueResultState(
              State, ResultSymbol,
              Succeeded ? qemu::facts::ResultStateKind::Complete
                        : qemu::facts::ResultStateKind::Rejected);
          std::optional<SVal> ActualLength;
          if (Succeeded)
            ActualLength = Length;
          State = qemu::state::setTransferOperation(
              State, ResultSymbol, Buffer, Owner, GuestAddress, Begin, Length,
              ActualLength, transferFactDirection(DirectionPath.Direction));
          if (!Succeeded && EnableFailedCompletionPublicationDiagnostics)
            State = startFailedCompletionPublication(State, Call, *Transfer,
                                                     ResultSymbol, C);
        }

        const NoteTag *Tag = nullptr;
        if (DirectionPath.Direction == TransferBufferDirection::HostWrite) {
          if (!Succeeded) {
            if (EnableInitializedByteTracking)
              State = abandonInitializedByteDestination(
                  State, Call, Transfer->BufferArgument, C);
          } else {
            if (std::optional<SVal> Pointee = pointeeValue(State, Buffer)) {
              State = addInputTaint(State, *Pointee, InputClass::DMA);
              for (SymbolRef Symbol : Pointee->symbols())
                State = qemu::state::setValueProvenance(
                    State, Symbol, qemu::facts::ProvenanceKind::DMA);
              Tag = sourceNote(C, State, *Pointee, InputClass::DMA,
                               "populated guest-controlled data here");
            }
            if (EnableInitializedByteTracking) {
              std::optional<InitializedBytePosition> Position =
                  initializedBytePosition(Buffer, C.getASTContext());
              if (Position && State->get<QEMUInitializedByteObjectExtents>(
                                  Position->Base)) {
                State = State->remove<QEMUKnownNULTerminatorOffsets>(
                    Position->Base);
                State =
                    overwriteInitializedByteRange(State, *Position, Length, C);
                State = recordInitializedByteRange(
                    State, *Position, Length, InitializedByteKind::DMATransfer,
                    Call.getOriginExpr(), InputClass::DMA, C);
              }
            }
          }
        }
        if (!Succeeded && ReportDiscardedFailure &&
            reportIgnoredDMATransferFailure(C, State, Call, *Transfer,
                                            DirectionPath.Direction))
          continue;
        C.addTransition(State, Tag);
      }
    };

    Propagate(Result->Unsafe, /*Succeeded=*/false);
    Propagate(Result->Safe, /*Succeeded=*/true);
    return true;
  }

  void checkSuccessfulIovecCopy(const CallEvent &Call, const IovecCopy &Copy,
                                CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    std::optional<BoundStates> FullCopy =
        compare(State, Call.getReturnValue(), BO_EQ,
                Call.getArgSVal(Copy.LengthArgument), C.getSValBuilder());
    if (!FullCopy)
      return;
    if (FullCopy->Unsafe)
      C.addTransition(FullCopy->Unsafe);
    if (!FullCopy->Safe)
      return;

    ProgramStateRef Success = FullCopy->Safe;
    SVal Zero = C.getSValBuilder().makeZeroVal(
        Call.getArgExpr(Copy.LengthArgument)->getType());
    std::optional<BoundStates> Positive =
        compare(Success, Call.getArgSVal(Copy.LengthArgument), BO_GT, Zero,
                C.getSValBuilder());
    if (!Positive)
      return;
    if (Positive->Unsafe)
      C.addTransition(Positive->Unsafe);
    if (!Positive->Safe)
      return;
    Success = Positive->Safe;

    const NoteTag *Tag = nullptr;
    if (Copy.ToBuffer)
      if (std::optional<InputClass> Source =
              inputIovecSource(Success, Call.getArgSVal(Copy.IovecArgument)))
        if (std::optional<SVal> Pointee =
                pointeeValue(Success, Call.getArgSVal(Copy.BufferArgument))) {
          Success = addInputTaint(Success, *Pointee, *Source);
          Tag = sourceNote(C, Success, *Pointee, *Source,
                           "populated guest-controlled data here");
        }

    MemorySink Sink{Copy.BufferArgument, Copy.LengthArgument,
                    Copy.ToBuffer ? "memory-operation length"
                                  : "memory-operation source length",
                    Copy.ToBuffer ? "host-write" : "host-read"};
    if (checkMemorySink(Call, Sink, C, Success) ==
        MemorySinkResult::NotReported)
      C.addTransition(Success, Tag);
  }

public:
  void setReportLevelC(bool Enable) { ReportLevelC = Enable; }
  void setEnableInitializedByteTracking(bool Enable) {
    EnableInitializedByteTracking = Enable;
  }
  void setEnableDMATransferResultDiagnostics(bool Enable) {
    EnableDMATransferResultDiagnostics = Enable;
  }
  void setEnableFailedCompletionPublicationDiagnostics(bool Enable) {
    EnableFailedCompletionPublicationDiagnostics = Enable;
  }
  void setMaxInitializedRangesPerObject(int Maximum) {
    MaxInitializedRangesPerObject = unsigned(std::clamp(Maximum, 1, 64));
  }
  void setStructuredWitnessOptions(bool Enable, StringRef SourceRoot) {
    EmitStructuredWitness = Enable;
    QEMUSourceRoot = SourceRoot.str();
  }
  void setSelectiveSummaryManifest(StringRef Path, CheckerManager &Mgr) {
    loadSelectiveSummaryManifest(Path, Mgr);
  }

  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
                                 AnalysisManager &Mgr, BugReporter &BR) const {
    if (SelectiveSummaryManifest.empty())
      return;
    llvm::errs() << "QEMU_GMS_SELECTIVE_SUMMARY_V"
                 << SelectiveSummaryFormat << " loaded="
                 << SelectiveSummaries.size()
                 << " matched=" << SelectiveSummaryMatchedCalls.size()
                 << " consumed=" << SelectiveSummaryConsumedCalls.size()
                 << " unsupported=" << SelectiveSummaryUnsupportedCalls.size()
                 << '\n';
  }

  void checkASTDecl(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                    BugReporter &BR) const {
    using CatalogBinding = qemu_contracts_generated::CallbackBindingRecord;
    llvm::DenseMap<const FunctionDecl *,
                   llvm::SmallVector<const CatalogBinding *, 2>>
        CatalogClassInitRoots;
    class CatalogClassInitVisitor : public DynamicRecursiveASTVisitor {
      const QEMUGuestMemorySafetyChecker &Checker;
      const SourceManager &SM;
      llvm::DenseMap<const FunctionDecl *,
                     llvm::SmallVector<const CatalogBinding *, 2>> &Roots;

    public:
      CatalogClassInitVisitor(
          const QEMUGuestMemorySafetyChecker &Checker, const SourceManager &SM,
          llvm::DenseMap<const FunctionDecl *,
                         llvm::SmallVector<const CatalogBinding *, 2>> &Roots)
          : Checker(Checker), SM(SM), Roots(Roots) {}

      bool VisitVarDecl(VarDecl *VD) override {
        for (const CatalogBinding &Binding :
             qemu_contracts_generated::CallbackBindings) {
          const FunctionDecl *Root =
              Checker.catalogClassInitRoot(VD, Binding, SM);
          if (!Root)
            continue;
          auto &Bindings = Roots[Root];
          bool Duplicate = llvm::any_of(Bindings, [&](const auto *Existing) {
            return StringRef(Existing->ID) == Binding.ID;
          });
          if (!Duplicate)
            Bindings.push_back(&Binding);
        }
        return true;
      }
    } CatalogRootVisitor(*this, Mgr.getASTContext().getSourceManager(),
                         CatalogClassInitRoots);
    CatalogRootVisitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));

    class OperationTableVisitor : public DynamicRecursiveASTVisitor {
      const QEMUGuestMemorySafetyChecker &Checker;
      ASTContext &Context;
      const llvm::DenseMap<const FunctionDecl *,
                           llvm::SmallVector<const CatalogBinding *, 2>>
          &CatalogClassInitRoots;
      const FunctionDecl *CurrentFunction = nullptr;
      llvm::DenseMap<const FunctionDecl *, const CatalogBinding *>
          CatalogCallbacks;
      llvm::DenseSet<const FunctionDecl *> AmbiguousCatalogCallbacks;
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
          const QEMUGuestMemorySafetyChecker &Checker, ASTContext &Context,
          const llvm::DenseMap<const FunctionDecl *,
                               llvm::SmallVector<const CatalogBinding *, 2>>
              &CatalogClassInitRoots)
          : Checker(Checker), Context(Context),
            CatalogClassInitRoots(CatalogClassInitRoots) {}

      bool TraverseFunctionDecl(FunctionDecl *FD) override {
        const FunctionDecl *Previous = CurrentFunction;
        CurrentFunction = FD ? FD->getCanonicalDecl() : nullptr;
        bool Result = DynamicRecursiveASTVisitor::TraverseFunctionDecl(FD);
        CurrentFunction = Previous;
        return Result;
      }

      bool VisitVarDecl(VarDecl *VD) override {
        const InitListExpr *ILE = semanticInitList(VD->getInit());
        llvm::SmallVector<const FunctionDecl *, 4> RegisteredCallbacks;
        Checker.collectOperationTableCallbacks(ILE, RegisteredCallbacks);
        for (const FunctionDecl *FD : RegisteredCallbacks)
          Checker.recordCallbackRegistration(FD,
                                             VD->getQualifiedNameAsString());
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
        auto Root = CatalogClassInitRoots.find(CurrentFunction);
        if (Root == CatalogClassInitRoots.end())
          return true;
        auto Candidate = Checker.catalogCallbackAssignment(
            BO, Root->second, Context.getSourceManager());
        if (!Candidate)
          return true;
        const FunctionDecl *FD = Candidate->first;
        if (AmbiguousCatalogCallbacks.contains(FD))
          return true;
        auto [Found, Inserted] =
            CatalogCallbacks.try_emplace(FD, Candidate->second);
        if (!Inserted &&
            StringRef(Found->second->ID) != Candidate->second->ID) {
          CatalogCallbacks.erase(Found);
          AmbiguousCatalogCallbacks.insert(FD);
        }
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

      void applyCatalogCallbacks() {
        for (const auto &Entry : CatalogCallbacks)
          if (!AmbiguousCatalogCallbacks.contains(Entry.first))
            Checker.addCatalogCallback(Entry.first, *Entry.second);
      }
    } Visitor(*this, Mgr.getASTContext(), CatalogClassInitRoots);
    Visitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));
    Visitor.applyCatalogCallbacks();
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
    ProgramStateRef State = C.getState();
    const StackFrame *Frame = C.getStackFrame();
    const auto *FD = dyn_cast<FunctionDecl>(Frame->getDecl());
    if (!FD)
      return;
    if (EnableFailedCompletionPublicationDiagnostics)
      if (std::optional<FailedCompletionProtocolDescriptor> Protocol =
              failedCompletionProtocolForFunction(FD, C.getSourceManager())) {
        unsigned OwnerArgument =
            static_cast<unsigned>(Protocol->Owner->ArgumentIndex);
        if (OwnerArgument < FD->getNumParams()) {
          const MemRegion *ParameterRegion =
              State->getRegion(FD->getParamDecl(OwnerArgument), Frame);
          SVal Owner = State->getSVal(ParameterRegion);
          if (!Owner.isUnknownOrUndef())
            State = State->set<QEMUFailedCompletionScopeOwners>(Frame, Owner);
        }
      }
    if (!C.inTopFrame()) {
      if (State != C.getState())
        C.addTransition(State);
      return;
    }
    auto Found = Callbacks.find(FD->getCanonicalDecl());
    if (Found == Callbacks.end()) {
      if (State != C.getState())
        C.addTransition(State);
      return;
    }
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
      bool IsBuffer;
    };
    std::vector<SourceValue> Sources;

    for (const CallbackBufferInfo &Buffer : Found->second.Buffers) {
      if (Buffer.BufferParameter >= FD->getNumParams())
        continue;
      const ParmVarDecl *Parameter = FD->getParamDecl(Buffer.BufferParameter);
      const MemRegion *ParameterRegion =
          State->getRegion(Parameter, C.getStackFrame());
      SVal Pointer = State->getSVal(ParameterRegion);
      const MemRegion *Base = pointerBaseRegion(Pointer);
      std::optional<SVal> Length = callbackBufferLength(Buffer, FD, State, C);
      if (!Base || !Length || Length->isUnknownOrUndef())
        continue;
      std::optional<SVal> ReadCondition;
      if (Buffer.SelectorParameter) {
        if (*Buffer.SelectorParameter >= FD->getNumParams())
          continue;
        const ParmVarDecl *Selector =
            FD->getParamDecl(*Buffer.SelectorParameter);
        QualType SelectorType = Selector->getType();
        if (!SelectorType->isIntegerType())
          continue;
        const MemRegion *SelectorRegion =
            State->getRegion(Selector, C.getStackFrame());
        SVal SelectorValue = State->getSVal(SelectorRegion);
        SVal Mask =
            C.getSValBuilder().makeIntVal(Buffer.SelectorMask, SelectorType);
        SVal Expected =
            C.getSValBuilder().makeIntVal(Buffer.SelectorValue, SelectorType);
        SVal Masked = C.getSValBuilder().evalBinOp(State, BO_And, SelectorValue,
                                                   Mask, SelectorType);
        SVal Condition = C.getSValBuilder().evalBinOp(
            State, BO_EQ, Masked, Expected, C.getASTContext().BoolTy);
        if (Condition.isUnknownOrUndef() ||
            !Condition.getAs<DefinedOrUnknownSVal>())
          continue;
        ReadCondition = Condition;
      }
      InputClass Source = Found->second.Source;
      if (const unsigned *Previous = State->get<QEMUInputBufferClasses>(Base))
        if (static_cast<InputClass>(*Previous) != Source)
          Source = InputClass::Mixed;
      State =
          State->set<QEMUInputBufferLengths>(Base, *Length)
              ->set<QEMUInputBufferClasses>(Base, static_cast<unsigned>(Source))
              ->set<QEMUInputBufferParameters>(Base, Parameter);
      if (Buffer.LengthKind == CallbackBufferLengthKind::Parameter &&
          Buffer.LengthParameter < FD->getNumParams())
        State = State->set<QEMUInputBufferLengthParameters>(
            Base, FD->getParamDecl(Buffer.LengthParameter));
      else
        State = State->remove<QEMUInputBufferLengthParameters>(Base);
      if (ReadCondition)
        State = State->set<QEMUInputBufferReadConditions>(Base, *ReadCondition);
      else {
        State = State->remove<QEMUInputBufferReadConditions>(Base);
        Sources.push_back(
            {Pointer, Parameter->getNameAsString(), /*IsBuffer=*/true});
      }
    }
    for (const auto *Input : Found->second.MemberInputs) {
      if (!Input)
        continue;
      std::optional<SVal> Value = callbackMemberValue(
          FD, *Input, State, C.getStackFrame(), C.getSourceManager());
      if (!Value)
        continue;
      State = addInputTaint(State, *Value, InputClass::USB);
      Sources.push_back(
          {*Value, callbackMemberName(FD, *Input), /*IsBuffer=*/false});
    }
    for (unsigned Index = 0; Index < FD->getNumParams() && Index < 64;
         ++Index) {
      uint64_t Bit = uint64_t(1) << Index;
      if (!(Found->second.ParameterMask & Bit) &&
          !(Found->second.PointeeMask & Bit) &&
          !(Found->second.IovecMask & Bit))
        continue;
      const ParmVarDecl *Parameter = FD->getParamDecl(Index);
      const MemRegion *Region = State->getRegion(Parameter, C.getStackFrame());
      SVal Value = State->getSVal(Region);
      if (Found->second.ParameterMask & Bit) {
        State = addInputTaint(State, Value, Found->second.Source);
        Sources.push_back(
            {Value, Parameter->getNameAsString(), /*IsBuffer=*/false});
      }
      if (Found->second.PointeeMask & Bit)
        if (std::optional<SVal> Pointee = pointeeValue(State, Value)) {
          State = addInputTaint(State, *Pointee, Found->second.Source);
          Sources.push_back(
              {*Pointee, Parameter->getNameAsString(), /*IsBuffer=*/false});
        }
      if (Found->second.IovecMask & Bit)
        State = addInputIovec(State, Value, Found->second.Source);
    }
    if (State == C.getState())
      return;
    if (Sources.empty()) {
      C.addTransition(State);
      return;
    }

    std::string Class = inputClassName(Found->second.Source).str();
    const NoteTag *Tag =
        C.getNoteTag([Sources = std::move(Sources), Class = std::move(Class)](
                         PathSensitiveBugReport &Report) -> std::string {
          const SourceValue *MostSpecific = nullptr;
          size_t MostSpecificDepth = 0;
          for (const SourceValue &Source : Sources) {
            if (Source.IsBuffer || !Report.isInteresting(Source.Value))
              continue;
            size_t Depth = StringRef(Source.Name).count('.');
            if (!MostSpecific || Depth > MostSpecificDepth ||
                (Depth == MostSpecificDepth &&
                 Source.Name.size() > MostSpecific->Name.size())) {
              MostSpecific = &Source;
              MostSpecificDepth = Depth;
            }
          }
          if (MostSpecific)
            return Class + " callback parameter '" + MostSpecific->Name +
                   "' is guest-controlled";
          for (const SourceValue &Source : Sources)
            if (Source.IsBuffer && Report.isInteresting(Source.Value))
              return Class + " callback buffer parameter '" + Source.Name +
                     "' supplies guest-controlled bytes";
          return "";
        });
    C.addTransition(State, Tag);
  }

  void checkPreStmt(const CallExpr *Call, CheckerContext &C) const {
    if (!EnableInitializedByteTracking ||
        !isInitializedByteBulkFunction(Call->getDirectCallee(),
                                       Call->getNumArgs()))
      return;
    std::optional<InitializedBytePosition> Destination =
        initializedBytePosition(C.getSVal(Call->getArg(0)), C.getASTContext());
    if (!Destination ||
        !C.getState()->get<QEMUInitializedByteObjectExtents>(Destination->Base))
      return;
    ProgramStateRef State =
        C.getState()->set<QEMUPendingInitializedByteBulkDestinations>(
            Call, Destination->Base);
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkPostStmt(const CallExpr *Call, CheckerContext &C) const {
    ProgramStateRef State =
        C.getState()->remove<QEMUPendingInitializedByteBulkDestinations>(Call);
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (EnableFailedCompletionPublicationDiagnostics &&
        checkFailedCompletionPublication(Call, C))
      return;
    if (EnableInitializedByteTracking && checkInitializedCStringSink(Call, C))
      return;
    if (checkSelectiveSummaryPreCall(Call, C))
      return;
    if (checkDMATransferPreCall(Call, C))
      return;
    if (EnableInitializedByteTracking) {
      std::optional<USBPacketCopyDescriptor> USB =
          usbPacketCopyDescriptor(Call);
      if (USB) {
        std::optional<qemu::facts::USBPacketDirection> Direction =
            usbPacketCopyDirection(Call, *USB, C.getState(), C);
        if (Direction) {
          const Expr *Origin = Call.getOriginExpr();
          if (!Origin)
            return;
          ProgramStateRef State =
              recordUSBPacketTransaction(Call, *USB, *Direction, C.getState());
          const MemRegion *Packet =
              Call.getArgSVal(USB->PacketArgument).getAsRegion();
          if (qemu::state::getUSBTransaction(State, Packet) &&
              validateUSBPacketCopyBounds(Call, *USB, State, C))
            return;
          if (qemu::state::getUSBTransaction(State, Packet)) {
            if (State->get<QEMUPendingUSBPacketCopyDirections>(Origin))
              State = State->remove<QEMUPendingUSBPacketCopyDirections>(Origin);
          } else {
            State = State->set<QEMUPendingUSBPacketCopyDirections>(
                Origin, static_cast<unsigned>(*Direction));
          }
          const bool DeviceToHost =
              *Direction == qemu::facts::USBPacketDirection::DeviceToHost;
          MemorySink Sink{USB->HostBufferArgument, USB->LengthArgument,
                          DeviceToHost ? "USB packet source length"
                                       : "USB packet destination length",
                          DeviceToHost ? "host-read" : "host-write"};
          if (DeviceToHost &&
              checkInitializedByteSink(Call, Sink, C, State,
                                       /*IsDisclosureSink=*/true))
            return;
          if (checkMemorySink(Call, Sink, C, State) !=
              MemorySinkResult::NotReported)
            return;
          C.addTransition(State);
          return;
        }

        // The packet direction controls whether the host buffer is read or
        // written, but it does not change the number of bytes accessed.  Keep
        // the spatial check when pid is unresolved without inventing either
        // direction or an initialized-byte effect.  PostCall conservatively
        // abandons the destination's initialized-byte precision.
        ProgramStateRef State = C.getState();
        if (const MemRegion *Packet =
                Call.getArgSVal(USB->PacketArgument).getAsRegion())
          State = qemu::state::removeUSBTransaction(State, Packet);
        MemorySink Sink{USB->HostBufferArgument, USB->LengthArgument,
                        "USB packet buffer length", ""};
        if (checkMemorySink(Call, Sink, C, State) !=
            MemorySinkResult::NotReported)
          return;
        if (State != C.getState())
          C.addTransition(State);
        return;
      }
    }
    if (std::optional<DirectDMAMapDescriptor> Map =
            directDMAMapDescriptor(Call)) {
      const Expr *Origin = Call.getOriginExpr();
      ProgramStateRef State = C.getState();
      std::optional<SVal> Requested =
          pointeeValue(State, Call.getArgSVal(Map->LengthPointerArgument));
      if (Origin) {
        if (Requested && !Requested->isUnknownOrUndef())
          State =
              State->set<QEMUPendingDMAMapRequestedExtents>(Origin, *Requested);
        SVal Direction = Call.getArgSVal(Map->DirectionArgument);
        if (!Direction.isUnknownOrUndef())
          State = State->set<QEMUPendingDMAMapDirections>(Origin, Direction);
        if (Map->OwnerArgument) {
          SVal Owner = Call.getArgSVal(*Map->OwnerArgument);
          if (!Owner.isUnknownOrUndef())
            State = State->set<QEMUPendingDMAMapOwners>(Origin, Owner);
        }
      }
      if (State != C.getState())
        C.addTransition(State);
      return;
    }
    if (std::optional<DirectDMAUnmapDescriptor> Unmap =
            directDMAUnmapDescriptor(Call)) {
      // Inline wrappers such as pci_dma_unmap() delegate to another catalog
      // unmap.  The outermost API owns the contract: validating or retiring
      // again in its implementation would manufacture double-unmap and owner
      // mismatch reports.
      if (isNestedDirectDMAContract(C, "unmap"))
        return;
      ProgramStateRef State = C.getState();
      SVal Buffer = Call.getArgSVal(Unmap->BufferArgument);
      if (std::optional<DefinedOrUnknownSVal> Defined =
              Buffer.getAs<DefinedOrUnknownSVal>()) {
        auto [NonNull, Null] = State->assume(*Defined);
        // address_space_unmap() and its wrappers require a successful map.
        // In particular, a null buffer falls through memory_region_from_host()
        // and is treated as an embedded BounceBuffer.  Diagnose only a path
        // on which null is already proven; a merely nullable untracked caller
        // argument is not enough evidence.
        if (!NonNull && Null) {
          reportDirectDMAContract(
              C, Null, Call.getOriginExpr(),
              "direct DMA unmap is called with a null mapping", Buffer);
          return;
        }
      }
      // An unmap must receive the pointer returned by the map operation, not
      // an interior address.  Pointer-preserving copies and casts retain the
      // same symbol, while getAsSymbol() deliberately does not look through
      // a derived ElementRegion to its base.
      if (SymbolRef Base = Buffer.getAsSymbol()) {
        std::optional<SVal> MappedExtent = directDMAMappedExtent(State, Buffer);
        const SVal *MappedDirection = State->get<QEMUDMAMappedDirections>(Base);
        std::optional<SVal> RetiredExtent =
            directDMARetiredExtent(State, Buffer);
        SVal Length = Call.getArgSVal(Unmap->LengthArgument);
        SVal Direction = Call.getArgSVal(Unmap->DirectionArgument);
        SVal AccessLength = Call.getArgSVal(Unmap->AccessLengthArgument);
        const Expr *Where = Call.getOriginExpr();
        if (!MappedExtent) {
          if (RetiredExtent)
            reportDirectDMAContract(
                C, State, Where,
                "direct DMA mapping is unmapped more than once", Buffer);
          return;
        }

        const MemRegion *Object = directDMAObject(Buffer);
        if (!Object)
          return;
        const qemu::state::ObjectLifetime *Lifetime =
            qemu::state::getObjectLifetime(State, Object);
        if (!Lifetime)
          return;
        const MemRegion *Owner = Lifetime->getOwner();
        QualType AccessLengthType =
            Call.getArgExpr(Unmap->AccessLengthArgument)->getType();
        bool Reported = false;
        auto RetireMapping = [Buffer, AccessLength, AccessLengthType, Where,
                              &C](ProgramStateRef Retired) {
          return retireDirectDMAMapping(Retired, Buffer, AccessLength,
                                        AccessLengthType, Where, C);
        };

        if (Unmap->OwnerArgument && Owner) {
          SVal ActualOwner = Call.getArgSVal(*Unmap->OwnerArgument);
          SVal ExpectedOwner = C.getSValBuilder().makeLoc(Owner);
          if (!ActualOwner.isUnknownOrUndef()) {
            std::optional<BoundStates> Equal = compare(
                State, ActualOwner, BO_EQ, ExpectedOwner, C.getSValBuilder());
            if (Equal && !Equal->Safe && Equal->Unsafe)
              Reported = reportDirectDMAContract(
                  C, RetireMapping(Equal->Unsafe), Where,
                  "direct DMA unmap owner differs from the map owner",
                  ActualOwner, ExpectedOwner);
          }
        }

        // Detect the distinctive reversed form (..., len, len, direction) by
        // expression identity and by relating its last argument to the
        // direction saved at map time.  Expression types alone are not
        // sufficient: valid callers sometimes use a bool-sized access_len.
        if (!Reported && MappedDirection &&
            sameSimpleExpression(Call.getArgExpr(Unmap->LengthArgument),
                                 Call.getArgExpr(Unmap->DirectionArgument))) {
          SVal AccessSource =
              expressionValue(Call.getArgExpr(Unmap->AccessLengthArgument)
                                  ->IgnoreParenImpCasts(),
                              C);
          if (isDefinitelyTrue(State, AccessSource, BO_EQ, *MappedDirection,
                               C.getSValBuilder())) {
            Reported = reportDirectDMAContract(
                C, RetireMapping(State), Where,
                "direct DMA unmap arguments match the reversed argument order",
                Direction, AccessLength);
          }
        }

        if (!Reported && MappedExtent) {
          std::optional<BoundStates> Equal =
              compare(State, Length, BO_EQ, *MappedExtent, C.getSValBuilder());
          if (Equal && !Equal->Safe && Equal->Unsafe) {
            Reported = reportDirectDMAContract(
                C, RetireMapping(Equal->Unsafe), Where,
                "direct DMA unmap length differs from the returned map length",
                Length, *MappedExtent);
          }
        }

        if (!Reported && MappedExtent) {
          std::optional<BoundStates> Within = compare(
              State, AccessLength, BO_LE, *MappedExtent, C.getSValBuilder());
          if (Within && !Within->Safe && Within->Unsafe) {
            Reported = reportDirectDMAContract(
                C, RetireMapping(Within->Unsafe), Where,
                "direct DMA unmap access length exceeds the returned map "
                "length",
                AccessLength, *MappedExtent);
          }
        }

        if (!Reported && MappedDirection) {
          std::optional<BoundStates> Equal = compare(
              State, Direction, BO_EQ, *MappedDirection, C.getSValBuilder());
          QualType AccessType =
              Call.getArgExpr(Unmap->AccessLengthArgument)->getType();
          SVal Zero = C.getSValBuilder().makeZeroVal(AccessType);
          std::optional<BoundStates> Positive =
              compare(State, AccessLength, BO_GT, Zero, C.getSValBuilder());
          // A direction change while discarding a mapping without access is
          // used by valid cleanup paths.  Require a definite nonzero transfer.
          if (Equal && !Equal->Safe && Equal->Unsafe && Positive &&
              Positive->Safe && !Positive->Unsafe)
            Reported = reportDirectDMAContract(
                C, RetireMapping(Equal->Unsafe), Where,
                "direct DMA unmap direction differs from the map direction",
                Direction, *MappedDirection);
        }

        // Keep a valid mapping live while an inline wrapper executes.  Its
        // outermost PostCall transition performs the single logical retire.
      }
      return;
    }
    if (std::optional<IovecAlias> Alias = iovecAlias(Call)) {
      if (Alias->SourceExtent != IovecAlias::SourceExtentKind::None) {
        const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
        const Expr *Origin = Call.getOriginExpr();
        if (FD && Origin) {
          std::optional<SVal> Size = qemuIovecSize(
              C.getState(), Call.getArgSVal(Alias->SourceArgument),
              FD->getParamDecl(Alias->SourceArgument)->getType(), C);
          if (Size) {
            ProgramStateRef State =
                C.getState()->set<QEMUPendingIovecSourceSizes>(Origin, *Size);
            C.addTransition(State);
            return;
          }
        }
      }
    }
    if (std::optional<AllocationExtentDescriptor> Descriptor =
            allocationExtentDescriptor(Call, C.getASTContext()))
      savePendingAllocationExtent(Call, *Descriptor, C);
    checkAvailabilityAllocation(Call, C);
    if (isBitmapBitSink(Call, C.getASTContext()))
      checkBitmapBitSink(Call, C);
    if (std::optional<MemorySink> Sink = destinationMemorySink(Call))
      if (checkMemorySink(Call, *Sink, C) ==
          MemorySinkResult::LifetimePathSplit)
        return;
    if (const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl()))
      if (FD->getIdentifier() &&
          (FD->getName() == "memcmp" || FD->getName() == "bcmp") &&
          Call.getNumArgs() >= 3) {
        bool ModeledLeft = checkCallbackBufferMemoryRead(Call, 0, 2, C);
        bool ModeledRight = checkCallbackBufferMemoryRead(Call, 1, 2, C);
        if (ModeledLeft || ModeledRight)
          return;
      }
    if (std::optional<MemorySink> Sink = sourceMemorySink(Call)) {
      if (EnableInitializedByteTracking &&
          checkInitializedByteSink(Call, *Sink, C))
        return;
      if (checkCallbackBufferMemoryRead(Call, Sink->BufferArgument,
                                        Sink->LengthArgument, C))
        return;
      checkMemorySink(Call, *Sink, C);
    }
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    if (checkSelectiveSummaryPostCall(Call, C))
      return;
    if (checkDMATransferPostCall(Call, C))
      return;
    if (std::optional<DirectDMAMapDescriptor> Map =
            directDMAMapDescriptor(Call)) {
      ProgramStateRef State = C.getState();
      const Expr *Origin = Call.getOriginExpr();
      std::optional<SVal> Requested;
      std::optional<SVal> Direction;
      std::optional<SVal> OwnerValue;
      if (Origin) {
        if (const SVal *Saved =
                State->get<QEMUPendingDMAMapRequestedExtents>(Origin))
          Requested = *Saved;
        if (const SVal *Saved = State->get<QEMUPendingDMAMapDirections>(Origin))
          Direction = *Saved;
        if (const SVal *Saved = State->get<QEMUPendingDMAMapOwners>(Origin))
          OwnerValue = *Saved;
        State = State->remove<QEMUPendingDMAMapRequestedExtents>(Origin)
                    ->remove<QEMUPendingDMAMapDirections>(Origin)
                    ->remove<QEMUPendingDMAMapOwners>(Origin);
      }
      std::optional<SVal> Returned =
          pointeeValue(State, Call.getArgSVal(Map->LengthPointerArgument));
      if (!Returned || Returned->isUnknownOrUndef()) {
        if (State != C.getState())
          C.addTransition(State);
        return;
      }
      if (Requested) {
        std::optional<BoundStates> WithinRequest =
            compare(State, *Returned, BO_LE, *Requested, C.getSValBuilder());
        if (!WithinRequest || !WithinRequest->Safe)
          return;
        State = WithinRequest->Safe;
      }
      SVal ReturnValue = Call.getReturnValue();
      QualType LengthType = Call.getArgExpr(Map->LengthPointerArgument)
                                ->getType()
                                ->getPointeeType();
      if (std::optional<DefinedOrUnknownSVal> Defined =
              ReturnValue.getAs<DefinedOrUnknownSVal>()) {
        auto [NonNull, Null] = State->assume(*Defined);
        SVal Zero = C.getSValBuilder().makeZeroVal(LengthType);

        // The direct-map API returns a zero extent on failure.  Keep the
        // return pointer and output extent correlated so a caller that proves
        // the returned extent positive cannot acquire an impossible null
        // successor (and vice versa).
        if (Null) {
          std::optional<BoundStates> ZeroExtent =
              compare(Null, *Returned, BO_EQ, Zero, C.getSValBuilder());
          if (ZeroExtent && ZeroExtent->Safe)
            C.addTransition(ZeroExtent->Safe);
        }
        if (NonNull) {
          std::optional<BoundStates> PositiveExtent =
              compare(NonNull, *Returned, BO_GT, Zero, C.getSValBuilder());
          State = PositiveExtent ? PositiveExtent->Safe : nullptr;
        } else {
          State = nullptr;
        }
      }
      if (!State)
        return;
      if (SymbolRef Base = ReturnValue.getAsSymbol()) {
        const MemRegion *Object = directDMAObject(ReturnValue);
        if (!Object)
          return;
        const MemRegion *Owner =
            Map->OwnerArgument
                ? (OwnerValue ? directDMAOwner(*OwnerValue) : nullptr)
                : Object;
        SVal ExtentBegin = C.getSValBuilder().makeZeroVal(LengthType);
        State = State->remove<QEMUDMARetiredOrigins>(Base)
                    ->remove<QEMUDMAMappedDirections>(Base);
        State = qemu::state::setObjectExtent(State, Object,
                                             qemu::facts::ExtentKind::Mapped,
                                             ExtentBegin, *Returned);
        State = qemu::state::removeObjectExtent(
            State, Object, qemu::facts::ExtentKind::ActualTransfer);
        if (Requested)
          State = qemu::state::setObjectExtent(
              State, Object, qemu::facts::ExtentKind::Requested, ExtentBegin,
              *Requested);
        else
          State = qemu::state::removeObjectExtent(
              State, Object, qemu::facts::ExtentKind::Requested);
        State =
            qemu::state::setObjectLifetime(State, Object, Owner, ReturnValue,
                                           qemu::facts::LifetimeState::Live);
        State = qemu::state::setValueProvenance(
            State, Base, qemu::facts::ProvenanceKind::DMA);
        State = qemu::state::removeObjectDirection(State, Object);
        if (Direction) {
          State = State->set<QEMUDMAMappedDirections>(Base, *Direction);
          QualType DirectionType =
              Call.getArgExpr(Map->DirectionArgument)->getType();
          SVal Zero = C.getSValBuilder().makeZeroVal(DirectionType);
          SVal One = C.getSValBuilder().makeIntVal(1, DirectionType);
          if (isDefinitelyTrue(State, *Direction, BO_EQ, Zero,
                               C.getSValBuilder()))
            State = qemu::state::setObjectDirection(
                State, Object, qemu::facts::AccessDirection::HostRead);
          else if (isDefinitelyTrue(State, *Direction, BO_EQ, One,
                                    C.getSValBuilder()))
            State = qemu::state::setObjectDirection(
                State, Object, qemu::facts::AccessDirection::HostWrite);
        }
        C.addTransition(State);
      } else if (State != C.getState()) {
        C.addTransition(State);
      }
      return;
    }
    if (std::optional<DirectDMAUnmapDescriptor> Unmap =
            directDMAUnmapDescriptor(Call)) {
      if (isNestedDirectDMAContract(C, "unmap"))
        return;
      SVal Buffer = Call.getArgSVal(Unmap->BufferArgument);
      ProgramStateRef State = retireDirectDMAMapping(
          C.getState(), Buffer, Call.getArgSVal(Unmap->AccessLengthArgument),
          Call.getArgExpr(Unmap->AccessLengthArgument)->getType(),
          Call.getOriginExpr(), C);
      if (State != C.getState())
        C.addTransition(State);
      return;
    }
    if (std::optional<AllocationExtentDescriptor> Descriptor =
            allocationExtentDescriptor(Call, C.getASTContext())) {
      ProgramStateRef State = C.getState();
      const Expr *Origin = Call.getOriginExpr();
      const SVal *SavedSize = State->get<QEMUPendingAllocationSizes>(Origin);
      const unsigned *SavedRelationKind =
          State->get<QEMUPendingAllocationRelationKinds>(Origin);
      const SVal *SavedRelationLeft =
          State->get<QEMUPendingAllocationRelationLeft>(Origin);
      const SVal *SavedRelationRight =
          State->get<QEMUPendingAllocationRelationRight>(Origin);
      std::optional<unsigned> RelationKind;
      std::optional<SVal> RelationLeft;
      std::optional<SVal> RelationRight;
      if (SavedRelationKind && SavedRelationLeft && SavedRelationRight) {
        RelationKind = *SavedRelationKind;
        RelationLeft = *SavedRelationLeft;
        RelationRight = *SavedRelationRight;
      }
      State = State->remove<QEMUPendingAllocationSizes>(Origin)
                  ->remove<QEMUPendingAllocationRelationKinds>(Origin)
                  ->remove<QEMUPendingAllocationRelationLeft>(Origin)
                  ->remove<QEMUPendingAllocationRelationRight>(Origin);
      SVal Size = SavedSize ? *SavedSize : UnknownVal();
      // Direct-size allocators cannot fail their size calculation, so recover
      // it if another checker dropped our pre-call bookkeeping.  For checked
      // products, absence of a saved size represents the overflow/failure
      // path and must not be replaced with the wrapped multiplication.
      if (!SavedSize && !Descriptor->ElementSizeArgument)
        Size = allocationArgumentValue(Call, Descriptor->CountArgument, C);
      if (const MemRegion *Region = Call.getReturnValue().getAsRegion()) {
        if (auto DefinedSize = Size.getAs<DefinedOrUnknownSVal>())
          State = setDynamicExtent(State, Region, *DefinedSize);
        if (SymbolRef Allocation = Call.getReturnValue().getLocSymbolInBase())
          if (RelationKind && RelationLeft && RelationRight)
            State =
                State
                    ->set<QEMUAllocationRelationKinds>(Allocation,
                                                       *RelationKind)
                    ->set<QEMUAllocationRelationLeft>(Allocation, *RelationLeft)
                    ->set<QEMUAllocationRelationRight>(Allocation,
                                                       *RelationRight);
        const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
        if (FD && FD->getIdentifier() && FD->getName() == "g_memdup2") {
          if (std::optional<InputClass> Source =
                  inputIovecSource(State, Call.getArgSVal(0))) {
            State = addInputIovec(State, Call.getReturnValue(), *Source);
            if (*Source == InputClass::Virtqueue)
              State = State->add<QEMUVirtqueueIovecs>(Region->getBaseRegion());
          }
        }
      }
      C.addTransition(State);
      return;
    }
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier())
      return;
    StringRef Name = FD->getName();

    if (EnableInitializedByteTracking) {
      std::optional<USBPacketCopyDescriptor> USB =
          usbPacketCopyDescriptor(Call);
      if (USB) {
        ProgramStateRef State = C.getState();
        std::optional<qemu::facts::USBPacketDirection> Direction;
        std::optional<qemu::state::USBTransaction> Transaction;
        const MemRegion *Packet =
            Call.getArgSVal(USB->PacketArgument).getAsRegion();
        if (const qemu::state::USBTransaction *Recorded =
                qemu::state::getUSBTransaction(State, Packet)) {
          Transaction = *Recorded;
          Direction = Recorded->getDirection();
        }
        State = qemu::state::removeUSBTransaction(State, Packet);
        if (Transaction)
          State =
              advanceUSBPacketActualLength(Call, *USB, *Transaction, State, C);
        if (const Expr *Origin = Call.getOriginExpr()) {
          if (const unsigned *Saved =
                  State->get<QEMUPendingUSBPacketCopyDirections>(Origin))
            if (!Direction &&
                *Saved <= static_cast<unsigned>(
                              qemu::facts::USBPacketDirection::Setup))
              Direction = static_cast<qemu::facts::USBPacketDirection>(*Saved);
          State = State->remove<QEMUPendingUSBPacketCopyDirections>(Origin);
        }
        if (!Direction) {
          State = abandonInitializedByteDestination(State, Call,
                                                    USB->HostBufferArgument, C);
          if (State != C.getState())
            C.addTransition(State);
          return;
        }
        if (*Direction == qemu::facts::USBPacketDirection::DeviceToHost) {
          // The pending fact is scoped to this one call.  Publish its removal
          // even though an IN packet has no initialized-byte PostCall effect;
          // otherwise a loop can reuse this CallExpr with an unresolved pid and
          // inherit the previous iteration's direction.
          if (State != C.getState())
            C.addTransition(State);
          return;
        }

        std::optional<InitializedBytePosition> Position =
            initializedBytePosition(Call.getArgSVal(USB->HostBufferArgument),
                                    C.getASTContext());
        SVal Length = Call.getArgSVal(USB->LengthArgument);
        if (Position &&
            State->get<QEMUInitializedByteObjectExtents>(Position->Base)) {
          if (Position->ByteOffset && *Position->ByteOffset == 0)
            if (const SVal *Extent =
                    State->get<QEMUInitializedByteObjectExtents>(
                        Position->Base))
              if (isDefinitelyTrue(State, Length, BO_EQ, *Extent,
                                   C.getSValBuilder()))
                State =
                    restoreInitializedByteObjectExact(State, Position->Base);
          State = State->remove<QEMUKnownNULTerminatorOffsets>(Position->Base);
          State = overwriteInitializedByteRange(State, *Position, Length, C);
          State = recordInitializedByteRange(
              State, *Position, Length, InitializedByteKind::USBPacketCopy,
              Call.getOriginExpr(), InputClass::USB, C);
        }
        const NoteTag *Tag = nullptr;
        if (std::optional<SVal> Pointee =
                pointeeValue(State, Call.getArgSVal(USB->HostBufferArgument))) {
          State = addInputTaint(State, *Pointee, InputClass::USB);
          Tag = sourceNote(C, State, *Pointee, InputClass::USB,
                           "populated USB packet-controlled bytes here");
        }
        if (State != C.getState() || Tag)
          C.addTransition(State, Tag);
        return;
      }
    }

    if (EnableInitializedByteTracking &&
        isQEMUGetBufferInitializedByteProducer(Call)) {
      ProgramStateRef State = C.getState();
      auto PropagateAbandoned = [&](ProgramStateRef Path) {
        if (!Path)
          return;
        C.addTransition(abandonInitializedByteDestination(Path, Call, 1, C));
      };
      SVal Returned = Call.getReturnValue();
      SVal Requested = Call.getArgSVal(2);
      std::optional<BoundStates> WithinRequest =
          compare(State, Returned, BO_LE, Requested, C.getSValBuilder());
      if (!WithinRequest) {
        PropagateAbandoned(State);
        return;
      }
      PropagateAbandoned(WithinRequest->Unsafe);
      if (!WithinRequest->Safe)
        return;
      State = WithinRequest->Safe;
      SVal Zero = C.getSValBuilder().makeZeroVal(FD->getReturnType());
      std::optional<BoundStates> NonNegative =
          compare(State, Returned, BO_GE, Zero, C.getSValBuilder());
      if (!NonNegative) {
        PropagateAbandoned(State);
        return;
      }
      PropagateAbandoned(NonNegative->Unsafe);
      if (!NonNegative->Safe)
        return;
      State = NonNegative->Safe;
      std::optional<InitializedBytePosition> Position =
          initializedBytePosition(Call.getArgSVal(1), C.getASTContext());
      if (Position &&
          State->get<QEMUInitializedByteObjectExtents>(Position->Base)) {
        if (Position->ByteOffset && *Position->ByteOffset == 0)
          if (const SVal *Extent =
                  State->get<QEMUInitializedByteObjectExtents>(Position->Base))
            if (isDefinitelyTrue(State, Returned, BO_EQ, *Extent,
                                 C.getSValBuilder()))
              State = restoreInitializedByteObjectExact(State, Position->Base);
        State = State->remove<QEMUKnownNULTerminatorOffsets>(Position->Base);
        State = recordInitializedByteRange(
            State, *Position, Returned, InitializedByteKind::QEMUGetBuffer,
            Call.getOriginExpr(), InputClass::Migration, C);
      }
      if (std::optional<SVal> Pointee =
              pointeeValue(State, Call.getArgSVal(1))) {
        State = addInputTaint(State, *Pointee, InputClass::Migration);
        const NoteTag *Tag =
            sourceNote(C, State, *Pointee, InputClass::Migration,
                       "populated migration-controlled bytes here");
        C.addTransition(State, Tag);
      } else if (State != C.getState()) {
        C.addTransition(State);
      }
      return;
    }

    if (EnableInitializedByteTracking &&
        isGInputStreamReadAllInitializedByteProducer(Call)) {
      ProgramStateRef State = C.getState();
      auto PropagateAbandoned = [&](ProgramStateRef Path) {
        if (!Path)
          return;
        C.addTransition(abandonInitializedByteDestination(Path, Call, 1, C));
      };
      std::optional<SVal> Actual = pointeeValue(State, Call.getArgSVal(3));
      std::optional<InitializedBytePosition> Position =
          initializedBytePosition(Call.getArgSVal(1), C.getASTContext());
      if (!Actual || Actual->isUnknownOrUndef() || !Position ||
          !State->get<QEMUInitializedByteObjectExtents>(Position->Base)) {
        PropagateAbandoned(State);
        return;
      }

      SVal Requested = Call.getArgSVal(2);
      std::optional<BoundStates> WithinRequest =
          compare(State, *Actual, BO_LE, Requested, C.getSValBuilder());
      if (!WithinRequest) {
        PropagateAbandoned(State);
        return;
      }
      PropagateAbandoned(WithinRequest->Unsafe);
      if (!WithinRequest->Safe)
        return;
      State = WithinRequest->Safe;
      // bytes_read reports the number of bytes initialized even when GLib
      // returns FALSE after a short read.
      if (Position->ByteOffset && *Position->ByteOffset == 0)
        if (const SVal *Extent =
                State->get<QEMUInitializedByteObjectExtents>(Position->Base))
          if (isDefinitelyTrue(State, *Actual, BO_EQ, *Extent,
                               C.getSValBuilder()))
            State = restoreInitializedByteObjectExact(State, Position->Base);
      State = State->remove<QEMUKnownNULTerminatorOffsets>(Position->Base);
      State = recordInitializedByteRange(State, *Position, *Actual,
                                         InitializedByteKind::GInputReadAll,
                                         Call.getOriginExpr(), std::nullopt, C);
      C.addTransition(State);
      return;
    }

    if (EnableInitializedByteTracking &&
        (Name == "memcpy" || Name == "memmove" || Name == "__builtin_memcpy" ||
         Name == "__builtin_memmove") &&
        Call.getNumArgs() >= 3) {
      ProgramStateRef State = C.getState();
      std::optional<InitializedBytePosition> Destination =
          initializedBytePosition(Call.getArgSVal(0), C.getASTContext());
      std::optional<InitializedBytePosition> Source =
          initializedBytePosition(Call.getArgSVal(1), C.getASTContext());
      if (!Destination ||
          !State->get<QEMUInitializedByteObjectExtents>(Destination->Base))
        return;

      bool SourceTracked =
          Source && State->get<QEMUInitializedByteObjectExtents>(Source->Base);
      unsigned SourceRangeCount = 0;
      std::optional<SVal> Available;
      if (SourceTracked) {
        for (const auto &Entry : State->get<QEMUInitializedByteRangeLengths>())
          if (Entry.first->getBaseRegion() == Source->Base)
            ++SourceRangeCount;
        InitializedCoverage Coverage =
            initializedCoverageIncludingAdjacentNUL(State, *Source, C);
        if (Coverage.Kind == InitializedCoverageKind::Unknown) {
          State = abandonInitializedByteObject(State, Destination->Base);
          if (State != C.getState())
            C.addTransition(State);
          return;
        }
        if (Coverage.Kind == InitializedCoverageKind::ExactCoverage)
          Available = Coverage.Length;
        else if (SourceRangeCount) {
          // A copy beginning in a known gap may later intersect another
          // initialized component.  Until all components are translated,
          // treating the whole window as uninitialized would be inexact.
          State = abandonInitializedByteObject(State, Destination->Base);
          if (State != C.getState())
            C.addTransition(State);
          return;
        }
      } else if (Source && Source->ByteOffset) {
        // Static-storage arrays with an initializer (including string
        // literals) are fully initialized even though no DeclStmt callback
        // creates a path-state object for them.  Account for an interior
        // source pointer instead of assigning it the whole array extent.
        if (std::optional<uint64_t> Extent = staticallyInitializedExtent(
                Call.getArgExpr(1), C.getASTContext())) {
          if (*Source->ByteOffset <= *Extent)
            Available = C.getSValBuilder().makeIntVal(
                *Extent - *Source->ByteOffset, C.getASTContext().getSizeType());
        }
      }

      // An untracked source is unknown, not known-uninitialized.  Drop this
      // object's initializedness model rather than manufacturing a definite
      // disclosure from a heap or opaque source that the checker cannot yet
      // describe.
      if (!SourceTracked && !Available) {
        State = abandonInitializedByteObject(State, Destination->Base);
        if (State != C.getState())
          C.addTransition(State);
        return;
      }

      SVal CopyLength = Call.getArgSVal(2);
      if (!Available) {
        // A tracked source with no covering range is known-uninitialized.
        State =
            overwriteInitializedByteRange(State, *Destination, CopyLength, C);
        if (State != C.getState())
          C.addTransition(State);
        return;
      }
      SVal InitializedLength;
      bool CopyFullyInitialized = false;
      if (isDefinitelyTrue(State, CopyLength, BO_LE, *Available,
                           C.getSValBuilder())) {
        InitializedLength = CopyLength;
        CopyFullyInitialized = true;
      } else if (isDefinitelyTrue(State, *Available, BO_LE, CopyLength,
                                  C.getSValBuilder())) {
        if (SourceTracked && SourceRangeCount > 1) {
          State = abandonInitializedByteObject(State, Destination->Base);
          if (State != C.getState())
            C.addTransition(State);
          return;
        }
        InitializedLength = *Available;
      } else {
        State = abandonInitializedByteObject(State, Destination->Base);
        if (State != C.getState())
          C.addTransition(State);
        return;
      }

      if (CopyFullyInitialized && Destination->ByteOffset &&
          *Destination->ByteOffset == 0)
        if (const SVal *Extent =
                State->get<QEMUInitializedByteObjectExtents>(Destination->Base))
          if (isDefinitelyTrue(State, CopyLength, BO_EQ, *Extent,
                               C.getSValBuilder()))
            State = restoreInitializedByteObjectExact(State, Destination->Base);

      State = overwriteInitializedByteRange(State, *Destination, CopyLength, C);
      State = recordInitializedByteRange(State, *Destination, InitializedLength,
                                         InitializedByteKind::Copy,
                                         Call.getOriginExpr(), std::nullopt, C);
      if (State != C.getState())
        C.addTransition(State);
      return;
    }

    if (EnableInitializedByteTracking &&
        (Name == "memset" || Name == "__builtin_memset") &&
        Call.getNumArgs() >= 3) {
      ProgramStateRef State = C.getState();
      std::optional<InitializedBytePosition> Destination =
          initializedBytePosition(Call.getArgSVal(0), C.getASTContext());
      if (Destination &&
          State->get<QEMUInitializedByteObjectExtents>(Destination->Base)) {
        SVal Length = Call.getArgSVal(2);
        if (Destination->ByteOffset && *Destination->ByteOffset == 0) {
          if (const SVal *Extent = State->get<QEMUInitializedByteObjectExtents>(
                  Destination->Base))
            if (isDefinitelyTrue(State, Length, BO_EQ, *Extent,
                                 C.getSValBuilder()))
              State =
                  restoreInitializedByteObjectExact(State, Destination->Base);
        }
        State = overwriteInitializedByteRange(State, *Destination, Length, C);
        State = recordInitializedByteRange(
            State, *Destination, Length, InitializedByteKind::Memset,
            Call.getOriginExpr(), std::nullopt, C);
        QualType FillType = Call.getArgExpr(1)->getType();
        SVal Zero = C.getSValBuilder().makeZeroVal(FillType);
        QualType LengthType = Call.getArgExpr(2)->getType();
        SVal ZeroLength = C.getSValBuilder().makeZeroVal(LengthType);
        bool PositiveLength = isDefinitelyTrue(State, Length, BO_GT, ZeroLength,
                                               C.getSValBuilder());
        if (initializedByteObjectIsExact(State, Destination->Base) &&
            Destination->ByteOffset && PositiveLength &&
            isDefinitelyTrue(State, Call.getArgSVal(1), BO_EQ, Zero,
                             C.getSValBuilder())) {
          SVal Offset = C.getSValBuilder().makeIntVal(
              *Destination->ByteOffset, C.getASTContext().getSizeType());
          const SVal *Existing =
              State->get<QEMUKnownNULTerminatorOffsets>(Destination->Base);
          if (!Existing || isDefinitelyTrue(State, Offset, BO_LT, *Existing,
                                            C.getSValBuilder()))
            State = State->set<QEMUKnownNULTerminatorOffsets>(Destination->Base,
                                                              Offset);
        } else if (!isDefinitelyTrue(State, Length, BO_EQ, ZeroLength,
                                     C.getSValBuilder())) {
          State =
              State->remove<QEMUKnownNULTerminatorOffsets>(Destination->Base);
        }
      }
      // Continue into the existing USB-object memset model as well.  It
      // tracks a separate persistent-state contract.
      if (State != C.getState())
        C.addTransition(State);
    }
    if ((Name == "memset" || Name == "__builtin_memset") &&
        Call.getNumArgs() >= 3) {
      QualType DestinationType =
          Call.getArgExpr(0)->IgnoreParenImpCasts()->getType();
      const RecordDecl *Record = DestinationType->isPointerType()
                                     ? DestinationType->getPointeeType()
                                           .getUnqualifiedType()
                                           ->getAsRecordDecl()
                                     : nullptr;
      if (usbDeviceDataBufferCapacity(Record, C.getASTContext())) {
        ProgramStateRef State = C.getState();
        QualType FillType = Call.getArgExpr(1)->getType();
        QualType LengthType = Call.getArgExpr(2)->getType();
        SVal Zero = C.getSValBuilder().makeZeroVal(FillType);
        uint64_t ObjectBytes =
            C.getASTContext()
                .getTypeSizeInChars(DestinationType->getPointeeType())
                .getQuantity();
        SVal Required = C.getSValBuilder().makeIntVal(ObjectBytes, LengthType);
        if (isDefinitelyTrue(State, Call.getArgSVal(1), BO_EQ, Zero,
                             C.getSValBuilder()) &&
            isDefinitelyTrue(State, Call.getArgSVal(2), BO_GE, Required,
                             C.getSValBuilder())) {
          const MemRegion *Destination = Call.getArgSVal(0).getAsRegion();
          State = clearInvalidUSBSetupLengthsWithin(State, Destination);
          if (State != C.getState())
            C.addTransition(State);
          return;
        }
      }
    }
    if (std::optional<IovecCopy> Copy = iovecCopy(Call)) {
      checkSuccessfulIovecCopy(Call, *Copy, C);
      return;
    }
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
                                    ->remove<QEMUVirtqueueIovecs>(Region)
                                    ->remove<QEMUInputIovecs>(Region);
        if (State != C.getState())
          C.addTransition(State);
      }
      return;
    }
    if ((Name == "qemu_iovec_destroy" || Name == "qemu_iovec_reset") &&
        FD->getNumParams() == 1 && Call.getNumArgs() == 1 &&
        FD->getReturnType()->isVoidType() &&
        isNamedRecordPointer(FD->getParamDecl(0)->getType(), "QEMUIOVector")) {
      if (const MemRegion *Region = pointerBaseRegion(Call.getArgSVal(0))) {
        ProgramStateRef State = C.getState()->remove<QEMUInputIovecs>(Region);
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
    if ((Name == "g_memdup2" || Name == "g_memdup") &&
        FD->getNumParams() == 2 && Call.getNumArgs() == 2 &&
        FD->getReturnType()->isPointerType() &&
        FD->getParamDecl(0)->getType()->isPointerType() &&
        isInteger(FD->getParamDecl(1)->getType())) {
      if (std::optional<InputClass> Source =
              inputIovecSource(C.getState(), Call.getArgSVal(0))) {
        ProgramStateRef State =
            addInputIovec(C.getState(), Call.getReturnValue(), *Source);
        C.addTransition(State);
      }
      return;
    }
    if (std::optional<IovecAlias> Alias = iovecAlias(Call)) {
      ProgramStateRef State = C.getState();
      std::optional<SVal> SourceSize;
      if (const Expr *Origin = Call.getOriginExpr()) {
        if (const SVal *Saved = State->get<QEMUPendingIovecSourceSizes>(Origin))
          SourceSize = *Saved;
        State = State->remove<QEMUPendingIovecSourceSizes>(Origin);
      }
      auto RemoveDestinationProvenance = [&](ProgramStateRef Input) {
        if (!Alias->ReplacesDestination)
          return Input;
        if (const MemRegion *Destination =
                pointerBaseRegion(Call.getArgSVal(Alias->DestinationArgument)))
          return Input->remove<QEMUInputIovecs>(Destination);
        return Input;
      };
      if (Alias->RequiresPositiveReturn) {
        SVal Zero = C.getSValBuilder().makeZeroVal(FD->getReturnType());
        std::optional<BoundStates> Positive = compare(
            State, Call.getReturnValue(), BO_GT, Zero, C.getSValBuilder());
        if (!Positive)
          return;
        if (Positive->Unsafe)
          C.addTransition(Positive->Unsafe);
        State = Positive->Safe;
      }
      if (!State)
        return;
      if (Alias->RequiredPositiveArgument) {
        unsigned Argument = *Alias->RequiredPositiveArgument;
        QualType Type = Call.getArgExpr(Argument)->getType();
        SVal Zero = C.getSValBuilder().makeZeroVal(Type);
        std::optional<BoundStates> Positive = compare(
            State, Call.getArgSVal(Argument), BO_GT, Zero, C.getSValBuilder());
        if (!Positive)
          return;
        if (Positive->Unsafe)
          C.addTransition(RemoveDestinationProvenance(Positive->Unsafe));
        State = Positive->Safe;
      }
      if (!State)
        return;
      if (Alias->SourceExtent != IovecAlias::SourceExtentKind::None) {
        if (!SourceSize) {
          C.addTransition(State);
          return;
        }
        auto Require = [&](SVal Left, BinaryOperatorKind Operation,
                           SVal Right) -> bool {
          std::optional<BoundStates> Bounds =
              compare(State, Left, Operation, Right, C.getSValBuilder());
          if (!Bounds)
            return false;
          if (Bounds->Unsafe)
            C.addTransition(Bounds->Unsafe);
          State = Bounds->Safe;
          return State != nullptr;
        };
        QualType SizeType = SourceSize->getType(C.getASTContext());
        if (SizeType.isNull() || !SizeType->isIntegerType()) {
          C.addTransition(State);
          return;
        }
        if (Alias->SourceExtent == IovecAlias::SourceExtentKind::NonEmpty) {
          SVal Zero = C.getSValBuilder().makeZeroVal(SizeType);
          if (!Require(*SourceSize, BO_GT, Zero))
            return;
        } else if (Alias->SourceExtent ==
                   IovecAlias::SourceExtentKind::BytesAfterOffset) {
          if (!Alias->SourceOffsetArgument ||
              !Require(Call.getArgSVal(*Alias->SourceOffsetArgument), BO_LT,
                       *SourceSize))
            return;
        } else {
          if (!Alias->SourceOffsetArgument || !Alias->SourceLengthArgument)
            return;
          SVal Length = Call.getArgSVal(*Alias->SourceLengthArgument);
          if (!Require(Length, BO_LE, *SourceSize))
            return;
          SVal Remaining = C.getSValBuilder().evalBinOp(
              State, BO_Sub, *SourceSize, Length, SizeType);
          if (Remaining.isUnknownOrUndef() ||
              !Require(Call.getArgSVal(*Alias->SourceOffsetArgument), BO_LE,
                       Remaining))
            return;
        }
      }
      if (std::optional<InputClass> Source =
              inputIovecSource(State, Call.getArgSVal(Alias->SourceArgument))) {
        State = addInputIovec(
            State, Call.getArgSVal(Alias->DestinationArgument), *Source);
      } else if (Alias->ReplacesDestination) {
        State = RemoveDestinationProvenance(State);
      }
      C.addTransition(State);
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

  void checkPostStmt(const DeclStmt *Declaration, CheckerContext &C) const {
    if (!EnableInitializedByteTracking)
      return;
    ProgramStateRef State = C.getState();
    ASTContext &Context = C.getASTContext();
    for (const Decl *D : Declaration->decls()) {
      const auto *Variable = dyn_cast<VarDecl>(D);
      if (!Variable || !Variable->hasLocalStorage())
        continue;
      const ConstantArrayType *Array =
          Context.getAsConstantArrayType(Variable->getType());
      if (!Array || !Array->getElementType()->isIntegerType() ||
          Context.getIntWidth(Array->getElementType()) != 8 ||
          Array->getSize().getActiveBits() > 64)
        continue;
      uint64_t Elements = Array->getSize().getZExtValue();
      uint64_t ElementBytes =
          Context.getTypeSizeInChars(Array->getElementType()).getQuantity();
      if (!ElementBytes ||
          Elements > std::numeric_limits<uint64_t>::max() / ElementBytes)
        continue;
      uint64_t Bytes = Elements * ElementBytes;
      const VarRegion *Region = State->getRegion(Variable, C.getStackFrame());
      if (!Region)
        continue;
      SVal Extent = C.getSValBuilder().makeIntVal(Bytes, Context.getSizeType());
      // A VarRegion is reused when analysis revisits a declaration (for
      // example, on the next loop iteration).  Declaration execution starts
      // a fresh object lifetime, so no initialized range or terminator fact
      // from the previous lifetime may survive.
      State = clearInitializedByteObject(State, Region);
      State = recordInitializedByteObject(State, Region, Extent);
      if (!Variable->hasInit())
        continue;

      InitializedBytePosition Position{Region, Region, uint64_t(0)};
      InitializedByteKind Kind =
          isZeroAggregateInitializer(Variable->getInit(), Context)
              ? InitializedByteKind::ZeroInitialized
              : InitializedByteKind::Copy;
      State = recordInitializedByteRange(State, Position, Extent, Kind,
                                         Variable->getInit(), std::nullopt, C);
      if (Kind == InitializedByteKind::ZeroInitialized) {
        SVal Zero = C.getSValBuilder().makeIntVal(0, Context.getSizeType());
        State = State->set<QEMUKnownNULTerminatorOffsets>(Region, Zero);
      }
    }
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkPostStmt(const ImplicitCastExpr *Cast, CheckerContext &C) const {
    if (Cast->getCastKind() != CK_LValueToRValue)
      return;
    if (isUSBSetupBufferElement(C.getSVal(Cast->getSubExpr()).getAsRegion(),
                                C.getASTContext())) {
      SVal Value = C.getSVal(Cast);
      if (Value.isUnknownOrUndef())
        return;
      ProgramStateRef State =
          addInputTaint(C.getState(), Value, InputClass::USB);
      if (State == C.getState())
        return;
      const NoteTag *Tag = sourceNote(
          C, State, Value, InputClass::USB,
          "setup packet field 'setup_buf' supplies guest-controlled bytes");
      C.addTransition(State, Tag);
      return;
    }
    if (modelCallbackBufferLoad(Cast, C))
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

  void checkLocation(SVal Location, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const {
    const auto *At = dyn_cast_or_null<Expr>(S);
    const MemRegion *Region = Location.getAsRegion();
    SymbolRef Base = Location.getLocSymbolInBase();
    if (!At || !Region || !Base)
      return;

    ProgramStateRef State = C.getState();
    std::optional<SVal> MappedExtent = directDMAMappedExtent(State, Location);
    std::optional<SVal> RetiredExtent = directDMARetiredExtent(State, Location);
    if (!MappedExtent && !RetiredExtent)
      return;

    const auto *Typed = dyn_cast<TypedValueRegion>(Region);
    if (!Typed)
      return;
    if (const auto *Field = dyn_cast<FieldRegion>(Region))
      if (Field->getDecl()->isBitField())
        return;

    QualType AccessType = Typed->getValueType();
    if (AccessType.isNull() || AccessType->isVoidType() ||
        AccessType->isIncompleteType() ||
        AccessType->isVariablyModifiedType() || AccessType->isDependentType())
      return;
    // Keep this first slice to concrete-offset scalar accesses.  Aggregate
    // accesses can be represented as LazyCompoundVal instead of a location,
    // and need a separate model before they can be covered consistently.
    if (!AccessType->isScalarType() || AccessType->isSizelessType())
      return;
    int64_t AccessBytes =
        C.getASTContext().getTypeSizeInChars(AccessType).getQuantity();
    if (AccessBytes <= 0)
      return;

    QualType SizeType = C.getASTContext().getSizeType();
    SVal AccessSize =
        C.getSValBuilder().makeIntVal(uint64_t(AccessBytes), SizeType);
    StringRef Direction = IsLoad ? "host-read" : "host-write";
    // Loads can be diagnosed at the accessed subexpression when it appears on
    // a different source line.  Stores are normally diagnosed at the
    // assignment operator, so preserve the report's own location for them.
    SourceLocation AccessLocation =
        IsLoad ? At->IgnoreParenImpCasts()->getExprLoc() : SourceLocation();

    // An active map wins defensively if malformed state ever contains both
    // tokens.  A retired access is temporally invalid regardless of whether
    // its derived offset can still be represented precisely.
    if (!MappedExtent) {
      if (RetiredExtent) {
        const Expr *Origin = State->get<QEMUDMARetiredOrigins>(Base)
                                 ? *State->get<QEMUDMARetiredOrigins>(Base)
                                 : nullptr;
        reportDirectDMAUseAfterUnmap(C, State, Location, At, Direction,
                                     AccessSize, *RetiredExtent, Origin,
                                     AccessLocation);
      }
      return;
    }

    const SymbolicRegion *Symbolic = Region->getSymbolicBase();
    RegionOffset Offset = Region->getAsOffset();
    unsigned CharWidth = C.getASTContext().getCharWidth();
    if (!Symbolic || Symbolic->getSymbol() != Base || !Offset.isValid() ||
        Offset.getRegion() != Symbolic || Offset.hasSymbolicOffset() ||
        !CharWidth || Offset.getOffset() < 0 || Offset.getOffset() % CharWidth)
      return;
    uint64_t ByteOffset = uint64_t(Offset.getOffset()) / CharWidth;
    if (uint64_t(AccessBytes) >
        std::numeric_limits<uint64_t>::max() - ByteOffset)
      return;
    uint64_t AccessEndBytes = ByteOffset + uint64_t(AccessBytes);
    llvm::APSInt Maximum =
        C.getSValBuilder().getBasicValueFactory().getMaxValue(SizeType);
    if (Maximum.getActiveBits() <= 64 &&
        AccessEndBytes > Maximum.getZExtValue())
      return;

    SVal AccessEnd = C.getSValBuilder().makeIntVal(AccessEndBytes, SizeType);
    std::optional<BoundStates> Within =
        compare(State, AccessEnd, BO_LE, *MappedExtent, C.getSValBuilder());
    if (!Within || !Within->Unsafe)
      return;

    MemoryAccessWitness Witness{
        Direction,
        "effective address '" + witnessExpression(At, C.getASTContext()) + "'",
        AccessSize};
    Witness.ByteOffset = C.getSValBuilder().makeIntVal(ByteOffset, SizeType);
    Witness.Base = "direct DMA mapping";
    Witness.Input = InputClass::DMA;
    Witness.DiagnosticLocation = AccessLocation;
    report(C, Within->Safe, Within->Unsafe, AccessEnd, At,
           "direct DMA mapped-buffer typed access end", *MappedExtent,
           BoundUnit::Bytes, "DMA map returned length", Witness);
  }

  void checkBind(SVal Location, SVal Value, const Stmt *S, bool AtDeclInit,
                 CheckerContext &C) const {
    if (EnableFailedCompletionPublicationDiagnostics &&
        checkFailedCompletionRingAdvance(Location, S, C))
      return;
    const MemRegion *BindingRegion = Location.getAsRegion();
    if (EnableInitializedByteTracking) {
      if (std::optional<InitializedBytePosition> Position =
              initializedBytePosition(Location, C.getASTContext())) {
        ProgramStateRef Initial = C.getState();
        if (Initial->get<QEMUInitializedByteObjectExtents>(Position->Base)) {
          const auto *Typed = dyn_cast_or_null<TypedValueRegion>(BindingRegion);
          QualType StoredType = Typed ? Typed->getValueType() : QualType();
          const auto *Field = dyn_cast_or_null<FieldRegion>(BindingRegion);
          bool Supported =
              !StoredType.isNull() && !StoredType->isIncompleteType() &&
              !StoredType->isVariablyModifiedType() &&
              !StoredType->isDependentType() && !StoredType->isSizelessType() &&
              StoredType->isScalarType() &&
              (!Field || !Field->getDecl()->isBitField());
          if (!Supported) {
            ProgramStateRef State =
                abandonInitializedByteObject(Initial, Position->Base);
            if (State != Initial)
              C.addTransition(State);
            return;
          }

          int64_t StoredBytes =
              C.getASTContext().getTypeSizeInChars(StoredType).getQuantity();
          if (StoredBytes <= 0) {
            ProgramStateRef State =
                abandonInitializedByteObject(Initial, Position->Base);
            if (State != Initial)
              C.addTransition(State);
            return;
          }

          SVal WriteLength = C.getSValBuilder().makeIntVal(
              uint64_t(StoredBytes), C.getASTContext().getSizeType());
          ProgramStateRef State = Initial;
          // evalBind invokes checkBind before bindLoc sends its direct region
          // change notification.  Mark only writes we modeled precisely so
          // that checkRegionChanges can distinguish that notification from
          // bindDefaultInitial/Zero and other non-checkBind invalidations.
          if (!AtDeclInit)
            State = State->add<QEMUPendingInitializedBytePreciseBinds>(
                Position->Base);
          State =
              overwriteInitializedByteRange(State, *Position, WriteLength, C);

          // Assigning an indeterminate scalar does not initialize its object
          // representation.  The overwrite still invalidates older range and
          // NUL facts for every byte touched by the store.
          if (Value.isUndef()) {
            if (State != Initial)
              C.addTransition(State);
            return;
          }

          QualType ValueType = Value.getType(C.getASTContext());
          bool IsSingleByteZero = false;
          if (StoredBytes == 1 && !ValueType.isNull() &&
              ValueType->isIntegralOrEnumerationType()) {
            SVal Zero = C.getSValBuilder().makeZeroVal(ValueType);
            IsSingleByteZero =
                isDefinitelyTrue(State, Value, BO_EQ, Zero, C.getSValBuilder());
          }
          // A symbolic terminator has a dedicated relational fact.  Keeping
          // it out of the interval set lets the producer prefix remain exact
          // without pretending that an isolated byte extends that prefix.
          if (StoredBytes != 1 || Position->ByteOffset || !IsSingleByteZero)
            State = recordInitializedByteRange(
                State, *Position, WriteLength, InitializedByteKind::Copy,
                dyn_cast_or_null<Expr>(S), std::nullopt, C);

          if (IsSingleByteZero &&
              initializedByteObjectIsExact(State, Position->Base)) {
            if (std::optional<SVal> Offset =
                    initializedByteOffsetValue(*Position, State, C)) {
              const SVal *Existing =
                  State->get<QEMUKnownNULTerminatorOffsets>(Position->Base);
              if (!Existing || isDefinitelyTrue(State, *Offset, BO_LT,
                                                *Existing, C.getSValBuilder()))
                State = State->set<QEMUKnownNULTerminatorOffsets>(
                    Position->Base, *Offset);
            }
          }
          if (State != Initial)
            C.addTransition(State);
          return;
        }
      }
    }
    if (isUSBDeviceObjectRegion(BindingRegion, C.getASTContext())) {
      ProgramStateRef State = C.getState();
      const FieldRegion *Destination = usbSetupLengthRegion(BindingRegion, C);
      const Expr *Right = nullptr;
      if (const auto *Assignment = dyn_cast_or_null<BinaryOperator>(S))
        if (Assignment->getOpcode() == BO_Assign)
          Right = Assignment->getRHS();
      if (!Right)
        Right = dyn_cast_or_null<Expr>(S);
      if (isZeroAggregateInitializer(Right, C.getASTContext())) {
        State = clearInvalidUSBSetupLengthsWithin(State, BindingRegion);
        if (State != C.getState())
          C.addTransition(State);
        return;
      }
      const FieldRegion *Source = nullptr;
      const MemRegion *SourceObject = nullptr;
      if (std::optional<nonloc::LazyCompoundVal> Compound =
              Value.getAs<nonloc::LazyCompoundVal>())
        SourceObject = Compound->getRegion();
      if (!SourceObject && Right)
        SourceObject = C.getSVal(Right->IgnoreParenImpCasts()).getAsRegion();
      Source = invalidUSBSetupLengthWithin(State, SourceObject);
      State = copyInvalidUSBSetupLength(State, Source, Destination,
                                        C.getStackFrame());
      if (State != C.getState())
        C.addTransition(State);
      return;
    }
    if (const auto *Field = dyn_cast_or_null<FieldRegion>(BindingRegion)) {
      std::optional<uint64_t> Capacity =
          usbSetupLengthCapacity(Field, C.getASTContext());
      if (!Capacity)
        return;
      const Expr *SourceExpression = nullptr;
      if (const auto *Assignment = dyn_cast_or_null<BinaryOperator>(S))
        if (Assignment->isAssignmentOp())
          SourceExpression = Assignment->getOpcode() == BO_Assign
                                 ? Assignment->getRHS()
                                 : Assignment;
      if (!SourceExpression)
        SourceExpression = dyn_cast_or_null<Expr>(S);
      SVal SourceValue =
          SourceExpression ? expressionValue(SourceExpression, C) : Value;
      if (SourceValue.isUnknownOrUndef())
        SourceValue = Value;
      std::optional<InputClass> Source =
          inputClassInScalarExpression(SourceExpression, C.getState(), C);
      if (!Source)
        Source = inputClassForValue(C.getState(), SourceValue);
      if (!Source && !Value.isUnknownOrUndef())
        Source = inputClassForValue(C.getState(), Value);
      ProgramStateRef State = clearInvalidUSBSetupLength(C.getState(), Field);
      QualType Type = Field->getDecl()->getType();
      // Preserve the assignment conversion represented by the RHS AST.  The
      // checkBind value can still name the pre-conversion symbol for integral
      // casts, which would compare (for example) an unsigned 64-bit source
      // against the signed 32-bit setup_len bounds.
      SVal StoredValue = SourceExpression ? C.getSVal(SourceExpression) : Value;
      if (StoredValue.isUnknownOrUndef()) {
        QualType ValueType = Value.getType(C.getASTContext());
        StoredValue = ValueType.isNull()
                          ? Value
                          : C.getSValBuilder().evalCast(Value, Type, ValueType);
      }
      if (!Source || *Source != InputClass::USB ||
          StoredValue.isUnknownOrUndef()) {
        if (State != C.getState())
          C.addTransition(State);
        return;
      }
      if (usbNarrowingConversionKnownZero(SourceExpression, Type, State, C)) {
        if (State != C.getState())
          C.addTransition(State);
        return;
      }
      State = addInputTaint(State, StoredValue, InputClass::USB);

      const Expr *Origin = dyn_cast_or_null<Expr>(S);
      ProgramStateRef NonNegativeState = State;
      SVal Zero = C.getSValBuilder().makeZeroVal(Type);
      if (!isDefinitelyTrue(State, StoredValue, BO_GE, Zero,
                            C.getSValBuilder()) &&
          !usbStoredLengthKnownNonNegative(SourceExpression, Type, State, C)) {
        std::optional<BoundStates> NonNegative =
            compare(State, StoredValue, BO_GE, Zero, C.getSValBuilder());
        if (!NonNegative) {
          if (State != C.getState())
            C.addTransition(State);
          return;
        }
        if (NonNegative->Unsafe) {
          ProgramStateRef Invalid = markInvalidUSBSetupLength(
              NonNegative->Unsafe, Field, StoredValue, Origin,
              C.getStackFrame(), USBSetupLengthViolation::Negative,
              !NonNegative->Safe);
          C.addTransition(Invalid);
        }
        NonNegativeState = NonNegative->Safe;
      }

      if (NonNegativeState) {
        SVal Limit = C.getSValBuilder().makeIntVal(*Capacity, Type);
        std::optional<BoundStates> Within = compare(
            NonNegativeState, StoredValue, BO_LE, Limit, C.getSValBuilder());
        if (!Within) {
          C.addTransition(NonNegativeState);
          return;
        }
        if (Within->Unsafe) {
          ProgramStateRef Invalid = markInvalidUSBSetupLength(
              Within->Unsafe, Field, StoredValue, Origin, C.getStackFrame(),
              USBSetupLengthViolation::ExceedsCapacity, !Within->Safe);
          C.addTransition(Invalid);
        }
        if (Within->Safe)
          C.addTransition(Within->Safe);
      }
      return;
    }

    const auto *Region = dyn_cast_or_null<VarRegion>(BindingRegion);
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
    SVal BoundValue = Value;
    if (SourceExpression) {
      SVal SourceValue = C.getSVal(SourceExpression);
      if (!SourceValue.isUnknownOrUndef() &&
          taint::isTainted(State, SourceValue))
        BoundValue = SourceValue;
    }
    std::optional<InputClass> BoundInput =
        inputClassInScalarExpression(SourceExpression, State, C);
    if (!BoundValue.isUnknownOrUndef() && BoundInput)
      State = addInputTaint(State, BoundValue, *BoundInput);
    std::optional<InputClass> ScalarInput = BoundInput;
    if (!ScalarInput && !BoundValue.isUnknownOrUndef())
      ScalarInput = inputClassForValue(State, BoundValue);
    if (!BoundValue.isUnknownOrUndef() && taint::isTainted(State, BoundValue)) {
      State = State->set<QEMUSavedTaintedScalars>(Region, BoundValue);
    } else {
      State = State->remove<QEMUSavedTaintedScalars>(Region);
    }
    if (!BoundValue.isUnknownOrUndef() && ScalarInput &&
        *ScalarInput == InputClass::USB &&
        usbLengthExpressionKnownNonNegative(SourceExpression, State, C))
      State = State->add<QEMUNonNegativeUSBScalars>(Region);
    else
      State = State->remove<QEMUNonNegativeUSBScalars>(Region);
    unsigned LowZeroBits = usbKnownLowZeroBits(SourceExpression, State, C);
    if (!BoundValue.isUnknownOrUndef() && ScalarInput &&
        *ScalarInput == InputClass::USB && LowZeroBits)
      State = State->set<QEMUUSBScalarLowZeroBits>(Region, LowZeroBits);
    else
      State = State->remove<QEMUUSBScalarLowZeroBits>(Region);
    if (Source)
      State = State->set<QEMUPersistentLocalSources>(Region, Source->Field);
    else
      State = State->remove<QEMUPersistentLocalSources>(Region);
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    // Remove terminal or owner-dead joins before ordinary result facts expire.
    State = qemu::state::removeDeadCompletionPublications(State, SymReaper);
    State = qemu::state::removeDeadUSBTransactions(State, SymReaper);
    auto PendingBulkDestinations =
        State->get<QEMUPendingInitializedByteBulkDestinations>();
    for (const auto &Entry : PendingBulkDestinations)
      if (!SymReaper.isLiveRegion(Entry.second))
        State = State->remove<QEMUPendingInitializedByteBulkDestinations>(
            Entry.first);
    for (const MemRegion *Region :
         State->get<QEMUPendingInitializedBytePreciseBinds>())
      if (!SymReaper.isLiveRegion(Region))
        State = State->remove<QEMUPendingInitializedBytePreciseBinds>(Region);
    auto Saved = State->get<QEMUSavedTaintedScalars>();
    for (const auto &Entry : Saved)
      if (!SymReaper.isLiveRegion(Entry.first))
        State = State->remove<QEMUSavedTaintedScalars>(Entry.first);
    for (const VarRegion *Region : State->get<QEMUNonNegativeUSBScalars>())
      if (!SymReaper.isLiveRegion(Region))
        State = State->remove<QEMUNonNegativeUSBScalars>(Region);
    auto LowZeroBits = State->get<QEMUUSBScalarLowZeroBits>();
    for (const auto &Entry : LowZeroBits)
      if (!SymReaper.isLiveRegion(Entry.first))
        State = State->remove<QEMUUSBScalarLowZeroBits>(Entry.first);
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
    auto InputIovecs = State->get<QEMUInputIovecs>();
    for (const auto &Entry : InputIovecs)
      if (!SymReaper.isLiveRegion(Entry.first))
        State = State->remove<QEMUInputIovecs>(Entry.first);
    auto InputBuffers = State->get<QEMUInputBufferLengths>();
    for (const auto &Entry : InputBuffers)
      if (!SymReaper.isLiveRegion(Entry.first))
        State = clearCallbackInputBuffer(State, Entry.first);
    auto InvalidUSBSetupLengths = State->get<QEMUInvalidUSBSetupLengthValues>();
    for (const auto &Entry : InvalidUSBSetupLengths)
      if (!SymReaper.isLiveRegion(Entry.first))
        State = clearInvalidUSBSetupLength(State, Entry.first);
    auto InitializedObjects = State->get<QEMUInitializedByteObjectExtents>();
    for (const auto &Entry : InitializedObjects)
      if (!SymReaper.isLiveRegion(Entry.first))
        State = clearInitializedByteObject(State, Entry.first);
    auto AllocationRelations = State->get<QEMUAllocationRelationKinds>();
    for (const auto &Entry : AllocationRelations)
      if (SymReaper.isDead(Entry.first)) {
        State = State->remove<QEMUAllocationRelationKinds>(Entry.first)
                    ->remove<QEMUAllocationRelationLeft>(Entry.first)
                    ->remove<QEMUAllocationRelationRight>(Entry.first);
      }
    auto DMALifetimes = State->get<qemu::state::ObjectLifetimeMap>();
    for (const auto &Entry : DMALifetimes)
      if (!SymReaper.isLiveRegion(Entry.first)) {
        State = qemu::state::removeObjectExtent(
            State, Entry.first, qemu::facts::ExtentKind::Mapped);
        State = qemu::state::removeObjectExtent(
            State, Entry.first, qemu::facts::ExtentKind::Requested);
        State = qemu::state::removeObjectExtent(
            State, Entry.first, qemu::facts::ExtentKind::ActualTransfer);
        State = qemu::state::removeObjectDirection(State, Entry.first);
        State = qemu::state::removeObjectLifetime(State, Entry.first);
      }
    auto DMAMappedDirections = State->get<QEMUDMAMappedDirections>();
    for (const auto &Entry : DMAMappedDirections)
      if (SymReaper.isDead(Entry.first))
        State = State->remove<QEMUDMAMappedDirections>(Entry.first);
    auto DMARetiredOrigins = State->get<QEMUDMARetiredOrigins>();
    for (const auto &Entry : DMARetiredOrigins)
      if (SymReaper.isDead(Entry.first))
        State = State->remove<QEMUDMARetiredOrigins>(Entry.first);
    auto SharedProvenance = State->get<qemu::state::ValueProvenanceMap>();
    for (const auto &Entry : SharedProvenance)
      if (SymReaper.isDead(Entry.first))
        State = qemu::state::removeValueProvenance(State, Entry.first);
    auto SharedResultStates = State->get<qemu::state::ValueResultStateMap>();
    for (const auto &Entry : SharedResultStates)
      if (SymReaper.isDead(Entry.first))
        State = qemu::state::removeValueResultState(State, Entry.first);
    auto SharedTransferOperations =
        State->get<qemu::state::TransferOperationMap>();
    for (const auto &Entry : SharedTransferOperations)
      if (SymReaper.isDead(Entry.first))
        State = qemu::state::removeTransferOperation(State, Entry.first);
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkLiveSymbols(ProgramStateRef State, SymbolReaper &SymReaper) const {
    for (const auto &Entry :
         State->get<QEMUPendingInitializedByteBulkDestinations>())
      SymReaper.markLive(Entry.second);
    for (const MemRegion *Region :
         State->get<QEMUPendingInitializedBytePreciseBinds>())
      SymReaper.markLive(Region);
    for (const auto &Entry : State->get<QEMUFailedCompletionScopeOwners>()) {
      if (const MemRegion *Region = Entry.second.getAsRegion())
        SymReaper.markLive(Region);
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    }
    // Only a nonterminal publication with a live owner roots its join symbols.
    // Root the function-entry owner capture first: an external DMA call can
    // invalidate and reconjure the parameter region while the original owner
    // remains the stable identity for the protocol.
    qemu::state::markLiveCompletionPublications(State, SymReaper);
    qemu::state::markLiveUSBTransactions(State, SymReaper);
    for (const auto &Entry : State->get<QEMUSavedTaintedScalars>()) {
      SymReaper.markLive(Entry.first);
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    }
    for (const auto &Entry : State->get<QEMUPendingIovecSourceSizes>())
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    for (const auto &Entry : State->get<QEMUPendingDMAMapRequestedExtents>())
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    for (const auto &Entry : State->get<QEMUPendingDMAMapDirections>())
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    for (const auto &Entry : State->get<QEMUPendingDMAMapOwners>())
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    for (const auto &Entry : State->get<QEMUDMAMappedDirections>())
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    // Shared DMA facts do not keep their object or epoch alive.  A pointer
    // alias owns that lifetime; the extent values are only relational facts
    // needed while such an alias remains live.
    for (const auto &Entry : State->get<qemu::state::ObjectExtentMap>()) {
      for (SymbolRef Symbol : Entry.second.getBegin().symbols())
        SymReaper.markLive(Symbol);
      for (SymbolRef Symbol : Entry.second.getLength().symbols())
        SymReaper.markLive(Symbol);
    }
    for (const auto &Entry : State->get<qemu::state::ObjectLifetimeMap>()) {
      if (!SymReaper.isLiveRegion(Entry.first))
        continue;
      const MemRegion *Owner = Entry.second.getOwner();
      if (Owner && Owner != Entry.first)
        SymReaper.markLive(Owner);
      const SymbolicRegion *ObjectBase = Entry.first->getSymbolicBase();
      SymbolRef ObjectSymbol = ObjectBase ? ObjectBase->getSymbol() : nullptr;
      for (SymbolRef Symbol : Entry.second.getEpoch().symbols())
        if (Symbol != ObjectSymbol)
          SymReaper.markLive(Symbol);
    }
    for (const MemRegion *Region : State->get<QEMUVirtqueueElements>())
      SymReaper.markLive(Region);
    for (const MemRegion *Region : State->get<QEMUVirtqueueIovecs>())
      SymReaper.markLive(Region);
    for (const auto &Entry : State->get<QEMUInputIovecs>())
      SymReaper.markLive(Entry.first);
    for (const auto &Entry : State->get<QEMUInputBufferLengths>()) {
      SymReaper.markLive(Entry.first);
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    }
    for (const auto &Entry : State->get<QEMUInputBufferReadConditions>())
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    for (const auto &Entry : State->get<QEMUInvalidUSBSetupLengthValues>()) {
      SymReaper.markLive(Entry.first);
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    }
    for (const auto &Entry : State->get<QEMUInitializedByteObjectExtents>()) {
      SymReaper.markLive(Entry.first);
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    }
    for (const auto &Entry : State->get<QEMUInitializedByteRangeLengths>()) {
      SymReaper.markLive(Entry.first);
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    }
    for (const auto &Entry : State->get<QEMUKnownNULTerminatorOffsets>())
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    for (const auto &Entry : State->get<QEMUAllocationRelationLeft>())
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    for (const auto &Entry : State->get<QEMUAllocationRelationRight>())
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
  }

  ProgramStateRef
  checkRegionChanges(ProgramStateRef State,
                     const InvalidatedSymbols *Invalidated,
                     ArrayRef<const MemRegion *> ExplicitRegions,
                     ArrayRef<const MemRegion *> InvalidatedRegions,
                     const StackFrame *Frame, const CallEvent *Call) const {
    // Unknown callees and modeled bulk writes can replace the complete USB
    // object without producing a field bind.  Once such a call invalidates an
    // ancestor of setup_len, the pending invalid-state fact is no longer
    // justified.  Direct binds are handled precisely in checkBind and must not
    // be cleared here merely because a sibling field changed.
    if (Call) {
      auto InvalidUSBSetupLengths =
          State->get<QEMUInvalidUSBSetupLengthValues>();
      for (const auto &Entry : InvalidUSBSetupLengths) {
        const FieldRegion *Field = Entry.first;
        for (const MemRegion *InvalidatedRegion : InvalidatedRegions) {
          if (InvalidatedRegion &&
              Field->isSubRegionOf(InvalidatedRegion->StripCasts())) {
            State = clearInvalidUSBSetupLength(State, Field);
            break;
          }
        }
      }
    }

    const MemRegion *ModeledInitializedByteDestination = nullptr;
    if (Call) {
      if (const auto *FD = dyn_cast_or_null<FunctionDecl>(Call->getDecl())) {
        if (FD->getIdentifier()) {
          StringRef Name = FD->getName();
          std::optional<unsigned> DestinationArgument;
          if (std::optional<DMATransferDescriptor> Transfer =
                  dmaTransferDescriptor(*Call))
            DestinationArgument = Transfer->BufferArgument;
          else if (isQEMUGetBufferInitializedByteProducer(*Call) ||
                   isGInputStreamReadAllInitializedByteProducer(*Call))
            DestinationArgument = 1;
          else if (std::optional<USBPacketCopyDescriptor> USB =
                       usbPacketCopyDescriptor(*Call))
            // The helper either reads or writes this buffer according to
            // USBPacket.pid.  Both operations preserve byte initializedness;
            // PostCall records USB provenance for a proved OUT/SETUP token and
            // abandons precision when the direction is unresolved.
            DestinationArgument = USB->HostBufferArgument;
          else if (Name == "memcpy" || Name == "memmove" || Name == "memset" ||
                   Name == "__builtin_memcpy" || Name == "__builtin_memmove" ||
                   Name == "__builtin_memset")
            DestinationArgument = 0;
          if (DestinationArgument && *DestinationArgument < Call->getNumArgs())
            if (const MemRegion *Destination =
                    Call->getArgSVal(*DestinationArgument).getAsRegion())
              ModeledInitializedByteDestination =
                  Destination->StripCasts()->getBaseRegion();
        }
      }
    }

    const bool DirectBindNotification = !Call && !Invalidated;
    if (EnableInitializedByteTracking) {
      auto Objects = State->get<QEMUInitializedByteObjectExtents>();
      for (const auto &Entry : Objects) {
        const MemRegion *Base = Entry.first;
        for (const MemRegion *InvalidatedRegion : InvalidatedRegions) {
          if (!InvalidatedRegion)
            continue;
          InvalidatedRegion = InvalidatedRegion->StripCasts();
          if (Base->isSubRegionOf(InvalidatedRegion) ||
              InvalidatedRegion->isSubRegionOf(Base)) {
            if (DirectBindNotification &&
                State->contains<QEMUPendingInitializedBytePreciseBinds>(Base)) {
              State =
                  State->remove<QEMUPendingInitializedBytePreciseBinds>(Base);
              continue;
            }
            if (Base == ModeledInitializedByteDestination)
              continue;
            bool PendingBulkDestination = false;
            for (const auto &Pending :
                 State->get<QEMUPendingInitializedByteBulkDestinations>())
              if (Pending.second == Base) {
                PendingBulkDestination = true;
                break;
              }
            if (PendingBulkDestination)
              continue;
            State = abandonInitializedByteObject(State, Base);
            break;
          }
        }
      }
      // A direct notification is paired with one checkBind callback.  Clear
      // any unmatched marker rather than letting it exempt a later default
      // bind or unrelated invalidation.
      if (DirectBindNotification) {
        auto PendingPreciseBinds =
            State->get<QEMUPendingInitializedBytePreciseBinds>();
        for (const MemRegion *Base : PendingPreciseBinds)
          State = State->remove<QEMUPendingInitializedBytePreciseBinds>(Base);
      }
    }
    return State;
  }

  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    const StackFrame *Frame = C.getStackFrame();
    if (!Frame->getParent()) {
      auto InvalidUSBSetupFrames =
          State->get<QEMUInvalidUSBSetupLengthFrames>();
      for (const auto &Entry : InvalidUSBSetupFrames) {
        const FieldRegion *Field = Entry.first;
        const SVal *Value = State->get<QEMUInvalidUSBSetupLengthValues>(Field);
        const Expr *const *Origin =
            State->get<QEMUInvalidUSBSetupLengthOrigins>(Field);
        const unsigned *Kind =
            State->get<QEMUInvalidUSBSetupLengthKinds>(Field);
        const unsigned *Definite =
            State->get<QEMUInvalidUSBSetupLengthDefinite>(Field);
        std::optional<uint64_t> Capacity =
            usbSetupLengthCapacity(Field, C.getASTContext());
        if (Value && Origin && Kind && Definite && Capacity &&
            (*Kind ==
                 static_cast<unsigned>(USBSetupLengthViolation::Negative) ||
             *Kind == static_cast<unsigned>(
                          USBSetupLengthViolation::ExceedsCapacity)) &&
            reportInvalidUSBSetupLength(
                C, State, *Value, *Origin, *Capacity,
                static_cast<USBSetupLengthViolation>(*Kind), *Definite != 0))
          return;
        State = clearInvalidUSBSetupLength(State, Field);
      }
    }
    auto PendingBulkDestinations =
        State->get<QEMUPendingInitializedByteBulkDestinations>();
    for (const auto &Entry : PendingBulkDestinations)
      if (const auto *Variable = dyn_cast<VarRegion>(Entry.second))
        if (Variable->getStackFrame() == Frame)
          State = State->remove<QEMUPendingInitializedByteBulkDestinations>(
              Entry.first);
    for (const MemRegion *Region :
         State->get<QEMUPendingInitializedBytePreciseBinds>())
      if (const auto *Variable = dyn_cast<VarRegion>(Region))
        if (Variable->getStackFrame() == Frame)
          State = State->remove<QEMUPendingInitializedBytePreciseBinds>(Region);
    auto InitializedObjects = State->get<QEMUInitializedByteObjectExtents>();
    for (const auto &Entry : InitializedObjects)
      if (const auto *Variable = dyn_cast<VarRegion>(Entry.first))
        if (Variable->getStackFrame() == Frame)
          State = clearInitializedByteObject(State, Entry.first);
    auto SavedScalars = State->get<QEMUSavedTaintedScalars>();
    for (const auto &Entry : SavedScalars)
      if (Entry.first->getStackFrame() == Frame)
        State = State->remove<QEMUSavedTaintedScalars>(Entry.first);
    for (const VarRegion *Region : State->get<QEMUNonNegativeUSBScalars>())
      if (Region->getStackFrame() == Frame)
        State = State->remove<QEMUNonNegativeUSBScalars>(Region);
    auto LowZeroBits = State->get<QEMUUSBScalarLowZeroBits>();
    for (const auto &Entry : LowZeroBits)
      if (Entry.first->getStackFrame() == Frame)
        State = State->remove<QEMUUSBScalarLowZeroBits>(Entry.first);
    auto LocalSources = State->get<QEMUPersistentLocalSources>();
    for (const auto &Entry : LocalSources)
      if (Entry.first->getStackFrame() == Frame)
        State = State->remove<QEMUPersistentLocalSources>(Entry.first);
    const auto *FD = dyn_cast<FunctionDecl>(Frame->getDecl());
    if (FD) {
      if (EnableFailedCompletionPublicationDiagnostics)
        if (std::optional<FailedCompletionProtocolDescriptor> Protocol =
                failedCompletionProtocolForFunction(FD, C.getSourceManager())) {
          if (const SVal *Captured =
                  State->get<QEMUFailedCompletionScopeOwners>(Frame))
            if (const MemRegion *Owner = directDMAOwner(*Captured))
              State = removeFailedCompletionFactsForOwner(State, Owner);
        }
      State = State->remove<QEMUFailedCompletionScopeOwners>(Frame);
      auto BufferParameters = State->get<QEMUInputBufferParameters>();
      for (const auto &Entry : BufferParameters)
        if (Entry.second->getDeclContext() == FD)
          State = clearCallbackInputBuffer(State, Entry.first);
    }
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
    if (IndexExpression->getType()->isIntegerType())
      if (auto Location = Index.getAs<Loc>())
        Index = State->getSVal(*Location);
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
    SVal Count = UnknownVal();
    const ConstantArrayType *Array =
        C.getASTContext().getAsConstantArrayType(Base->getType());
    bool FlexibleArrayLike =
        Array && Array->getSize().getActiveBits() <= 64 &&
        Array->getSize().getZExtValue() <= 1 &&
        Base->isFlexibleArrayMemberLike(
            C.getASTContext(),
            C.getASTContext().getLangOpts().getStrictFlexArraysLevel());
    SVal RuntimeCount = getDynamicElementCountWithOffset(
        State, C.getSVal(ASE->getBase()), ASE->getType());
    bool HasDynamicCount =
        hasUsableExtent(State, RuntimeCount, C.getSValBuilder());
    bool HasStaticCount =
        Array && !FlexibleArrayLike && Array->getSize().getActiveBits() <= 64;
    if (HasStaticCount) {
      uint64_t StaticElements = Array->getSize().getZExtValue();
      Count = C.getSValBuilder().makeArrayIndex(StaticElements);
      // The declared dimension is the language-level bound for an ordinary
      // fixed array and avoids mistaking the rest of an enclosing object for
      // more elements of a nested subarray.  A runtime extent proved smaller
      // is nevertheless a stronger physical bound (for example, a fixed-array
      // view over a short mapped or allocated object), so retain that count.
      // When neither ordering is proved, the symbolic runtime extent remains
      // a separate safety property for its producer-specific checks.
      if (HasDynamicCount && isDefinitelyTrue(State, RuntimeCount, BO_LT, Count,
                                              C.getSValBuilder()))
        Count = RuntimeCount;
    } else if (HasDynamicCount) {
      // A trailing flexible-array-like member's declared [0]/[1] size is only
      // a placeholder under the active -fstrict-flex-arrays policy.  Preserve
      // ordinary fixed dimensions greater than one: without a visible
      // allocation the analyzer otherwise loses their language-level bound.
      Count = RuntimeCount;
    }
    if (!hasUsableExtent(State, Count, C.getSValBuilder())) {
      SVal Extent = flexibleArrayMemberExtent(Base, State, C);
      if (hasUsableExtent(State, Extent, C.getSValBuilder())) {
        SVal ElementExtent =
            getElementExtent(ASE->getType(), C.getSValBuilder());
        Count = C.getSValBuilder().evalBinOp(
            State, BO_Div, Extent, ElementExtent,
            C.getSValBuilder().getArrayIndexType());
      }
    }
    if (!hasUsableExtent(State, Count, C.getSValBuilder())) {
      if (HasStaticCount) {
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
             "array index", Count, BoundUnit::Elements, SourceDetail,
             arrayAccessWitness(ASE, C),
             isAddressComputationOnly(ASE, C.getASTContext())
                 ? "address-computation-only"
                 : "");
      return;
    }

    std::optional<BoundStates> Inside =
        compare(State, Index, BO_LT, Count, C.getSValBuilder());
    if (!Inside || !Inside->Unsafe)
      return;
    report(C, Inside->Safe, Inside->Unsafe, Index, ASE->getIdx(), "array index",
           Count, BoundUnit::Elements, SourceDetail, arrayAccessWitness(ASE, C),
           isAddressComputationOnly(ASE, C.getASTContext())
               ? "address-computation-only"
               : "");
  }
};

} // namespace

void ento::registerQEMUGuestMemorySafetyChecker(CheckerManager &Mgr) {
  auto *Checker = Mgr.registerChecker<QEMUGuestMemorySafetyChecker>();
  Checker->setReportLevelC(Mgr.getAnalyzerOptions().getCheckerBooleanOption(
      Checker, "ReportLevelC"));
  Checker->setEnableInitializedByteTracking(
      Mgr.getAnalyzerOptions().getCheckerBooleanOption(
          Checker, "EnableInitializedByteTracking"));
  Checker->setEnableDMATransferResultDiagnostics(
      Mgr.getAnalyzerOptions().getCheckerBooleanOption(
          Checker, "EnableDMATransferResultDiagnostics"));
  Checker->setEnableFailedCompletionPublicationDiagnostics(
      Mgr.getAnalyzerOptions().getCheckerBooleanOption(
          Checker, "EnableFailedCompletionPublicationDiagnostics"));
  Checker->setMaxInitializedRangesPerObject(
      Mgr.getAnalyzerOptions().getCheckerIntegerOption(
          Checker, "MaxInitializedRangesPerObject"));
  Checker->setStructuredWitnessOptions(
      Mgr.getAnalyzerOptions().getCheckerBooleanOption(Checker,
                                                       "EmitStructuredWitness"),
      Mgr.getAnalyzerOptions().getCheckerStringOption(Checker,
                                                      "QEMUSourceRoot"));
  Checker->setSelectiveSummaryManifest(
      Mgr.getAnalyzerOptions().getCheckerStringOption(
          Checker, "SelectiveSummaryManifest"),
      Mgr);
}

bool ento::shouldRegisterQEMUGuestMemorySafetyChecker(
    const CheckerManager &Mgr) {
  return true;
}
