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

#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DynamicRecursiveASTVisitor.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/RecordLayout.h"
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
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Base64.h"
#include "llvm/Support/JSON.h"
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
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUDMAMappedExtents, SymbolRef, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUDMAMappedDirections, SymbolRef, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUDMARetiredExtents, SymbolRef, SVal)
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
                     check::Location, check::Bind, check::LiveSymbols,
                     check::DeadSymbols, check::RegionChanges,
                     check::PostStmt<ImplicitCastExpr>,
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
  bool ReportLevelC = false;
  bool EmitStructuredWitness = false;
  std::string QEMUSourceRoot;

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
    if ((Info.ParameterMask || Info.PointeeMask || Info.IovecMask) &&
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
               Existing.FixedLength == Buffer->FixedLength;
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

  static StringRef arraySinkDirection(const ArraySubscriptExpr *Subscript,
                                      ASTContext &Context) {
    DynTypedNode Child = DynTypedNode::create(*Subscript);
    for (unsigned Depth = 0; Depth < 8; ++Depth) {
      auto Parents = Context.getParents(Child);
      if (Parents.size() != 1)
        return "indirect";
      DynTypedNode Parent = Parents[0];
      if (const auto *Cast = Parent.get<ImplicitCastExpr>()) {
        if (Cast->getCastKind() == CK_LValueToRValue)
          return "host-read";
        Child = Parent;
        continue;
      }
      if (Parent.get<ParenExpr>()) {
        Child = Parent;
        continue;
      }
      if (const auto *Assignment = Parent.get<BinaryOperator>())
        if (Assignment->isAssignmentOp() &&
            Assignment->getLHS()->IgnoreParenImpCasts() == Subscript)
          return "host-write";
      if (const auto *Unary = Parent.get<UnaryOperator>())
        if (Unary->isIncrementDecrementOp() &&
            Unary->getSubExpr()->IgnoreParenImpCasts() == Subscript)
          return "host-write";
      return "indirect";
    }
    return "indirect";
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

  void addStructuredWitness(PathSensitiveBugReport &Report, CheckerContext &C,
                            ProgramStateRef State, StringRef Message,
                            std::optional<InputClass> Source,
                            StringRef SourceDetail, StringRef Constraint,
                            SVal ConcreteValue, StringRef SinkDirection,
                            StringRef AddressOrOffset, StringRef AccessSize,
                            StringRef ObjectExtent,
                            StringRef MissingRelationship,
                            SourceLocation DiagnosticLocation = {}) const {
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
        !witnessStringValid(ProvenanceSource) ||
        !witnessStringValid(Constraint) ||
        (Concrete && !witnessStringValid(*Concrete)) ||
        !witnessStringValid(AddressOrOffset) ||
        !witnessStringValid(AccessSize) || !witnessStringValid(ObjectExtent) ||
        !witnessStringValid(MissingRelationship))
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
        EmitBoundary("extent-minus-one", "object extent - 1");
        EmitBoundary("extent", "object extent");
        EmitBoundary("extent-plus-one", "object extent + 1");
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
      JSON.attribute("schema_version", 1);
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
        "QEMU_GMS_WITNESS_V1=" + llvm::encodeBase64(JSONBuffer.str());
    Report.addNote(Marker, Report.getLocation());
  }

  void addStructuredWitnessNotApplicable(PathSensitiveBugReport &Report,
                                         CheckerContext &C, StringRef Message,
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
      JSON.attribute("kind", "qemu-gms-witness-not-applicable");
      JSON.attribute("reason", Reason);
      JSON.attribute("schema_version", 1);
    });
    JSON.flush();
    std::string Marker =
        "QEMU_GMS_WITNESS_NA_V1=" + llvm::encodeBase64(JSONBuffer.str());
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
    addStructuredWitnessNotApplicable(*Report, C, Message,
                                      "dma-map-unmap-contract");
    C.emitReport(std::move(Report));
    return true;
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
        *Report, C, State, Message, InputClass::DMA,
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
    StringRef Direction = arraySinkDirection(Subscript, C.getASTContext());
    // An address-only or unresolved use still gets its human bounds report,
    // but does not establish a memory access for the witness contract.
    if (Direction != "host-read" && Direction != "host-write")
      return std::nullopt;
    QualType AccessType = Subscript->getType();
    if (AccessType->isIncompleteType() ||
        AccessType->isVariablyModifiedType() || AccessType->isDependentType())
      return std::nullopt;
    uint64_t AccessBytes =
        C.getASTContext().getTypeSizeInChars(AccessType).getQuantity();
    if (!AccessBytes)
      return std::nullopt;
    return MemoryAccessWitness{
        Direction, witnessExpression(Subscript, C.getASTContext()),
        C.getSValBuilder().makeIntVal(AccessBytes,
                                      C.getASTContext().getSizeType())};
  }

  static bool
  isAddressComputationOnly(const ArraySubscriptExpr *Subscript,
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
      addStructuredWitness(
          *Report, C, Unsafe, Message.str(), Source, WitnessSource, Constraint,
          TaintedValue, Witness->Direction, AddressOrOffset, AccessSize,
          ObjectExtent, MissingRelationship, Witness->DiagnosticLocation);
    } else if (!WitnessNotApplicableReason.empty()) {
      addStructuredWitnessNotApplicable(*Report, C, Message.str(),
                                        WitnessNotApplicableReason);
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
                                      "usb-state-capacity-contract");
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
    unsigned LengthPointerArgument;
    unsigned DirectionArgument;
    bool BooleanDirection;
  };

  struct DirectDMAUnmapDescriptor {
    unsigned BufferArgument;
    unsigned LengthArgument;
    unsigned DirectionArgument;
    unsigned AccessLengthArgument;
    bool BooleanDirection;
  };

  static std::optional<DirectDMAMapDescriptor>
  directDMAMapDescriptor(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() || !isVoidPointer(FD->getReturnType()))
      return std::nullopt;

    StringRef Name = FD->getName();
    unsigned ParameterCount;
    unsigned LengthPointerArgument;
    unsigned DirectionArgument;
    bool BooleanDirection;
    if (Name == "address_space_map") {
      ParameterCount = 5;
      LengthPointerArgument = 2;
      DirectionArgument = 3;
      BooleanDirection = true;
    } else if (Name == "dma_memory_map") {
      ParameterCount = 5;
      LengthPointerArgument = 2;
      DirectionArgument = 3;
      BooleanDirection = false;
    } else if (Name == "pci_dma_map") {
      ParameterCount = 4;
      LengthPointerArgument = 2;
      DirectionArgument = 3;
      BooleanDirection = false;
    } else if (Name == "physical_memory_map" ||
               Name == "cpu_physical_memory_map") {
      ParameterCount = 3;
      LengthPointerArgument = 1;
      DirectionArgument = 2;
      BooleanDirection = true;
    } else {
      return std::nullopt;
    }
    if (FD->getNumParams() != ParameterCount ||
        Call.getNumArgs() != ParameterCount)
      return std::nullopt;
    QualType LengthPointer =
        FD->getParamDecl(LengthPointerArgument)->getType();
    if (!LengthPointer->isPointerType() ||
        !LengthPointer->getPointeeType()->isIntegerType())
      return std::nullopt;
    QualType Direction = FD->getParamDecl(DirectionArgument)->getType();
    if (!Direction->isIntegralOrEnumerationType() ||
        Direction->isBooleanType() != BooleanDirection)
      return std::nullopt;
    return DirectDMAMapDescriptor{LengthPointerArgument, DirectionArgument,
                                  BooleanDirection};
  }

  static std::optional<DirectDMAUnmapDescriptor>
  directDMAUnmapDescriptor(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier() || !FD->getReturnType()->isVoidType())
      return std::nullopt;
    StringRef Name = FD->getName();
    unsigned ParameterCount;
    DirectDMAUnmapDescriptor Descriptor;
    if (Name == "address_space_unmap") {
      ParameterCount = 5;
      Descriptor = {1, 2, 3, 4, true};
    } else if (Name == "dma_memory_unmap" || Name == "pci_dma_unmap") {
      ParameterCount = 5;
      Descriptor = {1, 2, 3, 4, false};
    } else if (Name == "physical_memory_unmap" ||
               Name == "cpu_physical_memory_unmap") {
      ParameterCount = 4;
      Descriptor = {0, 1, 2, 3, true};
    } else {
      return std::nullopt;
    }
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

  static std::optional<SVal> directDMAMappedExtent(ProgramStateRef State,
                                                    SVal Buffer) {
    // This intentionally models pointer-preserving aliases only.  QEMU code
    // that casts a mapped host pointer to an integer and reconstructs another
    // pointer needs a separate provenance model; treating arbitrary integer
    // arithmetic as an alias here would be too noisy.
    SymbolRef Base = Buffer.getLocSymbolInBase();
    if (!Base)
      return std::nullopt;
    if (const SVal *Extent = State->get<QEMUDMAMappedExtents>(Base))
      return *Extent;
    return std::nullopt;
  }

  static std::optional<SVal> directDMARetiredExtent(ProgramStateRef State,
                                                    SVal Buffer) {
    SymbolRef Base = Buffer.getLocSymbolInBase();
    if (!Base)
      return std::nullopt;
    if (const SVal *Extent = State->get<QEMUDMARetiredExtents>(Base))
      return *Extent;
    return std::nullopt;
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
    if ((Name == "address_space_read" || Name == "address_space_read_full") &&
        Call.getNumArgs() >= 5)
      return MemorySink{3, 4, "memory-operation length", "host-write"};
    if ((Name == "dma_memory_read" || Name == "pci_dma_read") &&
        Call.getNumArgs() >= 4)
      return MemorySink{2, 3, "memory-operation length", "host-write"};
    if (Name == "cpu_physical_memory_read" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "memory-operation length", "host-write"};
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
    if ((Name == "dma_memory_write" || Name == "pci_dma_write") &&
        Call.getNumArgs() >= 4)
      return MemorySink{2, 3, "DMA source length", "host-read"};
    if (Name == "cpu_physical_memory_write" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "DMA source length", "host-read"};
    if (Name == "qemu_put_buffer" && Call.getNumArgs() >= 3)
      return MemorySink{1, 2, "migration-output source length", "host-read"};
    if (Name == "bdrv_pwrite" && Call.getNumArgs() >= 5)
      return MemorySink{3, 2, "block-write source length", "host-read"};
    return std::nullopt;
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
    if (const ParmVarDecl *const *Parameter =
            Unsafe->get<QEMUInputBufferParameters>(BufferBase)) {
      if (!(*Parameter)->getName().empty()) {
        std::string AddressOrOffset =
            "byte offset " + valueRange(Unsafe, Offset, C.getSValBuilder()) +
            " from callback buffer parameter '" +
            (*Parameter)->getNameAsString() + "'";
        addStructuredWitness(
            *Report, C, Unsafe, Message.str(), Source, SourceDetail,
            "access end > available guest-input bytes", AccessEnd, "host-read",
            AddressOrOffset, AccessSize, ObjectExtent,
            "access end <= available guest-input bytes");
      }
    }
    C.emitReport(std::move(Report));
  }

  bool checkCallbackBufferMemoryRead(const CallEvent &Call,
                                     unsigned BufferArgument,
                                     unsigned LengthArgument,
                                     CheckerContext &C) const {
    if (BufferArgument >= Call.getNumArgs() ||
        LengthArgument >= Call.getNumArgs())
      return false;
    const MemRegion *Region = Call.getArgSVal(BufferArgument).getAsRegion();
    if (!Region)
      return false;
    const MemRegion *Base = Region->getBaseRegion();
    ProgramStateRef State = C.getState();
    const SVal *StoredLength = State->get<QEMUInputBufferLengths>(Base);
    const unsigned *StoredClass = State->get<QEMUInputBufferClasses>(Base);
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

    llvm::APSInt Maximum = SVB.getBasicValueFactory().getMaxValue(SizeType);
    SVal MaximumSVal = SVB.makeIntVal(Maximum);
    SVal Remaining =
        SVB.evalBinOp(State, BO_Sub, MaximumSVal, Offset, SizeType);
    if (Remaining.isUnknownOrUndef() || !Require(Access, BO_LE, Remaining))
      return true;
    SVal AccessEnd = SVB.evalBinOp(State, BO_Add, Offset, Access, SizeType);
    if (AccessEnd.isUnknownOrUndef())
      return true;

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
        SVal BaseExtent = MappedBaseExtent
                              ? *MappedBaseExtent
                              : getDynamicExtentWithOffset(
                                    State, pointerValue(Pointer, C));
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
          State =
              addInputTaint(State, OffsetValue, OffsetPersistent->Source);
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
  void setStructuredWitnessOptions(bool Enable, StringRef SourceRoot) {
    EmitStructuredWitness = Enable;
    QEMUSourceRoot = SourceRoot.str();
  }

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
      InputClass Source = Found->second.Source;
      if (const unsigned *Previous = State->get<QEMUInputBufferClasses>(Base))
        if (static_cast<InputClass>(*Previous) != Source)
          Source = InputClass::Mixed;
      State =
          State->set<QEMUInputBufferLengths>(Base, *Length)
              ->set<QEMUInputBufferClasses>(Base, static_cast<unsigned>(Source))
              ->set<QEMUInputBufferParameters>(Base, Parameter);
      Sources.push_back(
          {Pointer, Parameter->getNameAsString(), /*IsBuffer=*/true});
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
          for (const SourceValue &Source : Sources) {
            if (Source.IsBuffer || !Report.isInteresting(Source.Value))
              continue;
            return Class + " callback parameter '" + Source.Name +
                   "' is guest-controlled";
          }
          for (const SourceValue &Source : Sources)
            if (Source.IsBuffer && Report.isInteresting(Source.Value))
              return Class + " callback buffer parameter '" + Source.Name +
                     "' supplies guest-controlled bytes";
          return "";
        });
    C.addTransition(State, Tag);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
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
      }
      if (State != C.getState())
        C.addTransition(State);
      return;
    }
    if (std::optional<DirectDMAUnmapDescriptor> Unmap =
            directDMAUnmapDescriptor(Call)) {
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
        const SVal *MappedExtent = State->get<QEMUDMAMappedExtents>(Base);
        const SVal *MappedDirection = State->get<QEMUDMAMappedDirections>(Base);
        const SVal *RetiredExtent = State->get<QEMUDMARetiredExtents>(Base);
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

        SVal SavedExtent = *MappedExtent;
        bool Reported = false;
        auto RetireMapping = [Base, SavedExtent,
                              Where](ProgramStateRef Retired) {
          Retired = Retired->remove<QEMUDMAMappedExtents>(Base)
                        ->remove<QEMUDMAMappedDirections>(Base)
                        ->set<QEMUDMARetiredExtents>(Base, SavedExtent);
          return Where ? Retired->set<QEMUDMARetiredOrigins>(Base, Where)
                       : Retired->remove<QEMUDMARetiredOrigins>(Base);
        };

        // Detect the distinctive reversed form (..., len, len, direction) by
        // expression identity and by relating its last argument to the
        // direction saved at map time.  Expression types alone are not
        // sufficient: valid callers sometimes use a bool-sized access_len.
        if (MappedDirection &&
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

        State = RetireMapping(State);
        // A nonfatal error node is itself the successor for a reported path.
        // Adding the ordinary transition as well would fork a duplicate path.
        if (!Reported && State != C.getState())
          C.addTransition(State);
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
      if (checkCallbackBufferMemoryRead(Call, Sink->BufferArgument,
                                        Sink->LengthArgument, C))
        return;
      checkMemorySink(Call, *Sink, C);
    }
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    if (std::optional<DirectDMAMapDescriptor> Map =
            directDMAMapDescriptor(Call)) {
      ProgramStateRef State = C.getState();
      const Expr *Origin = Call.getOriginExpr();
      std::optional<SVal> Requested;
      std::optional<SVal> Direction;
      if (Origin) {
        if (const SVal *Saved =
                State->get<QEMUPendingDMAMapRequestedExtents>(Origin))
          Requested = *Saved;
        if (const SVal *Saved = State->get<QEMUPendingDMAMapDirections>(Origin))
          Direction = *Saved;
        State = State->remove<QEMUPendingDMAMapRequestedExtents>(Origin)
                    ->remove<QEMUPendingDMAMapDirections>(Origin);
      }
      std::optional<SVal> Returned =
          pointeeValue(State, Call.getArgSVal(Map->LengthPointerArgument));
      if (!Returned || Returned->isUnknownOrUndef()) {
        if (State != C.getState())
          C.addTransition(State);
        return;
      }
      if (Requested) {
        std::optional<BoundStates> WithinRequest = compare(
            State, *Returned, BO_LE, *Requested, C.getSValBuilder());
        if (!WithinRequest || !WithinRequest->Safe)
          return;
        State = WithinRequest->Safe;
      }
      SVal ReturnValue = Call.getReturnValue();
      if (std::optional<DefinedOrUnknownSVal> Defined =
              ReturnValue.getAs<DefinedOrUnknownSVal>()) {
        auto [NonNull, Null] = State->assume(*Defined);
        QualType LengthType = Call.getArgExpr(Map->LengthPointerArgument)
                                  ->getType()
                                  ->getPointeeType();
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
        State = State->remove<QEMUDMARetiredExtents>(Base)
                    ->remove<QEMUDMARetiredOrigins>(Base)
                    ->set<QEMUDMAMappedExtents>(Base, *Returned)
                    ->remove<QEMUDMAMappedDirections>(Base);
        if (Direction)
          State = State->set<QEMUDMAMappedDirections>(Base, *Direction);
        C.addTransition(State);
      } else if (State != C.getState()) {
        C.addTransition(State);
      }
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
    const SVal *MappedExtent = State->get<QEMUDMAMappedExtents>(Base);
    const SVal *RetiredExtent = State->get<QEMUDMARetiredExtents>(Base);
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
    const MemRegion *BindingRegion = Location.getAsRegion();
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
        State = State->remove<QEMUInputBufferLengths>(Entry.first)
                    ->remove<QEMUInputBufferClasses>(Entry.first)
                    ->remove<QEMUInputBufferParameters>(Entry.first);
    auto InvalidUSBSetupLengths = State->get<QEMUInvalidUSBSetupLengthValues>();
    for (const auto &Entry : InvalidUSBSetupLengths)
      if (!SymReaper.isLiveRegion(Entry.first))
        State = clearInvalidUSBSetupLength(State, Entry.first);
    auto AllocationRelations = State->get<QEMUAllocationRelationKinds>();
    for (const auto &Entry : AllocationRelations)
      if (SymReaper.isDead(Entry.first)) {
        State = State->remove<QEMUAllocationRelationKinds>(Entry.first)
                    ->remove<QEMUAllocationRelationLeft>(Entry.first)
                    ->remove<QEMUAllocationRelationRight>(Entry.first);
      }
    auto DMAMappedExtents = State->get<QEMUDMAMappedExtents>();
    for (const auto &Entry : DMAMappedExtents)
      if (SymReaper.isDead(Entry.first))
        State = State->remove<QEMUDMAMappedExtents>(Entry.first)
                    ->remove<QEMUDMAMappedDirections>(Entry.first);
    auto DMARetiredExtents = State->get<QEMUDMARetiredExtents>();
    for (const auto &Entry : DMARetiredExtents)
      if (SymReaper.isDead(Entry.first))
        State = State->remove<QEMUDMARetiredExtents>(Entry.first)
                    ->remove<QEMUDMARetiredOrigins>(Entry.first);
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkLiveSymbols(ProgramStateRef State, SymbolReaper &SymReaper) const {
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
    for (const auto &Entry : State->get<QEMUDMAMappedExtents>())
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    for (const auto &Entry : State->get<QEMUDMAMappedDirections>())
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    // A retired mapping is a tombstone, not an owner.  Keep symbols used by
    // its prior extent available while a real pointer alias keeps the base
    // alive, but do not keep the retired base alive solely for this checker.
    for (const auto &Entry : State->get<QEMUDMARetiredExtents>())
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
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
    for (const auto &Entry : State->get<QEMUInvalidUSBSetupLengthValues>()) {
      SymReaper.markLive(Entry.first);
      for (SymbolRef Symbol : Entry.second.symbols())
        SymReaper.markLive(Symbol);
    }
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
    if (!Call)
      return State;
    auto InvalidUSBSetupLengths = State->get<QEMUInvalidUSBSetupLengthValues>();
    for (const auto &Entry : InvalidUSBSetupLengths) {
      const FieldRegion *Field = Entry.first;
      for (const MemRegion *InvalidatedRegion : InvalidatedRegions) {
        if (Field->isSubRegionOf(InvalidatedRegion->StripCasts())) {
          State = clearInvalidUSBSetupLength(State, Field);
          break;
        }
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
      auto BufferParameters = State->get<QEMUInputBufferParameters>();
      for (const auto &Entry : BufferParameters)
        if (Entry.second->getDeclContext() == FD)
          State = State->remove<QEMUInputBufferLengths>(Entry.first)
                      ->remove<QEMUInputBufferClasses>(Entry.first)
                      ->remove<QEMUInputBufferParameters>(Entry.first);
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
      report(
          C, Outside->Unsafe, Outside->Safe, Index, ASE->getIdx(),
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
           Count, BoundUnit::Elements, SourceDetail,
           arrayAccessWitness(ASE, C),
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
  Checker->setStructuredWitnessOptions(
      Mgr.getAnalyzerOptions().getCheckerBooleanOption(Checker,
                                                       "EmitStructuredWitness"),
      Mgr.getAnalyzerOptions().getCheckerStringOption(Checker,
                                                      "QEMUSourceRoot"));
}

bool ento::shouldRegisterQEMUGuestMemorySafetyChecker(
    const CheckerManager &Mgr) {
  return true;
}
