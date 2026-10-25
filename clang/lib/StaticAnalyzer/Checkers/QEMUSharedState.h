//===-- QEMUSharedState.h - Shared QEMU analyzer state -------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file provides path-sensitive storage shared by QEMU checker
// implementations.  Unlike REGISTER_MAP_WITH_PROGRAMSTATE(), these named
// traits have one program-wide identity when this header is included by more
// than one checker translation unit.
//
// ProgramState deliberately stores analyzer-native identities (MemRegion and
// SVal) rather than the non-owning stable strings in QEMUSharedFacts.h.  A
// checker can convert a live fact to the stable vocabulary when it emits a
// summary or witness.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_QEMUSHAREDSTATE_H
#define LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_QEMUSHAREDSTATE_H

#include "QEMUSharedFacts.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "llvm/ADT/FoldingSet.h"
#include <functional>
#include <optional>

namespace clang {
class Stmt;

namespace ento {
namespace qemu {
namespace state {

/// Identifies one independently replaceable extent of an analyzer object.
class ObjectExtentKey {
  const MemRegion *Object;
  facts::ExtentKind Kind;

public:
  ObjectExtentKey(const MemRegion *Object, facts::ExtentKind Kind)
      : Object(Object), Kind(Kind) {}

  const MemRegion *getObject() const { return Object; }
  facts::ExtentKind getKind() const { return Kind; }

  friend bool operator==(const ObjectExtentKey &Left,
                         const ObjectExtentKey &Right) {
    return Left.Object == Right.Object && Left.Kind == Right.Kind;
  }

  friend bool operator<(const ObjectExtentKey &Left,
                        const ObjectExtentKey &Right) {
    if (Left.Object != Right.Object)
      return std::less<const MemRegion *>()(Left.Object, Right.Object);
    return static_cast<unsigned>(Left.Kind) < static_cast<unsigned>(Right.Kind);
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(Object);
    ID.AddInteger(static_cast<unsigned>(Kind));
  }
};

/// A half-open analyzer interval [Begin, Begin + Length).
class ObjectExtent {
  SVal Begin;
  SVal Length;

public:
  ObjectExtent(SVal Begin, SVal Length) : Begin(Begin), Length(Length) {}

  SVal getBegin() const { return Begin; }
  SVal getLength() const { return Length; }

  friend bool operator==(const ObjectExtent &Left, const ObjectExtent &Right) {
    return Left.Begin == Right.Begin && Left.Length == Right.Length;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    Begin.Profile(ID);
    Length.Profile(ID);
  }
};

class ValueProvenance {
  facts::ProvenanceKind Kind;

public:
  explicit ValueProvenance(facts::ProvenanceKind Kind) : Kind(Kind) {}

  facts::ProvenanceKind getKind() const { return Kind; }

  friend bool operator==(ValueProvenance Left, ValueProvenance Right) {
    return Left.Kind == Right.Kind;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(static_cast<unsigned>(Kind));
  }
};

/// Owner, generation, and current lifetime state of a resource object.
///
/// Owner may be null only when a producer cannot recover a canonical region.
/// Consumers that require an owner relation must treat that as coverage loss,
/// never as evidence that the object owns itself.
class ObjectLifetime {
  const MemRegion *Owner;
  SVal Epoch;
  facts::LifetimeState State;

public:
  ObjectLifetime(const MemRegion *Owner, SVal Epoch, facts::LifetimeState State)
      : Owner(Owner), Epoch(Epoch), State(State) {}

  const MemRegion *getOwner() const { return Owner; }
  SVal getEpoch() const { return Epoch; }
  facts::LifetimeState getState() const { return State; }

  friend bool operator==(const ObjectLifetime &Left,
                         const ObjectLifetime &Right) {
    return Left.Owner == Right.Owner && Left.Epoch == Right.Epoch &&
           Left.State == Right.State;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(Owner);
    Epoch.Profile(ID);
    ID.AddInteger(static_cast<unsigned>(State));
  }
};

class ObjectDirection {
  facts::AccessDirection Direction;

public:
  explicit ObjectDirection(facts::AccessDirection Direction)
      : Direction(Direction) {}

  facts::AccessDirection getDirection() const { return Direction; }

  friend bool operator==(ObjectDirection Left, ObjectDirection Right) {
    return Left.Direction == Right.Direction;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(static_cast<unsigned>(Direction));
  }
};

class ValueResultState {
  facts::ResultStateKind State;

public:
  explicit ValueResultState(facts::ResultStateKind State) : State(State) {}

  facts::ResultStateKind getState() const { return State; }

  friend bool operator==(ValueResultState Left, ValueResultState Right) {
    return Left.State == Right.State;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(static_cast<unsigned>(State));
  }
};

/// The values that identify one result-correlated guest-memory transfer.
///
/// The operation is keyed by the symbolic MemTxResult returned to the caller.
/// HostBufferBase, GuestAddress, Begin, and the lengths deliberately remain
/// SVals so constraints on the original analyzer values continue to apply.
/// Owner is null when no canonical owner region is available.  ActualLength is
/// present only when the transfer's successful extent is known; absence must
/// not be interpreted as either zero bytes or a complete transfer.
class TransferOperation {
  SVal HostBufferBase;
  const MemRegion *Owner;
  SVal GuestAddress;
  SVal Begin;
  SVal RequestedLength;
  std::optional<SVal> ActualLength;
  facts::ProvenanceKind Provenance;
  facts::AccessDirection HostBufferDirection;

public:
  TransferOperation(SVal HostBufferBase, const MemRegion *Owner,
                    SVal GuestAddress, SVal Begin, SVal RequestedLength,
                    std::optional<SVal> ActualLength,
                    facts::ProvenanceKind Provenance,
                    facts::AccessDirection HostBufferDirection)
      : HostBufferBase(HostBufferBase), Owner(Owner),
        GuestAddress(GuestAddress), Begin(Begin),
        RequestedLength(RequestedLength), ActualLength(ActualLength),
        Provenance(Provenance), HostBufferDirection(HostBufferDirection) {}

  SVal getHostBufferBase() const { return HostBufferBase; }
  const MemRegion *getOwner() const { return Owner; }
  SVal getGuestAddress() const { return GuestAddress; }
  SVal getBegin() const { return Begin; }
  SVal getRequestedLength() const { return RequestedLength; }
  const std::optional<SVal> &getActualLength() const { return ActualLength; }
  facts::ProvenanceKind getProvenance() const { return Provenance; }
  facts::AccessDirection getHostBufferDirection() const {
    return HostBufferDirection;
  }

  friend bool operator==(const TransferOperation &Left,
                         const TransferOperation &Right) {
    return Left.HostBufferBase == Right.HostBufferBase &&
           Left.Owner == Right.Owner &&
           Left.GuestAddress == Right.GuestAddress &&
           Left.Begin == Right.Begin &&
           Left.RequestedLength == Right.RequestedLength &&
           Left.ActualLength == Right.ActualLength &&
           Left.Provenance == Right.Provenance &&
           Left.HostBufferDirection == Right.HostBufferDirection;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    HostBufferBase.Profile(ID);
    ID.AddPointer(Owner);
    GuestAddress.Profile(ID);
    Begin.Profile(ID);
    RequestedLength.Profile(ID);
    ID.AddBoolean(ActualLength.has_value());
    if (ActualLength)
      ActualLength->Profile(ID);
    ID.AddInteger(static_cast<unsigned>(Provenance));
    ID.AddInteger(static_cast<unsigned>(HostBufferDirection));
  }
};

/// Path-sensitive state for one USB packet copy operation.
///
/// The packet MemRegion is the map key.  ActualLength is the packet offset
/// before the operation, RequestedLength is the requested copy width,
/// and Capacity is the selected direct or combined iovec size.  Status,
/// EndpointType, and SetupParameter preserve the remaining packet state used
/// by later callback summaries; SetupParameter is intentionally raw until the
/// catalog can declare its setup-wLength bit slice.  The checker must not
/// manufacture a transaction if any value is unknown: a missing record is an
/// explicit coverage loss, not evidence that the bounds relation holds.
class USBTransaction {
  SVal HostBuffer;
  SVal RequestedLength;
  SVal Capacity;
  SVal ActualLength;
  SVal Status;
  SVal EndpointType;
  SVal SetupParameter;
  facts::USBPacketDirection Direction;
  facts::USBPacketBufferKind Buffer;
  const Stmt *Origin;

public:
  USBTransaction(SVal HostBuffer, SVal RequestedLength, SVal Capacity,
                 SVal ActualLength, SVal Status, SVal EndpointType,
                 SVal SetupParameter, facts::USBPacketDirection Direction,
                 facts::USBPacketBufferKind Buffer, const Stmt *Origin)
      : HostBuffer(HostBuffer), RequestedLength(RequestedLength),
        Capacity(Capacity), ActualLength(ActualLength), Status(Status),
        EndpointType(EndpointType), SetupParameter(SetupParameter),
        Direction(Direction), Buffer(Buffer), Origin(Origin) {}

  SVal getHostBuffer() const { return HostBuffer; }
  SVal getRequestedLength() const { return RequestedLength; }
  SVal getCapacity() const { return Capacity; }
  SVal getActualLength() const { return ActualLength; }
  SVal getStatus() const { return Status; }
  SVal getEndpointType() const { return EndpointType; }
  SVal getSetupParameter() const { return SetupParameter; }
  facts::USBPacketDirection getDirection() const { return Direction; }
  facts::USBPacketBufferKind getBuffer() const { return Buffer; }
  const Stmt *getOrigin() const { return Origin; }

  bool isValid() const {
    return !HostBuffer.isUnknownOrUndef() &&
           !RequestedLength.isUnknownOrUndef() &&
           !Capacity.isUnknownOrUndef() && !ActualLength.isUnknownOrUndef() &&
           !Status.isUnknownOrUndef() && !EndpointType.isUnknownOrUndef() &&
           !SetupParameter.isUnknownOrUndef() &&
           facts::token(Direction) != "invalid" &&
           facts::token(Buffer) != "invalid";
  }

  friend bool operator==(const USBTransaction &Left,
                         const USBTransaction &Right) {
    return Left.HostBuffer == Right.HostBuffer &&
           Left.RequestedLength == Right.RequestedLength &&
           Left.Capacity == Right.Capacity &&
           Left.ActualLength == Right.ActualLength &&
           Left.Status == Right.Status &&
           Left.EndpointType == Right.EndpointType &&
           Left.SetupParameter == Right.SetupParameter &&
           Left.Direction == Right.Direction && Left.Buffer == Right.Buffer &&
           Left.Origin == Right.Origin;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    HostBuffer.Profile(ID);
    RequestedLength.Profile(ID);
    Capacity.Profile(ID);
    ActualLength.Profile(ID);
    Status.Profile(ID);
    EndpointType.Profile(ID);
    SetupParameter.Profile(ID);
    ID.AddInteger(static_cast<unsigned>(Direction));
    ID.AddInteger(static_cast<unsigned>(Buffer));
    ID.AddPointer(Origin);
  }
};

/// Composite identity for one in-flight queue completion attempt.
///
/// Slot is part of the key so reuse of an attempt token for another slot cannot
/// cross-correlate.  Owner scopes otherwise identical queue IDs belonging to
/// different devices.  All SVals must be known when the key enters state.
class CompletionPublicationKey {
  const MemRegion *Owner;
  SVal QueueID;
  SVal AttemptID;
  SVal Slot;

public:
  CompletionPublicationKey(const MemRegion *Owner, SVal QueueID, SVal AttemptID,
                           SVal Slot)
      : Owner(Owner), QueueID(QueueID), AttemptID(AttemptID), Slot(Slot) {}

  const MemRegion *getOwner() const { return Owner; }
  SVal getQueueID() const { return QueueID; }
  SVal getAttemptID() const { return AttemptID; }
  SVal getSlot() const { return Slot; }

  bool isValid() const {
    return Owner && !QueueID.isUnknownOrUndef() &&
           !AttemptID.isUnknownOrUndef() && !Slot.isUnknownOrUndef();
  }

  friend bool operator==(const CompletionPublicationKey &Left,
                         const CompletionPublicationKey &Right) {
    return Left.Owner == Right.Owner && Left.QueueID == Right.QueueID &&
           Left.AttemptID == Right.AttemptID && Left.Slot == Right.Slot;
  }

  friend bool operator<(const CompletionPublicationKey &Left,
                        const CompletionPublicationKey &Right) {
    if (Left.Owner != Right.Owner)
      return std::less<const MemRegion *>()(Left.Owner, Right.Owner);
    if (Left.QueueID != Right.QueueID)
      return Left.QueueID < Right.QueueID;
    if (Left.AttemptID != Right.AttemptID)
      return Left.AttemptID < Right.AttemptID;
    return Left.Slot < Right.Slot;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(Owner);
    QueueID.Profile(ID);
    AttemptID.Profile(ID);
    Slot.Profile(ID);
  }
};

/// Ordered path-sensitive observations for one completion attempt.
///
/// A descriptor observation starts a fresh publication sequence, clearing any
/// prior ring/interrupt stages.  Ring advancement is accepted only after a
/// terminal descriptor result, and interrupt publication only after ring
/// advancement.  This makes a failed publication true only for the ordered
/// sequence Failed -> RingAdvanced -> InterruptPublished.
class CompletionPublicationState {
  const MemRegion *Owner;
  SVal QueueID;
  SVal AttemptID;
  SVal Slot;
  SVal Vector;
  SymbolRef Result;
  uint8_t ObservedStages;
  const Stmt *DescriptorOrigin;
  const Stmt *RingAdvanceOrigin;
  const Stmt *InterruptOrigin;

  static constexpr uint8_t stageMask(facts::CompletionPublicationStage Stage) {
    switch (Stage) {
    case facts::CompletionPublicationStage::DescriptorPending:
      return uint8_t{1} << 0;
    case facts::CompletionPublicationStage::DescriptorComplete:
      return uint8_t{1} << 1;
    case facts::CompletionPublicationStage::DescriptorFailed:
      return uint8_t{1} << 2;
    case facts::CompletionPublicationStage::RingAdvanced:
      return uint8_t{1} << 3;
    case facts::CompletionPublicationStage::InterruptPublished:
      return uint8_t{1} << 4;
    }
    return 0;
  }

  static constexpr bool
  isDescriptorStage(facts::CompletionPublicationStage Stage) {
    return Stage == facts::CompletionPublicationStage::DescriptorPending ||
           Stage == facts::CompletionPublicationStage::DescriptorComplete ||
           Stage == facts::CompletionPublicationStage::DescriptorFailed;
  }

  CompletionPublicationState(const MemRegion *Owner, SVal QueueID,
                             SVal AttemptID, SVal Slot, SVal Vector,
                             SymbolRef Result, uint8_t ObservedStages,
                             const Stmt *DescriptorOrigin,
                             const Stmt *RingAdvanceOrigin,
                             const Stmt *InterruptOrigin)
      : Owner(Owner), QueueID(QueueID), AttemptID(AttemptID), Slot(Slot),
        Vector(Vector), Result(Result), ObservedStages(ObservedStages),
        DescriptorOrigin(DescriptorOrigin),
        RingAdvanceOrigin(RingAdvanceOrigin), InterruptOrigin(InterruptOrigin) {
  }

public:
  static std::optional<CompletionPublicationState>
  start(const MemRegion *Owner, SVal QueueID, SVal AttemptID, SVal Slot,
        SVal Vector, SymbolRef Result,
        facts::CompletionPublicationStage DescriptorStage, const Stmt *Origin) {
    if (!Owner || QueueID.isUnknownOrUndef() || AttemptID.isUnknownOrUndef() ||
        Slot.isUnknownOrUndef() || Vector.isUnknownOrUndef() || !Result ||
        !isDescriptorStage(DescriptorStage))
      return std::nullopt;
    return CompletionPublicationState(Owner, QueueID, AttemptID, Slot, Vector,
                                      Result, stageMask(DescriptorStage),
                                      Origin, nullptr, nullptr);
  }

  const MemRegion *getOwner() const { return Owner; }
  SVal getQueueID() const { return QueueID; }
  SVal getAttemptID() const { return AttemptID; }
  SVal getSlot() const { return Slot; }
  SVal getVector() const { return Vector; }
  SymbolRef getResult() const { return Result; }

  bool matches(const MemRegion *ExpectedOwner, SVal ExpectedQueueID,
               SVal ExpectedAttemptID, SVal ExpectedSlot, SVal ExpectedVector,
               SymbolRef ExpectedResult) const {
    return Owner == ExpectedOwner && QueueID == ExpectedQueueID &&
           AttemptID == ExpectedAttemptID && Slot == ExpectedSlot &&
           Vector == ExpectedVector && Result == ExpectedResult;
  }

  bool hasStage(facts::CompletionPublicationStage Stage) const {
    const uint8_t Mask = stageMask(Stage);
    return Mask && (ObservedStages & Mask);
  }

  const Stmt *getStageOrigin(facts::CompletionPublicationStage Stage) const {
    switch (Stage) {
    case facts::CompletionPublicationStage::DescriptorPending:
    case facts::CompletionPublicationStage::DescriptorComplete:
    case facts::CompletionPublicationStage::DescriptorFailed:
      return DescriptorOrigin;
    case facts::CompletionPublicationStage::RingAdvanced:
      return RingAdvanceOrigin;
    case facts::CompletionPublicationStage::InterruptPublished:
      return InterruptOrigin;
    }
    return nullptr;
  }

  std::optional<CompletionPublicationState>
  withObservedStage(facts::CompletionPublicationStage Stage,
                    const Stmt *Origin) const {
    if (!stageMask(Stage))
      return std::nullopt;

    if (isDescriptorStage(Stage))
      return CompletionPublicationState(Owner, QueueID, AttemptID, Slot, Vector,
                                        Result, stageMask(Stage), Origin,
                                        nullptr, nullptr);

    if (Stage == facts::CompletionPublicationStage::RingAdvanced) {
      if ((!hasStage(facts::CompletionPublicationStage::DescriptorComplete) &&
           !hasStage(facts::CompletionPublicationStage::DescriptorFailed)) ||
          hasStage(facts::CompletionPublicationStage::RingAdvanced) ||
          hasStage(facts::CompletionPublicationStage::InterruptPublished))
        return std::nullopt;
      return CompletionPublicationState(
          Owner, QueueID, AttemptID, Slot, Vector, Result,
          ObservedStages | stageMask(Stage), DescriptorOrigin, Origin, nullptr);
    }

    if (!hasStage(facts::CompletionPublicationStage::RingAdvanced) ||
        hasStage(facts::CompletionPublicationStage::InterruptPublished))
      return std::nullopt;
    return CompletionPublicationState(Owner, QueueID, AttemptID, Slot, Vector,
                                      Result, ObservedStages | stageMask(Stage),
                                      DescriptorOrigin, RingAdvanceOrigin,
                                      Origin);
  }

  /// Whether the ordered failed publication stages are present.  This is only
  /// the structural half of reportability; callers must additionally join the
  /// result and transfer facts with isFailedDMACompletionPublished().
  bool hasFailedPublicationSequence() const {
    return hasStage(facts::CompletionPublicationStage::DescriptorFailed) &&
           hasStage(facts::CompletionPublicationStage::RingAdvanced) &&
           hasStage(facts::CompletionPublicationStage::InterruptPublished);
  }

  bool isCompleteCompletionPublished() const {
    return hasStage(facts::CompletionPublicationStage::DescriptorComplete) &&
           hasStage(facts::CompletionPublicationStage::RingAdvanced) &&
           hasStage(facts::CompletionPublicationStage::InterruptPublished);
  }

  /// Terminal publications must be diagnosed or discarded by their event
  /// adapter.  They are not live in-flight identities.
  bool isTerminalPublication() const {
    return hasFailedPublicationSequence() || isCompleteCompletionPublished();
  }

  friend bool operator==(const CompletionPublicationState &Left,
                         const CompletionPublicationState &Right) {
    return Left.Owner == Right.Owner && Left.QueueID == Right.QueueID &&
           Left.AttemptID == Right.AttemptID && Left.Slot == Right.Slot &&
           Left.Vector == Right.Vector && Left.Result == Right.Result &&
           Left.ObservedStages == Right.ObservedStages &&
           Left.DescriptorOrigin == Right.DescriptorOrigin &&
           Left.RingAdvanceOrigin == Right.RingAdvanceOrigin &&
           Left.InterruptOrigin == Right.InterruptOrigin;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(Owner);
    QueueID.Profile(ID);
    AttemptID.Profile(ID);
    Slot.Profile(ID);
    Vector.Profile(ID);
    ID.AddPointer(Result);
    ID.AddInteger(ObservedStages);
    ID.AddPointer(DescriptorOrigin);
    ID.AddPointer(RingAdvanceOrigin);
    ID.AddPointer(InterruptOrigin);
  }
};

// Named marker types are required so every including checker translation unit
// uses the same ProgramState GDM key.  Do not replace these with the
// REGISTER_*_WITH_PROGRAMSTATE macros, whose marker types are TU-local.
class ObjectExtentMap {};
class ValueProvenanceMap {};
class ObjectLifetimeMap {};
class ObjectDirectionMap {};
class ValueResultStateMap {};
class TransferOperationMap {};
class USBTransactionMap {};
class CompletionPublicationMap {};

using ObjectExtentMapTy = CLANG_ENTO_PROGRAMSTATE_MAP(ObjectExtentKey,
                                                      ObjectExtent);
using ValueProvenanceMapTy = CLANG_ENTO_PROGRAMSTATE_MAP(SymbolRef,
                                                         ValueProvenance);
using ObjectLifetimeMapTy = CLANG_ENTO_PROGRAMSTATE_MAP(const MemRegion *,
                                                        ObjectLifetime);
using ObjectDirectionMapTy = CLANG_ENTO_PROGRAMSTATE_MAP(const MemRegion *,
                                                         ObjectDirection);
using ValueResultStateMapTy = CLANG_ENTO_PROGRAMSTATE_MAP(SymbolRef,
                                                          ValueResultState);
using TransferOperationMapTy = CLANG_ENTO_PROGRAMSTATE_MAP(SymbolRef,
                                                           TransferOperation);
using USBTransactionMapTy = CLANG_ENTO_PROGRAMSTATE_MAP(const MemRegion *,
                                                        USBTransaction);
using CompletionPublicationMapTy = CLANG_ENTO_PROGRAMSTATE_MAP(
    CompletionPublicationKey, CompletionPublicationState);

} // namespace state
} // namespace qemu

template <>
struct ProgramStateTrait<qemu::state::ObjectExtentMap>
    : ProgramStatePartialTrait<qemu::state::ObjectExtentMapTy> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

template <>
struct ProgramStateTrait<qemu::state::ValueProvenanceMap>
    : ProgramStatePartialTrait<qemu::state::ValueProvenanceMapTy> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

template <>
struct ProgramStateTrait<qemu::state::ObjectLifetimeMap>
    : ProgramStatePartialTrait<qemu::state::ObjectLifetimeMapTy> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

template <>
struct ProgramStateTrait<qemu::state::ObjectDirectionMap>
    : ProgramStatePartialTrait<qemu::state::ObjectDirectionMapTy> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

template <>
struct ProgramStateTrait<qemu::state::ValueResultStateMap>
    : ProgramStatePartialTrait<qemu::state::ValueResultStateMapTy> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

template <>
struct ProgramStateTrait<qemu::state::TransferOperationMap>
    : ProgramStatePartialTrait<qemu::state::TransferOperationMapTy> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

template <>
struct ProgramStateTrait<qemu::state::USBTransactionMap>
    : ProgramStatePartialTrait<qemu::state::USBTransactionMapTy> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

template <>
struct ProgramStateTrait<qemu::state::CompletionPublicationMap>
    : ProgramStatePartialTrait<qemu::state::CompletionPublicationMapTy> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};

namespace qemu {
namespace state {

inline const ObjectExtent *getObjectExtent(ProgramStateRef State,
                                           const MemRegion *Object,
                                           facts::ExtentKind Kind) {
  return State->get<ObjectExtentMap>(ObjectExtentKey(Object, Kind));
}

inline ProgramStateRef setObjectExtent(ProgramStateRef State,
                                       const MemRegion *Object,
                                       facts::ExtentKind Kind, SVal Begin,
                                       SVal Length) {
  return State->set<ObjectExtentMap>(ObjectExtentKey(Object, Kind),
                                     ObjectExtent(Begin, Length));
}

inline ProgramStateRef removeObjectExtent(ProgramStateRef State,
                                          const MemRegion *Object,
                                          facts::ExtentKind Kind) {
  return State->remove<ObjectExtentMap>(ObjectExtentKey(Object, Kind));
}

inline const ValueProvenance *getValueProvenance(ProgramStateRef State,
                                                 SymbolRef Value) {
  return State->get<ValueProvenanceMap>(Value);
}

inline ProgramStateRef setValueProvenance(ProgramStateRef State,
                                          SymbolRef Value,
                                          facts::ProvenanceKind Kind) {
  return State->set<ValueProvenanceMap>(Value, ValueProvenance(Kind));
}

inline ProgramStateRef removeValueProvenance(ProgramStateRef State,
                                             SymbolRef Value) {
  return State->remove<ValueProvenanceMap>(Value);
}

inline const ObjectLifetime *getObjectLifetime(ProgramStateRef State,
                                               const MemRegion *Object) {
  return State->get<ObjectLifetimeMap>(Object);
}

inline ProgramStateRef setObjectLifetime(ProgramStateRef State,
                                         const MemRegion *Object,
                                         const MemRegion *Owner, SVal Epoch,
                                         facts::LifetimeState Lifetime) {
  return State->set<ObjectLifetimeMap>(Object,
                                       ObjectLifetime(Owner, Epoch, Lifetime));
}

inline ProgramStateRef removeObjectLifetime(ProgramStateRef State,
                                            const MemRegion *Object) {
  return State->remove<ObjectLifetimeMap>(Object);
}

inline const ObjectDirection *getObjectDirection(ProgramStateRef State,
                                                 const MemRegion *Object) {
  return State->get<ObjectDirectionMap>(Object);
}

inline ProgramStateRef setObjectDirection(ProgramStateRef State,
                                          const MemRegion *Object,
                                          facts::AccessDirection Direction) {
  return State->set<ObjectDirectionMap>(Object, ObjectDirection(Direction));
}

inline ProgramStateRef removeObjectDirection(ProgramStateRef State,
                                             const MemRegion *Object) {
  return State->remove<ObjectDirectionMap>(Object);
}

inline const ValueResultState *getValueResultState(ProgramStateRef State,
                                                   SymbolRef Result) {
  return State->get<ValueResultStateMap>(Result);
}

inline ProgramStateRef setValueResultState(ProgramStateRef State,
                                           SymbolRef Result,
                                           facts::ResultStateKind ResultState) {
  return State->set<ValueResultStateMap>(Result, ValueResultState(ResultState));
}

inline ProgramStateRef removeValueResultState(ProgramStateRef State,
                                              SymbolRef Result) {
  return State->remove<ValueResultStateMap>(Result);
}

inline const TransferOperation *getTransferOperation(ProgramStateRef State,
                                                     SymbolRef Result) {
  return State->get<TransferOperationMap>(Result);
}

inline ProgramStateRef setTransferOperation(
    ProgramStateRef State, SymbolRef Result, SVal HostBufferBase,
    const MemRegion *Owner, SVal GuestAddress, SVal Begin, SVal RequestedLength,
    std::optional<SVal> ActualLength, facts::ProvenanceKind Provenance,
    facts::AccessDirection HostBufferDirection) {
  return State->set<TransferOperationMap>(
      Result, TransferOperation(HostBufferBase, Owner, GuestAddress, Begin,
                                RequestedLength, ActualLength, Provenance,
                                HostBufferDirection));
}

/// Record a DMA transfer.  Other transfer adapters must use the overload above
/// and provide their provenance explicitly.
inline ProgramStateRef
setTransferOperation(ProgramStateRef State, SymbolRef Result,
                     SVal HostBufferBase, const MemRegion *Owner,
                     SVal GuestAddress, SVal Begin, SVal RequestedLength,
                     std::optional<SVal> ActualLength,
                     facts::AccessDirection HostBufferDirection) {
  return setTransferOperation(State, Result, HostBufferBase, Owner,
                              GuestAddress, Begin, RequestedLength,
                              ActualLength, facts::ProvenanceKind::DMA,
                              HostBufferDirection);
}

inline ProgramStateRef removeTransferOperation(ProgramStateRef State,
                                               SymbolRef Result) {
  return State->remove<TransferOperationMap>(Result);
}

inline const USBTransaction *getUSBTransaction(ProgramStateRef State,
                                               const MemRegion *Packet) {
  if (!Packet)
    return nullptr;
  return State->get<USBTransactionMap>(Packet);
}

inline ProgramStateRef
setUSBTransaction(ProgramStateRef State, const MemRegion *Packet,
                  SVal HostBuffer, SVal RequestedLength, SVal Capacity,
                  SVal ActualLength, SVal Status, SVal EndpointType,
                  SVal SetupParameter, facts::USBPacketDirection Direction,
                  facts::USBPacketBufferKind Buffer, const Stmt *Origin) {
  USBTransaction Transaction(HostBuffer, RequestedLength, Capacity,
                             ActualLength, Status, EndpointType, SetupParameter,
                             Direction, Buffer, Origin);
  if (!Packet)
    return State;
  // An unresolved replacement invalidates the old one-call observation.  It
  // must never leave a prior packet epoch's relation live.
  if (!Transaction.isValid())
    return State->get<USBTransactionMap>(Packet)
               ? State->remove<USBTransactionMap>(Packet)
               : State;
  return State->set<USBTransactionMap>(Packet, Transaction);
}

inline ProgramStateRef removeUSBTransaction(ProgramStateRef State,
                                            const MemRegion *Packet) {
  if (!Packet)
    return State;
  return State->remove<USBTransactionMap>(Packet);
}

/// Keep the symbolic relation values alive only while the packet object is
/// live.  Transaction adapters must explicitly remove the record after a
/// completed one-call operation so it cannot leak into a later packet epoch.
inline void markLiveUSBTransactions(ProgramStateRef State,
                                    SymbolReaper &SymReaper) {
  const auto MarkValue = [&](SVal Value) {
    for (SymbolRef Symbol : Value.symbols())
      SymReaper.markLive(Symbol);
  };
  for (const auto &Entry : State->get<USBTransactionMap>()) {
    if (!SymReaper.isLiveRegion(Entry.first))
      continue;
    MarkValue(Entry.second.getHostBuffer());
    MarkValue(Entry.second.getRequestedLength());
    MarkValue(Entry.second.getCapacity());
    MarkValue(Entry.second.getActualLength());
    MarkValue(Entry.second.getStatus());
    MarkValue(Entry.second.getEndpointType());
    MarkValue(Entry.second.getSetupParameter());
  }
}

inline ProgramStateRef removeDeadUSBTransactions(ProgramStateRef State,
                                                 SymbolReaper &SymReaper) {
  const auto Transactions = State->get<USBTransactionMap>();
  for (const auto &Entry : Transactions)
    if (!SymReaper.isLiveRegion(Entry.first))
      State = State->remove<USBTransactionMap>(Entry.first);
  return State;
}

/// Failure states accepted by the failed-DMA publication rule.  Rejected is
/// the only state currently produced with the required transfer correlation.
/// UncheckedError is reserved for a future producer and is not evidence here;
/// Partial and Retry do not prove a terminal failed transfer either.
constexpr bool
isAcceptedFailedCompletionResult(facts::ResultStateKind ResultState) {
  return ResultState == facts::ResultStateKind::Rejected;
}

/// Join both result-correlated facts required by the failed-DMA rule.  Looking
/// up both maps with the same SymbolRef prevents a result from one operation
/// from authorizing publication of another.
inline bool hasFailedDMATransferResult(ProgramStateRef State,
                                       SymbolRef Result) {
  if (!Result)
    return false;
  const ValueResultState *ResultState = getValueResultState(State, Result);
  const TransferOperation *Transfer = getTransferOperation(State, Result);
  return ResultState && Transfer &&
         isAcceptedFailedCompletionResult(ResultState->getState()) &&
         Transfer->getProvenance() == facts::ProvenanceKind::DMA;
}

inline const CompletionPublicationState *
getCompletionPublication(ProgramStateRef State, const MemRegion *QueueOwner,
                         SVal QueueID, SVal AttemptID, SVal Slot) {
  const CompletionPublicationKey Key(QueueOwner, QueueID, AttemptID, Slot);
  if (!Key.isValid())
    return nullptr;
  return State->get<CompletionPublicationMap>(Key);
}

inline ProgramStateRef
setCompletionPublication(ProgramStateRef State,
                         const CompletionPublicationKey &Key,
                         const CompletionPublicationState &Publication) {
  if (!Key.isValid() || Publication.getOwner() != Key.getOwner() ||
      Publication.getQueueID() != Key.getQueueID() ||
      Publication.getAttemptID() != Key.getAttemptID() ||
      Publication.getSlot() != Key.getSlot())
    return State;
  if (Publication.hasStage(
          facts::CompletionPublicationStage::DescriptorFailed) &&
      !hasFailedDMATransferResult(State, Publication.getResult()))
    return State;

  // A result identifies one in-flight publication attempt.  Do not allow a
  // raw setter or a second adapter to rebind it to another queue identity.
  // Updating the exact same composite key remains valid.
  for (const auto &Entry : State->get<CompletionPublicationMap>()) {
    if (Entry.second.getResult() == Publication.getResult() &&
        !(Entry.first == Key))
      return State;
  }
  return State->set<CompletionPublicationMap>(Key, Publication);
}

inline ProgramStateRef startCompletionPublication(
    ProgramStateRef State, const MemRegion *QueueOwner, SVal QueueID,
    SVal AttemptID, SVal Slot, SVal Vector, SymbolRef Result,
    facts::CompletionPublicationStage InitialStage, const Stmt *Origin) {
  const CompletionPublicationKey Key(QueueOwner, QueueID, AttemptID, Slot);
  if (!Key.isValid())
    return State;
  std::optional<CompletionPublicationState> Publication =
      CompletionPublicationState::start(QueueOwner, QueueID, AttemptID, Slot,
                                        Vector, Result, InitialStage, Origin);
  if (!Publication)
    return State;
  if (InitialStage == facts::CompletionPublicationStage::DescriptorFailed &&
      !hasFailedDMATransferResult(State, Result))
    return State;
  return setCompletionPublication(State, Key, *Publication);
}

/// Add a stage to an existing queue publication.  A missing queue fact is a
/// producer coverage gap, so this helper leaves State unchanged rather than
/// inventing uncorrelated queue, slot, or vector identities.
inline ProgramStateRef observeCompletionPublicationStage(
    ProgramStateRef State, const MemRegion *QueueOwner, SVal QueueID,
    SVal AttemptID, SVal Slot, SVal Vector, SymbolRef Result,
    facts::CompletionPublicationStage Stage, const Stmt *Origin) {
  const CompletionPublicationKey Key(QueueOwner, QueueID, AttemptID, Slot);
  if (!Key.isValid() || Vector.isUnknownOrUndef() || !Result)
    return State;
  const CompletionPublicationState *Publication =
      State->get<CompletionPublicationMap>(Key);
  if (!Publication || !Publication->matches(QueueOwner, QueueID, AttemptID,
                                            Slot, Vector, Result))
    return State;
  const bool AdvancesFailedPublication =
      Stage == facts::CompletionPublicationStage::DescriptorFailed ||
      ((Stage == facts::CompletionPublicationStage::RingAdvanced ||
        Stage == facts::CompletionPublicationStage::InterruptPublished) &&
       Publication->hasStage(
           facts::CompletionPublicationStage::DescriptorFailed));
  if (AdvancesFailedPublication && !hasFailedDMATransferResult(State, Result))
    return State;
  std::optional<CompletionPublicationState> Updated =
      Publication->withObservedStage(Stage, Origin);
  if (!Updated)
    return State;
  return setCompletionPublication(State, Key, *Updated);
}

/// A failed completion is reportable only while its ordered publication
/// sequence and both result-correlated DMA facts coexist on this path.
inline bool
isFailedDMACompletionPublished(ProgramStateRef State,
                               const CompletionPublicationState *Publication) {
  return Publication && Publication->hasFailedPublicationSequence() &&
         hasFailedDMATransferResult(State, Publication->getResult());
}

inline bool isFailedDMACompletionPublished(ProgramStateRef State,
                                           const MemRegion *QueueOwner,
                                           SVal QueueID, SVal AttemptID,
                                           SVal Slot) {
  return isFailedDMACompletionPublished(
      State,
      getCompletionPublication(State, QueueOwner, QueueID, AttemptID, Slot));
}

inline ProgramStateRef
removeCompletionPublication(ProgramStateRef State,
                            const CompletionPublicationKey &Key) {
  if (!Key.isValid())
    return State;
  return State->remove<CompletionPublicationMap>(Key);
}

/// Release every publication tied to Result.  Completion event adapters use
/// this after terminal reporting or reset so retained identity symbols can die.
inline ProgramStateRef
removeCompletionPublicationsForResult(ProgramStateRef State, SymbolRef Result) {
  if (!Result)
    return State;
  const auto Publications = State->get<CompletionPublicationMap>();
  for (const auto &Entry : Publications) {
    if (Entry.second.getResult() == Result)
      State = State->remove<CompletionPublicationMap>(Entry.first);
  }
  return State;
}

/// Release all in-flight publications when an owning queue/device is reset.
inline ProgramStateRef
removeCompletionPublicationsForOwner(ProgramStateRef State,
                                     const MemRegion *QueueOwner) {
  if (!QueueOwner)
    return State;
  const auto Publications = State->get<CompletionPublicationMap>();
  for (const auto &Entry : Publications) {
    if (Entry.first.getOwner() == QueueOwner)
      State = State->remove<CompletionPublicationMap>(Entry.first);
  }
  return State;
}

/// Keep only an owner's active completion join alive across a dead-symbol
/// sweep.  Ordinary result and transfer facts deliberately are not roots.
inline void markLiveCompletionPublications(ProgramStateRef State,
                                           SymbolReaper &SymReaper) {
  const auto MarkValue = [&](SVal Value) {
    for (SymbolRef Symbol : Value.symbols())
      SymReaper.markLive(Symbol);
  };

  for (const auto &Entry : State->get<CompletionPublicationMap>()) {
    const CompletionPublicationState &Publication = Entry.second;
    if (Publication.isTerminalPublication() ||
        !SymReaper.isLiveRegion(Publication.getOwner()))
      continue;
    SymReaper.markLive(Publication.getResult());
    MarkValue(Publication.getQueueID());
    MarkValue(Publication.getAttemptID());
    MarkValue(Publication.getSlot());
    MarkValue(Publication.getVector());
  }
}

/// Drop terminal publications after their reporting event, as well as active
/// records whose owner or result did not survive liveness marking.
inline ProgramStateRef
removeDeadCompletionPublications(ProgramStateRef State,
                                 SymbolReaper &SymReaper) {
  const auto Publications = State->get<CompletionPublicationMap>();
  for (const auto &Entry : Publications) {
    const CompletionPublicationState &Publication = Entry.second;
    if (Publication.isTerminalPublication() ||
        !SymReaper.isLiveRegion(Publication.getOwner()) ||
        SymReaper.isDead(Publication.getResult()))
      State = State->remove<CompletionPublicationMap>(Entry.first);
  }
  return State;
}

inline ProgramStateRef removeCompletionPublication(ProgramStateRef State,
                                                   const MemRegion *QueueOwner,
                                                   SVal QueueID, SVal AttemptID,
                                                   SVal Slot) {
  const CompletionPublicationKey Key(QueueOwner, QueueID, AttemptID, Slot);
  return removeCompletionPublication(State, Key);
}

} // namespace state
} // namespace qemu
} // namespace ento
} // namespace clang

#endif // LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_QEMUSHAREDSTATE_H
