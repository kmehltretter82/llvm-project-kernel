//===-- QEMUSharedFacts.h - Shared QEMU analyzer facts ---------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines the stable vocabulary used to exchange QEMU facts between
// checkers and later interprocedural summary/witness stages.  The records are
// deliberately independent of ProgramState: individual checkers remain
// responsible for registering compact path-sensitive storage and can convert
// that storage to these records at checker boundaries.
//
// StableIDRef and the fact records are non-owning.  Their strings must live as
// long as the record (normally catalog literals or strings interned by the
// analyzer).  Canonical identities of well-formed facts are owning,
// length-prefixed byte strings.  They are suitable for persistent equality and
// external cryptographic hashing; stableHash() is only a deterministic index
// and never replaces full identity comparison.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_QEMUSHAREDFACTS_H
#define LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_QEMUSHAREDFACTS_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>

namespace clang {
namespace ento {
namespace qemu {
namespace facts {

inline constexpr unsigned CanonicalFormatVersion = 1;

struct ModelIDTag {};
struct RuleIDTag {};
struct EntityIDTag {};
struct ObjectIDTag {};
struct ValueIDTag {};

/// A strongly typed reference to a persistent identifier.
///
/// The tag prevents model, rule, entity, object, and symbolic-value IDs from
/// being mixed accidentally.  IDs are opaque to this layer, but production
/// IDs must be printable, non-empty ASCII tokens so they remain portable in
/// manifests and witnesses.
template <typename Tag> class StableIDRef {
  std::string_view Value;

public:
  constexpr StableIDRef() = default;
  explicit constexpr StableIDRef(std::string_view Value) : Value(Value) {}
  template <typename T,
            std::enable_if_t<std::is_same_v<std::decay_t<T>, std::string> &&
                                 !std::is_lvalue_reference_v<T>,
                             int> = 0>
  StableIDRef(T &&) = delete;

  constexpr std::string_view value() const { return Value; }
  constexpr bool empty() const { return Value.empty(); }

  friend constexpr bool operator==(StableIDRef Left, StableIDRef Right) {
    return Left.Value == Right.Value;
  }
  friend constexpr bool operator!=(StableIDRef Left, StableIDRef Right) {
    return !(Left == Right);
  }
  friend constexpr bool operator<(StableIDRef Left, StableIDRef Right) {
    return Left.Value < Right.Value;
  }
};

using ModelIDRef = StableIDRef<ModelIDTag>;
using RuleIDRef = StableIDRef<RuleIDTag>;
using EntityIDRef = StableIDRef<EntityIDTag>;
using ObjectIDRef = StableIDRef<ObjectIDTag>;
using ValueIDRef = StableIDRef<ValueIDTag>;

constexpr bool isValidPersistentToken(std::string_view Value) {
  if (Value.empty())
    return false;
  for (unsigned char Byte : Value)
    if (Byte < 0x21 || Byte > 0x7e)
      return false;
  return true;
}

enum class FactDomain : uint8_t {
  Provenance,
  Extent,
  Relation,
  Lifetime,
  Direction,
  ExecutionContext,
  ResultState,
  CompletionPublication,
  USBTransaction,
};

enum class ProvenanceKind : uint8_t {
  MMIO,
  PIO,
  DMA,
  Virtqueue,
  USB,
  Packet,
  BlockBackend,
  Migration,
  ImageParser,
  HostConfiguration,
  TrustedHostData,
};

enum class ExtentKind : uint8_t {
  Allocation,
  Mapped,
  LogicalPayload,
  InitializedBytes,
  ElementCount,
  Requested,
  ActualTransfer,
};

enum class RelationKind : uint8_t {
  Equality,
  UpperBound,
  LowerBound,
  Product,
  OffsetPlusLength,
  Alignment,
  SignednessConversion,
  WrapCondition,
};

enum class LifetimeState : uint8_t {
  Live,
  Pending,
  Cancelled,
  Unmapped,
  Released,
  Reinitialized,
};

enum class AccessDirection : uint8_t {
  HostRead,
  HostWrite,
  GuestVisibleCopy,
  DescriptorPublication,
  IndirectDispatch,
};

enum class ExecutionContextKind : uint8_t {
  BQL,
  RCU,
  AioContext,
  Coroutine,
  BottomHalf,
  Timer,
  Worker,
  VCPUThread,
};

enum class ResultStateKind : uint8_t {
  Complete,
  Partial,
  Retry,
  Rejected,
  UncheckedError,
};

/// Observable stages of publishing a device completion to the guest.
///
/// The stages are deliberately independent facts: a checker can retain, for
/// example, DescriptorFailed, RingAdvanced, and InterruptPublished together
/// to diagnose a failed DMA operation that was nevertheless advertised as a
/// consumable completion.
enum class CompletionPublicationStage : uint8_t {
  DescriptorPending,
  DescriptorComplete,
  DescriptorFailed,
  RingAdvanced,
  InterruptPublished,
};

/// Direction of one USB packet transaction as encoded by USBPacket::pid.
enum class USBPacketDirection : uint8_t {
  DeviceToHost,
  HostToDevice,
  Setup,
};

/// Iovec selected by usb_packet_copy() for this path.
enum class USBPacketBufferKind : uint8_t {
  Direct,
  Combined,
};

constexpr std::string_view token(FactDomain Value) {
  switch (Value) {
  case FactDomain::Provenance:
    return "provenance";
  case FactDomain::Extent:
    return "extent";
  case FactDomain::Relation:
    return "relation";
  case FactDomain::Lifetime:
    return "lifetime";
  case FactDomain::Direction:
    return "direction";
  case FactDomain::ExecutionContext:
    return "execution-context";
  case FactDomain::ResultState:
    return "result-state";
  case FactDomain::CompletionPublication:
    return "completion-publication";
  case FactDomain::USBTransaction:
    return "usb-transaction";
  }
  return "invalid";
}

constexpr std::string_view token(ProvenanceKind Value) {
  switch (Value) {
  case ProvenanceKind::MMIO:
    return "mmio";
  case ProvenanceKind::PIO:
    return "pio";
  case ProvenanceKind::DMA:
    return "dma";
  case ProvenanceKind::Virtqueue:
    return "virtqueue";
  case ProvenanceKind::USB:
    return "usb";
  case ProvenanceKind::Packet:
    return "packet";
  case ProvenanceKind::BlockBackend:
    return "block-backend";
  case ProvenanceKind::Migration:
    return "migration";
  case ProvenanceKind::ImageParser:
    return "image-parser";
  case ProvenanceKind::HostConfiguration:
    return "host-configuration";
  case ProvenanceKind::TrustedHostData:
    return "trusted-host-data";
  }
  return "invalid";
}

constexpr std::string_view token(ExtentKind Value) {
  switch (Value) {
  case ExtentKind::Allocation:
    return "allocation";
  case ExtentKind::Mapped:
    return "mapped";
  case ExtentKind::LogicalPayload:
    return "logical-payload";
  case ExtentKind::InitializedBytes:
    return "initialized-bytes";
  case ExtentKind::ElementCount:
    return "element-count";
  case ExtentKind::Requested:
    return "requested";
  case ExtentKind::ActualTransfer:
    return "actual-transfer";
  }
  return "invalid";
}

constexpr std::string_view token(RelationKind Value) {
  switch (Value) {
  case RelationKind::Equality:
    return "equality";
  case RelationKind::UpperBound:
    return "upper-bound";
  case RelationKind::LowerBound:
    return "lower-bound";
  case RelationKind::Product:
    return "product";
  case RelationKind::OffsetPlusLength:
    return "offset-plus-length";
  case RelationKind::Alignment:
    return "alignment";
  case RelationKind::SignednessConversion:
    return "signedness-conversion";
  case RelationKind::WrapCondition:
    return "wrap-condition";
  }
  return "invalid";
}

constexpr std::string_view token(LifetimeState Value) {
  switch (Value) {
  case LifetimeState::Live:
    return "live";
  case LifetimeState::Pending:
    return "pending";
  case LifetimeState::Cancelled:
    return "cancelled";
  case LifetimeState::Unmapped:
    return "unmapped";
  case LifetimeState::Released:
    return "released";
  case LifetimeState::Reinitialized:
    return "reinitialized";
  }
  return "invalid";
}

constexpr std::string_view token(AccessDirection Value) {
  switch (Value) {
  case AccessDirection::HostRead:
    return "host-read";
  case AccessDirection::HostWrite:
    return "host-write";
  case AccessDirection::GuestVisibleCopy:
    return "guest-visible-copy";
  case AccessDirection::DescriptorPublication:
    return "descriptor-publication";
  case AccessDirection::IndirectDispatch:
    return "indirect-dispatch";
  }
  return "invalid";
}

constexpr std::string_view token(ExecutionContextKind Value) {
  switch (Value) {
  case ExecutionContextKind::BQL:
    return "bql";
  case ExecutionContextKind::RCU:
    return "rcu";
  case ExecutionContextKind::AioContext:
    return "aio-context";
  case ExecutionContextKind::Coroutine:
    return "coroutine";
  case ExecutionContextKind::BottomHalf:
    return "bottom-half";
  case ExecutionContextKind::Timer:
    return "timer";
  case ExecutionContextKind::Worker:
    return "worker";
  case ExecutionContextKind::VCPUThread:
    return "vcpu-thread";
  }
  return "invalid";
}

constexpr std::string_view token(ResultStateKind Value) {
  switch (Value) {
  case ResultStateKind::Complete:
    return "complete";
  case ResultStateKind::Partial:
    return "partial";
  case ResultStateKind::Retry:
    return "retry";
  case ResultStateKind::Rejected:
    return "rejected";
  case ResultStateKind::UncheckedError:
    return "unchecked-error";
  }
  return "invalid";
}

constexpr std::string_view token(CompletionPublicationStage Value) {
  switch (Value) {
  case CompletionPublicationStage::DescriptorPending:
    return "descriptor-pending";
  case CompletionPublicationStage::DescriptorComplete:
    return "descriptor-complete";
  case CompletionPublicationStage::DescriptorFailed:
    return "descriptor-failed";
  case CompletionPublicationStage::RingAdvanced:
    return "ring-advanced";
  case CompletionPublicationStage::InterruptPublished:
    return "interrupt-published";
  }
  return "invalid";
}

constexpr std::string_view token(USBPacketDirection Value) {
  switch (Value) {
  case USBPacketDirection::DeviceToHost:
    return "device-to-host";
  case USBPacketDirection::HostToDevice:
    return "host-to-device";
  case USBPacketDirection::Setup:
    return "setup";
  }
  return "invalid";
}

constexpr std::string_view token(USBPacketBufferKind Value) {
  switch (Value) {
  case USBPacketBufferKind::Direct:
    return "direct-iovec";
  case USBPacketBufferKind::Combined:
    return "combined-iovec";
  }
  return "invalid";
}

/// Stable producer identity common to every fact.
///
/// Producer is normally a function USR plus source/compile-command identity.
/// Rule is absent for model facts which have not yet reached a diagnostic.
struct FactOrigin {
  ModelIDRef Model;
  std::optional<RuleIDRef> Rule;
  EntityIDRef Producer;
};

struct ProvenanceFact {
  FactOrigin Origin;
  ValueIDRef Value;
  ProvenanceKind Provenance;
};

/// An extent or interval.  Begin is explicit for every extent; use a stable
/// constant-zero ValueIDRef for whole-object extents.
struct ExtentFact {
  FactOrigin Origin;
  ObjectIDRef Object;
  ExtentKind Kind;
  ValueIDRef Begin;
  ValueIDRef Length;
};

/// A relation `Result Kind Operand [Parameter]`.
///
/// Equality, UpperBound, and LowerBound mean Result ==, <=, and >= Operand,
/// respectively.  Alignment means Result is aligned to the byte alignment in
/// Operand.  SignednessConversion and WrapCondition relate Result to the
/// expression identified by Operand.  Product and OffsetPlusLength mean
/// Result == Operand * Parameter and Result == Operand + Parameter; they are
/// the only relations which carry Parameter.
struct RelationFact {
  FactOrigin Origin;
  RelationKind Kind;
  ValueIDRef Result;
  ValueIDRef Operand;
  std::optional<ValueIDRef> Parameter;
};

struct LifetimeFact {
  FactOrigin Origin;
  ObjectIDRef Resource;
  ObjectIDRef Owner;
  ValueIDRef Epoch;
  LifetimeState State;
};

struct DirectionFact {
  FactOrigin Origin;
  ObjectIDRef Object;
  AccessDirection Direction;
};

struct ExecutionContextFact {
  FactOrigin Origin;
  EntityIDRef Operation;
  ExecutionContextKind Context;
};

struct ResultStateFact {
  FactOrigin Origin;
  ValueIDRef Result;
  ResultStateKind State;
};

/// One stage in the publication of a queue completion.
///
/// Queue, Slot, and Vector are stable semantic identifiers rather than source
/// expressions.  Producers may use explicit "unknown:*" identifiers only as a
/// serialization fallback when a persisted fact must record a coverage loss
/// while preserving a fixed canonical shape.  Such text is not evidence of a
/// known analyzer value: path-sensitive publication joins reject UnknownVal
/// and UndefinedVal identities rather than treating them as equal.
struct CompletionPublicationFact {
  FactOrigin Origin;
  ObjectIDRef Queue;
  ValueIDRef Attempt;
  ValueIDRef Slot;
  ValueIDRef Vector;
  ValueIDRef Result;
  CompletionPublicationStage Stage;
};

/// One USB copy operation bound to its packet transaction.
///
/// ActualLength is the packet offset before the operation.  RequestedLength
/// is the number of bytes this operation will consume or publish, while
/// Capacity is the selected direct or combined iovec size.  Keeping these as
/// separate values lets consumers express and solve
/// ``actual_length + requested_length <= capacity`` without confusing any of
/// them with the host object's allocation or initialized extent.  Status and
/// EndpointType retain the other packet-state inputs needed by later callback
/// summaries.  SetupParameter is the raw USBPacket::parameter value; decoding
/// its setup wLength field requires an explicit bit-slice relation and must not
/// be inferred by this record alone.
struct USBTransactionFact {
  FactOrigin Origin;
  ObjectIDRef Packet;
  ObjectIDRef HostBuffer;
  ValueIDRef RequestedLength;
  ValueIDRef Capacity;
  ValueIDRef ActualLength;
  ValueIDRef Status;
  ValueIDRef EndpointType;
  ValueIDRef SetupParameter;
  USBPacketDirection Direction;
  USBPacketBufferKind Buffer;
};

using FactRecord =
    std::variant<ProvenanceFact, ExtentFact, RelationFact, LifetimeFact,
                 DirectionFact, ExecutionContextFact, ResultStateFact,
                 CompletionPublicationFact, USBTransactionFact>;

constexpr FactDomain domainOf(const ProvenanceFact &) {
  return FactDomain::Provenance;
}
constexpr FactDomain domainOf(const ExtentFact &) { return FactDomain::Extent; }
constexpr FactDomain domainOf(const RelationFact &) {
  return FactDomain::Relation;
}
constexpr FactDomain domainOf(const LifetimeFact &) {
  return FactDomain::Lifetime;
}
constexpr FactDomain domainOf(const DirectionFact &) {
  return FactDomain::Direction;
}
constexpr FactDomain domainOf(const ExecutionContextFact &) {
  return FactDomain::ExecutionContext;
}
constexpr FactDomain domainOf(const ResultStateFact &) {
  return FactDomain::ResultState;
}
constexpr FactDomain domainOf(const CompletionPublicationFact &) {
  return FactDomain::CompletionPublication;
}
constexpr FactDomain domainOf(const USBTransactionFact &) {
  return FactDomain::USBTransaction;
}

inline FactDomain domainOf(const FactRecord &Fact) {
  return std::visit([](const auto &Value) { return domainOf(Value); }, Fact);
}

namespace detail {

inline void appendUnsigned(std::string &Output, std::size_t Value) {
  char Digits[3 * sizeof(std::size_t)];
  char *End = Digits + sizeof(Digits);
  char *Current = End;
  do {
    *--Current = static_cast<char>('0' + Value % 10);
    Value /= 10;
  } while (Value != 0);
  Output.append(Current, End);
}

inline void appendAtom(std::string &Output, std::string_view Name,
                       std::string_view Value) {
  appendUnsigned(Output, Name.size());
  Output.push_back(':');
  Output.append(Name);
  Output.push_back('=');
  appendUnsigned(Output, Value.size());
  Output.push_back(':');
  Output.append(Value);
  Output.push_back(';');
}

inline void appendOrigin(std::string &Output, const FactOrigin &Origin) {
  appendAtom(Output, "model", Origin.Model.value());
  appendAtom(Output, "rule",
             Origin.Rule ? Origin.Rule->value() : std::string_view());
  appendAtom(Output, "producer", Origin.Producer.value());
}

inline std::string beginIdentity(FactDomain Domain, const FactOrigin &Origin) {
  std::string Output = "qemu-fact-v";
  appendUnsigned(Output, CanonicalFormatVersion);
  Output.push_back(';');
  appendAtom(Output, "domain", token(Domain));
  appendOrigin(Output, Origin);
  return Output;
}

} // namespace detail

inline std::string canonicalIdentity(const ProvenanceFact &Fact) {
  std::string Output = detail::beginIdentity(domainOf(Fact), Fact.Origin);
  detail::appendAtom(Output, "value", Fact.Value.value());
  detail::appendAtom(Output, "provenance", token(Fact.Provenance));
  return Output;
}

inline std::string canonicalIdentity(const ExtentFact &Fact) {
  std::string Output = detail::beginIdentity(domainOf(Fact), Fact.Origin);
  detail::appendAtom(Output, "object", Fact.Object.value());
  detail::appendAtom(Output, "extent-kind", token(Fact.Kind));
  detail::appendAtom(Output, "begin", Fact.Begin.value());
  detail::appendAtom(Output, "length", Fact.Length.value());
  return Output;
}

inline std::string canonicalIdentity(const RelationFact &Fact) {
  std::string Output = detail::beginIdentity(domainOf(Fact), Fact.Origin);
  detail::appendAtom(Output, "relation-kind", token(Fact.Kind));
  detail::appendAtom(Output, "result", Fact.Result.value());
  detail::appendAtom(Output, "operand", Fact.Operand.value());
  detail::appendAtom(Output, "parameter",
                     Fact.Parameter ? Fact.Parameter->value()
                                    : std::string_view());
  return Output;
}

inline std::string canonicalIdentity(const LifetimeFact &Fact) {
  std::string Output = detail::beginIdentity(domainOf(Fact), Fact.Origin);
  detail::appendAtom(Output, "resource", Fact.Resource.value());
  detail::appendAtom(Output, "owner", Fact.Owner.value());
  detail::appendAtom(Output, "epoch", Fact.Epoch.value());
  detail::appendAtom(Output, "lifetime-state", token(Fact.State));
  return Output;
}

inline std::string canonicalIdentity(const DirectionFact &Fact) {
  std::string Output = detail::beginIdentity(domainOf(Fact), Fact.Origin);
  detail::appendAtom(Output, "object", Fact.Object.value());
  detail::appendAtom(Output, "direction", token(Fact.Direction));
  return Output;
}

inline std::string canonicalIdentity(const ExecutionContextFact &Fact) {
  std::string Output = detail::beginIdentity(domainOf(Fact), Fact.Origin);
  detail::appendAtom(Output, "operation", Fact.Operation.value());
  detail::appendAtom(Output, "execution-context", token(Fact.Context));
  return Output;
}

inline std::string canonicalIdentity(const ResultStateFact &Fact) {
  std::string Output = detail::beginIdentity(domainOf(Fact), Fact.Origin);
  detail::appendAtom(Output, "result", Fact.Result.value());
  detail::appendAtom(Output, "result-state", token(Fact.State));
  return Output;
}

inline std::string canonicalIdentity(const CompletionPublicationFact &Fact) {
  std::string Output = detail::beginIdentity(domainOf(Fact), Fact.Origin);
  detail::appendAtom(Output, "queue", Fact.Queue.value());
  detail::appendAtom(Output, "attempt", Fact.Attempt.value());
  detail::appendAtom(Output, "slot", Fact.Slot.value());
  detail::appendAtom(Output, "vector", Fact.Vector.value());
  detail::appendAtom(Output, "result", Fact.Result.value());
  detail::appendAtom(Output, "completion-publication-stage", token(Fact.Stage));
  return Output;
}

inline std::string canonicalIdentity(const USBTransactionFact &Fact) {
  std::string Output = detail::beginIdentity(domainOf(Fact), Fact.Origin);
  detail::appendAtom(Output, "packet", Fact.Packet.value());
  detail::appendAtom(Output, "host-buffer", Fact.HostBuffer.value());
  detail::appendAtom(Output, "requested-length", Fact.RequestedLength.value());
  detail::appendAtom(Output, "capacity", Fact.Capacity.value());
  detail::appendAtom(Output, "actual-length", Fact.ActualLength.value());
  detail::appendAtom(Output, "status", Fact.Status.value());
  detail::appendAtom(Output, "endpoint-type", Fact.EndpointType.value());
  detail::appendAtom(Output, "setup-parameter", Fact.SetupParameter.value());
  detail::appendAtom(Output, "usb-direction", token(Fact.Direction));
  detail::appendAtom(Output, "usb-buffer", token(Fact.Buffer));
  return Output;
}

inline std::string canonicalIdentity(const FactRecord &Fact) {
  return std::visit([](const auto &Value) { return canonicalIdentity(Value); },
                    Fact);
}

/// A process- and platform-independent FNV-1a index of canonical identity.
/// Every uint64_t value, including zero, is valid.  Always compare
/// canonicalIdentity() as well because hashes may collide.
inline uint64_t stableHash(std::string_view Identity) {
  uint64_t Hash = UINT64_C(14695981039346656037);
  for (unsigned char Byte : Identity) {
    Hash ^= Byte;
    Hash *= UINT64_C(1099511628211);
  }
  return Hash;
}

inline uint64_t stableHash(const FactRecord &Fact) {
  return stableHash(canonicalIdentity(Fact));
}

inline bool isWellFormed(const FactOrigin &Origin) {
  return isValidPersistentToken(Origin.Model.value()) &&
         (!Origin.Rule || isValidPersistentToken(Origin.Rule->value())) &&
         isValidPersistentToken(Origin.Producer.value());
}

inline bool isWellFormed(const ProvenanceFact &Fact) {
  return isWellFormed(Fact.Origin) &&
         isValidPersistentToken(Fact.Value.value()) &&
         token(Fact.Provenance) != "invalid";
}

inline bool isWellFormed(const ExtentFact &Fact) {
  return isWellFormed(Fact.Origin) &&
         isValidPersistentToken(Fact.Object.value()) &&
         isValidPersistentToken(Fact.Begin.value()) &&
         isValidPersistentToken(Fact.Length.value()) &&
         token(Fact.Kind) != "invalid";
}

inline bool isWellFormed(const RelationFact &Fact) {
  const bool NeedsParameter = Fact.Kind == RelationKind::Product ||
                              Fact.Kind == RelationKind::OffsetPlusLength;
  return isWellFormed(Fact.Origin) &&
         isValidPersistentToken(Fact.Result.value()) &&
         isValidPersistentToken(Fact.Operand.value()) &&
         (!Fact.Parameter || isValidPersistentToken(Fact.Parameter->value())) &&
         Fact.Parameter.has_value() == NeedsParameter &&
         token(Fact.Kind) != "invalid";
}

inline bool isWellFormed(const LifetimeFact &Fact) {
  return isWellFormed(Fact.Origin) &&
         isValidPersistentToken(Fact.Resource.value()) &&
         isValidPersistentToken(Fact.Owner.value()) &&
         isValidPersistentToken(Fact.Epoch.value()) &&
         token(Fact.State) != "invalid";
}

inline bool isWellFormed(const DirectionFact &Fact) {
  return isWellFormed(Fact.Origin) &&
         isValidPersistentToken(Fact.Object.value()) &&
         token(Fact.Direction) != "invalid";
}

inline bool isWellFormed(const ExecutionContextFact &Fact) {
  return isWellFormed(Fact.Origin) &&
         isValidPersistentToken(Fact.Operation.value()) &&
         token(Fact.Context) != "invalid";
}

inline bool isWellFormed(const ResultStateFact &Fact) {
  return isWellFormed(Fact.Origin) &&
         isValidPersistentToken(Fact.Result.value()) &&
         token(Fact.State) != "invalid";
}

inline bool isWellFormed(const CompletionPublicationFact &Fact) {
  return isWellFormed(Fact.Origin) &&
         isValidPersistentToken(Fact.Queue.value()) &&
         isValidPersistentToken(Fact.Attempt.value()) &&
         isValidPersistentToken(Fact.Slot.value()) &&
         isValidPersistentToken(Fact.Vector.value()) &&
         isValidPersistentToken(Fact.Result.value()) &&
         token(Fact.Stage) != "invalid";
}

inline bool isWellFormed(const USBTransactionFact &Fact) {
  return isWellFormed(Fact.Origin) &&
         isValidPersistentToken(Fact.Packet.value()) &&
         isValidPersistentToken(Fact.HostBuffer.value()) &&
         isValidPersistentToken(Fact.RequestedLength.value()) &&
         isValidPersistentToken(Fact.Capacity.value()) &&
         isValidPersistentToken(Fact.ActualLength.value()) &&
         isValidPersistentToken(Fact.Status.value()) &&
         isValidPersistentToken(Fact.EndpointType.value()) &&
         isValidPersistentToken(Fact.SetupParameter.value()) &&
         token(Fact.Direction) != "invalid" && token(Fact.Buffer) != "invalid";
}

inline bool isWellFormed(const FactRecord &Fact) {
  return std::visit([](const auto &Value) { return isWellFormed(Value); },
                    Fact);
}

} // namespace facts
} // namespace qemu
} // namespace ento
} // namespace clang

#endif // LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_QEMUSHAREDFACTS_H
