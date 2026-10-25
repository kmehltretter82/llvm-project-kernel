//===- unittests/StaticAnalyzer/QEMUSharedFactsTest.cpp -------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "../../lib/StaticAnalyzer/Checkers/QEMUSharedFacts.h"
#include "gtest/gtest.h"
#include <array>
#include <iterator>
#include <string>
#include <type_traits>
#include <utility>

using namespace clang::ento::qemu::facts;

namespace {

constexpr FactOrigin Origin{ModelIDRef("qemu-v3-direct-dma-v1"),
                            RuleIDRef("qemu.dma.short-map-access"),
                            EntityIDRef("usr:map-buffer@source-hash")};
constexpr FactOrigin PublicationOrigin{
    ModelIDRef("qemu-v3-completion-publication-v1"),
    RuleIDRef("qemu.failed-completion-publication"),
    EntityIDRef("usr:xhci-event-publish@source-hash")};
constexpr FactOrigin USBOrigin{ModelIDRef("qemu-v3-usb-transaction-v1"),
                               std::nullopt,
                               EntityIDRef("usr:usb-packet-copy@source-hash")};

static_assert(!std::is_convertible_v<ModelIDRef, RuleIDRef>);
static_assert(!std::is_constructible_v<ModelIDRef, std::string &&>);
static_assert(token(FactDomain::ExecutionContext) == "execution-context");
static_assert(token(ProvenanceKind::Virtqueue) == "virtqueue");
static_assert(token(ExtentKind::InitializedBytes) == "initialized-bytes");
static_assert(token(ExtentKind::Requested) == "requested");
static_assert(token(ExtentKind::ActualTransfer) == "actual-transfer");
static_assert(token(RelationKind::OffsetPlusLength) == "offset-plus-length");
static_assert(token(LifetimeState::Reinitialized) == "reinitialized");
static_assert(token(AccessDirection::DescriptorPublication) ==
              "descriptor-publication");
static_assert(token(ExecutionContextKind::VCPUThread) == "vcpu-thread");
static_assert(token(ResultStateKind::UncheckedError) == "unchecked-error");
static_assert(token(FactDomain::CompletionPublication) ==
              "completion-publication");
static_assert(token(FactDomain::USBTransaction) == "usb-transaction");
static_assert(token(CompletionPublicationStage::DescriptorFailed) ==
              "descriptor-failed");
static_assert(token(USBPacketDirection::DeviceToHost) == "device-to-host");
static_assert(token(USBPacketBufferKind::Combined) == "combined-iovec");

TEST(QEMUSharedFacts, StableIdentifiersAreTypedAndPortable) {
  EXPECT_TRUE(isValidPersistentToken("qemu.dma.address-space.map"));
  EXPECT_TRUE(isValidPersistentToken("usr:c:@F@map"));
  EXPECT_FALSE(isValidPersistentToken(""));
  EXPECT_FALSE(isValidPersistentToken("contains whitespace"));
  EXPECT_FALSE(isValidPersistentToken(std::string_view("bad\x01", 4)));
  EXPECT_FALSE(isValidPersistentToken(std::string_view("bad\x80", 4)));
  EXPECT_TRUE(isValidPersistentToken("punctuation:=;is-safe"));

  EXPECT_EQ(ModelIDRef("model.v1"), ModelIDRef("model.v1"));
  EXPECT_LT(ModelIDRef("model.v1"), ModelIDRef("model.v2"));
}

TEST(QEMUSharedFacts, EveryVocabularyTokenIsStable) {
  constexpr std::array DomainTokens{
      std::pair{FactDomain::Provenance, "provenance"},
      std::pair{FactDomain::Extent, "extent"},
      std::pair{FactDomain::Relation, "relation"},
      std::pair{FactDomain::Lifetime, "lifetime"},
      std::pair{FactDomain::Direction, "direction"},
      std::pair{FactDomain::ExecutionContext, "execution-context"},
      std::pair{FactDomain::ResultState, "result-state"},
      std::pair{FactDomain::CompletionPublication, "completion-publication"},
      std::pair{FactDomain::USBTransaction, "usb-transaction"},
  };
  constexpr std::array ProvenanceTokens{
      std::pair{ProvenanceKind::MMIO, "mmio"},
      std::pair{ProvenanceKind::PIO, "pio"},
      std::pair{ProvenanceKind::DMA, "dma"},
      std::pair{ProvenanceKind::Virtqueue, "virtqueue"},
      std::pair{ProvenanceKind::USB, "usb"},
      std::pair{ProvenanceKind::Packet, "packet"},
      std::pair{ProvenanceKind::BlockBackend, "block-backend"},
      std::pair{ProvenanceKind::Migration, "migration"},
      std::pair{ProvenanceKind::ImageParser, "image-parser"},
      std::pair{ProvenanceKind::HostConfiguration, "host-configuration"},
      std::pair{ProvenanceKind::TrustedHostData, "trusted-host-data"},
  };
  constexpr std::array ExtentTokens{
      std::pair{ExtentKind::Allocation, "allocation"},
      std::pair{ExtentKind::Mapped, "mapped"},
      std::pair{ExtentKind::LogicalPayload, "logical-payload"},
      std::pair{ExtentKind::InitializedBytes, "initialized-bytes"},
      std::pair{ExtentKind::ElementCount, "element-count"},
      std::pair{ExtentKind::Requested, "requested"},
      std::pair{ExtentKind::ActualTransfer, "actual-transfer"},
  };
  constexpr std::array RelationTokens{
      std::pair{RelationKind::Equality, "equality"},
      std::pair{RelationKind::UpperBound, "upper-bound"},
      std::pair{RelationKind::LowerBound, "lower-bound"},
      std::pair{RelationKind::Product, "product"},
      std::pair{RelationKind::OffsetPlusLength, "offset-plus-length"},
      std::pair{RelationKind::Alignment, "alignment"},
      std::pair{RelationKind::SignednessConversion, "signedness-conversion"},
      std::pair{RelationKind::WrapCondition, "wrap-condition"},
  };
  constexpr std::array LifetimeTokens{
      std::pair{LifetimeState::Live, "live"},
      std::pair{LifetimeState::Pending, "pending"},
      std::pair{LifetimeState::Cancelled, "cancelled"},
      std::pair{LifetimeState::Unmapped, "unmapped"},
      std::pair{LifetimeState::Released, "released"},
      std::pair{LifetimeState::Reinitialized, "reinitialized"},
  };
  constexpr std::array DirectionTokens{
      std::pair{AccessDirection::HostRead, "host-read"},
      std::pair{AccessDirection::HostWrite, "host-write"},
      std::pair{AccessDirection::GuestVisibleCopy, "guest-visible-copy"},
      std::pair{AccessDirection::DescriptorPublication,
                "descriptor-publication"},
      std::pair{AccessDirection::IndirectDispatch, "indirect-dispatch"},
  };
  constexpr std::array ContextTokens{
      std::pair{ExecutionContextKind::BQL, "bql"},
      std::pair{ExecutionContextKind::RCU, "rcu"},
      std::pair{ExecutionContextKind::AioContext, "aio-context"},
      std::pair{ExecutionContextKind::Coroutine, "coroutine"},
      std::pair{ExecutionContextKind::BottomHalf, "bottom-half"},
      std::pair{ExecutionContextKind::Timer, "timer"},
      std::pair{ExecutionContextKind::Worker, "worker"},
      std::pair{ExecutionContextKind::VCPUThread, "vcpu-thread"},
  };
  constexpr std::array ResultTokens{
      std::pair{ResultStateKind::Complete, "complete"},
      std::pair{ResultStateKind::Partial, "partial"},
      std::pair{ResultStateKind::Retry, "retry"},
      std::pair{ResultStateKind::Rejected, "rejected"},
      std::pair{ResultStateKind::UncheckedError, "unchecked-error"},
  };
  constexpr std::array CompletionPublicationTokens{
      std::pair{CompletionPublicationStage::DescriptorPending,
                "descriptor-pending"},
      std::pair{CompletionPublicationStage::DescriptorComplete,
                "descriptor-complete"},
      std::pair{CompletionPublicationStage::DescriptorFailed,
                "descriptor-failed"},
      std::pair{CompletionPublicationStage::RingAdvanced, "ring-advanced"},
      std::pair{CompletionPublicationStage::InterruptPublished,
                "interrupt-published"},
  };
  constexpr std::array USBPacketDirectionTokens{
      std::pair{USBPacketDirection::DeviceToHost, "device-to-host"},
      std::pair{USBPacketDirection::HostToDevice, "host-to-device"},
      std::pair{USBPacketDirection::Setup, "setup"},
  };
  constexpr std::array USBPacketBufferTokens{
      std::pair{USBPacketBufferKind::Direct, "direct-iovec"},
      std::pair{USBPacketBufferKind::Combined, "combined-iovec"},
  };

  const auto Check = [](const auto &Entries) {
    for (const auto &[Value, Expected] : Entries)
      EXPECT_EQ(token(Value), Expected);
  };
  Check(DomainTokens);
  Check(ProvenanceTokens);
  Check(ExtentTokens);
  Check(RelationTokens);
  Check(LifetimeTokens);
  Check(DirectionTokens);
  Check(ContextTokens);
  Check(ResultTokens);
  Check(CompletionPublicationTokens);
  Check(USBPacketDirectionTokens);
  Check(USBPacketBufferTokens);

  EXPECT_EQ(token(static_cast<FactDomain>(255)), "invalid");
  EXPECT_EQ(token(static_cast<ProvenanceKind>(255)), "invalid");
  EXPECT_EQ(token(static_cast<ExtentKind>(255)), "invalid");
  EXPECT_EQ(token(static_cast<RelationKind>(255)), "invalid");
  EXPECT_EQ(token(static_cast<LifetimeState>(255)), "invalid");
  EXPECT_EQ(token(static_cast<AccessDirection>(255)), "invalid");
  EXPECT_EQ(token(static_cast<ExecutionContextKind>(255)), "invalid");
  EXPECT_EQ(token(static_cast<ResultStateKind>(255)), "invalid");
  EXPECT_EQ(token(static_cast<CompletionPublicationStage>(255)), "invalid");
  EXPECT_EQ(token(static_cast<USBPacketDirection>(255)), "invalid");
  EXPECT_EQ(token(static_cast<USBPacketBufferKind>(255)), "invalid");
}

TEST(QEMUSharedFacts, EveryDomainHasOneTypedRecord) {
  ProvenanceFact Provenance{Origin, ValueIDRef("value:guest-length"),
                            ProvenanceKind::DMA};
  ExtentFact Extent{Origin, ObjectIDRef("object:mapped-buffer"),
                    ExtentKind::Mapped, ValueIDRef("const:0"),
                    ValueIDRef("value:mapped-length")};
  RelationFact Relation{
      Origin, RelationKind::OffsetPlusLength, ValueIDRef("value:access-end"),
      ValueIDRef("value:offset"), ValueIDRef("value:access-length")};
  LifetimeFact Lifetime{Origin, ObjectIDRef("object:mapped-buffer"),
                        ObjectIDRef("object:address-space"),
                        ValueIDRef("epoch:map-7"), LifetimeState::Live};
  DirectionFact Direction{Origin, ObjectIDRef("object:mapped-buffer"),
                          AccessDirection::HostRead};
  ExecutionContextFact Context{Origin, EntityIDRef("operation:dma-read"),
                               ExecutionContextKind::VCPUThread};
  ResultStateFact Result{Origin, ValueIDRef("value:memtx-result"),
                         ResultStateKind::Complete};
  CompletionPublicationFact Publication{
      PublicationOrigin,
      ObjectIDRef("object:completion-ring"),
      ValueIDRef("attempt:transfer-17"),
      ValueIDRef("value:enqueue-index"),
      ValueIDRef("value:interrupter"),
      ValueIDRef("value:memtx-result"),
      CompletionPublicationStage::DescriptorFailed};
  USBTransactionFact USB{USBOrigin,
                         ObjectIDRef("object:usb-packet"),
                         ObjectIDRef("object:host-buffer"),
                         ValueIDRef("value:copy-length"),
                         ValueIDRef("value:iov-capacity"),
                         ValueIDRef("value:actual-length"),
                         ValueIDRef("value:status"),
                         ValueIDRef("value:endpoint-type"),
                         ValueIDRef("value:setup-parameter"),
                         USBPacketDirection::DeviceToHost,
                         USBPacketBufferKind::Combined};

  const FactRecord Facts[] = {Provenance, Extent,      Relation,
                              Lifetime,   Direction,   Context,
                              Result,     Publication, USB};
  const FactDomain Domains[] = {
      FactDomain::Provenance,     FactDomain::Extent,
      FactDomain::Relation,       FactDomain::Lifetime,
      FactDomain::Direction,      FactDomain::ExecutionContext,
      FactDomain::ResultState,    FactDomain::CompletionPublication,
      FactDomain::USBTransaction,
  };

  for (unsigned Index = 0; Index != std::size(Facts); ++Index) {
    EXPECT_TRUE(isWellFormed(Facts[Index]));
    EXPECT_EQ(domainOf(Facts[Index]), Domains[Index]);
  }
}

TEST(QEMUSharedFacts, CompletionPublicationIdentityIsStable) {
  const FactRecord Fact =
      CompletionPublicationFact{PublicationOrigin,
                                ObjectIDRef("object:completion-ring"),
                                ValueIDRef("attempt:transfer-17"),
                                ValueIDRef("value:enqueue-index"),
                                ValueIDRef("value:interrupter"),
                                ValueIDRef("value:memtx-result"),
                                CompletionPublicationStage::DescriptorFailed};
  const std::string Expected =
      "qemu-fact-v1;6:domain=22:completion-publication;"
      "5:model=33:qemu-v3-completion-publication-v1;"
      "4:rule=34:qemu.failed-completion-publication;"
      "8:producer=34:usr:xhci-event-publish@source-hash;"
      "5:queue=22:object:completion-ring;"
      "7:attempt=19:attempt:transfer-17;4:slot=19:value:enqueue-index;"
      "6:vector=17:value:interrupter;6:result=18:value:memtx-result;"
      "28:completion-publication-stage=17:descriptor-failed;";

  EXPECT_EQ(canonicalIdentity(Fact), Expected);
  EXPECT_EQ(stableHash(Fact), UINT64_C(7541502825403125106));
}

TEST(QEMUSharedFacts, USBTransactionIdentityIsStable) {
  const FactRecord Fact =
      USBTransactionFact{USBOrigin,
                         ObjectIDRef("object:usb-packet"),
                         ObjectIDRef("object:host-buffer"),
                         ValueIDRef("value:copy-length"),
                         ValueIDRef("value:iov-capacity"),
                         ValueIDRef("value:actual-length"),
                         ValueIDRef("value:status"),
                         ValueIDRef("value:endpoint-type"),
                         ValueIDRef("value:setup-parameter"),
                         USBPacketDirection::DeviceToHost,
                         USBPacketBufferKind::Combined};
  const std::string Expected = "qemu-fact-v1;6:domain=15:usb-transaction;"
                               "5:model=26:qemu-v3-usb-transaction-v1;"
                               "4:rule=0:;"
                               "8:producer=31:usr:usb-packet-copy@source-hash;"
                               "6:packet=17:object:usb-packet;"
                               "11:host-buffer=18:object:host-buffer;"
                               "16:requested-length=17:value:copy-length;"
                               "8:capacity=18:value:iov-capacity;"
                               "13:actual-length=19:value:actual-length;"
                               "6:status=12:value:status;"
                               "13:endpoint-type=19:value:endpoint-type;"
                               "15:setup-parameter=21:value:setup-parameter;"
                               "13:usb-direction=14:device-to-host;"
                               "10:usb-buffer=14:combined-iovec;";

  EXPECT_EQ(canonicalIdentity(Fact), Expected);
  EXPECT_EQ(stableHash(Fact), UINT64_C(14271385910668362570));
}

TEST(QEMUSharedFacts, CanonicalIdentityIsOrderedAndUnambiguous) {
  const ExtentFact Extent{Origin, ObjectIDRef("object:mapped-buffer"),
                          ExtentKind::Mapped, ValueIDRef("const:0"),
                          ValueIDRef("value:mapped-length")};
  const FactRecord Fact = Extent;
  const std::string Identity = canonicalIdentity(Fact);

  EXPECT_EQ(
      Identity,
      "qemu-fact-v1;6:domain=6:extent;5:model=21:qemu-v3-direct-dma-v1;"
      "4:rule=25:qemu.dma.short-map-access;8:producer=26:usr:map-buffer@"
      "source-hash;6:object=20:object:mapped-buffer;11:extent-kind=6:mapped;"
      "5:begin=7:const:0;6:length=19:value:mapped-length;");
  EXPECT_EQ(Identity, canonicalIdentity(Fact));
  EXPECT_EQ(stableHash(Fact), stableHash(Identity));

  const ProvenanceFact Left{Origin, ValueIDRef("ab"), ProvenanceKind::DMA};
  const ProvenanceFact Right{Origin, ValueIDRef("a"), ProvenanceKind::PIO};
  EXPECT_NE(canonicalIdentity(Left), canonicalIdentity(Right));
  EXPECT_EQ(stableHash(FactRecord(Left)), stableHash(canonicalIdentity(Left)));
  EXPECT_EQ(stableHash(FactRecord(Right)),
            stableHash(canonicalIdentity(Right)));

  const ProvenanceFact Delimiters{Origin,
                                  ValueIDRef("value:with;canonical=delimiters"),
                                  ProvenanceKind::DMA};
  EXPECT_NE(canonicalIdentity(Left), canonicalIdentity(Delimiters));
}

TEST(QEMUSharedFacts, TransferExtentIdentityIsStable) {
  constexpr FactOrigin TransferOrigin{ModelIDRef("qemu-v3-test-v1"),
                                      std::nullopt, EntityIDRef("usr:test")};
  const FactRecord Fact = ExtentFact{
      TransferOrigin, ObjectIDRef("object:buffer"), ExtentKind::ActualTransfer,
      ValueIDRef("const:0"), ValueIDRef("value:actual")};
  const std::string Expected =
      "qemu-fact-v1;6:domain=6:extent;5:model=15:qemu-v3-test-v1;"
      "4:rule=0:;8:producer=8:usr:test;6:object=13:object:buffer;"
      "11:extent-kind=15:actual-transfer;5:begin=7:const:0;"
      "6:length=12:value:actual;";

  EXPECT_EQ(canonicalIdentity(Fact), Expected);
  EXPECT_EQ(stableHash(Fact), UINT64_C(4781920679314429851));
}

TEST(QEMUSharedFacts, InvalidAndIncompleteRecordsAreRejected) {
  const FactOrigin NoModel{ModelIDRef(), std::nullopt, EntityIDRef("producer")};
  EXPECT_FALSE(isWellFormed(NoModel));

  const RelationFact MissingOperand{Origin, RelationKind::Product,
                                    ValueIDRef("value:bytes"),
                                    ValueIDRef("value:count"), std::nullopt};
  EXPECT_FALSE(isWellFormed(MissingOperand));

  const RelationFact UnexpectedOperand{
      Origin, RelationKind::Equality, ValueIDRef("value:left"),
      ValueIDRef("value:right"), ValueIDRef("value:unexpected")};
  EXPECT_FALSE(isWellFormed(UnexpectedOperand));

  const RelationFact AlignmentWithUnexpectedParameter{
      Origin, RelationKind::Alignment, ValueIDRef("value:address"),
      ValueIDRef("const:16"), ValueIDRef("value:unexpected")};
  EXPECT_FALSE(isWellFormed(AlignmentWithUnexpectedParameter));

  const ResultStateFact InvalidEnum{Origin, ValueIDRef("value:result"),
                                    static_cast<ResultStateKind>(255)};
  EXPECT_FALSE(isWellFormed(InvalidEnum));

  const CompletionPublicationFact MissingQueue{
      PublicationOrigin,
      ObjectIDRef(),
      ValueIDRef("attempt:1"),
      ValueIDRef("value:slot"),
      ValueIDRef("value:vector"),
      ValueIDRef("value:result"),
      CompletionPublicationStage::DescriptorFailed};
  EXPECT_FALSE(isWellFormed(MissingQueue));

  const CompletionPublicationFact InvalidStage{
      PublicationOrigin,
      ObjectIDRef("object:queue"),
      ValueIDRef("attempt:1"),
      ValueIDRef("value:slot"),
      ValueIDRef("value:vector"),
      ValueIDRef("value:result"),
      static_cast<CompletionPublicationStage>(255)};
  EXPECT_FALSE(isWellFormed(InvalidStage));

  const CompletionPublicationFact MissingJoinIdentity{
      PublicationOrigin,
      ObjectIDRef("object:queue"),
      ValueIDRef(),
      ValueIDRef("value:slot"),
      ValueIDRef("value:vector"),
      ValueIDRef(),
      CompletionPublicationStage::DescriptorFailed};
  EXPECT_FALSE(isWellFormed(MissingJoinIdentity));

  const USBTransactionFact InvalidUSBTransaction{
      USBOrigin,
      ObjectIDRef("object:usb-packet"),
      ObjectIDRef(),
      ValueIDRef("value:copy-length"),
      ValueIDRef("value:iov-capacity"),
      ValueIDRef("value:actual-length"),
      ValueIDRef("value:status"),
      ValueIDRef("value:endpoint-type"),
      ValueIDRef("value:setup-parameter"),
      static_cast<USBPacketDirection>(255),
      static_cast<USBPacketBufferKind>(255)};
  EXPECT_FALSE(isWellFormed(InvalidUSBTransaction));
}

} // namespace
