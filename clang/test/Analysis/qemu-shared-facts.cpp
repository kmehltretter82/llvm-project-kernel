// REQUIRES: native
// RUN: %clangxx -std=c++17 -fsyntax-only -Xclang -verify %s
// RUN: %clangxx -std=c++17 %s -o %t && %t
// expected-no-diagnostics

#include "../../lib/StaticAnalyzer/Checkers/QEMUSharedFacts.h"
#include <string>
#include <type_traits>

using namespace clang::ento::qemu::facts;

static_assert(!std::is_same_v<ModelIDRef, RuleIDRef>);
static_assert(!std::is_constructible_v<ModelIDRef, std::string &&>);
static_assert(CanonicalFormatVersion == 1);
static_assert(token(ProvenanceKind::MMIO) == "mmio");
static_assert(token(ExtentKind::Allocation) == "allocation");
static_assert(token(ExtentKind::Requested) == "requested");
static_assert(token(ExtentKind::ActualTransfer) == "actual-transfer");
static_assert(token(RelationKind::WrapCondition) == "wrap-condition");
static_assert(token(LifetimeState::Cancelled) == "cancelled");
static_assert(token(AccessDirection::GuestVisibleCopy) ==
              "guest-visible-copy");
static_assert(token(ExecutionContextKind::AioContext) == "aio-context");
static_assert(token(ResultStateKind::Retry) == "retry");
static_assert(token(FactDomain::CompletionPublication) ==
              "completion-publication");
static_assert(token(CompletionPublicationStage::InterruptPublished) ==
              "interrupt-published");

bool instantiate_all_fact_domains() {
  const FactOrigin Origin{ModelIDRef("qemu-v3-test-v1"), std::nullopt,
                          EntityIDRef("usr:test")};
  const FactRecord Facts[] = {
      ProvenanceFact{Origin, ValueIDRef("value:length"), ProvenanceKind::MMIO},
      ExtentFact{Origin, ObjectIDRef("object:buffer"), ExtentKind::Allocation,
                 ValueIDRef("const:0"), ValueIDRef("value:allocation-size")},
      RelationFact{Origin, RelationKind::Equality, ValueIDRef("value:actual"),
                   ValueIDRef("value:requested"), std::nullopt},
      LifetimeFact{Origin, ObjectIDRef("object:resource"),
                   ObjectIDRef("object:owner"), ValueIDRef("epoch:1"),
                   LifetimeState::Live},
      DirectionFact{Origin, ObjectIDRef("object:buffer"),
                    AccessDirection::HostWrite},
      ExecutionContextFact{Origin, EntityIDRef("operation:callback"),
                           ExecutionContextKind::BottomHalf},
      ResultStateFact{Origin, ValueIDRef("value:result"),
                      ResultStateKind::Partial},
      CompletionPublicationFact{
          FactOrigin{ModelIDRef("qemu-v3-completion-publication-v1"),
                     RuleIDRef("qemu.failed-completion-publication"),
                     EntityIDRef("usr:xhci-event-publish@source-hash")},
          ObjectIDRef("object:completion-ring"),
          ValueIDRef("attempt:transfer-17"),
          ValueIDRef("value:enqueue-index"), ValueIDRef("value:interrupter"),
          ValueIDRef("value:memtx-result"),
          CompletionPublicationStage::DescriptorFailed},
  };

  for (const FactRecord &Fact : Facts)
    if (!isWellFormed(Fact) || canonicalIdentity(Fact).empty() ||
        stableHash(Fact) != stableHash(canonicalIdentity(Fact)))
      return false;

  const FactRecord IdentityProbe = ProvenanceFact{
      FactOrigin{ModelIDRef("m"), std::nullopt, EntityIDRef("p")},
      ValueIDRef("v"), ProvenanceKind::DMA};
  const std::string ExpectedIdentity =
      "qemu-fact-v1;6:domain=10:provenance;5:model=1:m;4:rule=0:;"
      "8:producer=1:p;5:value=1:v;10:provenance=3:dma;";
  if (canonicalIdentity(IdentityProbe) != ExpectedIdentity ||
      stableHash(IdentityProbe) != UINT64_C(3190151180515417878))
    return false;

  const FactRecord TransferProbe = ExtentFact{
      Origin, ObjectIDRef("object:buffer"), ExtentKind::ActualTransfer,
      ValueIDRef("const:0"), ValueIDRef("value:actual")};
  const std::string ExpectedTransferIdentity =
      "qemu-fact-v1;6:domain=6:extent;5:model=15:qemu-v3-test-v1;"
      "4:rule=0:;8:producer=8:usr:test;6:object=13:object:buffer;"
      "11:extent-kind=15:actual-transfer;5:begin=7:const:0;"
      "6:length=12:value:actual;";
  if (canonicalIdentity(TransferProbe) != ExpectedTransferIdentity ||
      stableHash(TransferProbe) != UINT64_C(4781920679314429851))
    return false;

  const FactRecord PublicationProbe = CompletionPublicationFact{
          FactOrigin{ModelIDRef("qemu-v3-completion-publication-v1"),
                     RuleIDRef("qemu.failed-completion-publication"),
                 EntityIDRef("usr:xhci-event-publish@source-hash")},
      ObjectIDRef("object:completion-ring"),
      ValueIDRef("attempt:transfer-17"), ValueIDRef("value:enqueue-index"),
      ValueIDRef("value:interrupter"), ValueIDRef("value:memtx-result"),
      CompletionPublicationStage::DescriptorFailed};
  const std::string ExpectedPublicationIdentity =
      "qemu-fact-v1;6:domain=22:completion-publication;"
      "5:model=33:qemu-v3-completion-publication-v1;"
      "4:rule=34:qemu.failed-completion-publication;"
      "8:producer=34:usr:xhci-event-publish@source-hash;"
      "5:queue=22:object:completion-ring;"
      "7:attempt=19:attempt:transfer-17;4:slot=19:value:enqueue-index;"
      "6:vector=17:value:interrupter;6:result=18:value:memtx-result;"
      "28:completion-publication-stage=17:descriptor-failed;";
  if (canonicalIdentity(PublicationProbe) != ExpectedPublicationIdentity ||
      stableHash(PublicationProbe) != UINT64_C(7541502825403125106))
    return false;
  return true;
}

int main() { return instantiate_all_fact_domains() ? 0 : 1; }
