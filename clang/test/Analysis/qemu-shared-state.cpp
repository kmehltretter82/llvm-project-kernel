// REQUIRES: native
// RUN: %clangxx -std=c++17 -I %src_include_dir -I %S/../../../llvm/include \
// RUN:   -I %resource_dir/../../../../include \
// RUN:   -I %resource_dir/../../../../tools/clang/include \
// RUN:   -fsyntax-only -Xclang -verify %s
// expected-no-diagnostics

#include "../../lib/StaticAnalyzer/Checkers/QEMUSharedState.h"
#include <type_traits>

using namespace clang::ento;
using namespace clang::ento::qemu;

static_assert(
    std::is_same_v<ProgramStateTrait<state::ObjectExtentMap>::lookup_type,
                   const state::ObjectExtent *>);
static_assert(
    std::is_same_v<ProgramStateTrait<state::ValueProvenanceMap>::lookup_type,
                   const state::ValueProvenance *>);
static_assert(
    std::is_same_v<ProgramStateTrait<state::ObjectLifetimeMap>::lookup_type,
                   const state::ObjectLifetime *>);
static_assert(
    std::is_same_v<ProgramStateTrait<state::ObjectDirectionMap>::lookup_type,
                   const state::ObjectDirection *>);
static_assert(
    std::is_same_v<ProgramStateTrait<state::ValueResultStateMap>::lookup_type,
                   const state::ValueResultState *>);
static_assert(
    std::is_same_v<ProgramStateTrait<state::TransferOperationMap>::lookup_type,
                   const state::TransferOperation *>);
static_assert(std::is_same_v<
              ProgramStateTrait<state::CompletionPublicationMap>::lookup_type,
              const state::CompletionPublicationState *>);

ProgramStateRef exercise_shared_state_api(ProgramStateRef State,
                                          const MemRegion *Object,
                                          const MemRegion *Owner, SVal Begin,
                                          SVal Length, SymbolRef Value,
                                          SVal Epoch, SymbolRef Result,
                                          SVal HostBufferBase,
                                          SVal GuestAddress) {
  State = state::setObjectExtent(State, Object, facts::ExtentKind::Requested,
                                 Begin, Length);
  State = state::setValueProvenance(State, Value,
                                    facts::ProvenanceKind::Virtqueue);
  State = state::setObjectLifetime(State, Object, Owner, Epoch,
                                   facts::LifetimeState::Pending);
  State = state::setObjectDirection(
      State, Object, facts::AccessDirection::DescriptorPublication);
  State = state::setValueResultState(State, Result,
                                     facts::ResultStateKind::Rejected);
  State = state::setTransferOperation(
      State, Result, HostBufferBase, Owner, GuestAddress, Begin, Length,
      std::nullopt, facts::AccessDirection::HostWrite);
  State = state::startCompletionPublication(
      State, Owner, GuestAddress, Epoch, Begin, Length, Result,
      facts::CompletionPublicationStage::DescriptorFailed, nullptr);
  State = state::observeCompletionPublicationStage(
      State, Owner, GuestAddress, Epoch, Begin, Length, Result,
      facts::CompletionPublicationStage::RingAdvanced, nullptr);
  State = state::observeCompletionPublicationStage(
      State, Owner, GuestAddress, Epoch, Begin, Length, Result,
      facts::CompletionPublicationStage::InterruptPublished, nullptr);

  (void)state::getObjectExtent(State, Object,
                               facts::ExtentKind::Requested);
  (void)state::getValueProvenance(State, Value);
  (void)state::getObjectLifetime(State, Object);
  (void)state::getObjectDirection(State, Object);
  (void)state::getValueResultState(State, Result);
  (void)state::getTransferOperation(State, Result);
  (void)state::getCompletionPublication(State, Owner, GuestAddress, Epoch,
                                        Begin);
  (void)state::isFailedDMACompletionPublished(
      State, Owner, GuestAddress, Epoch, Begin);

  State = state::removeObjectExtent(State, Object,
                                    facts::ExtentKind::Requested);
  State = state::removeValueProvenance(State, Value);
  State = state::removeObjectLifetime(State, Object);
  State = state::removeObjectDirection(State, Object);
  State = state::removeValueResultState(State, Result);
  State = state::removeTransferOperation(State, Result);
  return state::removeCompletionPublication(State, Owner, GuestAddress, Epoch,
                                            Begin);
}
