//===- QEMUSharedStateProducer.cpp ---------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "QEMUSharedStateTestSupport.h"

namespace clang {
namespace ento {
namespace qemu {
namespace test {

SharedStateTraitIndices producerTraitIndices() {
  return {
      ProgramStateTrait<state::ObjectExtentMap>::GDMIndex(),
      ProgramStateTrait<state::ValueProvenanceMap>::GDMIndex(),
      ProgramStateTrait<state::ObjectLifetimeMap>::GDMIndex(),
      ProgramStateTrait<state::ObjectDirectionMap>::GDMIndex(),
      ProgramStateTrait<state::ValueResultStateMap>::GDMIndex(),
      ProgramStateTrait<state::TransferOperationMap>::GDMIndex(),
      ProgramStateTrait<state::USBTransactionMap>::GDMIndex(),
      ProgramStateTrait<state::CompletionPublicationMap>::GDMIndex(),
  };
}

ProgramStateRef produceSharedFacts(ProgramStateRef State,
                                   const MemRegion *Object,
                                   const MemRegion *Owner, SVal Begin,
                                   SVal Requested, SVal Actual, SymbolRef Value,
                                   SVal Epoch, SymbolRef Result,
                                   SymbolRef FailedResult, SVal HostBufferBase,
                                   SVal GuestAddress) {
  State = state::setObjectExtent(State, Object, facts::ExtentKind::Requested,
                                 Begin, Requested);
  State = state::setObjectExtent(
      State, Object, facts::ExtentKind::ActualTransfer, Begin, Actual);
  State = state::setValueProvenance(State, Value, facts::ProvenanceKind::DMA);
  State = state::setObjectLifetime(State, Object, Owner, Epoch,
                                   facts::LifetimeState::Live);
  State = state::setObjectDirection(State, Object,
                                    facts::AccessDirection::HostRead);
  State = state::setValueResultState(State, Result,
                                     facts::ResultStateKind::Complete);
  State = state::setValueResultState(State, FailedResult,
                                     facts::ResultStateKind::Rejected);
  State = state::setTransferOperation(State, Result, HostBufferBase, Owner,
                                      GuestAddress, Begin, Requested, Actual,
                                      facts::AccessDirection::HostRead);
  State = state::setTransferOperation(
      State, FailedResult, HostBufferBase, nullptr, GuestAddress, Begin,
      Requested, std::nullopt, facts::AccessDirection::HostRead);
  State = state::setUSBTransaction(
      State, Object, HostBufferBase, Requested, Actual, Begin, Epoch,
      GuestAddress, Requested, facts::USBPacketDirection::DeviceToHost,
      facts::USBPacketBufferKind::Direct, nullptr);
  State = state::startCompletionPublication(
      State, Owner, GuestAddress, Epoch, Begin, Requested, FailedResult,
      facts::CompletionPublicationStage::DescriptorFailed, nullptr);
  State = state::observeCompletionPublicationStage(
      State, Owner, GuestAddress, Epoch, Begin, Requested, FailedResult,
      facts::CompletionPublicationStage::RingAdvanced, nullptr);
  return state::observeCompletionPublicationStage(
      State, Owner, GuestAddress, Epoch, Begin, Requested, FailedResult,
      facts::CompletionPublicationStage::InterruptPublished, nullptr);
}

} // namespace test
} // namespace qemu
} // namespace ento
} // namespace clang
