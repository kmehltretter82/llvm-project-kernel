//===- QEMUSharedStateTest.cpp -------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "QEMUSharedStateTestSupport.h"
#include "Reusables.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "clang/Tooling/Tooling.h"
#include "gtest/gtest.h"
#include <iterator>

using namespace clang;
using namespace ento;
using namespace qemu;

namespace {

class SharedStateConsumer : public ExprEngineConsumer {
  bool Checked = false;

  void checkFunction(const FunctionDecl *Function) {
    ASSERT_GE(Function->getNumParams(), 4u);
    const StackFrame *Frame =
        Eng.getAnalysisDeclContextManager().getTopStackFrame(Function);
    ProgramStateRef Initial = Eng.getInitialState(Frame);
    const MemRegion *Object =
        Initial->getRegion(Function->getParamDecl(0), Frame);
    const MemRegion *Owner =
        Initial->getRegion(Function->getParamDecl(1), Frame);
    const MemRegion *SuccessResultObject =
        Initial->getRegion(Function->getParamDecl(2), Frame);
    const MemRegion *FailedResultObject =
        Initial->getRegion(Function->getParamDecl(3), Frame);

    SValBuilder &Builder = Eng.getSValBuilder();
    QualType SizeType = C.getASTContext().UnsignedLongLongTy;
    const SVal Begin = Builder.makeIntVal(0, SizeType);
    const SVal Requested = Builder.makeIntVal(64, SizeType);
    const SVal Actual = Builder.makeIntVal(32, SizeType);
    const SVal Replacement = Builder.makeIntVal(16, SizeType);
    const SVal Epoch = Builder.makeIntVal(1, SizeType);
    const SVal NewEpoch = Builder.makeIntVal(2, SizeType);
    const SVal GuestAddress = Builder.makeIntVal(0x1000, SizeType);
    const SVal HostBufferBase =
        Builder.getRegionValueSymbolVal(cast<TypedValueRegion>(Object));
    const SymbolRef Value = HostBufferBase.getAsSymbol();
    const SymbolRef Result =
        Builder
            .getRegionValueSymbolVal(
                cast<TypedValueRegion>(SuccessResultObject))
            .getAsSymbol();
    const SymbolRef FailedResult =
        Builder
            .getRegionValueSymbolVal(cast<TypedValueRegion>(FailedResultObject))
            .getAsSymbol();
    ASSERT_NE(Value, nullptr);
    ASSERT_NE(Result, nullptr);
    ASSERT_NE(FailedResult, nullptr);

    const qemu::test::SharedStateTraitIndices ProducerIndices =
        qemu::test::producerTraitIndices();
    EXPECT_EQ(ProducerIndices.Extent,
              ProgramStateTrait<state::ObjectExtentMap>::GDMIndex());
    EXPECT_EQ(ProducerIndices.Provenance,
              ProgramStateTrait<state::ValueProvenanceMap>::GDMIndex());
    EXPECT_EQ(ProducerIndices.Lifetime,
              ProgramStateTrait<state::ObjectLifetimeMap>::GDMIndex());
    EXPECT_EQ(ProducerIndices.Direction,
              ProgramStateTrait<state::ObjectDirectionMap>::GDMIndex());
    EXPECT_EQ(ProducerIndices.Result,
              ProgramStateTrait<state::ValueResultStateMap>::GDMIndex());
    EXPECT_EQ(ProducerIndices.TransferOperation,
              ProgramStateTrait<state::TransferOperationMap>::GDMIndex());
    EXPECT_EQ(ProducerIndices.USBTransaction,
              ProgramStateTrait<state::USBTransactionMap>::GDMIndex());
    EXPECT_EQ(ProducerIndices.CompletionPublication,
              ProgramStateTrait<state::CompletionPublicationMap>::GDMIndex());

    // Each named trait has a distinct program-wide GDM key, including the
    // eighth key returned from the producer translation unit.
    void *Indices[] = {
        ProducerIndices.Extent,         ProducerIndices.Provenance,
        ProducerIndices.Lifetime,       ProducerIndices.Direction,
        ProducerIndices.Result,         ProducerIndices.TransferOperation,
        ProducerIndices.USBTransaction, ProducerIndices.CompletionPublication};
    for (unsigned I = 0; I != std::size(Indices); ++I)
      for (unsigned J = I + 1; J != std::size(Indices); ++J)
        EXPECT_NE(Indices[I], Indices[J]);

    ProgramStateRef Produced = qemu::test::produceSharedFacts(
        Initial, Object, Owner, Begin, Requested, Actual, Value, Epoch, Result,
        FailedResult, HostBufferBase, GuestAddress);

    const state::ObjectExtent *RequestedFact =
        state::getObjectExtent(Produced, Object, facts::ExtentKind::Requested);
    ASSERT_NE(RequestedFact, nullptr);
    EXPECT_EQ(RequestedFact->getBegin(), Begin);
    EXPECT_EQ(RequestedFact->getLength(), Requested);

    const state::ObjectExtent *ActualFact = state::getObjectExtent(
        Produced, Object, facts::ExtentKind::ActualTransfer);
    ASSERT_NE(ActualFact, nullptr);
    EXPECT_EQ(ActualFact->getLength(), Actual);
    EXPECT_EQ(
        state::getObjectExtent(Produced, Object, facts::ExtentKind::Allocation),
        nullptr);

    const state::ValueProvenance *Provenance =
        state::getValueProvenance(Produced, Value);
    ASSERT_NE(Provenance, nullptr);
    EXPECT_EQ(Provenance->getKind(), facts::ProvenanceKind::DMA);

    const state::ObjectLifetime *Lifetime =
        state::getObjectLifetime(Produced, Object);
    ASSERT_NE(Lifetime, nullptr);
    EXPECT_EQ(Lifetime->getOwner(), Owner);
    EXPECT_EQ(Lifetime->getEpoch(), Epoch);
    EXPECT_EQ(Lifetime->getState(), facts::LifetimeState::Live);

    const state::ObjectDirection *Direction =
        state::getObjectDirection(Produced, Object);
    ASSERT_NE(Direction, nullptr);
    EXPECT_EQ(Direction->getDirection(), facts::AccessDirection::HostRead);

    const state::ValueResultState *ResultState =
        state::getValueResultState(Produced, Result);
    ASSERT_NE(ResultState, nullptr);
    EXPECT_EQ(ResultState->getState(), facts::ResultStateKind::Complete);
    const state::ValueResultState *FailedResultState =
        state::getValueResultState(Produced, FailedResult);
    ASSERT_NE(FailedResultState, nullptr);
    EXPECT_EQ(FailedResultState->getState(), facts::ResultStateKind::Rejected);

    const state::TransferOperation *SuccessOperation =
        state::getTransferOperation(Produced, Result);
    ASSERT_NE(SuccessOperation, nullptr);
    EXPECT_EQ(SuccessOperation->getHostBufferBase(), HostBufferBase);
    EXPECT_EQ(SuccessOperation->getOwner(), Owner);
    EXPECT_EQ(SuccessOperation->getGuestAddress(), GuestAddress);
    EXPECT_EQ(SuccessOperation->getBegin(), Begin);
    EXPECT_EQ(SuccessOperation->getRequestedLength(), Requested);
    ASSERT_TRUE(SuccessOperation->getActualLength().has_value());
    EXPECT_EQ(*SuccessOperation->getActualLength(), Actual);
    EXPECT_EQ(SuccessOperation->getProvenance(), facts::ProvenanceKind::DMA);
    EXPECT_EQ(SuccessOperation->getHostBufferDirection(),
              facts::AccessDirection::HostRead);

    const state::TransferOperation *FailedOperation =
        state::getTransferOperation(Produced, FailedResult);
    ASSERT_NE(FailedOperation, nullptr);
    EXPECT_EQ(FailedOperation->getHostBufferBase(), HostBufferBase);
    EXPECT_EQ(FailedOperation->getOwner(), nullptr);
    EXPECT_EQ(FailedOperation->getGuestAddress(), GuestAddress);
    EXPECT_EQ(FailedOperation->getBegin(), Begin);
    EXPECT_EQ(FailedOperation->getRequestedLength(), Requested);
    EXPECT_FALSE(FailedOperation->getActualLength().has_value());
    EXPECT_EQ(FailedOperation->getProvenance(), facts::ProvenanceKind::DMA);
    EXPECT_EQ(FailedOperation->getHostBufferDirection(),
              facts::AccessDirection::HostRead);

    const state::USBTransaction *USBTransaction =
        state::getUSBTransaction(Produced, Object);
    ASSERT_NE(USBTransaction, nullptr);
    EXPECT_EQ(USBTransaction->getHostBuffer(), HostBufferBase);
    EXPECT_EQ(USBTransaction->getRequestedLength(), Requested);
    EXPECT_EQ(USBTransaction->getCapacity(), Actual);
    EXPECT_EQ(USBTransaction->getActualLength(), Begin);
    EXPECT_EQ(USBTransaction->getStatus(), Epoch);
    EXPECT_EQ(USBTransaction->getEndpointType(), GuestAddress);
    EXPECT_EQ(USBTransaction->getSetupParameter(), Requested);
    EXPECT_EQ(USBTransaction->getDirection(),
              facts::USBPacketDirection::DeviceToHost);
    EXPECT_EQ(USBTransaction->getBuffer(), facts::USBPacketBufferKind::Direct);
    EXPECT_EQ(USBTransaction->getOrigin(), nullptr);
    EXPECT_TRUE(USBTransaction->isValid());

    const state::USBTransaction EquivalentUSBTransaction(
        HostBufferBase, Requested, Actual, Begin, Epoch, GuestAddress,
        Requested, facts::USBPacketDirection::DeviceToHost,
        facts::USBPacketBufferKind::Direct, nullptr);
    EXPECT_EQ(*USBTransaction, EquivalentUSBTransaction);
    llvm::FoldingSetNodeID USBProfile;
    llvm::FoldingSetNodeID EquivalentUSBProfile;
    USBTransaction->Profile(USBProfile);
    EquivalentUSBTransaction.Profile(EquivalentUSBProfile);
    EXPECT_TRUE(USBProfile.getRef() == EquivalentUSBProfile.getRef());

    const state::CompletionPublicationState *FailedPublication =
        state::getCompletionPublication(Produced, Owner, GuestAddress, Epoch,
                                        Begin);
    ASSERT_NE(FailedPublication, nullptr);
    EXPECT_EQ(FailedPublication->getOwner(), Owner);
    EXPECT_EQ(FailedPublication->getQueueID(), GuestAddress);
    EXPECT_EQ(FailedPublication->getAttemptID(), Epoch);
    EXPECT_EQ(FailedPublication->getSlot(), Begin);
    EXPECT_EQ(FailedPublication->getVector(), Requested);
    EXPECT_EQ(FailedPublication->getResult(), FailedResult);
    EXPECT_TRUE(FailedPublication->hasStage(
        facts::CompletionPublicationStage::DescriptorFailed));
    EXPECT_TRUE(FailedPublication->hasStage(
        facts::CompletionPublicationStage::RingAdvanced));
    EXPECT_TRUE(FailedPublication->hasStage(
        facts::CompletionPublicationStage::InterruptPublished));
    EXPECT_TRUE(
        state::isFailedDMACompletionPublished(Produced, FailedPublication));
    EXPECT_TRUE(state::isFailedDMACompletionPublished(
        Produced, Owner, GuestAddress, Epoch, Begin));
    EXPECT_FALSE(FailedPublication->isCompleteCompletionPublished());
    EXPECT_TRUE(FailedPublication->isTerminalPublication());

    const state::TransferOperation EquivalentSuccess(
        HostBufferBase, Owner, GuestAddress, Begin, Requested, Actual,
        facts::ProvenanceKind::DMA, facts::AccessDirection::HostRead);
    EXPECT_EQ(*SuccessOperation, EquivalentSuccess);
    llvm::FoldingSetNodeID SuccessProfile;
    llvm::FoldingSetNodeID EquivalentProfile;
    SuccessOperation->Profile(SuccessProfile);
    EquivalentSuccess.Profile(EquivalentProfile);
    EXPECT_TRUE(SuccessProfile.getRef() == EquivalentProfile.getRef());

    const state::TransferOperation UnknownActual(
        HostBufferBase, Owner, GuestAddress, Begin, Requested, std::nullopt,
        facts::ProvenanceKind::DMA, facts::AccessDirection::HostRead);
    EXPECT_FALSE(*SuccessOperation == UnknownActual);
    llvm::FoldingSetNodeID UnknownActualProfile;
    UnknownActual.Profile(UnknownActualProfile);
    EXPECT_FALSE(SuccessProfile.getRef() == UnknownActualProfile.getRef());

    const state::TransferOperation NonDMAOperation(
        HostBufferBase, Owner, GuestAddress, Begin, Requested, Actual,
        facts::ProvenanceKind::Packet, facts::AccessDirection::HostRead);
    EXPECT_FALSE(*SuccessOperation == NonDMAOperation);
    llvm::FoldingSetNodeID NonDMAProfile;
    NonDMAOperation.Profile(NonDMAProfile);
    EXPECT_FALSE(SuccessProfile.getRef() == NonDMAProfile.getRef());

    ProgramStateRef Consumed = state::setObjectExtent(
        Produced, Object, facts::ExtentKind::Requested, Begin, Replacement);
    Consumed = state::setValueProvenance(Consumed, Value,
                                         facts::ProvenanceKind::Packet);
    Consumed = state::setObjectLifetime(Consumed, Object, Owner, NewEpoch,
                                        facts::LifetimeState::Released);
    Consumed = state::setObjectDirection(Consumed, Object,
                                         facts::AccessDirection::HostWrite);
    Consumed = state::setValueResultState(Consumed, Result,
                                          facts::ResultStateKind::Partial);
    Consumed = state::setTransferOperation(
        Consumed, Result, HostBufferBase, nullptr, GuestAddress, Begin,
        Replacement, std::nullopt, facts::AccessDirection::HostWrite);
    const Stmt *PublicationOrigin = Function->getBody();
    Consumed = state::setUSBTransaction(
        Consumed, Object, HostBufferBase, Replacement, Requested, Actual,
        NewEpoch, GuestAddress, Begin, facts::USBPacketDirection::HostToDevice,
        facts::USBPacketBufferKind::Combined, PublicationOrigin);
    Consumed = state::startCompletionPublication(
        Consumed, Owner, GuestAddress, NewEpoch, Actual, Replacement, Result,
        facts::CompletionPublicationStage::DescriptorPending,
        PublicationOrigin);
    Consumed = state::observeCompletionPublicationStage(
        Consumed, Owner, GuestAddress, NewEpoch, Actual, Replacement, Result,
        facts::CompletionPublicationStage::DescriptorComplete,
        PublicationOrigin);
    Consumed = state::observeCompletionPublicationStage(
        Consumed, Owner, GuestAddress, NewEpoch, Actual, Replacement, Result,
        facts::CompletionPublicationStage::RingAdvanced, PublicationOrigin);
    Consumed = state::observeCompletionPublicationStage(
        Consumed, Owner, GuestAddress, NewEpoch, Actual, Replacement, Result,
        facts::CompletionPublicationStage::InterruptPublished,
        PublicationOrigin);

    EXPECT_EQ(
        state::getObjectExtent(Consumed, Object, facts::ExtentKind::Requested)
            ->getLength(),
        Replacement);
    EXPECT_EQ(state::getObjectExtent(Consumed, Object,
                                     facts::ExtentKind::ActualTransfer)
                  ->getLength(),
              Actual);
    EXPECT_EQ(state::getValueProvenance(Consumed, Value)->getKind(),
              facts::ProvenanceKind::Packet);
    EXPECT_EQ(state::getObjectLifetime(Consumed, Object)->getEpoch(), NewEpoch);
    EXPECT_EQ(state::getObjectLifetime(Consumed, Object)->getState(),
              facts::LifetimeState::Released);
    EXPECT_EQ(state::getObjectDirection(Consumed, Object)->getDirection(),
              facts::AccessDirection::HostWrite);
    EXPECT_EQ(state::getValueResultState(Consumed, Result)->getState(),
              facts::ResultStateKind::Partial);
    const state::TransferOperation *ReplacedOperation =
        state::getTransferOperation(Consumed, Result);
    ASSERT_NE(ReplacedOperation, nullptr);
    EXPECT_EQ(ReplacedOperation->getOwner(), nullptr);
    EXPECT_EQ(ReplacedOperation->getRequestedLength(), Replacement);
    EXPECT_FALSE(ReplacedOperation->getActualLength().has_value());
    EXPECT_EQ(ReplacedOperation->getProvenance(), facts::ProvenanceKind::DMA);
    EXPECT_EQ(ReplacedOperation->getHostBufferDirection(),
              facts::AccessDirection::HostWrite);
    const state::USBTransaction *ReplacedUSBTransaction =
        state::getUSBTransaction(Consumed, Object);
    ASSERT_NE(ReplacedUSBTransaction, nullptr);
    EXPECT_EQ(ReplacedUSBTransaction->getRequestedLength(), Replacement);
    EXPECT_EQ(ReplacedUSBTransaction->getCapacity(), Requested);
    EXPECT_EQ(ReplacedUSBTransaction->getActualLength(), Actual);
    EXPECT_EQ(ReplacedUSBTransaction->getStatus(), NewEpoch);
    EXPECT_EQ(ReplacedUSBTransaction->getEndpointType(), GuestAddress);
    EXPECT_EQ(ReplacedUSBTransaction->getSetupParameter(), Begin);
    EXPECT_EQ(ReplacedUSBTransaction->getDirection(),
              facts::USBPacketDirection::HostToDevice);
    EXPECT_EQ(ReplacedUSBTransaction->getBuffer(),
              facts::USBPacketBufferKind::Combined);
    EXPECT_EQ(ReplacedUSBTransaction->getOrigin(), PublicationOrigin);
    const state::CompletionPublicationState *CompletePublication =
        state::getCompletionPublication(Consumed, Owner, GuestAddress, NewEpoch,
                                        Actual);
    ASSERT_NE(CompletePublication, nullptr);
    EXPECT_EQ(CompletePublication->getOwner(), Owner);
    EXPECT_EQ(CompletePublication->getSlot(), Actual);
    EXPECT_EQ(CompletePublication->getVector(), Replacement);
    EXPECT_EQ(CompletePublication->getResult(), Result);
    EXPECT_FALSE(CompletePublication->hasStage(
        facts::CompletionPublicationStage::DescriptorPending));
    EXPECT_TRUE(CompletePublication->hasStage(
        facts::CompletionPublicationStage::DescriptorComplete));
    EXPECT_FALSE(CompletePublication->hasStage(
        facts::CompletionPublicationStage::DescriptorFailed));
    EXPECT_TRUE(CompletePublication->isCompleteCompletionPublished());
    EXPECT_FALSE(CompletePublication->hasFailedPublicationSequence());
    EXPECT_TRUE(CompletePublication->isTerminalPublication());
    EXPECT_FALSE(
        state::isFailedDMACompletionPublished(Consumed, CompletePublication));
    EXPECT_EQ(CompletePublication->getStageOrigin(
                  facts::CompletionPublicationStage::DescriptorComplete),
              PublicationOrigin);
    EXPECT_EQ(CompletePublication->getStageOrigin(
                  facts::CompletionPublicationStage::RingAdvanced),
              PublicationOrigin);
    EXPECT_EQ(CompletePublication->getStageOrigin(
                  facts::CompletionPublicationStage::InterruptPublished),
              PublicationOrigin);

    std::optional<state::CompletionPublicationState> EquivalentPublication =
        state::CompletionPublicationState::start(
            Owner, GuestAddress, NewEpoch, Actual, Replacement, Result,
            facts::CompletionPublicationStage::DescriptorComplete,
            PublicationOrigin);
    ASSERT_TRUE(EquivalentPublication.has_value());
    EquivalentPublication = EquivalentPublication->withObservedStage(
        facts::CompletionPublicationStage::RingAdvanced, PublicationOrigin);
    ASSERT_TRUE(EquivalentPublication.has_value());
    EquivalentPublication = EquivalentPublication->withObservedStage(
        facts::CompletionPublicationStage::InterruptPublished,
        PublicationOrigin);
    ASSERT_TRUE(EquivalentPublication.has_value());
    EXPECT_EQ(*CompletePublication, *EquivalentPublication);
    llvm::FoldingSetNodeID PublicationProfile;
    llvm::FoldingSetNodeID EquivalentPublicationProfile;
    CompletePublication->Profile(PublicationProfile);
    EquivalentPublication->Profile(EquivalentPublicationProfile);
    EXPECT_TRUE(PublicationProfile.getRef() ==
                EquivalentPublicationProfile.getRef());

    // Even the raw setter cannot rehome a publication under another owner.
    const state::CompletionPublicationKey CrossOwnerKey(Object, GuestAddress,
                                                        NewEpoch, Actual);
    ProgramStateRef CrossOwnerInsertion = state::setCompletionPublication(
        Initial, CrossOwnerKey, *EquivalentPublication);
    EXPECT_EQ(CrossOwnerInsertion, Initial);
    EXPECT_EQ(state::getCompletionPublication(CrossOwnerInsertion, Object,
                                              GuestAddress, NewEpoch, Actual),
              nullptr);

    // Invalid, reversed, and uncorrelated observations never advance state.
    const auto InvalidStage =
        static_cast<facts::CompletionPublicationStage>(255);
    EXPECT_FALSE(CompletePublication->hasStage(InvalidStage));
    const auto InvalidUSBDirection =
        static_cast<facts::USBPacketDirection>(255);
    const auto InvalidUSBBuffer = static_cast<facts::USBPacketBufferKind>(255);
    EXPECT_EQ(state::setUSBTransaction(
                  Initial, nullptr, HostBufferBase, Requested, Actual, Begin,
                  Epoch, GuestAddress, Requested,
                  facts::USBPacketDirection::DeviceToHost,
                  facts::USBPacketBufferKind::Direct, PublicationOrigin),
              Initial);
    auto ExpectUnknownUSBOperandRejected =
        [&](SVal HostBuffer, SVal CopyLength, SVal Capacity, SVal Offset,
            SVal Status, SVal EndpointType, SVal SetupParameter) {
          EXPECT_EQ(state::setUSBTransaction(
                        Initial, Object, HostBuffer, CopyLength, Capacity,
                        Offset, Status, EndpointType, SetupParameter,
                        facts::USBPacketDirection::DeviceToHost,
                        facts::USBPacketBufferKind::Direct, PublicationOrigin),
                    Initial);
        };
    ExpectUnknownUSBOperandRejected(UnknownVal(), Requested, Actual, Begin,
                                    Epoch, GuestAddress, Requested);
    ExpectUnknownUSBOperandRejected(HostBufferBase, UnknownVal(), Actual, Begin,
                                    Epoch, GuestAddress, Requested);
    ExpectUnknownUSBOperandRejected(HostBufferBase, Requested, UnknownVal(),
                                    Begin, Epoch, GuestAddress, Requested);
    ExpectUnknownUSBOperandRejected(HostBufferBase, Requested, Actual,
                                    UnknownVal(), Epoch, GuestAddress,
                                    Requested);
    ExpectUnknownUSBOperandRejected(HostBufferBase, Requested, Actual, Begin,
                                    UnknownVal(), GuestAddress, Requested);
    ExpectUnknownUSBOperandRejected(HostBufferBase, Requested, Actual, Begin,
                                    Epoch, UnknownVal(), Requested);
    ExpectUnknownUSBOperandRejected(HostBufferBase, Requested, Actual, Begin,
                                    Epoch, GuestAddress, UnknownVal());
    EXPECT_EQ(state::setUSBTransaction(
                  Initial, Object, HostBufferBase, Requested, Actual, Begin,
                  Epoch, GuestAddress, Requested, InvalidUSBDirection,
                  facts::USBPacketBufferKind::Direct, PublicationOrigin),
              Initial);
    EXPECT_EQ(state::setUSBTransaction(Initial, Object, HostBufferBase,
                                       Requested, Actual, Begin, Epoch,
                                       GuestAddress, Requested,
                                       facts::USBPacketDirection::DeviceToHost,
                                       InvalidUSBBuffer, PublicationOrigin),
              Initial);
    ProgramStateRef ValidUSB = state::setUSBTransaction(
        Initial, Object, HostBufferBase, Requested, Actual, Begin, Epoch,
        GuestAddress, Requested, facts::USBPacketDirection::DeviceToHost,
        facts::USBPacketBufferKind::Direct, PublicationOrigin);
    ASSERT_NE(ValidUSB, Initial);
    ProgramStateRef InvalidReplacement = state::setUSBTransaction(
        ValidUSB, Object, HostBufferBase, UnknownVal(), Actual, Begin, Epoch,
        GuestAddress, Requested, facts::USBPacketDirection::DeviceToHost,
        facts::USBPacketBufferKind::Direct, PublicationOrigin);
    EXPECT_EQ(state::getUSBTransaction(InvalidReplacement, Object), nullptr);
    EXPECT_EQ(state::getUSBTransaction(Initial, nullptr), nullptr);
    EXPECT_EQ(state::removeUSBTransaction(Initial, nullptr), Initial);
    EXPECT_TRUE(state::isAcceptedFailedCompletionResult(
        facts::ResultStateKind::Rejected));
    EXPECT_FALSE(state::isAcceptedFailedCompletionResult(
        facts::ResultStateKind::UncheckedError));
    EXPECT_FALSE(state::isAcceptedFailedCompletionResult(
        facts::ResultStateKind::Complete));
    EXPECT_FALSE(state::isAcceptedFailedCompletionResult(
        facts::ResultStateKind::Partial));
    EXPECT_FALSE(
        state::isAcceptedFailedCompletionResult(facts::ResultStateKind::Retry));

    ProgramStateRef JoinedFailure = state::setValueResultState(
        Initial, FailedResult, facts::ResultStateKind::Rejected);
    JoinedFailure = state::setTransferOperation(
        JoinedFailure, FailedResult, HostBufferBase, Owner, GuestAddress, Begin,
        Requested, std::nullopt, facts::AccessDirection::HostRead);
    ASSERT_TRUE(state::hasFailedDMATransferResult(JoinedFailure, FailedResult));

    const auto StartFailed = [&](ProgramStateRef State, SVal Queue,
                                 SVal Attempt, SVal PublicationSlot,
                                 SVal PublicationVector,
                                 SymbolRef PublicationResult) {
      return state::startCompletionPublication(
          State, Owner, Queue, Attempt, PublicationSlot, PublicationVector,
          PublicationResult,
          facts::CompletionPublicationStage::DescriptorFailed,
          PublicationOrigin);
    };
    const auto StartPending = [&](ProgramStateRef State,
                                  SymbolRef PublicationResult) {
      return state::startCompletionPublication(
          State, Owner, GuestAddress, NewEpoch, Begin, Replacement,
          PublicationResult,
          facts::CompletionPublicationStage::DescriptorPending,
          PublicationOrigin);
    };
    const auto MarkDescriptorFailed = [&](ProgramStateRef State,
                                          SymbolRef PublicationResult) {
      return state::observeCompletionPublicationStage(
          State, Owner, GuestAddress, NewEpoch, Begin, Replacement,
          PublicationResult,
          facts::CompletionPublicationStage::DescriptorFailed,
          PublicationOrigin);
    };

    // Starting or marking a failed descriptor requires two facts under the
    // exact same result symbol: a terminal failure and a DMA transfer.
    ProgramStateRef TransferOnly = state::setTransferOperation(
        Initial, FailedResult, HostBufferBase, Owner, GuestAddress, Begin,
        Requested, std::nullopt, facts::AccessDirection::HostRead);
    ProgramStateRef ResultOnly = state::setValueResultState(
        Initial, FailedResult, facts::ResultStateKind::Rejected);
    ProgramStateRef MismatchedResult = state::setTransferOperation(
        ResultOnly, Result, HostBufferBase, Owner, GuestAddress, Begin,
        Requested, std::nullopt, facts::AccessDirection::HostRead);
    ProgramStateRef NonDMA = state::setTransferOperation(
        ResultOnly, FailedResult, HostBufferBase, Owner, GuestAddress, Begin,
        Requested, std::nullopt, facts::ProvenanceKind::Packet,
        facts::AccessDirection::HostRead);
    for (ProgramStateRef MissingJoin :
         {TransferOnly, ResultOnly, MismatchedResult, NonDMA}) {
      EXPECT_FALSE(
          state::hasFailedDMATransferResult(MissingJoin, FailedResult));
      EXPECT_EQ(StartFailed(MissingJoin, GuestAddress, NewEpoch, Begin,
                            Replacement, FailedResult),
                MissingJoin);
      ProgramStateRef Pending = StartPending(MissingJoin, FailedResult);
      ASSERT_NE(Pending, MissingJoin);
      EXPECT_EQ(MarkDescriptorFailed(Pending, FailedResult), Pending);
    }

    ProgramStateRef UncheckedFailure = state::setValueResultState(
        TransferOnly, FailedResult, facts::ResultStateKind::UncheckedError);
    EXPECT_FALSE(
        state::hasFailedDMATransferResult(UncheckedFailure, FailedResult));
    EXPECT_EQ(StartFailed(UncheckedFailure, GuestAddress, NewEpoch, Begin,
                          Replacement, FailedResult),
              UncheckedFailure);
    ProgramStateRef UncheckedPending =
        StartPending(UncheckedFailure, FailedResult);
    ASSERT_NE(UncheckedPending, UncheckedFailure);
    EXPECT_EQ(MarkDescriptorFailed(UncheckedPending, FailedResult),
              UncheckedPending);

    const SVal Unknown = UnknownVal();
    const SVal Undefined = UndefinedVal();
    const auto ExpectInvalidPublicationIdentity = [&](SVal Queue, SVal Attempt,
                                                      SVal PublicationSlot,
                                                      SVal PublicationVector) {
      EXPECT_EQ(StartFailed(JoinedFailure, Queue, Attempt, PublicationSlot,
                            PublicationVector, FailedResult),
                JoinedFailure);
    };
    for (SVal InvalidValue : {Unknown, Undefined}) {
      ExpectInvalidPublicationIdentity(InvalidValue, NewEpoch, Begin,
                                       Replacement);
      ExpectInvalidPublicationIdentity(GuestAddress, InvalidValue, Begin,
                                       Replacement);
      ExpectInvalidPublicationIdentity(GuestAddress, NewEpoch, InvalidValue,
                                       Replacement);
      ExpectInvalidPublicationIdentity(GuestAddress, NewEpoch, Begin,
                                       InvalidValue);
    }
    EXPECT_EQ(StartFailed(JoinedFailure, GuestAddress, NewEpoch, Begin,
                          Replacement, nullptr),
              JoinedFailure);

    ProgramStateRef ValidFailedStart =
        StartFailed(JoinedFailure, GuestAddress, NewEpoch, Begin, Replacement,
                    FailedResult);
    ASSERT_NE(ValidFailedStart, JoinedFailure);
    const auto ExpectInvalidFailedAdvance =
        [&](SVal Queue, SVal Attempt, SVal PublicationSlot,
            SVal PublicationVector, SymbolRef PublicationResult) {
          EXPECT_EQ(state::observeCompletionPublicationStage(
                        ValidFailedStart, Owner, Queue, Attempt,
                        PublicationSlot, PublicationVector, PublicationResult,
                        facts::CompletionPublicationStage::RingAdvanced,
                        PublicationOrigin),
                    ValidFailedStart);
        };
    for (SVal InvalidValue : {Unknown, Undefined}) {
      ExpectInvalidFailedAdvance(InvalidValue, NewEpoch, Begin, Replacement,
                                 FailedResult);
      ExpectInvalidFailedAdvance(GuestAddress, InvalidValue, Begin, Replacement,
                                 FailedResult);
      ExpectInvalidFailedAdvance(GuestAddress, NewEpoch, InvalidValue,
                                 Replacement, FailedResult);
      ExpectInvalidFailedAdvance(GuestAddress, NewEpoch, Begin, InvalidValue,
                                 FailedResult);
    }
    ExpectInvalidFailedAdvance(GuestAddress, NewEpoch, Begin, Replacement,
                               nullptr);

    // The join is checked again while advancing and when deciding whether a
    // completed sequence is reportable; stale facts cannot authorize it.
    ProgramStateRef MissingResultAfterStart =
        state::removeValueResultState(ValidFailedStart, FailedResult);
    EXPECT_EQ(state::observeCompletionPublicationStage(
                  MissingResultAfterStart, Owner, GuestAddress, NewEpoch, Begin,
                  Replacement, FailedResult,
                  facts::CompletionPublicationStage::RingAdvanced,
                  PublicationOrigin),
              MissingResultAfterStart);
    ProgramStateRef MissingTransferAfterStart =
        state::removeTransferOperation(ValidFailedStart, FailedResult);
    EXPECT_EQ(state::observeCompletionPublicationStage(
                  MissingTransferAfterStart, Owner, GuestAddress, NewEpoch,
                  Begin, Replacement, FailedResult,
                  facts::CompletionPublicationStage::RingAdvanced,
                  PublicationOrigin),
              MissingTransferAfterStart);
    ProgramStateRef NonDMAAfterStart = state::setTransferOperation(
        ValidFailedStart, FailedResult, HostBufferBase, Owner, GuestAddress,
        Begin, Requested, std::nullopt, facts::ProvenanceKind::Packet,
        facts::AccessDirection::HostRead);
    EXPECT_EQ(state::observeCompletionPublicationStage(
                  NonDMAAfterStart, Owner, GuestAddress, NewEpoch, Begin,
                  Replacement, FailedResult,
                  facts::CompletionPublicationStage::RingAdvanced,
                  PublicationOrigin),
              NonDMAAfterStart);

    ProgramStateRef PublishedWithoutResult =
        state::removeValueResultState(Produced, FailedResult);
    ProgramStateRef PublishedWithoutTransfer =
        state::removeTransferOperation(Produced, FailedResult);
    ProgramStateRef PublishedNonDMA = state::setTransferOperation(
        Produced, FailedResult, HostBufferBase, Owner, GuestAddress, Begin,
        Requested, std::nullopt, facts::ProvenanceKind::Packet,
        facts::AccessDirection::HostRead);
    EXPECT_FALSE(state::isFailedDMACompletionPublished(
        PublishedWithoutResult, Owner, GuestAddress, Epoch, Begin));
    EXPECT_FALSE(state::isFailedDMACompletionPublished(
        PublishedWithoutTransfer, Owner, GuestAddress, Epoch, Begin));
    EXPECT_FALSE(state::isFailedDMACompletionPublished(
        PublishedNonDMA, Owner, GuestAddress, Epoch, Begin));

    EXPECT_EQ(state::startCompletionPublication(
                  Initial, nullptr, GuestAddress, NewEpoch, Begin, Replacement,
                  FailedResult,
                  facts::CompletionPublicationStage::DescriptorFailed,
                  PublicationOrigin),
              Initial);
    EXPECT_EQ(state::getCompletionPublication(Initial, nullptr, GuestAddress,
                                              NewEpoch, Begin),
              nullptr);
    EXPECT_EQ(state::startCompletionPublication(
                  Initial, Owner, GuestAddress, NewEpoch, Begin, Replacement,
                  FailedResult, InvalidStage, PublicationOrigin),
              Initial);

    ProgramStateRef Ordered = state::startCompletionPublication(
        JoinedFailure, Owner, GuestAddress, NewEpoch, Begin, Replacement,
        FailedResult, facts::CompletionPublicationStage::DescriptorPending,
        PublicationOrigin);
    ProgramStateRef Reversed = state::observeCompletionPublicationStage(
        Ordered, Owner, GuestAddress, NewEpoch, Begin, Replacement,
        FailedResult, facts::CompletionPublicationStage::InterruptPublished,
        PublicationOrigin);
    EXPECT_EQ(Reversed, Ordered);
    Reversed = state::observeCompletionPublicationStage(
        Ordered, Owner, GuestAddress, NewEpoch, Begin, Replacement,
        FailedResult, facts::CompletionPublicationStage::RingAdvanced,
        PublicationOrigin);
    EXPECT_EQ(Reversed, Ordered);
    Reversed = state::observeCompletionPublicationStage(
        Ordered, Owner, GuestAddress, NewEpoch, Begin, Replacement,
        FailedResult, InvalidStage, PublicationOrigin);
    EXPECT_EQ(Reversed, Ordered);
    Reversed = state::observeCompletionPublicationStage(
        Ordered, Owner, Actual, NewEpoch, Begin, Replacement, FailedResult,
        facts::CompletionPublicationStage::DescriptorFailed, PublicationOrigin);
    EXPECT_EQ(Reversed, Ordered);
    Reversed = state::observeCompletionPublicationStage(
        Ordered, Owner, GuestAddress, NewEpoch, Begin, Replacement, Result,
        facts::CompletionPublicationStage::DescriptorFailed, PublicationOrigin);
    EXPECT_EQ(Reversed, Ordered);

    // A descriptor retry resets any old publication stages.  Only the ordered
    // Failed -> RingAdvanced -> InterruptPublished sequence becomes reportable.
    Ordered = state::observeCompletionPublicationStage(
        Ordered, Owner, GuestAddress, NewEpoch, Begin, Replacement,
        FailedResult, facts::CompletionPublicationStage::DescriptorFailed,
        PublicationOrigin);
    Ordered = state::observeCompletionPublicationStage(
        Ordered, Owner, GuestAddress, NewEpoch, Begin, Replacement,
        FailedResult, facts::CompletionPublicationStage::RingAdvanced,
        PublicationOrigin);
    const state::CompletionPublicationState *BeforeInterrupt =
        state::getCompletionPublication(Ordered, Owner, GuestAddress, NewEpoch,
                                        Begin);
    ASSERT_NE(BeforeInterrupt, nullptr);
    EXPECT_FALSE(
        state::isFailedDMACompletionPublished(Ordered, BeforeInterrupt));
    ProgramStateRef DuplicateRing = state::observeCompletionPublicationStage(
        Ordered, Owner, GuestAddress, NewEpoch, Begin, Replacement,
        FailedResult, facts::CompletionPublicationStage::RingAdvanced,
        PublicationOrigin);
    EXPECT_EQ(DuplicateRing, Ordered);
    Ordered = state::observeCompletionPublicationStage(
        Ordered, Owner, GuestAddress, NewEpoch, Begin, Replacement,
        FailedResult, facts::CompletionPublicationStage::InterruptPublished,
        PublicationOrigin);
    ASSERT_TRUE(state::isFailedDMACompletionPublished(
        Ordered, Owner, GuestAddress, NewEpoch, Begin));

    ProgramStateRef Retried = state::observeCompletionPublicationStage(
        Ordered, Owner, GuestAddress, NewEpoch, Begin, Replacement,
        FailedResult, facts::CompletionPublicationStage::DescriptorPending,
        PublicationOrigin);
    const state::CompletionPublicationState *RetryPublication =
        state::getCompletionPublication(Retried, Owner, GuestAddress, NewEpoch,
                                        Begin);
    ASSERT_NE(RetryPublication, nullptr);
    EXPECT_TRUE(RetryPublication->hasStage(
        facts::CompletionPublicationStage::DescriptorPending));
    EXPECT_FALSE(RetryPublication->hasStage(
        facts::CompletionPublicationStage::RingAdvanced));
    EXPECT_FALSE(RetryPublication->hasStage(
        facts::CompletionPublicationStage::InterruptPublished));
    EXPECT_FALSE(
        state::isFailedDMACompletionPublished(Retried, RetryPublication));

    ProgramStateRef Reused = state::startCompletionPublication(
        Ordered, Owner, GuestAddress, NewEpoch, Begin, Replacement,
        FailedResult, facts::CompletionPublicationStage::DescriptorFailed,
        PublicationOrigin);
    const state::CompletionPublicationState *ReusedPublication =
        state::getCompletionPublication(Reused, Owner, GuestAddress, NewEpoch,
                                        Begin);
    ASSERT_NE(ReusedPublication, nullptr);
    EXPECT_TRUE(ReusedPublication->hasStage(
        facts::CompletionPublicationStage::DescriptorFailed));
    EXPECT_FALSE(ReusedPublication->hasStage(
        facts::CompletionPublicationStage::RingAdvanced));
    EXPECT_FALSE(ReusedPublication->hasStage(
        facts::CompletionPublicationStage::InterruptPublished));
    EXPECT_FALSE(ReusedPublication->isTerminalPublication());

    // A result is bound to one active composite identity.  A second queue may
    // not reuse it until the original publication is explicitly removed.
    ProgramStateRef TwoQueues = state::startCompletionPublication(
        Reused, Owner, Actual, NewEpoch, Begin, Replacement, FailedResult,
        facts::CompletionPublicationStage::DescriptorFailed, PublicationOrigin);
    EXPECT_EQ(TwoQueues, Reused);
    EXPECT_NE(state::getCompletionPublication(TwoQueues, Owner, GuestAddress,
                                              NewEpoch, Begin),
              nullptr);
    EXPECT_EQ(state::getCompletionPublication(TwoQueues, Owner, Actual,
                                              NewEpoch, Begin),
              nullptr);

    ProgramStateRef Released =
        state::removeCompletionPublicationsForResult(Reused, FailedResult);
    EXPECT_EQ(state::getCompletionPublication(Released, Owner, GuestAddress,
                                              NewEpoch, Begin),
              nullptr);
    ProgramStateRef Rebound = state::startCompletionPublication(
        Released, Owner, Actual, NewEpoch, Begin, Replacement, FailedResult,
        facts::CompletionPublicationStage::DescriptorFailed, PublicationOrigin);
    EXPECT_NE(Rebound, Released);
    EXPECT_NE(state::getCompletionPublication(Rebound, Owner, Actual, NewEpoch,
                                              Begin),
              nullptr);

    // A live packet keeps the symbolic operands of its current transaction
    // alive.  Once the packet region dies, the relation is removed rather
    // than leaking into a later packet epoch.
    const SVal USBResultOperand = Builder.makeSymbolVal(Result);
    const SVal USBFailureOperand = Builder.makeSymbolVal(FailedResult);
    ProgramStateRef USBOnly = state::setUSBTransaction(
        Initial, Object, HostBufferBase, Requested, USBResultOperand, Begin,
        USBFailureOperand, USBResultOperand, USBFailureOperand,
        facts::USBPacketDirection::DeviceToHost,
        facts::USBPacketBufferKind::Direct, PublicationOrigin);
    ASSERT_NE(USBOnly, Initial);
    SymbolReaper USBActiveReaper(nullptr, nullptr, Eng.getSymbolManager(),
                                 Eng.getStoreManager());
    USBActiveReaper.markLive(Object);
    state::markLiveUSBTransactions(USBOnly, USBActiveReaper);
    EXPECT_TRUE(USBActiveReaper.isLive(Value));
    EXPECT_TRUE(USBActiveReaper.isLive(Result));
    EXPECT_TRUE(USBActiveReaper.isLive(FailedResult));
    EXPECT_EQ(state::removeDeadUSBTransactions(USBOnly, USBActiveReaper),
              USBOnly);

    SymbolReaper USBDeadReaper(nullptr, nullptr, Eng.getSymbolManager(),
                               Eng.getStoreManager());
    state::markLiveUSBTransactions(USBOnly, USBDeadReaper);
    ProgramStateRef USBDeadCleaned =
        state::removeDeadUSBTransactions(USBOnly, USBDeadReaper);
    EXPECT_EQ(state::getUSBTransaction(USBDeadCleaned, Object), nullptr);

    // An active publication rooted by a live owner retains only its exact
    // result and queue identity symbols across the shared liveness sweep.
    const SVal ResultIdentity = Builder.makeSymbolVal(Result);
    const SVal FailureIdentity = Builder.makeSymbolVal(FailedResult);
    ProgramStateRef SymbolicPublication = state::startCompletionPublication(
        Initial, Owner, HostBufferBase, ResultIdentity, Begin, FailureIdentity,
        FailedResult, facts::CompletionPublicationStage::DescriptorPending,
        PublicationOrigin);
    ASSERT_NE(SymbolicPublication, Initial);
    SymbolReaper ActiveReaper(nullptr, nullptr, Eng.getSymbolManager(),
                              Eng.getStoreManager());
    ActiveReaper.markLive(Owner);
    state::markLiveCompletionPublications(SymbolicPublication, ActiveReaper);
    EXPECT_TRUE(ActiveReaper.isLive(Value));
    EXPECT_TRUE(ActiveReaper.isLive(Result));
    EXPECT_TRUE(ActiveReaper.isLive(FailedResult));
    EXPECT_EQ(state::removeDeadCompletionPublications(SymbolicPublication,
                                                      ActiveReaper),
              SymbolicPublication);

    SymbolReaper DeadOwnerReaper(nullptr, nullptr, Eng.getSymbolManager(),
                                 Eng.getStoreManager());
    state::markLiveCompletionPublications(SymbolicPublication, DeadOwnerReaper);
    ProgramStateRef DeadOwnerCleaned = state::removeDeadCompletionPublications(
        SymbolicPublication, DeadOwnerReaper);
    EXPECT_EQ(state::getCompletionPublication(DeadOwnerCleaned, Owner,
                                              HostBufferBase, ResultIdentity,
                                              Begin),
              nullptr);

    ProgramStateRef SymbolicReleased =
        state::removeCompletionPublicationsForResult(SymbolicPublication,
                                                     FailedResult);
    SymbolReaper ReleasedReaper(nullptr, nullptr, Eng.getSymbolManager(),
                                Eng.getStoreManager());
    ReleasedReaper.markLive(Owner);
    state::markLiveCompletionPublications(SymbolicReleased, ReleasedReaper);
    EXPECT_TRUE(ReleasedReaper.isDead(Value));
    EXPECT_TRUE(ReleasedReaper.isDead(Result));
    EXPECT_TRUE(ReleasedReaper.isDead(FailedResult));

    // Completed records are never liveness roots and are purged at the next
    // sweep even while their queue owner remains live.
    SymbolReaper TerminalReaper(nullptr, nullptr, Eng.getSymbolManager(),
                                Eng.getStoreManager());
    TerminalReaper.markLive(Owner);
    state::markLiveCompletionPublications(Consumed, TerminalReaper);
    ProgramStateRef TerminalCleaned =
        state::removeDeadCompletionPublications(Consumed, TerminalReaper);
    EXPECT_EQ(state::getCompletionPublication(TerminalCleaned, Owner,
                                              GuestAddress, NewEpoch, Actual),
              nullptr);
    EXPECT_EQ(state::getCompletionPublication(TerminalCleaned, Owner,
                                              GuestAddress, Epoch, Begin),
              nullptr);

    // ProgramState is persistent: replacing facts did not mutate the state
    // returned by the producer translation unit.
    EXPECT_EQ(
        state::getObjectExtent(Produced, Object, facts::ExtentKind::Requested)
            ->getLength(),
        Requested);
    EXPECT_EQ(state::getValueResultState(Produced, Result)->getState(),
              facts::ResultStateKind::Complete);
    ASSERT_TRUE(state::getTransferOperation(Produced, Result)
                    ->getActualLength()
                    .has_value());
    EXPECT_EQ(
        state::getTransferOperation(Produced, Result)->getRequestedLength(),
        Requested);
    EXPECT_EQ(state::getUSBTransaction(Produced, Object)->getRequestedLength(),
              Requested);
    EXPECT_EQ(state::getUSBTransaction(Produced, Object)->getCapacity(),
              Actual);
    EXPECT_TRUE(state::isFailedDMACompletionPublished(
        Produced, Owner, GuestAddress, Epoch, Begin));

    // Observing a stage without a queue fact does not invent an uncorrelated
    // publication record.
    ProgramStateRef MissingPublication =
        state::observeCompletionPublicationStage(
            Consumed, Object, GuestAddress, NewEpoch, Actual, Replacement,
            Result, facts::CompletionPublicationStage::InterruptPublished,
            PublicationOrigin);
    EXPECT_EQ(MissingPublication, Consumed);

    // Terminal reporting and queue reset have explicit cleanup operations.
    // Removing one result leaves unrelated publications intact; owner reset
    // releases all identities owned by that queue/device.
    ProgramStateRef ResultCleaned =
        state::removeCompletionPublicationsForResult(Consumed, Result);
    EXPECT_EQ(state::getCompletionPublication(ResultCleaned, Owner,
                                              GuestAddress, NewEpoch, Actual),
              nullptr);
    EXPECT_NE(state::getCompletionPublication(ResultCleaned, Owner,
                                              GuestAddress, Epoch, Begin),
              nullptr);
    ProgramStateRef OwnerCleaned =
        state::removeCompletionPublicationsForOwner(Consumed, Owner);
    EXPECT_EQ(state::getCompletionPublication(OwnerCleaned, Owner, GuestAddress,
                                              NewEpoch, Actual),
              nullptr);
    EXPECT_EQ(state::getCompletionPublication(OwnerCleaned, Owner, GuestAddress,
                                              Epoch, Begin),
              nullptr);
    EXPECT_EQ(state::removeCompletionPublicationsForResult(Consumed, nullptr),
              Consumed);
    EXPECT_EQ(state::removeCompletionPublicationsForOwner(Consumed, nullptr),
              Consumed);

    Consumed = state::removeObjectExtent(Consumed, Object,
                                         facts::ExtentKind::Requested);
    Consumed = state::removeObjectExtent(Consumed, Object,
                                         facts::ExtentKind::ActualTransfer);
    Consumed = state::removeValueProvenance(Consumed, Value);
    Consumed = state::removeObjectLifetime(Consumed, Object);
    Consumed = state::removeObjectDirection(Consumed, Object);
    Consumed = state::removeValueResultState(Consumed, Result);
    Consumed = state::removeValueResultState(Consumed, FailedResult);
    Consumed = state::removeTransferOperation(Consumed, Result);
    Consumed = state::removeTransferOperation(Consumed, FailedResult);
    Consumed = state::removeUSBTransaction(Consumed, Object);
    Consumed = state::removeCompletionPublication(Consumed, Owner, GuestAddress,
                                                  NewEpoch, Actual);

    EXPECT_EQ(
        state::getObjectExtent(Consumed, Object, facts::ExtentKind::Requested),
        nullptr);
    EXPECT_EQ(state::getObjectExtent(Consumed, Object,
                                     facts::ExtentKind::ActualTransfer),
              nullptr);
    EXPECT_EQ(state::getValueProvenance(Consumed, Value), nullptr);
    EXPECT_EQ(state::getObjectLifetime(Consumed, Object), nullptr);
    EXPECT_EQ(state::getObjectDirection(Consumed, Object), nullptr);
    EXPECT_EQ(state::getValueResultState(Consumed, Result), nullptr);
    EXPECT_EQ(state::getValueResultState(Consumed, FailedResult), nullptr);
    EXPECT_EQ(state::getTransferOperation(Consumed, Result), nullptr);
    EXPECT_EQ(state::getTransferOperation(Consumed, FailedResult), nullptr);
    EXPECT_EQ(state::getUSBTransaction(Consumed, Object), nullptr);
    EXPECT_EQ(state::getCompletionPublication(Consumed, Owner, GuestAddress,
                                              NewEpoch, Actual),
              nullptr);

    Checked = true;
  }

public:
  explicit SharedStateConsumer(CompilerInstance &Compiler)
      : ExprEngineConsumer(Compiler) {}

  ~SharedStateConsumer() override { EXPECT_TRUE(Checked); }

  bool HandleTopLevelDecl(DeclGroupRef Declarations) override {
    for (Decl *Declaration : Declarations) {
      const auto *Function = dyn_cast<FunctionDecl>(Declaration);
      if (!Function || !Function->hasBody())
        continue;
      checkFunction(Function);
    }
    return true;
  }
};

class SharedStateAction : public ASTFrontendAction {
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &Compiler,
                                                 StringRef) override {
    return std::make_unique<SharedStateConsumer>(Compiler);
  }
};

TEST(QEMUSharedState, ProducerAndConsumerSharePersistentFactsAcrossTUs) {
  EXPECT_TRUE(tooling::runToolOnCode(
      std::make_unique<SharedStateAction>(),
      "void transfer(unsigned char *object, void *owner, int success_result, "
      "int failed_result) {}"));
}

} // namespace
