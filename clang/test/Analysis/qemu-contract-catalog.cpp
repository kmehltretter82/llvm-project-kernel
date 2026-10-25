// RUN: %python %S/../../utils/analyzer/qemu_contract_catalog.py --check
// RUN: %python %S/../../utils/analyzer/tests/test_qemu_contract_catalog.py
// RUN: env QEMU_CONTRACT_TEST_CLANG=%clang %python %S/../../utils/analyzer/tests/test_qemu_contract_catalog_resolver.py
// RUN: %clang_cc1 -std=c++17 -fsyntax-only -verify %s
// expected-no-diagnostics

#include "../../lib/StaticAnalyzer/Checkers/QEMUContractCatalog.inc"

using namespace clang::ento::qemu_contracts_generated;

static_assert(CatalogFormat == 5);
static_assert(ParameterRecordCount == 82);
static_assert(OperandRecordCount == 105);
static_assert(MemberStepRecordCount == 12);
static_assert(EffectRecordCount == 22);
static_assert(ContractAdditionalRuleRecordCount == 1);
static_assert(ContractRecordCount == 18);
static_assert(CallbackRuleRecordCount == 4);
static_assert(CallbackParameterRecordCount == 9);
static_assert(CallbackMemberStepRecordCount == 12);
static_assert(CallbackEntryInputRecordCount == 11);
static_assert(CallbackInputBufferRecordCount == 1);
static_assert(CallbackBindingRecordCount == 2);
static_assert(ProtocolBindingRecordCount == 6);
static_assert(ProtocolSelectorRecordCount == 4);
static_assert(ProtocolEventRecordCount == 3);
static_assert(ProtocolRecordCount == 1);

static_assert(Contracts[0].ParameterBegin == 0);
static_assert(Contracts[0].ReturnType[0] == 'v');
static_assert(Contracts[0].ReturnType[5] == '*');
static_assert(Contracts[1].ReturnType[4] == '\0');
static_assert(Contracts[8].Kind[0] == 'i');
static_assert(Contracts[9].Kind[0] == 'r');
static_assert(Contracts[10].Kind[0] == 'u');
static_assert(Effects[12].Kind[0] == 'i');
static_assert(Effects[12].Callback[0] == 'c');
static_assert(Effects[13].MemoryRegion[0] == 'm');
static_assert(Contracts[11].Kind[0] == 't');
static_assert(Contracts[11].ReturnType[0] == 'M');
static_assert(Contracts[11].DirectionEncoding[0] == 'f');
static_assert(Contracts[11].PairID[0] == '\0');
static_assert(Effects[15].Kind[0] == 't');
static_assert(Effects[15].Target[0] == 'h');
static_assert(Contracts[ContractRecordCount - 1].Kind[0] == 'p');
static_assert(Contracts[ContractRecordCount - 1].SelectorName[0] == 'u');
static_assert(MemberSteps[0].RecordType[0] == 'U');
static_assert(MemberSteps[MemberStepRecordCount - 1].Field[0] == 's');
static_assert(Effects[EffectRecordCount - 1].Kind[0] == 'p');
static_assert(Contracts[ContractRecordCount - 1].AdditionalRuleBegin == 0);
static_assert(Contracts[ContractRecordCount - 1].AdditionalRuleCount == 1);
static_assert(ContractAdditionalRules[0].ContractID[5] == 'u');
static_assert(ContractAdditionalRules[0].RuleID[5] == 'g');
static_assert(Contracts[ContractRecordCount - 1].EffectBegin +
                  Contracts[ContractRecordCount - 1].EffectCount ==
              EffectRecordCount);
static_assert(CallbackBindings[0].SlotRecordType[0] == 'U');
static_assert(CallbackBindings[0].SlotField[7] == 'c');
static_assert(CallbackBindings[0].SlotHeader[8] == 'h');
static_assert(CallbackBindings[0].SlotTranslationUnit[7] == 'b');
static_assert(CallbackBindings[0].SlotImplementation[8] == 'h');
static_assert(CallbackBindings[0].RegistrationRecordType[0] == 'T');
static_assert(CallbackBindings[0].RegistrationField[0] == 'c');
static_assert(CallbackBindings[0].RegistrationHeader[8] == 'q');
static_assert(CallbackBindings[0].RegistrationTranslationUnit[7] == 'u');
static_assert(CallbackBindings[0].RegistrationVariable[8] == 'i');
static_assert(CallbackBindings[0].RegistrationInitializer[8] == 'c');
static_assert(CallbackBindings[0].RuleBegin == 0);
static_assert(CallbackBindings[0].RuleCount == 2);
static_assert(CallbackBindings[0].ParameterBegin == 0);
static_assert(CallbackBindings[0].ParameterCount == 7);
static_assert(CallbackBindings[0].InputBufferBegin == 0);
static_assert(CallbackBindings[0].InputBufferCount == 1);
static_assert(CallbackBindings[1].SlotField[7] == 'd');
static_assert(CallbackBindings[1].RuleBegin == 2);
static_assert(CallbackBindings[1].RuleCount == 2);
static_assert(CallbackBindings[1].ParameterBegin == 7);
static_assert(CallbackBindings[1].ParameterCount == 2);
static_assert(CallbackBindings[1].InputBufferBegin == 1);
static_assert(CallbackBindings[1].InputBufferCount == 0);
static_assert(CallbackRules[0].CallbackID[5] == 'u');
static_assert(CallbackRules[0].RuleID[5] == 'c');
static_assert(CallbackParameters[6].Index == 6);
static_assert(CallbackParameters[6].Type[0] == 'u');
static_assert(CallbackBindings[CallbackBindingRecordCount - 1].EntryInputBegin +
                  CallbackBindings[CallbackBindingRecordCount - 1]
                      .EntryInputCount ==
              CallbackEntryInputRecordCount);
static_assert(CallbackEntryInputs[0].MemberStepCount == 0);
static_assert(CallbackEntryInputs[4].ArgumentIndex == 1);
static_assert(CallbackEntryInputs[4].MemberStepBegin == 0);
static_assert(CallbackEntryInputs[4].MemberStepCount == 3);
static_assert(CallbackMemberSteps[0].RecordType[0] == 'U');
static_assert(CallbackMemberSteps[CallbackMemberStepRecordCount - 1].Type[0] ==
              'u');
static_assert(CallbackInputBuffers[0].BufferArgumentIndex == 6);
static_assert(CallbackInputBuffers[0].LengthArgumentIndex == 5);
static_assert(CallbackInputBuffers[0].SelectorArgumentIndex == 2);
static_assert(CallbackInputBuffers[0].SelectorMask == 0x8000);
static_assert(CallbackInputBuffers[0].SelectorValue == 0);
static_assert(Protocols[0].BindingBegin == 0);
static_assert(Protocols[0].BindingCount == ProtocolBindingRecordCount);
static_assert(Protocols[0].EventBegin == 0);
static_assert(Protocols[0].EventCount == ProtocolEventRecordCount);
static_assert(ProtocolEvents[ProtocolEventRecordCount - 1].SelectorBegin +
                  ProtocolEvents[ProtocolEventRecordCount - 1].SelectorCount ==
              ProtocolSelectorRecordCount);
static_assert(ProtocolSelectors[0].Kind[0] == 't');
static_assert(ProtocolSelectors[2].Kind[0] == 'm');
static_assert(ProtocolSelectors[3].Kind[0] == 'f');
