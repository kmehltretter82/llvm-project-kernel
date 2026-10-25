//===- QEMUSharedStateTestSupport.h ---------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_UNITTESTS_STATICANALYZER_QEMUSHAREDSTATETESTSUPPORT_H
#define LLVM_CLANG_UNITTESTS_STATICANALYZER_QEMUSHAREDSTATETESTSUPPORT_H

#include "../../lib/StaticAnalyzer/Checkers/QEMUSharedState.h"

namespace clang {
namespace ento {
namespace qemu {
namespace test {

struct SharedStateTraitIndices {
  void *Extent;
  void *Provenance;
  void *Lifetime;
  void *Direction;
  void *Result;
  void *TransferOperation;
  void *USBTransaction;
  void *CompletionPublication;
};

SharedStateTraitIndices producerTraitIndices();

ProgramStateRef produceSharedFacts(ProgramStateRef State,
                                   const MemRegion *Object,
                                   const MemRegion *Owner, SVal Begin,
                                   SVal Requested, SVal Actual, SymbolRef Value,
                                   SVal Epoch, SymbolRef Result,
                                   SymbolRef FailedResult, SVal HostBufferBase,
                                   SVal GuestAddress);

} // namespace test
} // namespace qemu
} // namespace ento
} // namespace clang

#endif
