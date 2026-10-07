//===-- SH.h - The entry points of the SuperH backend -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SH_SH_H
#define LLVM_LIB_TARGET_SH_SH_H

#include "MCTargetDesc/SHMCTargetDesc.h"
#include "llvm/Support/CodeGen.h"

namespace llvm {

class FunctionPass;
class PassRegistry;
class SHTargetMachine;

FunctionPass *createSHISelDag(SHTargetMachine &TM, CodeGenOptLevel OptLevel);
FunctionPass *createSHDelaySlotFillerPass();
FunctionPass *createSHFPModeSwitchPass();
FunctionPass *createSHConstantIslandsPass();

void initializeSHAsmPrinterPass(PassRegistry &);

} // namespace llvm

#endif
