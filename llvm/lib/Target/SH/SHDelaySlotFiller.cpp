//===-- SHDelaySlotFiller.cpp - The instruction behind a delayed branch
//-----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

//
// bra, jmp, jsr and rts execute the instruction that follows them before
// they take effect.  This pass puts a nop there.  Moving a useful
// instruction into the slot is left for later.
//
//===----------------------------------------------------------------------===//

#include "SH.h"
#include "SHInstrInfo.h"
#include "SHSubtarget.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"

using namespace llvm;

#define DEBUG_TYPE "sh-delay-slot"

namespace {

class SHDelaySlotFiller : public MachineFunctionPass {
public:
  static char ID;
  SHDelaySlotFiller() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override { return "SuperH delay slot filler"; }

  bool runOnMachineFunction(MachineFunction &MF) override {
    const SHInstrInfo &TII = *MF.getSubtarget<SHSubtarget>().getInstrInfo();
    bool Changed = false;
    for (MachineBasicBlock &MBB : MF)
      for (auto I = MBB.begin(); I != MBB.end(); ++I) {
        if (!I->hasDelaySlot())
          continue;
        BuildMI(MBB, std::next(I), I->getDebugLoc(), TII.get(SH::NOP));
        ++I;
        Changed = true;
      }
    return Changed;
  }

  MachineFunctionProperties getRequiredProperties() const override {
    return MachineFunctionProperties().setNoVRegs();
  }
};

} // namespace

char SHDelaySlotFiller::ID = 0;

FunctionPass *llvm::createSHDelaySlotFillerPass() {
  return new SHDelaySlotFiller();
}
