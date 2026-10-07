//===-- SHFPModeSwitch.cpp - The precision of the floating point unit -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The floating point unit of the SH-4 computes with float or with double,
// depending on the PR bit of FPSCR: "fadd" is one instruction for both.  The
// calling convention says what the bit is when a function is called and
// when it returns: double, or float with -m4-single.
//
// This pass keeps every block to that: it starts and ends in the precision
// of the convention, and so does every call.  In front of an instruction
// that needs the other precision the bit is changed, and it is changed back
// in front of the next instruction that minds: one that needs the first
// precision, a call, the end of the block.
//
// The bit is changed with
//
//   mov #8,rA; shll16 rA; sts fpscr,rB; xor rA,rB; lds rB,fpscr
//
// which leaves T alone, so it can stand between a comparison and its
// branch.  An SH-4A has fpchg for it.  The pass runs on virtual registers.
//
// What GCC does better: it carries the precision across blocks.  A loop
// that computes with float in a function of the double convention changes
// the bit twice in every pass here.
//
//===----------------------------------------------------------------------===//

#include "SH.h"
#include "SHInstrInfo.h"
#include "SHSubtarget.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"

using namespace llvm;

#define DEBUG_TYPE "sh-fp-mode"

namespace {

class SHFPModeSwitch : public MachineFunctionPass {
public:
  static char ID;
  SHFPModeSwitch() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override {
    return "SuperH floating point precision";
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  enum Precision { Single, Double, Any };

  static Precision needed(const MachineInstr &MI, Precision Default);
  void change(MachineBasicBlock &MBB, MachineBasicBlock::iterator Before);

  const SHSubtarget *STI = nullptr;
  const SHInstrInfo *TII = nullptr;
};

} // namespace

char SHFPModeSwitch::ID = 0;

INITIALIZE_PASS(SHFPModeSwitch, DEBUG_TYPE, "SuperH floating point precision",
                false, false)

FunctionPass *llvm::createSHFPModeSwitchPass() { return new SHFPModeSwitch(); }

/// The precision that an instruction has to find.
SHFPModeSwitch::Precision SHFPModeSwitch::needed(const MachineInstr &MI,
                                                 Precision Default) {
  switch (MI.getOpcode()) {
  case SH::FADDS:
  case SH::FSUBS:
  case SH::FMULS:
  case SH::FDIVS:
  case SH::FSQRTS:
  case SH::FCMPEQS:
  case SH::FCMPGTS:
  case SH::FLOATS:
  case SH::FTRCS:
    return Single;
  case SH::FADDD:
  case SH::FSUBD:
  case SH::FMULD:
  case SH::FDIVD:
  case SH::FSQRTD:
  case SH::FCMPEQD:
  case SH::FCMPGTD:
  case SH::FLOATD:
  case SH::FTRCD:
  case SH::FCNVSD:
  case SH::FCNVDS:
    return Double;
  default:
    break;
  }
  // What leaves the block or the function, and what the pass cannot look
  // into.
  if (MI.isCall() || MI.isTerminator() || MI.isInlineAsm())
    return Default;
  return Any;
}

void SHFPModeSwitch::change(MachineBasicBlock &MBB,
                            MachineBasicBlock::iterator Before) {
  DebugLoc DL;
  if (Before != MBB.end())
    DL = Before->getDebugLoc();
  if (STI->hasSH4A()) {
    BuildMI(MBB, Before, DL, TII->get(SH::FPCHG));
    return;
  }
  MachineRegisterInfo &MRI = MBB.getParent()->getRegInfo();
  const TargetRegisterClass *RC = &SH::GPRRegClass;
  Register Eight = MRI.createVirtualRegister(RC);
  Register Bit = MRI.createVirtualRegister(RC);
  Register Old = MRI.createVirtualRegister(RC);
  Register New = MRI.createVirtualRegister(RC);
  // PR is bit 19.
  BuildMI(MBB, Before, DL, TII->get(SH::MOVI), Eight).addImm(8);
  BuildMI(MBB, Before, DL, TII->get(SH::SHLL16), Bit).addReg(Eight);
  BuildMI(MBB, Before, DL, TII->get(SH::STSFPSCR), Old);
  BuildMI(MBB, Before, DL, TII->get(SH::XORrr), New).addReg(Old).addReg(Bit);
  BuildMI(MBB, Before, DL, TII->get(SH::LDSFPSCR)).addReg(New);
}

bool SHFPModeSwitch::runOnMachineFunction(MachineFunction &MF) {
  STI = &MF.getSubtarget<SHSubtarget>();
  // Without double in the unit there is one precision.
  if (!STI->hasFPUDouble())
    return false;
  TII = STI->getInstrInfo();
  Precision Default = STI->hasFPUSingleMode() ? Single : Double;

  bool Changed = false;
  for (MachineBasicBlock &MBB : MF) {
    Precision Current = Default;
    for (MachineBasicBlock::iterator I = MBB.begin(); I != MBB.end(); ++I) {
      if (I->isPHI() || I->isDebugInstr())
        continue;
      Precision Needed = needed(*I, Default);
      if (Needed == Any || Needed == Current)
        continue;
      change(MBB, I);
      Current = Needed;
      Changed = true;
    }
    if (Current != Default) {
      change(MBB, MBB.end());
      Changed = true;
    }
  }
  return Changed;
}
