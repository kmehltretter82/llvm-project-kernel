//===-- SHFrameLowering.cpp - The stack frame of a SuperH function -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

//
// The frame, from high addresses to low ones:
//
//   the arguments that came on the stack
//   r4 to r7 of a function with variable arguments, as far as they hold
//     none of its named parameters, so that all arguments are in one row
//   the registers that the function saves, pushed: r8 to r14, then pr
//   local variables and spill slots
//   the arguments of the calls that the function makes
//
// r15 points to the lowest address.  A function with a frame pointer copies
// r15 to r14 when the frame is complete, as GCC does, so that the offset
// of a slot is the same from either register.
//
// A local variable that is aligned to more than four bytes changes this.
// The prologue then rounds r15 down behind the pushes, which leaves a gap
// of unknown size between the saved registers and the local variables.
// r14 is set in front of the gap and is the base of what lies above it, the
// arguments.  The local variables are found from r15, or from r13 where
// r15 moves because the function allocates memory on the stack.
//
//===----------------------------------------------------------------------===//

#include "SHFrameLowering.h"
#include "SHInstrInfo.h"
#include "SHMachineFunctionInfo.h"
#include "SHSubtarget.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/RegisterScavenging.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"

using namespace llvm;

SHFrameLowering::SHFrameLowering(const SHSubtarget &STI)
    : TargetFrameLowering(StackGrowsDown, Align(4), 0, Align(4)), STI(STI) {}

bool SHFrameLowering::hasFPImpl(const MachineFunction &MF) const {
  const MachineFrameInfo &MFI = MF.getFrameInfo();
  return MF.disableFramePointerElim() || MFI.hasVarSizedObjects() ||
         MFI.isFrameAddressTaken() || realignsStack(MF);
}

bool SHFrameLowering::realignsStack(const MachineFunction &MF) const {
  return STI.getRegisterInfo()->hasStackRealignment(MF);
}

bool SHFrameLowering::hasBasePointer(const MachineFunction &MF) const {
  return realignsStack(MF) && MF.getFrameInfo().hasVarSizedObjects();
}

// The space for the arguments of calls is part of the frame, unless the
// stack pointer moves for an object of variable size.
bool SHFrameLowering::hasReservedCallFrame(const MachineFunction &MF) const {
  return !MF.getFrameInfo().hasVarSizedObjects();
}

void SHFrameLowering::adjustStack(MachineBasicBlock &MBB,
                                  MachineBasicBlock::iterator I,
                                  const DebugLoc &DL, int64_t Amount,
                                  Register Scratch,
                                  MachineInstr::MIFlag Flag) const {
  const SHInstrInfo &TII = *STI.getInstrInfo();
  if (!Amount)
    return;
  // One or two additions of an eight bit number.
  if (Amount >= -256 && Amount <= 248) {
    while (Amount) {
      int64_t Step = std::clamp<int64_t>(Amount, -128, 124);
      BuildMI(MBB, I, DL, TII.get(SH::ADDri), SH::R15)
          .addReg(SH::R15)
          .addImm(Step)
          .setMIFlag(Flag);
      Amount -= Step;
    }
    return;
  }
  TII.loadImmediate(MBB, I, DL, Scratch, Amount);
  BuildMI(MBB, I, DL, TII.get(SH::ADDrr), SH::R15)
      .addReg(SH::R15)
      .addReg(Scratch, RegState::Kill)
      .setMIFlag(Flag);
}

static bool isPush(const MachineInstr &MI) {
  return (MI.getOpcode() == SH::PUSH || MI.getOpcode() == SH::PUSHPR) &&
         MI.getFlag(MachineInstr::FrameSetup);
}

static bool isPop(const MachineInstr &MI) {
  return (MI.getOpcode() == SH::POP || MI.getOpcode() == SH::POPPR) &&
         MI.getFlag(MachineInstr::FrameDestroy);
}

void SHFrameLowering::emitPrologue(MachineFunction &MF,
                                   MachineBasicBlock &MBB) const {
  const MachineFrameInfo &MFI = MF.getFrameInfo();
  const SHMachineFunctionInfo *FI = MF.getInfo<SHMachineFunctionInfo>();
  const SHInstrInfo &TII = *STI.getInstrInfo();
  MachineBasicBlock::iterator MBBI = MBB.begin();
  DebugLoc DL;

  int64_t SaveSize = FI->getArgRegSaveSize();
  int64_t PushSize = MFI.getCalleeSavedInfo().size() * 4;
  int64_t LocalSize = MFI.getStackSize() - SaveSize - PushSize;
  assert(LocalSize >= 0 && "the frame is smaller than what is saved in it");

  // The area for the argument registers lies above the pushes.  r1 is free
  // on entry: it carries neither an argument nor the address of a result.
  adjustStack(MBB, MBBI, DL, -SaveSize, SH::R1, MachineInstr::FrameSetup);
  while (MBBI != MBB.end() && isPush(*MBBI))
    ++MBBI;
  auto CopySP = [&](Register To) {
    BuildMI(MBB, MBBI, DL, TII.get(SH::MOVrr), To)
        .addReg(SH::R15)
        .setMIFlag(MachineInstr::FrameSetup);
  };
  if (realignsStack(MF)) {
    // r14 in front of the gap, then the stack pointer rounded down.
    CopySP(SH::R14);
    adjustStack(MBB, MBBI, DL, -LocalSize, SH::R1, MachineInstr::FrameSetup);
    TII.loadImmediate(MBB, MBBI, DL, SH::R1,
                      -int64_t(MFI.getMaxAlign().value()));
    BuildMI(MBB, MBBI, DL, TII.get(SH::ANDrr), SH::R15)
        .addReg(SH::R15)
        .addReg(SH::R1, RegState::Kill)
        .setMIFlag(MachineInstr::FrameSetup);
    if (hasBasePointer(MF))
      CopySP(SH::R13);
    return;
  }
  adjustStack(MBB, MBBI, DL, -LocalSize, SH::R1, MachineInstr::FrameSetup);
  if (hasFP(MF))
    CopySP(SH::R14);
}

void SHFrameLowering::emitEpilogue(MachineFunction &MF,
                                   MachineBasicBlock &MBB) const {
  const MachineFrameInfo &MFI = MF.getFrameInfo();
  const SHMachineFunctionInfo *FI = MF.getInfo<SHMachineFunctionInfo>();
  const SHInstrInfo &TII = *STI.getInstrInfo();
  MachineBasicBlock::iterator MBBI = MBB.getLastNonDebugInstr();
  DebugLoc DL;
  if (MBBI != MBB.end())
    DL = MBBI->getDebugLoc();

  int64_t SaveSize = FI->getArgRegSaveSize();
  int64_t PushSize = MFI.getCalleeSavedInfo().size() * 4;
  int64_t LocalSize = MFI.getStackSize() - SaveSize - PushSize;

  // The return is behind the pops, the locals go in front of them.  r3 is
  // free here: r0 and r1 may hold the result.
  MachineBasicBlock::iterator Return = MBBI;
  MachineBasicBlock::iterator FirstPop = MBBI;
  while (FirstPop != MBB.begin() && isPop(*std::prev(FirstPop)))
    --FirstPop;
  if (hasFP(MF))
    BuildMI(MBB, FirstPop, DL, TII.get(SH::MOVrr), SH::R15)
        .addReg(SH::R14)
        .setMIFlag(MachineInstr::FrameDestroy);
  // r14 was the stack pointer behind the pushes if the stack was realigned,
  // and at the end of the frame otherwise.
  if (!realignsStack(MF))
    adjustStack(MBB, FirstPop, DL, LocalSize, SH::R3,
                MachineInstr::FrameDestroy);
  adjustStack(MBB, Return, DL, SaveSize, SH::R3, MachineInstr::FrameDestroy);
}

MachineBasicBlock::iterator SHFrameLowering::eliminateCallFramePseudoInstr(
    MachineFunction &MF, MachineBasicBlock &MBB,
    MachineBasicBlock::iterator I) const {
  const SHInstrInfo &TII = *STI.getInstrInfo();
  if (!hasReservedCallFrame(MF)) {
    int64_t Amount = I->getOperand(0).getImm();
    if (I->getOpcode() == SH::ADJCALLSTACKDOWN)
      Amount = -Amount;
    // Between the arguments and the call nothing is free but the registers
    // that a call destroys and that carry nothing: r1 before the call,
    // r3 after it, as in the prologue and the epilogue.
    adjustStack(MBB, I, I->getDebugLoc(), Amount,
                I->getOpcode() == SH::ADJCALLSTACKDOWN ? SH::R1 : SH::R3,
                MachineInstr::NoFlags);
  }
  (void)TII;
  return MBB.erase(I);
}

// The registers are pushed in the order of the list.  That is the order in
// which the slots were laid out, from high addresses to low ones.
bool SHFrameLowering::spillCalleeSavedRegisters(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator MI,
    ArrayRef<CalleeSavedInfo> CSI, const TargetRegisterInfo *TRI) const {
  if (CSI.empty())
    return false;
  const SHInstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL;
  if (MI != MBB.end())
    DL = MI->getDebugLoc();
  for (const CalleeSavedInfo &I : CSI) {
    MCRegister Reg = I.getReg();
    if (Reg == SH::PR) {
      BuildMI(MBB, MI, DL, TII.get(SH::PUSHPR))
          .setMIFlag(MachineInstr::FrameSetup);
      continue;
    }
    MBB.addLiveIn(Reg);
    BuildMI(MBB, MI, DL, TII.get(SH::PUSH))
        .addReg(Reg, RegState::Kill)
        .setMIFlag(MachineInstr::FrameSetup);
  }
  return true;
}

bool SHFrameLowering::restoreCalleeSavedRegisters(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator MI,
    MutableArrayRef<CalleeSavedInfo> CSI, const TargetRegisterInfo *TRI) const {
  if (CSI.empty())
    return false;
  const SHInstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL;
  if (MI != MBB.end())
    DL = MI->getDebugLoc();
  for (const CalleeSavedInfo &I : reverse(CSI)) {
    MCRegister Reg = I.getReg();
    if (Reg == SH::PR)
      BuildMI(MBB, MI, DL, TII.get(SH::POPPR))
          .setMIFlag(MachineInstr::FrameDestroy);
    else
      BuildMI(MBB, MI, DL, TII.get(SH::POP), Reg)
          .setMIFlag(MachineInstr::FrameDestroy);
  }
  return true;
}

void SHFrameLowering::determineCalleeSaves(MachineFunction &MF,
                                           BitVector &SavedRegs,
                                           RegScavenger *RS) const {
  TargetFrameLowering::determineCalleeSaves(MF, SavedRegs, RS);
  if (hasFP(MF))
    SavedRegs.set(SH::R14);
  if (hasBasePointer(MF))
    SavedRegs.set(SH::R13);
}
