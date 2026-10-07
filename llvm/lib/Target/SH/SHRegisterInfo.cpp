//===-- SHRegisterInfo.cpp - SuperH registers -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SHRegisterInfo.h"
#include "SHFrameLowering.h"
#include "SHInstrInfo.h"
#include "SHMachineFunctionInfo.h"
#include "SHSubtarget.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/RegisterScavenging.h"
#include "llvm/Support/ErrorHandling.h"

using namespace llvm;

#define DEBUG_TYPE "sh-reg-info"

#define GET_REGINFO_TARGET_DESC
#include "SHGenRegisterInfo.inc"

SHRegisterInfo::SHRegisterInfo() : SHGenRegisterInfo(SH::PR) {}

static const SHFrameLowering *getSHFrameLowering(const MachineFunction &MF) {
  return static_cast<const SHFrameLowering *>(
      MF.getSubtarget().getFrameLowering());
}

// With a floating point unit fr12 to fr15 are saved by the callee.
const MCPhysReg *
SHRegisterInfo::getCalleeSavedRegs(const MachineFunction *MF) const {
  return MF->getSubtarget<SHSubtarget>().hasFPU() ? CSR_SH_FPU_SaveList
                                                  : CSR_SH_SaveList;
}

const uint32_t *SHRegisterInfo::getCallPreservedMask(const MachineFunction &MF,
                                                     CallingConv::ID) const {
  return MF.getSubtarget<SHSubtarget>().hasFPU() ? CSR_SH_FPU_RegMask
                                                 : CSR_SH_RegMask;
}

BitVector SHRegisterInfo::getReservedRegs(const MachineFunction &MF) const {
  BitVector Reserved(getNumRegs());
  Reserved.set(SH::R15);
  Reserved.set(SH::PR);
  Reserved.set(SH::GBR);
  Reserved.set(SH::MACH);
  Reserved.set(SH::MACL);
  Reserved.set(SH::T);
  Reserved.set(SH::FPUL);
  Reserved.set(SH::FPSCR);
  const SHFrameLowering *TFI = getSHFrameLowering(MF);
  if (TFI->hasFP(MF))
    Reserved.set(SH::R14);
  if (TFI->hasBasePointer(MF))
    Reserved.set(SH::R13);
  return Reserved;
}

Register SHRegisterInfo::getFrameRegister(const MachineFunction &MF) const {
  return getFrameLowering(MF)->hasFP(MF) ? SH::R14 : SH::R15;
}

// The frame pointer, where there is one, has the value that the stack
// pointer has behind the prologue.  So a stack slot has one offset, the one
// from the lowest address of the frame.  A function that realigns its stack
// is different: see SHFrameLowering.cpp.
bool SHRegisterInfo::eliminateFrameIndex(MachineBasicBlock::iterator II,
                                         int SPAdj, unsigned FIOperandNum,
                                         RegScavenger *RS) const {
  MachineInstr &MI = *II;
  MachineBasicBlock &MBB = *MI.getParent();
  MachineFunction &MF = *MBB.getParent();
  const MachineFrameInfo &MFI = MF.getFrameInfo();
  const SHInstrInfo &TII = *MF.getSubtarget<SHSubtarget>().getInstrInfo();
  DebugLoc DL = MI.getDebugLoc();

  int FrameIndex = MI.getOperand(FIOperandNum).getIndex();
  const SHFrameLowering *TFI = getSHFrameLowering(MF);
  Register FrameReg = getFrameRegister(MF);
  int64_t Offset = MFI.getObjectOffset(FrameIndex) + MFI.getStackSize() +
                   MI.getOperand(FIOperandNum + 1).getImm();
  if (TFI->realignsStack(MF)) {
    if (MFI.isFixedObjectIndex(FrameIndex)) {
      // What the caller put there, from r14: that is where the stack
      // pointer was when the registers had been pushed.
      const SHMachineFunctionInfo *FI = MF.getInfo<SHMachineFunctionInfo>();
      FrameReg = SH::R14;
      Offset = MFI.getObjectOffset(FrameIndex) + FI->getArgRegSaveSize() +
               MFI.getCalleeSavedInfo().size() * 4 +
               MI.getOperand(FIOperandNum + 1).getImm();
    } else {
      FrameReg = TFI->hasBasePointer(MF) ? SH::R13 : SH::R15;
    }
  }
  // With the stack pointer as the base, what a call sequence has taken
  // from the stack counts.
  if (FrameReg == SH::R15)
    Offset += SPAdj;

  unsigned Opc = MI.getOpcode();

  // The floating point unit has no displacement at all.  The address goes
  // into a general register, one that is free or one that is pushed and
  // popped.
  if (Opc == SH::FLDFI || Opc == SH::FSTFI || Opc == SH::DLDFI ||
      Opc == SH::DSTFI) {
    Register Value = MI.getOperand(0).getReg();
    bool IsDouble = Opc == SH::DLDFI || Opc == SH::DSTFI;
    bool IsLoad = Opc == SH::FLDFI || Opc == SH::DLDFI;
    if (!IsDouble && Offset == 0) {
      if (IsLoad)
        BuildMI(MBB, II, DL, TII.get(SH::FMOVSld), Value).addReg(FrameReg);
      else
        BuildMI(MBB, II, DL, TII.get(SH::FMOVSst))
            .addReg(Value, getKillRegState(MI.getOperand(0).isKill()))
            .addReg(FrameReg);
      MI.eraseFromParent();
      return true;
    }
    Register Scratch;
    bool Pushed = false;
    if (RS)
      Scratch = RS->scavengeRegisterBackwards(SH::GPRRegClass, II,
                                              /*RestoreAfter=*/false, SPAdj,
                                              /*AllowSpill=*/false);
    if (!Scratch) {
      Scratch = SH::R1;
      BuildMI(MBB, II, DL, TII.get(SH::PUSH)).addReg(Scratch);
      Pushed = true;
      if (FrameReg == SH::R15)
        Offset += 4;
    }
    if (isInt<8>(Offset)) {
      BuildMI(MBB, II, DL, TII.get(SH::MOVrr), Scratch).addReg(FrameReg);
      if (Offset)
        BuildMI(MBB, II, DL, TII.get(SH::ADDri), Scratch)
            .addReg(Scratch)
            .addImm(Offset);
    } else {
      TII.loadImmediate(MBB, II, DL, Scratch, Offset);
      BuildMI(MBB, II, DL, TII.get(SH::ADDrr), Scratch)
          .addReg(Scratch)
          .addReg(FrameReg);
    }
    if (!IsDouble) {
      if (IsLoad)
        BuildMI(MBB, II, DL, TII.get(SH::FMOVSld), Value).addReg(Scratch);
      else
        BuildMI(MBB, II, DL, TII.get(SH::FMOVSst))
            .addReg(Value)
            .addReg(Scratch);
    } else if (IsLoad) {
      // The half with the lower address first.
      BuildMI(MBB, II, DL, TII.get(SH::FMOVSldinc), TII.firstHalf(MBB, Value))
          .addReg(Scratch, RegState::Define)
          .addReg(Scratch);
      BuildMI(MBB, II, DL, TII.get(SH::FMOVSld), TII.secondHalf(MBB, Value))
          .addReg(Scratch);
    } else {
      BuildMI(MBB, II, DL, TII.get(SH::FMOVSst))
          .addReg(TII.firstHalf(MBB, Value))
          .addReg(Scratch);
      BuildMI(MBB, II, DL, TII.get(SH::ADDri), Scratch)
          .addReg(Scratch)
          .addImm(4);
      BuildMI(MBB, II, DL, TII.get(SH::FMOVSst))
          .addReg(TII.secondHalf(MBB, Value))
          .addReg(Scratch);
    }
    if (Pushed)
      BuildMI(MBB, II, DL, TII.get(SH::POP), Scratch);
    MI.eraseFromParent();
    return true;
  }

  if (Opc == SH::LEAFI) {
    Register Dst = MI.getOperand(0).getReg();
    if (isInt<8>(Offset)) {
      BuildMI(MBB, II, DL, TII.get(SH::MOVrr), Dst).addReg(FrameReg);
      if (Offset)
        BuildMI(MBB, II, DL, TII.get(SH::ADDri), Dst)
            .addReg(Dst, RegState::Kill)
            .addImm(Offset);
    } else {
      TII.loadImmediate(MBB, II, DL, Dst, Offset);
      BuildMI(MBB, II, DL, TII.get(SH::ADDrr), Dst)
          .addReg(Dst, RegState::Kill)
          .addReg(FrameReg);
    }
    MI.eraseFromParent();
    return true;
  }

  bool IsLong = Opc == SH::MOVLld || Opc == SH::MOVLst;
  bool IsLoad = Opc == SH::MOVLld || Opc == SH::MOVWld || Opc == SH::MOVBld;
  assert((IsLong || Opc == SH::MOVWld || Opc == SH::MOVWst ||
          Opc == SH::MOVBld || Opc == SH::MOVBst) &&
         "frame index in an unexpected instruction");

  if (Offset == 0 ||
      (IsLong && Offset > 0 && Offset <= 60 && (Offset & 3) == 0)) {
    MI.getOperand(FIOperandNum).ChangeToRegister(FrameReg, false);
    MI.getOperand(FIOperandNum + 1).ChangeToImmediate(Offset);
    return false;
  }

  // Out of reach: the address goes into a register first.  A load can use
  // its destination.  A store takes a register that is free, and if none
  // is, one that is pushed and popped around it.
  Register Scratch;
  bool Pushed = false;
  if (IsLoad) {
    Scratch = MI.getOperand(0).getReg();
  } else {
    Register Src = MI.getOperand(0).getReg();
    if (RS)
      Scratch = RS->scavengeRegisterBackwards(SH::GPRRegClass, II,
                                              /*RestoreAfter=*/false, SPAdj,
                                              /*AllowSpill=*/false);
    if (!Scratch) {
      Scratch = Src == SH::R1 ? SH::R2 : SH::R1;
      BuildMI(MBB, II, DL, TII.get(SH::PUSH)).addReg(Scratch);
      Pushed = true;
      if (FrameReg == SH::R15)
        Offset += 4;
    }
  }
  TII.loadImmediate(MBB, II, DL, Scratch, Offset);
  BuildMI(MBB, II, DL, TII.get(SH::ADDrr), Scratch)
      .addReg(Scratch, RegState::Kill)
      .addReg(FrameReg);
  MI.getOperand(FIOperandNum)
      .ChangeToRegister(Scratch, false, false, /*isKill=*/!IsLoad);
  MI.getOperand(FIOperandNum + 1).ChangeToImmediate(0);
  if (Pushed)
    BuildMI(MBB, std::next(II), DL, TII.get(SH::POP), Scratch);
  return false;
}
