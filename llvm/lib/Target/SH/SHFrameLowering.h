//===-- SHFrameLowering.h - The stack frame of a SuperH function -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SH_SHFRAMELOWERING_H
#define LLVM_LIB_TARGET_SH_SHFRAMELOWERING_H

#include "llvm/CodeGen/TargetFrameLowering.h"

namespace llvm {

class SHSubtarget;

class SHFrameLowering : public TargetFrameLowering {
  const SHSubtarget &STI;

  /// "add #Amount,r15", in more than one step or through \p Scratch if
  /// the number does not fit.
  void adjustStack(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                   const DebugLoc &DL, int64_t Amount, Register Scratch,
                   MachineInstr::MIFlag Flag) const;

protected:
  bool hasFPImpl(const MachineFunction &MF) const override;

public:
  explicit SHFrameLowering(const SHSubtarget &STI);

  void emitPrologue(MachineFunction &MF, MachineBasicBlock &MBB) const override;
  void emitEpilogue(MachineFunction &MF, MachineBasicBlock &MBB) const override;

  MachineBasicBlock::iterator
  eliminateCallFramePseudoInstr(MachineFunction &MF, MachineBasicBlock &MBB,
                                MachineBasicBlock::iterator I) const override;

  bool spillCalleeSavedRegisters(MachineBasicBlock &MBB,
                                 MachineBasicBlock::iterator MI,
                                 ArrayRef<CalleeSavedInfo> CSI,
                                 const TargetRegisterInfo *TRI) const override;
  bool
  restoreCalleeSavedRegisters(MachineBasicBlock &MBB,
                              MachineBasicBlock::iterator MI,
                              MutableArrayRef<CalleeSavedInfo> CSI,
                              const TargetRegisterInfo *TRI) const override;

  void determineCalleeSaves(MachineFunction &MF, BitVector &SavedRegs,
                            RegScavenger *RS) const override;

  bool hasReservedCallFrame(const MachineFunction &MF) const override;

  /// The function has a local variable that wants more alignment than the
  /// stack has, and gives it to the stack pointer in its prologue.  r14
  /// then points to the saved registers instead of the end of the frame.
  bool realignsStack(const MachineFunction &MF) const;
  /// In such a function r13 takes the place of the stack pointer as the
  /// base of the local variables if the stack pointer moves.
  bool hasBasePointer(const MachineFunction &MF) const;
};

} // namespace llvm

#endif
