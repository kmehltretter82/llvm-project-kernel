//===-- SHRegisterInfo.h - SuperH registers -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SH_SHREGISTERINFO_H
#define LLVM_LIB_TARGET_SH_SHREGISTERINFO_H

#include "llvm/CodeGen/TargetRegisterInfo.h"

#define GET_REGINFO_HEADER
#include "SHGenRegisterInfo.inc"

namespace llvm {

class SHRegisterInfo : public SHGenRegisterInfo {
public:
  SHRegisterInfo();

  const MCPhysReg *getCalleeSavedRegs(const MachineFunction *MF) const override;
  const uint32_t *getCallPreservedMask(const MachineFunction &MF,
                                       CallingConv::ID) const override;
  BitVector getReservedRegs(const MachineFunction &MF) const override;

  // A stack slot that is out of reach of a displacement needs a register
  // for its address.  One that happens to be free is asked for.
  bool requiresRegisterScavenging(const MachineFunction &MF) const override {
    return true;
  }
  bool eliminateFrameIndex(MachineBasicBlock::iterator II, int SPAdj,
                           unsigned FIOperandNum,
                           RegScavenger *RS = nullptr) const override;
  Register getFrameRegister(const MachineFunction &MF) const override;
};

} // namespace llvm

#endif
