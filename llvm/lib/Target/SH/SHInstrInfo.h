//===-- SHInstrInfo.h - SuperH instructions -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SH_SHINSTRINFO_H
#define LLVM_LIB_TARGET_SH_SHINSTRINFO_H

#include "MCTargetDesc/SHMCTargetDesc.h"
#include "SHRegisterInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"

#define GET_INSTRINFO_HEADER
#include "SHGenInstrInfo.inc"

namespace llvm {

class SHSubtarget;

namespace SH {
/// A number that does not fit the eight bits of an immediate but is one
/// instruction away from a number that does: MOVI2 makes it in a register
/// with two instructions, where a literal is an instruction, four bytes of
/// data and a load.  None of the second instructions changes T.
enum class TwoInsnImm {
  None,
  /// 128 to 255: "mov #imm,Rn; extu.b Rn,Rn".
  ZExt8,
  /// 65408 to 65535: "mov #imm,Rn; extu.w Rn,Rn".
  ZExt16,
  /// Twice a number: "mov #imm,Rn; add Rn,Rn".
  Shl1,
  /// "mov #imm,Rn" and shll2, shll8 or shll16.
  Shl2,
  Shl8,
  Shl16,
};

/// Which of these \p Imm is, and the immediate of the mov.
inline TwoInsnImm classifyTwoInsnImm(int64_t Imm, int64_t &First) {
  if (isInt<8>(Imm) || !isInt<32>(Imm))
    return TwoInsnImm::None;
  if (Imm >= 128 && Imm <= 255) {
    First = Imm - 256;
    return TwoInsnImm::ZExt8;
  }
  if (Imm >= 65408 && Imm <= 65535) {
    First = Imm - 65536;
    return TwoInsnImm::ZExt16;
  }
  static const std::pair<unsigned, TwoInsnImm> Shifts[] = {
      {1, TwoInsnImm::Shl1},
      {2, TwoInsnImm::Shl2},
      {8, TwoInsnImm::Shl8},
      {16, TwoInsnImm::Shl16},
  };
  for (auto [Amount, Kind] : Shifts)
    if (Imm % (int64_t(1) << Amount) == 0 && isInt<8>(Imm >> Amount)) {
      First = Imm >> Amount;
      return Kind;
    }
  return TwoInsnImm::None;
}
} // namespace SH

class SHInstrInfo : public SHGenInstrInfo {
  const SHRegisterInfo RI;
  virtual void anchor();

public:
  explicit SHInstrInfo(const SHSubtarget &STI);

  const SHRegisterInfo &getRegisterInfo() const { return RI; }

  void copyPhysReg(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                   const DebugLoc &DL, Register DestReg, Register SrcReg,
                   bool KillSrc, bool RenamableDest = false,
                   bool RenamableSrc = false) const override;
  void storeRegToStackSlot(
      MachineBasicBlock &MBB, MachineBasicBlock::iterator MI, Register SrcReg,
      bool IsKill, int FrameIndex, const TargetRegisterClass *RC, Register VReg,
      MachineInstr::MIFlag Flags = MachineInstr::NoFlags) const override;
  void loadRegFromStackSlot(
      MachineBasicBlock &MBB, MachineBasicBlock::iterator MI, Register DestReg,
      int FrameIndex, const TargetRegisterClass *RC, Register VReg,
      unsigned SubReg = 0,
      MachineInstr::MIFlag Flags = MachineInstr::NoFlags) const override;

  unsigned getInstSizeInBytes(const MachineInstr &MI) const override;

  bool analyzeBranch(MachineBasicBlock &MBB, MachineBasicBlock *&TBB,
                     MachineBasicBlock *&FBB,
                     SmallVectorImpl<MachineOperand> &Cond,
                     bool AllowModify) const override;
  unsigned removeBranch(MachineBasicBlock &MBB,
                        int *BytesRemoved = nullptr) const override;
  unsigned insertBranch(MachineBasicBlock &MBB, MachineBasicBlock *TBB,
                        MachineBasicBlock *FBB, ArrayRef<MachineOperand> Cond,
                        const DebugLoc &DL,
                        int *BytesAdded = nullptr) const override;
  bool
  reverseBranchCondition(SmallVectorImpl<MachineOperand> &Cond) const override;

  bool expandPostRAPseudo(MachineInstr &MI) const override;

  /// The names of the target flags of an operand, for machine code as text.
  std::pair<unsigned, unsigned>
  decomposeMachineOperandsTargetFlags(unsigned TF) const override;
  ArrayRef<std::pair<unsigned, const char *>>
  getSerializableDirectMachineOperandTargetFlags() const override;

  /// The half of a double that has the lower address in memory, and the
  /// other one.
  Register firstHalf(const MachineBasicBlock &MBB, Register Reg) const;
  Register secondHalf(const MachineBasicBlock &MBB, Register Reg) const;

  /// Put the number \p Value into \p Reg, in front of \p I, without a
  /// change to the T bit.
  void loadImmediate(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                     const DebugLoc &DL, Register Reg, int64_t Value) const;
};

} // namespace llvm

#endif
