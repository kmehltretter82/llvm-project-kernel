//===-- SHInstrInfo.cpp - SuperH instructions -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SHInstrInfo.h"
#include "MCTargetDesc/SHMCAsmInfo.h"
#include "SHSubtarget.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Target/TargetMachine.h"

using namespace llvm;

#define GET_INSTRINFO_CTOR_DTOR
#include "SHGenInstrInfo.inc"

void SHInstrInfo::anchor() {}

SHInstrInfo::SHInstrInfo(const SHSubtarget &STI)
    : SHGenInstrInfo(STI, RI, SH::ADJCALLSTACKDOWN, SH::ADJCALLSTACKUP), RI() {}

void SHInstrInfo::copyPhysReg(MachineBasicBlock &MBB,
                              MachineBasicBlock::iterator I, const DebugLoc &DL,
                              Register DestReg, Register SrcReg, bool KillSrc,
                              bool RenamableDest, bool RenamableSrc) const {
  bool DestGPR = SH::GPRRegClass.contains(DestReg);
  bool SrcGPR = SH::GPRRegClass.contains(SrcReg);
  if (DestGPR && SrcGPR) {
    BuildMI(MBB, I, DL, get(SH::MOVrr), DestReg)
        .addReg(SrcReg, getKillRegState(KillSrc));
    return;
  }
  if (SH::FPRRegClass.contains(DestReg, SrcReg)) {
    BuildMI(MBB, I, DL, get(SH::FMOV), DestReg)
        .addReg(SrcReg, getKillRegState(KillSrc));
    return;
  }
  // A double is two registers, and fmov moves one.
  if (SH::DFPRRegClass.contains(DestReg, SrcReg)) {
    for (unsigned Half : {SH::sub_fhi, SH::sub_flo})
      BuildMI(MBB, I, DL, get(SH::FMOV), RI.getSubReg(DestReg, Half))
          .addReg(RI.getSubReg(SrcReg, Half));
    return;
  }
  // To and from the system registers.
  unsigned Opc = 0;
  if (DestGPR) {
    Opc = SrcReg == SH::PR     ? SH::STSPR
          : SrcReg == SH::MACL ? SH::STSMACL
          : SrcReg == SH::MACH ? SH::STSMACH
          : SrcReg == SH::GBR  ? SH::STCGBR
                               : 0;
    if (Opc) {
      BuildMI(MBB, I, DL, get(Opc), DestReg);
      return;
    }
  } else if (SrcGPR) {
    Opc = DestReg == SH::PR     ? SH::LDSPR
          : DestReg == SH::MACL ? SH::LDSMACL
          : DestReg == SH::MACH ? SH::LDSMACH
          : DestReg == SH::GBR  ? SH::LDCGBR
                                : 0;
    if (Opc) {
      BuildMI(MBB, I, DL, get(Opc)).addReg(SrcReg, getKillRegState(KillSrc));
      return;
    }
  }
  llvm_unreachable("cannot copy between these registers");
}

void SHInstrInfo::storeRegToStackSlot(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator MI, Register SrcReg,
    bool IsKill, int FrameIndex, const TargetRegisterClass *RC, Register VReg,
    MachineInstr::MIFlag Flags) const {
  DebugLoc DL;
  if (MI != MBB.end())
    DL = MI->getDebugLoc();
  unsigned Opc = SH::GPRRegClass.hasSubClassEq(RC)    ? SH::MOVLst
                 : SH::FPRRegClass.hasSubClassEq(RC)  ? SH::FSTFI
                 : SH::DFPRRegClass.hasSubClassEq(RC) ? SH::DSTFI
                                                      : 0;
  assert(Opc && "cannot store this register");
  BuildMI(MBB, MI, DL, get(Opc))
      .addReg(SrcReg, getKillRegState(IsKill))
      .addFrameIndex(FrameIndex)
      .addImm(0)
      .setMIFlag(Flags);
}

void SHInstrInfo::loadRegFromStackSlot(MachineBasicBlock &MBB,
                                       MachineBasicBlock::iterator MI,
                                       Register DestReg, int FrameIndex,
                                       const TargetRegisterClass *RC,
                                       Register VReg, unsigned SubReg,
                                       MachineInstr::MIFlag Flags) const {
  DebugLoc DL;
  if (MI != MBB.end())
    DL = MI->getDebugLoc();
  unsigned Opc = SH::GPRRegClass.hasSubClassEq(RC)    ? SH::MOVLld
                 : SH::FPRRegClass.hasSubClassEq(RC)  ? SH::FLDFI
                 : SH::DFPRRegClass.hasSubClassEq(RC) ? SH::DLDFI
                                                      : 0;
  assert(Opc && "cannot load this register");
  BuildMI(MBB, MI, DL, get(Opc), DestReg)
      .addFrameIndex(FrameIndex)
      .addImm(0)
      .setMIFlag(Flags);
}

unsigned SHInstrInfo::getInstSizeInBytes(const MachineInstr &MI) const {
  switch (MI.getOpcode()) {
  case TargetOpcode::INLINEASM:
  case TargetOpcode::INLINEASM_BR: {
    const MachineFunction *MF = MI.getParent()->getParent();
    return getInlineAsmLength(MI.getOperand(0).getSymbolName(),
                              MF->getTarget().getMCAsmInfo());
  }
  default:
    if (MI.isMetaInstruction())
      return 0;
    return MI.getDesc().getSize();
  }
}

//===----------------------------------------------------------------------===//
// Branches.  The condition is one number: 1 for "branch if T is set", 0 for
// "branch if T is clear".
//===----------------------------------------------------------------------===//

bool SHInstrInfo::analyzeBranch(MachineBasicBlock &MBB, MachineBasicBlock *&TBB,
                                MachineBasicBlock *&FBB,
                                SmallVectorImpl<MachineOperand> &Cond,
                                bool AllowModify) const {
  MachineBasicBlock::iterator I = MBB.end();
  while (I != MBB.begin()) {
    --I;
    if (I->isDebugInstr())
      continue;
    if (!isUnpredicatedTerminator(*I))
      break;
    unsigned Opc = I->getOpcode();
    if (Opc != SH::BRA && Opc != SH::BT && Opc != SH::BF)
      return true;

    if (Opc == SH::BRA) {
      if (!AllowModify) {
        TBB = I->getOperand(0).getMBB();
        continue;
      }
      // Nothing behind an unconditional branch is reached.
      MBB.erase(std::next(I), MBB.end());
      Cond.clear();
      FBB = nullptr;
      if (MBB.isLayoutSuccessor(I->getOperand(0).getMBB())) {
        TBB = nullptr;
        I->eraseFromParent();
        I = MBB.end();
        continue;
      }
      TBB = I->getOperand(0).getMBB();
      continue;
    }

    // A second conditional branch is more than this can describe.
    if (!Cond.empty())
      return true;
    FBB = TBB;
    TBB = I->getOperand(0).getMBB();
    Cond.push_back(MachineOperand::CreateImm(Opc == SH::BT));
  }
  return false;
}

unsigned SHInstrInfo::removeBranch(MachineBasicBlock &MBB,
                                   int *BytesRemoved) const {
  assert(!BytesRemoved && "code size not handled");
  MachineBasicBlock::iterator I = MBB.end();
  unsigned Count = 0;
  while (I != MBB.begin()) {
    --I;
    if (I->isDebugInstr())
      continue;
    unsigned Opc = I->getOpcode();
    if (Opc != SH::BRA && Opc != SH::BT && Opc != SH::BF)
      break;
    I->eraseFromParent();
    I = MBB.end();
    ++Count;
  }
  return Count;
}

unsigned SHInstrInfo::insertBranch(MachineBasicBlock &MBB,
                                   MachineBasicBlock *TBB,
                                   MachineBasicBlock *FBB,
                                   ArrayRef<MachineOperand> Cond,
                                   const DebugLoc &DL, int *BytesAdded) const {
  assert(TBB && "insertBranch must not be told to insert a fallthrough");
  assert(Cond.size() <= 1 && "a SuperH branch condition is one number");
  assert(!BytesAdded && "code size not handled");

  if (Cond.empty()) {
    assert(!FBB && "unconditional branch with two targets");
    BuildMI(&MBB, DL, get(SH::BRA)).addMBB(TBB);
    return 1;
  }
  BuildMI(&MBB, DL, get(Cond[0].getImm() ? SH::BT : SH::BF)).addMBB(TBB);
  if (!FBB)
    return 1;
  BuildMI(&MBB, DL, get(SH::BRA)).addMBB(FBB);
  return 2;
}

bool SHInstrInfo::reverseBranchCondition(
    SmallVectorImpl<MachineOperand> &Cond) const {
  assert(Cond.size() == 1 && "a SuperH branch condition is one number");
  Cond[0].setImm(!Cond[0].getImm());
  return false;
}

//===----------------------------------------------------------------------===//
// Pseudo instructions
//===----------------------------------------------------------------------===//

// The half of a double that has the lower address in memory, and the
// other one.
Register SHInstrInfo::firstHalf(const MachineBasicBlock &MBB,
                                Register Reg) const {
  bool Little = MBB.getParent()->getDataLayout().isLittleEndian();
  return RI.getSubReg(Reg, Little ? SH::sub_flo : SH::sub_fhi);
}

Register SHInstrInfo::secondHalf(const MachineBasicBlock &MBB,
                                 Register Reg) const {
  bool Little = MBB.getParent()->getDataLayout().isLittleEndian();
  return RI.getSubReg(Reg, Little ? SH::sub_fhi : SH::sub_flo);
}

bool SHInstrInfo::expandPostRAPseudo(MachineInstr &MI) const {
  MachineBasicBlock &MBB = *MI.getParent();
  DebugLoc DL = MI.getDebugLoc();
  switch (MI.getOpcode()) {
  default:
    return false;
  case SH::MUL32:
  case SH::MULHU32:
  case SH::MULHS32: {
    // The product is in MACL or MACH, whatever the registers of the
    // operands are.
    unsigned Mul = MI.getOpcode() == SH::MUL32     ? SH::MULL
                   : MI.getOpcode() == SH::MULHU32 ? SH::DMULU
                                                   : SH::DMULS;
    Register Dst = MI.getOperand(0).getReg();
    BuildMI(MBB, MI, DL, get(Mul))
        .addReg(MI.getOperand(1).getReg(),
                getKillRegState(MI.getOperand(1).isKill()))
        .addReg(MI.getOperand(2).getReg(),
                getKillRegState(MI.getOperand(2).isKill()));
    BuildMI(MBB, MI, DL,
            get(MI.getOpcode() == SH::MUL32 ? SH::STSMACL : SH::STSMACH), Dst);
    break;
  }
  case SH::MOVRT: {
    // 0 - (-1) - T
    Register Dst = MI.getOperand(0).getReg();
    BuildMI(MBB, MI, DL, get(SH::MOVI), Dst).addImm(-1);
    BuildMI(MBB, MI, DL, get(SH::NEGC), Dst).addReg(Dst, RegState::Kill);
    break;
  }

  // Between the floating point unit and the general registers, and
  // between float and double: through FPUL.
  case SH::MOVR2F:
  case SH::FLOATS:
  case SH::FLOATD: {
    unsigned Out = MI.getOpcode() == SH::MOVR2F   ? SH::FSTS
                   : MI.getOpcode() == SH::FLOATS ? SH::FLOATfpulS
                                                  : SH::FLOATfpulD;
    BuildMI(MBB, MI, DL, get(SH::LDSFPUL)).add(MI.getOperand(1));
    BuildMI(MBB, MI, DL, get(Out), MI.getOperand(0).getReg());
    break;
  }
  case SH::MOVF2R:
  case SH::FTRCS:
  case SH::FTRCD: {
    unsigned In = MI.getOpcode() == SH::MOVF2R  ? SH::FLDS
                  : MI.getOpcode() == SH::FTRCS ? SH::FTRCfpulS
                                                : SH::FTRCfpulD;
    BuildMI(MBB, MI, DL, get(In)).add(MI.getOperand(1));
    BuildMI(MBB, MI, DL, get(SH::STSFPUL), MI.getOperand(0).getReg());
    break;
  }
  case SH::FCNVSD:
    BuildMI(MBB, MI, DL, get(SH::FLDS)).add(MI.getOperand(1));
    BuildMI(MBB, MI, DL, get(SH::FCNVSDfpul), MI.getOperand(0).getReg());
    break;
  case SH::FCNVDS:
    BuildMI(MBB, MI, DL, get(SH::FCNVDSfpul)).add(MI.getOperand(1));
    BuildMI(MBB, MI, DL, get(SH::FSTS), MI.getOperand(0).getReg());
    break;

  // A double in memory: the half with the lower address first.  The
  // register with the address moves and comes back.
  case SH::FMOVDld: {
    Register Dst = MI.getOperand(0).getReg();
    Register Base = MI.getOperand(1).getReg();
    BuildMI(MBB, MI, DL, get(SH::FMOVSldinc), firstHalf(MBB, Dst))
        .addReg(Base, RegState::Define)
        .addReg(Base);
    BuildMI(MBB, MI, DL, get(SH::FMOVSld), secondHalf(MBB, Dst)).addReg(Base);
    BuildMI(MBB, MI, DL, get(SH::ADDri), Base).addReg(Base).addImm(-4);
    break;
  }
  case SH::FMOVDst: {
    Register Src = MI.getOperand(0).getReg();
    Register Base = MI.getOperand(1).getReg();
    BuildMI(MBB, MI, DL, get(SH::ADDri), Base).addReg(Base).addImm(8);
    for (Register Half : {secondHalf(MBB, Src), firstHalf(MBB, Src)})
      BuildMI(MBB, MI, DL, get(SH::FMOVSstdec), Base).addReg(Half).addReg(Base);
    break;
  }
  }
  MI.eraseFromParent();
  return true;
}

void SHInstrInfo::loadImmediate(MachineBasicBlock &MBB,
                                MachineBasicBlock::iterator I,
                                const DebugLoc &DL, Register Reg,
                                int64_t Value) const {
  Value = SignExtend64<32>(Value);
  if (isInt<8>(Value)) {
    BuildMI(MBB, I, DL, get(SH::MOVI), Reg).addImm(Value);
    return;
  }
  // An eight bit number that is shifted.  shll2, shll8 and shll16 leave T
  // alone.
  static const std::pair<unsigned, unsigned> Shifts[] = {
      {2, SH::SHLL2}, {8, SH::SHLL8}, {16, SH::SHLL16}};
  for (auto [Amount, Opc] : Shifts) {
    int64_t Mask = (int64_t(1) << Amount) - 1;
    if ((Value & Mask) == 0 && isInt<8>(Value >> Amount)) {
      BuildMI(MBB, I, DL, get(SH::MOVI), Reg).addImm(Value >> Amount);
      BuildMI(MBB, I, DL, get(Opc), Reg).addReg(Reg, RegState::Kill);
      return;
    }
  }
  BuildMI(MBB, I, DL, get(SH::MOVLpcrel), Reg).addImm(Value);
}

//===----------------------------------------------------------------------===//
// Target flags: what stands behind the "@" of a symbol in a literal.
//===----------------------------------------------------------------------===//

std::pair<unsigned, unsigned>
SHInstrInfo::decomposeMachineOperandsTargetFlags(unsigned TF) const {
  return {TF, 0u};
}

ArrayRef<std::pair<unsigned, const char *>>
SHInstrInfo::getSerializableDirectMachineOperandTargetFlags() const {
  static const std::pair<unsigned, const char *> Flags[] = {
      {SH::S_GOT, "sh-got"},           {SH::S_GOTOFF, "sh-gotoff"},
      {SH::S_PLT, "sh-plt"},           {SH::S_TPOFF, "sh-tpoff"},
      {SH::S_GOTTPOFF, "sh-gottpoff"}, {SH::S_TLSGD, "sh-tlsgd"},
      {SH::S_TLSLDM, "sh-tlsldm"},     {SH::S_DTPOFF, "sh-dtpoff"},
  };
  return ArrayRef(Flags);
}
