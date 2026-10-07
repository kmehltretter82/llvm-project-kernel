//===-- SHMCCodeEmitter.cpp - SuperH instructions as bytes ----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Every instruction is sixteen bits, written in the byte order of the
// target.  What tablegen makes of the encodings in SHInstrInfo.td puts the
// registers in place.  The numbers are checked and scaled here, and what
// is not a number yet becomes a fixup.
//
//===----------------------------------------------------------------------===//

#include "SHFixupKinds.h"
#include "SHMCTargetDesc.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/EndianStream.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/TargetParser/Triple.h"

using namespace llvm;

namespace {

class SHMCCodeEmitter : public MCCodeEmitter {
public:
  SHMCCodeEmitter(MCContext &Ctx, bool IsLittleEndian)
      : Ctx(Ctx), IsLittleEndian(IsLittleEndian) {}

  void encodeInstruction(const MCInst &MI, SmallVectorImpl<char> &CB,
                         SmallVectorImpl<MCFixup> &Fixups,
                         const MCSubtargetInfo &STI) const override;

  // From SHGenMCCodeEmitter.inc.
  uint64_t getBinaryCodeForInstr(const MCInst &MI,
                                 SmallVectorImpl<MCFixup> &Fixups,
                                 const MCSubtargetInfo &STI) const;

  unsigned getMachineOpValue(const MCInst &MI, const MCOperand &MO,
                             SmallVectorImpl<MCFixup> &Fixups,
                             const MCSubtargetInfo &STI) const;
  template <unsigned Bits, bool IsSigned>
  unsigned getImmOpValue(const MCInst &MI, unsigned OpNo,
                         SmallVectorImpl<MCFixup> &Fixups,
                         const MCSubtargetInfo &STI) const;
  template <unsigned Bits, unsigned Scale>
  unsigned getDispOpValue(const MCInst &MI, unsigned OpNo,
                          SmallVectorImpl<MCFixup> &Fixups,
                          const MCSubtargetInfo &STI) const;
  template <unsigned Bits>
  unsigned getBranchTargetOpValue(const MCInst &MI, unsigned OpNo,
                                  SmallVectorImpl<MCFixup> &Fixups,
                                  const MCSubtargetInfo &STI) const;
  template <unsigned Scale>
  unsigned getLiteralOpValue(const MCInst &MI, unsigned OpNo,
                             SmallVectorImpl<MCFixup> &Fixups,
                             const MCSubtargetInfo &STI) const;

private:
  /// The value of an operand if it is a number by now.
  bool getConstant(const MCOperand &MO, int64_t &Value) const;

  MCContext &Ctx;
  bool IsLittleEndian;
};

} // namespace

/// A number of the assembly is one of 32 bits: 0xfffffff0 is -16.
bool SHMCCodeEmitter::getConstant(const MCOperand &MO, int64_t &Value) const {
  if (MO.isImm())
    Value = MO.getImm();
  else if (!MO.isExpr() || !MO.getExpr()->evaluateAsAbsolute(Value))
    return false;
  if (isUInt<32>(Value))
    Value = SignExtend64<32>(Value);
  return true;
}

void SHMCCodeEmitter::encodeInstruction(const MCInst &MI,
                                        SmallVectorImpl<char> &CB,
                                        SmallVectorImpl<MCFixup> &Fixups,
                                        const MCSubtargetInfo &STI) const {
  uint16_t Bits = getBinaryCodeForInstr(MI, Fixups, STI);
  support::endian::write<uint16_t>(
      CB, Bits, IsLittleEndian ? endianness::little : endianness::big);
}

unsigned SHMCCodeEmitter::getMachineOpValue(const MCInst &MI,
                                            const MCOperand &MO,
                                            SmallVectorImpl<MCFixup> &Fixups,
                                            const MCSubtargetInfo &STI) const {
  if (MO.isReg())
    return Ctx.getRegisterInfo()->getEncodingValue(MO.getReg());
  if (MO.isImm())
    return MO.getImm();
  Ctx.reportError(MI.getLoc(), "an operand that cannot be encoded");
  return 0;
}

/// An immediate.  As in GNU as, one of eight bits is any number that fits
/// in eight bits with or without a sign: "mov #0xff,r1" is "mov #-1,r1".
template <unsigned Bits, bool IsSigned>
unsigned SHMCCodeEmitter::getImmOpValue(const MCInst &MI, unsigned OpNo,
                                        SmallVectorImpl<MCFixup> &Fixups,
                                        const MCSubtargetInfo &STI) const {
  const MCOperand &MO = MI.getOperand(OpNo);
  int64_t Value;
  if (!getConstant(MO, Value)) {
    // The low byte is the second one on a big-endian target.
    Fixups.push_back(MCFixup::create(IsLittleEndian ? 0 : 1, MO.getExpr(),
                                     MCFixupKind(SH::fixup_sh_imm8)));
    return 0;
  }
  // What is written as an unsigned number has passed getConstant() if it is
  // less than 2^31.
  if (Value < -(int64_t(1) << (Bits - 1)) || Value >= (int64_t(1) << Bits))
    Ctx.reportError(MI.getLoc(), "the immediate " + Twine(Value) +
                                     " does not fit in " + Twine(Bits) +
                                     " bits");
  return Value & ((1u << Bits) - 1);
}

/// A displacement in bytes, which the instruction has as a number of units.
template <unsigned Bits, unsigned Scale>
unsigned SHMCCodeEmitter::getDispOpValue(const MCInst &MI, unsigned OpNo,
                                         SmallVectorImpl<MCFixup> &Fixups,
                                         const MCSubtargetInfo &STI) const {
  int64_t Value;
  if (!getConstant(MI.getOperand(OpNo), Value)) {
    Ctx.reportError(MI.getLoc(), "the displacement has to be a number");
    return 0;
  }
  int64_t Limit = ((int64_t(1) << Bits) - 1) * Scale;
  if (Value < 0 || Value > Limit)
    Ctx.reportError(MI.getLoc(), "the displacement " + Twine(Value) +
                                     " is not between 0 and " + Twine(Limit));
  else if (Value % Scale)
    Ctx.reportError(MI.getLoc(), "the displacement " + Twine(Value) +
                                     " is not a multiple of " + Twine(Scale));
  return (Value / Scale) & ((1u << Bits) - 1);
}

/// The target of a branch.  A number is the distance from the instruction
/// in bytes, which is what the disassembler makes of the field.
template <unsigned Bits>
unsigned
SHMCCodeEmitter::getBranchTargetOpValue(const MCInst &MI, unsigned OpNo,
                                        SmallVectorImpl<MCFixup> &Fixups,
                                        const MCSubtargetInfo &STI) const {
  const MCOperand &MO = MI.getOperand(OpNo);
  if (MO.isImm())
    return ((MO.getImm() - 4) >> 1) & ((1u << Bits) - 1);
  Fixups.push_back(MCFixup::create(
      0, MO.getExpr(),
      MCFixupKind(Bits == 8 ? SH::fixup_sh_branch8 : SH::fixup_sh_branch12),
      /*PCRel=*/true));
  return 0;
}

/// The label of "mov.l label,Rn", "mov.w label,Rn" and "mova label,r0".  A
/// number is the distance from the instruction, as it is for a branch.  A
/// word is found from that.  A long word is not: its field counts from the
/// address of the instruction rounded down, which nobody knows here.
template <unsigned Scale>
unsigned SHMCCodeEmitter::getLiteralOpValue(const MCInst &MI, unsigned OpNo,
                                            SmallVectorImpl<MCFixup> &Fixups,
                                            const MCSubtargetInfo &STI) const {
  const MCOperand &MO = MI.getOperand(OpNo);
  if (MO.isImm()) {
    if (Scale == 4)
      Ctx.reportError(MI.getLoc(), "the place of a literal has to be a label "
                                   "or a distance from '.'");
    return ((MO.getImm() - 4) >> 1) & 0xff;
  }
  Fixups.push_back(MCFixup::create(
      0, MO.getExpr(),
      MCFixupKind(Scale == 4 ? SH::fixup_sh_literal4 : SH::fixup_sh_literal2),
      /*PCRel=*/true));
  return 0;
}

#include "SHGenMCCodeEmitter.inc"

MCCodeEmitter *llvm::createSHMCCodeEmitter(const MCInstrInfo &MCII,
                                           MCContext &Ctx) {
  return new SHMCCodeEmitter(Ctx, Ctx.getTargetTriple().isLittleEndian());
}
