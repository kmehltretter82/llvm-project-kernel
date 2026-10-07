//===-- SHDisassembler.cpp - SuperH instructions from bytes ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Every instruction is sixteen bits in the byte order of the target.  The
// table that tablegen makes of SHInstrInfo.td finds the instruction.  This
// file has what puts the operands into it.
//
// Two things cannot be read from the bits.  An operation of the floating
// point unit is on float or on double depending on a bit of FPSCR: it is
// printed as the one on float, which is what objdump does.  And a place in
// the code is a distance from the instruction, which the printer turns into
// an address when it knows where the instruction is.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/SHMCTargetDesc.h"
#include "TargetInfo/SHTargetInfo.h"
#include "llvm/MC/MCDecoder.h"
#include "llvm/MC/MCDecoderOps.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/TargetParser/Triple.h"

using namespace llvm;
using namespace llvm::MCD;

#define DEBUG_TYPE "sh-disassembler"

using DecodeStatus = MCDisassembler::DecodeStatus;

namespace {

class SHDisassembler : public MCDisassembler {
public:
  SHDisassembler(const MCSubtargetInfo &STI, MCContext &Ctx)
      : MCDisassembler(STI, Ctx),
        IsLittleEndian(STI.getTargetTriple().isLittleEndian()) {}

  DecodeStatus getInstruction(MCInst &MI, uint64_t &Size,
                              ArrayRef<uint8_t> Bytes, uint64_t Address,
                              raw_ostream &CStream) const override;

private:
  bool IsLittleEndian;
};

} // namespace

static const MCRegister GPRs[] = {
    SH::R0, SH::R1, SH::R2,  SH::R3,  SH::R4,  SH::R5,  SH::R6,  SH::R7,
    SH::R8, SH::R9, SH::R10, SH::R11, SH::R12, SH::R13, SH::R14, SH::R15};
static const MCRegister FPRs[] = {SH::FR0,  SH::FR1,  SH::FR2,  SH::FR3,
                                  SH::FR4,  SH::FR5,  SH::FR6,  SH::FR7,
                                  SH::FR8,  SH::FR9,  SH::FR10, SH::FR11,
                                  SH::FR12, SH::FR13, SH::FR14, SH::FR15};
static const MCRegister DFPRs[] = {SH::DR0, SH::DR2,  SH::DR4,  SH::DR6,
                                   SH::DR8, SH::DR10, SH::DR12, SH::DR14};
static const MCRegister XDPRs[] = {SH::XD0, SH::XD2,  SH::XD4,  SH::XD6,
                                   SH::XD8, SH::XD10, SH::XD12, SH::XD14};
static const MCRegister FVRs[] = {SH::FV0, SH::FV4, SH::FV8, SH::FV12};
static const MCRegister BankRegs[] = {SH::R0_BANK, SH::R1_BANK, SH::R2_BANK,
                                      SH::R3_BANK, SH::R4_BANK, SH::R5_BANK,
                                      SH::R6_BANK, SH::R7_BANK};

static DecodeStatus DecodeGPRRegisterClass(MCInst &Inst, unsigned RegNo,
                                           uint64_t Address,
                                           const MCDisassembler *Decoder) {
  Inst.addOperand(MCOperand::createReg(GPRs[RegNo & 15]));
  return MCDisassembler::Success;
}

static DecodeStatus DecodeFPRRegisterClass(MCInst &Inst, unsigned RegNo,
                                           uint64_t Address,
                                           const MCDisassembler *Decoder) {
  Inst.addOperand(MCOperand::createReg(FPRs[RegNo & 15]));
  return MCDisassembler::Success;
}

// A double register has the number of its first half, which is even.
static DecodeStatus DecodeDFPRRegisterClass(MCInst &Inst, unsigned RegNo,
                                            uint64_t Address,
                                            const MCDisassembler *Decoder) {
  if (RegNo & 1)
    return MCDisassembler::Fail;
  Inst.addOperand(MCOperand::createReg(DFPRs[(RegNo & 15) >> 1]));
  return MCDisassembler::Success;
}

// A double register of the second set has an odd number.
static DecodeStatus DecodeXDPRRegisterClass(MCInst &Inst, unsigned RegNo,
                                            uint64_t Address,
                                            const MCDisassembler *Decoder) {
  if (!(RegNo & 1))
    return MCDisassembler::Fail;
  Inst.addOperand(MCOperand::createReg(XDPRs[(RegNo & 15) >> 1]));
  return MCDisassembler::Success;
}

static DecodeStatus DecodeFVRRegisterClass(MCInst &Inst, unsigned RegNo,
                                           uint64_t Address,
                                           const MCDisassembler *Decoder) {
  Inst.addOperand(MCOperand::createReg(FVRs[RegNo & 3]));
  return MCDisassembler::Success;
}

static DecodeStatus DecodeBankRegRegisterClass(MCInst &Inst, unsigned RegNo,
                                               uint64_t Address,
                                               const MCDisassembler *Decoder) {
  Inst.addOperand(MCOperand::createReg(BankRegs[RegNo & 7]));
  return MCDisassembler::Success;
}

template <unsigned Bits>
static DecodeStatus decodeSImm(MCInst &Inst, uint64_t Imm, uint64_t Address,
                               const MCDisassembler *Decoder) {
  Inst.addOperand(MCOperand::createImm(SignExtend64<Bits>(Imm)));
  return MCDisassembler::Success;
}

template <unsigned Bits>
static DecodeStatus decodeUImm(MCInst &Inst, uint64_t Imm, uint64_t Address,
                               const MCDisassembler *Decoder) {
  Inst.addOperand(MCOperand::createImm(Imm));
  return MCDisassembler::Success;
}

// A displacement: the field counts bytes, words or long words.
template <unsigned Bits, unsigned Scale>
static DecodeStatus decodeDisp(MCInst &Inst, uint64_t Imm, uint64_t Address,
                               const MCDisassembler *Decoder) {
  Inst.addOperand(MCOperand::createImm(Imm * Scale));
  return MCDisassembler::Success;
}

// The target of a branch, as its distance from the instruction: the field
// counts words from four bytes behind it.
template <unsigned Bits>
static DecodeStatus decodeBranchTarget(MCInst &Inst, uint64_t Imm,
                                       uint64_t Address,
                                       const MCDisassembler *Decoder) {
  Inst.addOperand(MCOperand::createImm(SignExtend64<Bits>(Imm) * 2 + 4));
  return MCDisassembler::Success;
}

// The place of a literal, as its distance from the instruction.  The field
// counts long words from four bytes behind the address of the instruction
// rounded down to a multiple of four, or words from four bytes behind it.
template <unsigned Scale>
static DecodeStatus decodeLiteral(MCInst &Inst, uint64_t Imm, uint64_t Address,
                                  const MCDisassembler *Decoder) {
  int64_t Distance = Imm * Scale + 4;
  if (Scale == 4)
    Distance -= Address & 3;
  Inst.addOperand(MCOperand::createImm(Distance));
  return MCDisassembler::Success;
}

#include "SHGenDisassemblerTables.inc"

namespace {
// An instruction is a number of sixteen bits to the decoder.
template <> constexpr uint32_t InsnBitWidth<uint16_t> = 16;
} // namespace

DecodeStatus SHDisassembler::getInstruction(MCInst &MI, uint64_t &Size,
                                            ArrayRef<uint8_t> Bytes,
                                            uint64_t Address,
                                            raw_ostream &CStream) const {
  if (Bytes.size() < 2) {
    Size = 0;
    return MCDisassembler::Fail;
  }
  Size = 2;
  uint16_t Insn = IsLittleEndian ? support::endian::read16le(Bytes.data())
                                 : support::endian::read16be(Bytes.data());
  return decodeInstruction(DecoderTableSH16, MI, Insn, Address, this, STI);
}

static MCDisassembler *createSHDisassembler(const Target &T,
                                            const MCSubtargetInfo &STI,
                                            MCContext &Ctx) {
  return new SHDisassembler(STI, Ctx);
}

extern "C" LLVM_ABI LLVM_EXTERNAL_VISIBILITY void
LLVMInitializeSHDisassembler() {
  TargetRegistry::RegisterMCDisassembler(getTheSHTarget(),
                                         createSHDisassembler);
  TargetRegistry::RegisterMCDisassembler(getTheSHebTarget(),
                                         createSHDisassembler);
}
