//===-- SHAsmBackend.cpp - SuperH fixups and padding ----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Where an instruction names a place in the code, it has the distance to it
// in its low eight or twelve bits, counted in words or long words from a
// point behind the instruction.  This file computes those fields when the
// places are known.  GNU as does not leave them to the linker, and neither
// does this: a branch or a load across sections is an error.
//
//===----------------------------------------------------------------------===//

#include "SHFixupKinds.h"
#include "SHMCTargetDesc.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAssembler.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCELFObjectWriter.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCSection.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/MCValue.h"
#include "llvm/Support/EndianStream.h"
#include "llvm/TargetParser/Triple.h"

using namespace llvm;

namespace {

class SHAsmBackend : public MCAsmBackend {
public:
  SHAsmBackend(uint8_t OSABI, bool IsLittleEndian)
      : MCAsmBackend(IsLittleEndian ? endianness::little : endianness::big),
        OSABI(OSABI) {}

  std::unique_ptr<MCObjectTargetWriter>
  createObjectTargetWriter() const override {
    return createSHELFObjectWriter(OSABI);
  }

  MCFixupKindInfo getFixupKindInfo(MCFixupKind Kind) const override;
  std::optional<bool> evaluateFixup(const MCFragment &F, MCFixup &Fixup,
                                    MCValue &Target, uint64_t &Value) override;
  void applyFixup(const MCFragment &F, const MCFixup &Fixup,
                  const MCValue &Target, uint8_t *Data, uint64_t Value,
                  bool IsResolved) override;
  bool writeNopData(raw_ostream &OS, uint64_t Count,
                    const MCSubtargetInfo *STI) const override;

private:
  uint8_t OSABI;
};

} // namespace

MCFixupKindInfo SHAsmBackend::getFixupKindInfo(MCFixupKind Kind) const {
  // In the order of SH::Fixups.
  static const MCFixupKindInfo Infos[SH::NumTargetFixupKinds] = {
      // name               offset bits flags
      {"fixup_sh_branch8", 0, 8, 0},  {"fixup_sh_branch12", 0, 12, 0},
      {"fixup_sh_literal4", 0, 8, 0}, {"fixup_sh_literal2", 0, 8, 0},
      {"fixup_sh_imm8", 0, 8, 0},
  };
  if (Kind < FirstTargetFixupKind)
    return MCAsmBackend::getFixupKindInfo(Kind);
  assert(unsigned(Kind - FirstTargetFixupKind) < SH::NumTargetFixupKinds &&
         "not a fixup of this target");
  return Infos[Kind - FirstTargetFixupKind];
}

/// A branch or a load from a literal reaches a symbol of its own section
/// whatever the symbol is to the linker: there is no relocation that could
/// send it elsewhere, and GNU as resolves it in the same way.
std::optional<bool> SHAsmBackend::evaluateFixup(const MCFragment &F,
                                                MCFixup &Fixup, MCValue &Target,
                                                uint64_t &Value) {
  unsigned Kind = Fixup.getKind();
  if (Kind < FirstTargetFixupKind || Kind == SH::fixup_sh_imm8)
    return std::nullopt;
  const MCSymbol *Symbol = Target.getAddSym();
  if (!Symbol || Target.getSubSym() || !Symbol->isInSection() ||
      &Symbol->getSection() != F.getParent())
    return false;
  Value = Asm->getSymbolOffset(*Symbol) + Target.getConstant() -
          (Asm->getFragmentOffset(F) + Fixup.getOffset());
  return true;
}

void SHAsmBackend::applyFixup(const MCFragment &F, const MCFixup &Fixup,
                              const MCValue &Target, uint8_t *Data,
                              uint64_t Value, bool IsResolved) {
  MCContext &Ctx = getContext();
  unsigned Kind = Fixup.getKind();
  bool IsLittle = Endian == endianness::little;

  // Data: the bytes go where they are, in the byte order of the target.
  if (Kind < FirstTargetFixupKind || Kind == SH::fixup_sh_imm8) {
    maybeAddReloc(F, Fixup, Target, Value, IsResolved);
    if (mc::isRelocation(Fixup.getKind()))
      return;
    unsigned Size = Kind == SH::fixup_sh_imm8
                        ? 1
                        : getFixupKindInfo(Fixup.getKind()).TargetSize / 8;
    if (Kind == SH::fixup_sh_imm8 && IsResolved &&
        (int64_t(Value) < -128 || int64_t(Value) > 255))
      Ctx.reportError(Fixup.getLoc(), "the immediate " + Twine(int64_t(Value)) +
                                          " does not fit in 8 bits");
    for (unsigned I = 0; I != Size; ++I)
      Data[I] |= uint8_t(Value >> ((IsLittle ? I : Size - 1 - I) * 8));
    return;
  }

  if (!IsResolved) {
    Ctx.reportError(Fixup.getLoc(),
                    "the target is not in this section, or it is not defined");
    return;
  }

  // Value is the distance from the instruction to the target.
  int64_t Distance = int64_t(Value) - 4;
  int64_t Field = 0;
  unsigned Bits = 8;
  auto OutOfReach = [&](int64_t Low, int64_t High) {
    if (Distance >= Low && Distance <= High)
      return false;
    Ctx.reportError(Fixup.getLoc(), "the target is " + Twine(Distance) +
                                        " bytes away, out of the reach of the "
                                        "instruction (" +
                                        Twine(Low) + " to " + Twine(High) +
                                        ")");
    return true;
  };
  switch (Kind) {
  case SH::fixup_sh_branch8:
  case SH::fixup_sh_branch12: {
    Bits = Kind == SH::fixup_sh_branch8 ? 8 : 12;
    int64_t Limit = int64_t(1) << Bits;
    if (OutOfReach(-Limit, Limit - 2))
      return;
    if (Distance & 1) {
      Ctx.reportError(Fixup.getLoc(), "the target is at an odd address");
      return;
    }
    Field = Distance >> 1;
    break;
  }
  case SH::fixup_sh_literal4: {
    // The processor rounds the address of the instruction down to a
    // multiple of four, so the address must be known up to that: the
    // section has to be aligned.
    F.getParent()->ensureMinAlignment(Align(4));
    uint64_t Offset = Asm->getFragmentOffset(F) + Fixup.getOffset();
    Distance += Offset & 3;
    if (OutOfReach(0, 1020))
      return;
    if (Distance & 3) {
      Ctx.reportError(Fixup.getLoc(),
                      "the target is not at a multiple of four bytes");
      return;
    }
    Field = Distance >> 2;
    break;
  }
  case SH::fixup_sh_literal2:
    if (OutOfReach(0, 510))
      return;
    if (Distance & 1) {
      Ctx.reportError(Fixup.getLoc(), "the target is at an odd address");
      return;
    }
    Field = Distance >> 1;
    break;
  default:
    llvm_unreachable("not a fixup of this target");
  }

  // The field is the low bits of the instruction.
  uint16_t Mask = (1u << Bits) - 1;
  uint16_t Insn = IsLittle ? support::endian::read16le(Data)
                           : support::endian::read16be(Data);
  Insn = (Insn & ~Mask) | (uint16_t(Field) & Mask);
  if (IsLittle)
    support::endian::write16le(Data, Insn);
  else
    support::endian::write16be(Data, Insn);
}

/// Padding in code is "nop", 0x0009.  An odd byte in front of it is zero.
bool SHAsmBackend::writeNopData(raw_ostream &OS, uint64_t Count,
                                const MCSubtargetInfo *STI) const {
  if (Count & 1)
    OS.write_zeros(1);
  for (uint64_t I = 0, E = Count / 2; I != E; ++I)
    support::endian::write<uint16_t>(OS, 0x0009, Endian);
  return true;
}

MCAsmBackend *llvm::createSHAsmBackend(const Target &T,
                                       const MCSubtargetInfo &STI,
                                       const MCRegisterInfo &MRI,
                                       const MCTargetOptions &Options) {
  const Triple &TT = STI.getTargetTriple();
  return new SHAsmBackend(MCELFObjectTargetWriter::getOSABI(TT.getOS()),
                          TT.isLittleEndian());
}
