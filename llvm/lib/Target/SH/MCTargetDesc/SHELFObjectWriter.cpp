//===-- SHELFObjectWriter.cpp - SuperH relocations ------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The relocations of SuperH are for words of data: an address, a distance,
// or what "@GOT", "@PLT" and the like ask the linker for.  They are written
// as GNU as writes them, which the linker depends on: in sections of type
// RELA, with the addend in the word itself and none in the entry.
//
//===----------------------------------------------------------------------===//

#include "SHFixupKinds.h"
#include "SHMCAsmInfo.h"
#include "SHMCTargetDesc.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCELFObjectWriter.h"
#include "llvm/MC/MCFixup.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCSymbolELF.h"
#include "llvm/MC/MCValue.h"

using namespace llvm;

namespace {

class SHELFObjectWriter : public MCELFObjectTargetWriter {
public:
  SHELFObjectWriter(uint8_t OSABI)
      : MCELFObjectTargetWriter(/*Is64Bit=*/false, OSABI, ELF::EM_SH,
                                /*HasRelocationAddend=*/true) {}

  unsigned getRelocType(const MCFixup &Fixup, const MCValue &Target,
                        bool IsPCRel) const override;
  bool needsRelocateWithSymbol(const MCValue &Val,
                               unsigned Type) const override;
  bool hasInPlaceAddend(unsigned Type) const override {
    return Type != ELF::R_SH_DIR16;
  }
};

} // namespace

unsigned SHELFObjectWriter::getRelocType(const MCFixup &Fixup,
                                         const MCValue &Target,
                                         bool IsPCRel) const {
  auto Error = [&](const Twine &Message) {
    getContext().reportError(Fixup.getLoc(), Message);
    return unsigned(ELF::R_SH_NONE);
  };
  const auto *Symbol = static_cast<const MCSymbolELF *>(Target.getAddSym());
  switch (unsigned(Fixup.getKind())) {
  case FK_Data_1:
  case SH::fixup_sh_imm8:
    if (IsPCRel || Target.getSpecifier())
      return Error("no relocation for this expression in one byte");
    return ELF::R_SH_DIR8;
  case FK_Data_2:
    if (IsPCRel || Target.getSpecifier())
      return Error("no relocation for this expression in two bytes");
    return ELF::R_SH_DIR16;
  case FK_Data_4:
    break;
  default:
    return Error("no relocation for this place");
  }

  switch (Target.getSpecifier()) {
  case SH::S_None:
    // The address of the global offset table is always the distance to it.
    if (Symbol && Symbol->getName() == "_GLOBAL_OFFSET_TABLE_")
      return ELF::R_SH_GOTPC;
    return IsPCRel ? ELF::R_SH_REL32 : ELF::R_SH_DIR32;
  case SH::S_GOT:
    return ELF::R_SH_GOT32;
  case SH::S_GOTOFF:
    return ELF::R_SH_GOTOFF;
  case SH::S_PLT:
    return ELF::R_SH_PLT32;
  case SH::S_TPOFF:
  case SH::S_GOTTPOFF:
  case SH::S_TLSGD:
  case SH::S_TLSLDM:
  case SH::S_DTPOFF:
    break;
  default:
    return Error("no relocation for this specifier");
  }

  // Thread-local storage.  The symbol is one of a thread.
  if (Symbol)
    const_cast<MCSymbolELF *>(Symbol)->setType(ELF::STT_TLS);
  switch (Target.getSpecifier()) {
  case SH::S_TPOFF:
    return ELF::R_SH_TLS_LE_32;
  case SH::S_GOTTPOFF:
    return ELF::R_SH_TLS_IE_32;
  case SH::S_TLSGD:
    return ELF::R_SH_TLS_GD_32;
  case SH::S_TLSLDM:
    return ELF::R_SH_TLS_LD_32;
  default:
    return ELF::R_SH_TLS_LDO_32;
  }
}

/// What the linker looks up by the symbol must keep it.  An address or a
/// distance can count from the start of the section instead, and that is
/// what GNU as writes.
bool SHELFObjectWriter::needsRelocateWithSymbol(const MCValue &Val,
                                                unsigned Type) const {
  switch (Type) {
  case ELF::R_SH_DIR32:
  case ELF::R_SH_REL32:
  case ELF::R_SH_GOTOFF:
  case ELF::R_SH_DIR16:
  case ELF::R_SH_DIR8:
    return false;
  default:
    return true;
  }
}

std::unique_ptr<MCObjectTargetWriter>
llvm::createSHELFObjectWriter(uint8_t OSABI) {
  return std::make_unique<SHELFObjectWriter>(OSABI);
}
