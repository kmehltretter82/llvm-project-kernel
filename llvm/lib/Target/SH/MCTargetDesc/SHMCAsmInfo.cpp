//===-- SHMCAsmInfo.cpp - SuperH assembly properties -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

//
// The assembly is written for GNU as.
//
//===----------------------------------------------------------------------===//

#include "SHMCAsmInfo.h"
#include "llvm/ADT/Enum.h"
#include "llvm/TargetParser/Triple.h"

using namespace llvm;

constexpr EnumStringDef<MCAsmInfo::AtSpecifierKind> AtSpecifierDefs[] = {
    {{"GOT"}, SH::S_GOT},           {{"GOTOFF"}, SH::S_GOTOFF},
    {{"PLT"}, SH::S_PLT},           {{"TPOFF"}, SH::S_TPOFF},
    {{"GOTTPOFF"}, SH::S_GOTTPOFF}, {{"TLSGD"}, SH::S_TLSGD},
    {{"TLSLDM"}, SH::S_TLSLDM},     {{"DTPOFF"}, SH::S_DTPOFF},
};
constexpr auto AtSpecifiers = BUILD_ENUM_STRINGS(AtSpecifierDefs);

void SHMCAsmInfo::anchor() {}

SHMCAsmInfo::SHMCAsmInfo(const Triple &TT, const MCTargetOptions &Options)
    : MCAsmInfoELF(Options) {
  IsLittleEndian = TT.isLittleEndian();
  CodePointerSize = 4;
  CalleeSaveStackSlotSize = 4;
  MinInstAlignment = 2;
  MaxInstLength = 2;

  // '#' introduces an immediate, '@' an address.
  CommentString = "!";
  // ".align n" is an alignment to two to the power of n.
  AlignmentIsInBytes = false;
  // .short and .long refuse an odd address, which a member of a packed
  // structure can have.
  Data16bitsDirective = "\t.uaword\t";
  Data32bitsDirective = "\t.ualong\t";
  Data64bitsDirective = nullptr;
  ZeroDirective = "\t.zero\t";
  UsesELFSectionDirectiveForBSS = true;

  SupportsDebugInformation = true;
  ExceptionsType = ExceptionHandling::DwarfCFI;

  // There is no assembler in the library: the text goes to GNU as.
  UseIntegratedAssembler = false;

  initializeAtSpecifiers(AtSpecifiers);
}
