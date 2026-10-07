//===-- SHFixupKinds.h - SuperH fixups ---------------------------*- C++
//-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SH_MCTARGETDESC_SHFIXUPKINDS_H
#define LLVM_LIB_TARGET_SH_MCTARGETDESC_SHFIXUPKINDS_H

#include "llvm/MC/MCFixup.h"

namespace llvm {
namespace SH {

// The places in an instruction that say where something is.  All of them
// count from the instruction, in the low bits of its sixteen.
enum Fixups {
  /// bt, bf, bt/s, bf/s: a signed number of words in eight bits, from four
  /// bytes behind the instruction.
  fixup_sh_branch8 = FirstTargetFixupKind,
  /// bra, bsr: the same in twelve bits.
  fixup_sh_branch12,
  /// mov.l and mova with a label: a number of long words in eight bits,
  /// from four bytes behind the address of the instruction rounded down to
  /// a multiple of four.
  fixup_sh_literal4,
  /// mov.w with a label: a number of words in eight bits, from four bytes
  /// behind the instruction.
  fixup_sh_literal2,
  /// The eight bits of an immediate.
  fixup_sh_imm8,

  fixup_sh_invalid,
  NumTargetFixupKinds = fixup_sh_invalid - FirstTargetFixupKind
};

} // namespace SH
} // namespace llvm

#endif
