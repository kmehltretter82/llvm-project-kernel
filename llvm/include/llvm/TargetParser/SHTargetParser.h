//===-- SHTargetParser.h - SuperH processors and their properties -*- C++ -*-=//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The SuperH processors that can be named, with their instruction set and
// their floating point unit.  A name is what GCC has as -m<name> without the
// "sh": "sh4-nofpu" is -m4-nofpu.  The code generator, the clang frontend and
// the clang driver share this table, so that all three mean the same by a
// name and pick the same processor for a triple.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TARGETPARSER_SHTARGETPARSER_H
#define LLVM_TARGETPARSER_SHTARGETPARSER_H

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Compiler.h"

namespace llvm {
template <typename T> class SmallVectorImpl;
class Triple;

namespace SH {

/// The instruction set.  SH-1 is not here: it has no 32-bit multiplication,
/// and nothing that runs Linux has one.
enum ArchKind {
  AK_SH2,
  /// The J-Core J2: SH-2 with the shifts of SH-3 and with cas.l.
  AK_J2,
  AK_SH2E,
  AK_SH2A,
  AK_SH3,
  AK_SH3E,
  AK_SH4,
  AK_SH4A,
};

/// What the floating point unit computes.  It decides the calling
/// convention as well: without a unit every value is passed in r4 to r7,
/// with one floating point values go to fr4 to fr11 and va_list is a
/// structure.
enum FPUKind {
  /// None, or none that the compiler may use (-m4-nofpu).
  FK_None,
  /// float in registers, double in software (-m2e, -m3e, -m4-single-only).
  FK_SingleOnly,
  /// float and double, and a function is entered in single precision mode
  /// (-m4-single).
  FK_Single,
  /// float and double, and a function is entered in double precision mode
  /// (-m4).
  FK_Double,
};

struct CPUInfo {
  StringLiteral Name;
  ArchKind Arch;
  FPUKind FPU;
  /// The DSP instructions (SH4AL-DSP).
  bool DSP;

  bool hasFPU() const { return FPU != FK_None; }
  /// double is computed, passed and returned in floating point registers.
  bool hasDoubleFPU() const { return FPU == FK_Single || FPU == FK_Double; }
  /// C's double is a float: the processors whose names end in
  /// "-single-only", GCC's TARGET_FPU_SINGLE_ONLY.  An SH-2E or SH-3E has a
  /// unit for float alone as well, but keeps a double of 64 bits and
  /// computes it without the unit.
  bool doubleIsFloat() const {
    return FPU == FK_SingleOnly && Arch != AK_SH2E && Arch != AK_SH3E;
  }
  /// shad and shld: a shift by the number in a register.
  bool hasDynamicShift() const { return Arch != AK_SH2 && Arch != AK_SH2E; }
  /// An SH-4 that uses its unit for double, GCC's TARGET_SH4.  On a
  /// little-endian one the two registers of a pair change places for float
  /// arguments: the first float is in fr5, the second in fr4.
  bool isSH4FPU() const {
    return (Arch == AK_SH4 || Arch == AK_SH4A) && hasDoubleFPU();
  }
  /// With a floating point unit an argument that does not fit the registers
  /// that are left goes to the stack.  Here it leaves those registers to
  /// the arguments behind it, elsewhere they stay empty.
  bool leavesRegistersFree() const { return isSH4FPU() || Arch == AK_SH2A; }
};

/// The processor with this name, or null.
LLVM_ABI const CPUInfo *parseCPU(StringRef Name);

/// The processor that a triple stands for when nothing else names one.  It
/// is what a GCC that is configured for the triple has as its default, as
/// far as the first component of the triple says: "sh4" is an SH-4 with its
/// floating point unit, "sh3" an SH-3.  A plain "sh" is the SH-1 for GCC
/// and the SH-2 here.
LLVM_ABI StringRef getDefaultCPU(const Triple &TT);

LLVM_ABI void fillValidCPUList(SmallVectorImpl<StringRef> &Values);

} // namespace SH
} // namespace llvm

#endif // LLVM_TARGETPARSER_SHTARGETPARSER_H
