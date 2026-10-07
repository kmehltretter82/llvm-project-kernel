//===--- SuperH.cpp - Implement SuperH target feature support -------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements SuperHTargetInfo.
//
//===----------------------------------------------------------------------===//

#include "SuperH.h"
#include "clang/Basic/MacroBuilder.h"
#include "llvm/ADT/StringSwitch.h"

using namespace clang;
using namespace clang::targets;

SuperHTargetInfo::SuperHTargetInfo(const llvm::Triple &Triple,
                                   const TargetOptions &)
    : TargetInfo(Triple),
      CPU(llvm::SH::parseCPU(llvm::SH::getDefaultCPU(Triple))) {
  assert(CPU && "the default processor of a triple is in the table");
  BigEndian = Triple.getArch() == llvm::Triple::sheb;

  // The data model of GCC.  Nothing is aligned to more than four bytes, and
  // long double is double.
  LongLongAlign = 32;
  DoubleAlign = 32;
  LongDoubleWidth = 64;
  LongDoubleAlign = 32;
  LongDoubleFormat = &llvm::APFloat::IEEEdouble();
  SuitableAlign = 32;
  DefaultAlignForAttributeAligned = 32;
  SizeType = UnsignedInt;
  PtrDiffType = SignedInt;
  IntPtrType = SignedInt;
  WCharType = SignedLong;
  WIntType = UnsignedInt;
  TLSSupported = true;
  HasFloat128 = false;

  // On Linux the operations on up to 32 bits are calls of the __sync
  // functions of libgcc, which the kernel makes atomic by restarting them.
  MaxAtomicPromoteWidth = MaxAtomicInlineWidth = Triple.isOSLinux() ? 32 : 0;

  resetDataLayout();
}

bool SuperHTargetInfo::setCPU(StringRef Name) {
  const llvm::SH::CPUInfo *Info = llvm::SH::parseCPU(Name);
  if (!Info)
    return false;
  CPU = Info;
  return true;
}

bool SuperHTargetInfo::hasFeature(StringRef Feature) const {
  return llvm::StringSwitch<bool>(Feature)
      .Case("sh", true)
      .Case("fpu", CPU->hasFPU())
      .Default(false);
}

void SuperHTargetInfo::getTargetDefines(const LangOptions &Opts,
                                        MacroBuilder &Builder) const {
  using namespace llvm::SH;
  Builder.defineMacro("__sh__");
  Builder.defineMacro(BigEndian ? "__BIG_ENDIAN__" : "__LITTLE_ENDIAN__");

  // The macros of GCC.  The lower case forms exist for the processors
  // without a floating point unit only, and an SH-4 that does not use its
  // unit says that it is an SH-3.
  switch (CPU->Arch) {
  case AK_SH2:
    Builder.defineMacro("__SH2__");
    Builder.defineMacro("__sh2__");
    break;
  case AK_J2:
    break;
  case AK_SH2E:
    Builder.defineMacro("__SH2E__");
    break;
  case AK_SH2A:
    Builder.defineMacro("__SH2A__");
    switch (CPU->FPU) {
    case FK_None:
      Builder.defineMacro("__SH2A_NOFPU__");
      break;
    case FK_SingleOnly:
      Builder.defineMacro("__SH2A_SINGLE_ONLY__");
      break;
    case FK_Single:
      Builder.defineMacro("__SH2A_SINGLE__");
      break;
    case FK_Double:
      Builder.defineMacro("__SH2A_DOUBLE__");
      break;
    }
    break;
  case AK_SH3:
    Builder.defineMacro("__SH3__");
    Builder.defineMacro("__sh3__");
    break;
  case AK_SH3E:
    Builder.defineMacro("__SH3E__");
    break;
  case AK_SH4:
  case AK_SH4A:
    if (CPU->Arch == AK_SH4A)
      Builder.defineMacro("__SH4A__");
    switch (CPU->FPU) {
    case FK_None:
      if (CPU->Arch == AK_SH4) {
        Builder.defineMacro("__SH3__");
        Builder.defineMacro("__sh3__");
      }
      Builder.defineMacro("__SH4_NOFPU__");
      break;
    case FK_SingleOnly:
      Builder.defineMacro("__SH4_SINGLE_ONLY__");
      break;
    case FK_Single:
      Builder.defineMacro("__SH4_SINGLE__");
      break;
    case FK_Double:
      Builder.defineMacro("__SH4__");
      break;
    }
    break;
  }
  if (CPU->hasFPU())
    Builder.defineMacro("__SH_FPU_ANY__");
  if (CPU->hasDoubleFPU())
    Builder.defineMacro("__SH_FPU_DOUBLE__");

  // How GCC makes a sequence atomic by default: on Linux the kernel
  // restarts one that was interrupted, elsewhere interrupts are masked.
  bool Restartable = getTriple().isOSLinux() && CPU->Arch != AK_SH2 &&
                     CPU->Arch != AK_J2 && CPU->Arch != AK_SH2E &&
                     CPU->Arch != AK_SH2A;
  Builder.defineMacro(Restartable ? "__SH_ATOMIC_MODEL_SOFT_GUSA__"
                                  : "__SH_ATOMIC_MODEL_SOFT_IMASK__");
  // On Linux libgcc has the operations on up to 32 bits, and the code
  // generator calls them.
  if (getTriple().isOSLinux()) {
    Builder.defineMacro("__GCC_HAVE_SYNC_COMPARE_AND_SWAP_1");
    Builder.defineMacro("__GCC_HAVE_SYNC_COMPARE_AND_SWAP_2");
    Builder.defineMacro("__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4");
  }
}

// The names that GCC knows, in its order as far as the registers exist
// here.  "ap", "rap" and "sfp" are registers of the compiler only.
const char *const SuperHTargetInfo::GCCRegNames[] = {
    "r0",   "r1",   "r2",    "r3",   "r4",   "r5",     "r6",     "r7",  "r8",
    "r9",   "r10",  "r11",   "r12",  "r13",  "r14",    "r15",    "fr0", "fr1",
    "fr2",  "fr3",  "fr4",   "fr5",  "fr6",  "fr7",    "fr8",    "fr9", "fr10",
    "fr11", "fr12", "fr13",  "fr14", "fr15", "xd0",    "xd2",    "xd4", "xd6",
    "xd8",  "xd10", "xd12",  "xd14", "gbr",  "ap",     "pr",     "t",   "mach",
    "macl", "fpul", "fpscr", "rap",  "sfp",  "fpscr0", "fpscr1", "dr0", "dr2",
    "dr4",  "dr6",  "dr8",   "dr10", "dr12", "dr14",   "fv0",    "fv4", "fv8",
    "fv12", "mtrx"};

ArrayRef<const char *> SuperHTargetInfo::getGCCRegNames() const {
  return llvm::ArrayRef(GCCRegNames);
}

const TargetInfo::GCCRegAlias SuperHTargetInfo::GCCRegAliases[] = {
    {{"sp"}, "r15"},
    {{"fp"}, "r14"},
};

ArrayRef<TargetInfo::GCCRegAlias> SuperHTargetInfo::getGCCRegAliases() const {
  return llvm::ArrayRef(GCCRegAliases);
}

bool SuperHTargetInfo::validateAsmConstraint(
    const char *&Name, TargetInfo::ConstraintInfo &Info) const {
  // The letters and the three-letter names of GCC's constraints.md.
  StringRef Rest(Name);
  auto Three = [&](std::initializer_list<StringRef> Names) {
    for (StringRef N : Names)
      if (Rest.starts_with(N)) {
        Name += 2;
        return true;
      }
    return false;
  };

  switch (*Name) {
  default:
    return false;
  // Register classes: any register, fpscr, a double precision register, a
  // floating point register (twice), a register for a sibling call, pr, T,
  // any register but r15, fr0, mach and macl, fpul, r0.
  case 'a':
  case 'c':
  case 'd':
  case 'e':
  case 'f':
  case 'k':
  case 'l':
  case 't':
  case 'u':
  case 'w':
  case 'x':
  case 'y':
  case 'z':
    Info.setAllowsRegister();
    return true;
  // Signed numbers of 8, 16, 20 and 28 bits.
  case 'I':
    if (Three({"I08"})) {
      Info.setRequiresImmediate(-128, 127);
      return true;
    }
    if (Three({"I16"})) {
      Info.setRequiresImmediate(-32768, 32767);
      return true;
    }
    if (Three({"I20"})) {
      Info.setRequiresImmediate(-524288, 524287);
      return true;
    }
    if (Three({"I28"})) {
      Info.setRequiresImmediate();
      return true;
    }
    return false;
  // Masks: the low byte, the low word, the highest bit.
  case 'J':
    if (Three({"Jmb"})) {
      Info.setRequiresImmediate(0xff);
      return true;
    }
    if (Three({"Jmw"})) {
      Info.setRequiresImmediate(0xffff);
      return true;
    }
    if (Three({"Jhb"})) {
      Info.setRequiresImmediate();
      return true;
    }
    return false;
  // Unsigned numbers of 3, 4, 5, 8, 12 and 13 bits.
  case 'K':
    if (Three({"K03"})) {
      Info.setRequiresImmediate(0, 7);
      return true;
    }
    if (Three({"K04"})) {
      Info.setRequiresImmediate(0, 15);
      return true;
    }
    if (Three({"K05"})) {
      Info.setRequiresImmediate(0, 31);
      return true;
    }
    if (Three({"K08"})) {
      Info.setRequiresImmediate(0, 255);
      return true;
    }
    if (Three({"K12"})) {
      Info.setRequiresImmediate(0, 4095);
      return true;
    }
    if (Three({"K13"})) {
      Info.setRequiresImmediate(0, 8191);
      return true;
    }
    return false;
  // 1 and 0.
  case 'M':
    Info.setRequiresImmediate(1);
    return true;
  case 'N':
    Info.setRequiresImmediate(0);
    return true;
  // The floating point numbers 0.0 and 1.0, and a zero of any type.
  case 'G':
  case 'H':
  case 'Z':
    Info.setRequiresImmediate();
    return true;
  // A shift by 1, 2, 8 or 16, a number with one bit set in its low byte,
  // and one with one bit clear there.
  case 'P':
    if (Three({"P27", "Pso", "Psz"})) {
      Info.setRequiresImmediate();
      return true;
    }
    return false;
  // A label or a symbol, and a constant that a register can be loaded with.
  case 'C':
    if (Three({"Csy", "Cpg"})) {
      Info.setRequiresImmediate();
      return true;
    }
    return false;
  // Memory: a load relative to the program counter, and the addressing
  // modes that an instruction can be limited to.
  case 'Q':
    Info.setAllowsMemory();
    return true;
  case 'S':
    if (Three({"Sua", "Sdd", "Snd", "Sid", "Ssd", "Sbv", "Sbw", "Sra"})) {
      Info.setAllowsMemory();
      return true;
    }
    return false;
  case 'A':
    if (Three({"Ara", "Add"})) {
      Info.setAllowsMemory();
      return true;
    }
    return false;
  }
}

// A constraint of three letters goes to the code generator as "@3xyz".
std::string SuperHTargetInfo::convertConstraint(const char *&Constraint) const {
  switch (*Constraint) {
  case 'I':
  case 'J':
  case 'K':
  case 'P':
  case 'C':
  case 'S':
  case 'A': {
    std::string Converted = "@3" + std::string(Constraint, 3);
    Constraint += 2;
    return Converted;
  }
  default:
    return TargetInfo::convertConstraint(Constraint);
  }
}
