//===--- ParseOnly.cpp - Targets without a backend ------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements ParseOnlyTargetInfo.
//
//===----------------------------------------------------------------------===//

#include "ParseOnly.h"
#include "clang/Basic/Builtins.h"
#include "clang/Basic/MacroBuilder.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringSwitch.h"

using namespace clang;
using namespace clang::targets;

// The Alpha builtins are only declared: nothing outside this file needs
// their numbers.
namespace {
enum {
  LastTIBuiltin = Builtin::FirstTSBuiltin - 1,
#define BUILTIN(ID, TYPE, ATTRS) BI##ID,
#include "BuiltinsAlpha.def"
  LastAlphaBuiltin
};
} // namespace

static constexpr int NumAlphaBuiltins =
    LastAlphaBuiltin - Builtin::FirstTSBuiltin;

static constexpr llvm::StringTable AlphaBuiltinStrings =
    CLANG_BUILTIN_STR_TABLE_START
#define BUILTIN CLANG_BUILTIN_STR_TABLE
#include "BuiltinsAlpha.def"
    ;

static constexpr auto AlphaBuiltinInfos =
    Builtin::MakeInfos<NumAlphaBuiltins>({
#define BUILTIN CLANG_BUILTIN_ENTRY
#include "BuiltinsAlpha.def"
    });

llvm::SmallVector<Builtin::InfosShard>
ParseOnlyTargetInfo::getTargetBuiltins() const {
  if (Arch == Alpha)
    return {{&AlphaBuiltinStrings, AlphaBuiltinInfos}};
  return {};
}

std::optional<ParseOnlyTargetInfo::ArchKind>
ParseOnlyTargetInfo::getArchKind(const llvm::Triple &Triple) {
  if (Triple.getArch() != llvm::Triple::UnknownArch)
    return std::nullopt;
  StringRef Name = Triple.getArchName();
  if (Name.starts_with("alpha"))
    return Alpha;
  if (Name == "hppa64" || Name == "parisc64")
    return PARISC64;
  if (Name.starts_with("hppa") || Name == "parisc")
    return PARISC;
  if (Name.starts_with("microblaze"))
    return MicroBlaze;
  if (Name.starts_with("nios2"))
    return Nios2;
  if (Name.starts_with("or1k") || Name == "openrisc")
    return OpenRISC;
  // sh, sh2, sh3, sh4, sh4a and their big-endian forms such as sh4eb.
  if (Name.consume_front("sh")) {
    Name.consume_back("eb");
    Name.consume_back("el");
    if (Name.empty() || (llvm::isDigit(Name[0]) && Name.size() <= 2))
      return SuperH;
  }
  return std::nullopt;
}

ParseOnlyTargetInfo::ParseOnlyTargetInfo(const llvm::Triple &Triple,
                                         const TargetOptions &)
    : TargetInfo(Triple), Arch(*getArchKind(Triple)) {
  StringRef Name = Triple.getArchName();

  // The 32-bit data model of the TargetInfo defaults, with the types that
  // GCC uses for size_t and its relatives on these targets.
  SizeType = UnsignedInt;
  PtrDiffType = SignedInt;
  IntPtrType = SignedInt;
  TLSSupported = true;
  HasFloat128 = false;

  // GCC aligns 64-bit integers and doubles to 32 bits where its
  // BIGGEST_ALIGNMENT is 32.
  auto Align64To32 = [this] {
    LongLongAlign = 32;
    DoubleAlign = LongDoubleAlign = 32;
    SuitableAlign = 32;
  };

  switch (Arch) {
  case Alpha:
    BigEndian = false;
    PointerWidth = PointerAlign = 64;
    LongWidth = LongAlign = 64;
    SizeType = UnsignedLong;
    PtrDiffType = SignedLong;
    IntPtrType = SignedLong;
    IntMaxType = SignedLong;
    Int64Type = SignedLong;
    LongDoubleWidth = LongDoubleAlign = 128;
    LongDoubleFormat = &llvm::APFloat::IEEEquad();
    SuitableAlign = 128;
    MaxAtomicPromoteWidth = MaxAtomicInlineWidth = 64;
    resetDataLayout("e-m:e-p:64:64-i64:64-n64-S128");
    break;
  case PARISC64:
    BigEndian = true;
    PointerWidth = PointerAlign = 64;
    LongWidth = LongAlign = 64;
    SizeType = UnsignedLong;
    PtrDiffType = SignedLong;
    IntPtrType = SignedLong;
    IntMaxType = SignedLong;
    Int64Type = SignedLong;
    LongDoubleWidth = LongDoubleAlign = 128;
    LongDoubleFormat = &llvm::APFloat::IEEEquad();
    SuitableAlign = 128;
    MaxAtomicPromoteWidth = MaxAtomicInlineWidth = 64;
    resetDataLayout("E-m:e-p:64:64-i64:64-n32:64-S128");
    break;
  case PARISC:
    BigEndian = true;
    MaxAtomicPromoteWidth = MaxAtomicInlineWidth = 32;
    resetDataLayout("E-m:e-p:32:32-i64:64-n32-S64");
    break;
  case SuperH:
    BigEndian = Name.ends_with("eb");
    WCharType = SignedLong;
    Align64To32();
    MaxAtomicPromoteWidth = MaxAtomicInlineWidth = 32;
    resetDataLayout(BigEndian ? "E-m:e-p:32:32-i64:32-f64:32-n32-S32"
                              : "e-m:e-p:32:32-i64:32-f64:32-n32-S32");
    break;
  case MicroBlaze:
    BigEndian = !Name.ends_with("el");
    Align64To32();
    MaxAtomicPromoteWidth = MaxAtomicInlineWidth = 32;
    resetDataLayout(BigEndian ? "E-m:e-p:32:32-i64:32-f64:32-n32-S32"
                              : "e-m:e-p:32:32-i64:32-f64:32-n32-S32");
    break;
  case Nios2:
    BigEndian = false;
    Align64To32();
    MaxAtomicPromoteWidth = MaxAtomicInlineWidth = 32;
    resetDataLayout("e-m:e-p:32:32-i64:32-f64:32-n32-S32");
    break;
  case OpenRISC:
    BigEndian = true;
    Align64To32();
    MaxAtomicPromoteWidth = MaxAtomicInlineWidth = 32;
    resetDataLayout("E-m:e-p:32:32-i64:32-f64:32-n32-S32");
    break;
  }
}

ArrayRef<const char *> ParseOnlyTargetInfo::getGCCRegNames() const {
  // A register that is named by its number alone, as "$30" is on Alpha, is
  // looked up in this list.
  static const char *const Names[] = {
      "r0",  "r1",  "r2",  "r3",  "r4",  "r5",  "r6",  "r7",  "r8",  "r9",
      "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19",
      "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29",
      "r30", "r31", "r32", "r33", "r34", "r35", "r36", "r37", "r38", "r39",
      "r40", "r41", "r42", "r43", "r44", "r45", "r46", "r47", "r48", "r49",
      "r50", "r51", "r52", "r53", "r54", "r55", "r56", "r57", "r58", "r59",
      "r60", "r61", "r62", "r63"};
  return llvm::ArrayRef(Names);
}

bool ParseOnlyTargetInfo::hasFeature(StringRef Feature) const {
  switch (Arch) {
  case Alpha:
    return Feature == "alpha";
  case PARISC:
  case PARISC64:
    return Feature == "hppa";
  case SuperH:
    return Feature == "sh";
  case MicroBlaze:
    return Feature == "microblaze";
  case Nios2:
    return Feature == "nios2";
  case OpenRISC:
    return Feature == "or1k";
  }
  return false;
}

void ParseOnlyTargetInfo::getTargetDefines(const LangOptions &Opts,
                                           MacroBuilder &Builder) const {
  switch (Arch) {
  case Alpha: {
    Builder.defineMacro("__alpha__");
    Builder.defineMacro("__alpha");
    // The instruction set extensions by processor, as GCC defines them.
    StringRef C = CPU;
    bool BWX = llvm::StringSwitch<bool>(C)
                   .Cases({"ev56", "pca56", "ev6", "ev67", "ev68"}, true)
                   .Cases({"21164a", "21164pc", "21264", "21264a"}, true)
                   .Default(false);
    bool EV6 = llvm::StringSwitch<bool>(C)
                   .Cases({"ev6", "ev67", "ev68", "21264", "21264a"}, true)
                   .Default(false);
    bool EV67 = llvm::StringSwitch<bool>(C)
                    .Cases({"ev67", "ev68", "21264a"}, true)
                    .Default(false);
    if (BWX)
      Builder.defineMacro("__alpha_bwx__");
    if (C == "pca56" || C == "21164pc" || EV6)
      Builder.defineMacro("__alpha_max__");
    if (EV6)
      Builder.defineMacro("__alpha_fix__");
    if (EV67)
      Builder.defineMacro("__alpha_cix__");
    Builder.defineMacro(EV67  ? "__alpha_ev67__"
                        : EV6 ? "__alpha_ev6__"
                        : BWX ? "__alpha_ev56__"
                              : "__alpha_ev4__");
    break;
  }
  case PARISC:
    Builder.defineMacro("__hppa__");
    Builder.defineMacro("__hppa");
    Builder.defineMacro("_PA_RISC1_1");
    break;
  case PARISC64:
    Builder.defineMacro("__hppa__");
    Builder.defineMacro("__hppa");
    Builder.defineMacro("__hppa64__");
    Builder.defineMacro("_PA_RISC2_0");
    break;
  case SuperH:
    Builder.defineMacro("__sh__");
    Builder.defineMacro("__SH4__");
    break;
  case MicroBlaze:
    Builder.defineMacro("__microblaze__");
    Builder.defineMacro("__MICROBLAZE__");
    if (!BigEndian)
      Builder.defineMacro("__MICROBLAZEEL__");
    break;
  case Nios2:
    Builder.defineMacro("__nios2__");
    Builder.defineMacro("__NIOS2__");
    Builder.defineMacro("__nios2_little_endian__");
    break;
  case OpenRISC:
    Builder.defineMacro("__or1k__");
    Builder.defineMacro("__OR1K__");
    break;
  }
}
