//===--- ParseOnly.h - Targets without a backend ----------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file declares a TargetInfo for architectures that the Linux kernel
// supports and LLVM has no backend for: Alpha, PA-RISC, SuperH, MicroBlaze,
// Nios II and OpenRISC.  It describes their C data model well enough for the
// frontend to parse and check code written for them.  No code can be
// generated: these targets are for -fsyntax-only.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_BASIC_TARGETS_PARSEONLY_H
#define LLVM_CLANG_LIB_BASIC_TARGETS_PARSEONLY_H

#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/TargetOptions.h"
#include "llvm/Support/Compiler.h"
#include "llvm/TargetParser/Triple.h"
#include <optional>

namespace clang {
namespace targets {

class LLVM_LIBRARY_VISIBILITY ParseOnlyTargetInfo : public TargetInfo {
public:
  enum ArchKind {
    Alpha,
    PARISC,
    PARISC64,
    SuperH,
    MicroBlaze,
    Nios2,
    OpenRISC,
  };

  /// The architecture that the first component of \p Triple names, if it is
  /// one of those this class describes.  LLVM does not know them, so the
  /// triple has llvm::Triple::UnknownArch for all of them.
  static std::optional<ArchKind> getArchKind(const llvm::Triple &Triple);

  ParseOnlyTargetInfo(const llvm::Triple &Triple, const TargetOptions &Opts);

  void getTargetDefines(const LangOptions &Opts,
                        MacroBuilder &Builder) const override;

  /// The kernel selects the processor with -mcpu=, -march= and a number of
  /// -m flags.  Every name is accepted.  Only Alpha has predefined macros
  /// that depend on it.
  bool isValidCPUName(StringRef Name) const override { return true; }
  bool setCPU(StringRef Name) override {
    CPU = Name.str();
    return true;
  }

  bool hasFeature(StringRef Feature) const override;

  BuiltinVaListKind getBuiltinVaListKind() const override {
    return TargetInfo::VoidPtrBuiltinVaList;
  }

  /// GCC's builtin functions for Alpha, which the kernel headers use.
  llvm::SmallVector<Builtin::InfosShard> getTargetBuiltins() const override;

  /// Register names are not checked: what is written in a clobber list, in
  /// an explicit register variable or in a constraint is taken as it is.
  bool isValidGCCRegisterName(StringRef Name) const override {
    return !Name.empty();
  }
  ArrayRef<const char *> getGCCRegNames() const override;
  ArrayRef<TargetInfo::GCCRegAlias> getGCCRegAliases() const override {
    return {};
  }

  bool validateAsmConstraint(const char *&Name,
                             TargetInfo::ConstraintInfo &Info) const override {
    // A machine-specific constraint letter.  Most of them name a register
    // class, and none of them matters without a code generator.
    Info.setAllowsRegister();
    return true;
  }

  std::string_view getClobbers() const override { return ""; }

  bool hasBitIntType() const override { return true; }

private:
  ArchKind Arch;
  std::string CPU;
};

} // namespace targets
} // namespace clang

#endif // LLVM_CLANG_LIB_BASIC_TARGETS_PARSEONLY_H
