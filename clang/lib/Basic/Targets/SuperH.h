//===--- SuperH.h - Declare SuperH target feature support -------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file declares the SuperH TargetInfo: SH-2, SH-3, SH-4 and J2 in
// either byte order, with the data model and the conventions of GCC.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_BASIC_TARGETS_SUPERH_H
#define LLVM_CLANG_LIB_BASIC_TARGETS_SUPERH_H

#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/TargetOptions.h"
#include "llvm/Support/Compiler.h"
#include "llvm/TargetParser/SHTargetParser.h"
#include "llvm/TargetParser/Triple.h"

namespace clang {
namespace targets {

class LLVM_LIBRARY_VISIBILITY SuperHTargetInfo : public TargetInfo {
  static const char *const GCCRegNames[];
  static const TargetInfo::GCCRegAlias GCCRegAliases[];

  /// The processor, which is never null: the triple names one if no option
  /// does.
  const llvm::SH::CPUInfo *CPU;

public:
  SuperHTargetInfo(const llvm::Triple &Triple, const TargetOptions &Opts);

  const llvm::SH::CPUInfo &getCPUInfo() const { return *CPU; }

  void getTargetDefines(const LangOptions &Opts,
                        MacroBuilder &Builder) const override;

  bool isValidCPUName(StringRef Name) const override {
    return llvm::SH::parseCPU(Name) != nullptr;
  }
  void fillValidCPUList(SmallVectorImpl<StringRef> &Values) const override {
    llvm::SH::fillValidCPUList(Values);
  }
  bool setCPU(StringRef Name) override;

  bool hasFeature(StringRef Feature) const override;

  /// With a floating point unit va_list is a structure, which keeps the
  /// floating point registers of a variadic function apart from the others.
  BuiltinVaListKind getBuiltinVaListKind() const override {
    return CPU->hasFPU() ? TargetInfo::SuperHBuiltinVaList
                         : TargetInfo::VoidPtrBuiltinVaList;
  }

  llvm::SmallVector<Builtin::InfosShard> getTargetBuiltins() const override {
    return {};
  }

  ArrayRef<const char *> getGCCRegNames() const override;
  ArrayRef<TargetInfo::GCCRegAlias> getGCCRegAliases() const override;

  bool validateAsmConstraint(const char *&Name,
                             TargetInfo::ConstraintInfo &Info) const override;
  std::string convertConstraint(const char *&Constraint) const override;

  std::string_view getClobbers() const override { return ""; }

  bool hasBitIntType() const override { return true; }

  // __alignof__(long long) is 4 for GCC, and no variable gets more.
  bool allowsLargerPreferedTypeAlignment() const override { return false; }

  /// The exception handler gets its data in r4 to r7.
  int getEHDataRegisterNumber(unsigned RegNo) const override {
    return RegNo < 4 ? int(4 + RegNo) : -1;
  }
};

} // namespace targets
} // namespace clang

#endif // LLVM_CLANG_LIB_BASIC_TARGETS_SUPERH_H
