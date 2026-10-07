//===--- SuperH.cpp - SuperH Helpers for Tools ------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SuperH.h"
#include "clang/Options/Options.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Option/Arg.h"
#include "llvm/TargetParser/SHTargetParser.h"

using namespace clang::driver;
using namespace clang::driver::tools;
using namespace clang;
using namespace llvm::opt;
using llvm::StringRef;

std::string superh::getSuperHTargetCPU(const ArgList &Args,
                                       const llvm::Triple &Triple) {
  if (const Arg *A = Args.getLastArg(options::OPT_m_superh_cpu_Group,
                                     options::OPT_mcpu_EQ)) {
    if (A->getOption().matches(options::OPT_mcpu_EQ))
      return A->getValue();
    // "m4-nofpu" is the processor "sh4-nofpu".
    StringRef Name = A->getOption().getName();
    Name.consume_front("m");
    return Name == "j2" ? "j2" : ("sh" + Name).str();
  }
  return llvm::SH::getDefaultCPU(Triple).str();
}

std::string superh::getSuperHAsmISA(StringRef CPU) {
  using namespace llvm::SH;
  const CPUInfo *Info = parseCPU(CPU);
  if (!Info)
    return "";
  switch (Info->Arch) {
  case AK_SH2:
    return "--isa=sh2";
  // GNU as has no name for the J2, and takes its instructions when it is
  // not limited to a set.
  case AK_J2:
    return "";
  case AK_SH2E:
    return "--isa=sh2e";
  case AK_SH2A:
    return Info->hasFPU() ? "--isa=sh2a" : "--isa=sh2a-nofpu";
  case AK_SH3:
    return "--isa=sh3";
  case AK_SH3E:
    return "--isa=sh3e";
  // GCC passes the instruction set of the SH-4A for every SH-4.
  case AK_SH4:
  case AK_SH4A:
    if (Info->DSP)
      return "-dsp";
    return Info->hasFPU() ? "--isa=sh4a" : "--isa=sh4a-nofpu";
  }
  return "";
}
