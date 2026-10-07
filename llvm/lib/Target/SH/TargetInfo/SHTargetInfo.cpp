//===-- SHTargetInfo.cpp - SuperH target registration -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "TargetInfo/SHTargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/Compiler.h"

using namespace llvm;

Target &llvm::getTheSHTarget() {
  static Target TheSHTarget;
  return TheSHTarget;
}

Target &llvm::getTheSHebTarget() {
  static Target TheSHebTarget;
  return TheSHebTarget;
}

extern "C" LLVM_ABI LLVM_EXTERNAL_VISIBILITY void LLVMInitializeSHTargetInfo() {
  RegisterTarget<Triple::sh> X(getTheSHTarget(), "sh", "SuperH (little endian)",
                               "SH");
  RegisterTarget<Triple::sheb> Y(getTheSHebTarget(), "sheb",
                                 "SuperH (big endian)", "SH");
}
