//===-- SHSubtarget.cpp - The processor that code is generated for -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SHSubtarget.h"
#include "MCTargetDesc/SHMCTargetDesc.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/TargetParser/SHTargetParser.h"

using namespace llvm;

#define DEBUG_TYPE "sh-subtarget"

#define GET_SUBTARGETINFO_TARGET_DESC
#define GET_SUBTARGETINFO_CTOR
#include "SHGenSubtargetInfo.inc"

SHSubtarget &SHSubtarget::initializeSubtargetDependencies(StringRef CPU,
                                                          StringRef FS) {
  // The processor that the triple stands for, as for clang.
  if (CPU.empty())
    CPU = SH::getDefaultCPU(TargetTriple);
  ParseSubtargetFeatures(CPU, /*TuneCPU=*/CPU, FS);
  if (HasFPU)
    reportFatalUsageError(
        "the floating point unit of SuperH is not supported yet: select a "
        "processor without one, such as sh4-nofpu (-m4-nofpu)");
  return *this;
}

SHSubtarget::SHSubtarget(const Triple &TT, StringRef CPU, StringRef FS,
                         const TargetMachine &TM)
    : SHGenSubtargetInfo(TT, CPU, /*TuneCPU=*/CPU, FS), TargetTriple(TT),
      InstrInfo(initializeSubtargetDependencies(CPU, FS)), TLInfo(TM, *this),
      FrameLowering(*this) {}

SHSubtarget::~SHSubtarget() = default;
