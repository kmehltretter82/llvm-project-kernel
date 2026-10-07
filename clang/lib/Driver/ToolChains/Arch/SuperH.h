//===--- SuperH.h - SuperH-specific Tool Helpers -----------------*- C++
//-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_DRIVER_TOOLCHAINS_ARCH_SUPERH_H
#define LLVM_CLANG_LIB_DRIVER_TOOLCHAINS_ARCH_SUPERH_H

#include "llvm/Option/ArgList.h"
#include "llvm/TargetParser/Triple.h"
#include <string>

namespace clang {
namespace driver {
namespace tools {
namespace superh {

/// The processor: what the last of -m4, -m4-nofpu, -m2 ... and -mcpu= names,
/// and otherwise what the first component of the triple stands for.
std::string getSuperHTargetCPU(const llvm::opt::ArgList &Args,
                               const llvm::Triple &Triple);

/// The instruction set to tell the assembler, as GCC does: "--isa=sh4a".
/// Empty for a processor that GCC passes nothing for.
std::string getSuperHAsmISA(llvm::StringRef CPU);

} // end namespace superh
} // end namespace tools
} // end namespace driver
} // end namespace clang

#endif // LLVM_CLANG_LIB_DRIVER_TOOLCHAINS_ARCH_SUPERH_H
