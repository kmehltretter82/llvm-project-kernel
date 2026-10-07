//===-- SHTargetInfo.h - SuperH target registration -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SH_TARGETINFO_SHTARGETINFO_H
#define LLVM_LIB_TARGET_SH_TARGETINFO_SHTARGETINFO_H

namespace llvm {

class Target;

Target &getTheSHTarget();
Target &getTheSHebTarget();

} // namespace llvm

#endif
