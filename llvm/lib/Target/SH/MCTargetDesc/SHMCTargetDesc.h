//===-- SHMCTargetDesc.h - SuperH target descriptions -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SH_MCTARGETDESC_SHMCTARGETDESC_H
#define LLVM_LIB_TARGET_SH_MCTARGETDESC_SHMCTARGETDESC_H

#include "llvm/Support/DataTypes.h"

#include <cstdint>
#include <memory>

namespace llvm {
class MCAsmBackend;
class MCCodeEmitter;
class MCContext;
class MCInstrInfo;
class MCObjectTargetWriter;
class MCRegisterInfo;
class MCSubtargetInfo;
class MCTargetOptions;
class Target;

MCCodeEmitter *createSHMCCodeEmitter(const MCInstrInfo &MCII, MCContext &Ctx);
MCAsmBackend *createSHAsmBackend(const Target &T, const MCSubtargetInfo &STI,
                                 const MCRegisterInfo &MRI,
                                 const MCTargetOptions &Options);
std::unique_ptr<MCObjectTargetWriter> createSHELFObjectWriter(uint8_t OSABI);
} // namespace llvm

// The names of the registers.
#define GET_REGINFO_ENUM
#include "SHGenRegisterInfo.inc"

// The names of the instructions.
#define GET_INSTRINFO_ENUM
#define GET_INSTRINFO_MC_HELPER_DECLS
#include "SHGenInstrInfo.inc"

#define GET_SUBTARGETINFO_ENUM
#include "SHGenSubtargetInfo.inc"

#endif
