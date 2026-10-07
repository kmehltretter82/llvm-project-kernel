//===-- SHMCTargetDesc.cpp - SuperH target descriptions -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SHMCTargetDesc.h"
#include "SHInstPrinter.h"
#include "SHMCAsmInfo.h"
#include "TargetInfo/SHTargetInfo.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/MC/MCDwarf.h"
#include "llvm/MC/MCELFObjectWriter.h"
#include "llvm/MC/MCELFStreamer.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/Compiler.h"
#include "llvm/TargetParser/SHTargetParser.h"
#include "llvm/TargetParser/Triple.h"

using namespace llvm;

#define GET_INSTRINFO_MC_DESC
#define ENABLE_INSTR_PREDICATE_VERIFIER
#include "SHGenInstrInfo.inc"

#define GET_SUBTARGETINFO_MC_DESC
#include "SHGenSubtargetInfo.inc"

#define GET_REGINFO_MC_DESC
#include "SHGenRegisterInfo.inc"

static MCInstrInfo *createSHMCInstrInfo() {
  MCInstrInfo *X = new MCInstrInfo();
  InitSHMCInstrInfo(X);
  return X;
}

static MCRegisterInfo *createSHMCRegisterInfo(const Triple &TT) {
  MCRegisterInfo *X = new MCRegisterInfo();
  InitSHMCRegisterInfo(X, SH::PR);
  return X;
}

static MCAsmInfo *createSHMCAsmInfo(const MCRegisterInfo &MRI, const Triple &TT,
                                    const MCTargetOptions &Options) {
  MCAsmInfo *MAI = new SHMCAsmInfo(TT, Options);
  // On entry the frame is at the stack pointer.
  MCCFIInstruction Inst = MCCFIInstruction::cfiDefCfa(
      nullptr, MRI.getDwarfRegNum(SH::R15, true), 0);
  MAI->addInitialFrameState(Inst);
  return MAI;
}

static MCSubtargetInfo *createSHMCSubtargetInfo(const Triple &TT, StringRef CPU,
                                                StringRef FS) {
  if (CPU.empty())
    CPU = SH::getDefaultCPU(TT);
  return createSHMCSubtargetInfoImpl(TT, CPU, /*TuneCPU=*/CPU, FS);
}

static MCInstPrinter *createSHMCInstPrinter(const Triple &T,
                                            unsigned SyntaxVariant,
                                            const MCAsmInfo &MAI,
                                            const MCInstrInfo &MII,
                                            const MCRegisterInfo &MRI) {
  if (SyntaxVariant == 0)
    return new SHInstPrinter(MAI, MII, MRI);
  return nullptr;
}

namespace {

/// What an object file says about the processor that its code is for.  GNU
/// as writes the least processor that has every instruction of the file,
/// or the one that it is told with --isa.  This is the processor that the
/// code was generated for.
class SHTargetELFStreamer : public MCTargetStreamer {
public:
  SHTargetELFStreamer(MCStreamer &S, const MCSubtargetInfo &STI)
      : MCTargetStreamer(S) {
    bool HasFPU =
        STI.hasFeature(SH::FeatureFPU) || STI.hasFeature(SH::FeatureFPUDouble);
    unsigned Flags;
    if (STI.hasFeature(SH::FeatureSH4A))
      Flags = HasFPU ? ELF::EF_SH4A : ELF::EF_SH4A_NOFPU;
    else if (STI.hasFeature(SH::FeatureSH4))
      Flags = HasFPU ? ELF::EF_SH4 : ELF::EF_SH4_NOFPU;
    else if (STI.hasFeature(SH::FeatureSH2A))
      Flags = HasFPU ? ELF::EF_SH2A : ELF::EF_SH2A_NOFPU;
    else if (STI.hasFeature(SH::FeatureSH3))
      Flags = HasFPU ? ELF::EF_SH3E : ELF::EF_SH3;
    else if (STI.hasFeature(SH::FeatureJ2))
      Flags = ELF::EF_SH3_NOMMU;
    else
      Flags = HasFPU ? ELF::EF_SH2E : ELF::EF_SH2;
    static_cast<MCELFStreamer &>(S).getWriter().setELFHeaderEFlags(Flags);
  }
};

} // namespace

static MCTargetStreamer *
createSHObjectTargetStreamer(MCStreamer &S, const MCSubtargetInfo &STI) {
  if (STI.getTargetTriple().isOSBinFormatELF())
    return new SHTargetELFStreamer(S, STI);
  return nullptr;
}

extern "C" LLVM_ABI LLVM_EXTERNAL_VISIBILITY void LLVMInitializeSHTargetMC() {
  for (Target *T : {&getTheSHTarget(), &getTheSHebTarget()}) {
    TargetRegistry::RegisterMCCodeEmitter(*T, createSHMCCodeEmitter);
    TargetRegistry::RegisterMCAsmBackend(*T, createSHAsmBackend);
    TargetRegistry::RegisterObjectTargetStreamer(*T,
                                                 createSHObjectTargetStreamer);
    TargetRegistry::RegisterMCAsmInfo(*T, createSHMCAsmInfo);
    TargetRegistry::RegisterMCInstrInfo(*T, createSHMCInstrInfo);
    TargetRegistry::RegisterMCRegInfo(*T, createSHMCRegisterInfo);
    TargetRegistry::RegisterMCSubtargetInfo(*T, createSHMCSubtargetInfo);
    TargetRegistry::RegisterMCInstPrinter(*T, createSHMCInstPrinter);
  }
}
