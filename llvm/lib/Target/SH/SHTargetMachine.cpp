//===-- SHTargetMachine.cpp - The SuperH target machine -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SHTargetMachine.h"
#include "SH.h"
#include "SHMachineFunctionInfo.h"
#include "TargetInfo/SHTargetInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetLoweringObjectFileImpl.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/PassRegistry.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Transforms/Scalar.h"

using namespace llvm;

extern "C" LLVM_ABI LLVM_EXTERNAL_VISIBILITY void LLVMInitializeSHTarget() {
  RegisterTargetMachine<SHTargetMachine> X(getTheSHTarget());
  RegisterTargetMachine<SHTargetMachine> Y(getTheSHebTarget());
  PassRegistry &PR = *PassRegistry::getPassRegistry();
  initializeSHAsmPrinterPass(PR);
}

static Reloc::Model getEffectiveRelocModel(std::optional<Reloc::Model> RM) {
  return RM.value_or(Reloc::Static);
}

SHTargetMachine::SHTargetMachine(const Target &T, const Triple &TT,
                                 StringRef CPU, StringRef FS,
                                 const TargetOptions &Options,
                                 std::optional<Reloc::Model> RM,
                                 std::optional<CodeModel::Model> CM,
                                 CodeGenOptLevel OL, bool JIT)
    : CodeGenTargetMachineImpl(T, TT, CPU, FS, Options,
                               getEffectiveRelocModel(RM),
                               getEffectiveCodeModel(CM, CodeModel::Small), OL),
      TLOF(std::make_unique<TargetLoweringObjectFileELF>()) {
  initAsmInfo();
}

SHTargetMachine::~SHTargetMachine() = default;

const SHSubtarget *SHTargetMachine::getSubtargetImpl(const Function &F) const {
  Attribute CPUAttr = F.getFnAttribute("target-cpu");
  Attribute FSAttr = F.getFnAttribute("target-features");

  std::string CPU =
      CPUAttr.isValid() ? CPUAttr.getValueAsString().str() : TargetCPU;
  std::string FS =
      FSAttr.isValid() ? FSAttr.getValueAsString().str() : TargetFS;

  auto &I = SubtargetMap[CPU + FS];
  if (!I)
    I = std::make_unique<SHSubtarget>(TargetTriple, CPU, FS, *this);
  return I.get();
}

MachineFunctionInfo *SHTargetMachine::createMachineFunctionInfo(
    BumpPtrAllocator &Allocator, const Function &F,
    const TargetSubtargetInfo *STI) const {
  return SHMachineFunctionInfo::create<SHMachineFunctionInfo>(Allocator, F,
                                                              STI);
}

namespace {

class SHPassConfig : public TargetPassConfig {
public:
  SHPassConfig(SHTargetMachine &TM, PassManagerBase &PM)
      : TargetPassConfig(TM, PM) {}

  SHTargetMachine &getSHTargetMachine() const {
    return getTM<SHTargetMachine>();
  }

  void addIRPasses() override;
  bool addInstSelector() override;
  void addPreEmitPass() override;
};

} // namespace

void SHPassConfig::addIRPasses() {
  addPass(createAtomicExpandLegacyPass());
  TargetPassConfig::addIRPasses();
}

bool SHPassConfig::addInstSelector() {
  addPass(createSHISelDag(getSHTargetMachine(), getOptLevel()));
  return false;
}

// The two passes that need the final order and size of the code: the
// instruction behind a delayed branch, and the places of the literals.
void SHPassConfig::addPreEmitPass() {
  addPass(createSHDelaySlotFillerPass());
  addPass(createSHConstantIslandsPass());
}

TargetPassConfig *SHTargetMachine::createPassConfig(PassManagerBase &PM) {
  return new SHPassConfig(*this, PM);
}
