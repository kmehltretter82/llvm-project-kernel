//===-- SHTargetMachine.h - The SuperH target machine -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SH_SHTARGETMACHINE_H
#define LLVM_LIB_TARGET_SH_SHTARGETMACHINE_H

#include "SHSubtarget.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/CodeGen/CodeGenTargetMachineImpl.h"
#include <memory>
#include <optional>

namespace llvm {

class SHTargetMachine : public CodeGenTargetMachineImpl {
  std::unique_ptr<TargetLoweringObjectFile> TLOF;
  mutable StringMap<std::unique_ptr<SHSubtarget>> SubtargetMap;

public:
  SHTargetMachine(const Target &T, const Triple &TT, StringRef CPU,
                  StringRef FS, const TargetOptions &Options,
                  std::optional<Reloc::Model> RM,
                  std::optional<CodeModel::Model> CM, CodeGenOptLevel OL,
                  bool JIT);
  ~SHTargetMachine() override;

  const SHSubtarget *getSubtargetImpl(const Function &F) const override;
  TargetPassConfig *createPassConfig(PassManagerBase &PM) override;
  TargetLoweringObjectFile *getObjFileLowering() const override {
    return TLOF.get();
  }
  MachineFunctionInfo *
  createMachineFunctionInfo(BumpPtrAllocator &Allocator, const Function &F,
                            const TargetSubtargetInfo *STI) const override;
};

} // namespace llvm

#endif
