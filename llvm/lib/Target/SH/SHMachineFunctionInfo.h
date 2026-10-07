//===-- SHMachineFunctionInfo.h - What the backend keeps for a function
//-----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SH_SHMACHINEFUNCTIONINFO_H
#define LLVM_LIB_TARGET_SH_SHMACHINEFUNCTIONINFO_H

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/Register.h"

namespace llvm {

class SHMachineFunctionInfo : public MachineFunctionInfo {
  /// The frame index of the first variable argument.
  int VarArgsFrameIndex = 0;
  /// The size of the area right below the arguments that came on the stack,
  /// in which the function stores argument registers so that they and the
  /// stack make one row: the registers that hold none of the named
  /// parameters of a function with variable arguments, or the ones with the
  /// first words of a structure whose rest is on the stack.
  unsigned ArgRegSaveSize = 0;
  /// The register with the address for a result that is returned in memory.
  Register SRetReturnReg;
  /// The register with the address of the global offset table, if position
  /// independent code needs it.
  Register GlobalBaseReg;
  /// With a floating point unit: the buffer in which a function with
  /// variable arguments stores the registers that hold none of its named
  /// parameters, where the registers start in it, and how many of each
  /// kind there are.
  int VarArgsRegSaveIndex = 0;
  unsigned VarArgsRegSaveOffset = 0;
  unsigned VarArgsNumFloat = 0;
  unsigned VarArgsNumInt = 0;

public:
  SHMachineFunctionInfo(const Function &F, const TargetSubtargetInfo *STI) {}

  MachineFunctionInfo *
  clone(BumpPtrAllocator &Allocator, MachineFunction &DestMF,
        const DenseMap<MachineBasicBlock *, MachineBasicBlock *> &Src2DstMBB)
      const override {
    return DestMF.cloneInfo<SHMachineFunctionInfo>(*this);
  }

  int getVarArgsFrameIndex() const { return VarArgsFrameIndex; }
  void setVarArgsFrameIndex(int Index) { VarArgsFrameIndex = Index; }
  unsigned getArgRegSaveSize() const { return ArgRegSaveSize; }
  void setArgRegSaveSize(unsigned Size) { ArgRegSaveSize = Size; }
  Register getSRetReturnReg() const { return SRetReturnReg; }
  void setSRetReturnReg(Register Reg) { SRetReturnReg = Reg; }
  Register getGlobalBaseReg() const { return GlobalBaseReg; }
  void setGlobalBaseReg(Register Reg) { GlobalBaseReg = Reg; }

  void setVarArgsRegSave(int Index, unsigned Offset, unsigned NumFloat,
                         unsigned NumInt) {
    VarArgsRegSaveIndex = Index;
    VarArgsRegSaveOffset = Offset;
    VarArgsNumFloat = NumFloat;
    VarArgsNumInt = NumInt;
  }
  int getVarArgsRegSaveIndex() const { return VarArgsRegSaveIndex; }
  unsigned getVarArgsRegSaveOffset() const { return VarArgsRegSaveOffset; }
  unsigned getVarArgsNumFloat() const { return VarArgsNumFloat; }
  unsigned getVarArgsNumInt() const { return VarArgsNumInt; }
};

} // namespace llvm

#endif
