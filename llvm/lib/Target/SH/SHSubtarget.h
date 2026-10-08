//===-- SHSubtarget.h - The processor that code is generated for -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SH_SHSUBTARGET_H
#define LLVM_LIB_TARGET_SH_SHSUBTARGET_H

#include "SHFrameLowering.h"
#include "SHISelLowering.h"
#include "SHInstrInfo.h"
#include "SHSelectionDAGInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/TargetParser/Triple.h"

#define GET_SUBTARGETINFO_HEADER
#include "SHGenSubtargetInfo.inc"

namespace llvm {
class StringRef;
class TargetMachine;

class SHSubtarget : public SHGenSubtargetInfo {
  const Triple TargetTriple;
  bool HasDynShift = false;
  bool HasJ2 = false;
  bool HasSH2A = false;
  bool HasSH3 = false;
  bool HasSH4 = false;
  bool HasSH4A = false;
  bool HasFPU = false;
  bool HasFPUDouble = false;
  bool HasFPUSingleMode = false;

  SHInstrInfo InstrInfo;
  SHTargetLowering TLInfo;
  SHSelectionDAGInfo TSInfo;
  SHFrameLowering FrameLowering;

  SHSubtarget &initializeSubtargetDependencies(StringRef CPU, StringRef FS);

public:
  SHSubtarget(const Triple &TT, StringRef CPU, StringRef FS,
              const TargetMachine &TM);
  ~SHSubtarget() override;

  const Triple &getTargetTriple() const { return TargetTriple; }
  bool isLittleEndian() const { return TargetTriple.isLittleEndian(); }
  bool hasDynShift() const { return HasDynShift; }
  /// float is computed, passed and returned in floating point registers.
  bool hasFPU() const { return HasFPU; }
  /// double as well.
  bool hasFPUDouble() const { return HasFPUDouble; }
  /// A function is entered with the unit computing float, not double.
  bool hasFPUSingleMode() const { return HasFPUSingleMode; }
  /// fpchg changes the precision.
  bool hasSH4A() const { return HasSH4A; }
  /// The SH-4 before the SH-4A decodes what stands behind an instruction
  /// that raises an exception far enough to write to the cache or to a
  /// floating point register with it.  Its manuals ask for five "or r0,r0"
  /// behind trapa, sleep and the undefined instruction (SH7751 Group,
  /// 7.4.1).
  bool padsTraps() const { return HasSH4 && !HasSH4A; }
  /// An SH-4 that uses its unit for double.  GCC has two rules for it
  /// alone: see llvm/TargetParser/SHTargetParser.h.
  bool isSH4FPU() const { return HasSH4 && HasFPUDouble; }
  bool leavesRegistersFree() const { return isSH4FPU() || HasSH2A; }

  const TargetFrameLowering *getFrameLowering() const override {
    return &FrameLowering;
  }
  const SHInstrInfo *getInstrInfo() const override { return &InstrInfo; }
  const SHRegisterInfo *getRegisterInfo() const override {
    return &InstrInfo.getRegisterInfo();
  }
  const SHTargetLowering *getTargetLowering() const override { return &TLInfo; }
  const SelectionDAGTargetInfo *getSelectionDAGInfo() const override {
    return &TSInfo;
  }

  // From SHGenSubtargetInfo.inc.
  void ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS);
};

} // namespace llvm

#endif
