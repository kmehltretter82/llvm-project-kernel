//===-- SHISelLowering.h - How LLVM operations become SuperH ones -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SH_SHISELLOWERING_H
#define LLVM_LIB_TARGET_SH_SHISELLOWERING_H

#include "MCTargetDesc/SHMCTargetDesc.h"
#include "llvm/CodeGen/CallingConvLower.h"
#include "llvm/CodeGen/SelectionDAG.h"
#include "llvm/CodeGen/TargetLowering.h"

namespace llvm {

class SHSubtarget;

class SHTargetLowering : public TargetLowering {
  const SHSubtarget &Subtarget;

public:
  explicit SHTargetLowering(const TargetMachine &TM, const SHSubtarget &STI);

  SDValue LowerOperation(SDValue Op, SelectionDAG &DAG) const override;

  MachineBasicBlock *
  EmitInstrWithCustomInserter(MachineInstr &MI,
                              MachineBasicBlock *BB) const override;

  ConstraintType getConstraintType(StringRef Constraint) const override;
  std::pair<unsigned, const TargetRegisterClass *>
  getRegForInlineAsmConstraint(const TargetRegisterInfo *TRI,
                               StringRef Constraint, MVT VT) const override;

  /// "register unsigned long sp asm("r15")": the registers that a global
  /// variable can be, which are the ones that the allocator never uses.
  Register getRegisterByName(const char *RegName, LLT VT,
                             const MachineFunction &MF) const override;

  // shad and shld take the amount from a whole register.
  MVT getScalarShiftAmountTy(const DataLayout &, EVT) const override {
    return MVT::i32;
  }

  // movt puts the result of a comparison into a whole register.
  EVT getSetCCResultType(const DataLayout &, LLVMContext &,
                         EVT VT) const override {
    if (VT.isVector())
      return VT.changeVectorElementTypeToInteger();
    return MVT::i32;
  }

  /// A landing pad finds the exception in r4 and what it is in r5, where
  /// the unwinder of libgcc puts them.
  Register
  getExceptionPointerRegister(ExceptionHandling,
                              const Constant *PersonalityFn) const override {
    return SH::R4;
  }
  Register
  getExceptionSelectorRegister(ExceptionHandling,
                               const Constant *PersonalityFn) const override {
    return SH::R5;
  }

  /// What libgcc has no function for becomes a loop around a compare and
  /// swap.
  AtomicExpansionKind
  shouldExpandAtomicRMWInIR(const AtomicRMWInst *RMW) const override;

  /// The registers for the first words of a structure that is passed by
  /// value.
  void HandleByVal(CCState *State, unsigned &Size,
                   Align Alignment) const override;

  /// With a floating point unit an argument is in registers only if all of
  /// it fits, so the parts of one are placed together.
  bool functionArgumentNeedsConsecutiveRegisters(
      Type *Ty, CallingConv::ID CallConv, bool IsVarArg,
      const DataLayout &DL) const override;

private:
  MachineBasicBlock *emitSelect(MachineInstr &MI, MachineBasicBlock *BB) const;
  MachineBasicBlock *emitBlockCopy(MachineInstr &MI,
                                   MachineBasicBlock *BB) const;

  SDValue LowerBR_CC(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerSETCC(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerSELECT_CC(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerAddress(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerGlobalTLSAddress(SDValue Op, SelectionDAG &DAG) const;
  /// The address of the global offset table, in the register that the
  /// function keeps it in.
  SDValue getGlobalBase(SelectionDAG &DAG, const SDLoc &DL) const;
  SDValue LowerDivision(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerVASTART(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerVACOPY(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerShift(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerAtomicLoadStore(SDValue Op, SelectionDAG &DAG) const;
  CCAssignFn *getArgConvention() const;
  SDValue LowerFRAMEADDR(SDValue Op, SelectionDAG &DAG) const;
  SDValue LowerRETURNADDR(SDValue Op, SelectionDAG &DAG) const;

  SDValue LowerFormalArguments(SDValue Chain, CallingConv::ID CallConv,
                               bool IsVarArg,
                               const SmallVectorImpl<ISD::InputArg> &Ins,
                               const SDLoc &DL, SelectionDAG &DAG,
                               SmallVectorImpl<SDValue> &InVals) const override;
  bool mayBeEmittedAsTailCall(const CallInst *CI) const override;
  bool isEligibleForTailCall(const TargetLowering::CallLoweringInfo &CLI,
                             const MachineFunction &MF,
                             unsigned StackSize) const;
  SDValue LowerCall(TargetLowering::CallLoweringInfo &CLI,
                    SmallVectorImpl<SDValue> &InVals) const override;
  bool CanLowerReturn(CallingConv::ID CallConv, MachineFunction &MF,
                      bool IsVarArg,
                      const SmallVectorImpl<ISD::OutputArg> &Outs,
                      LLVMContext &Context, const Type *RetTy) const override;
  SDValue LowerReturn(SDValue Chain, CallingConv::ID CallConv, bool IsVarArg,
                      const SmallVectorImpl<ISD::OutputArg> &Outs,
                      const SmallVectorImpl<SDValue> &OutVals, const SDLoc &DL,
                      SelectionDAG &DAG) const override;
};

} // namespace llvm

#endif
