//===-- SHISelLowering.cpp - How LLVM operations become SuperH ones -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Calls and returns in the convention of GCC, comparisons through the T bit,
// and addresses through literals.
//
//===----------------------------------------------------------------------===//

#include "SHISelLowering.h"
#include "SH.h"
#include "SHMachineFunctionInfo.h"
#include "SHSelectionDAGInfo.h"
#include "SHSubtarget.h"
#include "llvm/CodeGen/CallingConvLower.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/SelectionDAGNodes.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/Support/ErrorHandling.h"

using namespace llvm;

#define DEBUG_TYPE "sh-lower"

#define GET_CALLING_CONV_IMPL
#include "SHGenCallingConv.inc"

SHTargetLowering::SHTargetLowering(const TargetMachine &TM,
                                   const SHSubtarget &STI)
    : TargetLowering(TM, STI), Subtarget(STI) {
  addRegisterClass(MVT::i32, &SH::GPRRegClass);
  computeRegisterProperties(STI.getRegisterInfo());

  setStackPointerRegisterToSaveRestore(SH::R15);
  setBooleanContents(ZeroOrOneBooleanContent);
  setSchedulingPreference(Sched::RegPressure);
  // A literal is aligned to four bytes, and the distance of a literal from
  // the instruction that loads it is counted from the start of the function.
  setMinFunctionAlignment(Align(4));
  setPrefFunctionAlignment(Align(4));

  // mov.b and mov.w extend the sign.  An extension with zeros is a load
  // and extu.
  for (MVT VT : MVT::integer_valuetypes()) {
    setLoadExtAction(ISD::EXTLOAD, VT, MVT::i1, Promote);
    setLoadExtAction(ISD::SEXTLOAD, VT, MVT::i1, Promote);
    setLoadExtAction(ISD::ZEXTLOAD, VT, MVT::i1, Promote);
    setLoadExtAction(ISD::ZEXTLOAD, VT, MVT::i8, Expand);
    setLoadExtAction(ISD::ZEXTLOAD, VT, MVT::i16, Expand);
  }
  setOperationAction(ISD::SIGN_EXTEND_INREG, MVT::i1, Expand);

  // Everything that looks at a condition goes through the T bit.
  setOperationAction(ISD::BR_CC, MVT::i32, Custom);
  setOperationAction(ISD::BRCOND, MVT::Other, Expand);
  setOperationAction(ISD::SELECT, MVT::i32, Expand);
  setOperationAction(ISD::SELECT_CC, MVT::i32, Custom);
  setOperationAction(ISD::SETCC, MVT::i32, Custom);
  setOperationAction(ISD::BR_JT, MVT::Other, Expand);

  // Addresses are loaded from literals.
  setOperationAction(ISD::GlobalAddress, MVT::i32, Custom);
  setOperationAction(ISD::ExternalSymbol, MVT::i32, Custom);
  setOperationAction(ISD::BlockAddress, MVT::i32, Custom);
  setOperationAction(ISD::JumpTable, MVT::i32, Custom);
  setOperationAction(ISD::ConstantPool, MVT::i32, Custom);

  // There is no instruction that divides.  The division is a library call,
  // and the remainder is computed from the quotient: libgcc has no function
  // for it on SuperH.
  setOperationAction(ISD::SDIV, MVT::i32, Custom);
  setOperationAction(ISD::UDIV, MVT::i32, Custom);
  setOperationAction(ISD::SREM, MVT::i32, Expand);
  setOperationAction(ISD::UREM, MVT::i32, Expand);
  setOperationAction(ISD::SDIVREM, MVT::i32, Expand);
  setOperationAction(ISD::UDIVREM, MVT::i32, Expand);

  // dmulu.l and dmuls.l give the high half of a product.
  setOperationAction(ISD::SMUL_LOHI, MVT::i32, Expand);
  setOperationAction(ISD::UMUL_LOHI, MVT::i32, Expand);

  setOperationAction(ISD::SHL_PARTS, MVT::i32, Expand);
  setOperationAction(ISD::SRL_PARTS, MVT::i32, Expand);
  setOperationAction(ISD::SRA_PARTS, MVT::i32, Expand);
  setOperationAction(ISD::ROTL, MVT::i32, Expand);
  setOperationAction(ISD::ROTR, MVT::i32, Expand);
  setOperationAction(ISD::CTLZ, MVT::i32, Expand);
  setOperationAction(ISD::CTTZ, MVT::i32, Expand);
  setOperationAction(ISD::CTPOP, MVT::i32, Expand);

  setOperationAction(ISD::VASTART, MVT::Other, Custom);
  setOperationAction(ISD::VAARG, MVT::Other, Expand);
  setOperationAction(ISD::VACOPY, MVT::Other, Expand);
  setOperationAction(ISD::VAEND, MVT::Other, Expand);
  setOperationAction(ISD::DYNAMIC_STACKALLOC, MVT::i32, Expand);
  setOperationAction(ISD::STACKSAVE, MVT::Other, Expand);
  setOperationAction(ISD::STACKRESTORE, MVT::Other, Expand);
  setOperationAction(ISD::TRAP, MVT::Other, Expand);

  // Atomic operations are library calls.
  setMaxAtomicSizeInBitsSupported(0);
}

SDValue SHTargetLowering::LowerOperation(SDValue Op, SelectionDAG &DAG) const {
  switch (Op.getOpcode()) {
  case ISD::BR_CC:
    return LowerBR_CC(Op, DAG);
  case ISD::SETCC:
    return LowerSETCC(Op, DAG);
  case ISD::SELECT_CC:
    return LowerSELECT_CC(Op, DAG);
  case ISD::GlobalAddress:
  case ISD::ExternalSymbol:
  case ISD::BlockAddress:
  case ISD::JumpTable:
  case ISD::ConstantPool:
    return LowerAddress(Op, DAG);
  case ISD::SDIV:
  case ISD::UDIV:
    return LowerDivision(Op, DAG);
  case ISD::VASTART:
    return LowerVASTART(Op, DAG);
  case ISD::FRAMEADDR:
    return LowerFRAMEADDR(Op, DAG);
  case ISD::RETURNADDR:
    return LowerRETURNADDR(Op, DAG);
  default:
    llvm_unreachable("no custom lowering for this operation");
  }
}

//===----------------------------------------------------------------------===//
// Comparisons
//===----------------------------------------------------------------------===//

/// The comparison that leaves the answer to "LHS CC RHS" in the T bit, or its
/// opposite: \p OnTrue says which.  The node has no value but the glue that
/// ties it to its user.
static SDValue emitComparison(SDValue LHS, SDValue RHS, ISD::CondCode CC,
                              const SDLoc &DL, SelectionDAG &DAG,
                              bool &OnTrue) {
  unsigned Opc;
  OnTrue = true;
  switch (CC) {
  default:
    llvm_unreachable("not an integer condition");
  case ISD::SETNE:
    OnTrue = false;
    [[fallthrough]];
  case ISD::SETEQ:
    Opc = SHISD::CMPEQ;
    break;
  case ISD::SETLT:
    OnTrue = false;
    [[fallthrough]];
  case ISD::SETGE:
    Opc = SHISD::CMPGE;
    break;
  case ISD::SETLE:
    OnTrue = false;
    [[fallthrough]];
  case ISD::SETGT:
    Opc = SHISD::CMPGT;
    break;
  case ISD::SETULT:
    OnTrue = false;
    [[fallthrough]];
  case ISD::SETUGE:
    Opc = SHISD::CMPHS;
    break;
  case ISD::SETULE:
    OnTrue = false;
    [[fallthrough]];
  case ISD::SETUGT:
    Opc = SHISD::CMPHI;
    break;
  }

  // The forms that compare with zero.
  if (isNullConstant(RHS)) {
    switch (Opc) {
    case SHISD::CMPEQ:
      // "(a & b) == 0" is what tst computes.
      if (LHS.getOpcode() == ISD::AND && LHS.hasOneUse())
        return DAG.getNode(SHISD::TST, DL, MVT::Glue, LHS.getOperand(0),
                           LHS.getOperand(1));
      return DAG.getNode(SHISD::TST, DL, MVT::Glue, LHS, LHS);
    case SHISD::CMPGT:
      return DAG.getNode(SHISD::CMPPL, DL, MVT::Glue, LHS);
    case SHISD::CMPGE:
      return DAG.getNode(SHISD::CMPPZ, DL, MVT::Glue, LHS);
    default:
      break;
    }
  }
  return DAG.getNode(Opc, DL, MVT::Glue, LHS, RHS);
}

SDValue SHTargetLowering::LowerBR_CC(SDValue Op, SelectionDAG &DAG) const {
  SDLoc DL(Op);
  SDValue Chain = Op.getOperand(0);
  ISD::CondCode CC = cast<CondCodeSDNode>(Op.getOperand(1))->get();
  SDValue Dest = Op.getOperand(4);
  bool OnTrue;
  SDValue Glue =
      emitComparison(Op.getOperand(2), Op.getOperand(3), CC, DL, DAG, OnTrue);
  return DAG.getNode(OnTrue ? SHISD::BRT : SHISD::BRF, DL, MVT::Other, Chain,
                     Dest, Glue);
}

SDValue SHTargetLowering::LowerSETCC(SDValue Op, SelectionDAG &DAG) const {
  SDLoc DL(Op);
  ISD::CondCode CC = cast<CondCodeSDNode>(Op.getOperand(2))->get();
  bool OnTrue;
  SDValue Glue =
      emitComparison(Op.getOperand(0), Op.getOperand(1), CC, DL, DAG, OnTrue);
  return DAG.getNode(OnTrue ? SHISD::MOVT : SHISD::MOVRT, DL, MVT::i32, Glue);
}

SDValue SHTargetLowering::LowerSELECT_CC(SDValue Op, SelectionDAG &DAG) const {
  SDLoc DL(Op);
  ISD::CondCode CC = cast<CondCodeSDNode>(Op.getOperand(4))->get();
  SDValue TrueV = Op.getOperand(2);
  SDValue FalseV = Op.getOperand(3);
  bool OnTrue;
  SDValue Glue =
      emitComparison(Op.getOperand(0), Op.getOperand(1), CC, DL, DAG, OnTrue);
  if (!OnTrue)
    std::swap(TrueV, FalseV);
  return DAG.getNode(SHISD::SELECT, DL, Op.getValueType(), TrueV, FalseV, Glue);
}

/// "dst = T ? a : b" as a branch around a copy.
MachineBasicBlock *
SHTargetLowering::EmitInstrWithCustomInserter(MachineInstr &MI,
                                              MachineBasicBlock *BB) const {
  assert(MI.getOpcode() == SH::SELECT && "unexpected custom inserter");
  const TargetInstrInfo &TII = *Subtarget.getInstrInfo();
  DebugLoc DL = MI.getDebugLoc();
  const BasicBlock *LLVMBB = BB->getBasicBlock();
  MachineFunction::iterator It = ++BB->getIterator();
  MachineFunction *MF = BB->getParent();

  //   BB:      bt Sink
  //   Copy:    (falls through)
  //   Sink:    dst = phi [a, BB], [b, Copy]
  MachineBasicBlock *Copy = MF->CreateMachineBasicBlock(LLVMBB);
  MachineBasicBlock *Sink = MF->CreateMachineBasicBlock(LLVMBB);
  MF->insert(It, Copy);
  MF->insert(It, Sink);
  Sink->splice(Sink->begin(), BB, std::next(MachineBasicBlock::iterator(MI)),
               BB->end());
  Sink->transferSuccessorsAndUpdatePHIs(BB);
  BB->addSuccessor(Copy);
  BB->addSuccessor(Sink);
  Copy->addSuccessor(Sink);

  BuildMI(BB, DL, TII.get(SH::BT)).addMBB(Sink);
  BuildMI(*Sink, Sink->begin(), DL, TII.get(SH::PHI), MI.getOperand(0).getReg())
      .addReg(MI.getOperand(1).getReg())
      .addMBB(BB)
      .addReg(MI.getOperand(2).getReg())
      .addMBB(Copy);
  MI.eraseFromParent();
  return Sink;
}

//===----------------------------------------------------------------------===//
// Addresses, division, variable arguments
//===----------------------------------------------------------------------===//

SDValue SHTargetLowering::LowerAddress(SDValue Op, SelectionDAG &DAG) const {
  SDLoc DL(Op);
  EVT VT = Op.getValueType();
  if (isPositionIndependent())
    reportFatalUsageError(
        "position independent code is not supported for SuperH yet");
  SDValue Target;
  if (const auto *GA = dyn_cast<GlobalAddressSDNode>(Op))
    Target =
        DAG.getTargetGlobalAddress(GA->getGlobal(), DL, VT, GA->getOffset());
  else if (const auto *ES = dyn_cast<ExternalSymbolSDNode>(Op))
    Target = DAG.getTargetExternalSymbol(ES->getSymbol(), VT);
  else if (const auto *BA = dyn_cast<BlockAddressSDNode>(Op))
    Target =
        DAG.getTargetBlockAddress(BA->getBlockAddress(), VT, BA->getOffset());
  else if (const auto *JT = dyn_cast<JumpTableSDNode>(Op))
    Target = DAG.getTargetJumpTable(JT->getIndex(), VT);
  else if (const auto *CP = dyn_cast<ConstantPoolSDNode>(Op))
    Target = DAG.getTargetConstantPool(CP->getConstVal(), VT, CP->getAlign(),
                                       CP->getOffset());
  else
    llvm_unreachable("not an address");
  return DAG.getNode(SHISD::LOADADDR, DL, VT, Target);
}

SDValue SHTargetLowering::LowerDivision(SDValue Op, SelectionDAG &DAG) const {
  SDLoc DL(Op);
  bool IsSigned = Op.getOpcode() == ISD::SDIV;
  SDValue Ops[] = {Op.getOperand(0), Op.getOperand(1)};
  MakeLibCallOptions Options;
  Options.setIsSigned(IsSigned);
  return makeLibCall(DAG, IsSigned ? RTLIB::SDIV_I32 : RTLIB::UDIV_I32,
                     MVT::i32, Ops, Options, DL)
      .first;
}

// va_list is a pointer to the next argument.
SDValue SHTargetLowering::LowerVASTART(SDValue Op, SelectionDAG &DAG) const {
  MachineFunction &MF = DAG.getMachineFunction();
  SHMachineFunctionInfo *FI = MF.getInfo<SHMachineFunctionInfo>();
  SDLoc DL(Op);
  SDValue Addr = DAG.getFrameIndex(FI->getVarArgsFrameIndex(),
                                   getPointerTy(DAG.getDataLayout()));
  const Value *SV = cast<SrcValueSDNode>(Op.getOperand(2))->getValue();
  return DAG.getStore(Op.getOperand(0), DL, Addr, Op.getOperand(1),
                      MachinePointerInfo(SV));
}

// __builtin_frame_address(0) is r14, which has the value that the stack
// pointer has behind the prologue.  The frames are not chained, so there is
// no answer for the functions further out.
SDValue SHTargetLowering::LowerFRAMEADDR(SDValue Op, SelectionDAG &DAG) const {
  MachineFunction &MF = DAG.getMachineFunction();
  MF.getFrameInfo().setFrameAddressIsTaken(true);
  SDLoc DL(Op);
  if (Op.getConstantOperandVal(0) != 0)
    return DAG.getConstant(0, DL, MVT::i32);
  return DAG.getCopyFromReg(DAG.getEntryNode(), DL, SH::R14, MVT::i32);
}

// __builtin_return_address(0) is what pr holds when the function is entered.
SDValue SHTargetLowering::LowerRETURNADDR(SDValue Op, SelectionDAG &DAG) const {
  MachineFunction &MF = DAG.getMachineFunction();
  MF.getFrameInfo().setReturnAddressIsTaken(true);
  SDLoc DL(Op);
  if (Op.getConstantOperandVal(0) != 0)
    return DAG.getConstant(0, DL, MVT::i32);
  Register Reg = MF.addLiveIn(SH::PR, &SH::GPRRegClass);
  return DAG.getCopyFromReg(DAG.getEntryNode(), DL, Reg, MVT::i32);
}

//===----------------------------------------------------------------------===//
// Calls
//===----------------------------------------------------------------------===//

static const MCPhysReg ArgRegs[] = {SH::R4, SH::R5, SH::R6, SH::R7};

// Without a floating point unit the arguments are one row of words, and a
// structure starts in the registers that are left and goes on on the stack.
// With one it is in registers only if all of it fits, and a structure that
// comes here is larger than the four registers.
void SHTargetLowering::HandleByVal(CCState *State, unsigned &Size,
                                   Align Alignment) const {
  if (Subtarget.hasFPU())
    return;
  unsigned First = State->getFirstUnallocated(ArgRegs);
  unsigned Count =
      std::min<unsigned>(std::size(ArgRegs) - First, (Size + 3) / 4);
  if (!Count)
    return;
  for (unsigned I = 0; I != Count; ++I)
    State->AllocateReg(ArgRegs[First + I]);
  State->addInRegsParamInfo(First, First + Count);
  Size -= std::min(Size, Count * 4);
}

static SDValue extendValue(SDValue Value, const CCValAssign &VA,
                           const SDLoc &DL, SelectionDAG &DAG) {
  switch (VA.getLocInfo()) {
  case CCValAssign::Full:
    return Value;
  case CCValAssign::SExt:
    return DAG.getNode(ISD::SIGN_EXTEND, DL, VA.getLocVT(), Value);
  case CCValAssign::ZExt:
    return DAG.getNode(ISD::ZERO_EXTEND, DL, VA.getLocVT(), Value);
  case CCValAssign::AExt:
    return DAG.getNode(ISD::ANY_EXTEND, DL, VA.getLocVT(), Value);
  default:
    llvm_unreachable("unexpected kind of argument");
  }
}

static SDValue truncateValue(SDValue Value, const CCValAssign &VA,
                             const SDLoc &DL, SelectionDAG &DAG) {
  switch (VA.getLocInfo()) {
  case CCValAssign::Full:
    return Value;
  case CCValAssign::SExt:
    Value = DAG.getNode(ISD::AssertSext, DL, VA.getLocVT(), Value,
                        DAG.getValueType(VA.getValVT()));
    break;
  case CCValAssign::ZExt:
    Value = DAG.getNode(ISD::AssertZext, DL, VA.getLocVT(), Value,
                        DAG.getValueType(VA.getValVT()));
    break;
  case CCValAssign::AExt:
    break;
  default:
    llvm_unreachable("unexpected kind of argument");
  }
  return DAG.getNode(ISD::TRUNCATE, DL, VA.getValVT(), Value);
}

SDValue SHTargetLowering::LowerFormalArguments(
    SDValue Chain, CallingConv::ID CallConv, bool IsVarArg,
    const SmallVectorImpl<ISD::InputArg> &Ins, const SDLoc &DL,
    SelectionDAG &DAG, SmallVectorImpl<SDValue> &InVals) const {
  MachineFunction &MF = DAG.getMachineFunction();
  MachineFrameInfo &MFI = MF.getFrameInfo();
  SHMachineFunctionInfo *FI = MF.getInfo<SHMachineFunctionInfo>();
  EVT PtrVT = getPointerTy(DAG.getDataLayout());

  SmallVector<CCValAssign, 16> ArgLocs;
  CCState CCInfo(CallConv, IsVarArg, MF, ArgLocs, *DAG.getContext());
  CCInfo.AnalyzeFormalArguments(Ins, CC_SH);

  unsigned SaveSize = 0;
  SmallVector<SDValue, 4> Stores;
  for (unsigned I = 0, E = ArgLocs.size(); I != E; ++I) {
    const CCValAssign &VA = ArgLocs[I];
    if (VA.isRegLoc()) {
      Register VReg = MF.addLiveIn(VA.getLocReg(), &SH::GPRRegClass);
      SDValue Value = DAG.getCopyFromReg(Chain, DL, VReg, VA.getLocVT());
      // The address for a result in memory is returned as well.
      if (Ins[I].Flags.isSRet()) {
        Register Copy = MF.getRegInfo().createVirtualRegister(&SH::GPRRegClass);
        FI->setSRetReturnReg(Copy);
        Chain = DAG.getCopyToReg(Chain, DL, Copy, Value);
      }
      InVals.push_back(truncateValue(Value, VA, DL, DAG));
      continue;
    }
    assert(VA.isMemLoc() && "an argument is in a register or in memory");
    // A structure that is passed by value lies in the argument area, and
    // its address is the argument.  The words of it that came in registers
    // are stored right below the ones on the stack.
    if (Ins[I].Flags.isByVal()) {
      unsigned Begin = 0, End = 0;
      if (CCInfo.getInRegsParamsProcessed() < CCInfo.getInRegsParamsCount()) {
        CCInfo.getInRegsParamInfo(CCInfo.getInRegsParamsProcessed(), Begin,
                                  End);
        CCInfo.nextInRegsParam();
      }
      unsigned RegBytes = (End - Begin) * 4;
      unsigned Size = std::max<unsigned>(Ins[I].Flags.getByValSize(), 1);
      int Index;
      if (RegBytes >= Size) {
        // All of it came in registers: any place will do.
        Index = MFI.CreateStackObject(RegBytes, Align(4), false);
      } else {
        assert((!RegBytes || VA.getLocMemOffset() == 0) &&
               "a structure in registers is the first thing on the stack");
        Index = MFI.CreateFixedObject(
            Size, int(VA.getLocMemOffset()) - int(RegBytes), false);
        if (RegBytes)
          SaveSize = RegBytes;
      }
      SDValue Addr = DAG.getFrameIndex(Index, PtrVT);
      for (unsigned R = Begin; R != End; ++R) {
        Register VReg = MF.addLiveIn(ArgRegs[R], &SH::GPRRegClass);
        SDValue Value = DAG.getCopyFromReg(Chain, DL, VReg, MVT::i32);
        Stores.push_back(DAG.getStore(
            Value.getValue(1), DL, Value,
            DAG.getObjectPtrOffset(DL, Addr,
                                   TypeSize::getFixed((R - Begin) * 4)),
            MachinePointerInfo::getFixedStack(MF, Index, (R - Begin) * 4)));
      }
      InVals.push_back(Addr);
      continue;
    }
    int Index = MFI.CreateFixedObject(4, VA.getLocMemOffset(), true);
    SDValue Value =
        DAG.getLoad(VA.getLocVT(), DL, Chain, DAG.getFrameIndex(Index, PtrVT),
                    MachinePointerInfo::getFixedStack(MF, Index));
    InVals.push_back(truncateValue(Value, VA, DL, DAG));
  }

  if (IsVarArg) {
    // The argument registers that hold no named parameter are stored right
    // below the arguments that came on the stack, in the order of their
    // numbers, so that va_arg walks one row of words.
    unsigned First = CCInfo.getFirstUnallocated(ArgRegs);
    assert((!SaveSize || First == std::size(ArgRegs)) &&
           "registers left behind a structure that is partly on the stack");
    if (First != std::size(ArgRegs))
      SaveSize = (std::size(ArgRegs) - First) * 4;
    for (unsigned I = First; I != std::size(ArgRegs); ++I) {
      int Offset = -int(std::size(ArgRegs) - I) * 4;
      int Index = MFI.CreateFixedObject(4, Offset, true);
      Register VReg = MF.addLiveIn(ArgRegs[I], &SH::GPRRegClass);
      SDValue Value = DAG.getCopyFromReg(Chain, DL, VReg, MVT::i32);
      Stores.push_back(DAG.getStore(
          Value.getValue(1), DL, Value, DAG.getFrameIndex(Index, PtrVT),
          MachinePointerInfo::getFixedStack(MF, Index)));
    }
    int FirstOffset = First != std::size(ArgRegs) ? -int(SaveSize)
                                                  : int(CCInfo.getStackSize());
    FI->setVarArgsFrameIndex(MFI.CreateFixedObject(4, FirstOffset, true));
  }
  FI->setArgRegSaveSize(SaveSize);
  if (!Stores.empty()) {
    Stores.push_back(Chain);
    Chain = DAG.getNode(ISD::TokenFactor, DL, MVT::Other, Stores);
  }
  return Chain;
}

SDValue SHTargetLowering::LowerCall(TargetLowering::CallLoweringInfo &CLI,
                                    SmallVectorImpl<SDValue> &InVals) const {
  SelectionDAG &DAG = CLI.DAG;
  SDLoc &DL = CLI.DL;
  SmallVectorImpl<ISD::OutputArg> &Outs = CLI.Outs;
  SmallVectorImpl<SDValue> &OutVals = CLI.OutVals;
  SmallVectorImpl<ISD::InputArg> &Ins = CLI.Ins;
  SDValue Chain = CLI.Chain;
  SDValue Callee = CLI.Callee;
  MachineFunction &MF = DAG.getMachineFunction();
  EVT PtrVT = getPointerTy(DAG.getDataLayout());

  // No tail calls yet.
  CLI.IsTailCall = false;

  SmallVector<CCValAssign, 16> ArgLocs;
  CCState CCInfo(CLI.CallConv, CLI.IsVarArg, MF, ArgLocs, *DAG.getContext());
  CCInfo.AnalyzeCallOperands(Outs, CC_SH);
  unsigned NumBytes = CCInfo.getStackSize();

  Chain = DAG.getCALLSEQ_START(Chain, NumBytes, 0, DL);

  SmallVector<std::pair<unsigned, SDValue>, 4> RegsToPass;
  SmallVector<SDValue, 8> MemOps;
  SDValue StackPtr;
  for (unsigned I = 0, E = ArgLocs.size(); I != E; ++I) {
    const CCValAssign &VA = ArgLocs[I];
    SDValue Arg = OutVals[I];
    ISD::ArgFlagsTy Flags = Outs[I].Flags;

    if (VA.isRegLoc()) {
      RegsToPass.push_back({VA.getLocReg(), extendValue(Arg, VA, DL, DAG)});
      continue;
    }
    assert(VA.isMemLoc() && "an argument is in a register or in memory");
    if (!StackPtr.getNode())
      StackPtr = DAG.getCopyFromReg(Chain, DL, SH::R15, PtrVT);
    SDValue Addr = DAG.getNode(ISD::ADD, DL, PtrVT, StackPtr,
                               DAG.getIntPtrConstant(VA.getLocMemOffset(), DL));
    if (Flags.isByVal()) {
      // The first words go to the registers that HandleByVal() took, the
      // rest is copied to the stack.
      unsigned Begin = 0, End = 0;
      if (CCInfo.getInRegsParamsProcessed() < CCInfo.getInRegsParamsCount()) {
        CCInfo.getInRegsParamInfo(CCInfo.getInRegsParamsProcessed(), Begin,
                                  End);
        CCInfo.nextInRegsParam();
      }
      unsigned RegBytes = (End - Begin) * 4;
      for (unsigned R = Begin; R != End; ++R) {
        SDValue Word =
            DAG.getLoad(MVT::i32, DL, Chain,
                        DAG.getObjectPtrOffset(
                            DL, Arg, TypeSize::getFixed((R - Begin) * 4)),
                        MachinePointerInfo());
        MemOps.push_back(Word.getValue(1));
        RegsToPass.push_back({ArgRegs[R], Word});
      }
      if (Flags.getByValSize() <= RegBytes)
        continue;
      SDValue Size =
          DAG.getConstant(Flags.getByValSize() - RegBytes, DL, MVT::i32);
      Align Alignment = std::min(Flags.getNonZeroByValAlign(), Align(4));
      MemOps.push_back(DAG.getMemcpy(
          Chain, DL, Addr,
          DAG.getObjectPtrOffset(DL, Arg, TypeSize::getFixed(RegBytes)), Size,
          Alignment, Alignment, /*isVol=*/false, /*AlwaysInline=*/false,
          /*CI=*/nullptr, std::nullopt, MachinePointerInfo(),
          MachinePointerInfo()));
      continue;
    }
    MemOps.push_back(
        DAG.getStore(Chain, DL, extendValue(Arg, VA, DL, DAG), Addr,
                     MachinePointerInfo::getStack(MF, VA.getLocMemOffset())));
  }
  if (!MemOps.empty())
    Chain = DAG.getNode(ISD::TokenFactor, DL, MVT::Other, MemOps);

  SDValue Glue;
  for (auto &[Reg, Value] : RegsToPass) {
    Chain = DAG.getCopyToReg(Chain, DL, Reg, Value, Glue);
    Glue = Chain.getValue(1);
  }

  // The address of the function comes from a literal: bsr reaches only
  // four kilobytes.
  if (const auto *GA = dyn_cast<GlobalAddressSDNode>(Callee))
    Callee = DAG.getNode(SHISD::LOADADDR, DL, PtrVT,
                         DAG.getTargetGlobalAddress(GA->getGlobal(), DL, PtrVT,
                                                    GA->getOffset()));
  else if (const auto *ES = dyn_cast<ExternalSymbolSDNode>(Callee))
    Callee = DAG.getNode(SHISD::LOADADDR, DL, PtrVT,
                         DAG.getTargetExternalSymbol(ES->getSymbol(), PtrVT));

  SmallVector<SDValue, 8> Ops;
  Ops.push_back(Chain);
  Ops.push_back(Callee);
  for (auto &[Reg, Value] : RegsToPass)
    Ops.push_back(DAG.getRegister(Reg, Value.getValueType()));
  const TargetRegisterInfo *TRI = Subtarget.getRegisterInfo();
  const uint32_t *Mask = TRI->getCallPreservedMask(MF, CLI.CallConv);
  assert(Mask && "no mask of the registers that a call preserves");
  Ops.push_back(DAG.getRegisterMask(Mask));
  if (Glue.getNode())
    Ops.push_back(Glue);

  SDVTList NodeTys = DAG.getVTList(MVT::Other, MVT::Glue);
  Chain = DAG.getNode(SHISD::CALL, DL, NodeTys, Ops);
  Glue = Chain.getValue(1);

  Chain = DAG.getCALLSEQ_END(Chain, NumBytes, 0, Glue, DL);
  Glue = Chain.getValue(1);

  // The result.
  SmallVector<CCValAssign, 2> RetLocs;
  CCState RetInfo(CLI.CallConv, CLI.IsVarArg, MF, RetLocs, *DAG.getContext());
  RetInfo.AnalyzeCallResult(Ins, RetCC_SH);
  for (const CCValAssign &VA : RetLocs) {
    SDValue Value =
        DAG.getCopyFromReg(Chain, DL, VA.getLocReg(), VA.getLocVT(), Glue);
    Chain = Value.getValue(1);
    Glue = Value.getValue(2);
    InVals.push_back(truncateValue(Value, VA, DL, DAG));
  }
  return Chain;
}

bool SHTargetLowering::CanLowerReturn(
    CallingConv::ID CallConv, MachineFunction &MF, bool IsVarArg,
    const SmallVectorImpl<ISD::OutputArg> &Outs, LLVMContext &Context,
    const Type *RetTy) const {
  SmallVector<CCValAssign, 2> RetLocs;
  CCState CCInfo(CallConv, IsVarArg, MF, RetLocs, Context);
  return CCInfo.CheckReturn(Outs, RetCC_SH);
}

SDValue
SHTargetLowering::LowerReturn(SDValue Chain, CallingConv::ID CallConv,
                              bool IsVarArg,
                              const SmallVectorImpl<ISD::OutputArg> &Outs,
                              const SmallVectorImpl<SDValue> &OutVals,
                              const SDLoc &DL, SelectionDAG &DAG) const {
  MachineFunction &MF = DAG.getMachineFunction();
  SmallVector<CCValAssign, 2> RetLocs;
  CCState CCInfo(CallConv, IsVarArg, MF, RetLocs, *DAG.getContext());
  CCInfo.AnalyzeReturn(Outs, RetCC_SH);

  SDValue Glue;
  SmallVector<SDValue, 4> RetOps(1, Chain);
  for (unsigned I = 0, E = RetLocs.size(); I != E; ++I) {
    const CCValAssign &VA = RetLocs[I];
    assert(VA.isRegLoc() && "a result is in a register");
    Chain = DAG.getCopyToReg(Chain, DL, VA.getLocReg(),
                             extendValue(OutVals[I], VA, DL, DAG), Glue);
    Glue = Chain.getValue(1);
    RetOps.push_back(DAG.getRegister(VA.getLocReg(), VA.getLocVT()));
  }
  // A function that returns its result in memory returns the address of
  // it in r0.
  if (Register SRet = MF.getInfo<SHMachineFunctionInfo>()->getSRetReturnReg()) {
    SDValue Value = DAG.getCopyFromReg(Chain, DL, SRet, MVT::i32);
    Chain = DAG.getCopyToReg(Value.getValue(1), DL, SH::R0, Value, Glue);
    Glue = Chain.getValue(1);
    RetOps.push_back(DAG.getRegister(SH::R0, MVT::i32));
  }
  RetOps[0] = Chain;
  if (Glue.getNode())
    RetOps.push_back(Glue);
  return DAG.getNode(SHISD::RET, DL, MVT::Other, RetOps);
}

//===----------------------------------------------------------------------===//
// Inline assembly
//===----------------------------------------------------------------------===//

TargetLowering::ConstraintType
SHTargetLowering::getConstraintType(StringRef Constraint) const {
  if (Constraint.size() == 1) {
    switch (Constraint[0]) {
    case 'r':
    case 'z':
      return C_RegisterClass;
    default:
      break;
    }
  }
  return TargetLowering::getConstraintType(Constraint);
}

std::pair<unsigned, const TargetRegisterClass *>
SHTargetLowering::getRegForInlineAsmConstraint(const TargetRegisterInfo *TRI,
                                               StringRef Constraint,
                                               MVT VT) const {
  if (Constraint.size() == 1) {
    switch (Constraint[0]) {
    case 'r':
      return {0U, &SH::GPRRegClass};
    // r0, which a number of instructions ask for.
    case 'z':
      return {0U, &SH::R0RegRegClass};
    default:
      break;
    }
  }
  return TargetLowering::getRegForInlineAsmConstraint(TRI, Constraint, VT);
}
