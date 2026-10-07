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

static bool CC_SH_FPU_Custom(unsigned &ValNo, MVT &ValVT, MVT &LocVT,
                             CCValAssign::LocInfo &LocInfo,
                             ISD::ArgFlagsTy &ArgFlags, CCState &State);

#define GET_CALLING_CONV_IMPL
#include "SHGenCallingConv.inc"

SHTargetLowering::SHTargetLowering(const TargetMachine &TM,
                                   const SHSubtarget &STI)
    : TargetLowering(TM, STI), Subtarget(STI) {
  addRegisterClass(MVT::i32, &SH::GPRRegClass);
  if (STI.hasFPU())
    addRegisterClass(MVT::f32, &SH::FPRRegClass);
  if (STI.hasFPUDouble())
    addRegisterClass(MVT::f64, &SH::DFPRRegClass);
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

  // The floating point unit compares for "equal" and "greater".  Both are
  // false if an operand is not a number, so they and their opposites are
  // six of the conditions, and the legalizer makes the others from them.
  for (MVT VT : {MVT::f32, MVT::f64}) {
    if (!isTypeLegal(VT))
      continue;
    setOperationAction(ISD::BR_CC, VT, Custom);
    setOperationAction(ISD::SETCC, VT, Custom);
    setOperationAction(ISD::SELECT_CC, VT, Custom);
    setOperationAction(ISD::SELECT, VT, Expand);
    for (ISD::CondCode CC : {ISD::SETOGE, ISD::SETOLE, ISD::SETONE, ISD::SETUEQ,
                             ISD::SETUGT, ISD::SETULT, ISD::SETO, ISD::SETUO})
      setCondCodeAction(CC, VT, Expand);
    setOperationAction(
        {ISD::FREM,   ISD::FMA,       ISD::FCOPYSIGN, ISD::FSIN,
         ISD::FCOS,   ISD::FSINCOS,   ISD::FPOW,      ISD::FPOWI,
         ISD::FEXP,   ISD::FEXP2,     ISD::FLOG,      ISD::FLOG2,
         ISD::FLOG10, ISD::FMINNUM,   ISD::FMAXNUM,   ISD::FCEIL,
         ISD::FFLOOR, ISD::FTRUNC,    ISD::FRINT,     ISD::FNEARBYINT,
         ISD::FROUND, ISD::FROUNDEVEN},
        VT, Expand);
  }
  // ftrc and float are for signed integers.
  setOperationAction(ISD::UINT_TO_FP, MVT::i32, Expand);
  setOperationAction(ISD::FP_TO_UINT, MVT::i32, Expand);
  if (isTypeLegal(MVT::f64)) {
    setLoadExtAction(ISD::EXTLOAD, MVT::f64, MVT::f32, Expand);
    setTruncStoreAction(MVT::f64, MVT::f32, Expand);
  }

  // The SH-2 shifts by one, two, eight and sixteen bits.  A shift by another
  // number is a row of those, and one by a variable amount is a function
  // of libgcc.
  if (!STI.hasDynShift())
    setOperationAction({ISD::SHL, ISD::SRL, ISD::SRA}, MVT::i32, Custom);

  // va_list is a structure with a floating point unit, and the expansion
  // copies a pointer.
  if (STI.hasFPU())
    setOperationAction(ISD::VACOPY, MVT::Other, Custom);

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
  case ISD::VACOPY:
    return LowerVACOPY(Op, DAG);
  case ISD::SHL:
  case ISD::SRL:
  case ISD::SRA:
    return LowerShift(Op, DAG);
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
  // Floating point numbers: fcmp/eq and fcmp/gt, which are false for what
  // is not a number.  So "less or equal, or unordered" is "not greater".
  if (LHS.getValueType().isFloatingPoint()) {
    OnTrue = true;
    switch (CC) {
    default:
      llvm_unreachable("a floating point condition that was to be expanded");
    case ISD::SETUNE:
    case ISD::SETNE:
      OnTrue = false;
      [[fallthrough]];
    case ISD::SETOEQ:
    case ISD::SETEQ:
      return DAG.getNode(SHISD::FCMPEQ, DL, MVT::Glue, LHS, RHS);
    case ISD::SETULE:
    case ISD::SETLE:
      OnTrue = false;
      [[fallthrough]];
    case ISD::SETOGT:
    case ISD::SETGT:
      return DAG.getNode(SHISD::FCMPGT, DL, MVT::Glue, LHS, RHS);
    case ISD::SETUGE:
    case ISD::SETGE:
      OnTrue = false;
      [[fallthrough]];
    case ISD::SETOLT:
    case ISD::SETLT:
      return DAG.getNode(SHISD::FCMPGT, DL, MVT::Glue, RHS, LHS);
    }
  }

  // There are instructions for "greater" and "greater or equal".  "Less"
  // is one of them with the operands the other way round, unless the
  // comparison is with zero, which has instructions of its own.
  if (!isNullConstant(RHS)) {
    switch (CC) {
    case ISD::SETLT:
    case ISD::SETLE:
    case ISD::SETULT:
    case ISD::SETULE:
      std::swap(LHS, RHS);
      CC = ISD::getSetCCSwappedOperands(CC);
      break;
    default:
      break;
    }
  }

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

MachineBasicBlock *
SHTargetLowering::EmitInstrWithCustomInserter(MachineInstr &MI,
                                              MachineBasicBlock *BB) const {
  switch (MI.getOpcode()) {
  case SH::SELECT:
  case SH::SELECTF:
  case SH::SELECTD:
    return emitSelect(MI, BB);
  case SH::BLOCKCOPY:
    return emitBlockCopy(MI, BB);
  default:
    llvm_unreachable("unexpected custom inserter");
  }
}

/// A copy of a block of memory as a loop:
///
///   BB:    count = number of units
///   Loop:  unit = *from; *to = unit; from += size; to += size;
///          if (--count != 0) goto Loop
///   Sink:  the bytes that are left over, one by one
MachineBasicBlock *
SHTargetLowering::emitBlockCopy(MachineInstr &MI, MachineBasicBlock *BB) const {
  const SHInstrInfo &TII = *Subtarget.getInstrInfo();
  DebugLoc DL = MI.getDebugLoc();
  MachineFunction *MF = BB->getParent();
  MachineRegisterInfo &MRI = MF->getRegInfo();
  const TargetRegisterClass *RC = &SH::GPRRegClass;

  Register Dst = MI.getOperand(0).getReg();
  Register Src = MI.getOperand(1).getReg();
  unsigned Size = MI.getOperand(2).getImm();
  // A word is moved only between addresses that four divides.
  unsigned Unit = MI.getOperand(3).getImm() >= 4 ? 4 : 1;
  unsigned Count = Size / Unit;
  unsigned Load = Unit == 4 ? SH::MOVLld : SH::MOVBld;
  unsigned Store = Unit == 4 ? SH::MOVLst : SH::MOVBst;

  MachineBasicBlock *Sink = BB;
  MachineBasicBlock::iterator At = MI.getIterator();
  Register DstEnd = Dst, SrcEnd = Src;
  if (Count) {
    const BasicBlock *LLVMBB = BB->getBasicBlock();
    MachineFunction::iterator It = ++BB->getIterator();
    MachineBasicBlock *Loop = MF->CreateMachineBasicBlock(LLVMBB);
    Sink = MF->CreateMachineBasicBlock(LLVMBB);
    MF->insert(It, Loop);
    MF->insert(It, Sink);
    Sink->splice(Sink->begin(), BB, std::next(MachineBasicBlock::iterator(MI)),
                 BB->end());
    Sink->transferSuccessorsAndUpdatePHIs(BB);
    BB->addSuccessor(Loop);
    Loop->addSuccessor(Loop);
    Loop->addSuccessor(Sink);
    // The copy stands between the arguments of a call.
    unsigned CallFrameSize = TII.getCallFrameSizeAt(MI);
    Loop->setCallFrameSize(CallFrameSize);
    Sink->setCallFrameSize(CallFrameSize);

    Register Count0 = MRI.createVirtualRegister(RC);
    BuildMI(*BB, MI.getIterator(), DL,
            TII.get(isInt<8>(Count) ? SH::MOVI : SH::MOVLpcrel), Count0)
        .addImm(Count);

    Register DstPhi = MRI.createVirtualRegister(RC);
    Register SrcPhi = MRI.createVirtualRegister(RC);
    Register CountPhi = MRI.createVirtualRegister(RC);
    Register Value = MRI.createVirtualRegister(RC);
    Register Count1 = MRI.createVirtualRegister(RC);
    DstEnd = MRI.createVirtualRegister(RC);
    SrcEnd = MRI.createVirtualRegister(RC);
    auto Phi = [&](Register Reg, Register First, Register Next) {
      BuildMI(Loop, DL, TII.get(SH::PHI), Reg)
          .addReg(First)
          .addMBB(BB)
          .addReg(Next)
          .addMBB(Loop);
    };
    Phi(DstPhi, Dst, DstEnd);
    Phi(SrcPhi, Src, SrcEnd);
    Phi(CountPhi, Count0, Count1);
    BuildMI(Loop, DL, TII.get(Load), Value).addReg(SrcPhi).addImm(0);
    BuildMI(Loop, DL, TII.get(Store)).addReg(Value).addReg(DstPhi).addImm(0);
    BuildMI(Loop, DL, TII.get(SH::ADDri), SrcEnd).addReg(SrcPhi).addImm(Unit);
    BuildMI(Loop, DL, TII.get(SH::ADDri), DstEnd).addReg(DstPhi).addImm(Unit);
    BuildMI(Loop, DL, TII.get(SH::ADDri), Count1).addReg(CountPhi).addImm(-1);
    BuildMI(Loop, DL, TII.get(SH::TST)).addReg(Count1).addReg(Count1);
    BuildMI(Loop, DL, TII.get(SH::BF)).addMBB(Loop);
    At = Sink->begin();
  }

  // What does not fill a word.
  for (unsigned I = 0, E = Size - Count * Unit; I != E; ++I) {
    Register From = SrcEnd, To = DstEnd;
    if (I) {
      From = MRI.createVirtualRegister(RC);
      To = MRI.createVirtualRegister(RC);
      BuildMI(*Sink, At, DL, TII.get(SH::ADDri), From).addReg(SrcEnd).addImm(I);
      BuildMI(*Sink, At, DL, TII.get(SH::ADDri), To).addReg(DstEnd).addImm(I);
    }
    Register Value = MRI.createVirtualRegister(RC);
    BuildMI(*Sink, At, DL, TII.get(SH::MOVBld), Value).addReg(From).addImm(0);
    BuildMI(*Sink, At, DL, TII.get(SH::MOVBst))
        .addReg(Value)
        .addReg(To)
        .addImm(0);
  }
  MI.eraseFromParent();
  return Sink;
}

/// "dst = T ? a : b" as a branch around a copy.
MachineBasicBlock *SHTargetLowering::emitSelect(MachineInstr &MI,
                                                MachineBasicBlock *BB) const {
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
  // A selection can stand between the arguments of a call.
  unsigned CallFrameSize = TII.getCallFrameSizeAt(MI);
  Copy->setCallFrameSize(CallFrameSize);
  Sink->setCallFrameSize(CallFrameSize);

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

// Without a floating point unit va_list is a pointer to the next argument.
// With one it is what GCC has:
//
//   struct { void *next_o, *next_o_limit;    the integer registers
//            void *next_fp, *next_fp_limit;  the floating point registers
//            void *next_stack; }             the arguments on the stack
//
// The registers are in the buffer that LowerFormalArguments() filled, the
// floating point ones first.
SDValue SHTargetLowering::LowerVASTART(SDValue Op, SelectionDAG &DAG) const {
  MachineFunction &MF = DAG.getMachineFunction();
  SHMachineFunctionInfo *FI = MF.getInfo<SHMachineFunctionInfo>();
  SDLoc DL(Op);
  EVT PtrVT = getPointerTy(DAG.getDataLayout());
  SDValue Chain = Op.getOperand(0);
  SDValue List = Op.getOperand(1);
  const Value *SV = cast<SrcValueSDNode>(Op.getOperand(2))->getValue();
  SDValue Stack = DAG.getFrameIndex(FI->getVarArgsFrameIndex(), PtrVT);
  if (!Subtarget.hasFPU())
    return DAG.getStore(Chain, DL, Stack, List, MachinePointerInfo(SV));

  // Where nothing was saved, the two rows are empty: any address will do.
  SDValue Float = Stack;
  if (FI->getVarArgsNumFloat() || FI->getVarArgsNumInt())
    Float = DAG.getObjectPtrOffset(
        DL, DAG.getFrameIndex(FI->getVarArgsRegSaveIndex(), PtrVT),
        TypeSize::getFixed(FI->getVarArgsRegSaveOffset()));
  SDValue FloatEnd = DAG.getObjectPtrOffset(
      DL, Float, TypeSize::getFixed(FI->getVarArgsNumFloat() * 4));
  SDValue IntEnd = DAG.getObjectPtrOffset(
      DL, FloatEnd, TypeSize::getFixed(FI->getVarArgsNumInt() * 4));
  SDValue Fields[] = {FloatEnd, IntEnd, Float, FloatEnd, Stack};
  SmallVector<SDValue, 5> Stores;
  for (unsigned I = 0; I != std::size(Fields); ++I)
    Stores.push_back(DAG.getStore(
        Chain, DL, Fields[I],
        DAG.getObjectPtrOffset(DL, List, TypeSize::getFixed(I * 4)),
        MachinePointerInfo(SV, I * 4)));
  return DAG.getNode(ISD::TokenFactor, DL, MVT::Other, Stores);
}

// Without shad and shld.  A shift by a constant is selected as a row of the
// shifts that there are (SHISelDAGToDAG.cpp).  Only shar shifts to the
// right with the sign, by one bit, so from a few bits on that is a call as
// well.
SDValue SHTargetLowering::LowerShift(SDValue Op, SelectionDAG &DAG) const {
  bool IsArithmetic = Op.getOpcode() == ISD::SRA;
  if (const auto *C = dyn_cast<ConstantSDNode>(Op.getOperand(1)))
    if (!IsArithmetic || C->getZExtValue() <= 5)
      return Op;
  RTLIB::Libcall LC = Op.getOpcode() == ISD::SHL   ? RTLIB::SHL_I32
                      : Op.getOpcode() == ISD::SRL ? RTLIB::SRL_I32
                                                   : RTLIB::SRA_I32;
  SDValue Ops[] = {Op.getOperand(0), Op.getOperand(1)};
  MakeLibCallOptions Options;
  return makeLibCall(DAG, LC, MVT::i32, Ops, Options, SDLoc(Op)).first;
}

// The five pointers of the va_list that LowerVASTART() describes.
SDValue SHTargetLowering::LowerVACOPY(SDValue Op, SelectionDAG &DAG) const {
  SDLoc DL(Op);
  const Value *DstSV = cast<SrcValueSDNode>(Op.getOperand(3))->getValue();
  const Value *SrcSV = cast<SrcValueSDNode>(Op.getOperand(4))->getValue();
  return DAG.getMemcpy(Op.getOperand(0), DL, Op.getOperand(1), Op.getOperand(2),
                       DAG.getConstant(20, DL, MVT::i32), Align(4), Align(4),
                       /*isVol=*/false, /*AlwaysInline=*/true, /*CI=*/nullptr,
                       std::nullopt, MachinePointerInfo(DstSV),
                       MachinePointerInfo(SrcSV));
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

// The registers for float arguments, in the order in which they are taken.
// On a little-endian SH-4 the two registers of a pair change places.  That
// way a function with variable arguments can store the pairs as doubles,
// and va_arg finds floats in the order of the arguments.
static const MCPhysReg FloatArgRegs[] = {SH::FR4, SH::FR5, SH::FR6,  SH::FR7,
                                         SH::FR8, SH::FR9, SH::FR10, SH::FR11};
static const MCPhysReg FloatArgRegsSwapped[] = {
    SH::FR5, SH::FR4, SH::FR7, SH::FR6, SH::FR9, SH::FR8, SH::FR11, SH::FR10};
static const MCPhysReg DoubleArgRegs[] = {SH::DR4, SH::DR6, SH::DR8, SH::DR10};

static bool swapsFloatPairs(const SHSubtarget &STI) {
  return STI.isSH4FPU() && STI.isLittleEndian();
}

static ArrayRef<MCPhysReg> floatArgRegs(const SHSubtarget &STI) {
  if (swapsFloatPairs(STI))
    return FloatArgRegsSwapped;
  return FloatArgRegs;
}

// The convention with a floating point unit.  An argument comes here part by
// part: the halves of a 64-bit integer, the words of a structure, the parts
// of a complex number.  It is placed when its last part is here, in
// registers if all of it fits and on the stack otherwise.
static bool CC_SH_FPU_Custom(unsigned &ValNo, MVT &ValVT, MVT &LocVT,
                             CCValAssign::LocInfo &LocInfo,
                             ISD::ArgFlagsTy &ArgFlags, CCState &State) {
  const SHSubtarget &STI =
      State.getMachineFunction().getSubtarget<SHSubtarget>();
  SmallVectorImpl<CCValAssign> &Pending = State.getPendingLocs();
  Pending.push_back(CCValAssign::getPending(ValNo, ValVT, LocVT, LocInfo));
  if (ArgFlags.isInConsecutiveRegs() && !ArgFlags.isInConsecutiveRegsLast())
    return true;

  ArrayRef<MCPhysReg> FloatRegs = floatArgRegs(STI);
  unsigned Parts = Pending.size();
  SmallVector<MCPhysReg, 4> Regs;
  auto Exhaust = [&](ArrayRef<MCPhysReg> List) {
    // Where an argument that does not fit takes the registers with it.
    if (!STI.leavesRegistersFree())
      for (MCPhysReg Reg : List)
        State.AllocateReg(Reg);
  };

  if (LocVT == MVT::f32) {
    unsigned Count = State.getFirstUnallocated(FloatRegs);
    if (Count + Parts <= FloatRegs.size()) {
      for (unsigned I = 0; I != Parts; ++I)
        Regs.push_back(FloatRegs[Count + I]);
      // A complex number that starts at an even place has its real part
      // in the register with the lower number, not in the one that a float
      // would get there.
      if (Parts == 2 && swapsFloatPairs(STI) && Count % 2 == 0)
        std::swap(Regs[0], Regs[1]);
    } else {
      Exhaust(FloatRegs);
    }
  } else if (LocVT == MVT::f64) {
    // A double starts at an even place.  The odd one in front of it stays
    // empty.
    unsigned Count = State.getFirstUnallocated(FloatRegs);
    unsigned Even = alignTo(Count, 2);
    if (Even + 2 * Parts <= FloatRegs.size()) {
      if (Even != Count)
        State.AllocateReg(FloatRegs[Count]);
      for (unsigned I = 0; I != Parts; ++I)
        Regs.push_back(DoubleArgRegs[Even / 2 + I]);
    } else {
      Exhaust(FloatRegs);
    }
  } else {
    unsigned Count = State.getFirstUnallocated(ArgRegs);
    if (Count + Parts <= std::size(ArgRegs))
      for (unsigned I = 0; I != Parts; ++I)
        Regs.push_back(ArgRegs[Count + I]);
    else
      Exhaust(ArgRegs);
  }

  for (unsigned I = 0; I != Parts; ++I) {
    const CCValAssign &VA = Pending[I];
    if (!Regs.empty()) {
      State.AllocateReg(Regs[I]);
      State.addLoc(CCValAssign::getReg(VA.getValNo(), VA.getValVT(), Regs[I],
                                       VA.getLocVT(), VA.getLocInfo()));
      continue;
    }
    int64_t Offset =
        State.AllocateStack(VA.getLocVT().getStoreSize(), Align(4));
    State.addLoc(CCValAssign::getMem(VA.getValNo(), VA.getValVT(), Offset,
                                     VA.getLocVT(), VA.getLocInfo()));
  }
  Pending.clear();
  return true;
}

CCAssignFn *SHTargetLowering::getArgConvention() const {
  return Subtarget.hasFPU() ? CC_SH_FPU : CC_SH;
}

bool SHTargetLowering::functionArgumentNeedsConsecutiveRegisters(
    Type *Ty, CallingConv::ID CallConv, bool IsVarArg,
    const DataLayout &DL) const {
  return Subtarget.hasFPU();
}

static const TargetRegisterClass *getArgRegClass(MVT VT) {
  switch (VT.SimpleTy) {
  case MVT::f32:
    return &SH::FPRRegClass;
  case MVT::f64:
    return &SH::DFPRRegClass;
  default:
    return &SH::GPRRegClass;
  }
}

// Without a floating point unit the arguments are one row of words, and a
// structure starts in the registers that are left and goes on on the stack.
// With one it is in registers only if all of it fits, and a structure that
// comes here is larger than the four registers.
void SHTargetLowering::HandleByVal(CCState *State, unsigned &Size,
                                   Align Alignment) const {
  if (Subtarget.hasFPU()) {
    if (!Subtarget.leavesRegistersFree())
      for (MCPhysReg Reg : ArgRegs)
        State->AllocateReg(Reg);
    return;
  }
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
  CCInfo.AnalyzeFormalArguments(Ins, getArgConvention());

  unsigned SaveSize = 0;
  SmallVector<SDValue, 4> Stores;
  for (unsigned I = 0, E = ArgLocs.size(); I != E; ++I) {
    const CCValAssign &VA = ArgLocs[I];
    if (VA.isRegLoc()) {
      Register VReg =
          MF.addLiveIn(VA.getLocReg(), getArgRegClass(VA.getLocVT()));
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
    int Index = MFI.CreateFixedObject(VA.getLocVT().getStoreSize(),
                                      VA.getLocMemOffset(), true);
    SDValue Value =
        DAG.getLoad(VA.getLocVT(), DL, Chain, DAG.getFrameIndex(Index, PtrVT),
                    MachinePointerInfo::getFixedStack(MF, Index));
    InVals.push_back(truncateValue(Value, VA, DL, DAG));
  }

  if (IsVarArg && Subtarget.hasFPU()) {
    // The registers that hold no named parameter go to a buffer among the
    // local variables: the floating point ones in the order in which
    // arguments take them, then the integer ones.  va_arg takes a double
    // from an address that eight divides, so the buffer starts four bytes
    // behind such an address if the number of float registers is odd.
    ArrayRef<MCPhysReg> FloatRegs = floatArgRegs(Subtarget);
    unsigned FirstFloat = CCInfo.getFirstUnallocated(FloatRegs);
    unsigned FirstInt = CCInfo.getFirstUnallocated(ArgRegs);
    unsigned NumFloat = FloatRegs.size() - FirstFloat;
    unsigned NumInt = std::size(ArgRegs) - FirstInt;
    if (NumFloat || NumInt) {
      bool Doubles = Subtarget.hasFPUDouble() && NumFloat;
      unsigned Skip = Doubles && NumFloat % 2 ? 4 : 0;
      int Index = MFI.CreateStackObject((NumFloat + NumInt) * 4 + Skip,
                                        Doubles ? Align(8) : Align(4), false);
      SDValue Base = DAG.getFrameIndex(Index, PtrVT);
      auto Save = [&](MCPhysReg Reg, MVT VT, unsigned Offset) {
        Register VReg = MF.addLiveIn(Reg, getArgRegClass(VT));
        SDValue Value = DAG.getCopyFromReg(Chain, DL, VReg, VT);
        Stores.push_back(DAG.getStore(
            Value.getValue(1), DL, Value,
            DAG.getObjectPtrOffset(DL, Base, TypeSize::getFixed(Offset)),
            MachinePointerInfo::getFixedStack(MF, Index, Offset)));
      };
      for (unsigned I = 0; I != NumFloat; ++I)
        Save(FloatRegs[FirstFloat + I], MVT::f32, Skip + I * 4);
      for (unsigned I = 0; I != NumInt; ++I)
        Save(ArgRegs[FirstInt + I], MVT::i32, Skip + (NumFloat + I) * 4);
      FI->setVarArgsRegSave(Index, Skip, NumFloat, NumInt);
    }
    FI->setVarArgsFrameIndex(
        MFI.CreateFixedObject(4, CCInfo.getStackSize(), true));
  } else if (IsVarArg) {
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
  CCInfo.AnalyzeCallOperands(Outs, getArgConvention());
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
      // The structure may be aligned to less than a word.
      Align Alignment = std::min(Flags.getNonZeroByValAlign(), Align(4));
      for (unsigned R = Begin; R != End; ++R) {
        SDValue Word =
            DAG.getLoad(MVT::i32, DL, Chain,
                        DAG.getObjectPtrOffset(
                            DL, Arg, TypeSize::getFixed((R - Begin) * 4)),
                        MachinePointerInfo(), Alignment);
        MemOps.push_back(Word.getValue(1));
        RegsToPass.push_back({ArgRegs[R], Word});
      }
      if (Flags.getByValSize() <= RegBytes)
        continue;
      // No call of memcpy here, between the arguments of another call: a
      // few loads and stores if that is enough, and a loop otherwise.
      unsigned Rest = Flags.getByValSize() - RegBytes;
      SDValue From =
          DAG.getObjectPtrOffset(DL, Arg, TypeSize::getFixed(RegBytes));
      if (Rest <= 32)
        MemOps.push_back(DAG.getMemcpy(
            Chain, DL, Addr, From, DAG.getConstant(Rest, DL, MVT::i32),
            Alignment, Alignment, /*isVol=*/false, /*AlwaysInline=*/true,
            /*CI=*/nullptr, std::nullopt, MachinePointerInfo(),
            MachinePointerInfo()));
      else
        MemOps.push_back(DAG.getNode(
            SHISD::BLOCKCOPY, DL, MVT::Other, Chain, Addr, From,
            DAG.getTargetConstant(Rest, DL, MVT::i32),
            DAG.getTargetConstant(Alignment.value(), DL, MVT::i32)));
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
