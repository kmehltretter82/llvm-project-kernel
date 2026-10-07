//===-- SHISelDAGToDAG.cpp - Instruction selection for SuperH -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SH.h"
#include "SHMachineFunctionInfo.h"
#include "SHSelectionDAGInfo.h"
#include "SHSubtarget.h"
#include "SHTargetMachine.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/SelectionDAGISel.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

#define DEBUG_TYPE "sh-isel"

namespace {

class SHDAGToDAGISel : public SelectionDAGISel {
  const SHSubtarget *Subtarget = nullptr;

public:
  explicit SHDAGToDAGISel(SHTargetMachine &TM, CodeGenOptLevel OptLevel)
      : SelectionDAGISel(TM, OptLevel) {}

  bool runOnMachineFunction(MachineFunction &MF) override {
    Subtarget = &MF.getSubtarget<SHSubtarget>();
    bool Changed = SelectionDAGISel::runOnMachineFunction(MF);
    // If the function asked for the address of the global offset table, the
    // register that has it is set where the function starts.  That
    // overwrites r0, which holds nothing there.
    if (Register Base =
            MF.getInfo<SHMachineFunctionInfo>()->getGlobalBaseReg()) {
      MachineBasicBlock &Entry = MF.front();
      BuildMI(Entry, Entry.begin(), DebugLoc(),
              Subtarget->getInstrInfo()->get(SH::LOADGOT), Base)
          .addExternalSymbol("_GLOBAL_OFFSET_TABLE_");
      Changed = true;
    }
    return Changed;
  }

  void Select(SDNode *Node) override;
  bool selectConstantShift(SDNode *Node);

  bool SelectInlineAsmMemoryOperand(const SDValue &Op,
                                    InlineAsm::ConstraintCode ConstraintID,
                                    std::vector<SDValue> &OutOps) override;

  /// A stack slot, with a constant offset or without one.
  bool SelectAddrFI(SDValue Addr, SDValue &Base, SDValue &Disp);
  /// The address of a long word: a stack slot, a register with a
  /// displacement of up to 60, or a register.
  bool SelectAddrL(SDValue Addr, SDValue &Base, SDValue &Disp);
  /// The address of a byte or a word: a stack slot or a register.
  bool SelectAddrBW(SDValue Addr, SDValue &Base, SDValue &Disp);

#include "SHGenDAGISel.inc"
};

class SHDAGToDAGISelLegacy : public SelectionDAGISelLegacy {
public:
  static char ID;
  SHDAGToDAGISelLegacy(SHTargetMachine &TM, CodeGenOptLevel OptLevel)
      : SelectionDAGISelLegacy(ID,
                               std::make_unique<SHDAGToDAGISel>(TM, OptLevel)) {
  }

  StringRef getPassName() const override {
    return "SuperH DAG->DAG Pattern Instruction Selection";
  }
};

} // namespace

char SHDAGToDAGISelLegacy::ID = 0;

FunctionPass *llvm::createSHISelDag(SHTargetMachine &TM,
                                    CodeGenOptLevel OptLevel) {
  return new SHDAGToDAGISelLegacy(TM, OptLevel);
}

bool SHDAGToDAGISel::SelectAddrFI(SDValue Addr, SDValue &Base, SDValue &Disp) {
  SDLoc DL(Addr);
  if (const auto *FI = dyn_cast<FrameIndexSDNode>(Addr)) {
    Base = CurDAG->getTargetFrameIndex(FI->getIndex(), MVT::i32);
    Disp = CurDAG->getTargetConstant(0, DL, MVT::i32);
    return true;
  }
  if (CurDAG->isBaseWithConstantOffset(Addr))
    if (const auto *FI = dyn_cast<FrameIndexSDNode>(Addr.getOperand(0))) {
      const auto *C = cast<ConstantSDNode>(Addr.getOperand(1));
      Base = CurDAG->getTargetFrameIndex(FI->getIndex(), MVT::i32);
      Disp = CurDAG->getSignedTargetConstant(C->getSExtValue(), DL, MVT::i32);
      return true;
    }
  return false;
}

bool SHDAGToDAGISel::SelectAddrL(SDValue Addr, SDValue &Base, SDValue &Disp) {
  if (SelectAddrFI(Addr, Base, Disp))
    return true;
  SDLoc DL(Addr);
  if (Addr.getOpcode() == ISD::ADD)
    if (const auto *C = dyn_cast<ConstantSDNode>(Addr.getOperand(1))) {
      int64_t Value = C->getSExtValue();
      if (Value > 0 && Value <= 60 && (Value & 3) == 0) {
        Base = Addr.getOperand(0);
        Disp = CurDAG->getTargetConstant(Value, DL, MVT::i32);
        return true;
      }
    }
  Base = Addr;
  Disp = CurDAG->getTargetConstant(0, DL, MVT::i32);
  return true;
}

bool SHDAGToDAGISel::SelectAddrBW(SDValue Addr, SDValue &Base, SDValue &Disp) {
  if (SelectAddrFI(Addr, Base, Disp))
    return true;
  Base = Addr;
  Disp = CurDAG->getTargetConstant(0, SDLoc(Addr), MVT::i32);
  return true;
}

bool SHDAGToDAGISel::SelectInlineAsmMemoryOperand(
    const SDValue &Op, InlineAsm::ConstraintCode ConstraintID,
    std::vector<SDValue> &OutOps) {
  // "m" and its relatives: the address in a register.  That of a stack
  // slot is computed first, an instruction of the assembly has no room for
  // a frame offset.
  SDLoc DL(Op);
  SDValue Zero = CurDAG->getTargetConstant(0, DL, MVT::i32);
  SDValue Base = Op;
  if (const auto *FI = dyn_cast<FrameIndexSDNode>(Op))
    Base = SDValue(CurDAG->getMachineNode(
                       SH::LEAFI, DL, MVT::i32,
                       CurDAG->getTargetFrameIndex(FI->getIndex(), MVT::i32),
                       Zero),
                   0);
  OutOps.push_back(Base);
  OutOps.push_back(Zero);
  return false;
}

/// A shift by a constant on a processor without shad and shld: a row of the
/// shifts by sixteen, eight, two and one.
bool SHDAGToDAGISel::selectConstantShift(SDNode *Node) {
  if (Subtarget->hasDynShift())
    return false;
  const auto *C = dyn_cast<ConstantSDNode>(Node->getOperand(1));
  if (!C || C->getZExtValue() == 0 || C->getZExtValue() > 31)
    return false;
  unsigned Amount = C->getZExtValue();
  SDLoc DL(Node);
  SDValue Value = Node->getOperand(0);
  auto Emit = [&](unsigned Opc, unsigned Bits) {
    SDValue Ops[] = {Value, Value};
    // "add Rn,Rn" is the shift to the left by one that leaves T alone.
    Value =
        SDValue(CurDAG->getMachineNode(Opc, DL, MVT::i32,
                                       ArrayRef(Ops, Opc == SH::ADDrr ? 2 : 1)),
                0);
    Amount -= Bits;
  };
  switch (Node->getOpcode()) {
  case ISD::SHL:
    while (Amount >= 16)
      Emit(SH::SHLL16, 16);
    while (Amount >= 8)
      Emit(SH::SHLL8, 8);
    while (Amount >= 2)
      Emit(SH::SHLL2, 2);
    while (Amount)
      Emit(SH::ADDrr, 1);
    break;
  case ISD::SRL:
    while (Amount >= 16)
      Emit(SH::SHLR16, 16);
    while (Amount >= 8)
      Emit(SH::SHLR8, 8);
    while (Amount >= 2)
      Emit(SH::SHLR2, 2);
    while (Amount)
      Emit(SH::SHLR, 1);
    break;
  case ISD::SRA:
    while (Amount)
      Emit(SH::SHAR, 1);
    break;
  default:
    return false;
  }
  ReplaceNode(Node, Value.getNode());
  return true;
}

void SHDAGToDAGISel::Select(SDNode *Node) {
  if (Node->isMachineOpcode()) {
    Node->setNodeId(-1);
    return;
  }
  switch (Node->getOpcode()) {
  case ISD::SHL:
  case ISD::SRL:
  case ISD::SRA:
    if (selectConstantShift(Node))
      return;
    break;
  default:
    break;
  }
  SelectCode(Node);
}
