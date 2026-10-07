//===-- SHISelDAGToDAG.cpp - Instruction selection for SuperH -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SH.h"
#include "SHSelectionDAGInfo.h"
#include "SHSubtarget.h"
#include "SHTargetMachine.h"
#include "llvm/CodeGen/MachineFunction.h"
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
    return SelectionDAGISel::runOnMachineFunction(MF);
  }

  void Select(SDNode *Node) override;

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

void SHDAGToDAGISel::Select(SDNode *Node) {
  if (Node->isMachineOpcode()) {
    Node->setNodeId(-1);
    return;
  }
  SelectCode(Node);
}
