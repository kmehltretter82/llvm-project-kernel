//===-- SHConstantIslands.cpp - Literals in the code and far branches -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

//
// An immediate operand has eight bits on SuperH.  A larger number, and every
// address, is loaded with "mov.l @(disp,pc),Rn" from a literal that lies in
// the code at most 1020 bytes behind the load.  This pass decides where the
// literals go:
//
// - behind an unconditional branch or a return, where nothing runs into
//   them, if one comes in time;
// - otherwise in the middle of the code, with a jump around them.
//
// The second job needs the same knowledge of where everything is: a
// conditional branch reaches 256 bytes and bra 4094.  A branch that does not
// reach its target is replaced by a longer form.
//
// The two depend on each other, so the pass works on a plan.  It walks the
// function and computes the address of every instruction as if the literals
// were placed, replaces the branches that the plan shows to be out of reach,
// and plans again until no branch changes.  Branches only ever get longer,
// so this ends.  Then the plan is carried out.
//
// The literals of one place are a block of their own, which nothing leads
// to.  Where they go into running code, the block is split and its first
// part gets a branch to the second.
//
// The delay slots are filled after this pass, so a branch with a slot
// counts as four bytes here.  Filling a slot with an instruction from in
// front of the branch makes the code two bytes shorter.  Not every distance
// gets shorter with it: the padding in front of literals can give the two
// bytes back, and a load counts from its own address rounded down to a
// multiple of four.  A load can be four bytes further from its literal
// than planned and a branch two bytes further from its target, however
// many slots are filled, and the limits below leave that room.
//
//===----------------------------------------------------------------------===//

#include "SH.h"
#include "SHInstrInfo.h"
#include "SHSubtarget.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/MC/MCContext.h"
#include <climits>

using namespace llvm;

#define DEBUG_TYPE "sh-constant-islands"

namespace {

class SHConstantIslands : public MachineFunctionPass {
public:
  static char ID;
  SHConstantIslands() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override {
    return "SuperH literal placement and branch relaxation";
  }

  bool runOnMachineFunction(MachineFunction &Fn) override;

  MachineFunctionProperties getRequiredProperties() const override {
    return MachineFunctionProperties().setNoVRegs();
  }

private:
  /// The displacement of a load is at most 1020 bytes from the address of
  /// the load, rounded down to a multiple of four, plus four.  Twenty bytes
  /// of margin are for the sizes that are estimates: inline assembly, and
  /// with it the padding in front of the literals behind it.  Four more
  /// are for the delay slots that are filled later.
  static constexpr int Reach = 996;
  /// What a bt or bf (254 bytes) and a bra (4094) reach, with eight and
  /// sixteen bytes for the estimates and two for the delay slots.
  static constexpr int CondReach = 244;
  static constexpr int BraReach = 4076;

  struct Literal {
    MachineOperand Value;
    /// The instructions that load it.  A MOVLpcrel is replaced by the real
    /// load, any other gets the label as its second operand.
    SmallVector<MachineInstr *, 2> Users;
    /// The literal of a far branch: not where its target is but how far it
    /// is from the branch, so no other instruction can share it.
    bool Distance = false;
  };

  MachineFunction *MF = nullptr;
  const SHInstrInfo *TII = nullptr;

  DenseMap<const MachineInstr *, int> InstAddr;
  DenseMap<const MachineBasicBlock *, int> BlockAddr;
  /// The blocks of literals that this pass made.
  SmallPtrSet<const MachineBasicBlock *, 8> Islands;

  /// The literals that are waiting for a place, in the order of their
  /// first use.
  SmallVector<Literal, 8> Pool;
  /// The largest "4 * index - address of the first use" of the pool: how
  /// far the literal that is worst off is from its load if the pool starts
  /// at address zero.
  int Worst = INT_MIN;
  int Addr = 0;

  /// The bytes that an instruction takes, with its delay slot.
  int sizeOf(const MachineInstr &MI) const {
    return TII->getInstSizeInBytes(MI) + (MI.hasDelaySlot() ? 2 : 0);
  }

  void addLiteral(const MachineOperand &Value, int UseAddr, MachineInstr *User,
                  bool Distance = false);
  MachineBasicBlock *flush(MachineBasicBlock &MBB,
                           MachineBasicBlock::iterator Before, bool Inline,
                           bool Materialize);
  void place(bool Materialize);
  bool relaxBranches();
};

} // namespace

char SHConstantIslands::ID = 0;

INITIALIZE_PASS(SHConstantIslands, DEBUG_TYPE,
                "SuperH literal placement and branch relaxation", false, false)

FunctionPass *llvm::createSHConstantIslandsPass() {
  return new SHConstantIslands();
}

void SHConstantIslands::addLiteral(const MachineOperand &Value, int UseAddr,
                                   MachineInstr *User, bool Distance) {
  if (!Distance)
    for (Literal &L : Pool)
      if (!L.Distance && L.Value.isIdenticalTo(Value)) {
        L.Users.push_back(User);
        return;
      }
  Worst = std::max(Worst, int(4 * Pool.size()) - UseAddr);
  Pool.push_back({Value, {User}, Distance});
}

/// Put the waiting literals behind \p MBB.  \p Inline: the code runs on
/// there.  The block then ends in front of \p Before with a jump around the
/// literals, and what was behind it is a block of its own, which is
/// returned once it exists.
MachineBasicBlock *SHConstantIslands::flush(MachineBasicBlock &MBB,
                                            MachineBasicBlock::iterator Before,
                                            bool Inline, bool Materialize) {
  MCContext &Ctx = MF->getContext();
  DebugLoc DL;
  MachineBasicBlock *Island = nullptr, *Rest = nullptr;
  if (Materialize) {
    MachineFunction::iterator After = std::next(MBB.getIterator());
    Island = MF->CreateMachineBasicBlock();
    MF->insert(After, Island);
    Island->setAlignment(Align(4));
    Islands.insert(Island);
    if (Inline) {
      Rest = MF->CreateMachineBasicBlock(MBB.getBasicBlock());
      MF->insert(After, Rest);
      Rest->splice(Rest->begin(), &MBB, Before, MBB.end());
      Rest->transferSuccessors(&MBB);
      MBB.addSuccessor(Rest);
      BuildMI(&MBB, DL, TII->get(SH::BRA)).addMBB(Rest);
      LivePhysRegs LiveRegs;
      computeAndAddLiveIns(LiveRegs, *Rest);
    }
  }
  // The jump and its delay slot, and the alignment of the literals.
  if (Inline)
    Addr += 4;
  Addr += Addr & 2;
  for (Literal &L : Pool) {
    if (Materialize && L.Distance) {
      MCSymbol *Label = Ctx.createTempSymbol();
      MCSymbol *Anchor = Ctx.createTempSymbol();
      BuildMI(Island, DL, TII->get(SH::CPENTRYrel))
          .addSym(Label)
          .add(L.Value)
          .addSym(Anchor);
      MachineInstr *User = L.Users.front();
      User->getOperand(1).ChangeToMCSymbol(Label);
      User->getOperand(2).ChangeToMCSymbol(Anchor);
    } else if (Materialize) {
      MCSymbol *Label = Ctx.createTempSymbol();
      BuildMI(Island, DL, TII->get(SH::CPENTRY)).addSym(Label).add(L.Value);
      for (MachineInstr *User : L.Users) {
        if (User->getOpcode() != SH::MOVLpcrel) {
          User->getOperand(1).ChangeToMCSymbol(Label);
          continue;
        }
        BuildMI(*User->getParent(), User, User->getDebugLoc(),
                TII->get(SH::MOVLpc), User->getOperand(0).getReg())
            .addSym(Label);
        User->eraseFromParent();
      }
    }
    Addr += 4;
  }
  Pool.clear();
  Worst = INT_MIN;
  return Rest;
}

/// Walk the function, give every instruction and block its address, and
/// decide where the literals go.  With \p Materialize, put them there.
void SHConstantIslands::place(bool Materialize) {
  Addr = 0;
  Pool.clear();
  Worst = INT_MIN;
  InstAddr.clear();
  BlockAddr.clear();

  for (MachineFunction::iterator BI = MF->begin(); BI != MF->end(); ++BI) {
    MachineBasicBlock *MBB = &*BI;
    // What this walk has placed is counted.
    if (Islands.count(MBB))
      continue;
    BlockAddr[MBB] = Addr;
    bool InTerminators = false;
    for (auto I = MBB->begin(); I != MBB->end();) {
      MachineInstr &MI = *I;
      ++I;
      int Size = sizeOf(MI);
      if (!Size)
        continue;

      // If the literals do not reach from behind this instruction, they go
      // in front of it.  The branches at the end of a block stay together:
      // the question is asked for all of them at the first.  Sixteen bytes
      // are for a literal of this instruction and for rounding.
      if (!Pool.empty() && !InTerminators) {
        int Need = Size;
        if (MI.isTerminator())
          for (auto T = I; T != MBB->end(); ++T)
            Need += sizeOf(*T);
        if (Addr + 6 + Worst + 16 + Need > Reach)
          if (MachineBasicBlock *Rest =
                  flush(*MBB, MI.getIterator(), /*Inline=*/true, Materialize)) {
            // MI is the first instruction of a new block now.
            MBB = Rest;
            BI = Rest->getIterator();
            BlockAddr[MBB] = Addr;
            I = std::next(MI.getIterator());
          }
      }
      InTerminators |= MI.isTerminator();

      InstAddr[&MI] = Addr;
      switch (MI.getOpcode()) {
      // The first of the three instructions has the longest way.
      case SH::MOVLpcrel:
      case SH::LOADGOT:
        addLiteral(MI.getOperand(1), Addr, &MI);
        break;
      // The load is the second instruction of the sequence, and the third
      // behind the conditional branch.
      case SH::BRAfar:
        addLiteral(MachineOperand::CreateMBB(MI.getOperand(0).getMBB()),
                   Addr + 2, &MI, /*Distance=*/true);
        break;
      case SH::BTfar:
      case SH::BFfar:
        addLiteral(MachineOperand::CreateMBB(MI.getOperand(0).getMBB()),
                   Addr + 4, &MI, /*Distance=*/true);
        break;
      default:
        break;
      }
      Addr += Size;

      // Behind an unconditional branch nothing runs into the literals, if
      // it is the last thing in its block that takes room.  What takes none
      // does not count: debug information must not change the code.
      if (!Pool.empty() && MI.isBarrier() &&
          none_of(make_range(I, MBB->end()),
                  [&](const MachineInstr &Next) { return sizeOf(Next) != 0; }))
        flush(*MBB, MBB->end(), /*Inline=*/false, Materialize);
    }
  }
  if (!Pool.empty())
    flush(MF->back(), MF->back().end(), /*Inline=*/false, Materialize);
}

/// Replace the branches that the last plan shows to be out of reach.
bool SHConstantIslands::relaxBranches() {
  bool Changed = false;
  for (MachineBasicBlock &MBB : *MF)
    for (auto I = MBB.begin(); I != MBB.end();) {
      MachineInstr &MI = *I;
      ++I;
      unsigned Opc = MI.getOpcode();
      if (Opc != SH::BT && Opc != SH::BF && Opc != SH::BRA &&
          Opc != SH::BTnear && Opc != SH::BFnear)
        continue;
      int From = InstAddr.lookup(&MI);
      int Target = BlockAddr.lookup(MI.getOperand(0).getMBB());
      // A displacement counts from four bytes behind the branch.
      auto Reaches = [&](int BranchAddr, int Limit) {
        int Distance = Target - (BranchAddr + 4);
        return Distance >= -Limit && Distance <= Limit;
      };
      bool IsTrue = Opc == SH::BT || Opc == SH::BTnear;
      switch (Opc) {
      case SH::BT:
      case SH::BF:
        if (Reaches(From, CondReach))
          continue;
        // "bf 1f; bra target; nop; 1:" if the bra reaches.
        if (Reaches(From + 2, BraReach)) {
          MI.setDesc(TII->get(IsTrue ? SH::BTnear : SH::BFnear));
          break;
        }
        [[fallthrough]];
      case SH::BTnear:
      case SH::BFnear:
        if ((Opc == SH::BTnear || Opc == SH::BFnear) &&
            Reaches(From + 2, BraReach))
          continue;
        MI.setDesc(TII->get(IsTrue ? SH::BTfar : SH::BFfar));
        MI.addOperand(*MF, MachineOperand::CreateImm(0));
        MI.addOperand(*MF, MachineOperand::CreateImm(0));
        break;
      case SH::BRA:
        if (Reaches(From, BraReach))
          continue;
        MI.setDesc(TII->get(SH::BRAfar));
        MI.addOperand(*MF, MachineOperand::CreateImm(0));
        MI.addOperand(*MF, MachineOperand::CreateImm(0));
        break;
      }
      Changed = true;
    }
  return Changed;
}

bool SHConstantIslands::runOnMachineFunction(MachineFunction &Fn) {
  MF = &Fn;
  TII = MF->getSubtarget<SHSubtarget>().getInstrInfo();
  Islands.clear();
  // The padding in front of literals is computed from the start of the
  // function.
  MF->ensureAlignment(Align(4));

  do
    place(/*Materialize=*/false);
  while (relaxBranches());
  place(/*Materialize=*/true);
  return true;
}
