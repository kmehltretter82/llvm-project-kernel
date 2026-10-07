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
// The literals are pseudo instructions inside their block.  A jump around
// them is one too (CPJUMP), which keeps the blocks and their edges as they
// are.
//
//===----------------------------------------------------------------------===//

#include "SH.h"
#include "SHInstrInfo.h"
#include "SHSubtarget.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
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
  /// the load, rounded down to a multiple of four, plus four.  The margin
  /// is for the sizes that are estimates: inline assembly, and with it the
  /// padding in front of the literals behind it.
  static constexpr int Reach = 1000;
  /// What a bt or bf and a bra reach, with the same margin.
  static constexpr int CondReach = 246;
  static constexpr int BraReach = 4078;

  struct Literal {
    MachineOperand Value;
    /// The instructions that load it.  A MOVLpcrel is replaced by the real
    /// load, a far branch gets the label as its second operand.
    SmallVector<MachineInstr *, 2> Users;
  };

  MachineFunction *MF = nullptr;
  const SHInstrInfo *TII = nullptr;

  DenseMap<const MachineInstr *, int> InstAddr;
  DenseMap<const MachineBasicBlock *, int> BlockAddr;

  /// The literals that are waiting for a place, in the order of their
  /// first use.
  SmallVector<Literal, 8> Pool;
  /// The largest "4 * index - address of the first use" of the pool: how
  /// far the literal that is worst off is from its load if the pool starts
  /// at address zero.
  int Worst = INT_MIN;
  int Addr = 0;

  void addLiteral(const MachineOperand &Value, int UseAddr, MachineInstr *User);
  void flush(MachineBasicBlock &MBB, MachineBasicBlock::iterator Before,
             bool Inline, bool Materialize);
  void place(bool Materialize);
  bool relaxBranches();
};

} // namespace

char SHConstantIslands::ID = 0;

FunctionPass *llvm::createSHConstantIslandsPass() {
  return new SHConstantIslands();
}

void SHConstantIslands::addLiteral(const MachineOperand &Value, int UseAddr,
                                   MachineInstr *User) {
  for (Literal &L : Pool)
    if (L.Value.isIdenticalTo(Value)) {
      L.Users.push_back(User);
      return;
    }
  Worst = std::max(Worst, int(4 * Pool.size()) - UseAddr);
  Pool.push_back({Value, {User}});
}

/// Put the waiting literals in front of \p Before.  \p Inline: the code
/// runs on here, and a jump goes around them.
void SHConstantIslands::flush(MachineBasicBlock &MBB,
                              MachineBasicBlock::iterator Before, bool Inline,
                              bool Materialize) {
  MCContext &Ctx = MF->getContext();
  DebugLoc DL;
  MCSymbol *Skip = nullptr;
  if (Inline) {
    if (Materialize) {
      Skip = Ctx.createTempSymbol();
      BuildMI(MBB, Before, DL, TII->get(SH::CPJUMP)).addSym(Skip);
    }
    Addr += 4;
  }
  int Pad = Addr & 2;
  if (Materialize)
    BuildMI(MBB, Before, DL, TII->get(SH::CPALIGN)).addImm(Pad);
  Addr += Pad;
  for (Literal &L : Pool) {
    if (Materialize) {
      MCSymbol *Label = Ctx.createTempSymbol();
      BuildMI(MBB, Before, DL, TII->get(SH::CPENTRY))
          .addSym(Label)
          .add(L.Value);
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
  if (Skip)
    BuildMI(MBB, Before, DL, TII->get(SH::CPLABEL)).addSym(Skip);
  Pool.clear();
  Worst = INT_MIN;
}

/// Walk the function, give every instruction and block its address, and
/// decide where the literals go.  With \p Materialize, put them there.
void SHConstantIslands::place(bool Materialize) {
  Addr = 0;
  Pool.clear();
  Worst = INT_MIN;
  InstAddr.clear();
  BlockAddr.clear();

  // The next instruction is in the delay slot of a branch, and that branch
  // is one that control does not pass.
  bool InSlot = false, SlotOfBarrier = false;

  for (MachineBasicBlock &MBB : *MF) {
    BlockAddr[&MBB] = Addr;
    for (auto I = MBB.begin(); I != MBB.end();) {
      MachineInstr &MI = *I;
      ++I;
      int Size = TII->getInstSizeInBytes(MI);
      if (!Size)
        continue;

      // If the literals do not reach from behind this instruction, they go
      // in front of it.  Sixteen bytes are for what cannot be split off:
      // the instruction in a delay slot, and a literal of this instruction.
      if (!Pool.empty() && !InSlot && Addr + 6 + Worst + 16 + Size > Reach)
        flush(MBB, MI.getIterator(), /*Inline=*/true, Materialize);

      InstAddr[&MI] = Addr;
      switch (MI.getOpcode()) {
      case SH::MOVLpcrel:
        addLiteral(MI.getOperand(1), Addr, &MI);
        break;
      // The load is the second instruction of the sequence, and the third
      // behind the conditional branch.
      case SH::BRAfar:
        addLiteral(MachineOperand::CreateMBB(MI.getOperand(0).getMBB()),
                   Addr + 2, &MI);
        break;
      case SH::BTfar:
      case SH::BFfar:
        addLiteral(MachineOperand::CreateMBB(MI.getOperand(0).getMBB()),
                   Addr + 4, &MI);
        break;
      default:
        break;
      }
      Addr += Size;

      bool WasSlotOfBarrier = InSlot && SlotOfBarrier;
      bool WasSlot = InSlot;
      InSlot = SlotOfBarrier = false;
      if (MI.hasDelaySlot()) {
        InSlot = true;
        SlotOfBarrier = MI.isBarrier();
        continue;
      }
      // Behind an unconditional branch and its delay slot nothing runs into
      // the literals.
      if (!Pool.empty() && (WasSlotOfBarrier || (!WasSlot && MI.isBarrier())))
        flush(MBB, I, /*Inline=*/false, Materialize);
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
        break;
      case SH::BRA:
        if (Reaches(From, BraReach))
          continue;
        MI.setDesc(TII->get(SH::BRAfar));
        MI.addOperand(*MF, MachineOperand::CreateImm(0));
        // The far form brings its own delay slot.
        if (I != MBB.end() && I->getOpcode() == SH::NOP) {
          MachineInstr &Nop = *I;
          ++I;
          Nop.eraseFromParent();
        }
        break;
      }
      Changed = true;
    }
  return Changed;
}

bool SHConstantIslands::runOnMachineFunction(MachineFunction &Fn) {
  MF = &Fn;
  TII = MF->getSubtarget<SHSubtarget>().getInstrInfo();
  // The padding in front of literals is computed from the start of the
  // function.
  MF->ensureAlignment(Align(4));

  do
    place(/*Materialize=*/false);
  while (relaxBranches());
  place(/*Materialize=*/true);
  return true;
}
