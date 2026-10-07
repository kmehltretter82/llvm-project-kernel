//===-- SHDelaySlotFiller.cpp - The instruction behind a delayed branch ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// bra, jmp, jsr and rts take effect one instruction late: the instruction
// behind them, in their delay slot, runs first.  This pass fills the slot
// with the instruction in front of the branch where that changes nothing,
// and with a nop otherwise.
//
// The instruction in front of the branch runs between what comes before it
// and the place that the branch goes to, wherever it is written.  What can
// differ is what it and the branch see of each other: jmp and jsr read the
// register with their target before the slot, jsr writes pr before it, and
// rts reads pr before it.  So the instruction must not write the target
// register or pr, and in front of a jsr it must not read pr either.  Some
// instructions are not allowed in a slot at all: branches, and a load that
// is relative to the program counter.
//
// The instruction need not be the one right in front of the branch: the
// pass looks a few instructions back for one that can be moved over the
// instructions behind it, because none of them reads what it writes or
// writes what it reads or writes.  A load or a store is not moved over
// another one: the order of the accesses to memory stays as it is, which a
// volatile object needs.  The search ends at a call, a branch, inline
// assembly, a label, and at the instructions that set up the frame.
//
// The two are one bundle, so that the branch is still the last thing in its
// block for everyone who looks.  A nop is behind the branch in the bundle.
// An instruction that was moved into the slot is in front of it, as it is
// in the order of execution, and the printer writes the branch first.
//
// This pass runs behind the one that places the literals, which counts a
// nop for every slot.  A slot that is filled makes the code two bytes
// shorter.  The padding in front of literals can give two bytes back, and a
// load counts from its address rounded down to four: so a load can end up
// four bytes further from its literal and a branch two bytes further from
// its target than planned, which that pass leaves room for.
//
//===----------------------------------------------------------------------===//

#include "SH.h"
#include "SHInstrInfo.h"
#include "SHSubtarget.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;

#define DEBUG_TYPE "sh-delay-slot"

static cl::opt<bool>
    FillSlots("sh-fill-delay-slots", cl::Hidden, cl::init(true),
              cl::desc("Move an instruction into the delay slot of a branch "
                       "instead of a nop"));

namespace {

class SHDelaySlotFiller : public MachineFunctionPass {
public:
  static char ID;
  SHDelaySlotFiller() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override { return "SuperH delay slot filler"; }

  bool runOnMachineFunction(MachineFunction &MF) override;

  MachineFunctionProperties getRequiredProperties() const override {
    return MachineFunctionProperties().setNoVRegs();
  }

private:
  bool canFill(const MachineInstr &Branch, const MachineInstr &MI) const;
  MachineInstr *findFiller(MachineInstr &Branch) const;

  const SHInstrInfo *TII = nullptr;
  const TargetRegisterInfo *TRI = nullptr;
};

} // namespace

char SHDelaySlotFiller::ID = 0;

INITIALIZE_PASS(SHDelaySlotFiller, DEBUG_TYPE, "SuperH delay slot filler",
                false, false)

FunctionPass *llvm::createSHDelaySlotFillerPass() {
  return new SHDelaySlotFiller();
}

/// Whether \p MI, the instruction in front of \p Branch, can be written
/// behind it.
bool SHDelaySlotFiller::canFill(const MachineInstr &Branch,
                                const MachineInstr &MI) const {
  // One real instruction of two bytes that is nothing special.
  if (MI.isPseudo() || MI.isMetaInstruction() || MI.isInlineAsm() ||
      MI.isBundled() || MI.isCall() || MI.isBranch() || MI.isReturn() ||
      MI.isTerminator() || MI.hasDelaySlot() || MI.hasUnmodeledSideEffects() ||
      TII->getInstSizeInBytes(MI) != 2)
    return false;
  // Relative to the program counter, which is another one in a slot.
  if (MI.getOpcode() == SH::MOVLpc)
    return false;

  auto Touches = [&](MCRegister Reg, bool OnlyDefs) {
    for (const MachineOperand &MO : MI.operands()) {
      if (!MO.isReg() || !MO.getReg() || (OnlyDefs && !MO.isDef()))
        continue;
      if (TRI->regsOverlap(MO.getReg(), Reg))
        return true;
    }
    return false;
  };

  switch (Branch.getOpcode()) {
  case SH::BRA:
    return true;
  // The target is read in front of the slot.
  case SH::JMP:
  case SH::TAILJMP:
  case SH::TAILrel:
    return !Touches(Branch.getOperand(0).getReg(), /*OnlyDefs=*/true);
  // And pr is written in front of it.
  case SH::JSR:
  case SH::CALLrel:
    return !Touches(Branch.getOperand(0).getReg(), /*OnlyDefs=*/true) &&
           !Touches(SH::PR, /*OnlyDefs=*/false);
  // pr is read in front of the slot.
  case SH::RTS:
    return !Touches(SH::PR, /*OnlyDefs=*/true);
  default:
    return false;
  }
}

/// The instruction in front of \p Branch that can go to its slot, or null.
MachineInstr *SHDelaySlotFiller::findFiller(MachineInstr &Branch) const {
  MachineBasicBlock &MBB = *Branch.getParent();
  // What the instructions between a candidate and the branch read and
  // write.
  SmallVector<MCRegister, 16> Read, Written;
  bool Memory = false;
  auto Overlaps = [&](ArrayRef<MCRegister> Regs, MCRegister Reg) {
    return any_of(Regs, [&](MCRegister R) { return TRI->regsOverlap(R, Reg); });
  };

  unsigned Budget = 8;
  for (MachineBasicBlock::iterator I = Branch.getIterator();
       I != MBB.begin() && Budget; --Budget) {
    --I;
    MachineInstr &MI = *I;
    if (MI.isDebugInstr()) {
      ++Budget;
      continue;
    }
    // The instructions that set up the frame stay where the unwind
    // information says they are.  The pass stops at them whether there is
    // such information or not: it is there with -g and may not be without,
    // and the code has to be the same.
    if (MI.getFlag(MachineInstr::FrameSetup))
      return nullptr;
    // Nothing is moved over these.
    if (MI.isMetaInstruction() || MI.isInlineAsm() || MI.isCall() ||
        MI.isTerminator() || MI.isBundled() || MI.hasDelaySlot() ||
        MI.hasUnmodeledSideEffects())
      return nullptr;

    bool Free = canFill(Branch, MI);
    if (Free && Memory && MI.mayLoadOrStore())
      Free = false;
    for (const MachineOperand &MO : MI.operands()) {
      if (!Free)
        break;
      if (MO.isRegMask())
        Free = false;
      if (!MO.isReg() || !MO.getReg())
        continue;
      MCRegister Reg = MO.getReg().asMCReg();
      if (Overlaps(Written, Reg) || (MO.isDef() && Overlaps(Read, Reg)))
        Free = false;
    }
    if (Free)
      return &MI;

    // It stays where it is, and the next candidate has to get past it.
    for (const MachineOperand &MO : MI.operands()) {
      if (MO.isRegMask())
        return nullptr;
      if (!MO.isReg() || !MO.getReg())
        continue;
      (MO.isDef() ? Written : Read).push_back(MO.getReg().asMCReg());
    }
    Memory |= MI.mayLoadOrStore();
  }
  return nullptr;
}

bool SHDelaySlotFiller::runOnMachineFunction(MachineFunction &MF) {
  const SHSubtarget &STI = MF.getSubtarget<SHSubtarget>();
  TII = STI.getInstrInfo();
  TRI = STI.getRegisterInfo();
  bool Fill = FillSlots && !skipFunction(MF.getFunction());

  bool Changed = false, Filled = false;
  for (MachineBasicBlock &MBB : MF)
    for (auto I = MBB.begin(); I != MBB.end(); ++I) {
      if (!I->hasDelaySlot())
        continue;
      Changed = true;
      if (Fill)
        if (MachineInstr *Filler = findFiller(*I)) {
          // What it reads is alive behind the instructions that it is
          // moved over.
          for (auto Over = std::next(Filler->getIterator()); Over != I; ++Over)
            for (const MachineOperand &MO : Filler->all_uses())
              if (MO.getReg())
                Over->clearRegisterKills(MO.getReg(), TRI);
          // In the order of execution: the instruction, then the branch.
          MBB.splice(I, &MBB, Filler->getIterator());
          MIBundleBuilder(MBB, Filler->getIterator(), std::next(I));
          Filled = true;
          continue;
        }
      BuildMI(MBB, std::next(I), I->getDebugLoc(), TII->get(SH::NOP));
      MIBundleBuilder(MBB, I, std::next(I, 2));
    }
  // A register that the instruction in the slot sets and the branch uses,
  // an argument of a call for one, is a definition and a use in one bundle,
  // which the liveness of registers has no word for.
  if (Filled)
    MF.getRegInfo().invalidateLiveness();
  return Changed;
}
