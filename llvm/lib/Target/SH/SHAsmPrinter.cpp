//===-- SHAsmPrinter.cpp - SuperH code as assembly text -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/SHInstPrinter.h"
#include "SH.h"
#include "SHInstrInfo.h"
#include "SHSubtarget.h"
#include "TargetInfo/SHTargetInfo.h"
#include "llvm/CodeGen/AsmPrinter.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

#define DEBUG_TYPE "asm-printer"

namespace {

class SHAsmPrinter : public AsmPrinter {
public:
  static char ID;

  explicit SHAsmPrinter(TargetMachine &TM, std::unique_ptr<MCStreamer> Streamer)
      : AsmPrinter(TM, std::move(Streamer), ID) {}

  StringRef getPassName() const override { return "SuperH Assembly Printer"; }

  void emitInstruction(const MachineInstr *MI) override;

  bool PrintAsmOperand(const MachineInstr *MI, unsigned OpNo,
                       const char *ExtraCode, raw_ostream &O) override;
  bool PrintAsmMemoryOperand(const MachineInstr *MI, unsigned OpNo,
                             const char *ExtraCode, raw_ostream &O) override;

private:
  /// The symbol that an operand names, with its offset, or null for an
  /// operand that names none.
  const MCExpr *lowerSymbol(const MachineOperand &MO) const;
  bool lowerOperand(const MachineOperand &MO, MCOperand &Out) const;
  void lower(const MachineInstr *MI, MCInst &Out) const;

  void emit(unsigned Opcode, std::initializer_list<MCOperand> Operands = {});
  MCOperand label(const MCSymbol *Symbol) const {
    return MCOperand::createExpr(MCSymbolRefExpr::create(Symbol, OutContext));
  }
  /// The jump through a literal: r0 is pushed, loaded, jumped through, and
  /// popped in the delay slot of the jump.
  void emitFarJump(const MachineInstr *MI);
  void emitOne(const MachineInstr *MI);
};

} // namespace

char SHAsmPrinter::ID = 0;

INITIALIZE_PASS(SHAsmPrinter, "sh-asm-printer", "SuperH Assembly Printer",
                false, false)

const MCExpr *SHAsmPrinter::lowerSymbol(const MachineOperand &MO) const {
  const MCSymbol *Symbol = nullptr;
  int64_t Offset = 0;
  switch (MO.getType()) {
  case MachineOperand::MO_MachineBasicBlock:
    Symbol = MO.getMBB()->getSymbol();
    break;
  case MachineOperand::MO_GlobalAddress:
    Symbol = getSymbol(MO.getGlobal());
    Offset = MO.getOffset();
    break;
  case MachineOperand::MO_ExternalSymbol:
    Symbol = GetExternalSymbolSymbol(MO.getSymbolName());
    break;
  case MachineOperand::MO_BlockAddress:
    Symbol = GetBlockAddressSymbol(MO.getBlockAddress());
    Offset = MO.getOffset();
    break;
  case MachineOperand::MO_JumpTableIndex:
    Symbol = GetJTISymbol(MO.getIndex());
    break;
  case MachineOperand::MO_ConstantPoolIndex:
    Symbol = GetCPISymbol(MO.getIndex());
    Offset = MO.getOffset();
    break;
  case MachineOperand::MO_MCSymbol:
    Symbol = MO.getMCSymbol();
    break;
  default:
    return nullptr;
  }
  const MCExpr *Expr = MCSymbolRefExpr::create(Symbol, OutContext);
  if (Offset)
    Expr = MCBinaryExpr::createAdd(
        Expr, MCConstantExpr::create(Offset, OutContext), OutContext);
  return Expr;
}

bool SHAsmPrinter::lowerOperand(const MachineOperand &MO,
                                MCOperand &Out) const {
  switch (MO.getType()) {
  case MachineOperand::MO_Register:
    if (MO.isImplicit())
      return false;
    Out = MCOperand::createReg(MO.getReg());
    return true;
  case MachineOperand::MO_Immediate:
    Out = MCOperand::createImm(MO.getImm());
    return true;
  case MachineOperand::MO_RegisterMask:
    return false;
  default:
    if (const MCExpr *Expr = lowerSymbol(MO)) {
      Out = MCOperand::createExpr(Expr);
      return true;
    }
    report_fatal_error("unexpected operand of a SuperH instruction");
  }
}

void SHAsmPrinter::lower(const MachineInstr *MI, MCInst &Out) const {
  Out.setOpcode(MI->getOpcode());
  for (const MachineOperand &MO : MI->operands()) {
    MCOperand Op;
    if (lowerOperand(MO, Op))
      Out.addOperand(Op);
  }
}

void SHAsmPrinter::emit(unsigned Opcode,
                        std::initializer_list<MCOperand> Operands) {
  MCInst Inst;
  Inst.setOpcode(Opcode);
  for (const MCOperand &Op : Operands)
    Inst.addOperand(Op);
  EmitToStreamer(*OutStreamer, Inst);
}

void SHAsmPrinter::emitFarJump(const MachineInstr *MI) {
  MCOperand R0 = MCOperand::createReg(SH::R0);
  emit(SH::PUSH, {R0});
  emit(SH::MOVLpc, {R0, label(MI->getOperand(1).getMCSymbol())});
  emit(SH::JMP, {R0});
  emit(SH::POP, {R0});
}

// An instruction with a delay slot is one bundle with the instruction in
// the slot.  A nop is behind the branch.  An instruction that the filler
// moved into the slot is in front of it, where it is in the order of
// execution, and is written behind it.
void SHAsmPrinter::emitInstruction(const MachineInstr *MI) {
  if (!MI->isBundledWithSucc()) {
    emitOne(MI);
    return;
  }
  MachineBasicBlock::const_instr_iterator First = MI->getIterator();
  MachineBasicBlock::const_instr_iterator Second = std::next(First);
  assert(!Second->isBundledWithSucc() && "a branch and its slot are two");
  if (Second->hasDelaySlot(MachineInstr::IgnoreBundle))
    std::swap(First, Second);
  emitOne(&*First);
  emitOne(&*Second);
}

void SHAsmPrinter::emitOne(const MachineInstr *MI) {
  switch (MI->getOpcode()) {
  // A literal.
  case SH::CPENTRY: {
    OutStreamer->emitLabel(MI->getOperand(0).getMCSymbol());
    const MachineOperand &Value = MI->getOperand(1);
    if (Value.isImm())
      OutStreamer->emitIntValue(uint32_t(Value.getImm()), 4);
    else
      OutStreamer->emitValue(lowerSymbol(Value), 4);
    return;
  }

  // The long forms of the branches.
  case SH::BTnear:
  case SH::BFnear:
  case SH::BTfar:
  case SH::BFfar: {
    bool IsTrue = MI->getOpcode() == SH::BTnear || MI->getOpcode() == SH::BTfar;
    bool IsFar = MI->getOpcode() == SH::BTfar || MI->getOpcode() == SH::BFfar;
    MCSymbol *Skip = OutContext.createTempSymbol();
    emit(IsTrue ? SH::BF : SH::BT, {label(Skip)});
    if (IsFar) {
      emitFarJump(MI);
    } else {
      emit(SH::BRA, {label(MI->getOperand(0).getMBB()->getSymbol())});
      emit(SH::NOP);
    }
    OutStreamer->emitLabel(Skip);
    return;
  }
  case SH::BRAfar:
    emitFarJump(MI);
    return;
  default:
    break;
  }

  MCInst Inst;
  lower(MI, Inst);
  EmitToStreamer(*OutStreamer, Inst);
}

// An operand of inline assembly, as GCC prints it: a register by its name
// and a constant with "#" in front of it.  The modifiers that GCC has:
//
//   %O   a constant without the "#"
//   %R   the register or the word in memory with the low half of a 64-bit
//        value, %S the one with the high half
//   %T   the second register or word, whichever half that is
//
// A 64-bit value in registers is two operands here, the first of which has
// the half that comes first in memory.
bool SHAsmPrinter::PrintAsmOperand(const MachineInstr *MI, unsigned OpNo,
                                   const char *ExtraCode, raw_ostream &O) {
  bool Hash = true;
  bool Little = MF->getDataLayout().isLittleEndian();
  if (ExtraCode && ExtraCode[0]) {
    if (ExtraCode[1])
      return true;
    switch (ExtraCode[0]) {
    case 'O':
      Hash = false;
      break;
    case 'R':
      OpNo += Little ? 0 : 1;
      break;
    case 'S':
      OpNo += Little ? 1 : 0;
      break;
    case 'T':
      OpNo += 1;
      break;
    default:
      return AsmPrinter::PrintAsmOperand(MI, OpNo, ExtraCode, O);
    }
    // The second half of a value that has one register: GCC names the
    // register with the next number there, which belongs to someone else.
    if (ExtraCode[0] != 'O' &&
        (OpNo >= MI->getNumOperands() || !MI->getOperand(OpNo).isReg()))
      return true;
  }
  const MachineOperand &MO = MI->getOperand(OpNo);
  switch (MO.getType()) {
  case MachineOperand::MO_Register:
    O << SHInstPrinter::getRegisterName(MO.getReg());
    return false;
  case MachineOperand::MO_Immediate:
    if (Hash)
      O << '#';
    O << MO.getImm();
    return false;
  default:
    if (const MCExpr *Expr = lowerSymbol(MO)) {
      if (Hash)
        O << '#';
      MAI.printExpr(O, *Expr);
      return false;
    }
    return true;
  }
}

// The address is in a register: "@r1".  %R, %S and %T ask for one of the
// two words of a 64-bit value there.
bool SHAsmPrinter::PrintAsmMemoryOperand(const MachineInstr *MI, unsigned OpNo,
                                         const char *ExtraCode,
                                         raw_ostream &O) {
  bool Little = MF->getDataLayout().isLittleEndian();
  int Offset = 0;
  if (ExtraCode && ExtraCode[0]) {
    if (ExtraCode[1])
      return true;
    switch (ExtraCode[0]) {
    case 'R':
      Offset = Little ? 0 : 4;
      break;
    case 'S':
      Offset = Little ? 4 : 0;
      break;
    case 'T':
      Offset = 4;
      break;
    default:
      return true;
    }
  }
  const MachineOperand &Base = MI->getOperand(OpNo);
  if (!Base.isReg())
    return true;
  if (Offset)
    O << "@(" << Offset << ',' << SHInstPrinter::getRegisterName(Base.getReg())
      << ')';
  else
    O << '@' << SHInstPrinter::getRegisterName(Base.getReg());
  return false;
}

extern "C" LLVM_ABI LLVM_EXTERNAL_VISIBILITY void LLVMInitializeSHAsmPrinter() {
  RegisterAsmPrinter<SHAsmPrinter> X(getTheSHTarget());
  RegisterAsmPrinter<SHAsmPrinter> Y(getTheSHebTarget());
}
