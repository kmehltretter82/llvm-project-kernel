//===-- SHAsmPrinter.cpp - SuperH code as assembly text -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/SHInstPrinter.h"
#include "MCTargetDesc/SHMCAsmInfo.h"
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
  bool lowerAddress(const MachineInstr *MI, MCInst &Out) const;
  void lower(const MachineInstr *MI, MCInst &Out) const;

  void emit(unsigned Opcode, std::initializer_list<MCOperand> Operands = {});
  MCOperand label(const MCSymbol *Symbol) const {
    return MCOperand::createExpr(MCSymbolRefExpr::create(Symbol, OutContext));
  }
  /// The jump over a distance from a literal: r0 is pushed, loaded, added
  /// to the program counter by braf, and popped in the delay slot of that.
  void emitFarJump(const MachineInstr *MI);
  void emitProfileCall();
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
  // The target flags are what stands behind the "@".
  const MCExpr *Expr =
      MCSymbolRefExpr::create(Symbol, MO.getTargetFlags(), OutContext);
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

// The instructions of the code generator have an address as a register and
// a displacement.  The processor has one instruction for "@Rm" and another
// for "@(disp,Rm)", and only a long word has both.
bool SHAsmPrinter::lowerAddress(const MachineInstr *MI, MCInst &Out) const {
  unsigned Indirect, Displaced = 0;
  // Where the address begins: behind the register that is loaded or
  // stored, if the instruction names it.
  unsigned Addr = 1;
  switch (MI->getOpcode()) {
  case SH::MOVLld:
    Indirect = SH::MOVLind;
    Displaced = SH::MOVLdisp;
    break;
  case SH::MOVWld:
    Indirect = SH::MOVWind;
    break;
  case SH::MOVBld:
    Indirect = SH::MOVBind;
    break;
  case SH::MOVLst:
    Indirect = SH::MOVLsti;
    Displaced = SH::MOVLstd;
    break;
  case SH::MOVWst:
    Indirect = SH::MOVWsti;
    break;
  case SH::MOVBst:
    Indirect = SH::MOVBsti;
    break;
  // With r0, which is not an operand: these have a displacement always.
  case SH::MOVBldr0:
    Indirect = Displaced = SH::MOVBlddisp;
    Addr = 0;
    break;
  case SH::MOVWldr0:
    Indirect = Displaced = SH::MOVWlddisp;
    Addr = 0;
    break;
  case SH::MOVBstr0:
    Indirect = Displaced = SH::MOVBstdisp;
    Addr = 0;
    break;
  case SH::MOVWstr0:
    Indirect = Displaced = SH::MOVWstdisp;
    Addr = 0;
    break;
  default:
    return false;
  }
  int64_t Disp = MI->getOperand(Addr + 1).getImm();
  bool HasDisp = Disp || Indirect == Displaced;
  assert((!HasDisp || Displaced) && "a displacement that no instruction has");
  Out.setOpcode(HasDisp ? Displaced : Indirect);
  if (Addr)
    Out.addOperand(MCOperand::createReg(MI->getOperand(0).getReg()));
  Out.addOperand(MCOperand::createReg(MI->getOperand(Addr).getReg()));
  if (HasDisp)
    Out.addOperand(MCOperand::createImm(Disp));
  return true;
}

void SHAsmPrinter::lower(const MachineInstr *MI, MCInst &Out) const {
  if (lowerAddress(MI, Out))
    return;
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
  OutStreamer->emitLabel(MI->getOperand(2).getMCSymbol());
  emit(SH::BRAF, {R0});
  emit(SH::POP, {R0});
}

// The call of mcount in front of everything else in a function, which is
// what -pg asks for.  It is GCC's, because mcount is written for it: the
// return address of the function is on top of the stack, pr is the address
// to come back to, and all other registers are as the function got them.
//
//   mov.l 1f,r1; sts.l pr,@-r15; mova 2f,r0; jmp @r1; lds r0,pr
//   .align 2
//   1: .long mcount
//   2: lds.l @r15+,pr
//
// Position independent code takes the address from the global offset
// table, which it finds first:
//
//   mov.l 3f,r1; mova 3f,r0; add r1,r0; mov.l 1f,r1; mov.l @(r0,r1),r1
//   (as above)
//   1: .long mcount@GOT
//   3: .long _GLOBAL_OFFSET_TABLE_
//
// mcount keeps the registers that carry arguments.  It does not keep r2 and
// r3, which a function is given the address of its result in and its static
// chain: where they are, they are put on the stack first, under pr, and
// taken back last.
//
// SHInstrInfo::getInstSizeInBytes() has the sizes.  They count on the
// function being aligned to four bytes.
void SHAsmPrinter::emitProfileCall() {
  MCOperand R0 = MCOperand::createReg(SH::R0);
  MCOperand R1 = MCOperand::createReg(SH::R1);
  MCSymbol *Function = OutContext.createTempSymbol();
  MCSymbol *Table = OutContext.createTempSymbol();
  MCSymbol *Back = OutContext.createTempSymbol();
  bool IsPIC = isPositionIndependent();
  SmallVector<MCRegister, 2> Saved;
  for (MCRegister Reg : {SH::R2, SH::R3})
    if (MF->front().isLiveIn(Reg))
      Saved.push_back(Reg);
  for (MCRegister Reg : Saved)
    emit(SH::PUSH, {MCOperand::createReg(Reg)});
  if (IsPIC) {
    emit(SH::MOVLpc, {R1, label(Table)});
    emit(SH::MOVA, {label(Table)});
    emit(SH::ADDrr, {R0, R0, R1});
    emit(SH::MOVLpc, {R1, label(Function)});
    emit(SH::MOVLldr0, {R1, R1});
  } else {
    emit(SH::MOVLpc, {R1, label(Function)});
  }
  emit(SH::PUSHPR);
  emit(SH::MOVA, {label(Back)});
  emit(SH::JMP, {R1});
  emit(SH::LDSPR, {R0});
  OutStreamer->emitCodeAlignment(Align(4), getSubtargetInfo());
  OutStreamer->emitLabel(Function);
  OutStreamer->emitValue(
      MCSymbolRefExpr::create(GetExternalSymbolSymbol("mcount"),
                              IsPIC ? SH::S_GOT : SH::S_None, OutContext),
      4);
  if (IsPIC) {
    OutStreamer->emitLabel(Table);
    OutStreamer->emitValue(
        MCSymbolRefExpr::create(
            GetExternalSymbolSymbol("_GLOBAL_OFFSET_TABLE_"), OutContext),
        4);
  }
  OutStreamer->emitLabel(Back);
  emit(SH::POPPR);
  for (MCRegister Reg : reverse(Saved))
    emit(SH::POP, {MCOperand::createReg(Reg)});
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

  // The literal of a far branch.  braf adds to the address that is four
  // bytes behind itself.
  case SH::CPENTRYrel: {
    OutStreamer->emitLabel(MI->getOperand(0).getMCSymbol());
    const MCExpr *Target = MCSymbolRefExpr::create(
        MI->getOperand(1).getMBB()->getSymbol(), OutContext);
    const MCExpr *From = MCBinaryExpr::createAdd(
        MCSymbolRefExpr::create(MI->getOperand(2).getMCSymbol(), OutContext),
        MCConstantExpr::create(4, OutContext), OutContext);
    OutStreamer->emitValue(MCBinaryExpr::createSub(Target, From, OutContext),
                           4);
    return;
  }

  // The literal of a call over a distance.  bsrf and braf add to the
  // address that is four bytes behind them, which is two behind the label
  // of the call.  An entry of the procedure linkage table is named by its
  // distance from where the literal is.
  case SH::CPENTRYcall: {
    MCSymbol *Label = MI->getOperand(0).getMCSymbol();
    OutStreamer->emitLabel(Label);
    const MachineOperand &Function = MI->getOperand(1);
    const MCExpr *From = MCBinaryExpr::createAdd(
        MCSymbolRefExpr::create(MI->getOperand(2).getMCSymbol(), OutContext),
        MCConstantExpr::create(2, OutContext), OutContext);
    if (Function.getTargetFlags() == SH::S_PLT)
      From = MCBinaryExpr::createSub(
          From, MCSymbolRefExpr::create(Label, OutContext), OutContext);
    OutStreamer->emitValue(
        MCBinaryExpr::createSub(lowerSymbol(Function), From, OutContext), 4);
    return;
  }

  // The call and the tail call over a distance, with the label that the
  // literal counts from, and the tail call through a register.
  case SH::CALLrel:
  case SH::TAILrel:
    emit(MI->getOpcode() == SH::CALLrel ? SH::BSRF : SH::BRAF,
         {MCOperand::createReg(MI->getOperand(0).getReg())});
    OutStreamer->emitLabel(MI->getOperand(1).getMCSymbol());
    return;
  case SH::TAILJMP:
    emit(SH::JMP, {MCOperand::createReg(MI->getOperand(0).getReg())});
    return;

  case TargetOpcode::FENTRY_CALL:
    emitProfileCall();
    return;

  // The address of the global offset table: the address of a literal and
  // what the literal says.
  case SH::LOADGOT: {
    MCOperand R0 = MCOperand::createReg(SH::R0);
    MCOperand Dst = MCOperand::createReg(MI->getOperand(0).getReg());
    MCOperand Literal = label(MI->getOperand(1).getMCSymbol());
    emit(SH::MOVA, {Literal});
    emit(SH::MOVLpc, {Dst, Literal});
    emit(SH::ADDrr, {Dst, Dst, R0});
    return;
  }

  // Thread-local storage: the two sequences that the linker rewrites.
  case SH::TLSCALL: {
    MCOperand R0 = MCOperand::createReg(SH::R0);
    MCOperand R1 = MCOperand::createReg(SH::R1);
    MCOperand R4 = MCOperand::createReg(SH::R4);
    MCSymbol *Argument = OutContext.createTempSymbol();
    MCSymbol *Function = OutContext.createTempSymbol();
    MCSymbol *Behind = OutContext.createTempSymbol();
    emit(SH::MOVLpc, {R4, label(Argument)});
    emit(SH::MOVA, {label(Function)});
    emit(SH::MOVLpc, {R1, label(Function)});
    emit(SH::ADDrr, {R1, R1, R0});
    emit(SH::JSR, {R1});
    emit(SH::ADDrr, {R4, R4, MCOperand::createReg(SH::R12)});
    emit(SH::BRA, {label(Behind)});
    emit(SH::NOP);
    OutStreamer->emitCodeAlignment(Align(4), getSubtargetInfo());
    OutStreamer->emitLabel(Argument);
    OutStreamer->emitValue(lowerSymbol(MI->getOperand(1)), 4);
    OutStreamer->emitLabel(Function);
    OutStreamer->emitValue(
        MCSymbolRefExpr::create(GetExternalSymbolSymbol("__tls_get_addr"),
                                SH::S_PLT, OutContext),
        4);
    OutStreamer->emitLabel(Behind);
    return;
  }
  case SH::TLSIE: {
    MCOperand R0 = MCOperand::createReg(SH::R0);
    MCOperand Dst = MCOperand::createReg(MI->getOperand(0).getReg());
    MCSymbol *Offset = OutContext.createTempSymbol();
    MCSymbol *Behind = OutContext.createTempSymbol();
    emit(SH::MOVLpc, {R0, label(Offset)});
    emit(SH::STCGBR, {Dst});
    emit(SH::MOVLldr0, {R0, MCOperand::createReg(SH::R12)});
    emit(SH::BRA, {label(Behind)});
    emit(SH::ADDrr, {Dst, Dst, R0});
    OutStreamer->emitCodeAlignment(Align(4), getSubtargetInfo());
    OutStreamer->emitLabel(Offset);
    OutStreamer->emitValue(lowerSymbol(MI->getOperand(2)), 4);
    OutStreamer->emitLabel(Behind);
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
