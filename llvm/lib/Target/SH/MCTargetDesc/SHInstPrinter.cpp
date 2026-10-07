//===-- SHInstPrinter.cpp - SuperH instructions as text -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SHInstPrinter.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

#define DEBUG_TYPE "asm-printer"

#include "SHGenAsmWriter.inc"

void SHInstPrinter::printRegName(raw_ostream &O, MCRegister Reg) {
  O << getRegisterName(Reg);
}

void SHInstPrinter::printInst(const MCInst *MI, uint64_t Address,
                              StringRef Annot, const MCSubtargetInfo &STI,
                              raw_ostream &O) {
  printInstruction(MI, Address, O);
  printAnnotation(O, Annot);
}

void SHInstPrinter::printOperand(const MCInst *MI, unsigned OpNo,
                                 raw_ostream &O) {
  const MCOperand &Op = MI->getOperand(OpNo);
  if (Op.isReg()) {
    printRegName(O, Op.getReg());
  } else if (Op.isImm()) {
    O << Op.getImm();
  } else {
    assert(Op.isExpr() && "unknown operand kind");
    MAI.printExpr(O, *Op.getExpr());
  }
}

// A place in the code is an expression where the compiler or the assembler
// made the instruction.  Where the disassembler did, it is a number: how
// far the place is from the instruction.  That is printed as an address
// where the address of the instruction is known and wanted, and as a
// distance from "." otherwise, which the assembler reads back.
void SHInstPrinter::printBranchTarget(const MCInst *MI, uint64_t Address,
                                      unsigned OpNo, raw_ostream &O) {
  const MCOperand &Op = MI->getOperand(OpNo);
  if (!Op.isImm())
    return printOperand(MI, OpNo, O);
  if (PrintBranchImmAsAddress)
    O << formatHex(Address + Op.getImm());
  else if (Op.getImm() < 0)
    O << ".-" << -Op.getImm();
  else
    O << ".+" << Op.getImm();
}

// "@(8,r15)", and "@r1" where there is no displacement.
void SHInstPrinter::printMemOperand(const MCInst *MI, unsigned OpNo,
                                    raw_ostream &O) {
  const MCOperand &Base = MI->getOperand(OpNo);
  const MCOperand &Disp = MI->getOperand(OpNo + 1);
  if (Disp.isImm() && Disp.getImm() == 0) {
    O << '@';
    printRegName(O, Base.getReg());
    return;
  }
  O << "@(";
  if (Disp.isImm())
    O << Disp.getImm();
  else
    MAI.printExpr(O, *Disp.getExpr());
  O << ',';
  printRegName(O, Base.getReg());
  O << ')';
}
