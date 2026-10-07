//===-- SHAsmParser.cpp - SuperH assembly as GNU as reads it --------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The syntax is the one of GNU as, where the source is the first operand:
//
//   mov     #-16,r1         an immediate
//   mov.l   @(8,r15),r2     at a displacement from a register
//   mov.l   @r1+,r2         the register moves on behind the load
//   mov.l   r2,@-r15        and back in front of the store
//   mov.b   @(r0,r4),r1     at the sum of two registers
//   mov.l   @(4,gbr),r0     at a displacement from gbr
//   mov.l   .L1,r1          from a literal in the code
//   cmp/eq  r1,r2           a mnemonic with a slash
//
// A statement becomes a list of registers, expressions and the characters
// between them, and the table that tablegen makes of the instructions finds
// the one that has this shape.  The parser does not know an addressing mode:
// "@", "(", ")", "+", "-" and "#" are tokens, and a comma is nothing.
//
// A name is a register if there is one of that name, and "sp" is r15.  T is
// not one: it is a bit, which no instruction names.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/SHMCTargetDesc.h"
#include "TargetInfo/SHTargetInfo.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCParser/AsmLexer.h"
#include "llvm/MC/MCParser/MCParsedAsmOperand.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSection.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/MathExtras.h"

using namespace llvm;

#define DEBUG_TYPE "sh-asm-parser"

namespace {

class SHOperand : public MCParsedAsmOperand {
public:
  enum KindTy { Token, Register, Immediate };

  static std::unique_ptr<SHOperand> createToken(StringRef Str, SMLoc Loc) {
    auto Op = std::make_unique<SHOperand>(Token, Loc, Loc);
    Op->Tok = Str;
    return Op;
  }
  static std::unique_ptr<SHOperand> createReg(MCRegister Reg, SMLoc Start,
                                              SMLoc End) {
    auto Op = std::make_unique<SHOperand>(Register, Start, End);
    Op->Reg = Reg;
    return Op;
  }
  static std::unique_ptr<SHOperand> createImm(const MCExpr *Value, SMLoc Start,
                                              SMLoc End) {
    auto Op = std::make_unique<SHOperand>(Immediate, Start, End);
    Op->Imm = Value;
    return Op;
  }

  SHOperand(KindTy Kind, SMLoc Start, SMLoc End)
      : Kind(Kind), Start(Start), End(End) {}

  bool isToken() const override { return Kind == Token; }
  bool isReg() const override { return Kind == Register; }
  bool isImm() const override { return Kind == Immediate; }
  bool isMem() const override { return false; }

  StringRef getToken() const {
    assert(Kind == Token && "not a token");
    return Tok;
  }
  MCRegister getReg() const override {
    assert(Kind == Register && "not a register");
    return Reg;
  }
  const MCExpr *getImm() const {
    assert(Kind == Immediate && "not an expression");
    return Imm;
  }

  SMLoc getStartLoc() const override { return Start; }
  SMLoc getEndLoc() const override { return End; }

  void addRegOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "one register");
    Inst.addOperand(MCOperand::createReg(getReg()));
  }
  // A number stays a number.  It is one of 32 bits: 0xfffffff0 is -16.
  void addImmOperands(MCInst &Inst, unsigned N) const {
    assert(N == 1 && "one expression");
    const auto *Constant = dyn_cast<MCConstantExpr>(getImm());
    if (!Constant) {
      Inst.addOperand(MCOperand::createExpr(getImm()));
      return;
    }
    int64_t Value = Constant->getValue();
    if (isUInt<32>(Value))
      Value = SignExtend64<32>(Value);
    Inst.addOperand(MCOperand::createImm(Value));
  }

  void print(raw_ostream &OS, const MCAsmInfo &MAI) const override {
    switch (Kind) {
    case Token:
      OS << "'" << Tok << "'";
      break;
    case Register:
      OS << "<register " << Reg.id() << ">";
      break;
    case Immediate:
      MAI.printExpr(OS, *Imm);
      break;
    }
  }

private:
  KindTy Kind;
  SMLoc Start, End;
  StringRef Tok;
  MCRegister Reg;
  const MCExpr *Imm = nullptr;
};

class SHAsmParser : public MCTargetAsmParser {
public:
  SHAsmParser(const MCSubtargetInfo &STI, MCAsmParser &Parser,
              const MCInstrInfo &MII)
      : MCTargetAsmParser(STI, MII) {
    MCAsmParserExtension::Initialize(Parser);
    setAvailableFeatures(ComputeAvailableFeatures(STI.getFeatureBits()));
  }

  bool parseRegister(MCRegister &Reg, SMLoc &StartLoc, SMLoc &EndLoc) override;
  ParseStatus tryParseRegister(MCRegister &Reg, SMLoc &StartLoc,
                               SMLoc &EndLoc) override;
  bool parseInstruction(ParseInstructionInfo &Info, StringRef Name,
                        SMLoc NameLoc, OperandVector &Operands) override;
  bool matchAndEmitInstruction(SMLoc IDLoc, unsigned &Opcode,
                               OperandVector &Operands, MCStreamer &Out,
                               uint64_t &ErrorInfo,
                               bool MatchingInlineAsm) override;
  ParseStatus parseDirective(AsmToken DirectiveID) override;

#define GET_ASSEMBLER_HEADER
#include "SHGenAsmMatcher.inc"

private:
  /// The register of this name, if there is one that an instruction names.
  static MCRegister matchRegister(StringRef Name);
  bool parseExpressionOperand(OperandVector &Operands);
  bool parseData(unsigned Size, bool Aligned);
};

} // namespace

// From SHGenAsmMatcher.inc.
static MCRegister MatchRegisterName(StringRef Name);

MCRegister SHAsmParser::matchRegister(StringRef Name) {
  // The one other name that GNU as has for a register.
  if (Name.equals_insensitive("sp"))
    return SH::R15;
  MCRegister Reg = MatchRegisterName(Name.lower());
  return Reg == SH::T ? MCRegister() : Reg;
}

bool SHAsmParser::parseRegister(MCRegister &Reg, SMLoc &StartLoc,
                                SMLoc &EndLoc) {
  if (!tryParseRegister(Reg, StartLoc, EndLoc).isSuccess())
    return Error(StartLoc, "a register is expected here");
  return false;
}

ParseStatus SHAsmParser::tryParseRegister(MCRegister &Reg, SMLoc &StartLoc,
                                          SMLoc &EndLoc) {
  const AsmToken &Tok = getTok();
  StartLoc = Tok.getLoc();
  EndLoc = Tok.getEndLoc();
  if (Tok.isNot(AsmToken::Identifier))
    return ParseStatus::NoMatch;
  Reg = matchRegister(Tok.getIdentifier());
  if (!Reg)
    return ParseStatus::NoMatch;
  Lex();
  return ParseStatus::Success;
}

bool SHAsmParser::parseExpressionOperand(OperandVector &Operands) {
  SMLoc Start = getTok().getLoc(), End;
  const MCExpr *Value;
  if (getParser().parseExpression(Value, End))
    return true;
  Operands.push_back(SHOperand::createImm(Value, Start, End));
  return false;
}

bool SHAsmParser::parseInstruction(ParseInstructionInfo &Info, StringRef Name,
                                   SMLoc NameLoc, OperandVector &Operands) {
  // "cmp/eq", "bt/s": the name goes on behind a slash that follows it at
  // once.
  std::string Mnemonic = Name.lower();
  const char *NameEnd = NameLoc.getPointer() + Name.size();
  while (getTok().is(AsmToken::Slash) &&
         getTok().getLoc().getPointer() == NameEnd) {
    Lex();
    if (getTok().isNot(AsmToken::Identifier) ||
        getTok().getLoc().getPointer() != NameEnd + 1)
      return Error(getTok().getLoc(), "the mnemonic ends in a slash");
    StringRef Rest = getTok().getIdentifier();
    Mnemonic += '/';
    Mnemonic += Rest.lower();
    NameEnd += 1 + Rest.size();
    Lex();
  }
  Operands.push_back(
      SHOperand::createToken(getContext().allocateString(Mnemonic), NameLoc));

  // An "@" begins an address: a "(" or a "-" behind it belongs to that and
  // not to an expression.
  bool AfterAt = false;
  while (getTok().isNot(AsmToken::EndOfStatement)) {
    const AsmToken &Tok = getTok();
    SMLoc Loc = Tok.getLoc();
    auto Punctuation = [&](StringRef Str) {
      Operands.push_back(SHOperand::createToken(Str, Loc));
      Lex();
    };
    bool WasAfterAt = AfterAt;
    AfterAt = false;
    switch (Tok.getKind()) {
    case AsmToken::Comma:
      Lex();
      continue;
    case AsmToken::At:
      Punctuation("@");
      AfterAt = true;
      continue;
    case AsmToken::Hash:
      Punctuation("#");
      if (parseExpressionOperand(Operands))
        return true;
      continue;
    case AsmToken::RParen:
      Punctuation(")");
      continue;
    case AsmToken::Plus:
      Punctuation("+");
      continue;
    case AsmToken::LParen:
      if (WasAfterAt) {
        Punctuation("(");
        continue;
      }
      break;
    case AsmToken::Minus:
      if (WasAfterAt) {
        Punctuation("-");
        continue;
      }
      break;
    case AsmToken::Identifier:
      if (MCRegister Reg = matchRegister(Tok.getIdentifier())) {
        Operands.push_back(SHOperand::createReg(Reg, Loc, Tok.getEndLoc()));
        Lex();
        continue;
      }
      break;
    default:
      break;
    }
    if (parseExpressionOperand(Operands))
      return true;
  }
  return false;
}

bool SHAsmParser::matchAndEmitInstruction(SMLoc IDLoc, unsigned &Opcode,
                                          OperandVector &Operands,
                                          MCStreamer &Out, uint64_t &ErrorInfo,
                                          bool MatchingInlineAsm) {
  MCInst Inst;
  switch (MatchInstructionImpl(Operands, Inst, ErrorInfo, MatchingInlineAsm)) {
  case Match_Success:
    Inst.setLoc(IDLoc);
    Opcode = Inst.getOpcode();
    Out.emitInstruction(Inst, getSTI());
    return false;
  case Match_MnemonicFail:
    return Error(IDLoc, "no instruction of this name");
  case Match_InvalidOperand: {
    SMLoc Loc = IDLoc;
    if (ErrorInfo != ~0ULL) {
      if (ErrorInfo >= Operands.size())
        return Error(IDLoc, "the instruction has more operands than this");
      SMLoc OpLoc = Operands[ErrorInfo]->getStartLoc();
      if (OpLoc.isValid())
        Loc = OpLoc;
    }
    return Error(Loc, "the instruction has no form with this operand");
  }
  default:
    return Error(IDLoc, "the instruction cannot be assembled");
  }
}

/// A list of values of \p Size bytes each.  With \p Aligned the directive
/// is one of those that GNU as wants at a multiple of the size.  It refuses
/// the value at another address.  This does not, but the section gets the
/// alignment as it does there: what is put together of such sections by the
/// linker, like the tables of the kernel, depends on it.
///
/// GNU as also takes what follows a "#" behind the values as a comment,
/// which it does not behind an instruction.  The kernel has such a line.
bool SHAsmParser::parseData(unsigned Size, bool Aligned) {
  if (Aligned && Size > 1)
    getStreamer().getCurrentSectionOnly()->ensureMinAlignment(Align(Size));
  if (getTok().isNot(AsmToken::EndOfStatement) &&
      getTok().isNot(AsmToken::Hash))
    do {
      const MCExpr *Value;
      SMLoc Loc = getTok().getLoc();
      if (getParser().parseExpression(Value))
        return true;
      const auto *Constant = dyn_cast<MCConstantExpr>(Value);
      if (!Constant) {
        getStreamer().emitValue(Value, Size, Loc);
        continue;
      }
      int64_t Number = Constant->getValue();
      if (Size < 8 && !isUIntN(8 * Size, Number) && !isIntN(8 * Size, Number))
        return Error(Loc, "the value does not fit in " + Twine(Size) +
                              (Size == 1 ? " byte" : " bytes"));
      getStreamer().emitIntValue(Number, Size);
    } while (parseOptionalToken(AsmToken::Comma));
  if (getTok().is(AsmToken::Hash)) {
    getParser().eatToEndOfStatement();
    return false;
  }
  return parseEOL();
}

// The data directives, with what GNU as does for SuperH (see parseData()):
// a word is two bytes, ".ualong" and its kind are for data at any address.
// And the byte order, which is the one of the target or an error.
ParseStatus SHAsmParser::parseDirective(AsmToken DirectiveID) {
  StringRef Name = DirectiveID.getIdentifier();
  struct Data {
    unsigned Size;
    bool Aligned;
  };
  Data D = StringSwitch<Data>(Name.lower())
               .Case(".byte", {1, false})
               .Cases({".word", ".short", ".hword"}, {2, true})
               .Cases({".long", ".int"}, {4, true})
               .Case(".quad", {8, true})
               .Cases({".uaword", ".2byte"}, {2, false})
               .Cases({".ualong", ".4byte"}, {4, false})
               .Cases({".uaquad", ".8byte"}, {8, false})
               .Default({0, false});
  if (D.Size)
    return parseData(D.Size, D.Aligned);
  if (Name.equals_insensitive(".little") || Name.equals_insensitive(".big")) {
    bool IsLittle = getSTI().getTargetTriple().isLittleEndian();
    if (Name.equals_insensitive(".little") != IsLittle)
      return Error(DirectiveID.getLoc(),
                   "the byte order is not the one of the target");
    return parseEOL();
  }
  return ParseStatus::NoMatch;
}

extern "C" LLVM_ABI LLVM_EXTERNAL_VISIBILITY void LLVMInitializeSHAsmParser() {
  RegisterMCAsmParser<SHAsmParser> X(getTheSHTarget());
  RegisterMCAsmParser<SHAsmParser> Y(getTheSHebTarget());
}

#define GET_REGISTER_MATCHER
#define GET_MATCHER_IMPLEMENTATION
#include "SHGenAsmMatcher.inc"
