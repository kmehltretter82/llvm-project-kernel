//===-- SHInstrInfo.td - SuperH instruction definitions ----*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The instructions of SuperH.  Every instruction is 16 bits wide.  The
// assembly is the syntax of GNU as: the source comes first.  The first part
// of the file has what the code generator uses, the last part what only the
// assembler and the disassembler know.
//
// In an encoding "n" is the register in bits 11 to 8 and "m" the one in
// bits 7 to 4.  The operands that are encoded have those names, $rn and
// $rm, whatever they are to the instruction.
//
// Three things shape this file:
//
// - Most instructions have two operands and overwrite the second one.
// - There is one condition bit, T.  A comparison sets it, bt and bf branch
//   on it, movt copies it into a register.  A comparison and its user are
//   glued together, so nothing that changes T can come between them, and
//   nothing that is inserted later (copies, spill code, frame offsets) uses
//   an instruction that changes T.
// - An immediate has eight bits.  Anything else, a number or an address, is
//   loaded from a literal that sits in the code within 1020 bytes behind the
//   load.  MOVLpcrel stands for such a load until SHConstantIslands.cpp
//   has placed the literals.
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// Selection DAG nodes
//===----------------------------------------------------------------------===//

def SDT_SHCall : SDTypeProfile<0, -1, [SDTCisVT<0, i32>]>;
def SDT_SHCallSeqStart
    : SDCallSeqStart<[SDTCisVT<0, i32>, SDTCisVT<1, i32>]>;
def SDT_SHCallSeqEnd : SDCallSeqEnd<[SDTCisVT<0, i32>, SDTCisVT<1, i32>]>;
def SDT_SHCmp : SDTypeProfile<0, 2, [SDTCisVT<0, i32>, SDTCisSameAs<0, 1>]>;
def SDT_SHCmp1 : SDTypeProfile<0, 1, [SDTCisVT<0, i32>]>;
def SDT_SHBr : SDTypeProfile<0, 1, [SDTCisVT<0, OtherVT>]>;
def SDT_SHFCmp : SDTypeProfile<0, 2, [SDTCisFP<0>, SDTCisSameAs<0, 1>]>;
def SDT_SHSelect
    : SDTypeProfile<1, 2, [SDTCisSameAs<0, 1>, SDTCisSameAs<1, 2>]>;
def SDT_SHMovT : SDTypeProfile<1, 0, [SDTCisVT<0, i32>]>;
def SDT_SHLoadAddr : SDTypeProfile<1, 1, [SDTCisVT<0, i32>, SDTCisPtrTy<1>]>;
def SDT_SHBlockCopy
    : SDTypeProfile<0, 4, [SDTCisVT<0, i32>, SDTCisVT<1, i32>,
                           SDTCisVT<2, i32>, SDTCisVT<3, i32>]>;

def SHcall : SDNode<"SHISD::CALL", SDT_SHCall,
                    [SDNPHasChain, SDNPOptInGlue, SDNPOutGlue, SDNPVariadic]>;
def SHret : SDNode<"SHISD::RET", SDTNone,
                   [SDNPHasChain, SDNPOptInGlue, SDNPVariadic]>;
// A call that does not come back: the function that is called returns to
// the caller of this one.
def SHtailcall : SDNode<"SHISD::TAILCALL", SDT_SHCall,
                        [SDNPHasChain, SDNPOptInGlue, SDNPVariadic]>;
// The distance from a call to the function, and the call and the tail call
// over that distance.  The second operand of each is the label behind the
// instruction that calls, which the distance is counted from.
def SDT_SHCallDist
    : SDTypeProfile<1, 2, [SDTCisVT<0, i32>, SDTCisPtrTy<1>, SDTCisPtrTy<2>]>;
def SDT_SHCallRel
    : SDTypeProfile<0, -1, [SDTCisVT<0, i32>, SDTCisPtrTy<1>]>;
def SHcalldist : SDNode<"SHISD::CALLDIST", SDT_SHCallDist>;
def SHcallrel : SDNode<"SHISD::CALLREL", SDT_SHCallRel,
                       [SDNPHasChain, SDNPOptInGlue, SDNPOutGlue,
                        SDNPVariadic]>;
def SHtailcallrel : SDNode<"SHISD::TAILCALLREL", SDT_SHCallRel,
                           [SDNPHasChain, SDNPOptInGlue, SDNPVariadic]>;
def SHcallseq_start : SDNode<"ISD::CALLSEQ_START", SDT_SHCallSeqStart,
                             [SDNPHasChain, SDNPOutGlue]>;
def SHcallseq_end : SDNode<"ISD::CALLSEQ_END", SDT_SHCallSeqEnd,
                           [SDNPHasChain, SDNPOptInGlue, SDNPOutGlue]>;

// The comparisons.  Each sets T to "first operand <relation> second".
def SHcmpeq : SDNode<"SHISD::CMPEQ", SDT_SHCmp, [SDNPOutGlue]>;
def SHcmpge : SDNode<"SHISD::CMPGE", SDT_SHCmp, [SDNPOutGlue]>;
def SHcmpgt : SDNode<"SHISD::CMPGT", SDT_SHCmp, [SDNPOutGlue]>;
def SHcmphi : SDNode<"SHISD::CMPHI", SDT_SHCmp, [SDNPOutGlue]>;
def SHcmphs : SDNode<"SHISD::CMPHS", SDT_SHCmp, [SDNPOutGlue]>;
// T = ((first & second) == 0)
def SHtst : SDNode<"SHISD::TST", SDT_SHCmp, [SDNPOutGlue]>;
// T = (operand > 0) and T = (operand >= 0)
def SHcmppl : SDNode<"SHISD::CMPPL", SDT_SHCmp1, [SDNPOutGlue]>;
def SHcmppz : SDNode<"SHISD::CMPPZ", SDT_SHCmp1, [SDNPOutGlue]>;
// The two comparisons of the floating point unit.  Both are false if an
// operand is not a number.
def SHfcmpeq : SDNode<"SHISD::FCMPEQ", SDT_SHFCmp, [SDNPOutGlue]>;
def SHfcmpgt : SDNode<"SHISD::FCMPGT", SDT_SHFCmp, [SDNPOutGlue]>;

// What uses T: a branch if it is set or clear, a choice between two values
// (the first if it is set), and its value or the opposite as a number.
def SHbrt : SDNode<"SHISD::BRT", SDT_SHBr, [SDNPHasChain, SDNPInGlue]>;
def SHbrf : SDNode<"SHISD::BRF", SDT_SHBr, [SDNPHasChain, SDNPInGlue]>;
def SHselect : SDNode<"SHISD::SELECT", SDT_SHSelect, [SDNPInGlue]>;
def SHmovt : SDNode<"SHISD::MOVT", SDT_SHMovT, [SDNPInGlue]>;
def SHmovrt : SDNode<"SHISD::MOVRT", SDT_SHMovT, [SDNPInGlue]>;

// The address of a global, a function, a block, a jump table or a constant
// pool entry, which is loaded from a literal.
def SHloadaddr : SDNode<"SHISD::LOADADDR", SDT_SHLoadAddr>;

// A copy of a block of memory without a call: to, from, the number of bytes
// and what both addresses are aligned to.  It is for a structure that is
// passed by value, whose copy stands between the arguments of a call, where
// a call of memcpy cannot be.
def SHblockcopy : SDNode<"SHISD::BLOCKCOPY", SDT_SHBlockCopy,
                         [SDNPHasChain, SDNPMayLoad, SDNPMayStore]>;

// Thread-local storage: the call of __tls_get_addr() and the offset of a
// variable from the global offset table.  The first operand of both is the
// address of that table.
def SDT_SHTLSCall : SDTypeProfile<0, 2, [SDTCisVT<0, i32>, SDTCisPtrTy<1>]>;
def SDT_SHTLSIE
    : SDTypeProfile<1, 2, [SDTCisVT<0, i32>, SDTCisVT<1, i32>, SDTCisPtrTy<2>]>;
def SHtlscall : SDNode<"SHISD::TLSCALL", SDT_SHTLSCall,
                       [SDNPHasChain, SDNPOutGlue, SDNPVariadic]>;
def SHtlsie : SDNode<"SHISD::TLSIE", SDT_SHTLSIE>;

//===----------------------------------------------------------------------===//
// Operands and patterns
//===----------------------------------------------------------------------===//

def HasDynShift : Predicate<"Subtarget->hasDynShift()">;

// The assembler takes any expression where an instruction has a number and
// checks the range when it knows the value.
class SHImm : Operand<i32> {
  let ParserMatchClass = ImmAsmOperand;
}

def simm8 : SHImm, ImmLeaf<i32, [{ return isInt<8>(Imm); }]> {
  let EncoderMethod = "getImmOpValue<8, true>";
  let DecoderMethod = "decodeSImm<8>";
}
// The eight bits of the logical instructions, which are not extended.
def uimm8 : SHImm, ImmLeaf<i32, [{ return isUInt<8>(Imm); }]> {
  let EncoderMethod = "getImmOpValue<8, false>";
  let DecoderMethod = "decodeUImm<8>";
}

// The target of bt and bf: a signed number of words from four bytes behind
// the branch, in eight bits.  bra and bsr have twelve.
def brtarget : Operand<OtherVT> {
  let ParserMatchClass = ImmAsmOperand;
  let EncoderMethod = "getBranchTargetOpValue<8>";
  let DecoderMethod = "decodeBranchTarget<8>";
  let PrintMethod = "printBranchTarget";
  let OperandType = "OPERAND_PCREL";
}
def brtarget12 : Operand<OtherVT> {
  let ParserMatchClass = ImmAsmOperand;
  let EncoderMethod = "getBranchTargetOpValue<12>";
  let DecoderMethod = "decodeBranchTarget<12>";
  let PrintMethod = "printBranchTarget";
  let OperandType = "OPERAND_PCREL";
}

// A label of a literal or of a place in the code.  In "mov.l label,Rn" and
// "mova label,r0" it is a number of long words from the address of the
// instruction, rounded down to a multiple of four, plus four.  In "mov.w
// label,Rn" it is a number of words from four bytes behind the instruction.
def labelop : Operand<i32> {
  let ParserMatchClass = ImmAsmOperand;
  let EncoderMethod = "getLiteralOpValue<4>";
  let DecoderMethod = "decodeLiteral<4>";
  let PrintMethod = "printBranchTarget";
  let OperandType = "OPERAND_PCREL";
}
def labelopw : Operand<i32> {
  let ParserMatchClass = ImmAsmOperand;
  let EncoderMethod = "getLiteralOpValue<2>";
  let DecoderMethod = "decodeLiteral<2>";
  let PrintMethod = "printBranchTarget";
  let OperandType = "OPERAND_PCREL";
}

// A displacement in bytes that the instruction has as a number of bytes,
// words or long words in four or eight bits.
class SHDisp<int width, int scale> : SHImm {
  let EncoderMethod = "getDispOpValue<" # width # ", " # scale # ">";
  let DecoderMethod = "decodeDisp<" # width # ", " # scale # ">";
}
def disp4x1 : SHDisp<4, 1>;
def disp4x2 : SHDisp<4, 2>;
def disp4x4 : SHDisp<4, 4>;
def disp8x1 : SHDisp<8, 1>;
def disp8x2 : SHDisp<8, 2>;
def disp8x4 : SHDisp<8, 4>;

// "@(disp,Rn)": a register, or a frame index until the frame is laid out,
// and a displacement.  A long word can be reached with a displacement of up
// to 60, a byte or a word only with none.
def memop : Operand<i32> {
  let PrintMethod = "printMemOperand";
  let MIOperandInfo = (ops GPR:$base, i32imm:$disp);
}

def addrl : ComplexPattern<i32, 2, "SelectAddrL", [frameindex]>;
def addrbw : ComplexPattern<i32, 2, "SelectAddrBW", [frameindex]>;
def addrbdisp : ComplexPattern<i32, 2, "SelectAddrBDisp", [add]>;
def addrwdisp : ComplexPattern<i32, 2, "SelectAddrWDisp", [add]>;
def addrfi : ComplexPattern<i32, 2, "SelectAddrFI", [frameindex, add]>;

// The amount of a shift to the right, which shad and shld take as a
// negative number.
def neg_imm : SDNodeXForm<imm, [{
  return CurDAG->getSignedTargetConstant(-N->getSExtValue(), SDLoc(N),
                                         MVT::i32);
}]>;
def shamt : ImmLeaf<i32, [{ return Imm >= 1 && Imm <= 31; }], neg_imm>;

//===----------------------------------------------------------------------===//
// Instruction classes
//===----------------------------------------------------------------------===//

class SHInst<dag outs, dag ins, string asmstr, list<dag> pattern>
    : Instruction {
  field bits<16> Inst;
  field bits<16> SoftFail = 0;
  let Namespace = "SH";
  let DecoderNamespace = "SH";
  let OutOperandList = outs;
  let InOperandList = ins;
  let AsmString = asmstr;
  let Pattern = pattern;
  let Size = 2;
}

// The encodings.  Each of these is the second parent of an instruction and
// says where its operands go.
class Enc0<bits<16> value> {
  bits<16> Inst = value;
}
// xxxx nnnn xxxx xxxx
class EncN<bits<4> hi, bits<8> lo> {
  bits<4> rn;
  bits<16> Inst;
  let Inst{15 - 12} = hi;
  let Inst{11 - 8} = rn;
  let Inst{7 - 0} = lo;
}
// xxxx mmmm xxxx xxxx
class EncM<bits<4> hi, bits<8> lo> {
  bits<4> rm;
  bits<16> Inst;
  let Inst{15 - 12} = hi;
  let Inst{11 - 8} = rm;
  let Inst{7 - 0} = lo;
}
// xxxx nnnn mmmm xxxx
class EncNM<bits<4> hi, bits<4> lo> {
  bits<4> rn;
  bits<4> rm;
  bits<16> Inst;
  let Inst{15 - 12} = hi;
  let Inst{11 - 8} = rn;
  let Inst{7 - 4} = rm;
  let Inst{3 - 0} = lo;
}
// xxxx nnnn iiii iiii
class EncNI<bits<4> hi> {
  bits<4> rn;
  bits<8> imm;
  bits<16> Inst;
  let Inst{15 - 12} = hi;
  let Inst{11 - 8} = rn;
  let Inst{7 - 0} = imm;
}
// xxxx xxxx iiii iiii
class EncI<bits<8> hi> {
  bits<8> imm;
  bits<16> Inst;
  let Inst{15 - 8} = hi;
  let Inst{7 - 0} = imm;
}
// xxxx xxxx dddd dddd and xxxx dddd dddd dddd: a place in the code.
class EncT8<bits<8> hi> {
  bits<8> target;
  bits<16> Inst;
  let Inst{15 - 8} = hi;
  let Inst{7 - 0} = target;
}
class EncT12<bits<4> hi> {
  bits<12> target;
  bits<16> Inst;
  let Inst{15 - 12} = hi;
  let Inst{11 - 0} = target;
}
// xxxx nnnn dddd dddd: a register and a place in the code.
class EncNT8<bits<4> hi> {
  bits<4> rn;
  bits<8> target;
  bits<16> Inst;
  let Inst{15 - 12} = hi;
  let Inst{11 - 8} = rn;
  let Inst{7 - 0} = target;
}
// xxxx nnnn mmmm dddd
class EncNMD<bits<4> hi> {
  bits<4> rn;
  bits<4> rm;
  bits<4> disp;
  bits<16> Inst;
  let Inst{15 - 12} = hi;
  let Inst{11 - 8} = rn;
  let Inst{7 - 4} = rm;
  let Inst{3 - 0} = disp;
}
// xxxx xxxx mmmm dddd and xxxx xxxx nnnn dddd
class EncMD<bits<8> hi> {
  bits<4> rm;
  bits<4> disp;
  bits<16> Inst;
  let Inst{15 - 8} = hi;
  let Inst{7 - 4} = rm;
  let Inst{3 - 0} = disp;
}
class EncND<bits<8> hi> {
  bits<4> rn;
  bits<4> disp;
  bits<16> Inst;
  let Inst{15 - 8} = hi;
  let Inst{7 - 4} = rn;
  let Inst{3 - 0} = disp;
}
// xxxx xxxx dddd dddd: a displacement from gbr.
class EncD8<bits<8> hi> {
  bits<8> disp;
  bits<16> Inst;
  let Inst{15 - 8} = hi;
  let Inst{7 - 0} = disp;
}

// What only the code generator has: an instruction with an address that is a
// register and a displacement until the frame is laid out, or one that names
// r15.  The assembler and the disassembler have the general form.
class SHCodeGenOnly {
  bit isCodeGenOnly = 1;
}

class SHPseudo<dag outs, dag ins, list<dag> pattern>
    : SHInst<outs, ins, "", pattern> {
  let isPseudo = 1;
  let isCodeGenOnly = 1;
}

// An instruction without a pattern.  All that it does is in its operands,
// in Uses and Defs and in mayLoad and mayStore.  That has to be said:
// without a pattern to look at, tablegen assumes that an instruction has
// effects that nobody knows, and then nothing may move or remove it.
class SHPlain<dag outs, dag ins, string asmstr>
    : SHInst<outs, ins, asmstr, []> {
  let hasSideEffects = 0;
}

// "op Rm,Rn": Rn = Rn op Rm.
class SHBinOp<bits<4> hi, bits<4> lo, string mnemonic, SDPatternOperator node>
    : SHInst<(outs GPR:$rn), (ins GPR:$src1, GPR:$rm),
             mnemonic # "\t$rm,$rn",
             [(set GPR:$rn, (node GPR:$src1, GPR:$rm))]>,
      EncNM<hi, lo> {
  let Constraints = "$src1 = $rn";
}

// "op Rm,Rn": Rn = op Rm.
class SHUnOp<bits<4> hi, bits<4> lo, string mnemonic, dag pattern>
    : SHInst<(outs GPR:$rn), (ins GPR:$rm), mnemonic # "\t$rm,$rn",
             [(set GPR:$rn, pattern)]>,
      EncNM<hi, lo>;

// "op Rn": Rn = op Rn.
class SHShift<bits<8> lo, string mnemonic, SDPatternOperator node, int amount>
    : SHInst<(outs GPR:$rn), (ins GPR:$src), mnemonic # "\t$rn",
             [(set GPR:$rn, (node GPR:$src, (i32 amount)))]>,
      EncN<0b0100, lo> {
  let Constraints = "$src = $rn";
}

//===----------------------------------------------------------------------===//
// Moves
//===----------------------------------------------------------------------===//

let isMoveReg = 1 in
def MOVrr : SHPlain<(outs GPR:$rn), (ins GPR:$rm), "mov\t$rm,$rn">,
            EncNM<0b0110, 0b0011>;

let isReMaterializable = 1, isAsCheapAsAMove = 1, isMoveImm = 1 in
def MOVI : SHInst<(outs GPR:$rn), (ins simm8:$imm), "mov\t#$imm,$rn",
                  [(set GPR:$rn, simm8:$imm)]>,
           EncNI<0b1110>;

// A number that is one instruction away from an immediate: 240 is
// "mov #-16,Rn; extu.b Rn,Rn" and 4096 is "mov #16,Rn; shll8 Rn" (see
// SH::classifyTwoInsnImm).  That is two bytes less than a literal and no
// load.  It is one instruction until the registers are allocated, so that it
// can be made again where it is needed instead of being kept on the stack.
def imm2insn : ImmLeaf<i32, [{
  int64_t First;
  return SH::classifyTwoInsnImm(Imm, First) != SH::TwoInsnImm::None;
}]>;
let isReMaterializable = 1, isAsCheapAsAMove = 1, isMoveImm = 1, Size = 4,
    hasSideEffects = 0 in
def MOVI2 : SHPseudo<(outs GPR:$dst), (ins i32imm:$imm),
                     [(set GPR:$dst, imm2insn:$imm)]>;

// A number or an address that is loaded from a literal.  The operand is the
// number, the global, the symbol, the block address, the jump table or the
// constant pool entry.
let isReMaterializable = 1 in
def MOVLpcrel : SHPseudo<(outs GPR:$dst), (ins i32imm:$src), []>;

// What the pseudo becomes: "mov.l .L1,Rn" with the label of the literal.
let mayLoad = 1 in
def MOVLpc : SHPlain<(outs GPR:$rn), (ins labelop:$target),
                    "mov.l\t$target,$rn">,
             EncNT8<0b1101>;

// The address of the global offset table, which position independent code
// finds everything through:
//
//   mova .L,r0; mov.l .L,Rn; add r0,Rn
//
// The literal .L has the distance from itself to the table.  The operand is
// the symbol of the table until the literal is placed, and the label of the
// literal from then on.
let Defs = [R0], Size = 6, hasSideEffects = 0 in
def LOADGOT : SHPseudo<(outs GPR:$dst), (ins i32imm:$literal), []>;

// "mova .L,r0": the address of a literal.
let Defs = [R0] in
def MOVA : SHPlain<(outs), (ins labelop:$target), "mova\t$target,r0">,
           EncT8<0b11000111>;

def : Pat<(SHloadaddr tglobaladdr:$a), (MOVLpcrel tglobaladdr:$a)>;
def : Pat<(SHloadaddr tglobaltlsaddr:$a), (MOVLpcrel tglobaltlsaddr:$a)>;
def : Pat<(SHloadaddr texternalsym:$a), (MOVLpcrel texternalsym:$a)>;
def : Pat<(SHloadaddr tblockaddress:$a), (MOVLpcrel tblockaddress:$a)>;
def : Pat<(SHloadaddr tjumptable:$a), (MOVLpcrel tjumptable:$a)>;
def : Pat<(SHloadaddr tconstpool:$a), (MOVLpcrel tconstpool:$a)>;
def : Pat<(i32 imm:$v), (MOVLpcrel imm:$v)>;

// The address of a stack slot.  It becomes "mov r15,Rn" and an addition
// when the frame is laid out.
def LEAFI : SHPseudo<(outs GPR:$dst), (ins memop:$addr),
                     [(set GPR:$dst, addrfi:$addr)]>;

//===----------------------------------------------------------------------===//
// Loads and stores
//===----------------------------------------------------------------------===//

// The address is one operand of the code generator's instructions, which
// can be a frame index.  SHAsmPrinter.cpp makes the instructions below of
// them: "@Rm" where the displacement is zero and "@(disp,Rm)" otherwise.
let canFoldAsLoad = 1 in {
def MOVLld : SHInst<(outs GPR:$dst), (ins memop:$addr), "mov.l\t$addr,$dst",
                    [(set GPR:$dst, (load addrl:$addr))]>,
             SHCodeGenOnly;
// A word or a byte is sign-extended when it is loaded.
def MOVWld : SHInst<(outs GPR:$dst), (ins memop:$addr), "mov.w\t$addr,$dst",
                    [(set GPR:$dst, (sextloadi16 addrbw:$addr))]>,
             SHCodeGenOnly;
def MOVBld : SHInst<(outs GPR:$dst), (ins memop:$addr), "mov.b\t$addr,$dst",
                    [(set GPR:$dst, (sextloadi8 addrbw:$addr))]>,
             SHCodeGenOnly;
}

def MOVLst : SHInst<(outs), (ins GPR:$src, memop:$addr), "mov.l\t$src,$addr",
                    [(store GPR:$src, addrl:$addr)]>,
             SHCodeGenOnly;
def MOVWst : SHInst<(outs), (ins GPR:$src, memop:$addr), "mov.w\t$src,$addr",
                    [(truncstorei16 GPR:$src, addrbw:$addr)]>,
             SHCodeGenOnly;
def MOVBst : SHInst<(outs), (ins GPR:$src, memop:$addr), "mov.b\t$src,$addr",
                    [(truncstorei8 GPR:$src, addrbw:$addr)]>,
             SHCodeGenOnly;

// What they become.  The register that is loaded or stored is the first
// operand, the address follows.
let mayLoad = 1 in {
def MOVLind : SHPlain<(outs GPR:$rn), (ins GPR:$rm), "mov.l\t@$rm,$rn">,
              EncNM<0b0110, 0b0010>;
def MOVWind : SHPlain<(outs GPR:$rn), (ins GPR:$rm), "mov.w\t@$rm,$rn">,
              EncNM<0b0110, 0b0001>;
def MOVBind : SHPlain<(outs GPR:$rn), (ins GPR:$rm), "mov.b\t@$rm,$rn">,
              EncNM<0b0110, 0b0000>;
def MOVLdisp : SHPlain<(outs GPR:$rn), (ins GPR:$rm, disp4x4:$disp),
                       "mov.l\t@($disp,$rm),$rn">,
               EncNMD<0b0101>;
}
let mayStore = 1 in {
def MOVLsti : SHPlain<(outs), (ins GPR:$rm, GPR:$rn), "mov.l\t$rm,@$rn">,
              EncNM<0b0010, 0b0010>;
def MOVWsti : SHPlain<(outs), (ins GPR:$rm, GPR:$rn), "mov.w\t$rm,@$rn">,
              EncNM<0b0010, 0b0001>;
def MOVBsti : SHPlain<(outs), (ins GPR:$rm, GPR:$rn), "mov.b\t$rm,@$rn">,
              EncNM<0b0010, 0b0000>;
def MOVLstd : SHPlain<(outs), (ins GPR:$rm, GPR:$rn, disp4x4:$disp),
                      "mov.l\t$rm,@($disp,$rn)">,
              EncNMD<0b0001>;
}

// A byte or a word at a displacement from a register, which only r0 can be
// loaded with and stored from.  That is one instruction where the address
// would need two more, and a copy if the value is not wanted in r0.
let AddedComplexity = 5 in {
let Defs = [R0] in {
def MOVBldr0 : SHInst<(outs), (ins memop:$addr), "mov.b\t$addr,r0",
                      [(set R0, (sextloadi8 addrbdisp:$addr))]>,
               SHCodeGenOnly;
def MOVWldr0 : SHInst<(outs), (ins memop:$addr), "mov.w\t$addr,r0",
                      [(set R0, (sextloadi16 addrwdisp:$addr))]>,
               SHCodeGenOnly;
}
let Uses = [R0] in {
def MOVBstr0 : SHInst<(outs), (ins memop:$addr), "mov.b\tr0,$addr",
                      [(truncstorei8 R0, addrbdisp:$addr)]>,
               SHCodeGenOnly;
def MOVWstr0 : SHInst<(outs), (ins memop:$addr), "mov.w\tr0,$addr",
                      [(truncstorei16 R0, addrwdisp:$addr)]>,
               SHCodeGenOnly;
}
def : Pat<(extloadi16 addrwdisp:$addr), (MOVWldr0 addrwdisp:$addr)>;
def : Pat<(extloadi8 addrbdisp:$addr), (MOVBldr0 addrbdisp:$addr)>;
def : Pat<(extloadi1 addrbdisp:$addr), (MOVBldr0 addrbdisp:$addr)>;
}

def : Pat<(extloadi16 addrbw:$addr), (MOVWld addrbw:$addr)>;
def : Pat<(extloadi8 addrbw:$addr), (MOVBld addrbw:$addr)>;
def : Pat<(extloadi1 addrbw:$addr), (MOVBld addrbw:$addr)>;

// The instructions that the four above become.
let Defs = [R0], mayLoad = 1 in {
def MOVBlddisp : SHPlain<(outs), (ins GPR:$rm, disp4x1:$disp),
                         "mov.b\t@($disp,$rm),r0">,
                 EncMD<0b10000100>;
def MOVWlddisp : SHPlain<(outs), (ins GPR:$rm, disp4x2:$disp),
                         "mov.w\t@($disp,$rm),r0">,
                 EncMD<0b10000101>;
}
let Uses = [R0], mayStore = 1 in {
def MOVBstdisp : SHPlain<(outs), (ins GPR:$rn, disp4x1:$disp),
                         "mov.b\tr0,@($disp,$rn)">,
                 EncND<0b10000000>;
def MOVWstdisp : SHPlain<(outs), (ins GPR:$rn, disp4x2:$disp),
                         "mov.w\tr0,@($disp,$rn)">,
                 EncND<0b10000001>;
}

// "mov.l @(r0,Rm),Rn": the address is the sum of r0 and a register.  Only
// the sequence for thread-local storage uses it so far.
let Uses = [R0], mayLoad = 1 in
def MOVLldr0 : SHPlain<(outs GPR:$rn), (ins GPR:$rm),
                       "mov.l\t@(r0,$rm),$rn">,
               EncNM<0b0000, 0b1110>;

// Push and pop, for the registers that a function saves.  They are the
// instructions with "@-Rn" and "@Rm+" below, with r15 for the register.
let Uses = [R15], Defs = [R15] in {
let mayStore = 1 in
def PUSH : SHPlain<(outs), (ins GPR:$rm), "mov.l\t$rm,@-r15">,
           EncM<0b0010, 0b00000110>, SHCodeGenOnly {
  let Inst{11 - 8} = 0b1111;
  let Inst{7 - 4} = rm;
  let Inst{3 - 0} = 0b0110;
}
let mayLoad = 1 in
def POP : SHPlain<(outs GPR:$rn), (ins), "mov.l\t@r15+,$rn">,
          EncN<0b0110, 0b11110110>, SHCodeGenOnly;
let Uses = [R15, PR], mayStore = 1 in
def PUSHPR : SHPlain<(outs), (ins), "sts.l\tpr,@-r15">, Enc0<0x4f22>,
             SHCodeGenOnly;
let Defs = [R15, PR], mayLoad = 1 in
def POPPR : SHPlain<(outs), (ins), "lds.l\t@r15+,pr">, Enc0<0x4f26>,
            SHCodeGenOnly;
}

// The system registers.
let Uses = [PR] in
def STSPR : SHPlain<(outs GPR:$rn), (ins), "sts\tpr,$rn">,
            EncN<0b0000, 0b00101010>;
let Defs = [PR] in
def LDSPR : SHPlain<(outs), (ins GPR:$rm), "lds\t$rm,pr">,
            EncM<0b0100, 0b00101010>;
let Uses = [MACL] in
def STSMACL : SHPlain<(outs GPR:$rn), (ins), "sts\tmacl,$rn">,
              EncN<0b0000, 0b00011010>;
let Uses = [MACH] in
def STSMACH : SHPlain<(outs GPR:$rn), (ins), "sts\tmach,$rn">,
              EncN<0b0000, 0b00001010>;
let Defs = [MACL] in
def LDSMACL : SHPlain<(outs), (ins GPR:$rm), "lds\t$rm,macl">,
              EncM<0b0100, 0b00011010>;
let Defs = [MACH] in
def LDSMACH : SHPlain<(outs), (ins GPR:$rm), "lds\t$rm,mach">,
              EncM<0b0100, 0b00001010>;
let Uses = [GBR] in
def STCGBR : SHPlain<(outs GPR:$rn), (ins), "stc\tgbr,$rn">,
             EncN<0b0000, 0b00010010>;
let Defs = [GBR] in
def LDCGBR : SHPlain<(outs), (ins GPR:$rm), "ldc\t$rm,gbr">,
             EncM<0b0100, 0b00011110>;

//===----------------------------------------------------------------------===//
// Arithmetic and logic
//===----------------------------------------------------------------------===//

let isCommutable = 1 in {
def ADDrr : SHBinOp<0b0011, 0b1100, "add", add>;
def ANDrr : SHBinOp<0b0010, 0b1001, "and", and>;
def ORrr : SHBinOp<0b0010, 0b1011, "or", or>;
def XORrr : SHBinOp<0b0010, 0b1010, "xor", xor>;
}
def SUBrr : SHBinOp<0b0011, 0b1000, "sub", sub>;

let Constraints = "$src = $rn" in
def ADDri : SHInst<(outs GPR:$rn), (ins GPR:$src, simm8:$imm),
                   "add\t#$imm,$rn",
                   [(set GPR:$rn, (add GPR:$src, simm8:$imm))]>,
            EncNI<0b0111>;

def NEG : SHUnOp<0b0110, 0b1011, "neg", (ineg GPR:$rm)>;
def NOT : SHUnOp<0b0110, 0b0111, "not", (not GPR:$rm)>;
def EXTUB : SHUnOp<0b0110, 0b1100, "extu.b", (and GPR:$rm, 255)>;
def EXTUW : SHUnOp<0b0110, 0b1101, "extu.w", (and GPR:$rm, 65535)>;
def EXTSB : SHUnOp<0b0110, 0b1110, "exts.b", (sext_inreg GPR:$rm, i8)>;
def EXTSW : SHUnOp<0b0110, 0b1111, "exts.w", (sext_inreg GPR:$rm, i16)>;
// The two halves change places, or the two low bytes do.
def SWAPW : SHUnOp<0b0110, 0b1001, "swap.w", (rotl GPR:$rm, (i32 16))>;
def SWAPB : SHPlain<(outs GPR:$rn), (ins GPR:$rm), "swap.b\t$rm,$rn">,
            EncNM<0b0110, 0b1000>;

def : Pat<(bswap GPR:$src), (SWAPB (SWAPW (SWAPB GPR:$src)))>;

// With the carry in T: the upper half of a sum or a difference of 64 bits
// adds the carry of the lower half, which adds none.  The lower half is
// "clrt" and the same instruction.  The two are glued, and nothing that is
// inserted between them later changes T (see the head of this file).
let Constraints = "$src1 = $rn", Uses = [T], Defs = [T] in {
def ADDC : SHInst<(outs GPR:$rn), (ins GPR:$src1, GPR:$rm),
                  "addc\t$rm,$rn",
                  [(set GPR:$rn, (adde GPR:$src1, GPR:$rm))]>,
           EncNM<0b0011, 0b1110>;
def SUBC : SHInst<(outs GPR:$rn), (ins GPR:$src1, GPR:$rm),
                  "subc\t$rm,$rn",
                  [(set GPR:$rn, (sube GPR:$src1, GPR:$rm))]>,
           EncNM<0b0011, 0b1010>;
}
let Constraints = "$src1 = $dst", Defs = [T], Size = 4 in {
def ADDC0 : SHPseudo<(outs GPR:$dst), (ins GPR:$src1, GPR:$src2),
                     [(set GPR:$dst, (addc GPR:$src1, GPR:$src2))]>;
def SUBC0 : SHPseudo<(outs GPR:$dst), (ins GPR:$src1, GPR:$src2),
                     [(set GPR:$dst, (subc GPR:$src1, GPR:$src2))]>;
}
// 0 - Rm - T: the halves of a 64-bit number with the other sign.
let Uses = [T], Defs = [T] in
def NEGC : SHInst<(outs GPR:$rn), (ins GPR:$rm), "negc\t$rm,$rn",
                  [(set GPR:$rn, (sube (i32 0), GPR:$rm))]>,
           EncNM<0b0110, 0b1010>;
let Defs = [T], Size = 4 in
def NEGC0 : SHPseudo<(outs GPR:$dst), (ins GPR:$src),
                     [(set GPR:$dst, (subc (i32 0), GPR:$src))]>;
let Defs = [T] in {
def CLRT : SHPlain<(outs), (ins), "clrt">, Enc0<0x0008>;
def SETT : SHPlain<(outs), (ins), "sett">, Enc0<0x0018>;
}

// A product goes to MACL, or to MACH and MACL if it has 64 bits.
let Defs = [MACL] in
def MULL : SHPlain<(outs), (ins GPR:$rn, GPR:$rm), "mul.l\t$rm,$rn">,
           EncNM<0b0000, 0b0111>;
let Defs = [MACH, MACL] in {
def DMULU : SHPlain<(outs), (ins GPR:$rn, GPR:$rm), "dmulu.l\t$rm,$rn">,
            EncNM<0b0011, 0b0101>;
def DMULS : SHPlain<(outs), (ins GPR:$rn, GPR:$rm), "dmuls.l\t$rm,$rn">,
            EncNM<0b0011, 0b1101>;
}

// A multiplication with the result in a register: the instruction above
// and a copy from MACL or MACH.
let isCommutable = 1 in {
let Defs = [MACL] in
def MUL32 : SHPseudo<(outs GPR:$dst), (ins GPR:$a, GPR:$b),
                     [(set GPR:$dst, (mul GPR:$a, GPR:$b))]>;
let Defs = [MACH, MACL] in {
def MULHU32 : SHPseudo<(outs GPR:$dst), (ins GPR:$a, GPR:$b),
                       [(set GPR:$dst, (mulhu GPR:$a, GPR:$b))]>;
def MULHS32 : SHPseudo<(outs GPR:$dst), (ins GPR:$a, GPR:$b),
                       [(set GPR:$dst, (mulhs GPR:$a, GPR:$b))]>;
}
}

//===----------------------------------------------------------------------===//
// Shifts
//===----------------------------------------------------------------------===//

// By two, eight and sixteen bits: these leave T alone.
let AddedComplexity = 10 in {
def SHLL2 : SHShift<0b00001000, "shll2", shl, 2>;
def SHLL8 : SHShift<0b00011000, "shll8", shl, 8>;
def SHLL16 : SHShift<0b00101000, "shll16", shl, 16>;
def SHLR2 : SHShift<0b00001001, "shlr2", srl, 2>;
def SHLR8 : SHShift<0b00011001, "shlr8", srl, 8>;
def SHLR16 : SHShift<0b00101001, "shlr16", srl, 16>;

// By one bit: the bit that leaves goes to T.  To the left it is an
// addition, which does not touch T.
let Defs = [T] in {
def SHLR : SHShift<0b00000001, "shlr", srl, 1>;
def SHAR : SHShift<0b00100001, "shar", sra, 1>;
def SHLL : SHPlain<(outs GPR:$rn), (ins GPR:$src), "shll\t$rn">,
           EncN<0b0100, 0b00000000> {
  let Constraints = "$src = $rn";
}
}
def : Pat<(shl GPR:$a, (i32 1)), (ADDrr GPR:$a, GPR:$a)>;
}

// By the number in a register: to the left if it is positive, to the right
// if it is negative.
let Constraints = "$src1 = $rn", Predicates = [HasDynShift] in {
def SHLD : SHInst<(outs GPR:$rn), (ins GPR:$src1, GPR:$rm),
                  "shld\t$rm,$rn",
                  [(set GPR:$rn, (shl GPR:$src1, GPR:$rm))]>,
           EncNM<0b0100, 0b1101>;
def SHAD : SHPlain<(outs GPR:$rn), (ins GPR:$src1, GPR:$rm),
                  "shad\t$rm,$rn">,
           EncNM<0b0100, 0b1100>;
}

let Predicates = [HasDynShift] in {
def : Pat<(srl GPR:$a, GPR:$n), (SHLD GPR:$a, (NEG GPR:$n))>;
def : Pat<(sra GPR:$a, GPR:$n), (SHAD GPR:$a, (NEG GPR:$n))>;
let AddedComplexity = 5 in {
def : Pat<(srl GPR:$a, shamt:$n), (SHLD GPR:$a, (MOVI shamt:$n))>;
def : Pat<(sra GPR:$a, shamt:$n), (SHAD GPR:$a, (MOVI shamt:$n))>;
}
}

//===----------------------------------------------------------------------===//
// Comparisons and what uses them
//===----------------------------------------------------------------------===//

let Defs = [T] in {
let isCommutable = 1 in
def CMPEQ : SHInst<(outs), (ins GPR:$rn, GPR:$rm), "cmp/eq\t$rm,$rn",
                   [(SHcmpeq GPR:$rn, GPR:$rm)]>,
            EncNM<0b0011, 0b0000>;
def CMPGE : SHInst<(outs), (ins GPR:$rn, GPR:$rm), "cmp/ge\t$rm,$rn",
                   [(SHcmpge GPR:$rn, GPR:$rm)]>,
            EncNM<0b0011, 0b0011>;
def CMPGT : SHInst<(outs), (ins GPR:$rn, GPR:$rm), "cmp/gt\t$rm,$rn",
                   [(SHcmpgt GPR:$rn, GPR:$rm)]>,
            EncNM<0b0011, 0b0111>;
def CMPHI : SHInst<(outs), (ins GPR:$rn, GPR:$rm), "cmp/hi\t$rm,$rn",
                   [(SHcmphi GPR:$rn, GPR:$rm)]>,
            EncNM<0b0011, 0b0110>;
def CMPHS : SHInst<(outs), (ins GPR:$rn, GPR:$rm), "cmp/hs\t$rm,$rn",
                   [(SHcmphs GPR:$rn, GPR:$rm)]>,
            EncNM<0b0011, 0b0010>;
let isCommutable = 1 in
def TST : SHInst<(outs), (ins GPR:$rn, GPR:$rm), "tst\t$rm,$rn",
                 [(SHtst GPR:$rn, GPR:$rm)]>,
          EncNM<0b0010, 0b1000>;
def CMPPL : SHInst<(outs), (ins GPR:$rn), "cmp/pl\t$rn",
                   [(SHcmppl GPR:$rn)]>,
            EncN<0b0100, 0b00010101>;
def CMPPZ : SHInst<(outs), (ins GPR:$rn), "cmp/pz\t$rn",
                   [(SHcmppz GPR:$rn)]>,
            EncN<0b0100, 0b00010001>;
// With an immediate, which only r0 can be compared with.  The value is
// copied to r0 if it is somewhere else, and that is no more than the "mov
// #imm" that the other form needs.  r0 is named, not asked for as a class of
// one register: a value that was given such a class through a copy would
// have to stay in r0 all its life.
let Uses = [R0] in {
def CMPEQI : SHInst<(outs), (ins simm8:$imm), "cmp/eq\t#$imm,r0",
                    [(SHcmpeq R0, simm8:$imm)]>,
             EncI<0b10001000>;
def TSTI : SHInst<(outs), (ins uimm8:$imm), "tst\t#$imm,r0",
                  [(SHtst R0, uimm8:$imm)]>,
           EncI<0b11001000>;
}
}

let Uses = [T] in
def MOVT : SHInst<(outs GPR:$rn), (ins), "movt\t$rn",
                  [(set GPR:$rn, (SHmovt))]>,
           EncN<0b0000, 0b00101001>;

// 1 - T: "mov #-1,Rn" and "negc Rn,Rn".
let Uses = [T], Defs = [T] in
def MOVRT : SHPseudo<(outs GPR:$dst), (ins), [(set GPR:$dst, (SHmovrt))]>;

// One of two values, the first if T is set.  It becomes a branch around a
// copy.
let usesCustomInserter = 1, Uses = [T] in
def SELECT : SHPseudo<(outs GPR:$dst), (ins GPR:$t, GPR:$f),
                      [(set GPR:$dst, (SHselect GPR:$t, GPR:$f))]>;

//===----------------------------------------------------------------------===//
// Control flow
//===----------------------------------------------------------------------===//

// A conditional branch reaches 256 bytes and has no delay slot.  bra reaches
// 4094 bytes.  bra, jmp, jsr and rts execute the instruction behind them
// before they take effect.
let isBranch = 1, isTerminator = 1 in {
let Uses = [T] in {
def BT : SHInst<(outs), (ins brtarget:$target), "bt\t$target",
                [(SHbrt bb:$target)]>,
         EncT8<0b10001001>;
def BF : SHInst<(outs), (ins brtarget:$target), "bf\t$target",
                [(SHbrf bb:$target)]>,
         EncT8<0b10001011>;
}
let isBarrier = 1, hasDelaySlot = 1 in {
def BRA : SHInst<(outs), (ins brtarget12:$target), "bra\t$target",
                 [(br bb:$target)]>,
          EncT12<0b1010>;
let isIndirectBranch = 1 in
def JMP : SHInst<(outs), (ins GPR:$rm), "jmp\t@$rm", [(brind GPR:$rm)]>,
          EncM<0b0100, 0b00101011>;
}

// What a branch becomes when its target is out of reach: a conditional
// branch around a bra ("bf 1f; bra target; nop; 1:"), and a jump over a
// distance from a literal with r0 saved around it ("mov.l r0,@-r15;
// mov.l .L,r0; braf r0; mov.l @r15+,r0").  The second operand of the far
// forms is the label of the literal, the third the label of the braf, which
// the distance is counted from.  That is the same code wherever it runs.
let Uses = [T] in {
let Size = 6 in {
def BTnear : SHPseudo<(outs), (ins brtarget:$dst), []>;
def BFnear : SHPseudo<(outs), (ins brtarget:$dst), []>;
}
let Size = 10 in {
def BTfar : SHPseudo<(outs),
                     (ins brtarget:$dst, labelop:$label, labelop:$anchor), []>;
def BFfar : SHPseudo<(outs),
                     (ins brtarget:$dst, labelop:$label, labelop:$anchor), []>;
}
}
let isBarrier = 1, Size = 8 in
def BRAfar : SHPseudo<(outs),
                      (ins brtarget:$dst, labelop:$label, labelop:$anchor), []>;

// A jump over the distance in a register, which counts from four bytes
// behind the instruction.
let isBarrier = 1, isIndirectBranch = 1, hasDelaySlot = 1 in
def BRAF : SHPlain<(outs), (ins GPR:$rm), "braf\t$rm">,
           EncM<0b0000, 0b00100011>;
}

let isCall = 1, hasDelaySlot = 1, Defs = [PR, T, MACH, MACL] in {
def JSR : SHInst<(outs), (ins GPR:$rm, variable_ops), "jsr\t@$rm",
                 [(SHcall GPR:$rm)]>,
          EncM<0b0100, 0b00001011>;
// A call over the distance in a register, which counts from four bytes
// behind the instruction.
def BSRF : SHPlain<(outs), (ins GPR:$rm), "bsrf\t$rm">,
           EncM<0b0000, 0b00000011>;
}

// Position independent code calls over a distance from a literal:
//
//   mov.l .L1,r1; ...; bsrf r1; .L2: (the delay slot)
//   .L1: .long function@PLT-(.L2+2-.L1)
//
// That is GCC's call.  It goes through the procedure linkage table, which
// finds the function when it is first called and wants the address of the
// global offset table in r12 for that.  A function of this module is called
// in the same way without the table, the literal is "function-(.L2+2)".
// MOVLcall is the load until the literal is placed, CALLrel the bsrf with
// its label.  The label is theirs alone, so neither can be made twice.
let isNotDuplicable = 1 in {
let hasSideEffects = 0 in
def MOVLcall : SHPseudo<(outs GPR:$dst),
                        (ins i32imm:$function, labelop:$anchor), []>;
let isCall = 1, hasDelaySlot = 1, Defs = [PR, T, MACH, MACL] in
def CALLrel : SHPseudo<(outs),
                       (ins GPR:$distance, labelop:$anchor, variable_ops),
                       [(SHcallrel GPR:$distance, mcsym:$anchor)]>;
}
def : Pat<(SHcalldist tglobaladdr:$f, mcsym:$anchor),
          (MOVLcall tglobaladdr:$f, mcsym:$anchor)>;
def : Pat<(SHcalldist texternalsym:$f, mcsym:$anchor),
          (MOVLcall texternalsym:$f, mcsym:$anchor)>;

// A tail call: "jmp @Rn" behind the epilogue, or "braf Rn" over a distance
// as above.  The register is one that the epilogue leaves alone.
let isCall = 1, isTerminator = 1, isReturn = 1, isBarrier = 1,
    hasDelaySlot = 1 in {
def TAILJMP : SHPseudo<(outs), (ins TCGPR:$target, variable_ops),
                       [(SHtailcall TCGPR:$target)]>;
let isNotDuplicable = 1 in
def TAILrel : SHPseudo<(outs),
                       (ins TCGPR:$distance, labelop:$anchor, variable_ops),
                       [(SHtailcallrel TCGPR:$distance, mcsym:$anchor)]>;
}

let isReturn = 1, isTerminator = 1, isBarrier = 1, hasDelaySlot = 1 in
def RTS : SHInst<(outs), (ins variable_ops), "rts", [(SHret)]>, Enc0<0x000b>;

def NOP : SHInst<(outs), (ins), "nop", []>, Enc0<0x0009>;

// The block copy becomes a loop over words, or over bytes where the
// alignment does not allow words.
let usesCustomInserter = 1, Defs = [T] in
def BLOCKCOPY : SHPseudo<(outs),
                         (ins GPR:$dst, GPR:$src, i32imm:$size, i32imm:$align),
                         [(SHblockcopy GPR:$dst, GPR:$src, timm:$size,
                                       timm:$align)]>;

// The stack pointer moves for the arguments of a call only in a function
// with objects of variable size.  A large distance is loaded into a
// register first: r1 in front of the call, which carries nothing into a
// function, and r7 behind it, which carries nothing out.
let Uses = [R15] in {
let Defs = [R15, R1] in
def ADJCALLSTACKDOWN : SHPseudo<(outs), (ins i32imm:$amt1, i32imm:$amt2),
                                [(SHcallseq_start timm:$amt1, timm:$amt2)]>;
let Defs = [R15, R7] in
def ADJCALLSTACKUP : SHPseudo<(outs), (ins i32imm:$amt1, i32imm:$amt2),
                              [(SHcallseq_end timm:$amt1, timm:$amt2)]>;
}

//===----------------------------------------------------------------------===//
// The floating point unit
//===----------------------------------------------------------------------===//
//
// One instruction is an operation on float or on double, depending on the PR
// bit of FPSCR.  The instructions here say which they are by their name, and
// SHFPModeSwitch.cpp puts the changes of the bit in front of them: a
// function is entered and left with the precision of its convention, and so
// is every block.
//
// A value moves between the unit and the general registers through FPUL.
// That is hidden in pseudo instructions, so that nothing sees FPUL alive.
//
// There is no displacement: the address of a load or a store is in a
// register.  A double is loaded and stored as two halves.

def HasFPU : Predicate<"Subtarget->hasFPU()">;
def HasFPUDouble : Predicate<"Subtarget->hasFPUDouble()">;

let isMoveReg = 1 in
def FMOV : SHPlain<(outs FPR:$rn), (ins FPR:$rm), "fmov\t$rm,$rn">,
           EncNM<0b1111, 0b1100>;

let canFoldAsLoad = 1 in
def FMOVSld : SHInst<(outs FPR:$rn), (ins GPR:$rm), "fmov.s\t@$rm,$rn",
                     [(set FPR:$rn, (load GPR:$rm))]>,
              EncNM<0b1111, 0b1000>;
def FMOVSst : SHInst<(outs), (ins FPR:$rm, GPR:$rn), "fmov.s\t$rm,@$rn",
                     [(store FPR:$rm, GPR:$rn)]>,
              EncNM<0b1111, 0b1010>;
// With the address moving on, for the halves of a double.
let mayLoad = 1, Constraints = "$rm = $wb" in
def FMOVSldinc : SHPlain<(outs FPR:$rn, GPR:$wb), (ins GPR:$rm),
                        "fmov.s\t@$rm+,$rn">,
                 EncNM<0b1111, 0b1001>;
let mayStore = 1, Constraints = "$rn = $wb" in
def FMOVSstdec : SHPlain<(outs GPR:$wb), (ins FPR:$rm, GPR:$rn),
                        "fmov.s\t$rm,@-$rn">,
                 EncNM<0b1111, 0b1011>;
let Uses = [R15], Defs = [R15] in {
let mayStore = 1 in
def FPUSH : SHPlain<(outs), (ins FPR:$rm), "fmov.s\t$rm,@-r15">,
            EncM<0b1111, 0b00001011>, SHCodeGenOnly {
  let Inst{11 - 8} = 0b1111;
  let Inst{7 - 4} = rm;
  let Inst{3 - 0} = 0b1011;
}
let mayLoad = 1 in
def FPOP : SHPlain<(outs FPR:$rn), (ins), "fmov.s\t@r15+,$rn">,
           EncN<0b1111, 0b11111001>, SHCodeGenOnly;
}

// A double through a register: two loads or stores that move the register
// and put it back.
let Size = 6 in {
def FMOVDld : SHPseudo<(outs DFPR:$dst), (ins GPR:$base),
                       [(set DFPR:$dst, (load GPR:$base))]>;
def FMOVDst : SHPseudo<(outs), (ins DFPR:$src, GPR:$base),
                       [(store DFPR:$src, GPR:$base)]>;
}

// A stack slot, until the frame is laid out.  Its address goes into a
// register then.
def FLDFI : SHPseudo<(outs FPR:$dst), (ins memop:$addr),
                     [(set FPR:$dst, (load addrfi:$addr))]>;
def FSTFI : SHPseudo<(outs), (ins FPR:$src, memop:$addr),
                     [(store FPR:$src, addrfi:$addr)]>;
def DLDFI : SHPseudo<(outs DFPR:$dst), (ins memop:$addr),
                     [(set DFPR:$dst, (load addrfi:$addr))]>;
def DSTFI : SHPseudo<(outs), (ins DFPR:$src, memop:$addr),
                     [(store DFPR:$src, addrfi:$addr)]>;

// Arithmetic: "op FRm,FRn" is FRn = FRn op FRm.
//
// An operation on double has the encoding of the operation on float, with
// the number of the first half of each register.  The disassembler cannot
// tell the two apart and prints the one on float, as objdump does.
class SHFBin<bits<4> lo, string mnemonic, SDPatternOperator node,
             RegisterClass RC>
    : SHInst<(outs RC:$rn), (ins RC:$src1, RC:$rm), mnemonic # "\t$rm,$rn",
             [(set RC:$rn, (node RC:$src1, RC:$rm))]>,
      EncNM<0b1111, lo> {
  let Constraints = "$src1 = $rn";
  let Uses = [FPSCR];
}
class SHFUn<bits<8> lo, string mnemonic, SDPatternOperator node,
            RegisterClass RC>
    : SHInst<(outs RC:$rn), (ins RC:$src), mnemonic # "\t$rn",
             [(set RC:$rn, (node RC:$src))]>,
      EncN<0b1111, lo> {
  let Constraints = "$src = $rn";
}

let isCommutable = 1 in {
def FADDS : SHFBin<0b0000, "fadd", fadd, FPR>;
def FMULS : SHFBin<0b0010, "fmul", fmul, FPR>;
let DecoderNamespace = "SHDouble" in {
def FADDD : SHFBin<0b0000, "fadd", fadd, DFPR>;
def FMULD : SHFBin<0b0010, "fmul", fmul, DFPR>;
}
}
def FSUBS : SHFBin<0b0001, "fsub", fsub, FPR>;
def FDIVS : SHFBin<0b0011, "fdiv", fdiv, FPR>;
let DecoderNamespace = "SHDouble" in {
def FSUBD : SHFBin<0b0001, "fsub", fsub, DFPR>;
def FDIVD : SHFBin<0b0011, "fdiv", fdiv, DFPR>;
}

// The sign is one bit of the first register in either precision.
def FNEGS : SHFUn<0b01001101, "fneg", fneg, FPR>;
def FABSS : SHFUn<0b01011101, "fabs", fabs, FPR>;
let DecoderNamespace = "SHDouble" in {
def FNEGD : SHFUn<0b01001101, "fneg", fneg, DFPR>;
def FABSD : SHFUn<0b01011101, "fabs", fabs, DFPR>;
}
let Uses = [FPSCR] in {
def FSQRTS : SHFUn<0b01101101, "fsqrt", fsqrt, FPR>;
let DecoderNamespace = "SHDouble" in
def FSQRTD : SHFUn<0b01101101, "fsqrt", fsqrt, DFPR>;
}

// "fcmp/gt FRm,FRn" is T = FRn > FRm.
let Defs = [T], Uses = [FPSCR] in {
let isCommutable = 1 in {
def FCMPEQS : SHInst<(outs), (ins FPR:$rn, FPR:$rm), "fcmp/eq\t$rm,$rn",
                     [(SHfcmpeq FPR:$rn, FPR:$rm)]>,
              EncNM<0b1111, 0b0100>;
let DecoderNamespace = "SHDouble" in
def FCMPEQD : SHInst<(outs), (ins DFPR:$rn, DFPR:$rm), "fcmp/eq\t$rm,$rn",
                     [(SHfcmpeq DFPR:$rn, DFPR:$rm)]>,
              EncNM<0b1111, 0b0100>;
}
def FCMPGTS : SHInst<(outs), (ins FPR:$rn, FPR:$rm), "fcmp/gt\t$rm,$rn",
                     [(SHfcmpgt FPR:$rn, FPR:$rm)]>,
              EncNM<0b1111, 0b0101>;
let DecoderNamespace = "SHDouble" in
def FCMPGTD : SHInst<(outs), (ins DFPR:$rn, DFPR:$rm), "fcmp/gt\t$rm,$rn",
                     [(SHfcmpgt DFPR:$rn, DFPR:$rm)]>,
              EncNM<0b1111, 0b0101>;
}

// Through FPUL.  Each becomes two instructions behind register allocation.
let Defs = [FPUL], Size = 4 in {
// The bits of a float in a general register and back.
def MOVR2F : SHPseudo<(outs FPR:$dst), (ins GPR:$src),
                      [(set FPR:$dst, (bitconvert GPR:$src))]>;
def MOVF2R : SHPseudo<(outs GPR:$dst), (ins FPR:$src),
                      [(set GPR:$dst, (bitconvert FPR:$src))]>;
let Uses = [FPSCR] in {
// "lds Rm,fpul; float fpul,FRn" and "ftrc FRm,fpul; sts fpul,Rn".
def FLOATS : SHPseudo<(outs FPR:$dst), (ins GPR:$src),
                      [(set FPR:$dst, (sint_to_fp GPR:$src))]>;
def FLOATD : SHPseudo<(outs DFPR:$dst), (ins GPR:$src),
                      [(set DFPR:$dst, (sint_to_fp GPR:$src))]>;
def FTRCS : SHPseudo<(outs GPR:$dst), (ins FPR:$src),
                     [(set GPR:$dst, (fp_to_sint FPR:$src))]>;
def FTRCD : SHPseudo<(outs GPR:$dst), (ins DFPR:$src),
                     [(set GPR:$dst, (fp_to_sint DFPR:$src))]>;
// "flds FRm,fpul; fcnvsd fpul,DRn" and "fcnvds DRm,fpul; fsts fpul,FRn".
def FCNVSD : SHPseudo<(outs DFPR:$dst), (ins FPR:$src),
                      [(set DFPR:$dst, (fpextend FPR:$src))]>;
def FCNVDS : SHPseudo<(outs FPR:$dst), (ins DFPR:$src),
                      [(set FPR:$dst, (fpround DFPR:$src))]>;
}
}

// What those are made of.  The conversions depend on the precision like
// the arithmetic does, and say so: an instruction that reads FPSCR is not
// moved over a change of it.
let Defs = [FPUL] in {
def LDSFPUL : SHPlain<(outs), (ins GPR:$rm), "lds\t$rm,fpul">,
              EncM<0b0100, 0b01011010>;
def FLDS : SHPlain<(outs), (ins FPR:$rm), "flds\t$rm,fpul">,
           EncM<0b1111, 0b00011101>;
let Uses = [FPSCR] in {
def FTRCfpulS : SHPlain<(outs), (ins FPR:$rm), "ftrc\t$rm,fpul">,
                EncM<0b1111, 0b00111101>;
let DecoderNamespace = "SHDouble" in
def FTRCfpulD : SHPlain<(outs), (ins DFPR:$rm), "ftrc\t$rm,fpul">,
                EncM<0b1111, 0b00111101>;
def FCNVDSfpul : SHPlain<(outs), (ins DFPR:$rm), "fcnvds\t$rm,fpul">,
                 EncM<0b1111, 0b10111101>;
}
}
let Uses = [FPUL] in {
def STSFPUL : SHPlain<(outs GPR:$rn), (ins), "sts\tfpul,$rn">,
              EncN<0b0000, 0b01011010>;
def FSTS : SHPlain<(outs FPR:$rn), (ins), "fsts\tfpul,$rn">,
           EncN<0b1111, 0b00001101>;
let Uses = [FPUL, FPSCR] in {
def FLOATfpulS : SHPlain<(outs FPR:$rn), (ins), "float\tfpul,$rn">,
                 EncN<0b1111, 0b00101101>;
let DecoderNamespace = "SHDouble" in
def FLOATfpulD : SHPlain<(outs DFPR:$rn), (ins), "float\tfpul,$rn">,
                 EncN<0b1111, 0b00101101>;
def FCNVSDfpul : SHPlain<(outs DFPR:$rn), (ins), "fcnvsd\tfpul,$rn">,
                 EncN<0b1111, 0b10101101>;
}
}

// The precision: FPSCR through a general register, or fpchg on an SH-4A.
let Uses = [FPSCR] in
def STSFPSCR : SHPlain<(outs GPR:$rn), (ins), "sts\tfpscr,$rn">,
               EncN<0b0000, 0b01101010>;
let Defs = [FPSCR] in
def LDSFPSCR : SHPlain<(outs), (ins GPR:$rm), "lds\t$rm,fpscr">,
               EncM<0b0100, 0b01101010>;
let Uses = [FPSCR], Defs = [FPSCR] in
def FPCHG : SHPlain<(outs), (ins), "fpchg">, Enc0<0xf7fd>;

let usesCustomInserter = 1, Uses = [T] in {
def SELECTF : SHPseudo<(outs FPR:$dst), (ins FPR:$t, FPR:$f),
                       [(set FPR:$dst, (SHselect FPR:$t, FPR:$f))]>;
def SELECTD : SHPseudo<(outs DFPR:$dst), (ins DFPR:$t, DFPR:$f),
                       [(set DFPR:$dst, (SHselect DFPR:$t, DFPR:$f))]>;
}

//===----------------------------------------------------------------------===//
// Thread-local storage
//===----------------------------------------------------------------------===//
//
// The linker turns the general forms of an access into the simpler ones
// when it sees that it can, and does that by writing other instructions
// over the ones that GCC emits, at fixed distances in front of the literal.
// So these two are GCC's sequences to the letter, with their literals in
// the code behind them and the address of the global offset table in r12.

// The address of a variable, or of the thread-local storage of this module,
// from __tls_get_addr():
//
//   mov.l 1f,r4; mova 2f,r0; mov.l 2f,r1; add r0,r1; jsr @r1; add r12,r4
//   bra 3f; nop; .align 2
//   1: .long sym@TLSGD        (or sym@TLSLDM)
//   2: .long __tls_get_addr@PLT
//   3:
//
// The result is in r0.  With the padding it is 26 bytes.
let isCall = 1, Defs = [R0, R1, R4, PR, T, MACH, MACL], Size = 26 in
def TLSCALL : SHPseudo<(outs), (ins R12Reg:$got, i32imm:$sym, variable_ops),
                       [(SHtlscall R12Reg:$got, tglobaltlsaddr:$sym)]>;

// The address of a variable whose offset from the thread pointer is in the
// global offset table:
//
//   mov.l 1f,r0; stc gbr,Rn; mov.l @(r0,r12),r0; bra 2f; add r0,Rn
//   .align 2
//   1: .long sym@GOTTPOFF
//   2:
//
// Rn is written while r12 is still needed.
let Defs = [R0], Uses = [GBR], Size = 16, mayLoad = 1,
    Constraints = "@earlyclobber $dst" in
def TLSIE : SHPseudo<(outs GPR:$dst), (ins R12Reg:$got, i32imm:$sym),
                     [(set GPR:$dst,
                           (SHtlsie R12Reg:$got, tglobaltlsaddr:$sym))]>;

//===----------------------------------------------------------------------===//
// Literals in the code (see SHConstantIslands.cpp)
//===----------------------------------------------------------------------===//

// A literal: its label and its value.  The literals of one place are a
// block of their own, which is aligned to four bytes.
let Size = 4 in {
def CPENTRY : SHPseudo<(outs), (ins labelop:$label, i32imm:$value), []>;
// The literal of a far branch: the distance to the target from four bytes
// behind the braf, which has the label that is the third operand.
def CPENTRYrel : SHPseudo<(outs),
                          (ins labelop:$label, brtarget:$target,
                               labelop:$anchor), []>;
// The literal of a call over a distance: the function and the label behind
// the bsrf or braf.
def CPENTRYcall : SHPseudo<(outs),
                           (ins labelop:$label, i32imm:$function,
                                labelop:$anchor), []>;
}

//===----------------------------------------------------------------------===//
// What only the assembler and the disassembler have
//===----------------------------------------------------------------------===//
//
// The rest of the instructions of the SH-1 to the SH-4A, without those of
// the signal processors and of the SH-2A.  They have operands and an
// encoding and nothing else: nothing here is selected.

class SHAsm<dag ins, string asmstr> : SHInst<(outs), ins, asmstr, []> {
  let hasSideEffects = 1;
}

// A word from a literal.  And the loads from a literal with the program
// counter written out, which is the same to GNU as: what stands in front of
// "pc" is the place, not a displacement.
def MOVWpc : SHAsm<(ins GPR:$rn, labelopw:$target), "mov.w\t$target,$rn">,
             EncNT8<0b1001>;
def : InstAlias<"mov.l\t@($target,pc),$rn",
                (MOVLpc GPR:$rn, labelop:$target), 0>;
def : InstAlias<"mov.w\t@($target,pc),$rn",
                (MOVWpc GPR:$rn, labelopw:$target), 0>;
def : InstAlias<"mova\t@($target,pc),r0", (MOVA labelop:$target), 0>;

// The address register moves: down in front of a store, up behind a load.
def MOVBstdec : SHAsm<(ins GPR:$rm, GPR:$rn), "mov.b\t$rm,@-$rn">,
                EncNM<0b0010, 0b0100>;
def MOVWstdec : SHAsm<(ins GPR:$rm, GPR:$rn), "mov.w\t$rm,@-$rn">,
                EncNM<0b0010, 0b0101>;
def MOVLstdec : SHAsm<(ins GPR:$rm, GPR:$rn), "mov.l\t$rm,@-$rn">,
                EncNM<0b0010, 0b0110>;
def MOVBldinc : SHAsm<(ins GPR:$rn, GPR:$rm), "mov.b\t@$rm+,$rn">,
                EncNM<0b0110, 0b0100>;
def MOVWldinc : SHAsm<(ins GPR:$rn, GPR:$rm), "mov.w\t@$rm+,$rn">,
                EncNM<0b0110, 0b0101>;
def MOVLldinc : SHAsm<(ins GPR:$rn, GPR:$rm), "mov.l\t@$rm+,$rn">,
                EncNM<0b0110, 0b0110>;

// The address is the sum of r0 and a register.
def MOVBstr0x : SHAsm<(ins GPR:$rm, GPR:$rn), "mov.b\t$rm,@(r0,$rn)">,
                EncNM<0b0000, 0b0100>;
def MOVWstr0x : SHAsm<(ins GPR:$rm, GPR:$rn), "mov.w\t$rm,@(r0,$rn)">,
                EncNM<0b0000, 0b0101>;
def MOVLstr0x : SHAsm<(ins GPR:$rm, GPR:$rn), "mov.l\t$rm,@(r0,$rn)">,
                EncNM<0b0000, 0b0110>;
def MOVBldr0x : SHAsm<(ins GPR:$rn, GPR:$rm), "mov.b\t@(r0,$rm),$rn">,
                EncNM<0b0000, 0b1100>;
def MOVWldr0x : SHAsm<(ins GPR:$rn, GPR:$rm), "mov.w\t@(r0,$rm),$rn">,
                EncNM<0b0000, 0b1101>;

// At a displacement from gbr.
def MOVBstgbr : SHAsm<(ins disp8x1:$disp), "mov.b\tr0,@($disp,gbr)">,
                EncD8<0b11000000>;
def MOVWstgbr : SHAsm<(ins disp8x2:$disp), "mov.w\tr0,@($disp,gbr)">,
                EncD8<0b11000001>;
def MOVLstgbr : SHAsm<(ins disp8x4:$disp), "mov.l\tr0,@($disp,gbr)">,
                EncD8<0b11000010>;
def MOVBldgbr : SHAsm<(ins disp8x1:$disp), "mov.b\t@($disp,gbr),r0">,
                EncD8<0b11000100>;
def MOVWldgbr : SHAsm<(ins disp8x2:$disp), "mov.w\t@($disp,gbr),r0">,
                EncD8<0b11000101>;
def MOVLldgbr : SHAsm<(ins disp8x4:$disp), "mov.l\t@($disp,gbr),r0">,
                EncD8<0b11000110>;

def XTRCT : SHAsm<(ins GPR:$rn, GPR:$rm), "xtrct\t$rm,$rn">,
            EncNM<0b0010, 0b1101>;
// Compare and swap, which only the J2 has: if the long word at r0 is Rm, it
// becomes Rn, and Rn is what was there.
def CASL : SHAsm<(ins GPR:$rm, GPR:$rn), "cas.l\t$rm,$rn,@r0">,
           EncNM<0b0010, 0b0011>;
def MOVCAL : SHAsm<(ins GPR:$rn), "movca.l\tr0,@$rn">,
             EncN<0b0000, 0b11000011>;
def MOVCOL : SHAsm<(ins GPR:$rn), "movco.l\tr0,@$rn">,
             EncN<0b0000, 0b01110011>;
def MOVLIL : SHAsm<(ins GPR:$rm), "movli.l\t@$rm,r0">,
             EncM<0b0000, 0b01100011>;
def MOVUAL : SHAsm<(ins GPR:$rm), "movua.l\t@$rm,r0">,
             EncM<0b0100, 0b10101001>;
def MOVUALinc : SHAsm<(ins GPR:$rm), "movua.l\t@$rm+,r0">,
                EncM<0b0100, 0b11101001>;

// Arithmetic.
def ADDV : SHAsm<(ins GPR:$rn, GPR:$rm), "addv\t$rm,$rn">,
           EncNM<0b0011, 0b1111>;
def SUBV : SHAsm<(ins GPR:$rn, GPR:$rm), "subv\t$rm,$rn">,
           EncNM<0b0011, 0b1011>;
def CMPSTR : SHAsm<(ins GPR:$rn, GPR:$rm), "cmp/str\t$rm,$rn">,
             EncNM<0b0010, 0b1100>;
def DIV1 : SHAsm<(ins GPR:$rn, GPR:$rm), "div1\t$rm,$rn">,
           EncNM<0b0011, 0b0100>;
def DIV0S : SHAsm<(ins GPR:$rn, GPR:$rm), "div0s\t$rm,$rn">,
            EncNM<0b0010, 0b0111>;
def DIV0U : SHAsm<(ins), "div0u">, Enc0<0x0019>;
def DT : SHAsm<(ins GPR:$rn), "dt\t$rn">, EncN<0b0100, 0b00010000>;
def MACLinc : SHAsm<(ins GPR:$rm, GPR:$rn), "mac.l\t@$rm+,@$rn+">,
           EncNM<0b0000, 0b1111>;
def MACWinc : SHAsm<(ins GPR:$rm, GPR:$rn), "mac.w\t@$rm+,@$rn+">,
           EncNM<0b0100, 0b1111>;
def MULSW : SHAsm<(ins GPR:$rn, GPR:$rm), "muls.w\t$rm,$rn">,
            EncNM<0b0010, 0b1111>;
def MULUW : SHAsm<(ins GPR:$rn, GPR:$rm), "mulu.w\t$rm,$rn">,
            EncNM<0b0010, 0b1110>;

// Logic with an immediate, on r0 and on the byte at the sum of r0 and gbr.
def ANDI : SHAsm<(ins uimm8:$imm), "and\t#$imm,r0">, EncI<0b11001001>;
def ORI : SHAsm<(ins uimm8:$imm), "or\t#$imm,r0">, EncI<0b11001011>;
def XORI : SHAsm<(ins uimm8:$imm), "xor\t#$imm,r0">, EncI<0b11001010>;
def ANDB : SHAsm<(ins uimm8:$imm), "and.b\t#$imm,@(r0,gbr)">,
           EncI<0b11001101>;
def ORB : SHAsm<(ins uimm8:$imm), "or.b\t#$imm,@(r0,gbr)">, EncI<0b11001111>;
def XORB : SHAsm<(ins uimm8:$imm), "xor.b\t#$imm,@(r0,gbr)">,
           EncI<0b11001110>;
def TSTB : SHAsm<(ins uimm8:$imm), "tst.b\t#$imm,@(r0,gbr)">,
           EncI<0b11001100>;
def TASB : SHAsm<(ins GPR:$rn), "tas.b\t@$rn">, EncN<0b0100, 0b00011011>;

// Rotations, and the shift to the left that sets T on an overflow.
def ROTL : SHAsm<(ins GPR:$rn), "rotl\t$rn">, EncN<0b0100, 0b00000100>;
def ROTR : SHAsm<(ins GPR:$rn), "rotr\t$rn">, EncN<0b0100, 0b00000101>;
def ROTCL : SHAsm<(ins GPR:$rn), "rotcl\t$rn">, EncN<0b0100, 0b00100100>;
def ROTCR : SHAsm<(ins GPR:$rn), "rotcr\t$rn">, EncN<0b0100, 0b00100101>;
def SHAL : SHAsm<(ins GPR:$rn), "shal\t$rn">, EncN<0b0100, 0b00100000>;

// Branches with a delay slot on a condition, and the call that reaches
// four kilobytes.
let isBranch = 1, isTerminator = 1, hasDelaySlot = 1 in {
def BTS : SHAsm<(ins brtarget:$target), "bt/s\t$target">, EncT8<0b10001101>;
def BFS : SHAsm<(ins brtarget:$target), "bf/s\t$target">, EncT8<0b10001111>;
}
let isCall = 1, hasDelaySlot = 1 in
def BSR : SHAsm<(ins brtarget12:$target), "bsr\t$target">, EncT12<0b1011>;

// The system.
def CLRMAC : SHAsm<(ins), "clrmac">, Enc0<0x0028>;
def CLRS : SHAsm<(ins), "clrs">, Enc0<0x0048>;
def SETS : SHAsm<(ins), "sets">, Enc0<0x0058>;
def LDTLB : SHAsm<(ins), "ldtlb">, Enc0<0x0038>;
def RTE : SHAsm<(ins), "rte">, Enc0<0x002b>;
def SLEEP : SHAsm<(ins), "sleep">, Enc0<0x001b>;
def SYNCO : SHAsm<(ins), "synco">, Enc0<0x00ab>;
def TRAPA : SHAsm<(ins uimm8:$imm), "trapa\t#$imm">, EncI<0b11000011>;
def PREF : SHAsm<(ins GPR:$rn), "pref\t@$rn">, EncN<0b0000, 0b10000011>;
def PREFI : SHAsm<(ins GPR:$rn), "prefi\t@$rn">, EncN<0b0000, 0b11010011>;
def OCBI : SHAsm<(ins GPR:$rn), "ocbi\t@$rn">, EncN<0b0000, 0b10010011>;
def OCBP : SHAsm<(ins GPR:$rn), "ocbp\t@$rn">, EncN<0b0000, 0b10100011>;
def OCBWB : SHAsm<(ins GPR:$rn), "ocbwb\t@$rn">, EncN<0b0000, 0b10110011>;
def ICBI : SHAsm<(ins GPR:$rn), "icbi\t@$rn">, EncN<0b0000, 0b11100011>;

// The control registers: to and from a general register, and from and to
// the stack.  The code generator has the two for gbr.
multiclass SHControl<string name, bits<8> ldc, bits<8> ldcl, bits<8> stc,
                     bits<8> stcl> {
  def LDC#NAME : SHAsm<(ins GPR:$rm), "ldc\t$rm," # name>, EncM<0b0100, ldc>;
  def LDCL#NAME : SHAsm<(ins GPR:$rm), "ldc.l\t@$rm+," # name>,
                  EncM<0b0100, ldcl>;
  def STC#NAME : SHAsm<(ins GPR:$rn), "stc\t" # name # ",$rn">,
                 EncN<0b0000, stc>;
  def STCL#NAME : SHAsm<(ins GPR:$rn), "stc.l\t" # name # ",@-$rn">,
                  EncN<0b0100, stcl>;
}
defm SR : SHControl<"sr", 0b00001110, 0b00000111, 0b00000010, 0b00000011>;
defm VBR : SHControl<"vbr", 0b00101110, 0b00100111, 0b00100010, 0b00100011>;
defm SSR : SHControl<"ssr", 0b00111110, 0b00110111, 0b00110010, 0b00110011>;
defm SPC : SHControl<"spc", 0b01001110, 0b01000111, 0b01000010, 0b01000011>;
defm SGR : SHControl<"sgr", 0b00111010, 0b00110110, 0b00111010, 0b00110010>;
defm DBR : SHControl<"dbr", 0b11111010, 0b11110110, 0b11111010, 0b11110010>;
def LDCLGBR : SHAsm<(ins GPR:$rm), "ldc.l\t@$rm+,gbr">,
              EncM<0b0100, 0b00010111>;
def STCLGBR : SHAsm<(ins GPR:$rn), "stc.l\tgbr,@-$rn">,
              EncN<0b0100, 0b00010011>;

// r0 to r7 of the other set.
class SHBank<bits<4> hi, bits<4> lo, dag ins, string asmstr>
    : SHAsm<ins, asmstr> {
  bits<4> reg;
  bits<3> bank;
  let Inst{15 - 12} = hi;
  let Inst{11 - 8} = reg;
  let Inst{7} = 1;
  let Inst{6 - 4} = bank;
  let Inst{3 - 0} = lo;
}
def LDCBANK : SHBank<0b0100, 0b1110, (ins GPR:$reg, BankReg:$bank),
                     "ldc\t$reg,$bank">;
def LDCLBANK : SHBank<0b0100, 0b0111, (ins GPR:$reg, BankReg:$bank),
                      "ldc.l\t@$reg+,$bank">;
def STCBANK : SHBank<0b0000, 0b0010, (ins BankReg:$bank, GPR:$reg),
                     "stc\t$bank,$reg">;
def STCLBANK : SHBank<0b0100, 0b0011, (ins BankReg:$bank, GPR:$reg),
                      "stc.l\t$bank,@-$reg">;

// The registers that a call and a multiplication write, from and to the
// stack.  The code generator has the two for pr with r15.
multiclass SHSystemStack<string name, bits<8> lds, bits<8> sts> {
  def LDSL#NAME : SHAsm<(ins GPR:$rm), "lds.l\t@$rm+," # name>,
                  EncM<0b0100, lds>;
  def STSL#NAME : SHAsm<(ins GPR:$rn), "sts.l\t" # name # ",@-$rn">,
                  EncN<0b0100, sts>;
}
defm MACH : SHSystemStack<"mach", 0b00000110, 0b00000010>;
defm MACL : SHSystemStack<"macl", 0b00010110, 0b00010010>;
defm PR : SHSystemStack<"pr", 0b00100110, 0b00100010>;
defm FPSCR : SHSystemStack<"fpscr", 0b01100110, 0b01100010>;
defm FPUL : SHSystemStack<"fpul", 0b01010110, 0b01010010>;

// The floating point unit.
def FLDI0 : SHAsm<(ins FPR:$rn), "fldi0\t$rn">, EncN<0b1111, 0b10001101>;
def FLDI1 : SHAsm<(ins FPR:$rn), "fldi1\t$rn">, EncN<0b1111, 0b10011101>;
def FMOVSldr0x : SHAsm<(ins FPR:$rn, GPR:$rm), "fmov.s\t@(r0,$rm),$rn">,
                 EncNM<0b1111, 0b0110>;
def FMOVSstr0x : SHAsm<(ins FPR:$rm, GPR:$rn), "fmov.s\t$rm,@(r0,$rn)">,
                 EncNM<0b1111, 0b0111>;
def FMAC : SHAsm<(ins FPR:$rm, FPR:$rn), "fmac\tfr0,$rm,$rn">,
           EncNM<0b1111, 0b1110>;
def FSRRA : SHAsm<(ins FPR:$rn), "fsrra\t$rn">, EncN<0b1111, 0b01111101>;
def FSCA : SHAsm<(ins DFPR:$rn), "fsca\tfpul,$rn">, EncN<0b1111, 0b11111101>;
def FSCHG : SHAsm<(ins), "fschg">, Enc0<0xf3fd>;
def FRCHG : SHAsm<(ins), "frchg">, Enc0<0xfbfd>;

// A double, when the unit moves two registers at once (the SZ bit of
// FPSCR).  The encodings are those of the moves of a float.
let DecoderNamespace = "SHDouble" in {
def FMOVD : SHAsm<(ins DFPR:$rn, DFPR:$rm), "fmov\t$rm,$rn">,
            EncNM<0b1111, 0b1100>;
def FMOVDind : SHAsm<(ins DFPR:$rn, GPR:$rm), "fmov.d\t@$rm,$rn">,
              EncNM<0b1111, 0b1000>;
def FMOVDsti : SHAsm<(ins DFPR:$rm, GPR:$rn), "fmov.d\t$rm,@$rn">,
              EncNM<0b1111, 0b1010>;
def FMOVDldinc : SHAsm<(ins DFPR:$rn, GPR:$rm), "fmov.d\t@$rm+,$rn">,
                 EncNM<0b1111, 0b1001>;
def FMOVDstdec : SHAsm<(ins DFPR:$rm, GPR:$rn), "fmov.d\t$rm,@-$rn">,
                 EncNM<0b1111, 0b1011>;
def FMOVDldr0x : SHAsm<(ins DFPR:$rn, GPR:$rm), "fmov.d\t@(r0,$rm),$rn">,
                 EncNM<0b1111, 0b0110>;
def FMOVDstr0x : SHAsm<(ins DFPR:$rm, GPR:$rn), "fmov.d\t$rm,@(r0,$rn)">,
                 EncNM<0b1111, 0b0111>;
}

// Other spellings that GNU as takes.
def : MnemonicAlias<"bt.s", "bt/s">;
def : MnemonicAlias<"bf.s", "bf/s">;
def : MnemonicAlias<"muls", "muls.w">;
def : MnemonicAlias<"mulu", "mulu.w">;
def : MnemonicAlias<"dmuls", "dmuls.l">;
def : MnemonicAlias<"dmulu", "dmulu.l">;
def : InstAlias<"fmov\t@$rm,$rn", (FMOVSld FPR:$rn, GPR:$rm), 0>;
def : InstAlias<"fmov\t$rm,@$rn", (FMOVSst FPR:$rm, GPR:$rn), 0>;
def : InstAlias<"fmov\t@$rm,$rn", (FMOVDind DFPR:$rn, GPR:$rm), 0>;
def : InstAlias<"fmov\t$rm,@$rn", (FMOVDsti DFPR:$rm, GPR:$rn), 0>;
def : InstAlias<"fmov\t@(r0,$rm),$rn", (FMOVSldr0x FPR:$rn, GPR:$rm), 0>;
def : InstAlias<"fmov\t$rm,@(r0,$rn)", (FMOVSstr0x FPR:$rm, GPR:$rn), 0>;
def : InstAlias<"fmov\t@(r0,$rm),$rn", (FMOVDldr0x DFPR:$rn, GPR:$rm), 0>;
def : InstAlias<"fmov\t$rm,@(r0,$rn)", (FMOVDstr0x DFPR:$rm, GPR:$rn), 0>;
