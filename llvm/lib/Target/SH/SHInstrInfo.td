//===-- SHInstrInfo.td - SuperH instruction definitions ----*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The integer instructions of SuperH that the code generator uses.  Every
// instruction is 16 bits wide.  The assembly is the syntax of GNU as: the
// source comes first.  There are no encodings here yet: the output is
// assembly text.
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
def SDT_SHSelect
    : SDTypeProfile<1, 2, [SDTCisVT<0, i32>, SDTCisSameAs<0, 1>,
                           SDTCisSameAs<1, 2>]>;
def SDT_SHMovT : SDTypeProfile<1, 0, [SDTCisVT<0, i32>]>;
def SDT_SHLoadAddr : SDTypeProfile<1, 1, [SDTCisVT<0, i32>, SDTCisPtrTy<1>]>;

def SHcall : SDNode<"SHISD::CALL", SDT_SHCall,
                    [SDNPHasChain, SDNPOptInGlue, SDNPOutGlue, SDNPVariadic]>;
def SHret : SDNode<"SHISD::RET", SDTNone,
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

//===----------------------------------------------------------------------===//
// Operands and patterns
//===----------------------------------------------------------------------===//

def HasDynShift : Predicate<"Subtarget->hasDynShift()">;

def simm8 : Operand<i32>, ImmLeaf<i32, [{ return isInt<8>(Imm); }]>;

def brtarget : Operand<OtherVT>;

// A label of a literal or of a place in the code.
def labelop : Operand<i32>;

// "@(disp,Rn)": a register, or a frame index until the frame is laid out,
// and a displacement.  A long word can be reached with a displacement of up
// to 60, a byte or a word only with none.
def memop : Operand<i32> {
  let PrintMethod = "printMemOperand";
  let MIOperandInfo = (ops GPR:$base, i32imm:$disp);
}

def addrl : ComplexPattern<i32, 2, "SelectAddrL", [frameindex]>;
def addrbw : ComplexPattern<i32, 2, "SelectAddrBW", [frameindex]>;
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
  let Namespace = "SH";
  let OutOperandList = outs;
  let InOperandList = ins;
  let AsmString = asmstr;
  let Pattern = pattern;
  let Size = 2;
}

class SHPseudo<dag outs, dag ins, list<dag> pattern>
    : SHInst<outs, ins, "", pattern> {
  let isPseudo = 1;
  let isCodeGenOnly = 1;
}

// "op Rm,Rn": Rn = Rn op Rm.
class SHBinOp<string mnemonic, SDPatternOperator node>
    : SHInst<(outs GPR:$dst), (ins GPR:$src1, GPR:$src2),
             mnemonic # "\t$src2,$dst",
             [(set GPR:$dst, (node GPR:$src1, GPR:$src2))]> {
  let Constraints = "$src1 = $dst";
}

// "op Rm,Rn": Rn = op Rm.
class SHUnOp<string mnemonic, dag pattern>
    : SHInst<(outs GPR:$dst), (ins GPR:$src), mnemonic # "\t$src,$dst",
             [(set GPR:$dst, pattern)]>;

// "op Rn": Rn = op Rn.
class SHShift<string mnemonic, SDPatternOperator node, int amount>
    : SHInst<(outs GPR:$dst), (ins GPR:$src), mnemonic # "\t$dst",
             [(set GPR:$dst, (node GPR:$src, (i32 amount)))]> {
  let Constraints = "$src = $dst";
}

//===----------------------------------------------------------------------===//
// Moves
//===----------------------------------------------------------------------===//

let isMoveReg = 1 in
def MOVrr : SHInst<(outs GPR:$dst), (ins GPR:$src), "mov\t$src,$dst", []>;

let isReMaterializable = 1, isAsCheapAsAMove = 1, isMoveImm = 1 in
def MOVI : SHInst<(outs GPR:$dst), (ins simm8:$imm), "mov\t#$imm,$dst",
                  [(set GPR:$dst, simm8:$imm)]>;

// A number or an address that is loaded from a literal.  The operand is the
// number, the global, the symbol, the block address, the jump table or the
// constant pool entry.
let isReMaterializable = 1 in
def MOVLpcrel : SHPseudo<(outs GPR:$dst), (ins i32imm:$src), []>;

// What the pseudo becomes: "mov.l .L1,Rn" with the label of the literal.
def MOVLpc : SHInst<(outs GPR:$dst), (ins labelop:$label),
                    "mov.l\t$label,$dst", []>;

def : Pat<(SHloadaddr tglobaladdr:$a), (MOVLpcrel tglobaladdr:$a)>;
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

let canFoldAsLoad = 1 in {
def MOVLld : SHInst<(outs GPR:$dst), (ins memop:$addr), "mov.l\t$addr,$dst",
                    [(set GPR:$dst, (load addrl:$addr))]>;
// A word or a byte is sign-extended when it is loaded.
def MOVWld : SHInst<(outs GPR:$dst), (ins memop:$addr), "mov.w\t$addr,$dst",
                    [(set GPR:$dst, (sextloadi16 addrbw:$addr))]>;
def MOVBld : SHInst<(outs GPR:$dst), (ins memop:$addr), "mov.b\t$addr,$dst",
                    [(set GPR:$dst, (sextloadi8 addrbw:$addr))]>;
}

def MOVLst : SHInst<(outs), (ins GPR:$src, memop:$addr), "mov.l\t$src,$addr",
                    [(store GPR:$src, addrl:$addr)]>;
def MOVWst : SHInst<(outs), (ins GPR:$src, memop:$addr), "mov.w\t$src,$addr",
                    [(truncstorei16 GPR:$src, addrbw:$addr)]>;
def MOVBst : SHInst<(outs), (ins GPR:$src, memop:$addr), "mov.b\t$src,$addr",
                    [(truncstorei8 GPR:$src, addrbw:$addr)]>;

def : Pat<(extloadi16 addrbw:$addr), (MOVWld addrbw:$addr)>;
def : Pat<(extloadi8 addrbw:$addr), (MOVBld addrbw:$addr)>;
def : Pat<(extloadi1 addrbw:$addr), (MOVBld addrbw:$addr)>;

// Push and pop, for the registers that a function saves.
let Uses = [R15], Defs = [R15] in {
def PUSH : SHInst<(outs), (ins GPR:$src), "mov.l\t$src,@-r15", []>;
def POP : SHInst<(outs GPR:$dst), (ins), "mov.l\t@r15+,$dst", []>;
let Uses = [R15, PR] in
def PUSHPR : SHInst<(outs), (ins), "sts.l\tpr,@-r15", []>;
let Defs = [R15, PR] in
def POPPR : SHInst<(outs), (ins), "lds.l\t@r15+,pr", []>;
}

// The system registers.
let Uses = [PR] in
def STSPR : SHInst<(outs GPR:$dst), (ins), "sts\tpr,$dst", []>;
let Defs = [PR] in
def LDSPR : SHInst<(outs), (ins GPR:$src), "lds\t$src,pr", []>;
let Uses = [MACL] in
def STSMACL : SHInst<(outs GPR:$dst), (ins), "sts\tmacl,$dst", []>;
let Uses = [MACH] in
def STSMACH : SHInst<(outs GPR:$dst), (ins), "sts\tmach,$dst", []>;
let Defs = [MACL] in
def LDSMACL : SHInst<(outs), (ins GPR:$src), "lds\t$src,macl", []>;
let Defs = [MACH] in
def LDSMACH : SHInst<(outs), (ins GPR:$src), "lds\t$src,mach", []>;
let Uses = [GBR] in
def STCGBR : SHInst<(outs GPR:$dst), (ins), "stc\tgbr,$dst", []>;
let Defs = [GBR] in
def LDCGBR : SHInst<(outs), (ins GPR:$src), "ldc\t$src,gbr", []>;

//===----------------------------------------------------------------------===//
// Arithmetic and logic
//===----------------------------------------------------------------------===//

let isCommutable = 1 in {
def ADDrr : SHBinOp<"add", add>;
def ANDrr : SHBinOp<"and", and>;
def ORrr : SHBinOp<"or", or>;
def XORrr : SHBinOp<"xor", xor>;
}
def SUBrr : SHBinOp<"sub", sub>;

let Constraints = "$src = $dst" in
def ADDri : SHInst<(outs GPR:$dst), (ins GPR:$src, simm8:$imm),
                   "add\t#$imm,$dst",
                   [(set GPR:$dst, (add GPR:$src, simm8:$imm))]>;

def NEG : SHUnOp<"neg", (ineg GPR:$src)>;
def NOT : SHUnOp<"not", (not GPR:$src)>;
def EXTUB : SHUnOp<"extu.b", (and GPR:$src, 255)>;
def EXTUW : SHUnOp<"extu.w", (and GPR:$src, 65535)>;
def EXTSB : SHUnOp<"exts.b", (sext_inreg GPR:$src, i8)>;
def EXTSW : SHUnOp<"exts.w", (sext_inreg GPR:$src, i16)>;
// The two halves change places, or the two low bytes do.
def SWAPW : SHUnOp<"swap.w", (rotl GPR:$src, (i32 16))>;
def SWAPB : SHInst<(outs GPR:$dst), (ins GPR:$src), "swap.b\t$src,$dst", []>;

def : Pat<(bswap GPR:$src), (SWAPB (SWAPW (SWAPB GPR:$src)))>;

// With the carry in T.
let Constraints = "$src1 = $dst", Uses = [T], Defs = [T] in {
def ADDC : SHInst<(outs GPR:$dst), (ins GPR:$src1, GPR:$src2),
                  "addc\t$src2,$dst", []>;
def SUBC : SHInst<(outs GPR:$dst), (ins GPR:$src1, GPR:$src2),
                  "subc\t$src2,$dst", []>;
}
let Uses = [T], Defs = [T] in
def NEGC : SHInst<(outs GPR:$dst), (ins GPR:$src), "negc\t$src,$dst", []>;
let Defs = [T] in {
def CLRT : SHInst<(outs), (ins), "clrt", []>;
def SETT : SHInst<(outs), (ins), "sett", []>;
}

// A product goes to MACL, or to MACH and MACL if it has 64 bits.
let Defs = [MACL] in
def MULL : SHInst<(outs), (ins GPR:$rn, GPR:$rm), "mul.l\t$rm,$rn", []>;
let Defs = [MACH, MACL] in {
def DMULU : SHInst<(outs), (ins GPR:$rn, GPR:$rm), "dmulu.l\t$rm,$rn", []>;
def DMULS : SHInst<(outs), (ins GPR:$rn, GPR:$rm), "dmuls.l\t$rm,$rn", []>;
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
def SHLL2 : SHShift<"shll2", shl, 2>;
def SHLL8 : SHShift<"shll8", shl, 8>;
def SHLL16 : SHShift<"shll16", shl, 16>;
def SHLR2 : SHShift<"shlr2", srl, 2>;
def SHLR8 : SHShift<"shlr8", srl, 8>;
def SHLR16 : SHShift<"shlr16", srl, 16>;

// By one bit: the bit that leaves goes to T.  To the left it is an
// addition, which does not touch T.
let Defs = [T] in {
def SHLR : SHShift<"shlr", srl, 1>;
def SHAR : SHShift<"shar", sra, 1>;
def SHLL : SHInst<(outs GPR:$dst), (ins GPR:$src), "shll\t$dst", []> {
  let Constraints = "$src = $dst";
}
}
def : Pat<(shl GPR:$a, (i32 1)), (ADDrr GPR:$a, GPR:$a)>;
}

// By the number in a register: to the left if it is positive, to the right
// if it is negative.
let Constraints = "$src1 = $dst", Predicates = [HasDynShift] in {
def SHLD : SHInst<(outs GPR:$dst), (ins GPR:$src1, GPR:$src2),
                  "shld\t$src2,$dst",
                  [(set GPR:$dst, (shl GPR:$src1, GPR:$src2))]>;
def SHAD : SHInst<(outs GPR:$dst), (ins GPR:$src1, GPR:$src2),
                  "shad\t$src2,$dst", []>;
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
                   [(SHcmpeq GPR:$rn, GPR:$rm)]>;
def CMPGE : SHInst<(outs), (ins GPR:$rn, GPR:$rm), "cmp/ge\t$rm,$rn",
                   [(SHcmpge GPR:$rn, GPR:$rm)]>;
def CMPGT : SHInst<(outs), (ins GPR:$rn, GPR:$rm), "cmp/gt\t$rm,$rn",
                   [(SHcmpgt GPR:$rn, GPR:$rm)]>;
def CMPHI : SHInst<(outs), (ins GPR:$rn, GPR:$rm), "cmp/hi\t$rm,$rn",
                   [(SHcmphi GPR:$rn, GPR:$rm)]>;
def CMPHS : SHInst<(outs), (ins GPR:$rn, GPR:$rm), "cmp/hs\t$rm,$rn",
                   [(SHcmphs GPR:$rn, GPR:$rm)]>;
let isCommutable = 1 in
def TST : SHInst<(outs), (ins GPR:$rn, GPR:$rm), "tst\t$rm,$rn",
                 [(SHtst GPR:$rn, GPR:$rm)]>;
def CMPPL : SHInst<(outs), (ins GPR:$rn), "cmp/pl\t$rn",
                   [(SHcmppl GPR:$rn)]>;
def CMPPZ : SHInst<(outs), (ins GPR:$rn), "cmp/pz\t$rn",
                   [(SHcmppz GPR:$rn)]>;
}

let Uses = [T] in
def MOVT : SHInst<(outs GPR:$dst), (ins), "movt\t$dst",
                  [(set GPR:$dst, (SHmovt))]>;

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
def BT : SHInst<(outs), (ins brtarget:$dst), "bt\t$dst", [(SHbrt bb:$dst)]>;
def BF : SHInst<(outs), (ins brtarget:$dst), "bf\t$dst", [(SHbrf bb:$dst)]>;
}
let isBarrier = 1, hasDelaySlot = 1 in {
def BRA : SHInst<(outs), (ins brtarget:$dst), "bra\t$dst", [(br bb:$dst)]>;
let isIndirectBranch = 1 in
def JMP : SHInst<(outs), (ins GPR:$target), "jmp\t@$target",
                 [(brind GPR:$target)]>;
}

// What a branch becomes when its target is out of reach: a conditional
// branch around a bra ("bf 1f; bra target; nop; 1:"), and a jump through a
// literal with r0 saved around it ("mov.l r0,@-r15; mov.l .L,r0; jmp @r0;
// mov.l @r15+,r0").  The second operand of the far forms is the label of
// the literal.
let Uses = [T] in {
let Size = 6 in {
def BTnear : SHPseudo<(outs), (ins brtarget:$dst), []>;
def BFnear : SHPseudo<(outs), (ins brtarget:$dst), []>;
}
let Size = 10 in {
def BTfar : SHPseudo<(outs), (ins brtarget:$dst, labelop:$label), []>;
def BFfar : SHPseudo<(outs), (ins brtarget:$dst, labelop:$label), []>;
}
}
let isBarrier = 1, Size = 8 in
def BRAfar : SHPseudo<(outs), (ins brtarget:$dst, labelop:$label), []>;
}

let isCall = 1, hasDelaySlot = 1, Defs = [PR, T, MACH, MACL] in
def JSR : SHInst<(outs), (ins GPR:$target, variable_ops), "jsr\t@$target",
                 [(SHcall GPR:$target)]>;

let isReturn = 1, isTerminator = 1, isBarrier = 1, hasDelaySlot = 1 in
def RTS : SHInst<(outs), (ins variable_ops), "rts", [(SHret)]>;

def NOP : SHInst<(outs), (ins), "nop", []>;

let Defs = [R15], Uses = [R15] in {
def ADJCALLSTACKDOWN : SHPseudo<(outs), (ins i32imm:$amt1, i32imm:$amt2),
                                [(SHcallseq_start timm:$amt1, timm:$amt2)]>;
def ADJCALLSTACKUP : SHPseudo<(outs), (ins i32imm:$amt1, i32imm:$amt2),
                              [(SHcallseq_end timm:$amt1, timm:$amt2)]>;
}

//===----------------------------------------------------------------------===//
// Literals in the code (see SHConstantIslands.cpp)
//===----------------------------------------------------------------------===//

// A literal: its label and its value.
let Size = 4 in
def CPENTRY : SHPseudo<(outs), (ins labelop:$label, i32imm:$value), []>;
// The alignment in front of the literals.  The operand is the number of
// bytes that it takes, 0 or 2.
let Size = 0 in
def CPALIGN : SHPseudo<(outs), (ins i32imm:$bytes), []>;
// A jump around literals that are placed where the code runs on:
// "bra label; nop".  CPLABEL is where it goes to.
let Size = 4 in
def CPJUMP : SHPseudo<(outs), (ins labelop:$label), []>;
let Size = 0 in
def CPLABEL : SHPseudo<(outs), (ins labelop:$label), []>;
