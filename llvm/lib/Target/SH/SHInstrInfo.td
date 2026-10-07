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

def simm8 : Operand<i32>, ImmLeaf<i32, [{ return isInt<8>(Imm); }]>;
// The eight bits of the logical instructions, which are not extended.
def uimm8 : Operand<i32>, ImmLeaf<i32, [{ return isUInt<8>(Imm); }]>;

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

// An instruction without a pattern.  All that it does is in its operands,
// in Uses and Defs and in mayLoad and mayStore.  That has to be said:
// without a pattern to look at, tablegen assumes that an instruction has
// effects that nobody knows, and then nothing may move or remove it.
class SHPlain<dag outs, dag ins, string asmstr>
    : SHInst<outs, ins, asmstr, []> {
  let hasSideEffects = 0;
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
def MOVrr : SHPlain<(outs GPR:$dst), (ins GPR:$src), "mov\t$src,$dst">;

let isReMaterializable = 1, isAsCheapAsAMove = 1, isMoveImm = 1 in
def MOVI : SHInst<(outs GPR:$dst), (ins simm8:$imm), "mov\t#$imm,$dst",
                  [(set GPR:$dst, simm8:$imm)]>;

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
def MOVLpc : SHPlain<(outs GPR:$dst), (ins labelop:$label),
                    "mov.l\t$label,$dst">;

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
def MOVA : SHPlain<(outs), (ins labelop:$label), "mova\t$label,r0">;

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

// A byte or a word at a displacement from a register, which only r0 can be
// loaded with and stored from.  That is one instruction where the address
// would need two more, and a copy if the value is not wanted in r0.
let AddedComplexity = 5 in {
let Defs = [R0] in {
def MOVBldr0 : SHInst<(outs), (ins memop:$addr), "mov.b\t$addr,r0",
                      [(set R0, (sextloadi8 addrbdisp:$addr))]>;
def MOVWldr0 : SHInst<(outs), (ins memop:$addr), "mov.w\t$addr,r0",
                      [(set R0, (sextloadi16 addrwdisp:$addr))]>;
}
let Uses = [R0] in {
def MOVBstr0 : SHInst<(outs), (ins memop:$addr), "mov.b\tr0,$addr",
                      [(truncstorei8 R0, addrbdisp:$addr)]>;
def MOVWstr0 : SHInst<(outs), (ins memop:$addr), "mov.w\tr0,$addr",
                      [(truncstorei16 R0, addrwdisp:$addr)]>;
}
def : Pat<(extloadi16 addrwdisp:$addr), (MOVWldr0 addrwdisp:$addr)>;
def : Pat<(extloadi8 addrbdisp:$addr), (MOVBldr0 addrbdisp:$addr)>;
def : Pat<(extloadi1 addrbdisp:$addr), (MOVBldr0 addrbdisp:$addr)>;
}

def : Pat<(extloadi16 addrbw:$addr), (MOVWld addrbw:$addr)>;
def : Pat<(extloadi8 addrbw:$addr), (MOVBld addrbw:$addr)>;
def : Pat<(extloadi1 addrbw:$addr), (MOVBld addrbw:$addr)>;

// "mov.l @(r0,Rm),Rn": the address is the sum of r0 and a register.  Only
// the sequence for thread-local storage uses it so far.
let Uses = [R0], mayLoad = 1 in
def MOVLldr0 : SHPlain<(outs GPR:$dst), (ins GPR:$base),
                       "mov.l\t@(r0,$base),$dst">;

// Push and pop, for the registers that a function saves.
let Uses = [R15], Defs = [R15] in {
let mayStore = 1 in
def PUSH : SHPlain<(outs), (ins GPR:$src), "mov.l\t$src,@-r15">;
let mayLoad = 1 in
def POP : SHPlain<(outs GPR:$dst), (ins), "mov.l\t@r15+,$dst">;
let Uses = [R15, PR], mayStore = 1 in
def PUSHPR : SHPlain<(outs), (ins), "sts.l\tpr,@-r15">;
let Defs = [R15, PR], mayLoad = 1 in
def POPPR : SHPlain<(outs), (ins), "lds.l\t@r15+,pr">;
}

// The system registers.
let Uses = [PR] in
def STSPR : SHPlain<(outs GPR:$dst), (ins), "sts\tpr,$dst">;
let Defs = [PR] in
def LDSPR : SHPlain<(outs), (ins GPR:$src), "lds\t$src,pr">;
let Uses = [MACL] in
def STSMACL : SHPlain<(outs GPR:$dst), (ins), "sts\tmacl,$dst">;
let Uses = [MACH] in
def STSMACH : SHPlain<(outs GPR:$dst), (ins), "sts\tmach,$dst">;
let Defs = [MACL] in
def LDSMACL : SHPlain<(outs), (ins GPR:$src), "lds\t$src,macl">;
let Defs = [MACH] in
def LDSMACH : SHPlain<(outs), (ins GPR:$src), "lds\t$src,mach">;
let Uses = [GBR] in
def STCGBR : SHPlain<(outs GPR:$dst), (ins), "stc\tgbr,$dst">;
let Defs = [GBR] in
def LDCGBR : SHPlain<(outs), (ins GPR:$src), "ldc\t$src,gbr">;

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
def SWAPB : SHPlain<(outs GPR:$dst), (ins GPR:$src), "swap.b\t$src,$dst">;

def : Pat<(bswap GPR:$src), (SWAPB (SWAPW (SWAPB GPR:$src)))>;

// With the carry in T: the upper half of a sum or a difference of 64 bits
// adds the carry of the lower half, which adds none.  The lower half is
// "clrt" and the same instruction.  The two are glued, and nothing that is
// inserted between them later changes T (see the head of this file).
let Constraints = "$src1 = $dst", Uses = [T], Defs = [T] in {
def ADDC : SHInst<(outs GPR:$dst), (ins GPR:$src1, GPR:$src2),
                  "addc\t$src2,$dst",
                  [(set GPR:$dst, (adde GPR:$src1, GPR:$src2))]>;
def SUBC : SHInst<(outs GPR:$dst), (ins GPR:$src1, GPR:$src2),
                  "subc\t$src2,$dst",
                  [(set GPR:$dst, (sube GPR:$src1, GPR:$src2))]>;
}
let Constraints = "$src1 = $dst", Defs = [T], Size = 4 in {
def ADDC0 : SHPseudo<(outs GPR:$dst), (ins GPR:$src1, GPR:$src2),
                     [(set GPR:$dst, (addc GPR:$src1, GPR:$src2))]>;
def SUBC0 : SHPseudo<(outs GPR:$dst), (ins GPR:$src1, GPR:$src2),
                     [(set GPR:$dst, (subc GPR:$src1, GPR:$src2))]>;
}
// 0 - Rm - T: the halves of a 64-bit number with the other sign.
let Uses = [T], Defs = [T] in
def NEGC : SHInst<(outs GPR:$dst), (ins GPR:$src), "negc\t$src,$dst",
                  [(set GPR:$dst, (sube (i32 0), GPR:$src))]>;
let Defs = [T], Size = 4 in
def NEGC0 : SHPseudo<(outs GPR:$dst), (ins GPR:$src),
                     [(set GPR:$dst, (subc (i32 0), GPR:$src))]>;
let Defs = [T] in {
def CLRT : SHPlain<(outs), (ins), "clrt">;
def SETT : SHPlain<(outs), (ins), "sett">;
}

// A product goes to MACL, or to MACH and MACL if it has 64 bits.
let Defs = [MACL] in
def MULL : SHPlain<(outs), (ins GPR:$rn, GPR:$rm), "mul.l\t$rm,$rn">;
let Defs = [MACH, MACL] in {
def DMULU : SHPlain<(outs), (ins GPR:$rn, GPR:$rm), "dmulu.l\t$rm,$rn">;
def DMULS : SHPlain<(outs), (ins GPR:$rn, GPR:$rm), "dmuls.l\t$rm,$rn">;
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
def SHLL : SHPlain<(outs GPR:$dst), (ins GPR:$src), "shll\t$dst"> {
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
def SHAD : SHPlain<(outs GPR:$dst), (ins GPR:$src1, GPR:$src2),
                  "shad\t$src2,$dst">;
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
// With an immediate, which only r0 can be compared with.  The value is
// copied to r0 if it is somewhere else, and that is no more than the "mov
// #imm" that the other form needs.  r0 is named, not asked for as a class of
// one register: a value that was given such a class through a copy would
// have to stay in r0 all its life.
let Uses = [R0] in {
def CMPEQI : SHInst<(outs), (ins simm8:$imm), "cmp/eq\t#$imm,r0",
                    [(SHcmpeq R0, simm8:$imm)]>;
def TSTI : SHInst<(outs), (ins uimm8:$imm), "tst\t#$imm,r0",
                  [(SHtst R0, uimm8:$imm)]>;
}
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
def BRAF : SHPlain<(outs), (ins GPR:$distance), "braf\t$distance">;
}

let isCall = 1, hasDelaySlot = 1, Defs = [PR, T, MACH, MACL] in {
def JSR : SHInst<(outs), (ins GPR:$target, variable_ops), "jsr\t@$target",
                 [(SHcall GPR:$target)]>;
// A call over the distance in a register, which counts from four bytes
// behind the instruction.
def BSRF : SHPlain<(outs), (ins GPR:$distance), "bsrf\t$distance">;
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
def RTS : SHInst<(outs), (ins variable_ops), "rts", [(SHret)]>;

def NOP : SHInst<(outs), (ins), "nop", []>;

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
def FMOV : SHPlain<(outs FPR:$dst), (ins FPR:$src), "fmov\t$src,$dst">;

let canFoldAsLoad = 1 in
def FMOVSld : SHInst<(outs FPR:$dst), (ins GPR:$base), "fmov.s\t@$base,$dst",
                     [(set FPR:$dst, (load GPR:$base))]>;
def FMOVSst : SHInst<(outs), (ins FPR:$src, GPR:$base), "fmov.s\t$src,@$base",
                     [(store FPR:$src, GPR:$base)]>;
// With the address moving on, for the halves of a double.
let Constraints = "$base = $wb" in {
let mayLoad = 1 in
def FMOVSldinc : SHPlain<(outs FPR:$dst, GPR:$wb), (ins GPR:$base),
                        "fmov.s\t@$base+,$dst">;
let mayStore = 1 in
def FMOVSstdec : SHPlain<(outs GPR:$wb), (ins FPR:$src, GPR:$base),
                        "fmov.s\t$src,@-$base">;
}
let Uses = [R15], Defs = [R15] in {
let mayStore = 1 in
def FPUSH : SHPlain<(outs), (ins FPR:$src), "fmov.s\t$src,@-r15">;
let mayLoad = 1 in
def FPOP : SHPlain<(outs FPR:$dst), (ins), "fmov.s\t@r15+,$dst">;
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
class SHFBin<string mnemonic, SDPatternOperator node, RegisterClass RC>
    : SHInst<(outs RC:$dst), (ins RC:$src1, RC:$src2),
             mnemonic # "\t$src2,$dst",
             [(set RC:$dst, (node RC:$src1, RC:$src2))]> {
  let Constraints = "$src1 = $dst";
  let Uses = [FPSCR];
}
class SHFUn<string mnemonic, SDPatternOperator node, RegisterClass RC>
    : SHInst<(outs RC:$dst), (ins RC:$src), mnemonic # "\t$dst",
             [(set RC:$dst, (node RC:$src))]> {
  let Constraints = "$src = $dst";
}

let isCommutable = 1 in {
def FADDS : SHFBin<"fadd", fadd, FPR>;
def FMULS : SHFBin<"fmul", fmul, FPR>;
def FADDD : SHFBin<"fadd", fadd, DFPR>;
def FMULD : SHFBin<"fmul", fmul, DFPR>;
}
def FSUBS : SHFBin<"fsub", fsub, FPR>;
def FDIVS : SHFBin<"fdiv", fdiv, FPR>;
def FSUBD : SHFBin<"fsub", fsub, DFPR>;
def FDIVD : SHFBin<"fdiv", fdiv, DFPR>;

// The sign is one bit of the first register in either precision.
def FNEGS : SHFUn<"fneg", fneg, FPR>;
def FABSS : SHFUn<"fabs", fabs, FPR>;
def FNEGD : SHFUn<"fneg", fneg, DFPR>;
def FABSD : SHFUn<"fabs", fabs, DFPR>;
let Uses = [FPSCR] in {
def FSQRTS : SHFUn<"fsqrt", fsqrt, FPR>;
def FSQRTD : SHFUn<"fsqrt", fsqrt, DFPR>;
}

// "fcmp/gt FRm,FRn" is T = FRn > FRm.
let Defs = [T], Uses = [FPSCR] in {
let isCommutable = 1 in {
def FCMPEQS : SHInst<(outs), (ins FPR:$rn, FPR:$rm), "fcmp/eq\t$rm,$rn",
                     [(SHfcmpeq FPR:$rn, FPR:$rm)]>;
def FCMPEQD : SHInst<(outs), (ins DFPR:$rn, DFPR:$rm), "fcmp/eq\t$rm,$rn",
                     [(SHfcmpeq DFPR:$rn, DFPR:$rm)]>;
}
def FCMPGTS : SHInst<(outs), (ins FPR:$rn, FPR:$rm), "fcmp/gt\t$rm,$rn",
                     [(SHfcmpgt FPR:$rn, FPR:$rm)]>;
def FCMPGTD : SHInst<(outs), (ins DFPR:$rn, DFPR:$rm), "fcmp/gt\t$rm,$rn",
                     [(SHfcmpgt DFPR:$rn, DFPR:$rm)]>;
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
def LDSFPUL : SHPlain<(outs), (ins GPR:$src), "lds\t$src,fpul">;
def FLDS : SHPlain<(outs), (ins FPR:$src), "flds\t$src,fpul">;
let Uses = [FPSCR] in {
def FTRCfpulS : SHPlain<(outs), (ins FPR:$src), "ftrc\t$src,fpul">;
def FTRCfpulD : SHPlain<(outs), (ins DFPR:$src), "ftrc\t$src,fpul">;
def FCNVDSfpul : SHPlain<(outs), (ins DFPR:$src), "fcnvds\t$src,fpul">;
}
}
let Uses = [FPUL] in {
def STSFPUL : SHPlain<(outs GPR:$dst), (ins), "sts\tfpul,$dst">;
def FSTS : SHPlain<(outs FPR:$dst), (ins), "fsts\tfpul,$dst">;
let Uses = [FPUL, FPSCR] in {
def FLOATfpulS : SHPlain<(outs FPR:$dst), (ins), "float\tfpul,$dst">;
def FLOATfpulD : SHPlain<(outs DFPR:$dst), (ins), "float\tfpul,$dst">;
def FCNVSDfpul : SHPlain<(outs DFPR:$dst), (ins), "fcnvsd\tfpul,$dst">;
}
}

// The precision: FPSCR through a general register, or fpchg on an SH-4A.
let Uses = [FPSCR] in
def STSFPSCR : SHPlain<(outs GPR:$dst), (ins), "sts\tfpscr,$dst">;
let Defs = [FPSCR] in
def LDSFPSCR : SHPlain<(outs), (ins GPR:$src), "lds\t$src,fpscr">;
let Uses = [FPSCR], Defs = [FPSCR] in
def FPCHG : SHPlain<(outs), (ins), "fpchg">;

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
