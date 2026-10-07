//===-- SHRegisterInfo.td - SuperH register definitions ----*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

class SHReg<bits<16> Enc, string n> : Register<n> {
  let HWEncoding = Enc;
  let Namespace = "SH";
}

// The sixteen general registers.  r15 is the stack pointer, r14 the frame
// pointer where one is needed.  The DWARF numbers are those of GCC.
foreach I = 0...15 in
  def R#I : SHReg<I, "r"#I>, DwarfRegNum<[I]>;

// The procedure register holds the return address of a call.
def PR : SHReg<17, "pr">, DwarfRegNum<[17]>;
def GBR : SHReg<18, "gbr">, DwarfRegNum<[18]>;
// The multiply and accumulate registers: a product ends up here.
def MACH : SHReg<20, "mach">, DwarfRegNum<[20]>;
def MACL : SHReg<21, "macl">, DwarfRegNum<[21]>;
// The T bit of the status register: the result of every comparison, and the
// carry of the instructions that have one.
def T : SHReg<22, "t">;

// What the code generator never names and the assembler has to know: the
// registers of the system, the second set of r0 to r7, and the program
// counter, which is written in "@(disp,pc)".
def SR : SHReg<0, "sr">;
def VBR : SHReg<0, "vbr">;
def SSR : SHReg<0, "ssr">;
def SPC : SHReg<0, "spc">;
def SGR : SHReg<0, "sgr">;
def DBR : SHReg<0, "dbr">;
def PC : SHReg<0, "pc">;
foreach I = 0...7 in
  def R#I#_BANK : SHReg<I, "r"#I#"_bank">;
def BankReg : RegisterClass<"SH", [i32], 32, (sequence "R%u_BANK", 0, 7)> {
  let isAllocatable = 0;
}

// r1 to r3 are free at any time, r0 is asked for by name too often to be the
// first choice, r4 to r7 carry arguments.  r8 to r14 are saved by the callee.
def GPR : RegisterClass<"SH", [i32], 32,
                        (add R1, R2, R3, R0, R7, R6, R5, R4, R8, R9, R10, R11,
                             R12, R13, R14, R15)>;

// The register that GCC keeps the address of the global offset table in.
// The sequences for thread-local storage that the linker knows use it.
def R12Reg : RegisterClass<"SH", [i32], 32, (add R12)>;

// Where the target of a tail call can be: in a register that the epilogue
// does not restore and that carries no argument.  r2 is not among them, the
// epilogue computes in it there.
def TCGPR : RegisterClass<"SH", [i32], 32, (add R1, R0, R3)>;

def SysReg : RegisterClass<"SH", [i32], 32, (add PR, MACH, MACL, GBR)> {
  let isAllocatable = 0;
}

//===----------------------------------------------------------------------===//
// The floating point unit
//===----------------------------------------------------------------------===//

// Sixteen registers for float.  The DWARF numbers are those of GCC.
foreach I = 0...15 in
  def FR#I : SHReg<I, "fr"#I>, DwarfRegNum<[!add(I, 25)]>;

// A double is two of them: the first one, with the even number, has the
// high half in either byte order.
let Namespace = "SH" in {
def sub_fhi : SubRegIndex<32>;
def sub_flo : SubRegIndex<32, 32>;
}

class SHDReg<bits<16> Enc, string n, list<Register> halves>
    : RegisterWithSubRegs<n, halves> {
  let HWEncoding = Enc;
  let Namespace = "SH";
  let SubRegIndices = [sub_fhi, sub_flo];
}
def DR0 : SHDReg<0, "dr0", [FR0, FR1]>;
def DR2 : SHDReg<2, "dr2", [FR2, FR3]>;
def DR4 : SHDReg<4, "dr4", [FR4, FR5]>;
def DR6 : SHDReg<6, "dr6", [FR6, FR7]>;
def DR8 : SHDReg<8, "dr8", [FR8, FR9]>;
def DR10 : SHDReg<10, "dr10", [FR10, FR11]>;
def DR12 : SHDReg<12, "dr12", [FR12, FR13]>;
def DR14 : SHDReg<14, "dr14", [FR14, FR15]>;

// FPUL is the way between the unit and the general registers, FPSCR holds
// the precision that the instructions compute in.
def FPUL : SHReg<23, "fpul">, DwarfRegNum<[23]>;
def FPSCR : SHReg<24, "fpscr">, DwarfRegNum<[24]>;

// fr0 to fr3 are free at any time, fr4 to fr11 carry arguments, fr12 to fr15
// are saved by the callee.
def FPR : RegisterClass<"SH", [f32], 32, (sequence "FR%u", 0, 15)>;
def DFPR : RegisterClass<"SH", [f64], 32,
                         (add DR0, DR2, DR4, DR6, DR8, DR10, DR12, DR14)>;

// For the assembler: the registers of the unit's second set as doubles,
// which an instruction names by an odd number, the vectors of four floats,
// and the matrix that the second set is.
foreach I = [0, 2, 4, 6, 8, 10, 12, 14] in
  def XD#I : SHReg<!add(I, 1), "xd"#I>;
foreach I = [0, 4, 8, 12] in
  def FV#I : SHReg<!srl(I, 2), "fv"#I>;
def XMTRX : SHReg<0, "xmtrx">;
def XDPR : RegisterClass<"SH", [f64], 32,
                         (add XD0, XD2, XD4, XD6, XD8, XD10, XD12, XD14)> {
  let isAllocatable = 0;
}
def FVR : RegisterClass<"SH", [i32], 32, (add FV0, FV4, FV8, FV12)> {
  let isAllocatable = 0;
}

def FPSysReg : RegisterClass<"SH", [i32], 32, (add FPUL, FPSCR)> {
  let isAllocatable = 0;
}

def TBit : RegisterClass<"SH", [i32], 32, (add T)> {
  let isAllocatable = 0;
  let CopyCost = -1;
}
