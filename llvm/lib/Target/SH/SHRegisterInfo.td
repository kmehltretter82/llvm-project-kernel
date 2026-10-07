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

// r1 to r3 are free at any time, r0 is asked for by name too often to be the
// first choice, r4 to r7 carry arguments.  r8 to r14 are saved by the callee.
def GPR : RegisterClass<"SH", [i32], 32,
                        (add R1, R2, R3, R0, R7, R6, R5, R4, R8, R9, R10, R11,
                             R12, R13, R14, R15)>;

def R0Reg : RegisterClass<"SH", [i32], 32, (add R0)>;

def SysReg : RegisterClass<"SH", [i32], 32, (add PR, MACH, MACL, GBR)> {
  let isAllocatable = 0;
}

def TBit : RegisterClass<"SH", [i32], 32, (add T)> {
  let isAllocatable = 0;
  let CopyCost = -1;
}
