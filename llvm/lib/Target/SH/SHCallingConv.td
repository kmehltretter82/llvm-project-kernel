//===-- SHCallingConv.td - SuperH calling conventions ------*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The conventions of GCC.
//
// Without a floating point unit: the words of all arguments in a row, the
// first four in r4 to r7 and the rest on the stack.  A 64-bit value takes
// two words wherever they are, the second can be on the stack when the first
// is in r7.
//
// With one: an argument is in registers only if all of it fits.  float goes
// to fr4 to fr11, and double to dr4 to dr10 if the unit computes it.  The
// counting is in SHISelLowering.cpp (CC_SH_FPU_Custom).
//
// A result is in r0 to r3, in fr0 and fr1, or in dr0 and dr2.
//
//===----------------------------------------------------------------------===//

def CC_SH : CallingConv<[
  // The address of the place for a result that is returned in memory.
  CCIfSRet<CCAssignToReg<[R2]>>,
  // The static chain of a nested function.
  CCIfNest<CCAssignToReg<[R3]>>,
  CCIfByVal<CCPassByVal<4, 4>>,
  CCIfType<[i1, i8, i16], CCPromoteToType<i32>>,
  CCIfType<[i32], CCAssignToReg<[R4, R5, R6, R7]>>,
  CCAssignToStack<4, 4>
]>;

def CC_SH_FPU : CallingConv<[
  CCIfSRet<CCAssignToReg<[R2]>>,
  // The static chain of a nested function.
  CCIfNest<CCAssignToReg<[R3]>>,
  CCIfByVal<CCPassByVal<4, 4>>,
  CCIfType<[i1, i8, i16], CCPromoteToType<i32>>,
  CCCustom<"CC_SH_FPU_Custom">
]>;

def RetCC_SH : CallingConv<[
  CCIfType<[i1, i8, i16], CCPromoteToType<i32>>,
  // A complex number of two 64-bit parts takes all four.
  CCIfType<[i32], CCAssignToReg<[R0, R1, R2, R3]>>,
  // A complex number has two parts.
  CCIfType<[f32], CCAssignToReg<[FR0, FR1]>>,
  CCIfType<[f64], CCAssignToReg<[DR0, DR2]>>
]>;

// PR is saved by a function that calls another one.
def CSR_SH : CalleeSavedRegs<(add R8, R9, R10, R11, R12, R13, R14, PR)>;
def CSR_SH_FPU : CalleeSavedRegs<(add CSR_SH, FR12, FR13, FR14, FR15)>;
