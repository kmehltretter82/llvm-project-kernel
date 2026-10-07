//===-- SHCallingConv.td - SuperH calling conventions ------*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The convention of GCC for a SuperH without a floating point unit: the
// first four words of the arguments in r4 to r7, the rest on the stack, the
// result in r0 and r1.  A 64-bit value takes two words wherever they are,
// the second can be on the stack when the first is in r7.
//
//===----------------------------------------------------------------------===//

def CC_SH : CallingConv<[
  // The address of the place for a result that is returned in memory.
  CCIfSRet<CCAssignToReg<[R2]>>,
  CCIfByVal<CCPassByVal<4, 4>>,
  CCIfType<[i1, i8, i16], CCPromoteToType<i32>>,
  CCIfType<[i32], CCAssignToReg<[R4, R5, R6, R7]>>,
  CCAssignToStack<4, 4>
]>;

def RetCC_SH : CallingConv<[
  CCIfType<[i1, i8, i16], CCPromoteToType<i32>>,
  // A complex number of two 64-bit parts takes all four.
  CCIfType<[i32], CCAssignToReg<[R0, R1, R2, R3]>>
]>;

// PR is saved by a function that calls another one.
def CSR_SH : CalleeSavedRegs<(add R8, R9, R10, R11, R12, R13, R14, PR)>;
