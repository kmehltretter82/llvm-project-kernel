//===-- SH.td - Describe the SuperH target machine ---------*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The top level of the description of the Renesas (Hitachi) SuperH family:
// SH-2, SH-3 and SH-4 and the J-Core J2.  Integer code only so far.
//
//===----------------------------------------------------------------------===//

include "llvm/Target/Target.td"

//===----------------------------------------------------------------------===//
// Subtarget features
//===----------------------------------------------------------------------===//

def FeatureDynShift
    : SubtargetFeature<"dynshift", "HasDynShift", "true",
                       "The dynamic shifts shad and shld (SH-3 and later, "
                       "SH-2A, J2)">;
def FeatureJ2
    : SubtargetFeature<"j2", "HasJ2", "true",
                       "The J-Core J2: SH-2 with dynamic shifts and cas.l",
                       [FeatureDynShift]>;
def FeatureSH2A
    : SubtargetFeature<"sh2a", "HasSH2A", "true", "The SH-2A instruction set",
                       [FeatureDynShift]>;
def FeatureSH3
    : SubtargetFeature<"sh3", "HasSH3", "true", "The SH-3 instruction set",
                       [FeatureDynShift]>;
def FeatureSH4
    : SubtargetFeature<"sh4", "HasSH4", "true", "The SH-4 instruction set",
                       [FeatureSH3]>;
def FeatureSH4A
    : SubtargetFeature<"sh4a", "HasSH4A", "true", "The SH-4A instruction set",
                       [FeatureSH4]>;

// The floating point unit, which decides the calling convention as well:
// with one, floating point values are passed in its registers and an
// argument is in registers only if all of it fits.
def FeatureFPU
    : SubtargetFeature<"fpu", "HasFPU", "true",
                       "A floating point unit that computes float">;
def FeatureFPUDouble
    : SubtargetFeature<"fpu-double", "HasFPUDouble", "true",
                       "The floating point unit computes double as well",
                       [FeatureFPU]>;
def FeatureFPUSingleMode
    : SubtargetFeature<"fpu-single-mode", "HasFPUSingleMode", "true",
                       "A function is entered with the floating point unit in "
                       "single precision mode">;

//===----------------------------------------------------------------------===//
// Processors.  The names are those of llvm/TargetParser/SHTargetParser.h:
// what GCC has as -m<name> without the "sh".
//===----------------------------------------------------------------------===//

class SHProcessor<string name, list<SubtargetFeature> features>
    : ProcessorModel<name, NoSchedModel, features>;

def : SHProcessor<"generic", []>;
def : SHProcessor<"sh2", []>;
def : SHProcessor<"j2", [FeatureJ2]>;
def : SHProcessor<"sh2e", [FeatureFPU]>;
def : SHProcessor<"sh2a", [FeatureSH2A, FeatureFPUDouble]>;
def : SHProcessor<"sh2a-nofpu", [FeatureSH2A]>;
def : SHProcessor<"sh2a-single",
                  [FeatureSH2A, FeatureFPUDouble, FeatureFPUSingleMode]>;
def : SHProcessor<"sh2a-single-only", [FeatureSH2A, FeatureFPU]>;
def : SHProcessor<"sh3", [FeatureSH3]>;
def : SHProcessor<"sh3e", [FeatureSH3, FeatureFPU]>;
def : SHProcessor<"sh4", [FeatureSH4, FeatureFPUDouble]>;
def : SHProcessor<"sh4-nofpu", [FeatureSH4]>;
def : SHProcessor<"sh4-single",
                  [FeatureSH4, FeatureFPUDouble, FeatureFPUSingleMode]>;
def : SHProcessor<"sh4-single-only", [FeatureSH4, FeatureFPU]>;
def : SHProcessor<"sh4a", [FeatureSH4A, FeatureFPUDouble]>;
def : SHProcessor<"sh4a-nofpu", [FeatureSH4A]>;
def : SHProcessor<"sh4a-single",
                  [FeatureSH4A, FeatureFPUDouble, FeatureFPUSingleMode]>;
def : SHProcessor<"sh4a-single-only", [FeatureSH4A, FeatureFPU]>;
def : SHProcessor<"sh4al", [FeatureSH4A]>;

//===----------------------------------------------------------------------===//
// Registers, calling conventions, instructions
//===----------------------------------------------------------------------===//

include "SHRegisterInfo.td"
include "SHCallingConv.td"
include "SHInstrInfo.td"

defm : RemapAllTargetPseudoPointerOperands<GPR>;

def SHInstrInfo : InstrInfo;

def SHInstPrinter : AsmWriter {
  string AsmWriterClassName = "InstPrinter";
}

// The syntax of GNU as.  A mnemonic can have a dot in it ("mov.l").  The
// characters of an address are tokens of their own: "@(4,r1)", "@r1+",
// "@-r15", and so is the "#" of an immediate.
def SHAsmParser : AsmParser;

def SHAsmParserVariant : AsmParserVariant {
  let TokenizingCharacters = "@()+-#";
}

def SH : Target {
  let InstructionSet = SHInstrInfo;
  let AssemblyWriters = [SHInstPrinter];
  let AssemblyParsers = [SHAsmParser];
  let AssemblyParserVariants = [SHAsmParserVariant];
}
