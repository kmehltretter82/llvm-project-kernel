//===-- SHTargetParser.cpp - SuperH processors and their properties -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The table of SuperH processors.
//
//===----------------------------------------------------------------------===//

#include "llvm/TargetParser/SHTargetParser.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/TargetParser/Triple.h"

using namespace llvm;

static constexpr SH::CPUInfo CPUs[] = {
    {"sh2", SH::AK_SH2, SH::FK_None, false},
    {"j2", SH::AK_J2, SH::FK_None, false},
    {"sh2e", SH::AK_SH2E, SH::FK_SingleOnly, false},
    {"sh2a", SH::AK_SH2A, SH::FK_Double, false},
    {"sh2a-nofpu", SH::AK_SH2A, SH::FK_None, false},
    {"sh2a-single", SH::AK_SH2A, SH::FK_Single, false},
    {"sh2a-single-only", SH::AK_SH2A, SH::FK_SingleOnly, false},
    {"sh3", SH::AK_SH3, SH::FK_None, false},
    {"sh3e", SH::AK_SH3E, SH::FK_SingleOnly, false},
    {"sh4", SH::AK_SH4, SH::FK_Double, false},
    {"sh4-nofpu", SH::AK_SH4, SH::FK_None, false},
    {"sh4-single", SH::AK_SH4, SH::FK_Single, false},
    {"sh4-single-only", SH::AK_SH4, SH::FK_SingleOnly, false},
    {"sh4a", SH::AK_SH4A, SH::FK_Double, false},
    {"sh4a-nofpu", SH::AK_SH4A, SH::FK_None, false},
    {"sh4a-single", SH::AK_SH4A, SH::FK_Single, false},
    {"sh4a-single-only", SH::AK_SH4A, SH::FK_SingleOnly, false},
    {"sh4al", SH::AK_SH4A, SH::FK_None, true},
};

const SH::CPUInfo *SH::parseCPU(StringRef Name) {
  for (const CPUInfo &Info : CPUs)
    if (Info.Name == Name)
      return &Info;
  return nullptr;
}

StringRef SH::getDefaultCPU(const Triple &TT) {
  // "sh4eb", "sh3le": the byte order is not part of the name of a
  // processor.  The order of the tries is that of Triple.cpp, which makes
  // "sh2eb" a big-endian SH-2 and not a little-endian SH-2E.
  StringRef Arch = TT.getArchName();
  if (!Arch.consume_back("eb") && !Arch.consume_back("be") &&
      !Arch.consume_back("le"))
    Arch.consume_back("el");
  if (const CPUInfo *Info = parseCPU(Arch))
    return Info->Name;
  return "sh2";
}

void SH::fillValidCPUList(SmallVectorImpl<StringRef> &Values) {
  for (const CPUInfo &Info : CPUs)
    Values.push_back(Info.Name);
}
