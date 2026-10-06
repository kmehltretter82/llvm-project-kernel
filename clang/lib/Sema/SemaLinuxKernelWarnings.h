//===- SemaLinuxKernelWarnings.h - Linux kernel diagnostics -*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_SEMA_SEMALINUXKERNELWARNINGS_H
#define LLVM_CLANG_LIB_SEMA_SEMALINUXKERNELWARNINGS_H

#include <memory>

namespace clang {

class AnalysisDeclContext;
class FunctionDecl;
class Sema;

namespace sema {

/// What the Linux kernel checks keep for one translation unit: the contracts
/// read from -flinux-kernel-contracts= and what was inferred from the function
/// bodies seen so far.
class LinuxKernelUnit {
public:
  LinuxKernelUnit();
  ~LinuxKernelUnit();
  LinuxKernelUnit(const LinuxKernelUnit &) = delete;
  LinuxKernelUnit &operator=(const LinuxKernelUnit &) = delete;

  struct Impl;
  std::unique_ptr<Impl> State;
};

void IssueLinuxKernelWarnings(Sema &S, const FunctionDecl *FD,
                              LinuxKernelUnit &Unit);

/// Whether any of the checks that need the function's CFG is enabled.
bool wantsLinuxKernelFlowWarnings(Sema &S, const FunctionDecl *FD);

/// Run the CFG-based Linux kernel checks.
void IssueLinuxKernelFlowWarnings(Sema &S, const FunctionDecl *FD,
                                  AnalysisDeclContext &AC,
                                  LinuxKernelUnit &Unit);

/// Called once at the end of the translation unit.  Appends the facts about
/// its functions to the file named by -flinux-kernel-emit-facts=.
void FinishLinuxKernelWarnings(Sema &S, LinuxKernelUnit &Unit);

} // namespace sema
} // namespace clang

#endif
