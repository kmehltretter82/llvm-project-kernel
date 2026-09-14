//===- SemaLinuxKernelWarnings.h - Linux kernel diagnostics -*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_SEMA_SEMALINUXKERNELWARNINGS_H
#define LLVM_CLANG_LIB_SEMA_SEMALINUXKERNELWARNINGS_H

namespace clang {

class FunctionDecl;
class Sema;

namespace sema {

void IssueLinuxKernelWarnings(Sema &S, const FunctionDecl *FD);

} // namespace sema
} // namespace clang

#endif
