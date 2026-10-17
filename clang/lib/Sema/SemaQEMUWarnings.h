//===- SemaQEMUWarnings.h - QEMU semantic diagnostics ---------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_SEMA_SEMAQEMUWARNINGS_H
#define LLVM_CLANG_LIB_SEMA_SEMAQEMUWARNINGS_H

namespace clang {

class AnalysisDeclContext;
class CallExpr;
class FunctionDecl;
class Sema;
class VarDecl;
enum class UninitOutputParamContract;

namespace sema {

void IssueQEMUWarnings(Sema &S, const FunctionDecl *FD);

/// Whether any enabled QEMU check needs the function CFG.
bool wantsQEMUFlowWarnings(Sema &S, const FunctionDecl *FD);

/// Run CFG-based QEMU contract checks.
void IssueQEMUFlowWarnings(Sema &S, const FunctionDecl *FD,
                           AnalysisDeclContext &AC);

/// QEMU contracts consumed by the generic conditional-initialization engine.
UninitOutputParamContract getQEMUOutputParamContract(const CallExpr *Call,
                                                     const VarDecl *VD);
bool isQEMUKnownNonNullCall(Sema &S, const CallExpr *Call);

} // namespace sema
} // namespace clang

#endif
