//===--- DmaBufMappingRfcCheck.h - DMA-buf RFC checks -----------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_DMABUF_RFC_DMABUFMAPPINGRFCCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_DMABUF_RFC_DMABUFMAPPINGRFCCHECK_H

#include "clang-tidy/ClangTidyCheck.h"
#include "clang/Basic/SourceLocation.h"
#include "llvm/ADT/SmallVector.h"

namespace clang::tidy::linuxkernel {

/// Checks the callback, locking, publication, revocation, and allocation
/// contracts introduced by the DMA-buf mapping-type/PAL RFC.
///
/// This is deliberately shipped as an opt-in plugin while the API is an RFC.
class DmaBufMappingRfcCheck final : public ClangTidyCheck {
public:
  DmaBufMappingRfcCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}

  void registerPPCallbacks(const SourceManager &SM, Preprocessor *PP,
                           Preprocessor *ModuleExpanderPP) override;
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;

private:
  llvm::SmallVector<SourceLocation, 4> DmaResvAssertions;
};

} // namespace clang::tidy::linuxkernel

#endif
