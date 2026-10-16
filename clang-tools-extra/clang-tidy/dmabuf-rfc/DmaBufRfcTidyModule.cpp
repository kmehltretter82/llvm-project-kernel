//===--- DmaBufRfcTidyModule.cpp - clang-tidy module ----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "DmaBufMappingRfcCheck.h"
#include "clang-tidy/ClangTidyModule.h"

namespace clang::tidy::linuxkernel {
namespace {

class DmaBufRfcModule final : public ClangTidyModule {
public:
  void addCheckFactories(ClangTidyCheckFactories &Factories) override {
    Factories.registerCheck<DmaBufMappingRfcCheck>(
        "linuxkernel-dmabuf-mapping-rfc");
  }
};

} // namespace

static ClangTidyModuleRegistry::Add<DmaBufRfcModule>
    X("dmabuf-rfc-module",
      "Checks DMA-buf mapping-type and PAL RFC contracts.");

// Anchor for platforms which otherwise drop a registration-only module.
// NOLINTNEXTLINE(misc-use-internal-linkage)
volatile int DmaBufRfcModuleAnchorSource = 0;

} // namespace clang::tidy::linuxkernel
