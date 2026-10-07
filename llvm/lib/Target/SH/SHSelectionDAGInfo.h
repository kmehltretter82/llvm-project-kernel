//===-- SHSelectionDAGInfo.h - The DAG nodes of SuperH -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SH_SHSELECTIONDAGINFO_H
#define LLVM_LIB_TARGET_SH_SHSELECTIONDAGINFO_H

#include "llvm/CodeGen/SelectionDAGTargetInfo.h"

#define GET_SDNODE_ENUM
#include "SHGenSDNodeInfo.inc"

namespace llvm {

class SHSelectionDAGInfo : public SelectionDAGGenTargetInfo {
public:
  SHSelectionDAGInfo();
  ~SHSelectionDAGInfo() override;
};

} // namespace llvm

#endif
