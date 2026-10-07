//===-- SHSelectionDAGInfo.cpp - The DAG nodes of SuperH -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SHSelectionDAGInfo.h"

#define GET_SDNODE_DESC
#include "SHGenSDNodeInfo.inc"

using namespace llvm;

SHSelectionDAGInfo::SHSelectionDAGInfo()
    : SelectionDAGGenTargetInfo(SHGenSDNodeInfo) {}

SHSelectionDAGInfo::~SHSelectionDAGInfo() = default;
