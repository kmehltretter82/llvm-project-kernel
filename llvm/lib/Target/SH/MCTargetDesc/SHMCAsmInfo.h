//===-- SHMCAsmInfo.h - SuperH assembly properties -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SH_MCTARGETDESC_SHMCASMINFO_H
#define LLVM_LIB_TARGET_SH_MCTARGETDESC_SHMCASMINFO_H

#include "llvm/MC/MCAsmInfoELF.h"

namespace llvm {
class Triple;

namespace SH {
/// What is written with an "@" behind a symbol in a literal.  An operand
/// that names the symbol has the number as its target flags.
enum Specifier {
  S_None,
  /// Where the entry of the symbol is in the global offset table, counted
  /// from the start of the table.
  S_GOT,
  /// Where the symbol is, counted from the start of the table.
  S_GOTOFF,
  /// The entry of a function in the procedure linkage table, counted from
  /// the literal.
  S_PLT,
  // Thread-local storage, see LowerGlobalTLSAddress().
  /// Where the variable is, counted from the thread pointer.
  S_TPOFF,
  /// Where that number is in the global offset table.
  S_GOTTPOFF,
  /// Where the table has the module and the offset of the variable, which
  /// are the argument of __tls_get_addr().
  S_TLSGD,
  /// The same for the start of the module's thread-local storage.
  S_TLSLDM,
  /// Where the variable is, counted from that start.
  S_DTPOFF,
};
} // namespace SH

class SHMCAsmInfo : public MCAsmInfoELF {
  void anchor() override;

public:
  explicit SHMCAsmInfo(const Triple &TT, const MCTargetOptions &Options);
};

} // namespace llvm

#endif
