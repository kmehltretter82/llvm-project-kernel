//===- LinuxKernelModeling.h - Shared by the Linux kernel checkers -*- C++ -*-//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// What the alpha.linux checkers agree on: which functions take and release
// locks, and which checkers are interested in a function at all.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_LINUXKERNELMODELING_H
#define LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_LINUXKERNELMODELING_H

#include "llvm/ADT/StringRef.h"

namespace clang {
namespace ento {

class CheckerManager;

namespace linuxkernel {

enum class LockKind { Spin, Mutex, RWSem };

/// What a call does to the lock that is its first argument.
enum class LockOp {
  None,
  Acquire,        ///< returns with the lock held
  TryAcquire,     ///< holds the lock if the result is not zero
  AcquireOrError, ///< holds the lock if the result is zero
  Release,
};

struct LockCall {
  LockOp Op = LockOp::None;
  LockKind Kind = LockKind::Spin;
};

/// The role of the out-of-line function \p Name.  The inline wrappers such
/// as spin_lock() are not listed: they end in one of these.
LockCall classifyLockCall(llvm::StringRef Name);

/// Whether \p Name returns a device tree node with a reference that the
/// caller has to drop with of_node_put().  \p Consumed is the index of the
/// argument whose reference the function drops, or -1.
bool acquiresNodeReference(llvm::StringRef Name, int &Consumed);

/// What a checker needs in a function to be able to report something.
enum Interest : unsigned {
  AtomicSections = 1, ///< a spinlock, RCU, preemption or bottom half section
  Locks = 2,          ///< a spinlock, mutex or rwsem that is taken
  NodeReferences = 4, ///< a device tree node that is looked up
};

/// Tell alpha.linux.KernelModel that an enabled checker has this interest.
void addInterest(CheckerManager &Mgr, unsigned Mask);

} // namespace linuxkernel
} // namespace ento
} // namespace clang

#endif
