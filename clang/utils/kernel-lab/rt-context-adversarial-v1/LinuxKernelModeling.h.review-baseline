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
#include "llvm/ADT/FoldingSet.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState_Fwd.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include <optional>

namespace clang {
class Expr;
namespace ento {

class CheckerContext;
class CheckerManager;

namespace linuxkernel {

enum class LockKind { Spin, Mutex, RWSem, RTSpin, RTRW };

/// RT spin/rw locks preserve task state while waiting. They are not ordinary
/// sleeping operations and do not create a raw atomic section.
inline bool isRTLock(LockKind Kind) {
  return Kind == LockKind::RTSpin || Kind == LockKind::RTRW;
}

enum class ContextOp { None, Enter, Leave, IRQDisable, IRQEnable, IRQSave,
                       IRQRestore, IRQQuery, IRQSample, IRQFlagsQuery };
enum class ContextKind { Preempt, BottomHalf, RCU, Migration, HardIRQ, NMI };
struct ContextCall {
  ContextOp Op = ContextOp::None;
  ContextKind Kind = ContextKind::Preempt;
};
ContextCall classifyContextCall(llvm::StringRef Name);

/// Unknown is intentional: an arbitrary analyzed function is not proof of an
/// IRQ-enabled entry point. Save/restore preserves the sampled symbolic state.
enum class IRQMode : unsigned { Unknown, Enabled, Disabled };
struct IRQState {
  IRQMode Mode = IRQMode::Unknown;
  const Expr *Entry = nullptr;
  bool operator==(const IRQState &Other) const {
    return Mode == Other.Mode && Entry == Other.Entry;
  }
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(static_cast<unsigned>(Mode));
    ID.AddPointer(Entry);
  }
};
IRQState getIRQState(ProgramStateRef State);
ProgramStateRef setIRQState(ProgramStateRef State, IRQState IRQ);

/// Canonicalize flags through integral casts only when no source bits were
/// lost. Saved snapshots survive IRQ-state effects; current-sample associations
/// do not. A sample alone does not create an outstanding save or mask IRQs.
SymbolRef getIRQFlagsSymbol(ProgramStateRef State, SymbolRef Flags);
std::optional<IRQState> getSavedIRQState(ProgramStateRef State, SymbolRef Flags);
ProgramStateRef storeSavedIRQState(ProgramStateRef State, SymbolRef Flags,
                                  IRQState IRQ);

/// Exit-state facts for the paired-path context-balance checker. Unknown
/// effects cannot serve as a proved balanced or unbalanced exit.
struct ContextBalanceFacts {
  unsigned BottomHalfDepth = 0;
  bool BottomHalfUnknown = false;
  unsigned IRQSaveDepth = 0;
  bool IRQSaveUnknown = false;
};
ContextBalanceFacts getContextBalanceFacts(ProgramStateRef State);

/// x86 restores only enable interrupts when the saved state was enabled.
/// The abstract local_irq_restore API retains its full-restore contract.
bool isEnableOnlyIRQRestore(llvm::StringRef Name, const CheckerContext &C);

/// What a call does to the lock that is its first argument.
enum class LockOp {
  None,
  Acquire,           ///< returns with the lock held
  TryAcquire,        ///< holds the lock if the result is not zero
  AcquireOrError,    ///< holds the lock if the result is zero
  AcquireAndRelease, ///< waits for the lock, but returns with it released
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

/// Enable the shared RT context effects only for an explicitly enabled
/// alpha.linux.AtomicSleep:RTContext option.
void enableRTContext(CheckerManager &Mgr);
bool isRTContextEnabled(const CheckerContext &C);

} // namespace linuxkernel
} // namespace ento
} // namespace clang

#endif
