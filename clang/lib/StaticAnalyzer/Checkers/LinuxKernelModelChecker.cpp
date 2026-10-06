//===- LinuxKernelModelChecker.cpp - Linux kernel modeling ----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The base of the alpha.linux checkers.  It reports nothing.  It evaluates
// the out-of-line lock functions, so that taking a lock does not make the
// analyzer forget the object that the lock lives in, and it has two options
// that make a sweep over a whole kernel affordable:
//
//   SkipIrrelevant         Do not analyze a function in which no enabled
//                          alpha.linux checker can have anything to report.
//   LikelyStaticBranches   Take a static branch the way its likely() or
//                          unlikely() annotation says instead of both ways.
//                          Every kmalloc() and every tracepoint has one, and
//                          each doubles the number of paths.
//
//===----------------------------------------------------------------------===//

#include "LinuxKernelModeling.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSwitch.h"

using namespace clang;
using namespace ento;
using namespace linuxkernel;

LockCall linuxkernel::classifyLockCall(StringRef Name) {
  using K = LockKind;
  using O = LockOp;
  return llvm::StringSwitch<LockCall>(Name)
      // The "__raw" forms are the inline versions that some configurations
      // use instead of the out-of-line ones.
      .Cases({"_raw_spin_lock", "_raw_spin_lock_bh", "_raw_spin_lock_irq",
              "_raw_spin_lock_irqsave", "_raw_spin_lock_nested",
              "_raw_spin_lock_nest_lock", "_raw_spin_lock_irqsave_nested"},
             {O::Acquire, K::Spin})
      .Cases({"_raw_read_lock", "_raw_read_lock_bh", "_raw_read_lock_irq",
              "_raw_read_lock_irqsave", "_raw_write_lock",
              "_raw_write_lock_bh", "_raw_write_lock_irq",
              "_raw_write_lock_irqsave", "_raw_write_lock_nested"},
             {O::Acquire, K::Spin})
      .Cases({"__raw_spin_lock", "__raw_spin_lock_bh", "__raw_spin_lock_irq",
              "__raw_spin_lock_irqsave", "__raw_read_lock",
              "__raw_read_lock_bh", "__raw_read_lock_irq",
              "__raw_read_lock_irqsave", "__raw_write_lock",
              "__raw_write_lock_bh", "__raw_write_lock_irq",
              "__raw_write_lock_irqsave"},
             {O::Acquire, K::Spin})
      .Cases({"_raw_spin_trylock", "_raw_spin_trylock_bh", "_raw_read_trylock",
              "_raw_write_trylock", "__raw_spin_trylock",
              "__raw_spin_trylock_bh", "__raw_read_trylock",
              "__raw_write_trylock"},
             {O::TryAcquire, K::Spin})
      .Cases({"_raw_spin_unlock", "_raw_spin_unlock_bh", "_raw_spin_unlock_irq",
              "_raw_spin_unlock_irqrestore", "_raw_read_unlock",
              "_raw_read_unlock_bh", "_raw_read_unlock_irq",
              "_raw_read_unlock_irqrestore", "_raw_write_unlock",
              "_raw_write_unlock_bh", "_raw_write_unlock_irq",
              "_raw_write_unlock_irqrestore"},
             {O::Release, K::Spin})
      .Cases({"__raw_spin_unlock", "__raw_spin_unlock_bh",
              "__raw_spin_unlock_irq", "__raw_spin_unlock_irqrestore",
              "__raw_read_unlock", "__raw_read_unlock_bh",
              "__raw_read_unlock_irq", "__raw_read_unlock_irqrestore",
              "__raw_write_unlock", "__raw_write_unlock_bh",
              "__raw_write_unlock_irq", "__raw_write_unlock_irqrestore"},
             {O::Release, K::Spin})
      .Cases({"mutex_lock", "mutex_lock_nested", "mutex_lock_io",
              "mutex_lock_io_nested", "_mutex_lock_nest_lock"},
             {O::Acquire, K::Mutex})
      .Cases({"mutex_lock_interruptible", "mutex_lock_interruptible_nested",
              "mutex_lock_killable", "mutex_lock_killable_nested"},
             {O::AcquireOrError, K::Mutex})
      .Cases({"mutex_trylock", "_mutex_trylock_nest_lock"},
             {O::TryAcquire, K::Mutex})
      .Case("mutex_unlock", {O::Release, K::Mutex})
      .Cases({"down_read", "down_read_nested", "down_write",
              "down_write_nested"},
             {O::Acquire, K::RWSem})
      .Cases({"down_read_interruptible", "down_read_killable",
              "down_write_killable", "down_write_killable_nested"},
             {O::AcquireOrError, K::RWSem})
      .Cases({"down_read_trylock", "down_write_trylock"},
             {O::TryAcquire, K::RWSem})
      .Cases({"up_read", "up_write"}, {O::Release, K::RWSem})
      .Default(LockCall());
}

bool linuxkernel::acquiresNodeReference(StringRef Name, int &Consumed) {
  // -2: not an acquiring function.
  Consumed = llvm::StringSwitch<int>(Name)
                 // "from": the search starts after this node and drops it.
                 .Cases({"of_find_node_by_name", "of_find_node_by_type",
                         "of_find_compatible_node",
                         "of_find_matching_node_and_match",
                         "of_find_node_with_property", "of_get_next_parent"},
                        0)
                 // "prev": the iteration drops the node it comes from.
                 .Cases({"of_get_next_child", "of_get_next_available_child",
                         "of_get_next_reserved_child",
                         "of_graph_get_next_endpoint"},
                        1)
                 .Cases({"of_find_node_by_phandle",
                         "of_find_node_opts_by_path", "of_get_parent",
                         "of_get_child_by_name",
                         "of_get_available_child_by_name",
                         "of_get_compatible_child", "of_get_cpu_node",
                         "of_parse_phandle"},
                        -1)
                 .Cases({"of_graph_get_remote_endpoint",
                         "of_graph_get_port_parent",
                         "of_graph_get_remote_port_parent",
                         "of_graph_get_remote_port", "of_graph_get_port_by_id",
                         "of_graph_get_endpoint_by_regs",
                         "of_graph_get_remote_node"},
                        -1)
                 .Default(-2);
  return Consumed != -2;
}

namespace {

class LinuxKernelModelChecker
    : public Checker<eval::Call, check::BeginFunction> {
  /// Whether a function, with everything it calls that has a body, can make
  /// an enabled checker report something.
  mutable llvm::DenseMap<const FunctionDecl *, bool> Relevant;

  bool isTrigger(StringRef Name) const;
  bool isRelevant(const FunctionDecl *FD, unsigned Depth) const;

public:
  bool SkipIrrelevant = false;
  bool LikelyStaticBranches = false;
  unsigned Interests = 0;

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBeginFunction(CheckerContext &C) const;
};

} // namespace

bool LinuxKernelModelChecker::isTrigger(StringRef Name) const {
  LockCall LC = classifyLockCall(Name);
  bool Acquires = LC.Op != LockOp::None && LC.Op != LockOp::Release;
  if (Acquires && (Interests & Locks))
    return true;
  if (Interests & AtomicSections) {
    if (Acquires && LC.Kind == LockKind::Spin)
      return true;
    if (llvm::StringSwitch<bool>(Name)
            .Cases({"__rcu_read_lock", "preempt_count_add",
                    "__preempt_count_add", "__local_bh_disable_ip"},
                   true)
            .Default(false))
      return true;
  }
  int Consumed;
  return (Interests & NodeReferences) && acquiresNodeReference(Name, Consumed);
}

bool LinuxKernelModelChecker::isRelevant(const FunctionDecl *FD,
                                         unsigned Depth) const {
  const FunctionDecl *Def = nullptr;
  if (!FD->hasBody(Def))
    return false;
  auto Known = Relevant.find(Def);
  if (Known != Relevant.end())
    return Known->second;
  if (Depth > 8)
    return true;
  // The provisional answer ends recursion.
  Relevant[Def] = false;

  bool Result = false;
  llvm::SmallVector<const Stmt *, 32> Worklist;
  Worklist.push_back(Def->getBody());
  while (!Worklist.empty() && !Result) {
    const Stmt *S = Worklist.pop_back_val();
    if (!S)
      continue;
    if (const auto *CE = dyn_cast<CallExpr>(S))
      if (const FunctionDecl *Callee = CE->getDirectCallee())
        Result = (Callee->getIdentifier() && isTrigger(Callee->getName())) ||
                 isRelevant(Callee, Depth + 1);
    for (const Stmt *Child : S->children())
      Worklist.push_back(Child);
  }
  Relevant[Def] = Result;
  return Result;
}

void LinuxKernelModelChecker::checkBeginFunction(CheckerContext &C) const {
  if (!SkipIrrelevant || !Interests || !C.inTopFrame())
    return;
  const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getStackFrame()->getDecl());
  if (FD && !isRelevant(FD, 0))
    C.generateSink(C.getState(), C.getPredecessor());
}

bool LinuxKernelModelChecker::evalCall(const CallEvent &Call,
                                       CheckerContext &C) const {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  const Expr *Origin = Call.getOriginExpr();
  if (!FD || !FD->getIdentifier() || !Origin ||
      !FD->getDeclContext()->isFileContext())
    return false;
  StringRef Name = FD->getName();
  ProgramStateRef State = C.getState();

  // static_branch_likely() negates the result and static_branch_unlikely()
  // does not, so "not taken" follows the annotation in both.
  if (LikelyStaticBranches &&
      (Name == "arch_static_branch" || Name == "arch_static_branch_jump")) {
    C.addTransition(State->BindExpr(
        Origin, C.getStackFrame(),
        C.getSValBuilder().makeTruthVal(false, Call.getResultType())));
    return true;
  }

  // The out-of-line lock functions change nothing but the lock.  Evaluated
  // conservatively, spin_lock(&dev->lock) makes the analyzer forget every
  // field of *dev, and with it conditions like "if (dev->flags & ATOMIC)"
  // that decide between a spinlock and a mutex and later between a busy wait
  // and a sleep.
  bool EntersOrLeaves =
      llvm::StringSwitch<bool>(Name)
          .Cases({"__rcu_read_lock", "__rcu_read_unlock", "preempt_count_add",
                  "preempt_count_sub", "__local_bh_disable_ip",
                  "__local_bh_enable_ip"},
                 true)
          .Default(false);
  if (FD->hasBody() ||
      (classifyLockCall(Name).Op == LockOp::None && !EntersOrLeaves))
    return false;
  if (!Call.getResultType()->isVoidType())
    State = State->BindExpr(
        Origin, C.getStackFrame(),
        C.getSValBuilder().conjureSymbolVal(Call, C.blockCount()));
  C.addTransition(State);
  return true;
}

void linuxkernel::addInterest(CheckerManager &Mgr, unsigned Mask) {
  Mgr.getChecker<LinuxKernelModelChecker>()->Interests |= Mask;
}

void ento::registerLinuxKernelModelChecker(CheckerManager &Mgr) {
  auto *Checker = Mgr.registerChecker<LinuxKernelModelChecker>();
  const AnalyzerOptions &Opts = Mgr.getAnalyzerOptions();
  Checker->SkipIrrelevant =
      Opts.getCheckerBooleanOption(Checker, "SkipIrrelevant");
  Checker->LikelyStaticBranches =
      Opts.getCheckerBooleanOption(Checker, "LikelyStaticBranches");
}

bool ento::shouldRegisterLinuxKernelModelChecker(const CheckerManager &Mgr) {
  return true;
}
