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
#include "clang/Basic/TargetInfo.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSwitch.h"

using namespace clang;
using namespace ento;
using namespace linuxkernel;

REGISTER_TRAIT_WITH_PROGRAMSTATE(LinuxIRQMode, unsigned)
REGISTER_TRAIT_WITH_PROGRAMSTATE(LinuxIRQEntry, const Expr *)
REGISTER_MAP_WITH_PROGRAMSTATE(LinuxIRQQueries, SymbolRef, const Expr *)
REGISTER_MAP_WITH_PROGRAMSTATE(LinuxSavedIRQStates, SymbolRef, IRQState)
REGISTER_MAP_WITH_PROGRAMSTATE(LinuxCurrentIRQSamples, SymbolRef, const Expr *)

IRQState linuxkernel::getIRQState(ProgramStateRef State) {
  return {static_cast<IRQMode>(State->get<LinuxIRQMode>()),
          State->get<LinuxIRQEntry>()};
}

ProgramStateRef linuxkernel::setIRQState(ProgramStateRef State, IRQState IRQ) {
  // A cached query describes the IRQ state at its call, not after a later
  // disable, enable or restore. Keep its ordinary value constraints, but stop
  // using it to infer the current state after any IRQ-state effect.
  return State->remove<LinuxIRQQueries>()
      ->remove<LinuxCurrentIRQSamples>()
      ->set<LinuxIRQMode>(static_cast<unsigned>(IRQ.Mode))
      ->set<LinuxIRQEntry>(IRQ.Entry);
}

SymbolRef linuxkernel::getIRQFlagsSymbol(ProgramStateRef State, SymbolRef Flags) {
  const ASTContext &Ctx = State->getStateManager().getContext();
  while (const auto *Cast = dyn_cast_or_null<SymbolCast>(Flags)) {
    QualType From = Cast->getOperand()->getType();
    QualType To = Cast->getType();
    if (!From->isIntegralOrEnumerationType() ||
        !To->isIntegralOrEnumerationType() ||
        Ctx.getIntWidth(From) > Ctx.getIntWidth(To))
      break;
    Flags = Cast->getOperand();
  }
  return Flags;
}

std::optional<IRQState> linuxkernel::getSavedIRQState(ProgramStateRef State,
                                                    SymbolRef Flags) {
  Flags = getIRQFlagsSymbol(State, Flags);
  if (Flags)
    if (const IRQState *Saved = State->get<LinuxSavedIRQStates>(Flags))
      return *Saved;
  return std::nullopt;
}

ProgramStateRef linuxkernel::storeSavedIRQState(ProgramStateRef State,
                                               SymbolRef Flags, IRQState IRQ) {
  Flags = getIRQFlagsSymbol(State, Flags);
  return Flags ? State->set<LinuxSavedIRQStates>(Flags, IRQ) : State;
}

bool linuxkernel::isEnableOnlyIRQRestore(StringRef Name,
                                        const CheckerContext &C) {
  if (!C.getASTContext().getTargetInfo().getTriple().isX86())
    return false;
  return Name == "arch_local_irq_restore" ||
         Name == "native_local_irq_restore" ||
         ((Name.starts_with("_raw_") || Name.starts_with("__raw_")) &&
          Name.ends_with("_unlock_irqrestore"));
}

ContextCall linuxkernel::classifyContextCall(StringRef Name) {
  using O = ContextOp;
  using K = ContextKind;
  return llvm::StringSwitch<ContextCall>(Name)
      .Cases({"preempt_count_add", "__preempt_count_add", "preempt_disable"},
             {O::Enter, K::Preempt})
      .Cases({"preempt_count_sub", "__preempt_count_sub",
              "__preempt_count_dec_and_test", "preempt_enable"},
             {O::Leave, K::Preempt})
      .Cases({"__local_bh_disable_ip", "local_bh_disable"},
             {O::Enter, K::BottomHalf})
      .Cases({"__local_bh_enable_ip", "local_bh_enable"},
             {O::Leave, K::BottomHalf})
      .Cases({"__rcu_read_lock", "rcu_read_lock"}, {O::Enter, K::RCU})
      .Cases({"__rcu_read_unlock", "rcu_read_unlock"}, {O::Leave, K::RCU})
      .Case("migrate_disable", {O::Enter, K::Migration})
      .Case("migrate_enable", {O::Leave, K::Migration})
      .Cases({"irq_enter", "__irq_enter", "irq_enter_rcu"},
             {O::Enter, K::HardIRQ})
      .Cases({"irq_exit", "__irq_exit", "irq_exit_rcu"},
             {O::Leave, K::HardIRQ})
      .Cases({"nmi_enter", "__nmi_enter"}, {O::Enter, K::NMI})
      .Cases({"nmi_exit", "__nmi_exit"}, {O::Leave, K::NMI})
      .Cases({"local_irq_disable", "raw_local_irq_disable",
              "arch_local_irq_disable", "native_irq_disable"},
             {O::IRQDisable, K::Preempt})
      .Cases({"local_irq_enable", "raw_local_irq_enable",
              "arch_local_irq_enable", "native_irq_enable"},
             {O::IRQEnable, K::Preempt})
      .Cases({"local_irq_save", "raw_local_irq_save", "arch_local_irq_save",
              "native_local_irq_save"},
             {O::IRQSave, K::Preempt})
      .Cases({"local_irq_restore", "raw_local_irq_restore",
              "arch_local_irq_restore", "native_local_irq_restore"},
             {O::IRQRestore, K::Preempt})
      .Cases({"irqs_disabled", "raw_irqs_disabled", "arch_irqs_disabled"},
             {O::IRQQuery, K::Preempt})
      .Cases({"arch_local_save_flags", "native_save_fl"},
             {O::IRQSample, K::Preempt})
      .Cases({"arch_irqs_disabled_flags", "native_irqs_disabled_flags",
              "raw_irqs_disabled_flags", "irqs_disabled_flags"},
             {O::IRQFlagsQuery, K::Preempt})
      .Default(ContextCall());
}

LockCall linuxkernel::classifyLockCall(StringRef Name) {
  using K = LockKind;
  using O = LockOp;
  return llvm::StringSwitch<LockCall>(Name)
      .Cases({"rt_spin_lock", "rt_spin_lock_nested", "rt_spin_lock_nest_lock"},
             {O::Acquire, K::RTSpin})
      .Cases({"rt_spin_trylock", "rt_spin_trylock_bh"},
             {O::TryAcquire, K::RTSpin})
      .Case("rt_spin_lock_unlock", {O::AcquireAndRelease, K::RTSpin})
      .Case("rt_spin_unlock", {O::Release, K::RTSpin})
      .Cases({"rt_read_lock", "rt_write_lock", "rt_write_lock_nested"},
             {O::Acquire, K::RTRW})
      .Cases({"rt_read_trylock", "rt_write_trylock"},
             {O::TryAcquire, K::RTRW})
      .Cases({"rt_read_unlock", "rt_write_unlock"}, {O::Release, K::RTRW})
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
    : public Checker<eval::Call, eval::Assume, check::DeadSymbols,
                     check::BeginFunction> {
  /// Whether a function, with everything it calls that has a body, can make
  /// an enabled checker report something.
  mutable llvm::DenseMap<const FunctionDecl *, bool> Relevant;

  bool isTrigger(StringRef Name) const;
  bool isRelevant(const FunctionDecl *FD, unsigned Depth) const;

public:
  bool SkipIrrelevant = false;
  bool LikelyStaticBranches = false;
  bool RTContextEnabled = false;
  bool ReviewedContextInputs = false;
  unsigned Interests = 0;

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond,
                            bool Assumption) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;
  void checkBeginFunction(CheckerContext &C) const;
};

} // namespace

bool LinuxKernelModelChecker::isTrigger(StringRef Name) const {
  LockCall LC = classifyLockCall(Name);
  if (isRTLock(LC.Kind) && !RTContextEnabled)
    LC = LockCall();
  bool Acquires = LC.Op != LockOp::None && LC.Op != LockOp::Release;
  if (Acquires && (Interests & Locks))
    return true;
  if (Interests & AtomicSections) {
    if (Acquires && (LC.Kind == LockKind::Spin || isRTLock(LC.Kind)))
      return true;
    if (RTContextEnabled &&
        classifyContextCall(Name).Op != ContextOp::None)
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
  if (!SkipIrrelevant || ReviewedContextInputs || !Interests || !C.inTopFrame())
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
  LockCall LC = classifyLockCall(Name);
  if (isRTLock(LC.Kind) && !RTContextEnabled)
    LC = LockCall();
  ContextCall CC = RTContextEnabled ? classifyContextCall(Name) : ContextCall();
  bool EntersOrLeaves = CC.Op != ContextOp::None ||
      llvm::StringSwitch<bool>(Name)
          .Cases({"__rcu_read_lock", "__rcu_read_unlock", "preempt_count_add",
                  "preempt_count_sub", "__local_bh_disable_ip",
                  "__local_bh_enable_ip"},
                 true)
          .Default(false);
  // Model reviewed effect leaves before their bodies. Their implementations
  // otherwise inline into assembly or accounting details, while wrappers must
  // inline to reach these leaves and avoid applying the same effect twice.
  bool ModelBeforeInline = RTContextEnabled &&
      (CC.Op == ContextOp::IRQDisable || CC.Op == ContextOp::IRQEnable ||
       CC.Op == ContextOp::IRQSave || CC.Op == ContextOp::IRQRestore ||
       CC.Op == ContextOp::IRQQuery || CC.Op == ContextOp::IRQSample ||
       (CC.Op == ContextOp::IRQFlagsQuery &&
        (Name == "arch_irqs_disabled_flags" ||
         Name == "native_irqs_disabled_flags")) ||
       llvm::StringSwitch<bool>(Name)
           .Cases({"preempt_count_add", "__preempt_count_add",
                   "preempt_count_sub", "__preempt_count_sub",
                   "__preempt_count_dec_and_test", "__local_bh_disable_ip",
                   "__local_bh_enable_ip", "__rcu_read_lock",
                   "__rcu_read_unlock", "migrate_disable", "migrate_enable"},
                  true)
           .Default(false));
  if ((FD->hasBody() && !ModelBeforeInline) ||
      (LC.Op == LockOp::None && !EntersOrLeaves))
    return false;
  if (!Call.getResultType()->isVoidType()) {
    IRQMode QueryMode = IRQMode::Unknown;
    bool ReflectsCurrentIRQ = CC.Op == ContextOp::IRQQuery;
    if (ReflectsCurrentIRQ)
      QueryMode = getIRQState(State).Mode;
    else if (CC.Op == ContextOp::IRQFlagsQuery && Call.getNumArgs()) {
      SymbolRef Flags = getIRQFlagsSymbol(State, Call.getArgSVal(0).getAsSymbol());
      if (auto Saved = getSavedIRQState(State, Flags))
        QueryMode = Saved->Mode;
      ReflectsCurrentIRQ = Flags && State->get<LinuxCurrentIRQSamples>(Flags);
    }
    if (QueryMode != IRQMode::Unknown)
      State = State->BindExpr(
          Origin, C.getStackFrame(),
          C.getSValBuilder().makeTruthVal(
              QueryMode == IRQMode::Disabled, Call.getResultType()));
    else {
      SVal Result = C.getSValBuilder().conjureSymbolVal(Call, C.blockCount());
      State = State->BindExpr(Origin, C.getStackFrame(), Result);
      if (CC.Op == ContextOp::IRQSave || CC.Op == ContextOp::IRQSample)
        if (SymbolRef Sym = Result.getAsSymbol()) {
          State = storeSavedIRQState(State, Sym, getIRQState(State));
          if (CC.Op == ContextOp::IRQSample)
            State = State->set<LinuxCurrentIRQSamples>(Sym, Origin);
        }
      if (ReflectsCurrentIRQ) {
        // These predicates return exactly zero or one, even when declared as
        // int. Preserve that range so a comparison with two is unreachable.
        SValBuilder &SVB = C.getSValBuilder();
        QualType Type = Call.getResultType();
        if (Type->isIntegerType()) {
          for (BinaryOperatorKind Op : {BO_GE, BO_LE}) {
            SVal Bound = SVB.makeIntVal(Op == BO_GE ? 0 : 1, Type);
            SVal Test = SVB.evalBinOp(State, Op, Result, Bound,
                                     C.getASTContext().BoolTy);
            if (auto Cond = Test.getAs<DefinedOrUnknownSVal>())
              State = State->assume(*Cond, true);
            if (!State)
              return true;
          }
        }
        if (SymbolRef Sym = Result.getAsSymbol())
          State = State->set<LinuxIRQQueries>(Sym, Origin);
      }
    }
  }
  C.addTransition(State);
  return true;
}

ProgramStateRef LinuxKernelModelChecker::evalAssume(ProgramStateRef State,
                                                   SVal Cond,
                                                   bool Assumption) const {
  if (!RTContextEnabled)
    return State;
  // Consult the constraints after the branch assumption rather than matching
  // only a bare symbol: casts, !query and query == 0 must work as well.
  for (const auto &[Sym, Origin] : State->get<LinuxIRQQueries>()) {
    ConditionTruthVal IsZero = State->isNull(nonloc::SymbolVal(Sym));
    if (IsZero.isUnderconstrained())
      continue;
    IRQMode Mode = IsZero.isConstrainedTrue() ? IRQMode::Enabled
                                             : IRQMode::Disabled;
    IRQState Current = getIRQState(State);
    if (Current.Mode != IRQMode::Unknown && Current.Mode != Mode)
      return nullptr;
    // This refines the sampled state. It is not an IRQ-state effect, so other
    // queries from the same unchanged state must retain their associations.
    State = State->set<LinuxIRQMode>(static_cast<unsigned>(Mode))
                ->set<LinuxIRQEntry>(Current.Entry ? Current.Entry : Origin);
    // A current sample captured this same unchanged state. Preserve the newly
    // proved snapshot for future queries after the sample becomes stale.
    for (const auto &[Flags, Sample] : State->get<LinuxCurrentIRQSamples>())
      if (auto Saved = getSavedIRQState(State, Flags))
        if (Saved->Mode == IRQMode::Unknown)
          State = storeSavedIRQState(
              State, Flags, {Mode, Saved->Entry ? Saved->Entry : Origin});
  }
  return State;
}

void LinuxKernelModelChecker::checkDeadSymbols(SymbolReaper &SR,
                                              CheckerContext &C) const {
  if (!RTContextEnabled)
    return;
  ProgramStateRef State = C.getState();
  for (const auto &[Sym, Origin] : State->get<LinuxIRQQueries>())
    if (SR.isDead(Sym))
      State = State->remove<LinuxIRQQueries>(Sym);
  for (const auto &[Sym, Saved] : State->get<LinuxSavedIRQStates>())
    if (SR.isDead(Sym))
      State = State->remove<LinuxSavedIRQStates>(Sym);
  for (const auto &[Sym, Origin] : State->get<LinuxCurrentIRQSamples>())
    if (SR.isDead(Sym))
      State = State->remove<LinuxCurrentIRQSamples>(Sym);
  if (State != C.getState())
    C.addTransition(State);
}

void linuxkernel::addInterest(CheckerManager &Mgr, unsigned Mask) {
  Mgr.getChecker<LinuxKernelModelChecker>()->Interests |= Mask;
}

void linuxkernel::enableRTContext(CheckerManager &Mgr) {
  auto *Checker = Mgr.getChecker<LinuxKernelModelChecker>();
  Checker->RTContextEnabled = true;
}

bool linuxkernel::isRTContextEnabled(const CheckerContext &C) {
  return C.getAnalysisManager()
      .getCheckerManager()
      ->getChecker<LinuxKernelModelChecker>()
      ->RTContextEnabled;
}

void ento::registerLinuxKernelModelChecker(CheckerManager &Mgr) {
  auto *Checker = Mgr.registerChecker<LinuxKernelModelChecker>();
  const AnalyzerOptions &Opts = Mgr.getAnalyzerOptions();
  Checker->SkipIrrelevant =
      Opts.getCheckerBooleanOption(Checker, "SkipIrrelevant");
  Checker->LikelyStaticBranches =
      Opts.getCheckerBooleanOption(Checker, "LikelyStaticBranches");
  for (StringRef Name : {"alpha.linux.AtomicSleep:RTContextManifest",
                        "alpha.linux.AtomicSleep:RTContextManifestOutput"}) {
    auto I = Opts.Config.find(Name.str());
    if (I != Opts.Config.end() && !I->second.empty())
      Checker->ReviewedContextInputs = true;
  }
}

bool ento::shouldRegisterLinuxKernelModelChecker(const CheckerManager &Mgr) {
  return true;
}
