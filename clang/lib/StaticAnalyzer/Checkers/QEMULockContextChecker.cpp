//=== QEMULockContextChecker.cpp - Track QEMU lock contexts -----*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This checker complements QEMU's existing Clang thread-safety annotations.
// It tracks the two global execution contexts that cannot be expressed by
// those annotations today: RCU read-side critical sections and the Big QEMU
// Lock (BQL).  Only context changes visible on the current path are used for
// diagnostics, so a function may legitimately inherit either context from its
// caller.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "llvm/ADT/StringSwitch.h"
#include <algorithm>
#include <utility>

using namespace clang;
using namespace ento;

namespace {

enum class ContextKind { RCU, BQL };

enum class BQLKnowledge : unsigned { Unknown, Held, Released };

enum class CallRole {
  None,
  RCUEnter,
  RCUAutoEnter,
  RCULeave,
  RCUAutoLeave,
  RCUCleanup,
  RCUBarrier,
  RCUUnregister,
  BQLEnter,
  BQLAutoEnter,
  BQLLeave,
  BQLAutoLeave,
  BQLCleanup,
  BQLRequire,
};

static CallRole classify(StringRef Name) {
  return llvm::StringSwitch<CallRole>(Name)
      .Case("rcu_read_lock", CallRole::RCUEnter)
      .Case("rcu_read_auto_lock", CallRole::RCUAutoEnter)
      .Case("rcu_read_unlock", CallRole::RCULeave)
      .Case("rcu_read_auto_unlock", CallRole::RCUAutoLeave)
      .Case("glib_autoptr_cleanup_RCUReadAuto", CallRole::RCUCleanup)
      .Cases({"synchronize_rcu", "drain_call_rcu"}, CallRole::RCUBarrier)
      .Case("rcu_unregister_thread", CallRole::RCUUnregister)
      .Case("bql_lock_impl", CallRole::BQLEnter)
      .Case("bql_auto_lock", CallRole::BQLAutoEnter)
      .Case("bql_unlock", CallRole::BQLLeave)
      .Case("bql_auto_unlock", CallRole::BQLAutoLeave)
      .Case("glib_autoptr_cleanup_BQLLockAuto", CallRole::BQLCleanup)
      .Cases({"qemu_cond_wait_bql", "qemu_cond_timedwait_bql"},
             CallRole::BQLRequire)
      .Cases({"bql_block_unlock", "bdrv_graph_wrlock",
              "bdrv_graph_wrlock_drained"},
             CallRole::BQLRequire)
      .Cases({"bdrv_graph_wrunlock", "bdrv_graph_rdlock_main_loop",
              "bdrv_graph_rdunlock_main_loop"},
             CallRole::BQLRequire)
      .Cases({"graph_lockable_auto_lock_mainloop",
              "graph_lockable_auto_unlock_mainloop"},
             CallRole::BQLRequire)
      .Default(CallRole::None);
}

static const FunctionDecl *getCallee(const CallEvent &Call) {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD || !FD->getIdentifier() || !FD->getDeclContext()->isFileContext())
    return nullptr;
  return FD;
}

static bool hasAnnotation(const FunctionDecl *FD, StringRef Annotation) {
  if (!FD)
    return false;
  for (const FunctionDecl *Redecl : FD->getCanonicalDecl()->redecls())
    for (const auto *A : Redecl->specific_attrs<AnnotateAttr>())
      if (A->getAnnotation() == Annotation)
        return true;
  return false;
}

static bool allowsContextEscape(const FunctionDecl *FD, ContextKind Kind) {
  if (!FD || !FD->getIdentifier())
    return false;
  StringRef Annotation = Kind == ContextKind::RCU
                             ? "qemu::returns_with_rcu_read_lock"
                             : "qemu::returns_with_bql";
  if (hasAnnotation(FD, Annotation))
    return true;

  StringRef Name = FD->getName();
  if (Kind == ContextKind::RCU)
    return Name == "rcu_read_auto_lock" || Name == "qemu_log_trylock_with_err";
  return Name == "bql_auto_lock" || Name == "prepare_mmio_access" ||
         Name == "qemu_init_subsystems";
}

} // namespace

REGISTER_TRAIT_WITH_PROGRAMSTATE(QEMURCUBalance, int)
REGISTER_TRAIT_WITH_PROGRAMSTATE(QEMUBQLBalance, int)
REGISTER_TRAIT_WITH_PROGRAMSTATE(QEMURCUOrigin, const Expr *)
REGISTER_TRAIT_WITH_PROGRAMSTATE(QEMUBQLOrigin, const Expr *)
REGISTER_TRAIT_WITH_PROGRAMSTATE(QEMUBQLKnowledge, BQLKnowledge)
REGISTER_TRAIT_WITH_PROGRAMSTATE(QEMURCUViolation, bool)
REGISTER_TRAIT_WITH_PROGRAMSTATE(QEMUBQLViolation, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUInCoroutineResults, const StackFrame *,
                               SymbolRef)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUStableKVMIRQChipResults, const StackFrame *,
                               SymbolRef)

namespace {

class QEMULockContextChecker
    : public Checker<check::PreCall, check::PostCall, check::Location,
                     check::Bind, check::EndFunction, check::LiveSymbols> {
  const BugType BalanceBug{this, "Unbalanced QEMU execution context",
                           "QEMU lock context"};
  const BugType ContextBug{this, "Invalid QEMU execution context",
                           "QEMU lock context"};

  static int getBalance(ProgramStateRef State, ContextKind Kind) {
    return Kind == ContextKind::RCU ? State->get<QEMURCUBalance>()
                                    : State->get<QEMUBQLBalance>();
  }

  static const Expr *getOrigin(ProgramStateRef State, ContextKind Kind) {
    return Kind == ContextKind::RCU ? State->get<QEMURCUOrigin>()
                                    : State->get<QEMUBQLOrigin>();
  }

  static ProgramStateRef setBalance(ProgramStateRef State, ContextKind Kind,
                                    int Balance, const Expr *Origin) {
    if (Kind == ContextKind::RCU) {
      State = Balance ? State->set<QEMURCUBalance>(Balance)
                      : State->remove<QEMURCUBalance>();
      return Origin ? State->set<QEMURCUOrigin>(Origin)
                    : State->remove<QEMURCUOrigin>();
    }
    State = Balance ? State->set<QEMUBQLBalance>(Balance)
                    : State->remove<QEMUBQLBalance>();
    return Origin ? State->set<QEMUBQLOrigin>(Origin)
                  : State->remove<QEMUBQLOrigin>();
  }

  static ProgramStateRef enter(ProgramStateRef State, ContextKind Kind,
                               const Expr *At) {
    int Old = getBalance(State, Kind);
    int New = std::min(Old + 1, 8);
    const Expr *Origin = getOrigin(State, Kind);
    if (Old <= 0 && New > 0)
      Origin = At;
    if (New <= 0)
      Origin = nullptr;
    return setBalance(State, Kind, New, Origin);
  }

  static ProgramStateRef leave(ProgramStateRef State, ContextKind Kind) {
    int Old = getBalance(State, Kind);
    int New = std::max(Old - 1, -8);
    const Expr *Origin = New > 0 ? getOrigin(State, Kind) : nullptr;
    return setBalance(State, Kind, New, Origin);
  }

  static SVal cleanupValue(const CallEvent &Call, ProgramStateRef State,
                           bool Indirect) {
    if (!Call.getNumArgs())
      return UnknownVal();
    SVal Value = Call.getArgSVal(0);
    if (!Indirect)
      return Value;
    const MemRegion *Region = Value.getAsRegion();
    return Region ? State->getSVal(Region) : UnknownVal();
  }

  static std::pair<ProgramStateRef, ProgramStateRef>
  assumeActive(ProgramStateRef State, SVal Value) {
    std::optional<DefinedOrUnknownSVal> DV =
        Value.getAs<DefinedOrUnknownSVal>();
    if (!DV)
      return {State, nullptr};
    return State->assume(*DV);
  }

  void reportCall(const BugType &Type, StringRef Message, const CallEvent &Call,
                  ContextKind Kind, CheckerContext &C) const {
    ProgramStateRef ErrorState = C.getState();
    ErrorState = Kind == ContextKind::RCU
                     ? ErrorState->set<QEMURCUViolation>(true)
                     : ErrorState->set<QEMUBQLViolation>(true);
    ExplodedNode *N = C.generateNonFatalErrorNode(ErrorState);
    if (!N)
      return;
    auto R = std::make_unique<PathSensitiveBugReport>(Type, Message, N);
    if (const Expr *At = Call.getOriginExpr())
      R->addRange(At->getSourceRange());
    if (const Expr *Origin = getOrigin(C.getState(), Kind)) {
      StringRef Note = Kind == ContextKind::RCU
                           ? "RCU read-side critical section entered here"
                           : "BQL acquired here";
      R->addNote(Note, {Origin, C.getSourceManager(), C.getStackFrame()});
    }
    C.emitReport(std::move(R));
  }

  void reportLeaks(const ReturnStmt *RS, ProgramStateRef State,
                   CheckerContext &C, bool ReportRCU, bool ReportBQL) const {
    ExplodedNode *N = C.generateNonFatalErrorNode(State);
    if (!N)
      return;
    auto Emit = [&](ContextKind Kind, StringRef Message) {
      auto R = std::make_unique<PathSensitiveBugReport>(BalanceBug, Message, N);
      if (RS)
        R->addRange(RS->getSourceRange());
      if (const Expr *Origin = getOrigin(State, Kind)) {
        StringRef Note = Kind == ContextKind::RCU
                             ? "RCU read-side critical section entered here"
                             : "BQL acquired here";
        R->addNote(Note, {Origin, C.getSourceManager(), C.getStackFrame()});
      }
      C.emitReport(std::move(R));
    };
    if (ReportRCU)
      Emit(ContextKind::RCU,
           "QEMU RCU read-side critical section is not exited on this path");
    if (ReportBQL)
      Emit(ContextKind::BQL,
           "BQL acquired in this function is not released on this path");
  }

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, bool AtDeclInit,
                 CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkLiveSymbols(ProgramStateRef State, SymbolReaper &SymReaper) const;
};

static bool isKVMKernelIRQChipRegion(const MemRegion *Region) {
  const auto *VR = dyn_cast_or_null<VarRegion>(Region);
  const auto *VD = VR ? dyn_cast<VarDecl>(VR->getDecl()) : nullptr;
  return VD && VD->getIdentifier() && VD->hasGlobalStorage() &&
         VD->getDeclContext()->isFileContext() &&
         VD->getName() == "kvm_kernel_irqchip";
}

void QEMULockContextChecker::checkPreCall(const CallEvent &Call,
                                          CheckerContext &C) const {
  const FunctionDecl *FD = getCallee(Call);
  if (!FD)
    return;
  CallRole Role = classify(FD->getName());
  ProgramStateRef State = C.getState();

  if (Role == CallRole::RCUBarrier && getBalance(State, ContextKind::RCU) > 0) {
    reportCall(ContextBug,
               "RCU grace-period wait is called inside a QEMU RCU read-side "
               "critical section",
               Call, ContextKind::RCU, C);
    return;
  }
  if (Role == CallRole::RCUUnregister &&
      getBalance(State, ContextKind::RCU) > 0) {
    reportCall(ContextBug,
               "RCU thread is unregistered inside a QEMU RCU read-side "
               "critical section",
               Call, ContextKind::RCU, C);
    return;
  }
  if ((Role == CallRole::BQLEnter) &&
      State->get<QEMUBQLKnowledge>() == BQLKnowledge::Held) {
    reportCall(ContextBug, "BQL is acquired again while already held", Call,
               ContextKind::BQL, C);
    return;
  }
  if ((Role == CallRole::BQLLeave) &&
      State->get<QEMUBQLKnowledge>() == BQLKnowledge::Released) {
    reportCall(ContextBug,
               "BQL is released again after it was already released", Call,
               ContextKind::BQL, C);
    return;
  }
  if (Role == CallRole::BQLRequire &&
      State->get<QEMUBQLKnowledge>() == BQLKnowledge::Released) {
    reportCall(ContextBug,
               ("Call to '" + FD->getName() +
                "' requires the BQL after this path released it")
                   .str(),
               Call, ContextKind::BQL, C);
    return;
  }

  switch (Role) {
  case CallRole::RCULeave:
    C.addTransition(leave(State, ContextKind::RCU));
    return;
  case CallRole::RCUAutoLeave:
  case CallRole::RCUCleanup: {
    auto [Active, Inactive] = assumeActive(
        State, cleanupValue(Call, State, Role == CallRole::RCUCleanup));
    if (Active)
      C.addTransition(leave(Active, ContextKind::RCU));
    if (Inactive)
      C.addTransition(Inactive);
    return;
  }
  case CallRole::BQLLeave:
    State = leave(State, ContextKind::BQL)
                ->set<QEMUBQLKnowledge>(BQLKnowledge::Released);
    C.addTransition(State);
    return;
  case CallRole::BQLAutoLeave:
  case CallRole::BQLCleanup: {
    auto [Active, Inactive] = assumeActive(
        State, cleanupValue(Call, State, Role == CallRole::BQLCleanup));
    if (Active) {
      Active = leave(Active, ContextKind::BQL)
                   ->set<QEMUBQLKnowledge>(BQLKnowledge::Released);
      C.addTransition(Active);
    }
    if (Inactive)
      C.addTransition(Inactive);
    return;
  }
  default:
    return;
  }
}

void QEMULockContextChecker::checkPostCall(const CallEvent &Call,
                                           CheckerContext &C) const {
  const FunctionDecl *FD = getCallee(Call);
  if (!FD)
    return;
  ProgramStateRef State = C.getState();

  // Whether a QEMU function is running in coroutine context cannot change
  // during one invocation.  Treat repeated queries in the same stack frame
  // as the same value instead of letting the analyzer independently choose a
  // result for every call.
  if (FD->getName() == "qemu_in_coroutine") {
    SymbolRef Current = Call.getReturnValue().getAsSymbol();
    if (!Current)
      return;

    const StackFrame *Frame = C.getStackFrame();
    if (const SymbolRef *Previous = State->get<QEMUInCoroutineResults>(Frame)) {
      DefinedOrUnknownSVal Equal = C.getSValBuilder().evalEQ(
          State, nonloc::SymbolVal(*Previous), nonloc::SymbolVal(Current));
      if (ProgramStateRef Consistent = State->assume(Equal, true))
        C.addTransition(Consistent);
    } else {
      C.addTransition(State->set<QEMUInCoroutineResults>(Frame, Current));
    }
    return;
  }

  CallRole Role = classify(FD->getName());
  const Expr *At = Call.getOriginExpr();

  if (Role == CallRole::RCUEnter) {
    C.addTransition(enter(State, ContextKind::RCU, At));
    return;
  }
  if (Role == CallRole::RCUAutoEnter) {
    auto [NonNull, Null] = assumeActive(State, Call.getReturnValue());
    if (NonNull)
      C.addTransition(enter(NonNull, ContextKind::RCU, At));
    return;
  }
  if (Role == CallRole::BQLEnter) {
    State = enter(State, ContextKind::BQL, At)
                ->set<QEMUBQLKnowledge>(BQLKnowledge::Held);
    C.addTransition(State);
    return;
  }
  if (Role == CallRole::BQLAutoEnter) {
    auto [Acquired, AlreadyHeld] = assumeActive(State, Call.getReturnValue());
    if (Acquired) {
      Acquired = enter(Acquired, ContextKind::BQL, At)
                     ->set<QEMUBQLKnowledge>(BQLKnowledge::Held);
      C.addTransition(Acquired);
    }
    if (AlreadyHeld) {
      AlreadyHeld = AlreadyHeld->set<QEMUBQLKnowledge>(BQLKnowledge::Held);
      C.addTransition(AlreadyHeld);
    }
  }
}

void QEMULockContextChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                           CheckerContext &C) const {
  if (!IsLoad || !isKVMKernelIRQChipRegion(Loc.getAsRegion()))
    return;

  ProgramStateRef State = C.getState();
  SymbolRef Current = State->getSVal(Loc.getAsRegion()).getAsSymbol();
  if (!Current)
    return;

  // kvm_kernel_irqchip is configuration established during KVM
  // initialization.  Calls made while handling a vCPU exit cannot change it,
  // but the generic RegionStore invalidates globals across those calls.  Keep
  // repeated reads in one stack frame consistent while still forgetting the
  // value on an explicit write (see checkBind).
  const StackFrame *Frame = C.getStackFrame();
  if (const SymbolRef *Previous =
          State->get<QEMUStableKVMIRQChipResults>(Frame)) {
    DefinedOrUnknownSVal Equal = C.getSValBuilder().evalEQ(
        State, nonloc::SymbolVal(*Previous), nonloc::SymbolVal(Current));
    if (ProgramStateRef Consistent = State->assume(Equal, true))
      C.addTransition(Consistent);
    return;
  }

  C.addTransition(State->set<QEMUStableKVMIRQChipResults>(Frame, Current));
}

void QEMULockContextChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                       bool AtDeclInit,
                                       CheckerContext &C) const {
  if (!isKVMKernelIRQChipRegion(Loc.getAsRegion()))
    return;

  ProgramStateRef State = C.getState();
  ProgramStateRef Updated =
      State->remove<QEMUStableKVMIRQChipResults>(C.getStackFrame());
  if (Updated != State)
    C.addTransition(Updated);
}

void QEMULockContextChecker::checkEndFunction(const ReturnStmt *RS,
                                              CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  ProgramStateRef ExitState =
      State->remove<QEMUInCoroutineResults>(C.getStackFrame());
  ExitState = ExitState->remove<QEMUStableKVMIRQChipResults>(C.getStackFrame());
  int RCUBalance = getBalance(State, ContextKind::RCU);
  int BQLBalance = getBalance(State, ContextKind::BQL);
  bool ReportRCU = RCUBalance > 0;
  bool ReportBQL = BQLBalance > 0;
  ReportRCU &= !State->get<QEMURCUViolation>();
  ReportBQL &= !State->get<QEMUBQLViolation>();

  const auto *FD = dyn_cast<FunctionDecl>(C.getStackFrame()->getDecl());
  if (RCUBalance == 1 && allowsContextEscape(FD, ContextKind::RCU))
    ReportRCU = false;
  if (BQLBalance == 1 && allowsContextEscape(FD, ContextKind::BQL))
    ReportBQL = false;
  if (ReportRCU || ReportBQL)
    reportLeaks(RS, ExitState, C, ReportRCU, ReportBQL);
  else if (ExitState != State)
    C.addTransition(ExitState);
}

void QEMULockContextChecker::checkLiveSymbols(ProgramStateRef State,
                                              SymbolReaper &SymReaper) const {
  for (const auto &Entry : State->get<QEMUInCoroutineResults>())
    SymReaper.markLive(Entry.second);
  for (const auto &Entry : State->get<QEMUStableKVMIRQChipResults>())
    SymReaper.markLive(Entry.second);
}

} // namespace

void ento::registerQEMULockContextChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<QEMULockContextChecker>();
}

bool ento::shouldRegisterQEMULockContextChecker(const CheckerManager &Mgr) {
  return true;
}
