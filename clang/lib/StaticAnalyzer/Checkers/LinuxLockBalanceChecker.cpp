//===- LinuxLockBalanceChecker.cpp - Locks left held on a return path -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// alpha.linux.LockBalance finds the missed unlock on an error path:
//
//   mutex_lock(&dev->lock);
//   ret = prepare(dev);
//   if (ret)
//     return ret;                 <- still locked
//   ...
//   mutex_unlock(&dev->lock);
//   return 0;
//
// A function that returns with a lock held is not wrong by itself: lock
// helpers do, and so do functions that lock an object and hand it back.  The
// checker therefore compares the return paths of one function.  It reports a
// lock that the function took and still holds where it returns a failure
// while another path releases it, and a lock that is held on one path and
// released on another with the same kind of result.  A lock that is held
// where the function succeeds and released where it fails is taken to be
// what the function is for.
//
// Locks taken by a scoped guard are left alone: the analyzer does not run
// cleanup functions.
//
//===----------------------------------------------------------------------===//

#include "LinuxKernelModeling.h"
#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/MapVector.h"
#include <optional>

using namespace clang;
using namespace ento;
using namespace linuxkernel;

namespace {

struct TrackedLock {
  enum Kind : unsigned {
    Held,     ///< taken on this path and not released
    Released, ///< taken on this path and released again
    Foreign,  ///< released first, so the caller holds it: not ours to judge
  };
  Kind K = Held;
  /// A spinlock, a mutex or a rwsem, and the order in which the path took
  /// its locks.
  unsigned LockKind = 0;
  unsigned Order = 0;

  bool operator==(const TrackedLock &Other) const {
    return K == Other.K && LockKind == Other.LockKind && Order == Other.Order;
  }
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(K);
    ID.AddInteger(LockKind);
    ID.AddInteger(Order);
  }
};

/// What kind of result a return path has.
enum ReturnClass : unsigned { RCVoid, RCFailure, RCSuccess, RCUnknown };

} // namespace

REGISTER_MAP_WITH_PROGRAMSTATE(TrackedLocks, const MemRegion *, TrackedLock)
REGISTER_TRAIT_WITH_PROGRAMSTATE(LocksTaken, unsigned)

namespace {

class LinuxLockBalanceChecker
    : public Checker<check::PostCall, check::EndFunction, check::EndAnalysis> {
  const BugType LeftHeld{this, "Lock left held on a return path",
                         "Linux kernel"};

  using Exit = std::pair<const MemRegion *, unsigned>;
  /// The return paths of the function under analysis: where a lock was still
  /// held, and with which lock and kind of result one was released.
  mutable llvm::MapVector<Exit, const ExplodedNode *> HeldExits;
  mutable llvm::DenseSet<Exit> ReleasedExits;

  static bool inScopedGuard(const CheckerContext &C);
  static bool keepsLocksByDesign(const FunctionDecl *FD);
  static ReturnClass classifyReturn(const ReturnStmt *RS, CheckerContext &C);

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR,
                        ExprEngine &Eng) const;
};

} // namespace

/// guard(mutex)(&lock) takes the lock in a function named
/// class_mutex_constructor(), and the matching unlock is a cleanup function.
bool LinuxLockBalanceChecker::inScopedGuard(const CheckerContext &C) {
  for (const StackFrame *Frame = C.getStackFrame(); Frame;
       Frame = Frame->getParent()) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Frame->getDecl());
    if (FD && FD->getIdentifier() && FD->getName().starts_with("class_"))
      return true;
  }
  return false;
}

bool LinuxLockBalanceChecker::keepsLocksByDesign(const FunctionDecl *FD) {
  // The annotations that sparse and the thread safety analysis read.
  if (FD->hasAttr<AcquireCapabilityAttr>() ||
      FD->hasAttr<TryAcquireCapabilityAttr>() ||
      FD->hasAttr<ReleaseCapabilityAttr>())
    return true;
  if (!FD->getIdentifier())
    return false;
  // foo_lock(), foo_trylock(), and the start and stop of a seq_file.
  StringRef Name = FD->getName();
  return Name.contains_insensitive("lock") || Name.ends_with("_start") ||
         Name.ends_with("_stop") || Name.ends_with("_begin") ||
         Name.ends_with("_end");
}

ReturnClass LinuxLockBalanceChecker::classifyReturn(const ReturnStmt *RS,
                                                    CheckerContext &C) {
  if (!RS || !RS->getRetValue())
    return RCVoid;
  ProgramStateRef State = C.getState();
  SVal Value = C.getSVal(RS->getRetValue());
  QualType Type = RS->getRetValue()->getType();

  if (Type->isPointerType())
    return State->isNull(Value).isConstrainedTrue() ? RCFailure : RCUnknown;
  if (!Type->isIntegerType() || Type->isBooleanType())
    return RCUnknown;

  SValBuilder &SVB = C.getSValBuilder();
  if (const llvm::APSInt *Known = SVB.getKnownValue(State, Value))
    return Known->isNegative() ? RCFailure : RCSuccess;

  // "if (ret) goto err;" leaves a value that is only known not to be zero.
  std::optional<DefinedOrUnknownSVal> Cond =
      Value.getAs<DefinedOrUnknownSVal>();
  if (!Cond)
    return RCUnknown;
  ProgramStateRef NonZero, Zero;
  std::tie(NonZero, Zero) = State->assume(*Cond);
  if (NonZero && !Zero)
    return RCFailure;
  if (Zero && !NonZero)
    return RCSuccess;
  return RCUnknown;
}

void LinuxLockBalanceChecker::checkPostCall(const CallEvent &Call,
                                            CheckerContext &C) const {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD || !FD->getIdentifier() || Call.getNumArgs() < 1)
    return;
  LockCall LC = classifyLockCall(FD->getName());
  if (LC.Op == LockOp::None)
    return;
  const MemRegion *Lock = Call.getArgSVal(0).getAsRegion();
  if (!Lock)
    return;
  Lock = Lock->StripCasts();

  ProgramStateRef State = C.getState();
  const TrackedLock *Known = State->get<TrackedLocks>(Lock);

  unsigned Kind = static_cast<unsigned>(LC.Kind);
  if (inScopedGuard(C)) {
    C.addTransition(State->set<TrackedLocks>(
        Lock, TrackedLock{TrackedLock::Foreign, Kind, 0}));
    return;
  }

  if (LC.Op == LockOp::Release) {
    if (Known) {
      if (Known->K == TrackedLock::Held)
        C.addTransition(State->set<TrackedLocks>(
            Lock, TrackedLock{TrackedLock::Released, Kind, Known->Order}));
      return;
    }
    // "mutex_unlock(&dev->parent->lock)" after a call that made the
    // analyzer forget dev->parent names a lock that it has not seen being
    // taken.  It is far more likely the lock of this kind that the path
    // took last than one that the caller holds.
    const MemRegion *Last = nullptr;
    unsigned LastOrder = 0;
    for (const auto &[Other, Tracked] : State->get<TrackedLocks>())
      if (Tracked.K == TrackedLock::Held && Tracked.LockKind == Kind &&
          Tracked.Order >= LastOrder) {
        Last = Other;
        LastOrder = Tracked.Order;
      }
    if (Last)
      C.addTransition(State->set<TrackedLocks>(
          Last, TrackedLock{TrackedLock::Released, Kind, LastOrder}));
    else
      C.addTransition(State->set<TrackedLocks>(
          Lock, TrackedLock{TrackedLock::Foreign, Kind, 0}));
    return;
  }

  if (Known && Known->K != TrackedLock::Released)
    return;
  unsigned Order = State->get<LocksTaken>() + 1;
  State = State->set<LocksTaken>(Order);
  TrackedLock Taken{TrackedLock::Held, Kind, Order};
  const BugType *BT = &LeftHeld;
  const NoteTag *Note = C.getNoteTag(
      [Lock, BT](PathSensitiveBugReport &BR, llvm::raw_ostream &OS) {
        if (&BR.getBugType() == BT && BR.isInteresting(Lock))
          OS << "Lock taken here";
      });

  if (LC.Op == LockOp::Acquire) {
    C.addTransition(State->set<TrackedLocks>(Lock, Taken), Note);
    return;
  }

  // A trylock holds the lock if it returns non-zero, an interruptible or
  // killable lock if it returns zero.
  std::optional<DefinedOrUnknownSVal> Result =
      Call.getReturnValue().getAs<DefinedOrUnknownSVal>();
  if (!Result)
    return;
  ProgramStateRef NonZero, Zero;
  std::tie(NonZero, Zero) = State->assume(*Result);
  ProgramStateRef Got = LC.Op == LockOp::TryAcquire ? NonZero : Zero;
  ProgramStateRef Missed = LC.Op == LockOp::TryAcquire ? Zero : NonZero;
  if (Got)
    C.addTransition(Got->set<TrackedLocks>(Lock, Taken), Note);
  if (Missed)
    C.addTransition(Missed);
}

void LinuxLockBalanceChecker::checkEndFunction(const ReturnStmt *RS,
                                               CheckerContext &C) const {
  if (!C.inTopFrame())
    return;
  const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getStackFrame()->getDecl());
  if (!FD || keepsLocksByDesign(FD))
    return;
  ProgramStateRef State = C.getState();
  TrackedLocksTy Locks = State->get<TrackedLocks>();
  if (Locks.isEmpty())
    return;

  ReturnClass RC = classifyReturn(RS, C);
  const ExplodedNode *N = nullptr;
  for (const auto &[Lock, Tracked] : Locks) {
    if (Tracked.K == TrackedLock::Released) {
      ReleasedExits.insert({Lock, RC});
    } else if (Tracked.K == TrackedLock::Held && RC != RCUnknown) {
      if (!N)
        N = C.generateNonFatalErrorNode(State);
      if (N)
        HeldExits.insert({{Lock, RC}, N});
    }
  }
}

void LinuxLockBalanceChecker::checkEndAnalysis(ExplodedGraph &G,
                                               BugReporter &BR,
                                               ExprEngine &Eng) const {
  llvm::DenseSet<const MemRegion *> Reported;
  for (const auto &[Key, N] : HeldExits) {
    const auto &[Lock, RC] = Key;
    bool ReleasedElsewhere = false;
    for (unsigned Other : {RCVoid, RCFailure, RCSuccess, RCUnknown})
      if (ReleasedExits.count({Lock, Other}) &&
          (RC == RCFailure || Other == RC))
        ReleasedElsewhere = true;
    if (!ReleasedElsewhere || !Reported.insert(Lock).second)
      continue;
    auto R = std::make_unique<PathSensitiveBugReport>(
        LeftHeld,
        RC == RCFailure
            ? "Lock is still held on this failure path, but other paths "
              "release it"
            : "Lock is still held on this return path, but another path with "
              "the same result releases it",
        N);
    R->markInteresting(Lock);
    BR.emitReport(std::move(R));
  }
  HeldExits.clear();
  ReleasedExits.clear();
}

void ento::registerLinuxLockBalanceChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<LinuxLockBalanceChecker>();
  linuxkernel::addInterest(Mgr, linuxkernel::Locks);
}

bool ento::shouldRegisterLinuxLockBalanceChecker(const CheckerManager &Mgr) {
  return true;
}
