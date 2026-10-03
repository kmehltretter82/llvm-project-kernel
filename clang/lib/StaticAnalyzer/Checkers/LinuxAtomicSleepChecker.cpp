//===-- LinuxAtomicSleepChecker.cpp -----------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Finds calls that may sleep while Linux kernel code is in atomic context:
// with a spinlock or rwlock held, inside an RCU read-side critical section,
// or with preemption or bottom halves disabled.
//
// The kernel's locking wrappers are inline functions and macros, so the
// checker keys on the functions they end in (_raw_spin_lock() and friends).
// A call may sleep if
//
//   - it is the kernel's own might_sleep() annotation, which also covers
//     every inline helper that carries one,
//   - it is one of a list of functions that always sleep, or
//   - its body is not visible and it is passed gfp flags that allow direct
//     reclaim, as in kmalloc(size, GFP_KERNEL).
//
// Out-of-line lock functions are evaluated by the checker so that taking a
// lock inside a structure does not invalidate the rest of the structure.
//
// The checker only reports what it can see on one path through one
// translation unit: the lock has to be taken and the sleeping call has to be
// reached without leaving that path.  It gives up on a critical section when
// a function that is not inlined contains an unlock somewhere below it, or
// when an external function that looks like an unlock helper is called,
// because either may have dropped the lock.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerHelpers.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/StringSwitch.h"
#include <optional>

using namespace clang;
using namespace ento;

namespace {

enum class SectionKind : unsigned { Lock, RCU, Preempt, BottomHalf };

/// One entry into atomic context that the current path has not left yet.
struct AtomicSection {
  const Expr *Entry = nullptr;
  const MemRegion *Lock = nullptr;
  SectionKind Kind = SectionKind::Lock;

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(Entry);
    ID.AddPointer(Lock);
    ID.AddInteger(static_cast<unsigned>(Kind));
  }
  bool operator==(const AtomicSection &Other) const {
    return Entry == Other.Entry && Lock == Other.Lock && Kind == Other.Kind;
  }
};

enum class Role {
  None,
  Enter,
  TryEnter,
  Leave,
  Sleep,
  MightSleep,
};

struct CallRole {
  Role R = Role::None;
  SectionKind Kind = SectionKind::Lock;
};

} // namespace

REGISTER_LIST_WITH_PROGRAMSTATE(AtomicSections, AtomicSection)

static CallRole classify(StringRef Name) {
  using SK = SectionKind;
  return llvm::StringSwitch<CallRole>(Name)
      // Spinlocks and rwlocks.  The "__raw" forms are the inline versions
      // that some configurations use instead of the out-of-line ones.
      .Cases({"_raw_spin_lock", "_raw_spin_lock_bh", "_raw_spin_lock_irq",
              "_raw_spin_lock_irqsave", "_raw_spin_lock_nested",
              "_raw_spin_lock_nest_lock", "_raw_spin_lock_irqsave_nested"},
             {Role::Enter, SK::Lock})
      .Cases({"_raw_read_lock", "_raw_read_lock_bh", "_raw_read_lock_irq",
              "_raw_read_lock_irqsave", "_raw_write_lock",
              "_raw_write_lock_bh", "_raw_write_lock_irq",
              "_raw_write_lock_irqsave", "_raw_write_lock_nested"},
             {Role::Enter, SK::Lock})
      .Cases({"__raw_spin_lock", "__raw_spin_lock_bh", "__raw_spin_lock_irq",
              "__raw_spin_lock_irqsave", "__raw_read_lock",
              "__raw_read_lock_bh", "__raw_read_lock_irq",
              "__raw_read_lock_irqsave", "__raw_write_lock",
              "__raw_write_lock_bh", "__raw_write_lock_irq",
              "__raw_write_lock_irqsave"},
             {Role::Enter, SK::Lock})
      .Cases({"_raw_spin_trylock", "_raw_spin_trylock_bh", "_raw_read_trylock",
              "_raw_write_trylock", "__raw_spin_trylock",
              "__raw_spin_trylock_bh", "__raw_read_trylock",
              "__raw_write_trylock"},
             {Role::TryEnter, SK::Lock})
      .Cases({"_raw_spin_unlock", "_raw_spin_unlock_bh", "_raw_spin_unlock_irq",
              "_raw_spin_unlock_irqrestore", "_raw_read_unlock",
              "_raw_read_unlock_bh", "_raw_read_unlock_irq",
              "_raw_read_unlock_irqrestore", "_raw_write_unlock",
              "_raw_write_unlock_bh", "_raw_write_unlock_irq",
              "_raw_write_unlock_irqrestore"},
             {Role::Leave, SK::Lock})
      .Cases({"__raw_spin_unlock", "__raw_spin_unlock_bh",
              "__raw_spin_unlock_irq", "__raw_spin_unlock_irqrestore",
              "__raw_read_unlock", "__raw_read_unlock_bh",
              "__raw_read_unlock_irq", "__raw_read_unlock_irqrestore",
              "__raw_write_unlock", "__raw_write_unlock_bh",
              "__raw_write_unlock_irq", "__raw_write_unlock_irqrestore"},
             {Role::Leave, SK::Lock})
      // RCU.  SRCU readers may sleep and are not listed.
      .Case("__rcu_read_lock", {Role::Enter, SK::RCU})
      .Case("__rcu_read_unlock", {Role::Leave, SK::RCU})
      // preempt_disable() and preempt_enable() in their out-of-line
      // (CONFIG_DEBUG_PREEMPT) and inline forms.
      .Cases({"preempt_count_add", "__preempt_count_add"},
             {Role::Enter, SK::Preempt})
      .Cases({"preempt_count_sub", "__preempt_count_sub",
              "__preempt_count_dec_and_test"},
             {Role::Leave, SK::Preempt})
      .Case("__local_bh_disable_ip", {Role::Enter, SK::BottomHalf})
      .Case("__local_bh_enable_ip", {Role::Leave, SK::BottomHalf})
      // The might_sleep() annotation (CONFIG_DEBUG_ATOMIC_SLEEP).
      .Case("__might_sleep", {Role::MightSleep, SK::Lock})
      // Functions that always sleep or wait.
      .Cases({"schedule", "schedule_timeout", "schedule_timeout_interruptible",
              "schedule_timeout_killable", "schedule_timeout_uninterruptible",
              "schedule_timeout_idle", "schedule_hrtimeout",
              "schedule_hrtimeout_range", "io_schedule", "io_schedule_timeout"},
             {Role::Sleep, SK::Lock})
      .Cases({"msleep", "msleep_interruptible", "usleep_range_state"},
             {Role::Sleep, SK::Lock})
      .Cases({"mutex_lock", "mutex_lock_nested", "mutex_lock_interruptible",
              "mutex_lock_interruptible_nested", "mutex_lock_killable",
              "mutex_lock_killable_nested", "mutex_lock_io",
              "mutex_lock_io_nested", "_mutex_lock_nest_lock"},
             {Role::Sleep, SK::Lock})
      .Cases({"down", "down_interruptible", "down_killable", "down_timeout",
              "down_read", "down_read_nested", "down_read_interruptible",
              "down_read_killable", "down_write", "down_write_nested",
              "down_write_killable", "down_write_killable_nested"},
             {Role::Sleep, SK::Lock})
      .Cases({"wait_for_completion", "wait_for_completion_timeout",
              "wait_for_completion_interruptible",
              "wait_for_completion_interruptible_timeout",
              "wait_for_completion_killable",
              "wait_for_completion_killable_timeout", "wait_for_completion_io",
              "wait_for_completion_io_timeout", "wait_for_completion_state"},
             {Role::Sleep, SK::Lock})
      .Cases({"synchronize_rcu", "synchronize_rcu_expedited",
              "synchronize_srcu", "synchronize_net", "synchronize_irq",
              "rcu_barrier"},
             {Role::Sleep, SK::Lock})
      .Cases({"flush_work", "flush_delayed_work", "cancel_work_sync",
              "cancel_delayed_work_sync", "__flush_workqueue",
              "drain_workqueue", "destroy_workqueue"},
             {Role::Sleep, SK::Lock})
      .Cases({"kthread_stop", "free_irq", "devm_free_irq", "disable_irq"},
             {Role::Sleep, SK::Lock})
      .Cases({"vmalloc_noprof", "vzalloc_noprof"}, {Role::Sleep, SK::Lock})
      .Default(CallRole());
}

namespace {

class LinuxAtomicSleepChecker
    : public Checker<check::PreCall, check::PostCall, eval::Call> {
  const BugType SleepBug{this, "Sleeping call in atomic context",
                         "Linux kernel"};

  /// The mask of __GFP_DIRECT_RECLAIM, looked up once per translation unit.
  /// Zero if the kernel headers in use do not reveal it.
  mutable std::optional<uint64_t> DirectReclaimMask;

  /// Whether a function with a visible body contains, at any depth, a call
  /// that leaves an atomic section.
  mutable llvm::DenseMap<const FunctionDecl *, bool> MayLeave;

  bool mayLeaveAtomicSection(const FunctionDecl *FD, unsigned Depth) const;
  uint64_t getDirectReclaimMask(CheckerContext &C) const;
  bool allowsBlocking(const CallEvent &Call, CheckerContext &C) const;
  void reportSleep(const CallEvent &Call, StringRef What,
                   CheckerContext &C) const;
  const NoteTag *createEntryNote(AtomicSection Section,
                                 CheckerContext &C) const;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
};

} // namespace

static const FunctionDecl *getCallee(const CallEvent &Call) {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD || !FD->getIdentifier() || !FD->getDeclContext()->isFileContext())
    return nullptr;
  return FD;
}

/// Out-of-line lock and unlock functions.  They change nothing but the lock,
/// so they are evaluated here instead of conservatively.  Otherwise a call
/// such as spin_lock(&dev->lock) makes the analyzer forget every field of
/// *dev, and with it conditions like "if (dev->flags & ATOMIC)" that decide
/// between a spinlock and a mutex and later between a busy wait and a sleep.
static bool isLockOperation(StringRef Name) {
  switch (classify(Name).R) {
  case Role::Enter:
  case Role::TryEnter:
  case Role::Leave:
    return true;
  default:
    break;
  }
  return llvm::StringSwitch<bool>(Name)
      .Cases({"mutex_lock", "mutex_lock_nested", "mutex_lock_interruptible",
              "mutex_lock_interruptible_nested", "mutex_lock_killable",
              "mutex_lock_killable_nested", "mutex_trylock", "mutex_unlock"},
             true)
      .Cases({"down_read", "down_read_nested", "down_write",
              "down_write_nested", "up_read", "up_write"},
             true)
      .Default(false);
}

/// Functions that take gfp flags and are meant to be called with a spinlock
/// held: the XArray drops and retakes its lock around a blocking allocation.
static bool dropsLockToAllocate(StringRef Name) {
  return Name.starts_with("__xa_") || Name.starts_with("xa_") ||
         Name.starts_with("xas_");
}

static StringRef describe(SectionKind Kind) {
  switch (Kind) {
  case SectionKind::Lock:
    return "with a spinlock held";
  case SectionKind::RCU:
    return "inside an RCU read-side critical section";
  case SectionKind::Preempt:
    return "with preemption disabled";
  case SectionKind::BottomHalf:
    return "with bottom halves disabled";
  }
  llvm_unreachable("unknown section kind");
}

static bool looksLikeUnlock(const FunctionDecl *FD) {
  if (!FD->getIdentifier())
    return false;
  StringRef Name = FD->getName();
  return classify(Name).R == Role::Leave || Name.contains_insensitive("unlock");
}

bool LinuxAtomicSleepChecker::mayLeaveAtomicSection(const FunctionDecl *FD,
                                                    unsigned Depth) const {
  const FunctionDecl *Def = nullptr;
  if (!FD->hasBody(Def))
    return false;
  auto Known = MayLeave.find(Def);
  if (Known != MayLeave.end())
    return Known->second;
  if (Depth > 8)
    return true;
  // The provisional answer ends recursion.
  MayLeave[Def] = false;

  bool Result = false;
  llvm::SmallVector<const Stmt *, 32> Worklist;
  Worklist.push_back(Def->getBody());
  while (!Worklist.empty() && !Result) {
    const Stmt *S = Worklist.pop_back_val();
    if (!S)
      continue;
    if (const auto *CE = dyn_cast<CallExpr>(S))
      if (const FunctionDecl *Callee = CE->getDirectCallee())
        Result = looksLikeUnlock(Callee) ||
                 mayLeaveAtomicSection(Callee, Depth + 1);
    for (const Stmt *Child : S->children())
      Worklist.push_back(Child);
  }
  MayLeave[Def] = Result;
  return Result;
}

uint64_t LinuxAtomicSleepChecker::getDirectReclaimMask(CheckerContext &C) const {
  if (DirectReclaimMask)
    return *DirectReclaimMask;
  DirectReclaimMask = 0;

  // Current kernels number the gfp bits with an enumeration.
  ASTContext &Ctx = C.getASTContext();
  IdentifierInfo &II = Ctx.Idents.get("___GFP_DIRECT_RECLAIM_BIT");
  for (const NamedDecl *ND : Ctx.getTranslationUnitDecl()->lookup(&II))
    if (const auto *ECD = dyn_cast<EnumConstantDecl>(ND)) {
      uint64_t Bit = ECD->getInitVal().getZExtValue();
      if (Bit < 64)
        DirectReclaimMask = uint64_t(1) << Bit;
    }

  // Older ones define the mask itself.
  if (!*DirectReclaimMask)
    if (std::optional<int> Mask = tryExpandAsInteger(
            "___GFP_DIRECT_RECLAIM", C.getBugReporter().getPreprocessor()))
      DirectReclaimMask = static_cast<uint64_t>(*Mask);
  return *DirectReclaimMask;
}

/// True if \p Call cannot be looked into and is passed gfp flags that are
/// known to allow direct reclaim.
bool LinuxAtomicSleepChecker::allowsBlocking(const CallEvent &Call,
                                             CheckerContext &C) const {
  const FunctionDecl *FD = getCallee(Call);
  if (!FD || FD->hasBody() || dropsLockToAllocate(FD->getName()))
    return false;
  uint64_t Mask = getDirectReclaimMask(C);
  if (!Mask)
    return false;

  unsigned NumArgs = std::min<unsigned>(Call.getNumArgs(), FD->getNumParams());
  for (unsigned I = 0; I != NumArgs; ++I) {
    const auto *TT = FD->getParamDecl(I)->getType()->getAs<TypedefType>();
    if (!TT || TT->getDecl()->getName() != "gfp_t")
      continue;
    const llvm::APSInt *Flags =
        C.getSValBuilder().getKnownValue(C.getState(), Call.getArgSVal(I));
    if (Flags && (Flags->getZExtValue() & Mask))
      return true;
  }
  return false;
}

const NoteTag *
LinuxAtomicSleepChecker::createEntryNote(AtomicSection Section,
                                         CheckerContext &C) const {
  const BugType *BT = &SleepBug;
  return C.getNoteTag(
      [Section, BT](PathSensitiveBugReport &BR, llvm::raw_ostream &OS) {
        if (&BR.getBugType() != BT)
          return;
        // Only mention sections that are still open where the report is.
        if (!llvm::is_contained(
                BR.getErrorNode()->getState()->get<AtomicSections>(), Section))
          return;
        switch (Section.Kind) {
        case SectionKind::Lock:
          OS << "Spinlock taken here";
          break;
        case SectionKind::RCU:
          OS << "RCU read-side critical section entered here";
          break;
        case SectionKind::Preempt:
          OS << "Preemption disabled here";
          break;
        case SectionKind::BottomHalf:
          OS << "Bottom halves disabled here";
          break;
        }
      });
}

void LinuxAtomicSleepChecker::reportSleep(const CallEvent &Call, StringRef What,
                                          CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const auto Sections = State->get<AtomicSections>();
  if (Sections.isEmpty())
    return;
  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;

  // Report once per statement of the function the analysis started in, not
  // once per might_sleep() in a shared inline helper.
  const StackFrame *Frame = C.getStackFrame();
  const Stmt *At = Call.getOriginExpr();
  while (Frame->getParent() && Frame->getCallSite()) {
    At = Frame->getCallSite();
    Frame = Frame->getParent();
  }
  PathDiagnosticLocation Unique;
  if (At)
    Unique = PathDiagnosticLocation::createBegin(At, C.getSourceManager(),
                                                 Frame);

  // The list is built by prepending, so its head is the innermost section.
  std::string Message =
      (What + " " + describe(Sections.getHead().Kind)).str();
  auto R = std::make_unique<PathSensitiveBugReport>(SleepBug, Message, N,
                                                    Unique, Frame->getDecl());
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void LinuxAtomicSleepChecker::checkPreCall(const CallEvent &Call,
                                           CheckerContext &C) const {
  const FunctionDecl *FD = getCallee(Call);
  if (!FD || C.getState()->get<AtomicSections>().isEmpty())
    return;

  StringRef Name = FD->getName();
  switch (classify(Name).R) {
  case Role::MightSleep:
    reportSleep(Call, "might_sleep() reached", C);
    return;
  case Role::Sleep:
    reportSleep(Call, ("Call to sleeping function '" + Name + "'").str(), C);
    return;
  case Role::None:
    if (allowsBlocking(Call, C))
      reportSleep(
          Call, ("Call to '" + Name + "' with gfp flags that may sleep").str(),
          C);
    return;
  default:
    return;
  }
}

void LinuxAtomicSleepChecker::checkPostCall(const CallEvent &Call,
                                            CheckerContext &C) const {
  const FunctionDecl *FD = getCallee(Call);
  if (!FD)
    return;
  ProgramStateRef State = C.getState();
  auto &Factory = State->get_context<AtomicSections>();
  const auto Sections = State->get<AtomicSections>();
  CallRole CR = classify(FD->getName());

  switch (CR.R) {
  case Role::Enter:
  case Role::TryEnter: {
    AtomicSection Section;
    Section.Entry = Call.getOriginExpr();
    Section.Kind = CR.Kind;
    if (CR.Kind == SectionKind::Lock && Call.getNumArgs() >= 1)
      Section.Lock = Call.getArgSVal(0).getAsRegion();
    // An inline lock function ends in the out-of-line one for the same lock.
    if (Section.Lock &&
        llvm::any_of(Sections, [&](const AtomicSection &Open) {
          return Open.Kind == SectionKind::Lock && Open.Lock == Section.Lock;
        }))
      return;

    ProgramStateRef Entered = State->add<AtomicSections>(Section);
    if (CR.R == Role::Enter) {
      C.addTransition(Entered, createEntryNote(Section, C));
      return;
    }
    // A trylock takes the lock only if it returns non-zero.
    std::optional<DefinedOrUnknownSVal> Ret =
        Call.getReturnValue().getAs<DefinedOrUnknownSVal>();
    if (!Ret)
      return;
    ProgramStateRef Taken, Missed;
    std::tie(Taken, Missed) = State->assume(*Ret);
    if (Taken)
      C.addTransition(Taken->add<AtomicSections>(Section),
                      createEntryNote(Section, C));
    if (Missed)
      C.addTransition(Missed);
    return;
  }
  case Role::Leave: {
    const MemRegion *Lock = nullptr;
    if (CR.Kind == SectionKind::Lock && Call.getNumArgs() >= 1)
      Lock = Call.getArgSVal(0).getAsRegion();
    // Drop the innermost section of this kind.  For a lock, prefer the
    // section of this very lock if the path has seen it being taken.
    llvm::SmallVector<AtomicSection, 8> Open(Sections.begin(), Sections.end());
    int Match = -1;
    for (int I = 0, E = Open.size(); I != E; ++I) {
      if (Open[I].Kind != CR.Kind)
        continue;
      if (Match < 0)
        Match = I;
      if (Lock && Open[I].Lock == Lock) {
        Match = I;
        break;
      }
    }
    if (Match < 0)
      return;
    Open.erase(Open.begin() + Match);
    llvm::ImmutableList<AtomicSection> List = Factory.getEmptyList();
    for (const AtomicSection &Section : llvm::reverse(Open))
      List = Factory.add(Section, List);
    C.addTransition(State->set<AtomicSections>(List));
    return;
  }
  case Role::None:
    break;
  default:
    return;
  }

  if (Sections.isEmpty())
    return;
  // A function that was not inlined although it unlocks something further
  // down, or an external one named like an unlock helper, may have left the
  // critical section.
  bool Opaque = !C.wasInlined && mayLeaveAtomicSection(FD, 0);
  bool UnlockHelper = !FD->hasBody() && looksLikeUnlock(FD);
  if (Opaque || UnlockHelper)
    C.addTransition(State->set<AtomicSections>(Factory.getEmptyList()));
}

bool LinuxAtomicSleepChecker::evalCall(const CallEvent &Call,
                                       CheckerContext &C) const {
  const FunctionDecl *FD = getCallee(Call);
  const Expr *Origin = Call.getOriginExpr();
  if (!FD || FD->hasBody() || !Origin || !isLockOperation(FD->getName()))
    return false;

  ProgramStateRef State = C.getState();
  if (!Call.getResultType()->isVoidType())
    State = State->BindExpr(
        Origin, C.getStackFrame(),
        C.getSValBuilder().conjureSymbolVal(Call, C.blockCount()));
  C.addTransition(State);
  return true;
}

void ento::registerLinuxAtomicSleepChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<LinuxAtomicSleepChecker>();
}

bool ento::shouldRegisterLinuxAtomicSleepChecker(const CheckerManager &Mgr) {
  return true;
}
