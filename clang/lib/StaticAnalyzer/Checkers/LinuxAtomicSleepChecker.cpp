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

#include "LinuxKernelModeling.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerHelpers.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/LineIterator.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/raw_ostream.h"
#include <map>
#include <optional>
#include <set>
#include <vector>

using namespace clang;
using namespace ento;
using namespace linuxkernel;

namespace {

enum class SectionKind : unsigned {
  Lock, RCU, Preempt, BottomHalf, RTLock, Migration, HardIRQ, NMI, IRQDisabled
};

/// One entry into atomic context that the current path has not left yet.
struct AtomicSection {
  const Expr *Entry = nullptr;
  const MemRegion *Lock = nullptr;
  SectionKind Kind = SectionKind::Lock;
  unsigned Amount = 1;
  bool Uncertain = false;

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(Entry);
    ID.AddPointer(Lock);
    ID.AddInteger(static_cast<unsigned>(Kind));
    ID.AddInteger(Amount);
    ID.AddBoolean(Uncertain);
  }
  bool operator==(const AtomicSection &Other) const {
    return Entry == Other.Entry && Lock == Other.Lock && Kind == Other.Kind &&
           Amount == Other.Amount && Uncertain == Other.Uncertain;
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

static std::string contentHash(StringRef Bytes) {
  llvm::SHA256 Hash;
  Hash.update(Bytes);
  return llvm::toHex(Hash.final(), /*LowerCase=*/true);
}

static bool hashText(StringRef S) {
  return S.size() == 64 && llvm::all_of(S, [](char C) {
    return (C >= '0' && C <= '9') || (C >= 'a' && C <= 'f');
  });
}

// LLVM's JSON object representation replaces duplicate keys. Check decoded
// keys before accepting its parsed object, including escaped spellings.
static bool uniqueJSONKeys(StringRef Text) {
  struct Scope { bool Object; std::set<std::string> Keys; };
  std::vector<Scope> Stack;
  for (size_t I = 0; I < Text.size(); ++I) {
    char C = Text[I];
    if (C == '{' || C == '[') {
      if (Stack.size() >= 128)
        return false;
      Stack.push_back({C == '{', {}});
    } else if (C == '}' || C == ']') {
      if (Stack.empty())
        return false;
      Stack.pop_back();
    } else if (C == '"') {
      size_t Start = I++;
      for (; I < Text.size(); ++I) {
        if (Text[I] == '\\')
          ++I;
        else if (Text[I] == '"')
          break;
      }
      if (I >= Text.size())
        return false;
      size_t Next = I + 1;
      while (Next < Text.size() && llvm::isSpace(Text[Next]))
        ++Next;
      if (Next < Text.size() && Text[Next] == ':') {
        auto Key = llvm::json::parse(Text.slice(Start, I + 1));
        if (!Key) {
          llvm::consumeError(Key.takeError());
          return false;
        }
        auto Name = Key->getAsString();
        if (!Name || Stack.empty() || !Stack.back().Object ||
            !Stack.back().Keys.insert(Name->str()).second)
          return false;
      }
    }
  }
  return Stack.empty();
}

struct RTManifestFunction {
  std::string Name, Type, Linkage, Source, SourceHash, Kind, Effect;
  std::string EntryKind;
  uint64_t Offset = 0;
  IRQMode IRQ = IRQMode::Unknown;
  unsigned Preempt = 0, BH = 0, RCU = 0, Migration = 0;
};

// Explicit reviewed inputs, never an inference that an opaque callee is safe.
struct RTContextManifest {
  std::string Path, Output;
  mutable bool Initialized = false;
  mutable std::string Error;
  mutable std::vector<RTManifestFunction> Functions;

  static std::optional<llvm::json::Object>
  binding(const FunctionDecl *FD, ASTContext &Ctx) {
    if (!FD || !FD->getIdentifier() || !FD->getDeclContext()->isFileContext())
      return std::nullopt;
    if (const FunctionDecl *Def = FD->getDefinition())
      FD = Def;
    SourceLocation Loc = FD->getLocation();
    if (!Loc.isFileID())
      return std::nullopt;
    const SourceManager &SM = Ctx.getSourceManager();
    FileID FID = SM.getFileID(Loc);
    auto File = SM.getFileEntryRefForID(FID);
    auto Bytes = SM.getBufferDataOrNone(FID);
    if (!File || !Bytes)
      return std::nullopt;
    StringRef Link = FD->getFormalLinkage() == Linkage::Internal ? "internal" :
                     FD->getFormalLinkage() == Linkage::External ? "external" : "unsupported";
    return llvm::json::Object{
        {"name", FD->getName()},
        {"type", FD->getType().getCanonicalType().getAsString()},
        {"linkage", Link},
        {"source_path", SM.getFileManager().getCanonicalName(*File)},
        {"source_sha256", contentHash(*Bytes)},
        {"offset", static_cast<int64_t>(SM.getFileOffset(Loc))}};
  }

  static llvm::json::Object facts(ASTContext &Ctx, Preprocessor &PP,
                                  std::string &Error) {
    const SourceManager &SM = Ctx.getSourceManager();
    auto Main = SM.getFileEntryRefForID(SM.getMainFileID());
    auto MainBytes = SM.getBufferDataOrNone(SM.getMainFileID());
    if (!Main || !MainBytes || Ctx.getExternalSource()) {
      Error = "Manifest input requires a real main file and no external AST";
      return {};
    }
    llvm::json::Object Files;
    for (auto I = SM.fileinfo_begin(); I != SM.fileinfo_end(); ++I) {
      const auto *Cache = I->second;
      auto Bytes = Cache->getBufferDataIfLoaded();
      if (!Bytes || !Cache->OrigEntry)
        continue;
      if (Cache->BufferOverridden || Cache->IsBufferInvalid) {
        Error = "Manifest input has an overridden or invalid source buffer";
        return {};
      }
      Files[SM.getFileManager().getCanonicalName(*Cache->OrigEntry)] = contentHash(*Bytes);
    }
    llvm::json::Array Bindings;
    std::set<std::string> Seen;
    for (const Decl *D : Ctx.getTranslationUnitDecl()->decls())
      if (const auto *FD = dyn_cast<FunctionDecl>(D))
        if (auto B = binding(FD, Ctx)) {
          std::string Key = std::string(*B->getString("source_path")) + ":" +
                            std::to_string(*B->getInteger("offset"));
          if (Seen.insert(Key).second)
            Bindings.push_back(std::move(*B));
        }
    llvm::json::Object Macros;
    for (StringRef Name : {"CONFIG_PREEMPT_RT", "CONFIG_PREEMPT_RT_NEEDS_BH_LOCK"}) {
      if (auto *History = PP.getLocalMacroDirectiveHistory(PP.getIdentifierInfo(Name)))
        if (History->getPrevious()) {
          Error = "Manifest input has changing RT configuration macros";
          return {};
        }
      if (!PP.isMacroDefined(Name))
        Macros[Name] = "absent";
      else if (auto Number = tryExpandAsInteger(Name, PP))
        Macros[Name] = std::to_string(*Number);
      else {
        Error = "Manifest input has an unsupported RT configuration macro";
        return {};
      }
    }
    return llvm::json::Object{
        {"schema", 1}, {"effect_model", "linux-rt-context-1"},
        {"target_triple", Ctx.getTargetInfo().getTriple().str()},
        {"predefines_sha256", contentHash(PP.getPredefines())},
        {"translation_unit", llvm::json::Object{
            {"path", SM.getFileManager().getCanonicalName(*Main)},
            {"sha256", contentHash(*MainBytes)}}},
        {"files", std::move(Files)}, {"macros", std::move(Macros)},
        {"functions", std::move(Bindings)}};
  }

  bool fail(StringRef Why) const {
    Error = Why.str();
    Functions.clear();
    return false;
  }

  void initialize(ASTContext &Ctx, Preprocessor &PP) const {
    if (Initialized)
      return;
    Initialized = true;
    auto Actual = facts(Ctx, PP, Error);
    if (!Error.empty())
      return;
    if (!Output.empty()) {
      std::error_code EC;
      llvm::raw_fd_ostream Stream(Output, EC, llvm::sys::fs::CD_CreateNew,
          llvm::sys::fs::FA_Write, llvm::sys::fs::OF_Text);
      if (EC) {
        fail("Cannot create fresh manifest identity output");
        return;
      }
      auto OutputFacts = Actual;
      Stream << llvm::formatv("{0:2}\n", llvm::json::Value(std::move(OutputFacts)));
      Stream.close();
      if (Stream.has_error()) {
        fail("Cannot finish manifest identity output");
        return;
      }
    }
    if (Path.empty())
      return;
    FileManager &FM = Ctx.getSourceManager().getFileManager();
    auto Buffer = FM.getBufferForFile(Path);
    if (!Buffer || (*Buffer)->getBufferSize() > 16 * 1024 * 1024) {
      fail("Cannot read bounded RT context manifest");
      return;
    }
    auto Parsed = llvm::json::parse((*Buffer)->getBuffer());
    if (!Parsed) {
      llvm::consumeError(Parsed.takeError());
      fail("Invalid RT context manifest JSON");
      return;
    }
    auto *Root = Parsed->getAsObject();
    if (!Root || !uniqueJSONKeys((*Buffer)->getBuffer()) || Root->getInteger("schema") != 1 ||
        Root->getString("effect_model") != "linux-rt-context-1") {
      fail("Unsupported or duplicate RT context manifest schema");
      return;
    }
    for (StringRef Key : {"target_triple", "predefines_sha256", "translation_unit", "macros"}) {
      auto M = Root->get(Key), A = Actual.get(Key);
      if (!M || !A || *M != *A) {
        fail("RT context manifest compiler identity differs");
        return;
      }
    }
    auto *Files = Root->getObject("files");
    if (!Files || Files->empty()) {
      fail("RT context manifest lacks source pins");
      return;
    }
    for (const auto &[Name, Value] : *Files) {
      auto Hash = Value.getAsString();
      if (!Hash || !hashText(*Hash) || !llvm::sys::path::is_absolute(StringRef(Name))) {
        fail("Invalid RT context manifest file pin");
        return;
      }
      auto Bytes = FM.getBufferForFile(Name);
      if (!Bytes || contentHash((*Bytes)->getBuffer()) != *Hash) {
        fail("RT context manifest source bytes differ");
        return;
      }
    }
    for (const auto &[Name, Value] : *Actual.getObject("files")) {
      auto Pin = Files->get(Name);
      if (!Pin || *Pin != Value) {
        fail("RT context manifest omits or mismatches a loaded source buffer");
        return;
      }
    }
    auto *Configuration = Root->getObject("configuration");
    if (!Configuration) {
      fail("RT context manifest lacks a configuration kind");
      return;
    }
    auto Kind = Configuration->getString("kind");
    if (Kind == "kernel") {
      auto Config = Configuration->getString("config_path");
      auto Autoconf = Configuration->getString("autoconf_path");
      if (!Config || !Autoconf || !Files->get(*Config) || !Files->get(*Autoconf) ||
          !Actual.getObject("files")->get(*Autoconf)) {
        fail("RT context manifest kernel configuration is not pinned and loaded");
        return;
      }
    } else if (Kind != "api-fixture") {
      fail("Unsupported RT context manifest configuration kind");
      return;
    }
    auto *Records = Root->getArray("functions");
    if (!Records) {
      fail("RT context manifest lacks function records");
      return;
    }
    std::set<std::string> Seen;
    for (const auto &Value : *Records) {
      auto *Record = Value.getAsObject();
      if (!Record) { fail("Invalid RT context manifest function"); return; }
      RTManifestFunction F;
      auto Name = Record->getString("name"), Type = Record->getString("type"),
           Link = Record->getString("linkage"), Source = Record->getString("source_path"),
           Hash = Record->getString("source_sha256"), Role = Record->getString("kind");
      auto Offset = Record->getInteger("offset");
      auto *Evidence = Record->getObject("evidence");
      if (!Name || !Type || !Link || !Source || !Hash || !Role || !Offset || *Offset < 0 ||
          !Evidence || !hashText(*Hash) || (Link != "internal" && Link != "external") ||
          !Files->get(*Source) || Files->getString(*Source) != Hash) {
        fail("Invalid RT context manifest function identity"); return;
      }
      auto EvidencePath = Evidence->getString("path"), EvidenceHash = Evidence->getString("sha256");
      if (!EvidencePath || !EvidenceHash || Files->getString(*EvidencePath) != EvidenceHash ||
          !hashText(*EvidenceHash)) { fail("RT context manifest lacks pinned review evidence"); return; }
      bool Bound = false;
      for (const auto &B : *Actual.getArray("functions")) {
        const auto *Obj = B.getAsObject();
        if (Obj->getString("name") == Name && Obj->getString("type") == Type &&
            Obj->getString("linkage") == Link && Obj->getString("source_path") == Source &&
            Obj->getString("source_sha256") == Hash && Obj->getInteger("offset") == Offset)
          Bound = true;
      }
      if (!Bound || !Seen.insert((Source->str() + ":" + std::to_string(*Offset))).second) {
        fail("Unbound or conflicting RT context manifest function"); return;
      }
      F.Name = Name->str(); F.Type = Type->str(); F.Linkage = Link->str();
      F.Source = Source->str(); F.SourceHash = Hash->str(); F.Offset = *Offset; F.Kind = Role->str();
      if (Role == "effect") {
        if (classifyLockCall(*Name).Op != LockOp::None ||
            classifyContextCall(*Name).Op != ContextOp::None) {
          fail("RT context manifest cannot override a modeled primitive"); return;
        }
        auto Effect = Record->getString("effect");
        if (Effect != "rt-lock-wait" && Effect != "ordinary-sleep" && Effect != "unknown") {
          fail("Unsupported RT context manifest effect"); return;
        }
        F.Effect = Effect->str();
      } else if (Role == "entry") {
        auto *Context = Record->getObject("context");
        auto Entry = Context ? Context->getString("kind") : std::nullopt;
        auto IRQ = Context ? Context->getString("irq_mode") : std::nullopt;
        if (!Entry || (Entry != "task" && Entry != "hardirq" && Entry != "nmi" &&
            Entry != "softirq" && Entry != "threadedirq") ||
            (IRQ != "enabled" && IRQ != "disabled" && IRQ != "unknown")) {
          fail("Unsupported RT context manifest entry context"); return;
        }
        F.EntryKind = Entry->str();
        F.IRQ = IRQ == "enabled" ? IRQMode::Enabled : IRQ == "disabled" ? IRQMode::Disabled : IRQMode::Unknown;
        auto Depth = [&](StringRef Key, unsigned &Result) {
          auto D = Context->getInteger(Key);
          if (!D || *D < 0 || *D > 1) return false;
          Result = *D; return true;
        };
        if (!Depth("preempt", F.Preempt) || !Depth("bh", F.BH) || !Depth("rcu", F.RCU) ||
            !Depth("migration", F.Migration)) { fail("Unsupported RT context manifest entry depth"); return; }
      } else { fail("Unsupported RT context manifest function role"); return; }
      Functions.push_back(std::move(F));
    }
  }

  const RTManifestFunction *find(const FunctionDecl *FD, CheckerContext &C) const {
    if (!Error.empty())
      return nullptr;
    auto B = binding(FD, C.getASTContext());
    if (!B)
      return nullptr;
    for (const auto &F : Functions)
      if (B->getString("name") == F.Name && B->getString("type") == F.Type &&
          B->getString("linkage") == F.Linkage && B->getString("source_path") == F.Source &&
          B->getString("source_sha256") == F.SourceHash && B->getInteger("offset") == F.Offset)
        return &F;
    return nullptr;
  }
};

} // namespace

REGISTER_LIST_WITH_PROGRAMSTATE(ActiveAtomicSections, AtomicSection)
REGISTER_MAP_WITH_PROGRAMSTATE(PendingIRQSave, const Expr *, IRQState)
REGISTER_MAP_WITH_PROGRAMSTATE(OutstandingIRQSaves, SymbolRef, const Expr *)
REGISTER_TRAIT_WITH_PROGRAMSTATE(IRQSaveBalanceUnknown, bool)
REGISTER_TRAIT_WITH_PROGRAMSTATE(UnknownContextKinds, unsigned)

ContextBalanceFacts linuxkernel::getContextBalanceFacts(ProgramStateRef State) {
  ContextBalanceFacts Facts;
  for (const AtomicSection &Section : State->get<ActiveAtomicSections>())
    if (Section.Kind == SectionKind::BottomHalf) {
      Facts.BottomHalfDepth += Section.Amount;
      Facts.BottomHalfUnknown |= Section.Uncertain;
    }
  Facts.BottomHalfUnknown |= State->get<UnknownContextKinds>() &
                             (1u << static_cast<unsigned>(SectionKind::BottomHalf));
  for (auto It = State->get<OutstandingIRQSaves>().begin(),
            End = State->get<OutstandingIRQSaves>().end(); It != End; ++It)
    ++Facts.IRQSaveDepth;
  Facts.IRQSaveUnknown = State->get<IRQSaveBalanceUnknown>();
  return Facts;
}

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
    : public Checker<check::BeginFunction, check::PreCall, check::PostCall,
                     check::EndOfTranslationUnit> {
  const BugType SleepBug{this, "Sleeping call in atomic context",
                         "Linux kernel"};
  const BugType RTLockBug{this, "RT lock acquisition in atomic context",
                         "Linux kernel"};
  const BugType UnknownBug{this, "Atomic context analysis incomplete",
                          "Linux kernel"};

  /// The mask of __GFP_DIRECT_RECLAIM, looked up once per translation unit.
  /// Zero if the kernel headers in use do not reveal it.
  mutable std::optional<uint64_t> DirectReclaimMask;

  /// Whether a function with a visible body contains, at any depth, a call
  /// that leaves an atomic section.
  mutable llvm::DenseMap<const FunctionDecl *, bool> MayLeave;
  mutable llvm::DenseMap<const FunctionDecl *, unsigned> MayAffect;

  bool mayLeaveAtomicSection(const FunctionDecl *FD, unsigned Depth) const;
  unsigned affectedContexts(const FunctionDecl *FD, unsigned Depth) const;
  uint64_t getDirectReclaimMask(CheckerContext &C) const;
  bool allowsBlocking(const CallEvent &Call, CheckerContext &C) const;
  void reportSleep(const CallEvent &Call, StringRef What,
                   CheckerContext &C, bool RTWait = false) const;
  void reportUnknown(const CallEvent &Call, CheckerContext &C,
                     ProgramStateRef State,
                     StringRef Why = "Atomic context became unknown after opaque unlock helper") const;
  CallRole role(const CallEvent &Call, CheckerContext &C) const;
  bool isRT(CheckerContext &C) const;
  const NoteTag *createEntryNote(AtomicSection Section,
                                 CheckerContext &C) const;

public:
  void checkBeginFunction(CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
                                 AnalysisManager &Mgr,
                                 BugReporter &BR) const;

  /// Functions that the -flinux-kernel-contracts= file says always sleep.
  llvm::StringSet<> Sleepers;
  bool RTContext = false;
  RTContextManifest Manifest;
  void loadSleepers(CheckerManager &Mgr);
};

} // namespace

static const FunctionDecl *getCallee(const CallEvent &Call) {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD || !FD->getIdentifier() || !FD->getDeclContext()->isFileContext())
    return nullptr;
  return FD;
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
  case SectionKind::RTLock:
    return "with an RT lock held";
  case SectionKind::Migration:
    return "with migration disabled";
  case SectionKind::HardIRQ:
    return "inside a hard IRQ handler";
  case SectionKind::NMI:
    return "inside NMI context";
  case SectionKind::IRQDisabled:
    return "with hard interrupts disabled";
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

static unsigned sectionMask(SectionKind Kind) {
  return 1u << static_cast<unsigned>(Kind);
}

unsigned LinuxAtomicSleepChecker::affectedContexts(const FunctionDecl *FD,
                                                  unsigned Depth) const {
  StringRef Name = FD->getName();
  unsigned Mask = 0;
  CallRole CR = classify(Name);
  if (CR.R == Role::Leave)
    Mask |= sectionMask(CR.Kind);
  ContextCall CC = classifyContextCall(Name);
  if (CC.Op == ContextOp::Leave) {
    switch (CC.Kind) {
    case ContextKind::Preempt:
      Mask |= sectionMask(SectionKind::Preempt);
      if (Name.contains("count_"))
        Mask |= sectionMask(SectionKind::BottomHalf) |
                sectionMask(SectionKind::IRQDisabled) |
                sectionMask(SectionKind::HardIRQ) | sectionMask(SectionKind::NMI);
      break;
    case ContextKind::BottomHalf: Mask |= sectionMask(SectionKind::BottomHalf); break;
    case ContextKind::RCU: Mask |= sectionMask(SectionKind::RCU); break;
    case ContextKind::Migration: Mask |= sectionMask(SectionKind::Migration); break;
    case ContextKind::HardIRQ: Mask |= sectionMask(SectionKind::HardIRQ); break;
    case ContextKind::NMI: Mask |= sectionMask(SectionKind::NMI); break;
    }
  }
  if (CC.Op == ContextOp::IRQEnable || CC.Op == ContextOp::IRQRestore)
    Mask |= sectionMask(SectionKind::IRQDisabled);
  LockCall LC = classifyLockCall(Name);
  if (LC.Op == LockOp::Release && isRTLock(LC.Kind))
    Mask |= sectionMask(SectionKind::RTLock);
  if (looksLikeUnlock(FD)) {
    if (LC.Op == LockOp::None)
      Mask |= sectionMask(SectionKind::Lock) | sectionMask(SectionKind::RTLock);
    if (Name.ends_with("_bh"))
      Mask |= sectionMask(SectionKind::BottomHalf);
    if (Name.contains("irq"))
      Mask |= sectionMask(SectionKind::IRQDisabled);
  }
  // A reviewed mutex/rwsem primitive can release only its named lock. Raw
  // locks taken and dropped privately by its slow path are not caller-owned
  // atomic sections, even when that implementation is visible but not inlined.
  if (LC.Op != LockOp::None &&
      (LC.Kind == LockKind::Mutex || LC.Kind == LockKind::RWSem))
    return Mask;
  const FunctionDecl *Def = nullptr;
  if (!FD->hasBody(Def))
    return Mask;
  if (Depth > 8)
    return ~0u;
  auto Known = MayAffect.find(Def);
  if (Known != MayAffect.end())
    return Mask | Known->second;
  // Recursion whose effect has not been proved cannot justify a clean state.
  MayAffect[Def] = ~0u;
  llvm::SmallVector<const Stmt *, 32> Worklist{Def->getBody()};
  while (!Worklist.empty()) {
    const Stmt *S = Worklist.pop_back_val();
    if (!S)
      continue;
    if (const auto *CE = dyn_cast<CallExpr>(S))
      if (const FunctionDecl *Callee = CE->getDirectCallee())
        Mask |= affectedContexts(Callee, Depth + 1);
    for (const Stmt *Child : S->children())
      Worklist.push_back(Child);
  }
  MayAffect[Def] = Mask;
  return Mask;
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
  const BugType *RTBT = &RTLockBug;
  return C.getNoteTag(
      [Section, BT, RTBT](PathSensitiveBugReport &BR, llvm::raw_ostream &OS) {
        if (&BR.getBugType() != BT && &BR.getBugType() != RTBT)
          return;
        // Only mention sections that are still open where the report is.
        if (!llvm::any_of(
                BR.getErrorNode()->getState()->get<ActiveAtomicSections>(),
                [&](const AtomicSection &Open) {
                  return !Open.Uncertain && Open.Entry == Section.Entry &&
                         Open.Kind == Section.Kind && Open.Lock == Section.Lock;
                }))
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
        case SectionKind::RTLock:
          OS << "RT lock taken here";
          break;
        case SectionKind::Migration:
          OS << "Migration disabled here";
          break;
        case SectionKind::HardIRQ:
          OS << "Hard IRQ context entered here";
          break;
        case SectionKind::NMI:
          OS << "NMI context entered here";
          break;
        case SectionKind::IRQDisabled:
          OS << "Hard interrupts disabled here";
          break;
        }
      });
}

void LinuxAtomicSleepChecker::reportSleep(const CallEvent &Call, StringRef What,
                                          CheckerContext &C, bool RTWait) const {
  ProgramStateRef State = C.getState();
  const auto Sections = State->get<ActiveAtomicSections>();
  const AtomicSection *Forbidden = nullptr;
  for (const AtomicSection &Section : Sections) {
    if (Section.Uncertain || Section.Kind == SectionKind::Migration)
      continue;
    if (RTWait && (Section.Kind == SectionKind::RCU ||
                   Section.Kind == SectionKind::RTLock ||
                   (Section.Kind == SectionKind::BottomHalf && isRT(C))))
      continue;
    Forbidden = &Section;
    break;
  }
  IRQState IRQ = getIRQState(State);
  bool IRQOff = RTContext && IRQ.Mode == IRQMode::Disabled;
  if (!Forbidden && !IRQOff)
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
  StringRef Context = IRQOff ? "with hard interrupts disabled" :
                              describe(Forbidden->Kind);
  if (RTWait && Forbidden && !IRQOff && Forbidden->Kind == SectionKind::Lock)
    Context = "with a raw spinlock held";
  std::string Message = (What + " " + Context).str();
  const BugType &BT = RTWait ? RTLockBug : SleepBug;
  auto R = std::make_unique<PathSensitiveBugReport>(BT, Message, N,
                                                    Unique, Frame->getDecl());
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

bool LinuxAtomicSleepChecker::isRT(CheckerContext &C) const {
  return RTContext &&
         tryExpandAsInteger("CONFIG_PREEMPT_RT",
                            C.getBugReporter().getPreprocessor()) == 1;
}

CallRole LinuxAtomicSleepChecker::role(const CallEvent &Call,
                                        CheckerContext &C) const {
  const FunctionDecl *FD = getCallee(Call);
  if (!FD)
    return {};
  StringRef Name = FD->getName();
  CallRole Result = classify(Name);
  if (!RTContext)
    return Result;
  LockCall LC = classifyLockCall(Name);
  if (isRTLock(LC.Kind) && LC.Op != LockOp::None) {
    if (LC.Op == LockOp::AcquireAndRelease)
      return {};
    Result.Kind = SectionKind::RTLock;
    Result.R = LC.Op == LockOp::Release ? Role::Leave :
               LC.Op == LockOp::TryAcquire ? Role::TryEnter : Role::Enter;
    return Result;
  }
  ContextCall CC = classifyContextCall(Name);
  if (CC.Op != ContextOp::Enter && CC.Op != ContextOp::Leave)
    return Result;
  Result.R = CC.Op == ContextOp::Enter ? Role::Enter : Role::Leave;
  switch (CC.Kind) {
  case ContextKind::Preempt: Result.Kind = SectionKind::Preempt; break;
  case ContextKind::BottomHalf: Result.Kind = SectionKind::BottomHalf; break;
  case ContextKind::RCU: Result.Kind = SectionKind::RCU; break;
  case ContextKind::Migration: Result.Kind = SectionKind::Migration; break;
  case ContextKind::HardIRQ: Result.Kind = SectionKind::HardIRQ; break;
  case ContextKind::NMI: Result.Kind = SectionKind::NMI; break;
  }
  return Result;
}

void LinuxAtomicSleepChecker::reportUnknown(const CallEvent &Call,
                                            CheckerContext &C,
                                            ProgramStateRef State,
                                            StringRef Why) const {
  if (ExplodedNode *N = C.generateNonFatalErrorNode(State)) {
    auto R = std::make_unique<PathSensitiveBugReport>(
        UnknownBug, Why, N);
    R->addRange(Call.getSourceRange());
    C.emitReport(std::move(R));
  }
}

void LinuxAtomicSleepChecker::checkBeginFunction(CheckerContext &C) const {
  if (!C.inTopFrame() || (Manifest.Path.empty() && Manifest.Output.empty()))
    return;
  if (!RTContext)
    Manifest.fail("RT context manifests require RTContext=true");
  else
    Manifest.initialize(C.getASTContext(), C.getBugReporter().getPreprocessor());
  if (!Manifest.Error.empty()) {
    if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
      auto R = std::make_unique<PathSensitiveBugReport>(
          UnknownBug, Manifest.Error, N);
      C.emitReport(std::move(R));
    }
    return;
  }
  const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getStackFrame()->getDecl());
  const RTManifestFunction *F = Manifest.find(FD, C);
  if (!F || F->Kind != "entry")
    return;
  ProgramStateRef State = setIRQState(C.getState(), {F->IRQ, nullptr});
  auto &Factory = State->get_context<ActiveAtomicSections>();
  auto Sections = State->get<ActiveAtomicSections>();
  auto Add = [&](SectionKind Kind, unsigned Amount) {
    if (!Amount)
      return;
    AtomicSection Section;
    Section.Kind = Kind;
    Section.Amount = Amount;
    Sections = Factory.add(Section, Sections);
  };
  Add(SectionKind::Preempt, F->Preempt);
  Add(SectionKind::BottomHalf, F->BH);
  Add(SectionKind::RCU, F->RCU);
  Add(SectionKind::Migration, F->Migration);
  if (F->EntryKind == "hardirq")
    Add(SectionKind::HardIRQ, 1);
  else if (F->EntryKind == "nmi")
    Add(SectionKind::NMI, 1);
  else if (F->EntryKind == "softirq" && !F->BH)
    Add(SectionKind::BottomHalf, 1);
  C.addTransition(State->set<ActiveAtomicSections>(Sections));
}

void LinuxAtomicSleepChecker::checkEndOfTranslationUnit(
    const TranslationUnitDecl *TU, AnalysisManager &Mgr,
    BugReporter &BR) const {
  if ((Manifest.Path.empty() && Manifest.Output.empty()) ||
      Manifest.Initialized || !Manifest.Error.empty())
    return;

  if (!RTContext)
    Manifest.fail("RT context manifests require RTContext=true");
  else
    Manifest.initialize(Mgr.getASTContext(), BR.getPreprocessor());
  if (Manifest.Error.empty())
    return;

  SourceManager &SM = Mgr.getASTContext().getSourceManager();
  SourceLocation Loc = SM.getLocForStartOfFile(SM.getMainFileID());
  for (const Decl *D : TU->decls()) {
    SourceLocation Candidate = SM.getExpansionLoc(D->getLocation());
    if (Candidate.isValid() && SM.isWrittenInMainFile(Candidate)) {
      Loc = Candidate;
      break;
    }
  }
  auto Report = std::make_unique<BasicBugReport>(
      UnknownBug, Manifest.Error, PathDiagnosticLocation(Loc, SM));
  BR.emitReport(std::move(Report));
}

void LinuxAtomicSleepChecker::checkPreCall(const CallEvent &Call,
                                           CheckerContext &C) const {
  const FunctionDecl *FD = getCallee(Call);
  if (!FD)
    return;

  StringRef Name = FD->getName();
  if (RTContext && Manifest.Initialized && Manifest.Error.empty())
    if (const auto *F = Manifest.find(FD, C))
      if (F->Kind == "effect") {
        if (F->Effect == "rt-lock-wait" && isRT(C))
          reportSleep(Call, ("Imported RT lock wait in '" + Name + "'").str(), C, true);
        else if (F->Effect == "ordinary-sleep")
          reportSleep(Call, ("Imported sleeping effect in '" + Name + "'").str(), C);
        // Do not bypass primitive IRQ/lock/context accounting below.
      }
  if (RTContext) {
    ContextCall CC = classifyContextCall(Name);
    LockCall LC = classifyLockCall(Name);
    bool Save = CC.Op == ContextOp::IRQSave || CC.Op == ContextOp::IRQSample ||
                (LC.Kind == LockKind::Spin && LC.Op != LockOp::Release &&
                 Name.contains("irqsave"));
    if (Save && Call.getOriginExpr())
      C.addTransition(C.getState()->set<PendingIRQSave>(
          Call.getOriginExpr(), getIRQState(C.getState())));
    if (isRT(C) && isRTLock(LC.Kind) &&
        (LC.Op == LockOp::Acquire || LC.Op == LockOp::AcquireAndRelease)) {
      reportSleep(Call, ("Call to RT lock '" + Name + "'").str(), C, true);
      return;
    }
  }
  if (C.getState()->get<ActiveAtomicSections>().isEmpty() &&
      (!RTContext || getIRQState(C.getState()).Mode != IRQMode::Disabled))
    return;
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
    else if (!FD->hasBody() && Sleepers.contains(Name))
      reportSleep(Call,
                  ("Call to '" + Name +
                   "' (always sleeps, according to its definition)")
                      .str(),
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
  auto &Factory = State->get_context<ActiveAtomicSections>();
  const auto Sections = State->get<ActiveAtomicSections>();
  StringRef Name = FD->getName();
  if (RTContext && Manifest.Initialized && Manifest.Error.empty() && !C.wasInlined)
    if (const auto *F = Manifest.find(FD, C))
      if (F->Kind == "effect") {
        auto List = State->get<ActiveAtomicSections>();
        auto &Factory = State->get_context<ActiveAtomicSections>();
        std::vector<AtomicSection> Kept;
        for (auto Section : List) {
          Section.Uncertain = true;
          Kept.push_back(Section);
        }
        List = Factory.getEmptyList();
        for (auto I = Kept.rbegin(); I != Kept.rend(); ++I)
          List = Factory.add(*I, List);
        State = setIRQState(State->set<ActiveAtomicSections>(List)
                                ->set<UnknownContextKinds>((1u << 9) - 1)
                                ->set<IRQSaveBalanceUnknown>(true), {});
        reportUnknown(Call, C, State,
                      "Imported effect has no proved post-call context preservation");
        return;
      }
  CallRole CR = role(Call, C);
  bool UnknownRestore = false;
  if (RTContext && classifyLockCall(Name).Op == LockOp::AcquireAndRelease)
    return;

  // Accounting helpers can add/subtract several independent fields in one
  // call. Do not turn a BH offset into preemption depth or lose an outer
  // entry when a bulk subtraction spans multiple nested entries.
  ContextCall CountCall = classifyContextCall(Name);
  if (RTContext && C.wasInlined &&
      (CountCall.Op == ContextOp::Enter || CountCall.Op == ContextOp::Leave))
    return; // The wrapper's leaf effects were already applied on this path.
  bool BHCount = CountCall.Kind == ContextKind::BottomHalf &&
                 (Name == "__local_bh_disable_ip" || Name == "__local_bh_enable_ip");
  bool PreemptCount = CountCall.Kind == ContextKind::Preempt &&
                      Name.contains("count_");
  if (RTContext && (PreemptCount || BHCount) &&
      (CountCall.Op == ContextOp::Enter || CountCall.Op == ContextOp::Leave) &&
      Call.getNumArgs() > (BHCount ? 1u : 0u)) {
    const llvm::APSInt *Value = C.getSValBuilder().getKnownValue(
        State, Call.getArgSVal(BHCount ? 1 : 0));
    if (!Value || Value->isNegative()) {
      llvm::ImmutableList<AtomicSection> List = Factory.getEmptyList();
      llvm::SmallVector<AtomicSection, 8> Open(Sections.begin(), Sections.end());
      for (AtomicSection Section : llvm::reverse(Open)) {
        if (Section.Kind == SectionKind::Preempt ||
            Section.Kind == SectionKind::BottomHalf ||
            Section.Kind == SectionKind::HardIRQ ||
            Section.Kind == SectionKind::NMI ||
            Section.Kind == SectionKind::IRQDisabled)
          Section.Uncertain = true;
        List = Factory.add(Section, List);
      }
      unsigned Unknown = State->get<UnknownContextKinds>() |
                         sectionMask(SectionKind::Preempt) |
                         sectionMask(SectionKind::BottomHalf) |
                         sectionMask(SectionKind::HardIRQ) |
                         sectionMask(SectionKind::NMI) |
                         sectionMask(SectionKind::IRQDisabled);
      State = State->set<UnknownContextKinds>(Unknown);
      reportUnknown(Call, C, State->set<ActiveAtomicSections>(List),
                    "Unknown preemption-counter effect");
      return;
    }
    uint64_t Bits = Value->getZExtValue();
    if (!Bits)
      return;
    const Preprocessor &PP = C.getBugReporter().getPreprocessor();
    auto Width = [&](StringRef Macro, unsigned Default) -> unsigned {
      auto V = tryExpandAsInteger(Macro, PP);
      return V && *V >= 0 && *V < 32 ? static_cast<unsigned>(*V) : Default;
    };
    unsigned Preempt = Width("PREEMPT_BITS", 8);
    unsigned BH = Width("SOFTIRQ_BITS", 8);
    // Older kernels lack the separate hard-IRQ-disable field.
    unsigned IRQDisable = Width("HARDIRQ_DISABLE_BITS", 0);
    unsigned Hard = Width("HARDIRQ_BITS", 4);
    bool SeparateResched =
        tryExpandAsInteger("CONFIG_HAS_SEPARATE_PREEMPT_RESCHED_BITS", PP) == 1;
    unsigned NMI = SeparateResched ? 4 : 1;
    if (!SeparateResched)
      Bits &= ~(uint64_t(1) << 31);
    std::pair<SectionKind, unsigned> Fields[] = {
        {SectionKind::Preempt, Preempt}, {SectionKind::BottomHalf, BH},
        {SectionKind::IRQDisabled, IRQDisable}, {SectionKind::HardIRQ, Hard},
        {SectionKind::NMI, NMI}};
    llvm::SmallVector<AtomicSection, 8> Open(Sections.begin(), Sections.end());
    unsigned Shift = 0;
    bool Incomplete = false;
    AtomicSection Last;
    for (const auto &[Kind, Size] : Fields) {
      if (!Size)
        continue;
      if (Shift + Size > 32) {
        Incomplete = true;
        break;
      }
      unsigned Amount = (Bits >> Shift) & ((uint64_t(1) << Size) - 1);
      Shift += Size;
      // On RT the BH helper updates a separate task/per-CPU softirq count;
      // its cnt argument is not an explicit preempt-count update.
      if (BHCount && isRT(C) && Kind != SectionKind::BottomHalf) {
        Incomplete |= Amount != 0;
        continue;
      }
      if (!Amount)
        continue;
      if (CountCall.Op == ContextOp::Enter) {
        AtomicSection Section;
        Section.Entry = Call.getOriginExpr();
        Section.Kind = Kind;
        Section.Amount = Amount;
        Section.Uncertain = State->get<UnknownContextKinds>() & sectionMask(Kind);
        Open.insert(Open.begin(), Section);
        Last = Section;
      } else {
        for (auto It = Open.begin(); It != Open.end() && Amount;) {
          if (It->Kind != Kind) {
            ++It;
            continue;
          }
          unsigned Removed = std::min(Amount, It->Amount);
          Amount -= Removed;
          It->Amount -= Removed;
          if (!It->Amount)
            It = Open.erase(It);
          else
            ++It;
        }
        Incomplete |= Amount != 0;
      }
    }
    // Reschedule bits are scheduler metadata, not a new atomic section.
    uint64_t Remaining = Shift < 32 ? Bits >> Shift : 0;
    Incomplete |= Remaining != 0;
    llvm::ImmutableList<AtomicSection> List = Factory.getEmptyList();
    for (const AtomicSection &Section : llvm::reverse(Open))
      List = Factory.add(Section, List);
    State = State->set<ActiveAtomicSections>(List);
    if (Incomplete) {
      unsigned CounterKinds = sectionMask(SectionKind::Preempt) |
                              sectionMask(SectionKind::BottomHalf) |
                              sectionMask(SectionKind::IRQDisabled) |
                              sectionMask(SectionKind::HardIRQ) |
                              sectionMask(SectionKind::NMI);
      List = Factory.getEmptyList();
      for (AtomicSection Section : llvm::reverse(Open)) {
        if (CounterKinds & sectionMask(Section.Kind))
          Section.Uncertain = true;
        List = Factory.add(Section, List);
      }
      State = State->set<ActiveAtomicSections>(List)
                  ->set<UnknownContextKinds>(State->get<UnknownContextKinds>() |
                                             CounterKinds);
      reportUnknown(Call, C, State, "Unbalanced or unsupported preemption-counter effect");
    } else
      C.addTransition(State, Last.Entry ? createEntryNote(Last, C) : nullptr);
    return;
  }

  if (RTContext) {
    ContextCall CC = classifyContextCall(Name);
    LockCall LC = classifyLockCall(Name);
    bool Raw = LC.Kind == LockKind::Spin && LC.Op != LockOp::None;
    bool Save = CC.Op == ContextOp::IRQSave || CC.Op == ContextOp::IRQSample ||
                (Raw && LC.Op != LockOp::Release && Name.contains("irqsave"));
    bool Restore = CC.Op == ContextOp::IRQRestore ||
                   (Raw && LC.Op == LockOp::Release &&
                    Name.ends_with("irqrestore"));
    if (Save) {
      if (const IRQState *Before = State->get<PendingIRQSave>(Call.getOriginExpr()))
        if (SymbolRef Sym = Call.getReturnValue().getAsSymbol()) {
          State = storeSavedIRQState(State, Sym, *Before);
          if (CC.Op != ContextOp::IRQSample)
            State = State->set<OutstandingIRQSaves>(Sym, Call.getOriginExpr());
        }
      State = State->remove<PendingIRQSave>(Call.getOriginExpr());
      if (CC.Op != ContextOp::IRQSample)
        State = setIRQState(State, {IRQMode::Disabled, Call.getOriginExpr()});
    } else if (Restore) {
      unsigned Arg = Raw ? 1 : 0;
      SymbolRef Flags = Call.getNumArgs() > Arg ? getIRQFlagsSymbol(
          State, Call.getArgSVal(Arg).getAsSymbol()) : nullptr;
      std::optional<IRQState> Before = Flags ? getSavedIRQState(State, Flags)
                                            : std::nullopt;
      if (Flags && Before)
        State = State->remove<OutstandingIRQSaves>(Flags);
      IRQState Current = getIRQState(State);
      IRQState Restored = Before ? *Before : IRQState{};
      bool EnableOnly = isEnableOnlyIRQRestore(Name, C);
      if (EnableOnly) {
        // Native x86 restoring IRQ-off flags does not disable IRQs. A
        // current enabled state stays enabled even with unknown flags.
        if (Current.Mode == IRQMode::Enabled ||
            (Before && Before->Mode == IRQMode::Disabled))
          Restored = Current;
      }
      State = setIRQState(State, Restored);
      UnknownRestore = !Before &&
                       !(EnableOnly && Current.Mode == IRQMode::Enabled);
      if (UnknownRestore)
        State = State->set<IRQSaveBalanceUnknown>(true);
      if (UnknownRestore && CR.R == Role::None) {
        reportUnknown(Call, C, State, "IRQ restore uses flags without a known saved state");
        return;
      }
    } else if (CC.Op == ContextOp::IRQDisable ||
               (Raw && LC.Op != LockOp::Release && Name.ends_with("_irq"))) {
      State = setIRQState(State, {IRQMode::Disabled, Call.getOriginExpr()});
    } else if (CC.Op == ContextOp::IRQEnable ||
               (Raw && LC.Op == LockOp::Release && Name.ends_with("_irq"))) {
      State = setIRQState(State, {IRQMode::Enabled, nullptr});
    }
    if (State != C.getState() && CR.R == Role::None) {
      IRQState After = getIRQState(State);
      const NoteTag *Note = nullptr;
      if (After.Mode == IRQMode::Disabled) {
        const BugType *SleepBT = &SleepBug;
        const BugType *RTBT = &RTLockBug;
        const Expr *Entry = After.Entry;
        Note = C.getNoteTag([SleepBT, RTBT, Entry](PathSensitiveBugReport &BR,
                                                llvm::raw_ostream &OS) {
          if ((&BR.getBugType() == SleepBT || &BR.getBugType() == RTBT) &&
              getIRQState(BR.getErrorNode()->getState()).Entry == Entry)
            OS << "Hard interrupts disabled here";
        });
      }
      C.addTransition(State, Note);
      return;
    }
  }

  switch (CR.R) {
  case Role::Enter:
  case Role::TryEnter: {
    AtomicSection Section;
    Section.Entry = Call.getOriginExpr();
    Section.Kind = CR.Kind;
    if ((CR.Kind == SectionKind::Lock || CR.Kind == SectionKind::RTLock) &&
        Call.getNumArgs() >= 1)
      Section.Lock = Call.getArgSVal(0).getAsRegion();
    if (Section.Lock)
      Section.Lock = Section.Lock->StripCasts();
    if (RTContext && CR.Kind == SectionKind::Preempt && Call.getNumArgs())
      if (const llvm::APSInt *Count = C.getSValBuilder().getKnownValue(
              State, Call.getArgSVal(0)))
        Section.Amount = std::max<unsigned>(1, Count->getZExtValue() & 0xff);
    // An inline lock function ends in the out-of-line one for the same lock.
    if (Section.Lock &&
        llvm::any_of(Sections, [&](const AtomicSection &Open) {
          return Open.Kind == CR.Kind && Open.Lock == Section.Lock;
        }))
      return;

    auto Enter = [&](ProgramStateRef Input) {
      // The BH suffix retains an independent BH obligation even if a caller
      // later drops this lock through a plain unlock operation.
      if (RTContext && !C.wasInlined && Section.Lock && Name.ends_with("_bh")) {
        AtomicSection BHSection;
        BHSection.Entry = Call.getOriginExpr();
        BHSection.Kind = SectionKind::BottomHalf;
        BHSection.Amount = 2; // SOFTIRQ_DISABLE_OFFSET / SOFTIRQ_OFFSET.
        BHSection.Uncertain = State->get<UnknownContextKinds>() &
                              sectionMask(SectionKind::BottomHalf);
        Input = Input->add<ActiveAtomicSections>(BHSection);
      }
      return Input->add<ActiveAtomicSections>(Section);
    };
    ProgramStateRef Entered = Enter(State);
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
      C.addTransition(Enter(Taken), createEntryNote(Section, C));
    if (Missed)
      C.addTransition(Missed);
    return;
  }
  case Role::Leave: {
    const MemRegion *Lock = nullptr;
    if ((CR.Kind == SectionKind::Lock || CR.Kind == SectionKind::RTLock) &&
        Call.getNumArgs() >= 1)
      Lock = Call.getArgSVal(0).getAsRegion();
    if (Lock)
      Lock = Lock->StripCasts();
    // Drop the innermost section of this kind.  For a lock, prefer the
    // section of this very lock if the path has seen it being taken.
    llvm::SmallVector<AtomicSection, 8> Open(Sections.begin(), Sections.end());
    int Match = -1;
    for (int I = 0, E = Open.size(); I != E; ++I) {
      if (Open[I].Kind != CR.Kind)
        continue;
      if (Match < 0 && !Lock)
        Match = I;
      if (Lock && Open[I].Lock == Lock) {
        Match = I;
        break;
      }
    }
    if (Match < 0 && !RTContext) {
      for (int I = 0, E = Open.size(); I != E; ++I)
        if (Open[I].Kind == CR.Kind) { Match = I; break; }
    }
    bool ReleaseBH = RTContext && !C.wasInlined && Name.ends_with("_bh");
    if (Match < 0 && !ReleaseBH) {
      if (UnknownRestore)
        reportUnknown(Call, C, State, "IRQ restore uses flags without a known saved state");
      else if (State != C.getState())
        C.addTransition(State);
      return;
    }
    unsigned Amount = 1;
    if (RTContext && CR.Kind == SectionKind::Preempt && Call.getNumArgs())
      if (const llvm::APSInt *Count = C.getSValBuilder().getKnownValue(
              State, Call.getArgSVal(0)))
        Amount = std::max<unsigned>(1, Count->getZExtValue() & 0xff);
    if (Match >= 0) {
      if (RTContext && Open[Match].Amount > Amount)
        Open[Match].Amount -= Amount;
      else
        Open.erase(Open.begin() + Match);
    }
    bool BHUnderflow = false;
    if (ReleaseBH) {
      unsigned Remaining = 2;
      for (auto It = Open.begin(); It != Open.end() && Remaining;) {
        if (It->Kind != SectionKind::BottomHalf) {
          ++It;
          continue;
        }
        unsigned Removed = std::min(Remaining, It->Amount);
        Remaining -= Removed;
        It->Amount -= Removed;
        if (!It->Amount)
          It = Open.erase(It);
        else
          ++It;
      }
      BHUnderflow = Remaining != 0;
    }
    llvm::ImmutableList<AtomicSection> List = Factory.getEmptyList();
    for (const AtomicSection &Section : llvm::reverse(Open))
      List = Factory.add(Section, List);
    State = State->set<ActiveAtomicSections>(List);
    if (BHUnderflow) {
      State = State->set<UnknownContextKinds>(State->get<UnknownContextKinds>() |
                                              sectionMask(SectionKind::BottomHalf));
      reportUnknown(Call, C, State, "BH release exceeds the known disabled depth");
    } else if (UnknownRestore)
      reportUnknown(Call, C, State, "IRQ restore uses flags without a known saved state");
    else
      C.addTransition(State);
    return;
  }
  case Role::None:
    break;
  default:
    return;
  }

  if (Sections.isEmpty() && (!RTContext || getIRQState(State).Mode == IRQMode::Unknown))
    return;
  // A function that was not inlined although it unlocks something further
  // down, or an external one named like an unlock helper, may have left the
  // critical section.
  unsigned Affected = RTContext ? affectedContexts(FD, 0) : 0;
  bool Opaque = !C.wasInlined && (RTContext ? Affected != 0 : mayLeaveAtomicSection(FD, 0));
  bool UnlockHelper = !FD->hasBody() &&
                      (RTContext ? Affected != 0 : looksLikeUnlock(FD));
  if (Opaque || UnlockHelper) {
    if (!RTContext) {
      C.addTransition(State->set<ActiveAtomicSections>(Factory.getEmptyList()));
      return;
    }
    // An unresolved release cannot justify clearing unrelated atomic state.
    // Retain it, mark possible lock releases unknown, and expose the gap.
    llvm::ImmutableList<AtomicSection> List = Factory.getEmptyList();
    llvm::SmallVector<AtomicSection, 8> Uncertain(Sections.begin(), Sections.end());
    for (AtomicSection Section : llvm::reverse(Uncertain)) {
      if (Affected & sectionMask(Section.Kind))
        Section.Uncertain = true;
      List = Factory.add(Section, List);
    }
    State = State->set<ActiveAtomicSections>(List);
    State = State->set<UnknownContextKinds>(State->get<UnknownContextKinds>() | Affected);
    if (Affected & sectionMask(SectionKind::IRQDisabled))
      State = setIRQState(State->set<IRQSaveBalanceUnknown>(true), {});
    reportUnknown(Call, C, State);
  }
}

/// The contracts file has one "sleeps <name>" line for each function that
/// was found to sleep whenever it runs, in whatever translation unit it is
/// defined.  That is what the analyzer cannot see from here.
void LinuxAtomicSleepChecker::loadSleepers(CheckerManager &Mgr) {
  const std::string &Path = Mgr.getLangOpts().LinuxKernelContractsFile;
  if (Path.empty())
    return;
  auto Buffer = Mgr.getASTContext().getSourceManager().getFileManager()
                    .getBufferForFile(Path);
  if (!Buffer)
    return;
  for (llvm::line_iterator Line(**Buffer, /*SkipBlanks=*/true, '#');
       !Line.is_at_end(); ++Line) {
    auto [Kind, Name] = Line->split('\t');
    if (Kind == "sleeps" && !Name.trim().empty())
      Sleepers.insert(Name.trim());
  }
}

void ento::registerLinuxAtomicSleepChecker(CheckerManager &Mgr) {
  auto *Checker = Mgr.registerChecker<LinuxAtomicSleepChecker>();
  Checker->loadSleepers(Mgr);
  Checker->RTContext = Mgr.getAnalyzerOptions().getCheckerBooleanOption(
      Checker, "RTContext");
  Checker->Manifest.Path = Mgr.getAnalyzerOptions().getCheckerStringOption(
      Checker, "RTContextManifest").str();
  Checker->Manifest.Output = Mgr.getAnalyzerOptions().getCheckerStringOption(
      Checker, "RTContextManifestOutput").str();
  if (Checker->RTContext)
    linuxkernel::enableRTContext(Mgr);
  linuxkernel::addInterest(Mgr, linuxkernel::AtomicSections);
}

bool ento::shouldRegisterLinuxAtomicSleepChecker(const CheckerManager &Mgr) {
  return true;
}
