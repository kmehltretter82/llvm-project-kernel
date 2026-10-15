//===- ClangKernelLab.cpp - Linux kernel experiment instrumentation -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This pass adds explicitly requested callbacks and perturbation points around
// Linux kernel context transitions.  It is deliberately separate from the
// text-inert site-map mode: loading this pass changes generated code and must
// never be used to claim that an unperturbed timing property was preserved.
// The first implementation is a pass plugin so experimental policy stays out
// of the Clang driver while the callback ABI is being qualified.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Plugins/PassPlugin.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Process.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/xxhash.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace llvm;

namespace {

constexpr StringLiteral SpecEnvironment = "CLANG_KERNEL_LAB_SPEC";
constexpr StringLiteral CallbackHookName = "__clang_kernel_lab_callback";
constexpr StringLiteral PerturbHookName = "__clang_kernel_lab_perturb";
constexpr StringLiteral SiteSectionName = ".clang_kernel_lab.callback_sites";
constexpr uint64_t MaxSpecBytes = 1024 * 1024;
constexpr uint32_t SiteMagic = 0x42414c4b; // "KLAB" in a little-endian object.
constexpr uint16_t SiteABIVersion = 1;

enum class MatchKind : uint8_t { Call, Function };
enum class SitePhase : uint8_t { Before = 1, After = 2, Entry = 3, Exit = 4 };

enum Action : uint8_t {
  ActionCallback = 1U << 0,
  ActionPerturb = 1U << 1,
};

struct Rule {
  MatchKind Match = MatchKind::Call;
  SitePhase Phase = SitePhase::Before;
  uint8_t Actions = 0;
  uint32_t EventID = 0;
  uint32_t PerturbClass = 0;
  std::string Symbol;
  std::string Event;
};

struct Config {
  uint64_t Hash = 0;
  bool RequireSite = false;
  bool Strict = true;
  std::string TargetOS = "linux";
  std::vector<Rule> Rules;
};

struct LoadedConfig {
  bool Requested = false;
  std::optional<Config> Value;
  std::string Error;
};

struct PlannedSite {
  Instruction *Anchor = nullptr;
  const Rule *Descriptor = nullptr;
  uint64_t ID = 0;
  unsigned Line = 0;
  unsigned Column = 0;
  unsigned Ordinal = 0;
  std::string FunctionName;
  std::string CalleeName;
  std::string SourceName;
};

static Error configError(const Twine &Message) {
  return make_error<StringError>(Message.str(), inconvertibleErrorCode());
}

static Expected<MatchKind> parseMatch(StringRef Text) {
  if (Text == "call")
    return MatchKind::Call;
  if (Text == "function")
    return MatchKind::Function;
  return configError("match must be 'call' or 'function'");
}

static Expected<SitePhase> parsePhase(StringRef Text, MatchKind Match) {
  if (Text == "before" && Match == MatchKind::Call)
    return SitePhase::Before;
  if (Text == "after" && Match == MatchKind::Call)
    return SitePhase::After;
  if (Text == "entry" && Match == MatchKind::Function)
    return SitePhase::Entry;
  if (Text == "exit" && Match == MatchKind::Function)
    return SitePhase::Exit;
  return configError("position does not apply to the selected match kind");
}

static Expected<uint8_t> parseActions(StringRef Text) {
  if (Text == "callback")
    return ActionCallback;
  if (Text == "perturb")
    return ActionPerturb;
  if (Text == "callback+perturb")
    return ActionCallback | ActionPerturb;
  return configError(
      "action must be 'callback', 'perturb', or 'callback+perturb'");
}

static Expected<Config> parseConfig(StringRef Path) {
  auto Buffer = MemoryBuffer::getFile(Path, /*IsText=*/true);
  if (!Buffer)
    return configError(Twine("cannot read specification '") + Path +
                       "': " + Buffer.getError().message());
  if ((*Buffer)->getBufferSize() > MaxSpecBytes)
    return configError("specification exceeds the 1 MiB input limit");

  StringRef Text = (*Buffer)->getBuffer();
  auto Parsed = json::parse(Text);
  if (!Parsed)
    return configError(Twine("invalid JSON: ") + toString(Parsed.takeError()));
  const json::Object *Root = Parsed->getAsObject();
  if (!Root)
    return configError("top-level specification must be an object");
  if (Root->getInteger("schema") != 1)
    return configError("unsupported or missing schema; expected 1");

  Config Result;
  Result.Hash = xxh3_64bits(Text);
  if (auto RequireSite = Root->getBoolean("require_site"))
    Result.RequireSite = *RequireSite;
  if (auto Strict = Root->getBoolean("strict"))
    Result.Strict = *Strict;
  if (auto TargetOS = Root->getString("target_os")) {
    if (*TargetOS != "linux" && *TargetOS != "any")
      return configError("target_os must be 'linux' or 'any'");
    Result.TargetOS = TargetOS->str();
  }

  const json::Array *Events = Root->getArray("events");
  if (!Events || Events->empty())
    return configError("specification must contain at least one event rule");
  if (Events->size() > 4096)
    return configError("specification exceeds the 4096-rule limit");

  std::set<std::string> RuleKeys;
  DenseMap<uint32_t, std::string> EventNames;
  for (const json::Value &Value : *Events) {
    const json::Object *Object = Value.getAsObject();
    if (!Object)
      return configError("each event rule must be an object");
    auto MatchText = Object->getString("match");
    auto PositionText = Object->getString("position");
    auto ActionText = Object->getString("action");
    auto Symbol = Object->getString("symbol");
    auto Event = Object->getString("event");
    auto EventID = Object->getInteger("event_id");
    if (!MatchText || !PositionText || !ActionText || !Symbol || !Event ||
        !EventID)
      return configError("event rule lacks a required field");
    if (Symbol->empty() || Symbol->size() > 256 || Event->empty() ||
        Event->size() > 128)
      return configError("event symbol or name has an invalid length");
    if (*EventID <= 0 ||
        static_cast<uint64_t>(*EventID) > std::numeric_limits<uint32_t>::max())
      return configError("event_id must fit in a nonzero uint32_t");

    Expected<MatchKind> Match = parseMatch(*MatchText);
    if (!Match)
      return Match.takeError();
    Expected<SitePhase> Phase = parsePhase(*PositionText, *Match);
    if (!Phase)
      return Phase.takeError();
    Expected<uint8_t> Actions = parseActions(*ActionText);
    if (!Actions)
      return Actions.takeError();

    Rule R;
    R.Match = *Match;
    R.Phase = *Phase;
    R.Actions = *Actions;
    R.EventID = static_cast<uint32_t>(*EventID);
    R.Symbol = Symbol->str();
    R.Event = Event->str();
    if (R.Actions & ActionPerturb) {
      auto PerturbClass = Object->getInteger("perturb_class");
      if (!PerturbClass || *PerturbClass <= 0 ||
          static_cast<uint64_t>(*PerturbClass) >
              std::numeric_limits<uint32_t>::max())
        return configError(
            "perturbing rules need a nonzero uint32_t perturb_class");
      R.PerturbClass = static_cast<uint32_t>(*PerturbClass);
    }

    std::string EventName = R.Event;
    auto Existing = EventNames.find(R.EventID);
    if (Existing != EventNames.end() && Existing->second != EventName)
      return configError("one event_id names multiple semantic events");
    EventNames.try_emplace(R.EventID, std::move(EventName));

    std::string Key =
        (Twine(*MatchText) + "\n" + R.Symbol + "\n" + *PositionText).str();
    if (!RuleKeys.insert(std::move(Key)).second)
      return configError("duplicate match/symbol/position rule");
    Result.Rules.push_back(std::move(R));
  }
  return Result;
}

static std::shared_ptr<const LoadedConfig> loadConfig() {
  auto Result = std::make_shared<LoadedConfig>();
  std::optional<std::string> Path = sys::Process::GetEnv(SpecEnvironment);
  if (!Path || Path->empty())
    return Result;
  Result->Requested = true;
  Expected<Config> Parsed = parseConfig(*Path);
  if (!Parsed) {
    Result->Error = toString(Parsed.takeError());
    return Result;
  }
  Result->Value = std::move(*Parsed);
  return Result;
}

static StringRef phaseName(SitePhase Phase) {
  switch (Phase) {
  case SitePhase::Before:
    return "before";
  case SitePhase::After:
    return "after";
  case SitePhase::Entry:
    return "entry";
  case SitePhase::Exit:
    return "exit";
  }
  llvm_unreachable("unknown kernel lab phase");
}

static void findLocation(const Instruction &I, const Function &F,
                         const Module &M, std::string &Source, unsigned &Line,
                         unsigned &Column) {
  Source = sys::path::filename(M.getSourceFileName()).str();
  if (const DebugLoc &Location = I.getDebugLoc()) {
    Source = sys::path::filename(Location->getFilename()).str();
    Line = Location.getLine();
    Column = Location.getCol();
    return;
  }
  if (const DISubprogram *Subprogram = F.getSubprogram()) {
    Source = sys::path::filename(Subprogram->getFilename()).str();
    Line = Subprogram->getLine();
  }
}

static uint64_t siteID(const Config &Configuration, const PlannedSite &Site) {
  SmallString<256> Key;
  raw_svector_ostream OS(Key);
  OS << Configuration.Hash << '\0' << Site.SourceName << '\0'
     << Site.FunctionName << '\0' << Site.CalleeName << '\0'
     << Site.Descriptor->EventID << '\0'
     << static_cast<unsigned>(Site.Descriptor->Phase) << '\0' << Site.Line
     << '\0' << Site.Column << '\0' << Site.Ordinal;
  uint64_t ID = xxh3_64bits(OS.str());
  return ID == 0 ? 1 : ID;
}

static MDNode *siteMetadata(LLVMContext &Context, const PlannedSite &Site) {
  const Rule &R = *Site.Descriptor;
  Metadata *Fields[] = {
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt64Ty(Context), Site.ID)),
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt32Ty(Context), R.EventID)),
      MDString::get(Context, R.Event),
      MDString::get(Context, phaseName(R.Phase)),
      MDString::get(Context, Site.FunctionName),
      MDString::get(Context, Site.CalleeName),
      MDString::get(Context, Site.SourceName),
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt32Ty(Context), Site.Line)),
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt32Ty(Context), Site.Column)),
  };
  return MDNode::get(Context, Fields);
}

static void emitSiteSection(Module &M, ArrayRef<PlannedSite> Sites,
                            uint64_t SpecHash) {
  if (Sites.empty())
    return;
  LLVMContext &Context = M.getContext();
  Type *I8 = Type::getInt8Ty(Context);
  Type *I16 = Type::getInt16Ty(Context);
  Type *I32 = Type::getInt32Ty(Context);
  Type *I64 = Type::getInt64Ty(Context);
  StructType *RecordType =
      StructType::get(Context, {I32, I16, I8, I8, I64, I32, I32, I32, I32},
                      /*isPacked=*/true);
  SmallVector<Constant *, 16> Records;
  for (const PlannedSite &Site : Sites) {
    const Rule &R = *Site.Descriptor;
    Constant *Fields[] = {
        ConstantInt::get(I32, SiteMagic),
        ConstantInt::get(I16, SiteABIVersion),
        ConstantInt::get(I8, static_cast<uint8_t>(R.Phase)),
        ConstantInt::get(I8, R.Actions),
        ConstantInt::get(I64, Site.ID),
        ConstantInt::get(I32, R.EventID),
        ConstantInt::get(I32, R.PerturbClass),
        ConstantInt::get(I32, Site.Line),
        ConstantInt::get(I32, Site.Column),
    };
    Records.push_back(ConstantStruct::get(RecordType, Fields));
  }
  ArrayType *TableType = ArrayType::get(RecordType, Records.size());
  auto *Table = new GlobalVariable(
      M, TableType, /*isConstant=*/true, GlobalValue::PrivateLinkage,
      ConstantArray::get(TableType, Records),
      (Twine("__clang_kernel_lab_sites.") + Twine::utohexstr(SpecHash)).str());
  Table->setSection(SiteSectionName);
  Table->setAlignment(Align(8));
  appendToCompilerUsed(M, {Table});
}

class KernelLabPass : public PassInfoMixin<KernelLabPass> {
public:
  explicit KernelLabPass(std::shared_ptr<const LoadedConfig> Loaded)
      : Loaded(std::move(Loaded)) {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &);
  static bool isRequired() { return true; }

private:
  std::shared_ptr<const LoadedConfig> Loaded;
};

PreservedAnalyses KernelLabPass::run(Module &M, ModuleAnalysisManager &) {
  if (M.getModuleFlag("clang.kernel.lab.instrumented"))
    return PreservedAnalyses::all();
  if (!Loaded->Requested)
    return PreservedAnalyses::all();
  if (!Loaded->Error.empty()) {
    M.getContext().emitError(Twine("clang-kernel-lab: ") + Loaded->Error);
    return PreservedAnalyses::all();
  }
  const Config &Configuration = *Loaded->Value;
  Triple Target(M.getTargetTriple());
  if (!Target.isRISCV()) {
    M.getContext().emitError(
        "clang-kernel-lab: the initial instrumentation target is RISC-V");
    return PreservedAnalyses::all();
  }
  if (Configuration.TargetOS == "linux" && !Target.isOSLinux()) {
    M.getContext().emitError(
        "clang-kernel-lab: specification requires a Linux target triple");
    return PreservedAnalyses::all();
  }

  std::vector<PlannedSite> Sites;
  std::vector<std::string> Gaps;
  for (Function &F : M) {
    if (F.isDeclaration() || F.getName().starts_with("__clang_kernel_lab_"))
      continue;

    DenseMap<const Instruction *, unsigned> Ordinals;
    unsigned NextOrdinal = 1;
    for (Instruction &I : instructions(F))
      Ordinals[&I] = NextOrdinal++;

    for (const Rule &R : Configuration.Rules) {
      if (R.Match != MatchKind::Function || R.Symbol != F.getName())
        continue;
      if (R.Phase == SitePhase::Entry) {
        BasicBlock::iterator Point = F.getEntryBlock().getFirstInsertionPt();
        if (Point == F.getEntryBlock().end()) {
          Gaps.push_back(
              (Twine(F.getName()) + ": no entry insertion point").str());
          continue;
        }
        PlannedSite Site;
        Site.Anchor = &*Point;
        Site.Descriptor = &R;
        Site.FunctionName = F.getName().str();
        Site.Ordinal = 0;
        findLocation(*Site.Anchor, F, M, Site.SourceName, Site.Line,
                     Site.Column);
        Site.ID = siteID(Configuration, Site);
        Sites.push_back(std::move(Site));
      } else {
        for (Instruction &I : instructions(F)) {
          if (!isa<ReturnInst>(I))
            continue;
          PlannedSite Site;
          Site.Anchor = &I;
          Site.Descriptor = &R;
          Site.FunctionName = F.getName().str();
          Site.Ordinal = Ordinals.lookup(&I);
          findLocation(I, F, M, Site.SourceName, Site.Line, Site.Column);
          Site.ID = siteID(Configuration, Site);
          Sites.push_back(std::move(Site));
        }
      }
    }

    for (Instruction &I : instructions(F)) {
      auto *Call = dyn_cast<CallBase>(&I);
      if (!Call)
        continue;
      Function *Callee =
          dyn_cast<Function>(Call->getCalledOperand()->stripPointerCasts());
      if (!Callee || Callee->isIntrinsic() ||
          Callee->getName().starts_with("__clang_kernel_lab_"))
        continue;
      for (const Rule &R : Configuration.Rules) {
        if (R.Match != MatchKind::Call || R.Symbol != Callee->getName())
          continue;
        if (R.Phase == SitePhase::After) {
          auto *PlainCall = dyn_cast<CallInst>(Call);
          if (!PlainCall || PlainCall->isMustTailCall()) {
            Gaps.push_back((Twine(F.getName()) + ": cannot instrument after " +
                            Callee->getName())
                               .str());
            continue;
          }
        }
        PlannedSite Site;
        Site.Anchor = &I;
        Site.Descriptor = &R;
        Site.FunctionName = F.getName().str();
        Site.CalleeName = Callee->getName().str();
        Site.Ordinal = Ordinals.lookup(&I);
        findLocation(I, F, M, Site.SourceName, Site.Line, Site.Column);
        Site.ID = siteID(Configuration, Site);
        Sites.push_back(std::move(Site));
      }
    }
  }

  if (Configuration.Strict && !Gaps.empty()) {
    M.getContext().emitError(Twine("clang-kernel-lab: ") + Gaps.front());
    return PreservedAnalyses::all();
  }
  if (Configuration.RequireSite && Sites.empty()) {
    M.getContext().emitError(
        "clang-kernel-lab: specification required at least one matched site");
    return PreservedAnalyses::all();
  }
  if (Sites.empty())
    return PreservedAnalyses::all();

  LLVMContext &Context = M.getContext();
  Type *Void = Type::getVoidTy(Context);
  Type *I32 = Type::getInt32Ty(Context);
  Type *I64 = Type::getInt64Ty(Context);
  FunctionCallee CallbackHook = M.getOrInsertFunction(
      CallbackHookName, FunctionType::get(Void, {I64, I32, I32}, false));
  FunctionCallee PerturbHook = M.getOrInsertFunction(
      PerturbHookName, FunctionType::get(Void, {I64, I32}, false));
  if (Function *Hook = dyn_cast<Function>(CallbackHook.getCallee()))
    Hook->addFnAttr(Attribute::NoUnwind);
  if (Function *Hook = dyn_cast<Function>(PerturbHook.getCallee()))
    Hook->addFnAttr(Attribute::NoUnwind);

  NamedMDNode *SiteList =
      M.getOrInsertNamedMetadata("clang.kernel.lab.callback_sites");
  for (PlannedSite &Site : Sites) {
    const Rule &R = *Site.Descriptor;
    Instruction *InsertBefore = Site.Anchor;
    if (R.Phase == SitePhase::After) {
      auto *Call = cast<CallInst>(Site.Anchor);
      if (Call->isTailCall())
        Call->setTailCallKind(CallInst::TCK_None);
      InsertBefore = Call->getNextNode();
    }
    IRBuilder<> Builder(InsertBefore);
    Builder.SetCurrentDebugLocation(Site.Anchor->getDebugLoc());
    Value *ID = ConstantInt::get(I64, Site.ID);
    if (R.Actions & ActionCallback) {
      CallInst *Hook = Builder.CreateCall(
          CallbackHook, {ID, ConstantInt::get(I32, R.EventID),
                         ConstantInt::get(I32, static_cast<uint8_t>(R.Phase))});
      Hook->setDoesNotThrow();
    }
    if (R.Actions & ActionPerturb) {
      CallInst *Hook = Builder.CreateCall(
          PerturbHook, {ID, ConstantInt::get(I32, R.PerturbClass)});
      Hook->setDoesNotThrow();
    }
    SiteList->addOperand(siteMetadata(Context, Site));
  }

  NamedMDNode *Summary =
      M.getOrInsertNamedMetadata("clang.kernel.lab.configuration");
  Metadata *SummaryFields[] = {
      ConstantAsMetadata::get(ConstantInt::get(I64, Configuration.Hash)),
      MDString::get(Context, M.getTargetTriple().str()),
      ConstantAsMetadata::get(ConstantInt::get(I32, Sites.size())),
  };
  Summary->addOperand(MDNode::get(Context, SummaryFields));
  for (const std::string &Gap : Gaps)
    M.getOrInsertNamedMetadata("clang.kernel.lab.gaps")
        ->addOperand(MDNode::get(Context, MDString::get(Context, Gap)));

  emitSiteSection(M, Sites, Configuration.Hash);
  M.addModuleFlag(Module::Error, "clang.kernel.lab.instrumented", 1);
  M.addModuleFlag(Module::Error, "clang.kernel.lab.spec_hash",
                  ConstantInt::get(I64, Configuration.Hash));
  return PreservedAnalyses::none();
}

static void registerCallbacks(PassBuilder &PB) {
  std::shared_ptr<const LoadedConfig> Loaded = loadConfig();
  PB.registerPipelineStartEPCallback(
      [Loaded](ModulePassManager &Manager, OptimizationLevel) {
        if (Loaded->Requested)
          Manager.addPass(KernelLabPass(Loaded));
      });
  PB.registerPipelineParsingCallback(
      [Loaded](StringRef Name, ModulePassManager &Manager,
               ArrayRef<PassBuilder::PipelineElement>) {
        if (Name != "clang-kernel-lab")
          return false;
        Manager.addPass(KernelLabPass(Loaded));
        return true;
      });
}

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
#if LLVM_VERSION_MAJOR >= 24
  return {LLVM_PLUGIN_API_VERSION, "ClangKernelLab", LLVM_VERSION_STRING,
          registerCallbacks,       nullptr,          nullptr};
#else
  return {LLVM_PLUGIN_API_VERSION, "ClangKernelLab", LLVM_VERSION_STRING,
          registerCallbacks, nullptr};
#endif
}
