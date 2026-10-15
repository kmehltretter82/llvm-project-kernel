//===- ClangKernelLabMap.cpp - Text-inert Linux IRQ site maps ------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This late IR pass attaches LLVM !pcsections metadata to selected existing
// instructions.  LLVM guarantees that PC sections metadata does not affect
// optimization or generated code outside the requested data section.  The
// emitted C carrier is deliberately separate from callback/perturb mode and
// is normalized with assembly records by llvm-riscv-irq-sites.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Plugins/PassPlugin.h"
#include "llvm/Support/CodeGen.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Process.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using namespace llvm;

namespace {

constexpr StringLiteral SpecEnvironment = "CLANG_KERNEL_LAB_MAP_SPEC";
constexpr StringLiteral CarrierSection = ".riscv.linux_irq_c_sites";
constexpr StringLiteral ExpectedSection = ".riscv.linux_irq_expected";
constexpr uint64_t MaxSpecBytes = 1024 * 1024;
constexpr uint8_t SiteVersion = 1;
constexpr uint8_t SiteRecordSize = 32;
constexpr uint32_t FlagAfterPreviousRetire = 1U << 0;
constexpr uint32_t FlagBeforeInsnAtSite = 1U << 1;
constexpr uint32_t FlagC = 1U << 3;
constexpr uint32_t FlagNoInstr = 1U << 4;
constexpr uint32_t FlagManualID = 1U << 5;

enum class MatchKind : uint8_t { Call, Function, Instruction };
enum class SitePhase : uint8_t { Before, After, Entry, Exit };

struct Rule {
  MatchKind Match = MatchKind::Call;
  SitePhase Phase = SitePhase::Before;
  uint16_t Kind = 0;
  bool NoInstr = false;
  std::optional<std::pair<uint64_t, uint64_t>> ManualID;
  std::optional<unsigned> Occurrence;
  std::string Opcode;
  std::string Symbol;
};

struct Config {
  bool RequireEachRule = true;
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
  uint64_t IDLow = 0;
  uint64_t IDHigh = 0;
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

static bool isKnownKind(uint16_t Kind) {
  switch (Kind) {
#define KLAB_IRQ_SITE_KIND(Name, Value, Text) case Value:
#include "clang/Basic/LinuxKernelIRQSiteKinds.def"
#undef KLAB_IRQ_SITE_KIND
    return true;
  }
  return false;
}

static Expected<MatchKind> parseMatch(StringRef Text) {
  if (Text == "call")
    return MatchKind::Call;
  if (Text == "function")
    return MatchKind::Function;
  if (Text == "instruction")
    return MatchKind::Instruction;
  return configError("match must be 'call', 'function', or 'instruction'");
}

static Expected<SitePhase> parsePhase(StringRef Text, MatchKind Match) {
  if (Text == "before" &&
      (Match == MatchKind::Call || Match == MatchKind::Instruction))
    return SitePhase::Before;
  if (Text == "after" && Match == MatchKind::Call)
    return SitePhase::After;
  if (Text == "entry" && Match == MatchKind::Function)
    return SitePhase::Entry;
  if (Text == "exit" && Match == MatchKind::Function)
    return SitePhase::Exit;
  return configError("position does not apply to the selected match kind");
}

static Expected<std::pair<uint64_t, uint64_t>> parseSiteID(StringRef Text) {
  if (Text.size() != 32)
    return configError("site_id must contain exactly 32 hexadecimal digits");
  APInt Value(128, 0);
  if (Text.getAsInteger(16, Value) || Value.isZero())
    return configError("site_id must be a nonzero 128-bit hexadecimal value");
  return std::make_pair(Value.extractBitsAsZExtValue(64, 0),
                        Value.extractBitsAsZExtValue(64, 64));
}

static Expected<Config> parseConfig(StringRef Path) {
  auto Buffer = MemoryBuffer::getFile(Path, /*IsText=*/true);
  if (!Buffer)
    return configError(Twine("cannot read specification '") + Path +
                       "': " + Buffer.getError().message());
  if ((*Buffer)->getBufferSize() > MaxSpecBytes)
    return configError("specification exceeds the 1 MiB input limit");

  Expected<json::Value> Parsed = json::parse((*Buffer)->getBuffer());
  if (!Parsed)
    return configError(Twine("invalid JSON: ") + toString(Parsed.takeError()));
  const json::Object *Root = Parsed->getAsObject();
  if (!Root)
    return configError("top-level specification must be an object");
  if (Root->getInteger("schema") != 1)
    return configError("unsupported or missing schema; expected 1");

  Config Result;
  if (auto Strict = Root->getBoolean("strict"))
    Result.Strict = *Strict;
  if (auto Require = Root->getBoolean("require_each_rule"))
    Result.RequireEachRule = *Require;
  if (auto TargetOS = Root->getString("target_os")) {
    if (*TargetOS != "linux" && *TargetOS != "any")
      return configError("target_os must be 'linux' or 'any'");
    Result.TargetOS = TargetOS->str();
  }

  const json::Array *Rules = Root->getArray("sites");
  if (!Rules || Rules->empty())
    return configError("specification must contain at least one site rule");
  if (Rules->size() > 4096)
    return configError("specification exceeds the 4096-rule limit");

  std::set<std::string> RuleKeys;
  for (const json::Value &Value : *Rules) {
    const json::Object *Object = Value.getAsObject();
    if (!Object)
      return configError("each site rule must be an object");
    auto MatchText = Object->getString("match");
    auto PositionText = Object->getString("position");
    auto Symbol = Object->getString("symbol");
    auto Kind = Object->getInteger("kind");
    if (!MatchText || !PositionText || !Symbol || !Kind)
      return configError("site rule lacks a required field");
    if (Symbol->empty() || Symbol->size() > 256)
      return configError("site symbol has an invalid length");
    if (*Kind <= 0 || *Kind > std::numeric_limits<uint16_t>::max() ||
        !isKnownKind(static_cast<uint16_t>(*Kind)))
      return configError("site kind is not assigned in version one");

    Expected<MatchKind> Match = parseMatch(*MatchText);
    if (!Match)
      return Match.takeError();
    Expected<SitePhase> Phase = parsePhase(*PositionText, *Match);
    if (!Phase)
      return Phase.takeError();

    Rule R;
    R.Match = *Match;
    R.Phase = *Phase;
    R.Kind = static_cast<uint16_t>(*Kind);
    R.Symbol = Symbol->str();
    if (*Match == MatchKind::Instruction) {
      auto Opcode = Object->getString("opcode");
      if (!Opcode || Opcode->empty() || Opcode->size() > 64)
        return configError(
            "instruction rule requires an opcode of 1 through 64 bytes");
      R.Opcode = Opcode->str();
      if (const json::Value *Value = Object->get("occurrence")) {
        std::optional<int64_t> Occurrence = Value->getAsInteger();
        if (!Occurrence || *Occurrence <= 0 ||
            static_cast<uint64_t>(*Occurrence) >
                std::numeric_limits<unsigned>::max())
          return configError(
              "instruction occurrence must be a positive integer");
        R.Occurrence = static_cast<unsigned>(*Occurrence);
      }
    } else if (Object->get("opcode") || Object->get("occurrence")) {
      return configError(
          "opcode and occurrence apply only to instruction rules");
    }
    if (auto NoInstr = Object->getBoolean("noinstr"))
      R.NoInstr = *NoInstr;
    if (auto Manual = Object->getString("site_id")) {
      Expected<std::pair<uint64_t, uint64_t>> ID = parseSiteID(*Manual);
      if (!ID)
        return ID.takeError();
      R.ManualID = *ID;
    }

    std::string Key = (Twine(*MatchText) + "\n" + R.Symbol + "\n" +
                       *PositionText + "\n" + Twine(R.Kind) + "\n" +
                       R.Opcode + "\n" + Twine(R.Occurrence.value_or(0)))
                          .str();
    if (!RuleKeys.insert(std::move(Key)).second)
      return configError("duplicate match/symbol/position/kind rule");
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

static std::pair<uint64_t, uint64_t> automaticSiteID(const PlannedSite &Site) {
  SmallString<256> Key;
  raw_svector_ostream OS(Key);
  OS << "clang-kernel-lab-map-v1" << '\0' << Site.SourceName << '\0'
     << Site.FunctionName << '\0' << Site.CalleeName << '\0'
     << Site.Descriptor->Kind << '\0'
     << static_cast<unsigned>(Site.Descriptor->Phase) << '\0' << Site.Line
     << '\0' << Site.Column << '\0' << Site.Ordinal;
  std::array<uint8_t, 32> Digest =
      SHA256::hash(arrayRefFromStringRef(OS.str()));
  uint64_t High = support::endian::read64be(Digest.data());
  uint64_t Low = support::endian::read64be(Digest.data() + 8);
  if (!High && !Low)
    Low = 1;
  return {Low, High};
}

static MDNode *siteMetadata(LLVMContext &Context, const PlannedSite &Site) {
  Metadata *Fields[] = {
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt64Ty(Context), Site.IDLow)),
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt64Ty(Context), Site.IDHigh)),
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt16Ty(Context), Site.Descriptor->Kind)),
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

static uint32_t siteFlags(const PlannedSite &Site) {
  uint32_t Flags = FlagAfterPreviousRetire | FlagBeforeInsnAtSite | FlagC;
  if (Site.Descriptor->NoInstr)
    Flags |= FlagNoInstr;
  if (Site.Descriptor->ManualID)
    Flags |= FlagManualID;
  return Flags;
}

static void attachSite(Instruction &Anchor, const PlannedSite &Site) {
  LLVMContext &Context = Anchor.getContext();
  SmallVector<Constant *> Aux{
      ConstantInt::get(Type::getInt8Ty(Context), SiteVersion),
      ConstantInt::get(Type::getInt8Ty(Context), SiteRecordSize),
      ConstantInt::get(Type::getInt16Ty(Context), Site.Descriptor->Kind),
      ConstantInt::get(Type::getInt32Ty(Context), siteFlags(Site)),
      ConstantInt::get(Type::getInt64Ty(Context), Site.IDLow),
      ConstantInt::get(Type::getInt64Ty(Context), Site.IDHigh),
  };
  MDNode *Added =
      MDBuilder(Context).createPCSections({{CarrierSection, std::move(Aux)}});
  MDNode *Existing = Anchor.getMetadata(LLVMContext::MD_pcsections);
  if (!Existing) {
    Anchor.setMetadata(LLVMContext::MD_pcsections, Added);
    return;
  }
  SmallVector<Metadata *, 8> Operands;
  for (const MDOperand &Operand : Existing->operands())
    Operands.push_back(Operand.get());
  for (const MDOperand &Operand : Added->operands())
    Operands.push_back(Operand.get());
  Anchor.setMetadata(LLVMContext::MD_pcsections,
                     MDNode::get(Context, Operands));
}

static void emitExpectedSites(Module &M, ArrayRef<PlannedSite> Sites) {
  LLVMContext &Context = M.getContext();
  Type *I16 = Type::getInt16Ty(Context);
  Type *I32 = Type::getInt32Ty(Context);
  Type *I64 = Type::getInt64Ty(Context);
  StructType *RecordType =
      StructType::get(Context, {I16, I16, I32, I64, I64}, /*isPacked=*/true);
  SmallVector<Constant *, 16> Records;
  for (const PlannedSite &Site : Sites) {
    Constant *Fields[] = {
        ConstantInt::get(I16, Site.Descriptor->Kind),
        ConstantInt::get(I16, 0),
        ConstantInt::get(I32, siteFlags(Site)),
        ConstantInt::get(I64, Site.IDLow),
        ConstantInt::get(I64, Site.IDHigh),
    };
    Records.push_back(ConstantStruct::get(RecordType, Fields));
  }
  ArrayType *TableType = ArrayType::get(RecordType, Records.size());
  auto *Table = new GlobalVariable(
      M, TableType, /*isConstant=*/true, GlobalValue::PrivateLinkage,
      ConstantArray::get(TableType, Records), "__clang_kernel_lab_expected");
  Table->setSection(ExpectedSection);
  Table->setAlignment(Align(8));
  appendToCompilerUsed(M, {Table});
}

class KernelLabMapPass : public PassInfoMixin<KernelLabMapPass> {
public:
  explicit KernelLabMapPass(std::shared_ptr<const LoadedConfig> Loaded)
      : Loaded(std::move(Loaded)) {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &);
  static bool isRequired() { return true; }

private:
  std::shared_ptr<const LoadedConfig> Loaded;
};

PreservedAnalyses KernelLabMapPass::run(Module &M, ModuleAnalysisManager &) {
  if (M.getModuleFlag("clang.kernel.lab.map"))
    return PreservedAnalyses::all();
  if (!Loaded->Requested)
    return PreservedAnalyses::all();
  if (!Loaded->Error.empty()) {
    M.getContext().emitError(Twine("clang-kernel-lab-map: ") + Loaded->Error);
    return PreservedAnalyses::all();
  }

  const Config &Configuration = *Loaded->Value;
  Triple Target(M.getTargetTriple());
  if (Target.getArch() != Triple::riscv64) {
    M.getContext().emitError(
        "clang-kernel-lab-map: version one requires an RV64 target");
    return PreservedAnalyses::all();
  }
  if (!Target.isOSBinFormatELF()) {
    M.getContext().emitError("clang-kernel-lab-map: version one requires ELF");
    return PreservedAnalyses::all();
  }
  if (Configuration.TargetOS == "linux" && !Target.isOSLinux()) {
    M.getContext().emitError(
        "clang-kernel-lab-map: specification requires a Linux target triple");
    return PreservedAnalyses::all();
  }
  std::optional<CodeModel::Model> CM = M.getCodeModel();
  if (!CM || (*CM != CodeModel::Medium && *CM != CodeModel::Large)) {
    M.getContext().emitError(
        "clang-kernel-lab-map: use -mcmodel=medany so PC records are 64-bit");
    return PreservedAnalyses::all();
  }

  std::vector<PlannedSite> Sites;
  std::vector<std::string> Gaps;
  DenseMap<const Rule *, unsigned> RuleMatches;
  for (Function &F : M) {
    if (F.isDeclaration())
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
          Gaps.push_back((Twine(F.getName()) + ": no entry instruction").str());
          continue;
        }
        PlannedSite Site;
        Site.Anchor = &*Point;
        Site.Descriptor = &R;
        Site.FunctionName = F.getName().str();
        findLocation(*Site.Anchor, F, M, Site.SourceName, Site.Line,
                     Site.Column);
        Sites.push_back(std::move(Site));
        ++RuleMatches[&R];
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
          Sites.push_back(std::move(Site));
          ++RuleMatches[&R];
        }
      }
    }

    for (const Rule &R : Configuration.Rules) {
      if (R.Match != MatchKind::Instruction || R.Symbol != F.getName())
        continue;
      unsigned MatchingOccurrence = 0;
      for (Instruction &I : instructions(F)) {
        if (R.Opcode != I.getOpcodeName())
          continue;
        ++MatchingOccurrence;
        if (R.Occurrence && MatchingOccurrence != *R.Occurrence)
          continue;
        PlannedSite Site;
        Site.Anchor = &I;
        Site.Descriptor = &R;
        Site.FunctionName = F.getName().str();
        Site.CalleeName = R.Opcode;
        Site.Ordinal = Ordinals.lookup(&I);
        findLocation(I, F, M, Site.SourceName, Site.Line, Site.Column);
        Sites.push_back(std::move(Site));
        ++RuleMatches[&R];
        if (R.Occurrence)
          break;
      }
    }

    for (Instruction &I : instructions(F)) {
      auto *Call = dyn_cast<CallBase>(&I);
      if (!Call)
        continue;
      Function *Callee =
          dyn_cast<Function>(Call->getCalledOperand()->stripPointerCasts());
      if (!Callee || Callee->isIntrinsic())
        continue;
      for (const Rule &R : Configuration.Rules) {
        if (R.Match != MatchKind::Call || R.Symbol != Callee->getName())
          continue;
        Instruction *Anchor = &I;
        if (R.Phase == SitePhase::After) {
          auto *PlainCall = dyn_cast<CallInst>(Call);
          if (!PlainCall || PlainCall->isMustTailCall() ||
              !PlainCall->getNextNode()) {
            Gaps.push_back(
                (Twine(F.getName()) + ": cannot map after " + Callee->getName())
                    .str());
            continue;
          }
          Anchor = PlainCall->getNextNode();
        }
        PlannedSite Site;
        Site.Anchor = Anchor;
        Site.Descriptor = &R;
        Site.FunctionName = F.getName().str();
        Site.CalleeName = Callee->getName().str();
        Site.Ordinal = Ordinals.lookup(&I);
        findLocation(I, F, M, Site.SourceName, Site.Line, Site.Column);
        Sites.push_back(std::move(Site));
        ++RuleMatches[&R];
      }
    }
  }

  if (Configuration.RequireEachRule) {
    for (const Rule &R : Configuration.Rules)
      if (!RuleMatches.lookup(&R))
        Gaps.push_back((Twine("unmatched rule for ") + R.Symbol).str());
  }
  if (Configuration.Strict && !Gaps.empty()) {
    M.getContext().emitError(Twine("clang-kernel-lab-map: ") + Gaps.front());
    return PreservedAnalyses::all();
  }
  if (Sites.empty())
    return PreservedAnalyses::all();

  std::set<std::pair<uint64_t, uint64_t>> IDs;
  for (PlannedSite &Site : Sites) {
    if (Site.Descriptor->ManualID) {
      Site.IDLow = Site.Descriptor->ManualID->first;
      Site.IDHigh = Site.Descriptor->ManualID->second;
    } else {
      std::tie(Site.IDLow, Site.IDHigh) = automaticSiteID(Site);
    }
    if (!IDs.insert({Site.IDHigh, Site.IDLow}).second) {
      M.getContext().emitError(
          "clang-kernel-lab-map: duplicate generated or manual site ID");
      return PreservedAnalyses::all();
    }
  }

  NamedMDNode *SiteList = M.getOrInsertNamedMetadata("clang.kernel.lab.sites");
  for (PlannedSite &Site : Sites) {
    attachSite(*Site.Anchor, Site);
    SiteList->addOperand(siteMetadata(M.getContext(), Site));
  }
  emitExpectedSites(M, Sites);
  for (const std::string &Gap : Gaps)
    M.getOrInsertNamedMetadata("clang.kernel.lab.map.gaps")
        ->addOperand(
            MDNode::get(M.getContext(), MDString::get(M.getContext(), Gap)));
  M.addModuleFlag(Module::Error, "clang.kernel.lab.map", 1);
  return PreservedAnalyses::none();
}

static void registerCallbacks(PassBuilder &PB) {
  std::shared_ptr<const LoadedConfig> Loaded = loadConfig();
  PB.registerOptimizerLastEPCallback([Loaded](ModulePassManager &Manager,
                                              OptimizationLevel,
                                              ThinOrFullLTOPhase) {
    if (Loaded->Requested)
      Manager.addPass(KernelLabMapPass(Loaded));
  });
  PB.registerPipelineParsingCallback(
      [Loaded](StringRef Name, ModulePassManager &Manager,
               ArrayRef<PassBuilder::PipelineElement>) {
        if (Name != "clang-kernel-lab-map")
          return false;
        Manager.addPass(KernelLabMapPass(Loaded));
        return true;
      });
}

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
#if LLVM_VERSION_MAJOR >= 24
  return {LLVM_PLUGIN_API_VERSION,
          "ClangKernelLabMap",
          LLVM_VERSION_STRING,
          registerCallbacks,
          nullptr,
          nullptr};
#else
  return {LLVM_PLUGIN_API_VERSION, "ClangKernelLabMap", LLVM_VERSION_STRING,
          registerCallbacks, nullptr};
#endif
}
