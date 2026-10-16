//===- ClangKernelLabMap.cpp - Text-inert Linux IRQ site maps ------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// These IR passes attach LLVM !pcsections metadata to selected existing
// instructions.  The source path plans its dedicated marker after early
// canonicalization and emits it at pipeline exit; the policy pass selects
// optimized IR at that same exit.  LLVM guarantees that PC sections metadata
// does not affect generated code outside the requested data section.  The
// emitted C carrier is deliberately separate from callback/perturb mode and is
// normalized with assembly records by llvm-riscv-irq-sites.
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
#include "llvm/Support/IOSandbox.h"
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
constexpr StringLiteral SourcePendingMetadata =
    "clang.kernel.lab.source.pending";
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
  uint16_t Kind = 0;
  SitePhase Phase = SitePhase::Before;
  bool NoInstr = false;
  std::optional<std::pair<uint64_t, uint64_t>> ManualID;
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
  auto Buffer = [&] {
    auto BypassSandbox = sys::sandbox::scopedDisable();
    return MemoryBuffer::getFile(Path, /*IsText=*/true);
  }();
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

static std::string normalizedSourcePath(StringRef Directory,
                                        StringRef Filename) {
  SmallString<256> Path;
  if (sys::path::is_absolute(Filename)) {
    Path = Filename;
  } else if (!Directory.empty() && !sys::path::is_absolute(Directory)) {
    Path = Directory;
    sys::path::append(Path, Filename);
  } else {
    Path = Filename;
  }
  sys::path::remove_dots(Path, /*remove_dot_dot=*/true);
  if (sys::path::is_absolute(Path))
    return sys::path::filename(Path).str();
  return sys::path::convert_to_slash(Path);
}

static void findLocation(const Instruction &I, const Function &F,
                         const Module &M, std::string &Source, unsigned &Line,
                         unsigned &Column) {
  Source = normalizedSourcePath({}, M.getSourceFileName());
  if (const DebugLoc &Location = I.getDebugLoc()) {
    Source =
        normalizedSourcePath(Location->getDirectory(), Location->getFilename());
    Line = Location.getLine();
    Column = Location.getCol();
    return;
  }
  if (const DISubprogram *Subprogram = F.getSubprogram()) {
    Source = normalizedSourcePath(Subprogram->getDirectory(),
                                  Subprogram->getFilename());
    Line = Subprogram->getLine();
  }
}

static std::pair<uint64_t, uint64_t> automaticSiteID(const PlannedSite &Site) {
  SmallString<256> Key;
  raw_svector_ostream OS(Key);
  OS << "clang-kernel-lab-map-v1" << '\0' << Site.SourceName << '\0'
     << Site.FunctionName << '\0' << Site.CalleeName << '\0' << Site.Kind
     << '\0' << static_cast<unsigned>(Site.Phase) << '\0' << Site.Line << '\0'
     << Site.Column << '\0' << Site.Ordinal;
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
          ConstantInt::get(Type::getInt16Ty(Context), Site.Kind)),
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
  if (Site.NoInstr)
    Flags |= FlagNoInstr;
  if (Site.ManualID)
    Flags |= FlagManualID;
  return Flags;
}

static void attachSite(Instruction &Anchor, const PlannedSite &Site) {
  LLVMContext &Context = Anchor.getContext();
  SmallVector<Constant *> Aux{
      ConstantInt::get(Type::getInt8Ty(Context), SiteVersion),
      ConstantInt::get(Type::getInt8Ty(Context), SiteRecordSize),
      ConstantInt::get(Type::getInt16Ty(Context), Site.Kind),
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
        ConstantInt::get(I16, Site.Kind),
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

static bool assignSiteIDs(Module &M, MutableArrayRef<PlannedSite> Sites,
                          StringRef Component) {
  std::set<std::pair<uint64_t, uint64_t>> IDs;
  for (PlannedSite &Site : Sites) {
    if (Site.ManualID) {
      Site.IDLow = Site.ManualID->first;
      Site.IDHigh = Site.ManualID->second;
    } else {
      std::tie(Site.IDLow, Site.IDHigh) = automaticSiteID(Site);
    }
    if (!IDs.insert({Site.IDHigh, Site.IDLow}).second) {
      M.getContext().emitError(Twine(Component) +
                               ": duplicate generated or manual site ID");
      return false;
    }
  }
  return true;
}

static bool isSourceMarker(const Instruction &I) {
  const auto *Call = dyn_cast<CallInst>(&I);
  const Function *Callee = Call ? Call->getCalledFunction() : nullptr;
  // Match the reserved intrinsic spelling instead of the generated enum so
  // the map-only plugin remains buildable against the LLVM 22 control lane,
  // whose headers predate this lab intrinsic.
  return Callee && Callee->getName() == "llvm.riscv.linux.irq.site";
}

static bool isNoInstrFunction(const Function &F) {
  if (!F.hasSection())
    return false;
  StringRef Section = F.getSection();
  return Section == ".noinstr.text" || Section == ".irqentry.text" ||
         Section == ".entry.text";
}

struct PendingSourceSite {
  PlannedSite Site;
  std::string AnchorOpcode;
  std::string AnchorSource;
  unsigned AnchorLine = 0;
  unsigned AnchorColumn = 0;
  unsigned AnchorOccurrence = 0;
  unsigned AnchorCount = 0;
};

static bool hasExactLocation(const Instruction &I) {
  return static_cast<bool>(I.getDebugLoc());
}

static bool matchesSourceAnchor(const Instruction &I, const Function &F,
                                const Module &M,
                                const PendingSourceSite &Pending) {
  if (I.getOpcodeName() != Pending.AnchorOpcode || !hasExactLocation(I))
    return false;
  std::string Source;
  unsigned Line = 0;
  unsigned Column = 0;
  findLocation(I, F, M, Source, Line, Column);
  return Source == Pending.AnchorSource && Line == Pending.AnchorLine &&
         Column == Pending.AnchorColumn;
}

static MDNode *pendingSourceMetadata(LLVMContext &Context,
                                     const PendingSourceSite &Pending) {
  Metadata *Fields[] = {
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt16Ty(Context), Pending.Site.Kind)),
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt32Ty(Context), Pending.Site.Ordinal)),
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt1Ty(Context), Pending.Site.NoInstr)),
      MDString::get(Context, Pending.Site.FunctionName),
      MDString::get(Context, Pending.Site.SourceName),
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt32Ty(Context), Pending.Site.Line)),
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt32Ty(Context), Pending.Site.Column)),
      MDString::get(Context, Pending.AnchorOpcode),
      MDString::get(Context, Pending.AnchorSource),
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt32Ty(Context), Pending.AnchorLine)),
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt32Ty(Context), Pending.AnchorColumn)),
      ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(Context),
                                               Pending.AnchorOccurrence)),
      ConstantAsMetadata::get(
          ConstantInt::get(Type::getInt32Ty(Context), Pending.AnchorCount)),
  };
  return MDNode::get(Context, Fields);
}

static bool readPendingSourceMetadata(const MDNode &Node,
                                      PendingSourceSite &Pending) {
  if (Node.getNumOperands() != 13)
    return false;
  auto UInt = [&](unsigned Index) -> std::optional<uint64_t> {
    auto *Value = mdconst::dyn_extract<ConstantInt>(Node.getOperand(Index));
    if (!Value)
      return std::nullopt;
    return Value->getZExtValue();
  };
  auto Text = [&](unsigned Index) -> MDString * {
    return dyn_cast_or_null<MDString>(Node.getOperand(Index));
  };
  std::optional<uint64_t> Kind = UInt(0);
  std::optional<uint64_t> Ordinal = UInt(1);
  std::optional<uint64_t> NoInstr = UInt(2);
  MDString *FunctionName = Text(3);
  MDString *SourceName = Text(4);
  std::optional<uint64_t> Line = UInt(5);
  std::optional<uint64_t> Column = UInt(6);
  MDString *AnchorOpcode = Text(7);
  MDString *AnchorSource = Text(8);
  std::optional<uint64_t> AnchorLine = UInt(9);
  std::optional<uint64_t> AnchorColumn = UInt(10);
  std::optional<uint64_t> AnchorOccurrence = UInt(11);
  std::optional<uint64_t> AnchorCount = UInt(12);
  if (!Kind || !Ordinal || !NoInstr || !FunctionName || !SourceName || !Line ||
      !Column || !AnchorOpcode || !AnchorSource || !AnchorLine ||
      !AnchorColumn || !AnchorOccurrence || !AnchorCount ||
      *Kind > std::numeric_limits<uint16_t>::max() || !isKnownKind(*Kind) ||
      *Ordinal > 65535 || *NoInstr > 1 || !*Line || !*AnchorLine ||
      *Line > std::numeric_limits<unsigned>::max() ||
      *Column > std::numeric_limits<unsigned>::max() ||
      *AnchorLine > std::numeric_limits<unsigned>::max() ||
      *AnchorColumn > std::numeric_limits<unsigned>::max() ||
      !*AnchorOccurrence ||
      *AnchorOccurrence > std::numeric_limits<unsigned>::max() ||
      !*AnchorCount || *AnchorCount > std::numeric_limits<unsigned>::max())
    return false;
  Pending.Site.Kind = static_cast<uint16_t>(*Kind);
  Pending.Site.Phase = SitePhase::Before;
  Pending.Site.NoInstr = static_cast<bool>(*NoInstr);
  Pending.Site.FunctionName = FunctionName->getString().str();
  Pending.Site.SourceName = SourceName->getString().str();
  Pending.Site.Line = static_cast<unsigned>(*Line);
  Pending.Site.Column = static_cast<unsigned>(*Column);
  Pending.Site.Ordinal = static_cast<unsigned>(*Ordinal);
  Pending.AnchorOpcode = AnchorOpcode->getString().str();
  Pending.AnchorSource = AnchorSource->getString().str();
  Pending.AnchorLine = static_cast<unsigned>(*AnchorLine);
  Pending.AnchorColumn = static_cast<unsigned>(*AnchorColumn);
  Pending.AnchorOccurrence = static_cast<unsigned>(*AnchorOccurrence);
  Pending.AnchorCount = static_cast<unsigned>(*AnchorCount);
  return true;
}

#if LLVM_VERSION_MAJOR >= 24
class KernelLabSourcePlanPass
    : public RequiredPassInfoMixin<KernelLabSourcePlanPass> {
#else
class KernelLabSourcePlanPass : public PassInfoMixin<KernelLabSourcePlanPass> {
#endif
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &);
  static bool isRequired() { return true; }
};

PreservedAnalyses KernelLabSourcePlanPass::run(Module &M,
                                               ModuleAnalysisManager &) {
  if (M.getModuleFlag("clang.kernel.lab.source-plan"))
    return PreservedAnalyses::all();

  SmallVector<CallInst *, 16> Markers;
  for (Function &F : M)
    if (!F.isDeclaration())
      for (Instruction &I : instructions(F))
        if (isSourceMarker(I))
          Markers.push_back(cast<CallInst>(&I));
  if (Markers.empty())
    return PreservedAnalyses::all();

  Triple Target(M.getTargetTriple());
  if (Target.getArch() != Triple::riscv64 || !Target.isOSBinFormatELF() ||
      !Target.isOSLinux()) {
    M.getContext().emitError(
        "clang-kernel-lab-source-map: version one requires RV64 Linux ELF");
    return PreservedAnalyses::all();
  }
  std::optional<CodeModel::Model> CM = M.getCodeModel();
  if (!CM || (*CM != CodeModel::Medium && *CM != CodeModel::Large)) {
    M.getContext().emitError("clang-kernel-lab-source-map: use -mcmodel=medany "
                             "so PC records are 64-bit");
    return PreservedAnalyses::all();
  }

  NamedMDNode *PendingList = M.getOrInsertNamedMetadata(SourcePendingMetadata);
  for (CallInst *Marker : Markers) {
    auto *Kind = dyn_cast<ConstantInt>(Marker->getArgOperand(0));
    auto *Ordinal = dyn_cast<ConstantInt>(Marker->getArgOperand(1));
    if (!Kind || !Ordinal || !isKnownKind(Kind->getZExtValue()) ||
        Ordinal->getZExtValue() > 65535) {
      M.getContext().emitError(
          "clang-kernel-lab-source-map: malformed source marker operands");
      return PreservedAnalyses::all();
    }

    Instruction *Anchor = Marker->getNextNode();
    while (Anchor && isSourceMarker(*Anchor))
      Anchor = Anchor->getNextNode();
    if (!Anchor) {
      M.getContext().emitError("clang-kernel-lab-source-map: source marker has "
                               "no following instruction");
      return PreservedAnalyses::all();
    }
    if (!hasExactLocation(*Marker) || !hasExactLocation(*Anchor)) {
      M.getContext().emitError(
          "clang-kernel-lab-source-map: source markers require line-table "
          "debug information");
      return PreservedAnalyses::all();
    }

    Function &F = *Marker->getFunction();
    PendingSourceSite Pending;
    Pending.Site.Kind = static_cast<uint16_t>(Kind->getZExtValue());
    Pending.Site.Phase = SitePhase::Before;
    Pending.Site.NoInstr = isNoInstrFunction(F);
    Pending.Site.FunctionName = F.getName().str();
    Pending.Site.Ordinal = static_cast<unsigned>(Ordinal->getZExtValue());
    findLocation(*Marker, F, M, Pending.Site.SourceName, Pending.Site.Line,
                 Pending.Site.Column);
    Pending.AnchorOpcode = Anchor->getOpcodeName();
    findLocation(*Anchor, F, M, Pending.AnchorSource, Pending.AnchorLine,
                 Pending.AnchorColumn);
    for (Instruction &I : instructions(F)) {
      if (!matchesSourceAnchor(I, F, M, Pending))
        continue;
      ++Pending.AnchorCount;
      if (&I == Anchor)
        Pending.AnchorOccurrence = Pending.AnchorCount;
    }
    if (!Pending.AnchorOccurrence) {
      M.getContext().emitError(
          "clang-kernel-lab-source-map: cannot identify source marker anchor");
      return PreservedAnalyses::all();
    }
    PendingList->addOperand(pendingSourceMetadata(M.getContext(), Pending));
  }

  M.addModuleFlag(Module::Error, "clang.kernel.lab.source-plan", 1);
  for (CallInst *Marker : Markers)
    Marker->eraseFromParent();
  return PreservedAnalyses::none();
}

#if LLVM_VERSION_MAJOR >= 24
class KernelLabSourceMapPass
    : public RequiredPassInfoMixin<KernelLabSourceMapPass> {
#else
class KernelLabSourceMapPass : public PassInfoMixin<KernelLabSourceMapPass> {
#endif
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &);
  static bool isRequired() { return true; }
};

PreservedAnalyses KernelLabSourceMapPass::run(Module &M,
                                              ModuleAnalysisManager &) {
  NamedMDNode *PendingList = M.getNamedMetadata(SourcePendingMetadata);
  if (!PendingList)
    return PreservedAnalyses::all();
  if (M.getModuleFlag("clang.kernel.lab.source-map")) {
    M.getContext().emitError(
        "clang-kernel-lab-source-map: pending sites were already processed");
    return PreservedAnalyses::all();
  }

  std::vector<PlannedSite> Sites;
  Sites.reserve(PendingList->getNumOperands());
  for (const MDNode *Node : PendingList->operands()) {
    PendingSourceSite Pending;
    if (!Node || !readPendingSourceMetadata(*Node, Pending)) {
      M.getContext().emitError(
          "clang-kernel-lab-source-map: malformed pending source site");
      return PreservedAnalyses::all();
    }
    Function *F = M.getFunction(Pending.Site.FunctionName);
    if (!F || F->isDeclaration()) {
      M.getContext().emitError(
          "clang-kernel-lab-source-map: source marker function was eliminated");
      return PreservedAnalyses::all();
    }
    SmallVector<Instruction *, 4> Candidates;
    for (Instruction &I : instructions(*F))
      if (matchesSourceAnchor(I, *F, M, Pending))
        Candidates.push_back(&I);
    if (Candidates.size() != Pending.AnchorCount ||
        Pending.AnchorOccurrence > Candidates.size()) {
      M.getContext().emitError(
          Twine("clang-kernel-lab-source-map: source marker anchor changed "
                "during optimization; expected ") +
          Pending.AnchorOpcode + " at " + Pending.AnchorSource + ":" +
          Twine(Pending.AnchorLine) + ":" + Twine(Pending.AnchorColumn) +
          " with " + Twine(Pending.AnchorCount) + " match(es), found " +
          Twine(Candidates.size()));
      return PreservedAnalyses::all();
    }
    Pending.Site.Anchor = Candidates[Pending.AnchorOccurrence - 1];
    Sites.push_back(std::move(Pending.Site));
  }

  if (!assignSiteIDs(M, Sites, "clang-kernel-lab-source-map"))
    return PreservedAnalyses::all();
  NamedMDNode *SiteList = M.getOrInsertNamedMetadata("clang.kernel.lab.sites");
  for (PlannedSite &Site : Sites) {
    attachSite(*Site.Anchor, Site);
    SiteList->addOperand(siteMetadata(M.getContext(), Site));
  }
  emitExpectedSites(M, Sites);
  M.eraseNamedMetadata(PendingList);
  M.addModuleFlag(Module::Error, "clang.kernel.lab.source-map", 1);
  return PreservedAnalyses::none();
}

#if LLVM_VERSION_MAJOR >= 24
class KernelLabMapPass : public RequiredPassInfoMixin<KernelLabMapPass> {
#else
class KernelLabMapPass : public PassInfoMixin<KernelLabMapPass> {
#endif
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
        Site.Kind = R.Kind;
        Site.Phase = R.Phase;
        Site.NoInstr = R.NoInstr;
        Site.ManualID = R.ManualID;
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
          Site.Kind = R.Kind;
          Site.Phase = R.Phase;
          Site.NoInstr = R.NoInstr;
          Site.ManualID = R.ManualID;
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
        Site.Kind = R.Kind;
        Site.Phase = R.Phase;
        Site.NoInstr = R.NoInstr;
        Site.ManualID = R.ManualID;
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
        Site.Kind = R.Kind;
        Site.Phase = R.Phase;
        Site.NoInstr = R.NoInstr;
        Site.ManualID = R.ManualID;
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

  if (!assignSiteIDs(M, Sites, "clang-kernel-lab-map"))
    return PreservedAnalyses::all();

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
  PB.registerPipelineEarlySimplificationEPCallback(
      [](ModulePassManager &Manager, OptimizationLevel, ThinOrFullLTOPhase) {
        Manager.addPass(KernelLabSourcePlanPass());
      });
  PB.registerOptimizerLastEPCallback([Loaded](ModulePassManager &Manager,
                                              OptimizationLevel,
                                              ThinOrFullLTOPhase) {
    Manager.addPass(KernelLabSourceMapPass());
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
