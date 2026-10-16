//===- rv-entrycheck.cpp - Audit RISC-V Linux entry code ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Object/BuildID.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/SymbolSize.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/SubtargetFeature.h"
#include "llvm/TargetParser/Triple.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using namespace llvm;
using namespace llvm::object;

namespace {

constexpr uint64_t MaxPolicyBytes = 1024 * 1024;
constexpr uint64_t MaxEntryRegionBytes = 256 * 1024 * 1024;
constexpr uint64_t MaxInstructionOffset = 256 * 1024 * 1024;
constexpr uint64_t MaxTransitiveFunctions = 4096;
constexpr unsigned MaxCallDepth = 128;

cl::opt<std::string> InputFilename(cl::Positional, cl::Required,
                                   cl::desc("<linked-rv64-elf>"));
cl::opt<std::string>
    PolicyFilename("policy", cl::Required,
                   cl::desc("Versioned entry-check policy in JSON format"));
cl::opt<bool> Compact("compact", cl::init(false),
                      cl::desc("Write compact rather than indented JSON"));

struct Policy {
  struct SymbolRange {
    std::string Name;
    std::string StartSymbol;
    std::string EndSymbol;
  };

  struct IndirectCallTargets {
    std::string CallerSymbol;
    uint64_t InstructionOffset = 0;
    std::vector<std::string> TargetSymbols;
  };

  unsigned Schema = 0;
  bool HasExpectedImage = false;
  std::string ExpectedImageSHA256;
  std::optional<std::string> ExpectedBuildID;
  std::vector<std::string> EntrySections;
  std::vector<SymbolRange> EntrySymbolRanges;
  std::vector<IndirectCallTargets> IndirectCalls;
  std::set<std::string> ForbiddenSymbols;
  std::string Hash;
};

struct ResolvedIndirectCall {
  std::string CallerSymbol;
  uint64_t CallerAddress = 0;
  uint64_t CallerEnd = 0;
  uint64_t InstructionOffset = 0;
  uint64_t InstructionAddress = 0;
  std::vector<std::string> TargetSymbols;
  std::vector<uint64_t> TargetAddresses;
  bool Used = false;
};

struct SymbolTables {
  std::map<uint64_t, std::vector<std::string>> FunctionsByAddress;
  std::map<uint64_t, std::vector<uint64_t>> FunctionSizesByAddress;
  std::map<uint64_t, std::vector<std::string>> CodeNamesByAddress;
  std::map<uint64_t, std::vector<std::string>> NamesByAddress;
  std::map<std::string, std::vector<uint64_t>> AddressesByName;
  std::map<std::string, std::vector<uint64_t>> SizesByName;
};

struct ResolvedRegion {
  std::string Name;
  std::string Source;
  std::string Section;
  uint64_t Begin = 0;
  uint64_t End = 0;
  StringRef Bytes;
};

struct DiscoveredTarget {
  uint64_t CallsiteAddress = 0;
  uint64_t TargetAddress = 0;
  std::vector<std::string> TargetSymbols;
  std::vector<std::string> CallPath;
  std::vector<uint64_t> CallPathAddresses;
  std::vector<uint64_t> CallPathCallsites;
};

struct ResolvedFunction {
  ResolvedRegion Region;
  uint64_t ReachedFromAddress = 0;
  unsigned Depth = 0;
  std::vector<std::string> Aliases;
  std::vector<std::string> CallPath;
  std::vector<uint64_t> CallPathAddresses;
  std::vector<uint64_t> CallPathCallsites;
};

struct Finding {
  std::string Rule;
  std::string Region;
  uint64_t InstructionAddress = 0;
  bool HasInstructionAddress = false;
  uint64_t TargetAddress = 0;
  bool HasTargetAddress = false;
  std::vector<std::string> TargetSymbols;
  std::string MatchedSymbol;
  std::string Detail;
  std::vector<std::string> CallPath;
  std::vector<uint64_t> CallPathAddresses;
  std::vector<uint64_t> CallPathCallsites;
};

struct Coverage {
  uint64_t Regions = 0;
  uint64_t Bytes = 0;
  uint64_t Instructions = 0;
  uint64_t Calls = 0;
  uint64_t ResolvedCalls = 0;
  uint64_t UnknownCalls = 0;
  uint64_t PolicyResolvedIndirectCalls = 0;
  uint64_t IndirectTargetEdges = 0;
  uint64_t RootRegions = 0;
  uint64_t TransitiveFunctions = 0;
  uint64_t MaxCallDepthReached = 0;
};

struct DisassemblyState {
  const Target *TheTarget = nullptr;
  std::unique_ptr<const MCRegisterInfo> RegisterInfo;
  std::unique_ptr<const MCAsmInfo> AsmInfo;
  std::unique_ptr<const MCSubtargetInfo> SubtargetInfo;
  std::unique_ptr<const MCInstrInfo> InstrInfo;
  std::unique_ptr<MCContext> Context;
  std::unique_ptr<MCDisassembler> Disassembler;
  std::unique_ptr<MCInstrAnalysis> InstrAnalysis;
};

static Error entryError(const Twine &Message) {
  return createStringError(inconvertibleErrorCode(), Message);
}

static int fail(const Twine &Message) {
  WithColor::error(errs(), "rv-entrycheck") << Message << '\n';
  return 2;
}

static std::string sha256(StringRef Bytes) {
  SHA256 Hasher;
  Hasher.update(Bytes);
  return toHex(Hasher.final(), /*LowerCase=*/true);
}

static bool isLowerHex(StringRef Value) {
  return llvm::all_of(Value, [](char Character) {
    return (Character >= '0' && Character <= '9') ||
           (Character >= 'a' && Character <= 'f');
  });
}

static std::string hex64(uint64_t Value) {
  std::string Result;
  raw_string_ostream OS(Result);
  OS << format_hex(Value, 18, /*Upper=*/false);
  return Result;
}

static Error rejectUnknownKeys(const json::Object &Object,
                               const std::set<std::string> &Known) {
  for (const auto &Entry : Object) {
    StringRef Key = Entry.first;
    if (!Known.count(Key.str()))
      return entryError(Twine("unknown policy field '") + Key + "'");
  }
  return Error::success();
}

// LLVM's JSON object representation replaces duplicate keys. Check decoded
// keys before accepting its parsed object, including escaped spellings.
static bool uniqueJSONKeys(StringRef Text) {
  struct Scope {
    bool Object;
    std::set<std::string> Keys;
  };
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
        Expected<json::Value> Key = json::parse(Text.slice(Start, I + 1));
        if (!Key) {
          consumeError(Key.takeError());
          return false;
        }
        std::optional<StringRef> Name = Key->getAsString();
        if (!Name || Stack.empty() || !Stack.back().Object ||
            !Stack.back().Keys.insert(Name->str()).second)
          return false;
      }
    }
  }
  return Stack.empty();
}

static Expected<Policy> parsePolicy(StringRef Path) {
  ErrorOr<std::unique_ptr<MemoryBuffer>> Buffer =
      MemoryBuffer::getFile(Path, /*IsText=*/true);
  if (!Buffer)
    return entryError(Twine("cannot read policy '") + Path +
                      "': " + Buffer.getError().message());
  if ((*Buffer)->getBufferSize() > MaxPolicyBytes)
    return entryError("policy exceeds the 1 MiB input limit");

  StringRef Text = (*Buffer)->getBuffer();
  if (!uniqueJSONKeys(Text))
    return entryError(
        "policy JSON has duplicate object keys or excessive nesting");
  Expected<json::Value> Parsed = json::parse(Text);
  if (!Parsed)
    return entryError(Twine("invalid policy JSON: ") +
                      toString(Parsed.takeError()));
  const json::Object *Root = Parsed->getAsObject();
  if (!Root)
    return entryError("top-level policy must be an object");
  std::optional<int64_t> SchemaValue = Root->getInteger("schema");
  if (!SchemaValue ||
      (*SchemaValue != 1 && *SchemaValue != 2 && *SchemaValue != 3))
    return entryError(
        "unsupported or missing policy schema; expected 1, 2, or 3");
  unsigned Schema = static_cast<unsigned>(*SchemaValue);
  std::set<std::string> KnownFields{"schema",
                                    "architecture",
                                    "entry_sections",
                                    "entry_symbol_ranges",
                                    "forbidden_symbols",
                                    "reject_unknown_calls"};
  if (Schema >= 2)
    KnownFields.insert({"expected_image", "indirect_call_targets"});
  if (Error E = rejectUnknownKeys(*Root, KnownFields))
    return std::move(E);
  std::optional<StringRef> Architecture = Root->getString("architecture");
  if (!Architecture || *Architecture != "riscv64")
    return entryError("policy architecture must be 'riscv64'");
  if (Root->getBoolean("reject_unknown_calls") != true)
    return entryError(
        "all supported policy schemas require reject_unknown_calls=true");

  const json::Object *ExpectedImage = Root->getObject("expected_image");
  if (Root->get("expected_image") && !ExpectedImage)
    return entryError("expected_image must be an object");

  const json::Array *EntrySections = Root->getArray("entry_sections");
  const json::Array *EntrySymbolRanges = Root->getArray("entry_symbol_ranges");
  const json::Array *IndirectCalls = Root->getArray("indirect_call_targets");
  if (Root->get("entry_sections") && !EntrySections)
    return entryError("entry_sections must be an array");
  if (Root->get("entry_symbol_ranges") && !EntrySymbolRanges)
    return entryError("entry_symbol_ranges must be an array");
  if (Root->get("indirect_call_targets") && !IndirectCalls)
    return entryError("indirect_call_targets must be an array");
  if ((EntrySections && EntrySections->empty()) ||
      (EntrySymbolRanges && EntrySymbolRanges->empty()))
    return entryError("an entry-region array cannot be empty when present");
  size_t EntrySectionCount = EntrySections ? EntrySections->size() : 0;
  size_t EntryRangeCount = EntrySymbolRanges ? EntrySymbolRanges->size() : 0;
  if (!EntrySectionCount && !EntryRangeCount)
    return entryError(
        "policy requires an entry section or symbol-bounded entry range");
  if (EntrySectionCount + EntryRangeCount > 64)
    return entryError("policy exceeds the 64-region limit");
  if (Schema == 2 &&
      (!IndirectCalls || IndirectCalls->empty() || IndirectCalls->size() > 256))
    return entryError(
        "schema two requires 1 through 256 indirect call target rules");
  if (Schema == 3 && (!IndirectCalls || IndirectCalls->size() > 4096))
    return entryError(
        "schema three requires 0 through 4096 indirect call target rules");
  const json::Array *Forbidden = Root->getArray("forbidden_symbols");
  if (!Forbidden || Forbidden->empty() || Forbidden->size() > 4096)
    return entryError("forbidden_symbols must contain 1 through 4096 names");

  Policy Result;
  Result.Schema = Schema;
  Result.Hash = sha256(Text);
  if (ExpectedImage) {
    if (Error E = rejectUnknownKeys(*ExpectedImage, {"sha256", "build_id"}))
      return std::move(E);
    std::optional<StringRef> ExpectedSHA = ExpectedImage->getString("sha256");
    const json::Value *ExpectedBuild = ExpectedImage->get("build_id");
    if (!ExpectedSHA || ExpectedSHA->size() != 64 ||
        !isLowerHex(*ExpectedSHA) || !ExpectedBuild)
      return entryError("expected_image has an invalid or missing field");
    Result.HasExpectedImage = true;
    Result.ExpectedImageSHA256 = ExpectedSHA->str();
    if (!ExpectedBuild->getAsNull()) {
      std::optional<StringRef> BuildID = ExpectedBuild->getAsString();
      if (!BuildID || BuildID->empty() || BuildID->size() > 128 ||
          (BuildID->size() & 1) || !isLowerHex(*BuildID))
        return entryError("expected_image build_id must be null or even hex");
      Result.ExpectedBuildID = BuildID->str();
    }
  }
  std::set<std::string> SeenSections;
  std::set<std::string> SeenRegionNames;
  if (EntrySections) {
    for (const json::Value &Value : *EntrySections) {
      std::optional<StringRef> Name = Value.getAsString();
      if (!Name || Name->empty() || Name->size() > 128)
        return entryError(
            "entry section names must contain 1 through 128 bytes");
      if (!SeenSections.insert(Name->str()).second)
        return entryError("entry_sections contains a duplicate name");
      if (!SeenRegionNames.insert(Name->str()).second)
        return entryError("entry regions must have unique names");
      Result.EntrySections.push_back(Name->str());
    }
  }
  std::set<std::string> SeenRanges;
  if (EntrySymbolRanges) {
    for (const json::Value &Value : *EntrySymbolRanges) {
      const json::Object *Object = Value.getAsObject();
      if (!Object)
        return entryError("each entry symbol range must be an object");
      if (Error E = rejectUnknownKeys(*Object,
                                      {"name", "start_symbol", "end_symbol"}))
        return std::move(E);
      std::optional<StringRef> Name = Object->getString("name");
      std::optional<StringRef> Start = Object->getString("start_symbol");
      std::optional<StringRef> End = Object->getString("end_symbol");
      if (!Name || Name->empty() || Name->size() > 128 || !Start ||
          Start->empty() || Start->size() > 256 || !End || End->empty() ||
          End->size() > 256)
        return entryError("entry symbol range has a missing or invalid field");
      if (*Start == *End)
        return entryError("entry symbol range boundaries must be distinct");
      if (!SeenRanges.insert(Name->str()).second)
        return entryError("entry_symbol_ranges contains a duplicate name");
      if (!SeenRegionNames.insert(Name->str()).second)
        return entryError("entry regions must have unique names");
      Result.EntrySymbolRanges.push_back(
          {Name->str(), Start->str(), End->str()});
    }
  }
  if (IndirectCalls) {
    std::set<std::pair<std::string, uint64_t>> SeenCallsites;
    for (const json::Value &Value : *IndirectCalls) {
      const json::Object *Object = Value.getAsObject();
      if (!Object)
        return entryError("each indirect call target rule must be an object");
      if (Error E =
              rejectUnknownKeys(*Object, {"caller_symbol", "instruction_offset",
                                          "target_symbols"}))
        return std::move(E);
      std::optional<StringRef> Caller = Object->getString("caller_symbol");
      std::optional<int64_t> Offset = Object->getInteger("instruction_offset");
      const json::Array *Targets = Object->getArray("target_symbols");
      if (!Caller || Caller->empty() || Caller->size() > 256 || !Offset ||
          *Offset < 0 || static_cast<uint64_t>(*Offset) > MaxInstructionOffset)
        return entryError(
            "indirect call rule has an invalid caller or instruction offset");
      if (!Targets || Targets->empty() || Targets->size() > 256)
        return entryError(
            "indirect call target_symbols must contain 1 through 256 names");
      uint64_t UnsignedOffset = static_cast<uint64_t>(*Offset);
      if (!SeenCallsites.insert({Caller->str(), UnsignedOffset}).second)
        return entryError(
            "indirect call target rules contain a duplicate site");

      Policy::IndirectCallTargets Rule;
      Rule.CallerSymbol = Caller->str();
      Rule.InstructionOffset = UnsignedOffset;
      std::set<std::string> SeenTargets;
      for (const json::Value &TargetValue : *Targets) {
        std::optional<StringRef> Target = TargetValue.getAsString();
        if (!Target || Target->empty() || Target->size() > 256)
          return entryError(
              "indirect call target names must contain 1 through 256 bytes");
        if (!SeenTargets.insert(Target->str()).second)
          return entryError(
              "an indirect call target rule contains a duplicate target");
        Rule.TargetSymbols.push_back(Target->str());
      }
      Result.IndirectCalls.push_back(std::move(Rule));
    }
  }
  for (const json::Value &Value : *Forbidden) {
    std::optional<StringRef> Name = Value.getAsString();
    if (!Name || Name->empty() || Name->size() > 256)
      return entryError(
          "forbidden symbol names must contain 1 through 256 bytes");
    if (!Result.ForbiddenSymbols.insert(Name->str()).second)
      return entryError("forbidden_symbols contains a duplicate name");
  }
  return Result;
}

static Expected<SymbolTables> readDefinedSymbols(const ObjectFile &Object) {
  SymbolTables Symbols;
  for (SymbolRef Symbol : Object.symbols()) {
    Expected<uint32_t> Flags = Symbol.getFlags();
    if (!Flags)
      return Flags.takeError();
    if (*Flags & SymbolRef::SF_Undefined)
      continue;
    Expected<StringRef> Name = Symbol.getName();
    if (!Name)
      return Name.takeError();
    if (Name->empty())
      continue;
    Expected<uint64_t> Address = Symbol.getAddress();
    if (!Address)
      return Address.takeError();
    Symbols.NamesByAddress[*Address].push_back(Name->str());
    Symbols.AddressesByName[Name->str()].push_back(*Address);
    Expected<SymbolRef::Type> Type = Symbol.getType();
    if (!Type)
      return Type.takeError();
    if (*Type == SymbolRef::ST_Function)
      Symbols.FunctionsByAddress[*Address].push_back(Name->str());
    Expected<section_iterator> Section = Symbol.getSection();
    if (!Section)
      return Section.takeError();
    if (*Section != Object.section_end() &&
        (ELFSectionRef(**Section).getFlags() & ELF::SHF_EXECINSTR))
      Symbols.CodeNamesByAddress[*Address].push_back(Name->str());
  }
  for (const auto &[Symbol, Size] : computeSymbolSizes(Object)) {
    Expected<uint32_t> Flags = Symbol.getFlags();
    if (!Flags)
      return Flags.takeError();
    if (*Flags & SymbolRef::SF_Undefined)
      continue;
    Expected<StringRef> Name = Symbol.getName();
    if (!Name)
      return Name.takeError();
    if (!Name->empty())
      Symbols.SizesByName[Name->str()].push_back(Size);
    Expected<SymbolRef::Type> Type = Symbol.getType();
    if (!Type)
      return Type.takeError();
    if (*Type == SymbolRef::ST_Function) {
      Expected<uint64_t> Address = Symbol.getAddress();
      if (!Address)
        return Address.takeError();
      Symbols.FunctionSizesByAddress[*Address].push_back(Size);
    }
  }
  for (auto &[Address, Names] : Symbols.FunctionsByAddress) {
    (void)Address;
    llvm::sort(Names);
    Names.erase(std::unique(Names.begin(), Names.end()), Names.end());
  }
  for (auto &[Address, Names] : Symbols.NamesByAddress) {
    (void)Address;
    llvm::sort(Names);
    Names.erase(std::unique(Names.begin(), Names.end()), Names.end());
  }
  for (auto &[Address, Names] : Symbols.CodeNamesByAddress) {
    (void)Address;
    llvm::sort(Names);
    Names.erase(std::unique(Names.begin(), Names.end()), Names.end());
  }
  for (auto &[Address, Sizes] : Symbols.FunctionSizesByAddress) {
    (void)Address;
    llvm::sort(Sizes);
    Sizes.erase(std::unique(Sizes.begin(), Sizes.end()), Sizes.end());
  }
  for (auto &[Name, Addresses] : Symbols.AddressesByName) {
    (void)Name;
    llvm::sort(Addresses);
    Addresses.erase(std::unique(Addresses.begin(), Addresses.end()),
                    Addresses.end());
  }
  for (auto &[Name, Sizes] : Symbols.SizesByName) {
    (void)Name;
    llvm::sort(Sizes);
    Sizes.erase(std::unique(Sizes.begin(), Sizes.end()), Sizes.end());
  }
  return Symbols;
}

static Expected<std::unique_ptr<DisassemblyState>>
createDisassembly(const ObjectFile &Object) {
  LLVMInitializeRISCVTargetInfo();
  LLVMInitializeRISCVTargetMC();
  LLVMInitializeRISCVDisassembler();

  Triple TheTriple = Object.makeTriple();
  std::string ErrorMessage;
  const Target *TheTarget =
      TargetRegistry::lookupTarget(TheTriple, ErrorMessage);
  if (!TheTarget)
    return entryError(Twine("cannot initialize RISC-V target: ") +
                      ErrorMessage);

  Expected<SubtargetFeatures> Features = Object.getFeatures();
  if (!Features)
    return Features.takeError();
  std::string CPU = Object.tryGetCPUName().value_or("").str();
  if (CPU.empty())
    CPU = "generic-rv64";

  auto Result = std::make_unique<DisassemblyState>();
  Result->TheTarget = TheTarget;
  Result->RegisterInfo.reset(TheTarget->createMCRegInfo(TheTriple));
  if (!Result->RegisterInfo)
    return entryError("RISC-V target has no register information");
  MCTargetOptions Options;
  Result->AsmInfo.reset(
      TheTarget->createMCAsmInfo(*Result->RegisterInfo, TheTriple, Options));
  if (!Result->AsmInfo)
    return entryError("RISC-V target has no assembly information");
  Result->SubtargetInfo.reset(
      TheTarget->createMCSubtargetInfo(TheTriple, CPU, Features->getString()));
  if (!Result->SubtargetInfo)
    return entryError("RISC-V target has no subtarget information");
  Result->InstrInfo.reset(TheTarget->createMCInstrInfo());
  if (!Result->InstrInfo)
    return entryError("RISC-V target has no instruction information");
#if LLVM_VERSION_MAJOR >= 24
  Result->Context = std::make_unique<MCContext>(TheTriple, *Result->AsmInfo,
                                                *Result->RegisterInfo,
                                                *Result->SubtargetInfo);
#else
  Result->Context = std::make_unique<MCContext>(
      TheTriple, Result->AsmInfo.get(), Result->RegisterInfo.get(),
      Result->SubtargetInfo.get());
#endif
  Result->Disassembler.reset(TheTarget->createMCDisassembler(
      *Result->SubtargetInfo, *Result->Context));
  if (!Result->Disassembler)
    return entryError("RISC-V target has no disassembler");
  Result->InstrAnalysis.reset(
      TheTarget->createMCInstrAnalysis(Result->InstrInfo.get()));
  if (!Result->InstrAnalysis)
    return entryError("RISC-V target has no instruction analysis");
  return std::move(Result);
}

static Finding addressFinding(StringRef Rule, StringRef Region,
                              uint64_t Address, StringRef Detail) {
  Finding Result;
  Result.Rule = Rule.str();
  Result.Region = Region.str();
  Result.InstructionAddress = Address;
  Result.HasInstructionAddress = true;
  Result.Detail = Detail.str();
  return Result;
}

static bool hasCodeName(const SymbolTables &Symbols, uint64_t Address,
                        StringRef Name) {
  if (Name.starts_with("$x") || Name.starts_with("$d"))
    return false;
  auto CodeNames = Symbols.CodeNamesByAddress.find(Address);
  return CodeNames != Symbols.CodeNamesByAddress.end() &&
         llvm::is_contained(CodeNames->second, Name.str());
}

static std::map<uint64_t, ResolvedIndirectCall>
resolveIndirectCalls(const Policy &Configuration, const SymbolTables &Symbols,
                     std::vector<Finding> &Findings) {
  std::map<uint64_t, ResolvedIndirectCall> Resolved;
  for (const Policy::IndirectCallTargets &Rule : Configuration.IndirectCalls) {
    auto Caller = Symbols.AddressesByName.find(Rule.CallerSymbol);
    if (Caller == Symbols.AddressesByName.end() || Caller->second.size() != 1) {
      Finding F;
      F.Rule = "unresolved-indirect-caller";
      F.Region = Rule.CallerSymbol;
      F.Detail = "caller_symbol must resolve to one defined symbol";
      Findings.push_back(std::move(F));
      continue;
    }
    uint64_t CallerAddress = Caller->second.front();
    auto CallerSizes = Symbols.SizesByName.find(Rule.CallerSymbol);
    if (CallerSizes == Symbols.SizesByName.end() ||
        CallerSizes->second.size() != 1 || !CallerSizes->second.front()) {
      Findings.push_back(addressFinding(
          "unresolved-indirect-caller-range", Rule.CallerSymbol, CallerAddress,
          "caller_symbol must have one non-empty linked symbol range"));
      continue;
    }
    uint64_t CallerSize = CallerSizes->second.front();
    if (CallerAddress > std::numeric_limits<uint64_t>::max() - CallerSize) {
      Findings.push_back(addressFinding(
          "invalid-indirect-caller-range", Rule.CallerSymbol, CallerAddress,
          "caller_symbol range overflows uint64"));
      continue;
    }
    if (Rule.InstructionOffset >= CallerSize) {
      Findings.push_back(addressFinding(
          "invalid-indirect-callsite", Rule.CallerSymbol, CallerAddress,
          "instruction offset is outside caller_symbol's linked range"));
      continue;
    }
    if (CallerAddress >
        std::numeric_limits<uint64_t>::max() - Rule.InstructionOffset) {
      Findings.push_back(addressFinding(
          "invalid-indirect-callsite", Rule.CallerSymbol, CallerAddress,
          "caller address plus instruction offset overflows uint64"));
      continue;
    }

    ResolvedIndirectCall Candidate;
    Candidate.CallerSymbol = Rule.CallerSymbol;
    Candidate.CallerAddress = CallerAddress;
    Candidate.CallerEnd = CallerAddress + CallerSize;
    Candidate.InstructionOffset = Rule.InstructionOffset;
    Candidate.InstructionAddress = CallerAddress + Rule.InstructionOffset;
    if (Candidate.InstructionAddress & 1) {
      Findings.push_back(
          addressFinding("misaligned-indirect-callsite", Rule.CallerSymbol,
                         Candidate.InstructionAddress,
                         "RISC-V indirect callsite must be two-byte aligned"));
      continue;
    }
    bool Valid = true;
    std::set<uint64_t> SeenTargetAddresses;
    for (const std::string &TargetName : Rule.TargetSymbols) {
      auto Target = Symbols.AddressesByName.find(TargetName);
      if (Target == Symbols.AddressesByName.end() ||
          Target->second.size() != 1 ||
          !hasCodeName(Symbols, Target->second.front(), TargetName)) {
        Finding F = addressFinding(
            "unresolved-indirect-target", Rule.CallerSymbol,
            Candidate.InstructionAddress,
            "target_symbols entry must resolve to one defined code symbol");
        F.MatchedSymbol = TargetName;
        Findings.push_back(std::move(F));
        Valid = false;
        continue;
      }
      uint64_t TargetAddress = Target->second.front();
      if (!SeenTargetAddresses.insert(TargetAddress).second) {
        Finding F = addressFinding(
            "duplicate-indirect-target-address", Rule.CallerSymbol,
            Candidate.InstructionAddress,
            "different target_symbols entries alias the same linked address");
        F.TargetAddress = TargetAddress;
        F.HasTargetAddress = true;
        F.MatchedSymbol = TargetName;
        Findings.push_back(std::move(F));
        Valid = false;
        continue;
      }
      if (TargetAddress & 1) {
        Finding F =
            addressFinding("misaligned-indirect-target", Rule.CallerSymbol,
                           Candidate.InstructionAddress,
                           "RISC-V indirect target must be two-byte aligned");
        F.TargetAddress = TargetAddress;
        F.HasTargetAddress = true;
        F.MatchedSymbol = TargetName;
        Findings.push_back(std::move(F));
        Valid = false;
        continue;
      }
      auto Names = Symbols.NamesByAddress.find(TargetAddress);
      std::optional<StringRef> ForbiddenName;
      if (Names != Symbols.NamesByAddress.end()) {
        auto Forbidden = std::find_if(
            Names->second.begin(), Names->second.end(),
            [&](StringRef CandidateName) {
              return Configuration.ForbiddenSymbols.count(CandidateName.str());
            });
        if (Forbidden != Names->second.end())
          ForbiddenName = *Forbidden;
      }
      if (ForbiddenName) {
        Finding F = addressFinding(
            "forbidden-indirect-target", Rule.CallerSymbol,
            Candidate.InstructionAddress,
            "an approved indirect target aliases a forbidden callback");
        F.TargetAddress = TargetAddress;
        F.HasTargetAddress = true;
        F.TargetSymbols = Names->second;
        F.MatchedSymbol = ForbiddenName->str();
        Findings.push_back(std::move(F));
        Valid = false;
        continue;
      }
      Candidate.TargetSymbols.push_back(TargetName);
      Candidate.TargetAddresses.push_back(TargetAddress);
    }
    if (!Valid)
      continue;
    auto [Position, Inserted] =
        Resolved.emplace(Candidate.InstructionAddress, std::move(Candidate));
    if (!Inserted)
      Findings.push_back(addressFinding(
          "ambiguous-indirect-callsite", Rule.CallerSymbol, Position->first,
          "multiple policy rules resolve to the same instruction address"));
  }
  return Resolved;
}

static Expected<std::optional<ResolvedFunction>>
resolveTransitiveFunction(const DiscoveredTarget &Target, unsigned Depth,
                          const ObjectFile &Object, const SymbolTables &Symbols,
                          std::vector<Finding> &Findings) {
  auto Functions = Symbols.FunctionsByAddress.find(Target.TargetAddress);
  std::string Name = Target.TargetSymbols.empty()
                         ? hex64(Target.TargetAddress)
                         : Target.TargetSymbols.front();
  std::vector<std::string> Path = Target.CallPath;
  Path.push_back(Name);
  std::vector<uint64_t> PathAddresses = Target.CallPathAddresses;
  PathAddresses.push_back(Target.TargetAddress);
  auto AddFailure = [&](StringRef Rule, StringRef Detail) {
    Finding F = addressFinding(Rule, Name, Target.CallsiteAddress, Detail);
    F.TargetAddress = Target.TargetAddress;
    F.HasTargetAddress = true;
    auto Aliases = Symbols.NamesByAddress.find(Target.TargetAddress);
    F.TargetSymbols = Aliases == Symbols.NamesByAddress.end()
                          ? Target.TargetSymbols
                          : Aliases->second;
    F.CallPath = Path;
    F.CallPathAddresses = PathAddresses;
    F.CallPathCallsites = Target.CallPathCallsites;
    Findings.push_back(std::move(F));
  };
  if (Functions == Symbols.FunctionsByAddress.end()) {
    AddFailure("unresolved-transitive-function",
               "reachable target has no defined function symbol");
    return std::optional<ResolvedFunction>();
  }

  std::set<uint64_t> Sizes;
  auto FunctionSizes =
      Symbols.FunctionSizesByAddress.find(Target.TargetAddress);
  if (FunctionSizes != Symbols.FunctionSizesByAddress.end()) {
    for (uint64_t Size : FunctionSizes->second) {
      if (Size)
        Sizes.insert(Size);
    }
  }
  if (Sizes.size() != 1) {
    AddFailure("unresolved-transitive-function-range",
               "reachable function aliases must identify one non-empty linked "
               "range");
    return std::optional<ResolvedFunction>();
  }
  uint64_t Size = *Sizes.begin();
  if (Size > MaxEntryRegionBytes) {
    AddFailure("oversized-transitive-function",
               "reachable function exceeds the 256 MiB region limit");
    return std::optional<ResolvedFunction>();
  }
  if (Target.TargetAddress > std::numeric_limits<uint64_t>::max() - Size) {
    AddFailure("invalid-transitive-function-range",
               "reachable function range overflows uint64");
    return std::optional<ResolvedFunction>();
  }
  uint64_t EndAddress = Target.TargetAddress + Size;

  std::vector<ResolvedRegion> Matches;
  for (SectionRef Section : Object.sections()) {
    if (!(ELFSectionRef(Section).getFlags() & ELF::SHF_EXECINSTR))
      continue;
    Expected<StringRef> SectionName = Section.getName();
    if (!SectionName)
      return SectionName.takeError();
    Expected<StringRef> Contents = Section.getContents();
    if (!Contents)
      return Contents.takeError();
    uint64_t SectionBegin = Section.getAddress();
    if (SectionBegin > std::numeric_limits<uint64_t>::max() - Contents->size())
      return entryError(Twine("executable section '") + *SectionName +
                        "' address range overflows uint64");
    uint64_t SectionEnd = SectionBegin + Contents->size();
    if (Target.TargetAddress < SectionBegin || EndAddress > SectionEnd)
      continue;
    uint64_t Offset = Target.TargetAddress - SectionBegin;
    Matches.push_back({Name, "function:" + Name, SectionName->str(),
                       Target.TargetAddress, EndAddress,
                       Contents->substr(Offset, Size)});
  }
  if (Matches.size() != 1) {
    AddFailure("unmapped-transitive-function",
               "reachable function must belong to one executable section");
    return std::optional<ResolvedFunction>();
  }

  ResolvedFunction Result;
  Result.Region = std::move(Matches.front());
  Result.ReachedFromAddress = Target.CallsiteAddress;
  Result.Depth = Depth;
  auto Aliases = Symbols.NamesByAddress.find(Target.TargetAddress);
  Result.Aliases = Aliases == Symbols.NamesByAddress.end()
                       ? Target.TargetSymbols
                       : Aliases->second;
  Result.CallPath = std::move(Path);
  Result.CallPathAddresses = std::move(PathAddresses);
  Result.CallPathCallsites = Target.CallPathCallsites;
  return std::optional<ResolvedFunction>(std::move(Result));
}

static Error scanRegion(
    const ResolvedRegion &Region, const Policy &Configuration,
    const SymbolTables &Symbols,
    std::map<uint64_t, ResolvedIndirectCall> &IndirectCalls,
    DisassemblyState &State, Coverage &Counts, std::vector<Finding> &Findings,
    ArrayRef<std::string> CallPath, ArrayRef<uint64_t> CallPathAddresses,
    ArrayRef<uint64_t> CallPathCallsites,
    std::vector<DiscoveredTarget> *DiscoveredTargets, bool IsTransitive) {
  auto AddFinding = [&](Finding F) {
    F.CallPath.assign(CallPath.begin(), CallPath.end());
    F.CallPathAddresses.assign(CallPathAddresses.begin(),
                               CallPathAddresses.end());
    F.CallPathCallsites.assign(CallPathCallsites.begin(),
                               CallPathCallsites.end());
    Findings.push_back(std::move(F));
  };
  if (Region.Bytes.empty()) {
    AddFinding(addressFinding("empty-entry-region", Region.Name, Region.Begin,
                              "configured entry region is empty"));
    return Error::success();
  }
  if (Region.Bytes.size() > MaxEntryRegionBytes)
    return entryError(Twine("entry region '") + Region.Name +
                      "' exceeds the 256 MiB limit");
  if (Region.Begin > std::numeric_limits<uint64_t>::max() - Region.Bytes.size())
    return entryError(Twine("entry region '") + Region.Name +
                      "' address range overflows uint64");
  if ((Region.Begin | Region.End) & 1) {
    AddFinding(
        addressFinding("misaligned-entry-region", Region.Name, Region.Begin,
                       "RISC-V entry boundaries must be two-byte aligned"));
    return Error::success();
  }

  ArrayRef<uint8_t> Bytes(
      reinterpret_cast<const uint8_t *>(Region.Bytes.data()),
      Region.Bytes.size());
  State.InstrAnalysis->resetState();
  ++Counts.Regions;
  if (IsTransitive)
    ++Counts.TransitiveFunctions;
  else
    ++Counts.RootRegions;
  Counts.Bytes += Bytes.size();
  for (uint64_t Offset = 0; Offset < Bytes.size();) {
    uint64_t InstructionAddress = Region.Begin + Offset;
    MCInst Instruction;
    uint64_t Size = 0;
    MCDisassembler::DecodeStatus Status = State.Disassembler->getInstruction(
        Instruction, Size, Bytes.drop_front(Offset), InstructionAddress,
        nulls());
    if (Status != MCDisassembler::Success || !Size ||
        Size > Bytes.size() - Offset) {
      AddFinding(
          addressFinding("decode-failure", Region.Name, InstructionAddress,
                         Status == MCDisassembler::SoftFail
                             ? "instruction decoded as architecturally invalid"
                             : "instruction could not be decoded completely"));
      break;
    }

    ++Counts.Instructions;
    if (State.InstrAnalysis->isCall(Instruction)) {
      ++Counts.Calls;
      uint64_t TargetAddress = 0;
      bool TargetKnown = State.InstrAnalysis->evaluateBranch(
          Instruction, InstructionAddress, Size, TargetAddress);
      auto Function = TargetKnown
                          ? Symbols.FunctionsByAddress.find(TargetAddress)
                          : Symbols.FunctionsByAddress.end();
      auto Names = TargetKnown ? Symbols.NamesByAddress.find(TargetAddress)
                               : Symbols.NamesByAddress.end();
      std::optional<StringRef> ForbiddenName;
      if (Names != Symbols.NamesByAddress.end()) {
        auto Forbidden = std::find_if(
            Names->second.begin(), Names->second.end(),
            [&](StringRef Candidate) {
              return Configuration.ForbiddenSymbols.count(Candidate.str());
            });
        if (Forbidden != Names->second.end())
          ForbiddenName = *Forbidden;
      }
      if (!TargetKnown) {
        auto Approved = IndirectCalls.find(InstructionAddress);
        if (Approved != IndirectCalls.end()) {
          if (InstructionAddress >
                  std::numeric_limits<uint64_t>::max() - Size ||
              InstructionAddress + Size > Approved->second.CallerEnd) {
            ++Counts.UnknownCalls;
            AddFinding(addressFinding(
                "callsite-outside-caller", Region.Name, InstructionAddress,
                "indirect call instruction crosses caller_symbol's linked "
                "range"));
          } else {
            Approved->second.Used = true;
            ++Counts.ResolvedCalls;
            ++Counts.PolicyResolvedIndirectCalls;
            Counts.IndirectTargetEdges +=
                Approved->second.TargetAddresses.size();
            if (DiscoveredTargets) {
              for (size_t Index = 0;
                   Index < Approved->second.TargetAddresses.size(); ++Index) {
                DiscoveredTarget Target;
                Target.CallsiteAddress = InstructionAddress;
                Target.TargetAddress = Approved->second.TargetAddresses[Index];
                Target.TargetSymbols = {Approved->second.TargetSymbols[Index]};
                Target.CallPath.assign(CallPath.begin(), CallPath.end());
                Target.CallPathAddresses.assign(CallPathAddresses.begin(),
                                                CallPathAddresses.end());
                Target.CallPathCallsites.assign(CallPathCallsites.begin(),
                                                CallPathCallsites.end());
                Target.CallPathCallsites.push_back(InstructionAddress);
                DiscoveredTargets->push_back(std::move(Target));
              }
            }
          }
        } else {
          ++Counts.UnknownCalls;
          AddFinding(addressFinding(
              "unknown-call", Region.Name, InstructionAddress,
              "call target cannot be resolved statically and has no exact "
              "callsite policy"));
        }
      } else if (ForbiddenName) {
        ++Counts.ResolvedCalls;
        Finding F =
            addressFinding("forbidden-call", Region.Name, InstructionAddress,
                           "entry region directly calls a forbidden callback");
        F.TargetAddress = TargetAddress;
        F.HasTargetAddress = true;
        F.TargetSymbols = Names->second;
        F.MatchedSymbol = ForbiddenName->str();
        AddFinding(std::move(F));
      } else if (Function == Symbols.FunctionsByAddress.end()) {
        ++Counts.UnknownCalls;
        Finding F =
            addressFinding("unknown-call", Region.Name, InstructionAddress,
                           "direct call target has no defined function symbol");
        F.TargetAddress = TargetAddress;
        F.HasTargetAddress = true;
        if (Names != Symbols.NamesByAddress.end())
          F.TargetSymbols = Names->second;
        AddFinding(std::move(F));
      } else {
        ++Counts.ResolvedCalls;
        if (DiscoveredTargets) {
          DiscoveredTarget Target;
          Target.CallsiteAddress = InstructionAddress;
          Target.TargetAddress = TargetAddress;
          Target.TargetSymbols = Function->second;
          Target.CallPath.assign(CallPath.begin(), CallPath.end());
          Target.CallPathAddresses.assign(CallPathAddresses.begin(),
                                          CallPathAddresses.end());
          Target.CallPathCallsites.assign(CallPathCallsites.begin(),
                                          CallPathCallsites.end());
          Target.CallPathCallsites.push_back(InstructionAddress);
          DiscoveredTargets->push_back(std::move(Target));
        }
      }
    }
#if LLVM_VERSION_MAJOR >= 24
    State.InstrAnalysis->updateState(Instruction, State.SubtargetInfo.get(),
                                     InstructionAddress);
#else
    State.InstrAnalysis->updateState(Instruction, InstructionAddress);
#endif
    Offset += Size;
  }
  return Error::success();
}

static json::Object findingJSON(const Finding &F) {
  json::Array Symbols;
  for (const std::string &Name : F.TargetSymbols)
    Symbols.push_back(Name);
  json::Object Result{
      {"rule", F.Rule},
      {"region", F.Region},
      {"detail", F.Detail},
      {"instruction_va", F.HasInstructionAddress
                             ? json::Value(hex64(F.InstructionAddress))
                             : json::Value(nullptr)},
      {"target_va", F.HasTargetAddress ? json::Value(hex64(F.TargetAddress))
                                       : json::Value(nullptr)},
      {"target_symbols", std::move(Symbols)},
  };
  Result["matched_symbol"] = F.MatchedSymbol.empty()
                                 ? json::Value(nullptr)
                                 : json::Value(F.MatchedSymbol);
  if (!F.CallPath.empty()) {
    json::Array Path;
    for (const std::string &Name : F.CallPath)
      Path.push_back(Name);
    Result["call_path"] = std::move(Path);
    json::Array Addresses;
    for (uint64_t Address : F.CallPathAddresses)
      Addresses.push_back(hex64(Address));
    Result["call_path_vas"] = std::move(Addresses);
    json::Array Callsites;
    for (uint64_t Address : F.CallPathCallsites)
      Callsites.push_back(hex64(Address));
    Result["call_path_callsites"] = std::move(Callsites);
  }
  return Result;
}

} // namespace

int main(int Argc, char **Argv) {
  InitLLVM Initialize(Argc, Argv);
  cl::ParseCommandLineOptions(
      Argc, Argv,
      "Conservatively audit calls reachable from RISC-V Linux entry regions\n");

  Expected<Policy> Configuration = parsePolicy(PolicyFilename);
  if (!Configuration)
    return fail(toString(Configuration.takeError()));

  ErrorOr<std::unique_ptr<MemoryBuffer>> Buffer =
      MemoryBuffer::getFile(InputFilename, /*IsText=*/false,
                            /*RequiresNullTerminator=*/false);
  if (!Buffer)
    return fail(Twine("cannot read '") + InputFilename +
                "': " + Buffer.getError().message());
  Expected<std::unique_ptr<ObjectFile>> ObjectOrError =
      ObjectFile::createObjectFile((*Buffer)->getMemBufferRef());
  if (!ObjectOrError)
    return fail(toString(ObjectOrError.takeError()));
  std::unique_ptr<ObjectFile> Object = std::move(*ObjectOrError);

  if (!Object->isELF())
    return fail("input is not an ELF image");
  if (Object->getArch() != Triple::riscv64 || Object->getBytesInAddress() != 8)
    return fail("entry checking requires an RV64 ELF image");
  if (!Object->isLittleEndian())
    return fail("entry checking requires a little-endian ELF image");
  if (Object->isRelocatableObject())
    return fail("entry checking requires a linked ELF image");

  std::string ImageSHA256 = sha256((*Buffer)->getBuffer());
  BuildIDRef BuildID = getBuildID(Object.get());
  std::optional<std::string> ImageBuildID;
  if (!BuildID.empty())
    ImageBuildID = toHex(BuildID, /*LowerCase=*/true);

  Expected<SymbolTables> Symbols = readDefinedSymbols(*Object);
  if (!Symbols)
    return fail(toString(Symbols.takeError()));
  Expected<std::unique_ptr<DisassemblyState>> State =
      createDisassembly(*Object);
  if (!State)
    return fail(toString(State.takeError()));

  Coverage Counts;
  std::vector<Finding> Findings;
  if (Configuration->HasExpectedImage) {
    if (Configuration->ExpectedImageSHA256 != ImageSHA256) {
      Finding F;
      F.Rule = "image-sha256-mismatch";
      F.Region = "image";
      F.Detail = "linked image does not match expected_image sha256";
      Findings.push_back(std::move(F));
    }
    if (Configuration->ExpectedBuildID != ImageBuildID) {
      Finding F;
      F.Rule = "image-build-id-mismatch";
      F.Region = "image";
      F.Detail = "linked image does not match expected_image build_id";
      Findings.push_back(std::move(F));
    }
  }
  std::map<uint64_t, ResolvedIndirectCall> IndirectCalls =
      resolveIndirectCalls(*Configuration, *Symbols, Findings);
  std::vector<ResolvedRegion> Regions;
  for (const std::string &Name : Configuration->EntrySections) {
    std::vector<SectionRef> Matches;
    for (SectionRef Section : Object->sections()) {
      Expected<StringRef> SectionName = Section.getName();
      if (!SectionName)
        return fail(toString(SectionName.takeError()));
      if (*SectionName == Name)
        Matches.push_back(Section);
    }
    if (Matches.empty()) {
      Finding F;
      F.Rule = "missing-entry-section";
      F.Region = Name;
      F.Detail = "configured entry section is absent";
      Findings.push_back(std::move(F));
      continue;
    }
    if (Matches.size() != 1) {
      Finding F;
      F.Rule = "duplicate-entry-section";
      F.Region = Name;
      F.Detail = "configured entry section appears more than once";
      Findings.push_back(std::move(F));
      continue;
    }
    SectionRef Section = Matches.front();
    if (!(ELFSectionRef(Section).getFlags() & ELF::SHF_EXECINSTR)) {
      Findings.push_back(addressFinding(
          "non-executable-entry-region", Name, Section.getAddress(),
          "configured entry section lacks SHF_EXECINSTR"));
      continue;
    }
    Expected<StringRef> Contents = Section.getContents();
    if (!Contents)
      return fail(toString(Contents.takeError()));
    uint64_t Begin = Section.getAddress();
    if (Begin > std::numeric_limits<uint64_t>::max() - Contents->size())
      return fail(Twine("entry section '") + Name +
                  "' address range overflows uint64");
    Regions.push_back({Name, "section:" + Name, Name, Begin,
                       Begin + Contents->size(), *Contents});
  }

  for (const Policy::SymbolRange &Range : Configuration->EntrySymbolRanges) {
    auto Start = Symbols->AddressesByName.find(Range.StartSymbol);
    auto End = Symbols->AddressesByName.find(Range.EndSymbol);
    if (Start == Symbols->AddressesByName.end() || Start->second.size() != 1 ||
        End == Symbols->AddressesByName.end() || End->second.size() != 1) {
      Finding F;
      F.Rule = "unresolved-entry-boundary";
      F.Region = Range.Name;
      F.Detail =
          "entry boundary symbols must each resolve to one defined address";
      Findings.push_back(std::move(F));
      continue;
    }
    uint64_t Begin = Start->second.front();
    uint64_t EndAddress = End->second.front();
    if (EndAddress <= Begin) {
      Findings.push_back(addressFinding(
          "invalid-entry-range", Range.Name, Begin,
          "entry end boundary does not follow its start boundary"));
      continue;
    }

    std::vector<ResolvedRegion> Matches;
    for (SectionRef Section : Object->sections()) {
      if (!(ELFSectionRef(Section).getFlags() & ELF::SHF_EXECINSTR))
        continue;
      Expected<StringRef> Name = Section.getName();
      if (!Name)
        return fail(toString(Name.takeError()));
      Expected<StringRef> Contents = Section.getContents();
      if (!Contents)
        return fail(toString(Contents.takeError()));
      uint64_t SectionBegin = Section.getAddress();
      if (SectionBegin >
          std::numeric_limits<uint64_t>::max() - Contents->size())
        return fail(Twine("executable section '") + *Name +
                    "' address range overflows uint64");
      uint64_t SectionEnd = SectionBegin + Contents->size();
      if (Begin < SectionBegin || EndAddress > SectionEnd)
        continue;
      uint64_t Offset = Begin - SectionBegin;
      uint64_t Size = EndAddress - Begin;
      Matches.push_back(
          {Range.Name, "symbols:" + Range.StartSymbol + ".." + Range.EndSymbol,
           Name->str(), Begin, EndAddress, Contents->substr(Offset, Size)});
    }
    if (Matches.size() != 1) {
      Finding F;
      F.Rule = "unmapped-entry-range";
      F.Region = Range.Name;
      F.Detail = "entry symbol range must belong to one executable section";
      Findings.push_back(std::move(F));
      continue;
    }
    Regions.push_back(std::move(Matches.front()));
  }

  llvm::sort(Regions,
             [](const ResolvedRegion &Left, const ResolvedRegion &Right) {
               return std::tie(Left.Begin, Left.End, Left.Name) <
                      std::tie(Right.Begin, Right.End, Right.Name);
             });
  for (size_t Index = 1; Index < Regions.size(); ++Index) {
    if (Regions[Index].Begin >= Regions[Index - 1].End)
      continue;
    Findings.push_back(addressFinding(
        "overlapping-entry-regions", Regions[Index].Name, Regions[Index].Begin,
        "configured entry regions overlap and would double-count code"));
  }
  std::vector<DiscoveredTarget> InitialTargets;
  for (const ResolvedRegion &Region : Regions) {
    std::vector<std::string> CallPath;
    std::vector<uint64_t> CallPathAddresses;
    std::vector<uint64_t> CallPathCallsites;
    if (Configuration->Schema >= 3) {
      CallPath.push_back(Region.Name);
      CallPathAddresses.push_back(Region.Begin);
    }
    if (Error E = scanRegion(
            Region, *Configuration, *Symbols, IndirectCalls, **State, Counts,
            Findings, CallPath, CallPathAddresses, CallPathCallsites,
            Configuration->Schema >= 3 ? &InitialTargets : nullptr,
            /*IsTransitive=*/false))
      return fail(toString(std::move(E)));
  }

  std::vector<ResolvedFunction> TransitiveFunctions;
  if (Configuration->Schema >= 3) {
    auto InRootRegion = [&](uint64_t Address) {
      return llvm::any_of(Regions, [&](const ResolvedRegion &Region) {
        return Address >= Region.Begin && Address < Region.End;
      });
    };
    std::set<uint64_t> Scheduled;
    std::vector<DiscoveredTarget> Worklist;
    bool FunctionLimitReported = false;
    auto Schedule = [&](DiscoveredTarget Target) {
      if (InRootRegion(Target.TargetAddress) ||
          Scheduled.count(Target.TargetAddress))
        return;
      if (Scheduled.size() >= MaxTransitiveFunctions) {
        if (!FunctionLimitReported) {
          Finding F = addressFinding(
              "transitive-function-limit", Target.CallPath.back(),
              Target.CallsiteAddress,
              "call graph exceeds the 4096-function safety limit");
          F.TargetAddress = Target.TargetAddress;
          F.HasTargetAddress = true;
          F.TargetSymbols = Target.TargetSymbols;
          F.CallPath = Target.CallPath;
          F.CallPathAddresses = Target.CallPathAddresses;
          F.CallPathCallsites = Target.CallPathCallsites;
          F.CallPath.push_back(Target.TargetSymbols.empty()
                                   ? hex64(Target.TargetAddress)
                                   : Target.TargetSymbols.front());
          F.CallPathAddresses.push_back(Target.TargetAddress);
          Findings.push_back(std::move(F));
          FunctionLimitReported = true;
        }
        return;
      }
      Scheduled.insert(Target.TargetAddress);
      Worklist.push_back(std::move(Target));
    };
    for (DiscoveredTarget &Target : InitialTargets)
      Schedule(std::move(Target));

    for (size_t Index = 0; Index < Worklist.size(); ++Index) {
      DiscoveredTarget Target = std::move(Worklist[Index]);
      unsigned Depth = static_cast<unsigned>(Target.CallPath.size());
      if (Depth > MaxCallDepth) {
        Finding F = addressFinding(
            "call-depth-limit", Target.CallPath.back(), Target.CallsiteAddress,
            "call path exceeds the 128-edge safety limit");
        F.TargetAddress = Target.TargetAddress;
        F.HasTargetAddress = true;
        F.TargetSymbols = Target.TargetSymbols;
        F.CallPath = Target.CallPath;
        F.CallPathAddresses = Target.CallPathAddresses;
        F.CallPathCallsites = Target.CallPathCallsites;
        F.CallPath.push_back(Target.TargetSymbols.empty()
                                 ? hex64(Target.TargetAddress)
                                 : Target.TargetSymbols.front());
        F.CallPathAddresses.push_back(Target.TargetAddress);
        Findings.push_back(std::move(F));
        continue;
      }
      Expected<std::optional<ResolvedFunction>> Function =
          resolveTransitiveFunction(Target, Depth, *Object, *Symbols, Findings);
      if (!Function)
        return fail(toString(Function.takeError()));
      if (!*Function)
        continue;

      Counts.MaxCallDepthReached =
          std::max<uint64_t>(Counts.MaxCallDepthReached, Depth);
      std::vector<DiscoveredTarget> ChildTargets;
      if (Error E =
              scanRegion((*Function)->Region, *Configuration, *Symbols,
                         IndirectCalls, **State, Counts, Findings,
                         (*Function)->CallPath, (*Function)->CallPathAddresses,
                         (*Function)->CallPathCallsites, &ChildTargets,
                         /*IsTransitive=*/true))
        return fail(toString(std::move(E)));
      TransitiveFunctions.push_back(std::move(**Function));
      for (DiscoveredTarget &Child : ChildTargets)
        Schedule(std::move(Child));
    }
  }
  for (const auto &[Address, Rule] : IndirectCalls) {
    if (!Rule.Used)
      Findings.push_back(addressFinding(
          "unused-indirect-callsite", Rule.CallerSymbol, Address,
          "resolved callsite policy did not match an indirect call"));
  }

  json::Array JSONFindings;
  for (const Finding &F : Findings)
    JSONFindings.push_back(findingJSON(F));
  json::Array JSONSections;
  for (const std::string &Name : Configuration->EntrySections)
    JSONSections.push_back(Name);
  json::Array JSONSymbolRanges;
  for (const Policy::SymbolRange &Range : Configuration->EntrySymbolRanges)
    JSONSymbolRanges.push_back(json::Object{
        {"name", Range.Name},
        {"start_symbol", Range.StartSymbol},
        {"end_symbol", Range.EndSymbol},
    });
  json::Array JSONRegions;
  for (const ResolvedRegion &Region : Regions)
    JSONRegions.push_back(json::Object{
        {"name", Region.Name},
        {"source", Region.Source},
        {"section", Region.Section},
        {"begin_va", hex64(Region.Begin)},
        {"end_va", hex64(Region.End)},
        {"size", static_cast<int64_t>(Region.Bytes.size())},
    });
  json::Array JSONTransitiveFunctions;
  for (const ResolvedFunction &Function : TransitiveFunctions) {
    json::Array Aliases;
    for (const std::string &Name : Function.Aliases)
      Aliases.push_back(Name);
    json::Array Path;
    for (const std::string &Name : Function.CallPath)
      Path.push_back(Name);
    json::Array PathAddresses;
    for (uint64_t Address : Function.CallPathAddresses)
      PathAddresses.push_back(hex64(Address));
    json::Array PathCallsites;
    for (uint64_t Address : Function.CallPathCallsites)
      PathCallsites.push_back(hex64(Address));
    JSONTransitiveFunctions.push_back(json::Object{
        {"symbol", Function.Region.Name},
        {"aliases", std::move(Aliases)},
        {"source", Function.Region.Source},
        {"section", Function.Region.Section},
        {"begin_va", hex64(Function.Region.Begin)},
        {"end_va", hex64(Function.Region.End)},
        {"size", static_cast<int64_t>(Function.Region.Bytes.size())},
        {"reached_from_va", hex64(Function.ReachedFromAddress)},
        {"depth", static_cast<int64_t>(Function.Depth)},
        {"call_path", std::move(Path)},
        {"call_path_vas", std::move(PathAddresses)},
        {"call_path_callsites", std::move(PathCallsites)},
    });
  }
  json::Array JSONForbidden;
  for (const std::string &Name : Configuration->ForbiddenSymbols)
    JSONForbidden.push_back(Name);
  json::Array JSONIndirectPolicy;
  for (const Policy::IndirectCallTargets &Rule : Configuration->IndirectCalls) {
    json::Array Targets;
    for (const std::string &Name : Rule.TargetSymbols)
      Targets.push_back(Name);
    JSONIndirectPolicy.push_back(json::Object{
        {"caller_symbol", Rule.CallerSymbol},
        {"instruction_offset", static_cast<int64_t>(Rule.InstructionOffset)},
        {"target_symbols", std::move(Targets)},
    });
  }
  json::Array JSONResolvedIndirectCalls;
  for (const auto &[Address, Rule] : IndirectCalls) {
    json::Array Targets;
    for (size_t Index = 0; Index < Rule.TargetSymbols.size(); ++Index)
      Targets.push_back(json::Object{
          {"symbol", Rule.TargetSymbols[Index]},
          {"address", hex64(Rule.TargetAddresses[Index])},
      });
    JSONResolvedIndirectCalls.push_back(json::Object{
        {"caller_symbol", Rule.CallerSymbol},
        {"caller_begin_va", hex64(Rule.CallerAddress)},
        {"caller_end_va", hex64(Rule.CallerEnd)},
        {"instruction_offset", static_cast<int64_t>(Rule.InstructionOffset)},
        {"instruction_va", hex64(Address)},
        {"targets", std::move(Targets)},
        {"used", Rule.Used},
    });
  }

  json::Value JSONExpectedImage(nullptr);
  if (Configuration->HasExpectedImage) {
    JSONExpectedImage = json::Object{
        {"sha256", Configuration->ExpectedImageSHA256},
        {"build_id", Configuration->ExpectedBuildID
                         ? json::Value(*Configuration->ExpectedBuildID)
                         : json::Value(nullptr)},
    };
  }

  json::Object Image{
      {"path", InputFilename},
      {"sha256", ImageSHA256},
      {"build_id",
       ImageBuildID ? json::Value(*ImageBuildID) : json::Value(nullptr)},
      {"format", Object->getFileFormatName()},
      {"arch", "riscv64"},
      {"address_bits", 64},
      {"endianness", "little"},
  };
  json::Object PolicyJSON{
      {"schema", static_cast<int64_t>(Configuration->Schema)},
      {"path", PolicyFilename},
      {"sha256", Configuration->Hash},
      {"expected_image", std::move(JSONExpectedImage)},
      {"identity_bound", Configuration->HasExpectedImage},
      {"entry_sections", std::move(JSONSections)},
      {"entry_symbol_ranges", std::move(JSONSymbolRanges)},
      {"forbidden_symbols", std::move(JSONForbidden)},
      {"indirect_call_targets", std::move(JSONIndirectPolicy)},
      {"reject_unknown_calls", true},
  };
  json::Object CoverageJSON{
      {"regions", static_cast<int64_t>(Counts.Regions)},
      {"bytes", static_cast<int64_t>(Counts.Bytes)},
      {"instructions", static_cast<int64_t>(Counts.Instructions)},
      {"calls", static_cast<int64_t>(Counts.Calls)},
      {"resolved_calls", static_cast<int64_t>(Counts.ResolvedCalls)},
      {"unknown_calls", static_cast<int64_t>(Counts.UnknownCalls)},
      {"policy_resolved_indirect_calls",
       static_cast<int64_t>(Counts.PolicyResolvedIndirectCalls)},
      {"indirect_target_edges",
       static_cast<int64_t>(Counts.IndirectTargetEdges)},
  };
  if (Configuration->Schema >= 3) {
    CoverageJSON["root_regions"] = static_cast<int64_t>(Counts.RootRegions);
    CoverageJSON["transitive_functions"] =
        static_cast<int64_t>(Counts.TransitiveFunctions);
    CoverageJSON["max_call_depth_reached"] =
        static_cast<int64_t>(Counts.MaxCallDepthReached);
    CoverageJSON["function_limit"] =
        static_cast<int64_t>(MaxTransitiveFunctions);
    CoverageJSON["call_depth_limit"] = static_cast<int64_t>(MaxCallDepth);
  }
  bool Passed = Findings.empty();
  json::Object Root{
      {"schema", 1},
      {"checker", "rv-entrycheck"},
      {"scope", Configuration->Schema == 1 ? "direct-calls-in-entry-regions-v1"
                : Configuration->Schema == 2 ? "site-scoped-indirect-targets-v2"
                                             : "transitive-call-graph-v3"},
      {"result", Passed ? "PASS" : "FAIL"},
      {"image", std::move(Image)},
      {"policy", std::move(PolicyJSON)},
      {"resolved_regions", std::move(JSONRegions)},
      {"resolved_indirect_calls", std::move(JSONResolvedIndirectCalls)},
      {"coverage", std::move(CoverageJSON)},
      {"findings", std::move(JSONFindings)},
  };
  if (Configuration->Schema >= 3)
    Root["resolved_transitive_functions"] = std::move(JSONTransitiveFunctions);
  outs() << formatv(Compact ? "{0}\n" : "{0:2}\n",
                    json::Value(std::move(Root)));
  return Passed ? 0 : 1;
}
