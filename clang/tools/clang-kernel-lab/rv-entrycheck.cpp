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

cl::opt<std::string> InputFilename(cl::Positional, cl::Required,
                                   cl::desc("<linked-rv64-elf>"));
cl::opt<std::string>
    PolicyFilename("policy", cl::Required,
                   cl::desc("Version-one entry-check policy in JSON format"));
cl::opt<bool> Compact("compact", cl::init(false),
                      cl::desc("Write compact rather than indented JSON"));

struct Policy {
  struct SymbolRange {
    std::string Name;
    std::string StartSymbol;
    std::string EndSymbol;
  };

  std::vector<std::string> EntrySections;
  std::vector<SymbolRange> EntrySymbolRanges;
  std::set<std::string> ForbiddenSymbols;
  std::string Hash;
};

struct SymbolTables {
  std::map<uint64_t, std::vector<std::string>> FunctionsByAddress;
  std::map<uint64_t, std::vector<std::string>> NamesByAddress;
  std::map<std::string, std::vector<uint64_t>> AddressesByName;
};

struct ResolvedRegion {
  std::string Name;
  std::string Source;
  std::string Section;
  uint64_t Begin = 0;
  uint64_t End = 0;
  StringRef Bytes;
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
};

struct Coverage {
  uint64_t Regions = 0;
  uint64_t Bytes = 0;
  uint64_t Instructions = 0;
  uint64_t Calls = 0;
  uint64_t ResolvedCalls = 0;
  uint64_t UnknownCalls = 0;
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

static Expected<Policy> parsePolicy(StringRef Path) {
  ErrorOr<std::unique_ptr<MemoryBuffer>> Buffer =
      MemoryBuffer::getFile(Path, /*IsText=*/true);
  if (!Buffer)
    return entryError(Twine("cannot read policy '") + Path +
                      "': " + Buffer.getError().message());
  if ((*Buffer)->getBufferSize() > MaxPolicyBytes)
    return entryError("policy exceeds the 1 MiB input limit");

  StringRef Text = (*Buffer)->getBuffer();
  Expected<json::Value> Parsed = json::parse(Text);
  if (!Parsed)
    return entryError(Twine("invalid policy JSON: ") +
                      toString(Parsed.takeError()));
  const json::Object *Root = Parsed->getAsObject();
  if (!Root)
    return entryError("top-level policy must be an object");
  if (Error E =
          rejectUnknownKeys(*Root, {"schema", "architecture", "entry_sections",
                                    "entry_symbol_ranges", "forbidden_symbols",
                                    "reject_unknown_calls"}))
    return std::move(E);
  if (Root->getInteger("schema") != 1)
    return entryError("unsupported or missing policy schema; expected 1");
  std::optional<StringRef> Architecture = Root->getString("architecture");
  if (!Architecture || *Architecture != "riscv64")
    return entryError("policy architecture must be 'riscv64'");
  if (Root->getBoolean("reject_unknown_calls") != true)
    return entryError("version-one policy requires reject_unknown_calls=true");

  const json::Array *EntrySections = Root->getArray("entry_sections");
  const json::Array *EntrySymbolRanges = Root->getArray("entry_symbol_ranges");
  if (Root->get("entry_sections") && !EntrySections)
    return entryError("entry_sections must be an array");
  if (Root->get("entry_symbol_ranges") && !EntrySymbolRanges)
    return entryError("entry_symbol_ranges must be an array");
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
  const json::Array *Forbidden = Root->getArray("forbidden_symbols");
  if (!Forbidden || Forbidden->empty() || Forbidden->size() > 4096)
    return entryError("forbidden_symbols must contain 1 through 4096 names");

  Policy Result;
  Result.Hash = sha256(Text);
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
  for (auto &[Name, Addresses] : Symbols.AddressesByName) {
    (void)Name;
    llvm::sort(Addresses);
    Addresses.erase(std::unique(Addresses.begin(), Addresses.end()),
                    Addresses.end());
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

static Error scanRegion(const ResolvedRegion &Region,
                        const Policy &Configuration,
                        const SymbolTables &Symbols, DisassemblyState &State,
                        Coverage &Counts, std::vector<Finding> &Findings) {
  if (Region.Bytes.empty()) {
    Findings.push_back(addressFinding("empty-entry-region", Region.Name,
                                      Region.Begin,
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
    Findings.push_back(
        addressFinding("misaligned-entry-region", Region.Name, Region.Begin,
                       "RISC-V entry boundaries must be two-byte aligned"));
    return Error::success();
  }

  ArrayRef<uint8_t> Bytes(
      reinterpret_cast<const uint8_t *>(Region.Bytes.data()),
      Region.Bytes.size());
  State.InstrAnalysis->resetState();
  ++Counts.Regions;
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
      Findings.push_back(
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
      if (TargetKnown && ForbiddenName) {
        ++Counts.ResolvedCalls;
        Finding F =
            addressFinding("forbidden-call", Region.Name, InstructionAddress,
                           "entry region directly calls a forbidden callback");
        F.TargetAddress = TargetAddress;
        F.HasTargetAddress = true;
        F.TargetSymbols = Names->second;
        F.MatchedSymbol = ForbiddenName->str();
        Findings.push_back(std::move(F));
      } else if (!TargetKnown || Function == Symbols.FunctionsByAddress.end()) {
        ++Counts.UnknownCalls;
        Finding F = addressFinding(
            "unknown-call", Region.Name, InstructionAddress,
            TargetKnown ? "direct call target has no defined symbol"
                        : "call target cannot be resolved statically");
        if (TargetKnown) {
          F.TargetAddress = TargetAddress;
          F.HasTargetAddress = true;
          if (Names != Symbols.NamesByAddress.end())
            F.TargetSymbols = Names->second;
        }
        Findings.push_back(std::move(F));
      } else {
        ++Counts.ResolvedCalls;
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
  return Result;
}

} // namespace

int main(int Argc, char **Argv) {
  InitLLVM Initialize(Argc, Argv);
  cl::ParseCommandLineOptions(
      Argc, Argv,
      "Conservatively audit direct calls in RISC-V Linux entry regions\n");

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
    return fail("version one requires an RV64 ELF image");
  if (!Object->isLittleEndian())
    return fail("version one requires a little-endian ELF image");
  if (Object->isRelocatableObject())
    return fail("entry checking requires a linked ELF image");

  Expected<SymbolTables> Symbols = readDefinedSymbols(*Object);
  if (!Symbols)
    return fail(toString(Symbols.takeError()));
  Expected<std::unique_ptr<DisassemblyState>> State =
      createDisassembly(*Object);
  if (!State)
    return fail(toString(State.takeError()));

  Coverage Counts;
  std::vector<Finding> Findings;
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
  for (const ResolvedRegion &Region : Regions) {
    if (Error E = scanRegion(Region, *Configuration, *Symbols, **State, Counts,
                             Findings))
      return fail(toString(std::move(E)));
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
  json::Array JSONForbidden;
  for (const std::string &Name : Configuration->ForbiddenSymbols)
    JSONForbidden.push_back(Name);

  BuildIDRef BuildID = getBuildID(Object.get());
  json::Object Image{
      {"path", InputFilename},
      {"sha256", sha256((*Buffer)->getBuffer())},
      {"build_id", BuildID.empty()
                       ? json::Value(nullptr)
                       : json::Value(toHex(BuildID, /*LowerCase=*/true))},
      {"format", Object->getFileFormatName()},
      {"arch", "riscv64"},
      {"address_bits", 64},
      {"endianness", "little"},
  };
  json::Object PolicyJSON{
      {"path", PolicyFilename},
      {"sha256", Configuration->Hash},
      {"entry_sections", std::move(JSONSections)},
      {"entry_symbol_ranges", std::move(JSONSymbolRanges)},
      {"forbidden_symbols", std::move(JSONForbidden)},
      {"reject_unknown_calls", true},
  };
  json::Object CoverageJSON{
      {"regions", static_cast<int64_t>(Counts.Regions)},
      {"bytes", static_cast<int64_t>(Counts.Bytes)},
      {"instructions", static_cast<int64_t>(Counts.Instructions)},
      {"calls", static_cast<int64_t>(Counts.Calls)},
      {"resolved_calls", static_cast<int64_t>(Counts.ResolvedCalls)},
      {"unknown_calls", static_cast<int64_t>(Counts.UnknownCalls)},
  };
  bool Passed = Findings.empty();
  json::Object Root{
      {"schema", 1},
      {"checker", "rv-entrycheck"},
      {"scope", "direct-calls-in-entry-regions-v1"},
      {"result", Passed ? "PASS" : "FAIL"},
      {"image", std::move(Image)},
      {"policy", std::move(PolicyJSON)},
      {"resolved_regions", std::move(JSONRegions)},
      {"coverage", std::move(CoverageJSON)},
      {"findings", std::move(JSONFindings)},
  };
  outs() << formatv(Compact ? "{0}\n" : "{0:2}\n",
                    json::Value(std::move(Root)));
  return Passed ? 0 : 1;
}
