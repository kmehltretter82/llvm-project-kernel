//===- llvm-riscv-irq-sites.cpp - Emit a Linux IRQ site sidecar -----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Object/BuildID.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"

#include <cinttypes>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>

using namespace llvm;
using namespace llvm::object;

namespace {

constexpr StringLiteral SiteSectionName = ".riscv.linux_irq_sites";
constexpr StringLiteral TriggerPhase =
    "AFTER_PREVIOUS_RETIRE/BEFORE_INSN_AT_SITE";
constexpr uint8_t SiteVersion = 1;
constexpr uint8_t SiteRecordSize = 32;
constexpr uint32_t FlagAfterPreviousRetire = 1U << 0;
constexpr uint32_t FlagBeforeInsnAtSite = 1U << 1;
constexpr uint32_t FlagAssembly = 1U << 2;
constexpr uint32_t FlagC = 1U << 3;
constexpr uint32_t KnownFlags = (1U << 6) - 1;
constexpr uint64_t MaxSiteSectionBytes = 16 * 1024 * 1024;

static StringRef siteKindName(uint16_t Kind) {
  switch (Kind) {
#define KLAB_IRQ_SITE_KIND(Name, Value, Text)                                  \
  case Value:                                                                  \
    return Text;
#include "clang/Basic/LinuxKernelIRQSiteKinds.def"
#undef KLAB_IRQ_SITE_KIND
  }
  return {};
}

cl::opt<std::string> InputFilename(cl::Positional, cl::Required,
                                   cl::desc("<linked-rv64-elf>"));
cl::opt<uint64_t>
    LoadBias("load-bias", cl::init(0),
             cl::desc("Add this load bias to linked site virtual addresses"));
cl::opt<bool> Compact("compact", cl::init(false),
                      cl::desc("Write compact rather than indented JSON"));
cl::opt<bool> ValidateRelocatable(
    "validate-relocatable", cl::init(false),
    cl::desc("Validate an RV64 relocatable object's site records instead of "
             "emitting a linked-image sidecar"));

struct Site {
  uint16_t Kind = 0;
  uint32_t Flags = 0;
  uint64_t Address = 0;
  uint64_t IDLow = 0;
  uint64_t IDHigh = 0;
  std::string TextSection;
  uint64_t TextSectionOffset = 0;
  std::string ContainingSymbol;
  uint64_t SymbolOffset = 0;
  std::string RelocationType;
  std::string RelocationSymbol;
};

static int fail(const Twine &Message) {
  WithColor::error(errs(), "llvm-riscv-irq-sites") << Message << '\n';
  return 1;
}

static std::string hex64(uint64_t Value) {
  std::string Result;
  raw_string_ostream OS(Result);
  OS << format_hex(Value, 18, /*Upper=*/false);
  return Result;
}

static std::string siteID(uint64_t High, uint64_t Low) {
  std::string Result;
  raw_string_ostream OS(Result);
  OS << format_hex_no_prefix(High, 16, /*Upper=*/false)
     << format_hex_no_prefix(Low, 16, /*Upper=*/false);
  return Result;
}

static std::string sha256(StringRef Bytes) {
  SHA256 Hasher;
  Hasher.update(Bytes);
  return toHex(Hasher.final(), /*LowerCase=*/true);
}

static Expected<std::string> containingTextSection(const ObjectFile &Object,
                                                   uint64_t Address) {
  std::optional<std::string> Match;
  for (SectionRef Section : Object.sections()) {
    if (!Section.isText())
      continue;
    uint64_t Begin = Section.getAddress();
    uint64_t Size = Section.getSize();
    if (Address < Begin || Address - Begin >= Size)
      continue;
    Expected<StringRef> Name = Section.getName();
    if (!Name)
      return Name.takeError();
    if (Match)
      return createStringError(
          inconvertibleErrorCode(),
          "site address belongs to multiple text sections");
    Match = Name->str();
  }
  if (!Match)
    return createStringError(inconvertibleErrorCode(),
                             "site address is outside executable text");
  return *Match;
}

static Expected<std::pair<std::string, uint64_t>>
containingFunction(const ObjectFile &Object, uint64_t Address) {
  std::optional<std::pair<std::string, uint64_t>> Best;
  uint64_t BestSize = std::numeric_limits<uint64_t>::max();
  for (SymbolRef Symbol : Object.symbols()) {
    Expected<SymbolRef::Type> Type = Symbol.getType();
    if (!Type)
      return Type.takeError();
    if (*Type != SymbolRef::ST_Function)
      continue;
    Expected<uint64_t> Begin = Symbol.getAddress();
    if (!Begin)
      return Begin.takeError();
    uint64_t Size = ELFSymbolRef(Symbol).getSize();
    if (!Size || Address < *Begin || Address - *Begin >= Size)
      continue;
    Expected<StringRef> Name = Symbol.getName();
    if (!Name)
      return Name.takeError();
    if (Size > BestSize ||
        (Size == BestSize && Best && Name->str() >= Best->first))
      continue;
    Best = std::make_pair(Name->str(), Address - *Begin);
    BestSize = Size;
  }
  if (!Best)
    return createStringError(inconvertibleErrorCode(),
                             "site address is outside every sized function");
  return *Best;
}

static Expected<SmallVector<Site, 16>> readSites(const ObjectFile &Object,
                                                 SectionRef SiteSection,
                                                 bool IsRelocatable) {
  Expected<StringRef> ContentsOrError = SiteSection.getContents();
  if (!ContentsOrError)
    return ContentsOrError.takeError();
  StringRef Contents = *ContentsOrError;
  if (Contents.size() > MaxSiteSectionBytes)
    return createStringError(inconvertibleErrorCode(),
                             "site section exceeds the 16 MiB limit");
  if (Contents.size() % SiteRecordSize)
    return createStringError(inconvertibleErrorCode(),
                             "site section ends with a partial record");

  SmallVector<Site, 16> Sites;
  std::set<std::pair<uint64_t, uint64_t>> IDs;
  for (size_t Offset = 0; Offset < Contents.size(); Offset += SiteRecordSize) {
    const auto *Data =
        reinterpret_cast<const uint8_t *>(Contents.data() + Offset);
    uint8_t Version = Data[0];
    uint8_t Size = Data[1];
    Site S;
    S.Kind = support::endian::read16le(Data + 2);
    S.Flags = support::endian::read32le(Data + 4);
    S.Address = support::endian::read64le(Data + 8);
    S.IDLow = support::endian::read64le(Data + 16);
    S.IDHigh = support::endian::read64le(Data + 24);

    if (Version != SiteVersion)
      return createStringError(inconvertibleErrorCode(),
                               "unsupported site record version");
    if (Size != SiteRecordSize)
      return createStringError(inconvertibleErrorCode(),
                               "unexpected site record size");
    if (siteKindName(S.Kind).empty())
      return createStringError(inconvertibleErrorCode(),
                               "unknown version-one site kind");
    if (S.Flags & ~KnownFlags)
      return createStringError(inconvertibleErrorCode(),
                               "site uses unknown version-one flags");
    uint32_t Boundary = FlagAfterPreviousRetire | FlagBeforeInsnAtSite;
    if ((S.Flags & Boundary) != Boundary)
      return createStringError(inconvertibleErrorCode(),
                               "site lacks the mandatory trigger boundary");
    if (static_cast<bool>(S.Flags & FlagAssembly) ==
        static_cast<bool>(S.Flags & FlagC))
      return createStringError(
          inconvertibleErrorCode(),
          "site must identify exactly one source language");
    if (!S.IDLow && !S.IDHigh)
      return createStringError(inconvertibleErrorCode(),
                               "zero site identifier is invalid");
    if (!IDs.insert({S.IDHigh, S.IDLow}).second)
      return createStringError(inconvertibleErrorCode(),
                               "duplicate site identifier");
    if (!IsRelocatable) {
      Expected<std::string> TextSection =
          containingTextSection(Object, S.Address);
      if (!TextSection)
        return joinErrors(
            TextSection.takeError(),
            createStringError(inconvertibleErrorCode(),
                              " while validating site at record offset 0x%x",
                              static_cast<unsigned>(Offset)));
      S.TextSection = std::move(*TextSection);
      Expected<std::pair<std::string, uint64_t>> Function =
          containingFunction(Object, S.Address);
      if (!Function)
        return joinErrors(
            Function.takeError(),
            createStringError(inconvertibleErrorCode(),
                              " while finding the function for site at "
                              "record offset 0x%x",
                              static_cast<unsigned>(Offset)));
      S.ContainingSymbol = std::move(Function->first);
      S.SymbolOffset = Function->second;
    }
    Sites.push_back(std::move(S));
  }
  return Sites;
}

static Expected<uint64_t> addSigned(uint64_t Value, int64_t Addend) {
  if (Addend >= 0) {
    uint64_t Positive = static_cast<uint64_t>(Addend);
    if (Value > std::numeric_limits<uint64_t>::max() - Positive)
      return createStringError(inconvertibleErrorCode(),
                               "relocation value overflows uint64");
    return Value + Positive;
  }
  uint64_t Magnitude = static_cast<uint64_t>(-(Addend + 1)) + 1;
  if (Value < Magnitude)
    return createStringError(inconvertibleErrorCode(),
                             "relocation value underflows uint64");
  return Value - Magnitude;
}

static Error validateRelocations(const ObjectFile &Object,
                                 SectionRef SiteSection,
                                 MutableArrayRef<Site> Sites) {
  SmallVector<bool, 16> Seen(Sites.size(), false);
  for (SectionRef Section : Object.sections()) {
    Expected<section_iterator> RelocatedOrError = Section.getRelocatedSection();
    if (!RelocatedOrError)
      return RelocatedOrError.takeError();
    section_iterator Relocated = *RelocatedOrError;
    if (Relocated == Object.section_end() || *Relocated != SiteSection)
      continue;

    for (RelocationRef Relocation : Section.relocations()) {
      uint64_t Offset = Relocation.getOffset();
      if (Offset < 8 || (Offset - 8) % SiteRecordSize)
        return createStringError(
            inconvertibleErrorCode(),
            "unexpected relocation at site-section offset 0x%" PRIx64, Offset);
      size_t Index = static_cast<size_t>((Offset - 8) / SiteRecordSize);
      if (Index >= Sites.size())
        return createStringError(
            inconvertibleErrorCode(),
            "relocation lies beyond the site-section records");
      if (Seen[Index])
        return createStringError(
            inconvertibleErrorCode(),
            "multiple relocations target one site address field");
      if (Relocation.getType() != ELF::R_RISCV_64)
        return createStringError(
            inconvertibleErrorCode(),
            "site address requires R_RISCV_64, found relocation type %" PRIu64,
            Relocation.getType());
      if (Sites[Index].Address != 0)
        return createStringError(
            inconvertibleErrorCode(),
            "R_RISCV_64 site address field has a nonzero encoded value");

      Expected<int64_t> Addend = ELFRelocationRef(Relocation).getAddend();
      if (!Addend)
        return Addend.takeError();
      symbol_iterator SymbolIterator = Relocation.getSymbol();
      if (SymbolIterator == Object.symbol_end())
        return createStringError(inconvertibleErrorCode(),
                                 "site relocation has no symbol");
      SymbolRef Symbol = *SymbolIterator;
      Expected<uint64_t> SymbolValue = Symbol.getValue();
      if (!SymbolValue)
        return SymbolValue.takeError();
      Expected<section_iterator> SymbolSectionOrError = Symbol.getSection();
      if (!SymbolSectionOrError)
        return SymbolSectionOrError.takeError();
      section_iterator SymbolSection = *SymbolSectionOrError;
      if (SymbolSection == Object.section_end() || !SymbolSection->isText())
        return createStringError(inconvertibleErrorCode(),
                                 "site relocation does not target text");

      Expected<uint64_t> Resolved = addSigned(*SymbolValue, *Addend);
      if (!Resolved)
        return Resolved.takeError();
      uint64_t SectionAddress = SymbolSection->getAddress();
      if (*Resolved < SectionAddress ||
          *Resolved - SectionAddress >= SymbolSection->getSize())
        return createStringError(inconvertibleErrorCode(),
                                 "site relocation points outside text");

      Expected<StringRef> SectionName = SymbolSection->getName();
      if (!SectionName)
        return SectionName.takeError();
      Expected<StringRef> SymbolName = Symbol.getName();
      if (!SymbolName)
        return SymbolName.takeError();
      SmallVector<char, 24> TypeName;
      Relocation.getTypeName(TypeName);

      Site &S = Sites[Index];
      S.TextSection = SectionName->str();
      S.TextSectionOffset = *Resolved - SectionAddress;
      S.RelocationType = StringRef(TypeName.data(), TypeName.size()).str();
      S.RelocationSymbol = SymbolName->str();
      Seen[Index] = true;
    }
  }

  for (bool Present : Seen)
    if (!Present)
      return createStringError(inconvertibleErrorCode(),
                               "site address field lacks an R_RISCV_64 "
                               "relocation");
  return Error::success();
}

} // namespace

int main(int Argc, char **Argv) {
  InitLLVM Initialize(Argc, Argv);
  cl::ParseCommandLineOptions(
      Argc, Argv, "Emit a validated RISC-V Linux IRQ site-map sidecar\n");

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
    return fail("input is not an ELF object");
  if (Object->getArch() != Triple::riscv64 || Object->getBytesInAddress() != 8)
    return fail("version one requires an RV64 ELF object");
  if (!Object->isLittleEndian())
    return fail("version one requires a little-endian ELF object");
  bool IsRelocatable = Object->isRelocatableObject();
  if (IsRelocatable != ValidateRelocatable)
    return fail(ValidateRelocatable
                    ? "--validate-relocatable requires a relocatable ELF"
                    : "linked-image mode requires a linked ELF with resolved "
                      "sites");
  if (IsRelocatable && LoadBias)
    return fail("--load-bias is invalid with --validate-relocatable");

  std::optional<SectionRef> SiteSection;
  for (SectionRef Section : Object->sections()) {
    Expected<StringRef> Name = Section.getName();
    if (!Name)
      return fail(toString(Name.takeError()));
    if (*Name != SiteSectionName)
      continue;
    if (SiteSection)
      return fail("linked image contains multiple IRQ site sections");
    SiteSection = Section;
  }
  if (!SiteSection)
    return fail(Twine("linked image lacks ") + SiteSectionName);

  Expected<SmallVector<Site, 16>> SitesOrError =
      readSites(*Object, *SiteSection, IsRelocatable);
  if (!SitesOrError)
    return fail(toString(SitesOrError.takeError()));
  if (SitesOrError->empty())
    return fail("IRQ site section contains no records");
  if (IsRelocatable) {
    if (Error Validation =
            validateRelocations(*Object, *SiteSection, *SitesOrError))
      return fail(toString(std::move(Validation)));
  } else {
    for (const Site &S : *SitesOrError)
      if (LoadBias > std::numeric_limits<uint64_t>::max() - S.Address)
        return fail("load bias overflows a runtime site address");
  }

  Expected<StringRef> SiteBytes = SiteSection->getContents();
  if (!SiteBytes)
    return fail(toString(SiteBytes.takeError()));
  BuildIDRef ID = getBuildID(Object.get());

  json::Array JSONSites;
  for (const Site &S : *SitesOrError) {
    json::Object JSONSite{
        {"site_id", siteID(S.IDHigh, S.IDLow)}, {"kind", S.Kind},
        {"kind_name", siteKindName(S.Kind)},    {"flags", S.Flags},
        {"text_section", S.TextSection},
    };
    if (IsRelocatable) {
      JSONSite["text_section_offset"] = hex64(S.TextSectionOffset);
      JSONSite["relocation_type"] = S.RelocationType;
      JSONSite["relocation_symbol"] = S.RelocationSymbol;
    } else {
      JSONSite["link_va"] = hex64(S.Address);
      JSONSite["runtime_va"] = hex64(S.Address + LoadBias);
      JSONSite["symbol"] = S.ContainingSymbol;
      JSONSite["symbol_offset"] = hex64(S.SymbolOffset);
    }
    JSONSites.push_back(std::move(JSONSite));
  }

  json::Object Image{
      {"path", InputFilename},
      {"sha256", sha256((*Buffer)->getBuffer())},
      {"format", Object->getFileFormatName()},
      {"arch", Triple::getArchTypeName(Object->getArch())},
      {"address_bits", static_cast<int64_t>(Object->getBytesInAddress() * 8)},
      {"endianness", "little"},
  };
  if (IsRelocatable) {
    Image["build_id"] = nullptr;
    Image["load_bias"] = nullptr;
  } else {
    Image["build_id"] = ID.empty() ? json::Value(nullptr)
                                   : json::Value(toHex(ID, /*LowerCase=*/true));
    Image["load_bias"] = hex64(LoadBias);
  }
  json::Object Root{
      {"schema", 1},
      {"artifact_kind", IsRelocatable ? "relocatable-object" : "linked-image"},
      {"record_format", 1},
      {"record_size", SiteRecordSize},
      {"trigger_phase", TriggerPhase},
      {"default_hit_count_scope", "per-vcpu"},
      {"site_section_sha256", sha256(*SiteBytes)},
      {"image", std::move(Image)},
      {"sites", std::move(JSONSites)},
  };
  outs() << formatv(Compact ? "{0}\n" : "{0:2}\n",
                    json::Value(std::move(Root)));
  return 0;
}
