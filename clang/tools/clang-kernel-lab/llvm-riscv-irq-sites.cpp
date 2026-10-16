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
#include <tuple>
#include <utility>
#include <vector>

using namespace llvm;
using namespace llvm::object;

namespace {

constexpr StringLiteral AssemblySectionName = ".riscv.linux_irq_sites";
constexpr StringLiteral CCarrierSectionName = ".riscv.linux_irq_c_sites";
constexpr StringLiteral ExpectedSectionName = ".riscv.linux_irq_expected";
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

enum class CarrierKind { Assembly, C };

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
  CarrierKind Carrier = CarrierKind::Assembly;
};

struct ExpectedSite {
  uint16_t Kind = 0;
  uint32_t Flags = 0;
  uint64_t IDLow = 0;
  uint64_t IDHigh = 0;
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
                                                 bool IsRelocatable,
                                                 CarrierKind Carrier) {
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
    Site S;
    S.Carrier = Carrier;
    uint8_t Version;
    uint8_t Size;
    if (Carrier == CarrierKind::Assembly) {
      Version = Data[0];
      Size = Data[1];
      S.Kind = support::endian::read16le(Data + 2);
      S.Flags = support::endian::read32le(Data + 4);
      S.Address = support::endian::read64le(Data + 8);
      S.IDLow = support::endian::read64le(Data + 16);
      S.IDHigh = support::endian::read64le(Data + 24);
    } else {
      int64_t Relative = static_cast<int64_t>(support::endian::read64le(Data));
      Version = Data[8];
      Size = Data[9];
      S.Kind = support::endian::read16le(Data + 10);
      S.Flags = support::endian::read32le(Data + 12);
      S.IDLow = support::endian::read64le(Data + 16);
      S.IDHigh = support::endian::read64le(Data + 24);
      if (!IsRelocatable) {
        if (SiteSection.getAddress() >
            std::numeric_limits<uint64_t>::max() - Offset)
          return createStringError(inconvertibleErrorCode(),
                                   "C carrier record address overflows");
        // PC-section expressions use address-width modular arithmetic.  A
        // non-allocated carrier has an address of zero, so a canonical
        // high-half kernel PC is encoded as a negative signed delta and must
        // wrap here.  The text-section and sized-function checks below still
        // reject a delta that does not resolve to a real instruction.
        S.Address =
            SiteSection.getAddress() + Offset + static_cast<uint64_t>(Relative);
      } else if (Relative != 0) {
        return createStringError(inconvertibleErrorCode(),
                                 "relocatable C carrier has nonzero PC data");
      }
    }

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
    if (Carrier == CarrierKind::Assembly && !(S.Flags & FlagAssembly))
      return createStringError(inconvertibleErrorCode(),
                               "assembly carrier contains a C site");
    if (Carrier == CarrierKind::C && !(S.Flags & FlagC))
      return createStringError(inconvertibleErrorCode(),
                               "C carrier contains an assembly site");
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

static Expected<SmallVector<ExpectedSite, 16>>
readExpectedSites(SectionRef Section) {
  constexpr size_t ExpectedRecordSize = 24;
  Expected<StringRef> ContentsOrError = Section.getContents();
  if (!ContentsOrError)
    return ContentsOrError.takeError();
  StringRef Contents = *ContentsOrError;
  if (Contents.size() > MaxSiteSectionBytes)
    return createStringError(inconvertibleErrorCode(),
                             "expected-site section exceeds 16 MiB");
  if (Contents.size() % ExpectedRecordSize)
    return createStringError(inconvertibleErrorCode(),
                             "expected-site section has a partial record");

  SmallVector<ExpectedSite, 16> Result;
  for (size_t Offset = 0; Offset < Contents.size();
       Offset += ExpectedRecordSize) {
    const auto *Data =
        reinterpret_cast<const uint8_t *>(Contents.data() + Offset);
    ExpectedSite E;
    E.Kind = support::endian::read16le(Data);
    uint16_t Reserved = support::endian::read16le(Data + 2);
    E.Flags = support::endian::read32le(Data + 4);
    E.IDLow = support::endian::read64le(Data + 8);
    E.IDHigh = support::endian::read64le(Data + 16);
    if (Reserved)
      return createStringError(inconvertibleErrorCode(),
                               "expected-site reserved field is nonzero");
    if (siteKindName(E.Kind).empty())
      return createStringError(inconvertibleErrorCode(),
                               "expected site has an unknown kind");
    if (E.Flags & ~KnownFlags)
      return createStringError(inconvertibleErrorCode(),
                               "expected site has unknown flags");
    uint32_t Boundary = FlagAfterPreviousRetire | FlagBeforeInsnAtSite;
    if ((E.Flags & Boundary) != Boundary || !(E.Flags & FlagC) ||
        (E.Flags & FlagAssembly))
      return createStringError(inconvertibleErrorCode(),
                               "expected site is not a C boundary");
    if (!E.IDLow && !E.IDHigh)
      return createStringError(inconvertibleErrorCode(),
                               "expected site has a zero identifier");
    Result.push_back(E);
  }
  return Result;
}

using SiteKey = std::tuple<uint64_t, uint64_t, uint16_t, uint32_t>;

static SiteKey key(uint64_t High, uint64_t Low, uint16_t Kind, uint32_t Flags) {
  return {High, Low, Kind, Flags};
}

static StringRef carrierName(CarrierKind Carrier) {
  return Carrier == CarrierKind::Assembly ? "assembly-record" : "pcsections";
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

static Error validateCRelocations(const ObjectFile &Object,
                                  SectionRef SiteSection,
                                  MutableArrayRef<Site> Sites) {
  struct RelocationPair {
    bool HasAdd = false;
    bool HasSub = false;
  };
  SmallVector<RelocationPair, 16> Seen(Sites.size());
  for (SectionRef Section : Object.sections()) {
    Expected<section_iterator> RelocatedOrError = Section.getRelocatedSection();
    if (!RelocatedOrError)
      return RelocatedOrError.takeError();
    section_iterator Relocated = *RelocatedOrError;
    if (Relocated == Object.section_end() || *Relocated != SiteSection)
      continue;

    for (RelocationRef Relocation : Section.relocations()) {
      uint64_t Offset = Relocation.getOffset();
      if (Offset % SiteRecordSize)
        return createStringError(
            inconvertibleErrorCode(),
            "unexpected C-carrier relocation at offset 0x%" PRIx64, Offset);
      size_t Index = static_cast<size_t>(Offset / SiteRecordSize);
      if (Index >= Sites.size())
        return createStringError(inconvertibleErrorCode(),
                                 "C-carrier relocation lies past its records");
      bool IsAdd = Relocation.getType() == ELF::R_RISCV_ADD64;
      bool IsSub = Relocation.getType() == ELF::R_RISCV_SUB64;
      if (!IsAdd && !IsSub)
        return createStringError(
            inconvertibleErrorCode(),
            "C carrier requires R_RISCV_ADD64/R_RISCV_SUB64, found %" PRIu64,
            Relocation.getType());
      if ((IsAdd && Seen[Index].HasAdd) || (IsSub && Seen[Index].HasSub))
        return createStringError(inconvertibleErrorCode(),
                                 "duplicate C-carrier PC relocation");

      Expected<int64_t> Addend = ELFRelocationRef(Relocation).getAddend();
      if (!Addend)
        return Addend.takeError();
      if (*Addend)
        return createStringError(inconvertibleErrorCode(),
                                 "C-carrier PC relocation has an addend");
      symbol_iterator SymbolIterator = Relocation.getSymbol();
      if (SymbolIterator == Object.symbol_end())
        return createStringError(inconvertibleErrorCode(),
                                 "C-carrier relocation has no symbol");
      SymbolRef Symbol = *SymbolIterator;
      Expected<uint64_t> Value = Symbol.getValue();
      if (!Value)
        return Value.takeError();
      Expected<section_iterator> SymbolSectionOrError = Symbol.getSection();
      if (!SymbolSectionOrError)
        return SymbolSectionOrError.takeError();
      section_iterator SymbolSection = *SymbolSectionOrError;
      if (SymbolSection == Object.section_end())
        return createStringError(inconvertibleErrorCode(),
                                 "C-carrier relocation symbol is undefined");
      Expected<StringRef> SymbolName = Symbol.getName();
      if (!SymbolName)
        return SymbolName.takeError();

      Site &S = Sites[Index];
      if (IsAdd) {
        if (!SymbolSection->isText())
          return createStringError(inconvertibleErrorCode(),
                                   "C-carrier ADD64 does not target text");
        uint64_t SectionAddress = SymbolSection->getAddress();
        if (*Value < SectionAddress ||
            *Value - SectionAddress >= SymbolSection->getSize())
          return createStringError(inconvertibleErrorCode(),
                                   "C-carrier ADD64 points outside text");
        Expected<StringRef> SectionName = SymbolSection->getName();
        if (!SectionName)
          return SectionName.takeError();
        S.TextSection = SectionName->str();
        S.TextSectionOffset = *Value - SectionAddress;
        S.RelocationSymbol = SymbolName->str();
        Seen[Index].HasAdd = true;
      } else {
        if (*SymbolSection != SiteSection || *Value != Offset)
          return createStringError(
              inconvertibleErrorCode(),
              "C-carrier SUB64 does not reference its own record base");
        Seen[Index].HasSub = true;
      }
      S.RelocationType = "R_RISCV_ADD64+R_RISCV_SUB64";
    }
  }

  for (const RelocationPair &Pair : Seen)
    if (!Pair.HasAdd || !Pair.HasSub)
      return createStringError(
          inconvertibleErrorCode(),
          "C-carrier PC lacks an ADD64/SUB64 relocation pair");
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

  SmallVector<std::pair<SectionRef, CarrierKind>, 4> SiteSections;
  SmallVector<SectionRef, 2> ExpectedSections;
  for (SectionRef Section : Object->sections()) {
    Expected<StringRef> Name = Section.getName();
    if (!Name)
      return fail(toString(Name.takeError()));
    if (*Name == AssemblySectionName)
      SiteSections.push_back({Section, CarrierKind::Assembly});
    else if (*Name == CCarrierSectionName)
      SiteSections.push_back({Section, CarrierKind::C});
    else if (*Name == ExpectedSectionName)
      ExpectedSections.push_back(Section);
  }
  if (SiteSections.empty())
    return fail(Twine("image lacks ") + AssemblySectionName + " and " +
                CCarrierSectionName);

  SmallVector<Site, 32> Sites;
  std::set<std::pair<uint64_t, uint64_t>> IDs;
  std::set<SiteKey> ActualCSites;
  SHA256 CombinedSectionHash;
  json::Array JSONSections;
  for (const auto &[Section, Carrier] : SiteSections) {
    Expected<StringRef> Name = Section.getName();
    if (!Name)
      return fail(toString(Name.takeError()));
    Expected<StringRef> Bytes = Section.getContents();
    if (!Bytes)
      return fail(toString(Bytes.takeError()));
    CombinedSectionHash.update(*Name);
    CombinedSectionHash.update(StringRef("\0", 1));
    CombinedSectionHash.update(*Bytes);
    JSONSections.push_back(json::Object{
        {"name", *Name},
        {"role", Carrier == CarrierKind::Assembly ? "site-records"
                                                  : "pcsections-carrier"},
        {"size", static_cast<int64_t>(Bytes->size())},
        {"sha256", sha256(*Bytes)},
    });

    Expected<SmallVector<Site, 16>> Parsed =
        readSites(*Object, Section, IsRelocatable, Carrier);
    if (!Parsed)
      return fail(toString(Parsed.takeError()));
    if (IsRelocatable) {
      Error Validation = Carrier == CarrierKind::Assembly
                             ? validateRelocations(*Object, Section, *Parsed)
                             : validateCRelocations(*Object, Section, *Parsed);
      if (Validation)
        return fail(toString(std::move(Validation)));
    }
    for (Site &S : *Parsed) {
      if (!IDs.insert({S.IDHigh, S.IDLow}).second)
        return fail("duplicate site identifier across carrier sections");
      if (S.Carrier == CarrierKind::C)
        ActualCSites.insert(key(S.IDHigh, S.IDLow, S.Kind, S.Flags));
      Sites.push_back(std::move(S));
    }
  }
  if (Sites.empty())
    return fail("IRQ site section contains no records");

  std::set<SiteKey> ExpectedCSites;
  for (SectionRef Section : ExpectedSections) {
    Expected<StringRef> Bytes = Section.getContents();
    if (!Bytes)
      return fail(toString(Bytes.takeError()));
    CombinedSectionHash.update(ExpectedSectionName);
    CombinedSectionHash.update(StringRef("\0", 1));
    CombinedSectionHash.update(*Bytes);
    JSONSections.push_back(json::Object{
        {"name", ExpectedSectionName},
        {"role", "expected-c-sites"},
        {"size", static_cast<int64_t>(Bytes->size())},
        {"sha256", sha256(*Bytes)},
    });
    Expected<SmallVector<ExpectedSite, 16>> Parsed = readExpectedSites(Section);
    if (!Parsed)
      return fail(toString(Parsed.takeError()));
    for (const ExpectedSite &E : *Parsed)
      if (!ExpectedCSites.insert(key(E.IDHigh, E.IDLow, E.Kind, E.Flags))
               .second)
        return fail("duplicate identifier in expected C-site table");
  }
  if (ActualCSites != ExpectedCSites)
    return fail(Twine("C carrier/expectation mismatch: emitted ") +
                Twine(ActualCSites.size()) + ", expected " +
                Twine(ExpectedCSites.size()));

  for (const Site &S : Sites)
    if (!IsRelocatable &&
        LoadBias > std::numeric_limits<uint64_t>::max() - S.Address)
      return fail("load bias overflows a runtime site address");

  std::string CombinedHash =
      toHex(CombinedSectionHash.final(), /*LowerCase=*/true);
  BuildIDRef ID = getBuildID(Object.get());

  json::Array JSONSites;
  for (const Site &S : Sites) {
    json::Object JSONSite{
        {"site_id", siteID(S.IDHigh, S.IDLow)}, {"kind", S.Kind},
        {"kind_name", siteKindName(S.Kind)},    {"flags", S.Flags},
        {"carrier", carrierName(S.Carrier)},    {"text_section", S.TextSection},
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
      {"site_section_sha256", CombinedHash},
      {"site_sections", std::move(JSONSections)},
      {"image", std::move(Image)},
      {"sites", std::move(JSONSites)},
  };
  outs() << formatv(Compact ? "{0}\n" : "{0:2}\n",
                    json::Value(std::move(Root)));
  return 0;
}
