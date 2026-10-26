//===- QEMUReentrancyGuardChecker.cpp --------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Consume a sealed QEMU cross-entry summary and check that the same device
// owner's MemReentrancyGuard is engaged when a summarized publication path is
// entered.  The producer is responsible for proving the otherwise invisible
// callback -> publication -> self-MMIO -> destructive handler -> resumed-use
// edges.  This checker deliberately emits nothing for incomplete summaries.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DynamicRecursiveASTVisitor.h"
#include "clang/AST/Type.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

using namespace clang;
using namespace ento;

namespace clang::ento {
void registerQEMUReentrancyGuardChecker(CheckerManager &Mgr);
bool shouldRegisterQEMUReentrancyGuardChecker(const CheckerManager &Mgr);
} // namespace clang::ento

namespace {

static constexpr llvm::StringLiteral RuleID =
    "qemu.reentrant-self-mmio-publication";

struct FunctionSpec {
  std::string Name;
  std::string ReturnType;
  llvm::SmallVector<std::string, 4> Parameters;
};

enum class GuardMode { DirectField, HelperFunctions };

struct ReentrancyProtocol {
  std::string ID;
  std::string SourcePath;
  std::string SourceSHA256;
  uint64_t SourceBytes = 0;
  FunctionSpec Entry;
  FunctionSpec PublicationWrapper;
  unsigned OwnerArgument = 0;
  llvm::SmallVector<std::string, 4> OwnerMemberPath;
  std::string GuardRecord;
  std::string GuardField;
  GuardMode Mode = GuardMode::DirectField;
  std::optional<std::string> EngageFunctionName;
  std::optional<std::string> RestoreFunctionName;
  std::string EvidenceSHA256;

  const FunctionDecl *EntryDecl = nullptr;
  const FunctionDecl *PublicationWrapperDecl = nullptr;
  const FunctionDecl *EngageDecl = nullptr;
  const FunctionDecl *RestoreDecl = nullptr;
  const FieldDecl *GuardFieldDecl = nullptr;
  bool Resolved = false;
};

static bool isLowerHexSHA256(StringRef Value) {
  if (Value.size() != 64)
    return false;
  return std::all_of(Value.begin(), Value.end(), [](char C) {
    return (C >= '0' && C <= '9') || (C >= 'a' && C <= 'f');
  });
}

static std::string normalizeType(StringRef Type) {
  std::string Result;
  Result.reserve(Type.size());
  for (size_t I = 0; I != Type.size();) {
    if (llvm::isSpace(Type[I])) {
      ++I;
      continue;
    }
    if (Type.substr(I).starts_with("_Bool")) {
      size_t End = I + StringRef("_Bool").size();
      bool BeginsToken =
          I == 0 || (!llvm::isAlnum(Type[I - 1]) && Type[I - 1] != '_');
      bool EndsToken =
          End == Type.size() || (!llvm::isAlnum(Type[End]) && Type[End] != '_');
      if (BeginsToken && EndsToken) {
        Result += "bool";
        I = End;
        continue;
      }
    }
    Result.push_back(Type[I++]);
  }
  return Result;
}

static bool signatureMatches(const FunctionDecl *FD, const FunctionSpec &Spec) {
  if (!FD || !FD->getIdentifier() || FD->getName() != Spec.Name ||
      FD->isVariadic() || FD->getNumParams() != Spec.Parameters.size() ||
      normalizeType(FD->getReturnType().getAsString()) !=
          normalizeType(Spec.ReturnType))
    return false;
  for (unsigned I = 0; I != Spec.Parameters.size(); ++I)
    if (normalizeType(FD->getParamDecl(I)->getType().getAsString()) !=
        normalizeType(Spec.Parameters[I]))
      return false;
  return true;
}

static std::optional<FunctionSpec>
parseFunctionSpec(const llvm::json::Object *Object) {
  if (!Object)
    return std::nullopt;
  std::optional<StringRef> Name = Object->getString("name");
  std::optional<StringRef> ReturnType = Object->getString("return_type");
  const llvm::json::Array *Parameters = Object->getArray("parameters");
  if (!Name || Name->empty() || !ReturnType || ReturnType->empty() ||
      !Parameters)
    return std::nullopt;
  FunctionSpec Result{std::string(*Name), std::string(*ReturnType), {}};
  for (const llvm::json::Value &Value : *Parameters) {
    std::optional<StringRef> Parameter = Value.getAsString();
    if (!Parameter || Parameter->empty())
      return std::nullopt;
    Result.Parameters.emplace_back(*Parameter);
  }
  return Result;
}

static const MemRegion *baseRegion(SVal Value) {
  const MemRegion *Region = Value.getAsRegion();
  return Region ? Region->StripCasts()->getBaseRegion() : nullptr;
}

} // namespace

REGISTER_TRAIT_WITH_PROGRAMSTATE(QEMUReentrancyActiveProtocol, unsigned)
REGISTER_TRAIT_WITH_PROGRAMSTATE(QEMUReentrancyReported, unsigned)
REGISTER_SET_WITH_PROGRAMSTATE(QEMUReentrancyGuardedOwners, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(QEMUReentrancyPendingEngagePrior,
                               const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUReentrancySavedGuardOwners, SymbolRef,
                               const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(QEMUReentrancySavedGuardWasEngaged, SymbolRef)

namespace {

class QEMUReentrancyGuardChecker
    : public Checker<check::ASTDecl<TranslationUnitDecl>, check::BeginFunction,
                     check::EndFunction, check::Bind, check::PreCall,
                     check::PostCall> {
  std::string SummaryManifest;
  llvm::SmallVector<ReentrancyProtocol, 4> Protocols;
  mutable llvm::DenseMap<const FunctionDecl *, unsigned> EntryProtocols;
  mutable std::unique_ptr<BugType> BT;

  static bool evidenceIsComplete(const llvm::json::Object *Evidence) {
    return Evidence &&
           Evidence->getString("status") ==
               std::optional<StringRef>("complete") &&
           Evidence->getBoolean("external_registration") ==
               std::optional<bool>(true) &&
           Evidence->getBoolean("guest_controlled_publication") ==
               std::optional<bool>(true) &&
           Evidence->getBoolean("self_mmio_dispatch") ==
               std::optional<bool>(true) &&
           Evidence->getBoolean("destructive_alias_path") ==
               std::optional<bool>(true) &&
           Evidence->getBoolean("post_publication_use") ==
               std::optional<bool>(true);
  }

  static bool witnessIsComplete(const llvm::json::Object *Witness,
                                StringRef ExpectedSHA) {
    if (!Witness ||
        Witness->getBoolean("complete") != std::optional<bool>(true))
      return false;
    const llvm::json::Array *Edges = Witness->getArray("edges");
    if (!Edges)
      return false;
    llvm::StringSet<> Required;
    for (StringRef Edge :
         {"external-registration", "live-object", "real-dma-publication",
          "real-msix-publication", "guest-controlled-address-and-data",
          "same-device-bar0-doorbell", "zero-doorbell-command-dispatch",
          "reentrant-free-epctx-and-xfer", "post-publication-use",
          "same-owner-guard-enforcement"})
      Required.insert(Edge);
    for (const llvm::json::Value &Value : *Edges)
      if (std::optional<StringRef> Edge = Value.getAsString())
        Required.erase(*Edge);
    if (!Required.empty())
      return false;

    llvm::json::Object Copy = *Witness;
    std::string Canonical;
    llvm::raw_string_ostream OS(Canonical);
    OS << llvm::json::Value(std::move(Copy));
    OS.flush();
    Canonical.push_back('\n');
    return llvm::toHex(
               llvm::SHA256::hash(llvm::arrayRefFromStringRef(Canonical)),
               /*LowerCase=*/true) == ExpectedSHA;
  }

  bool loadManifest(StringRef Path, CheckerManager &Mgr) {
    SummaryManifest.clear();
    Protocols.clear();
    if (Path.empty())
      return true;

    auto Invalid = [&](StringRef Reason) {
      SummaryManifest.clear();
      Protocols.clear();
      Mgr.reportInvalidCheckerOptionValue(
          this, "ReentrancySummaryManifest",
          ("a complete sealed QEMU reentrancy summary (" + Reason + ")").str());
      return false;
    };

    auto &VFS = Mgr.getASTContext()
                    .getSourceManager()
                    .getFileManager()
                    .getVirtualFileSystem();
    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> Buffer =
        VFS.getBufferForFile(Path);
    if (Buffer.getError())
      return Invalid("file cannot be read");
    llvm::Expected<llvm::json::Value> Parsed =
        llvm::json::parse(Buffer.get()->getBuffer());
    if (!Parsed) {
      llvm::consumeError(Parsed.takeError());
      return Invalid("JSON is malformed");
    }
    const llvm::json::Object *Root = Parsed->getAsObject();
    if (!Root || Root->getInteger("format") != std::optional<int64_t>(1) ||
        Root->getString("kind") !=
            std::optional<StringRef>("qemu-reentrancy-summary") ||
        Root->getString("model") !=
            std::optional<StringRef>("qemu.reentrancy/v1") ||
        Root->getString("result") != std::optional<StringRef>("pass"))
      return Invalid("format, kind, model, or result differs");

    const llvm::json::Object *QEMU = Root->getObject("qemu");
    std::optional<StringRef> Revision =
        QEMU ? QEMU->getString("revision") : std::nullopt;
    if (!QEMU || !Revision || Revision->empty() ||
        QEMU->getBoolean("dirty") != std::optional<bool>(false))
      return Invalid("QEMU identity is incomplete");

    const llvm::json::Object *Source = Root->getObject("source");
    std::optional<StringRef> SourcePath =
        Source ? Source->getString("path") : std::nullopt;
    std::optional<StringRef> SourceSHA =
        Source ? Source->getString("sha256") : std::nullopt;
    std::optional<int64_t> SourceBytes =
        Source ? Source->getInteger("bytes") : std::nullopt;
    if (!SourcePath || SourcePath->empty() || !SourceSHA ||
        !isLowerHexSHA256(*SourceSHA) || !SourceBytes || *SourceBytes <= 0)
      return Invalid("source identity is incomplete");

    const llvm::json::Array *Entries = Root->getArray("protocols");
    if (!Entries || Entries->empty())
      return Invalid("protocol list is empty");
    llvm::StringSet<> IDs;
    for (const llvm::json::Value &Value : *Entries) {
      const llvm::json::Object *Object = Value.getAsObject();
      std::optional<StringRef> ID =
          Object ? Object->getString("id") : std::nullopt;
      std::optional<FunctionSpec> Entry =
          Object ? parseFunctionSpec(Object->getObject("entry")) : std::nullopt;
      const llvm::json::Object *WrapperObject =
          Object ? Object->getObject("publication_wrapper") : nullptr;
      std::optional<FunctionSpec> Wrapper = parseFunctionSpec(WrapperObject);
      std::optional<int64_t> OwnerArgument =
          WrapperObject ? WrapperObject->getInteger("owner_argument")
                        : std::nullopt;
      const llvm::json::Array *OwnerPath =
          WrapperObject ? WrapperObject->getArray("owner_member_path")
                        : nullptr;
      const llvm::json::Object *Guard =
          Object ? Object->getObject("guard") : nullptr;
      std::optional<StringRef> GuardRecord =
          Guard ? Guard->getString("record") : std::nullopt;
      std::optional<StringRef> GuardField =
          Guard ? Guard->getString("field") : std::nullopt;
      std::optional<StringRef> GuardModeValue =
          Guard ? Guard->getString("mode") : std::nullopt;
      const llvm::json::Object *Evidence =
          Object ? Object->getObject("evidence") : nullptr;
      std::optional<StringRef> EvidenceSHA =
          Evidence ? Evidence->getString("sha256") : std::nullopt;
      const llvm::json::Object *Witness =
          Object ? Object->getObject("witness") : nullptr;
      std::optional<StringRef> WitnessSHA =
          Object ? Object->getString("witness_sha256") : std::nullopt;
      if (!Object || !ID || ID->empty() || !IDs.insert(*ID).second || !Entry ||
          !Wrapper || !OwnerArgument || *OwnerArgument < 0 ||
          static_cast<uint64_t>(*OwnerArgument) >= Wrapper->Parameters.size() ||
          !OwnerPath || !GuardRecord || GuardRecord->empty() || !GuardField ||
          GuardField->empty() || !GuardModeValue || !EvidenceSHA ||
          !isLowerHexSHA256(*EvidenceSHA) || !WitnessSHA ||
          *WitnessSHA != *EvidenceSHA ||
          Object->getString("rule_id") !=
              std::optional<StringRef>("qemu.reentrant-self-mmio") ||
          !evidenceIsComplete(Evidence) ||
          !witnessIsComplete(Witness, *EvidenceSHA))
        return Invalid("a protocol is incomplete or ambiguous");

      ReentrancyProtocol Protocol;
      Protocol.ID = std::string(*ID);
      Protocol.SourcePath = std::string(*SourcePath);
      Protocol.SourceSHA256 = std::string(*SourceSHA);
      Protocol.SourceBytes = static_cast<uint64_t>(*SourceBytes);
      Protocol.Entry = std::move(*Entry);
      Protocol.PublicationWrapper = std::move(*Wrapper);
      Protocol.OwnerArgument = static_cast<unsigned>(*OwnerArgument);
      for (const llvm::json::Value &StepValue : *OwnerPath) {
        std::optional<StringRef> Step = StepValue.getAsString();
        if (!Step || Step->empty())
          return Invalid("an owner projection is malformed");
        Protocol.OwnerMemberPath.emplace_back(*Step);
      }
      Protocol.GuardRecord = std::string(*GuardRecord);
      Protocol.GuardField = std::string(*GuardField);
      Protocol.EvidenceSHA256 = std::string(*EvidenceSHA);
      if (*GuardModeValue == "direct-field") {
        Protocol.Mode = GuardMode::DirectField;
      } else if (*GuardModeValue == "helper-functions") {
        Protocol.Mode = GuardMode::HelperFunctions;
        std::optional<StringRef> EngageName =
            Guard->getString("engage_function");
        std::optional<StringRef> RestoreName =
            Guard->getString("restore_function");
        if (EngageName && !EngageName->empty())
          Protocol.EngageFunctionName = std::string(*EngageName);
        if (RestoreName && !RestoreName->empty())
          Protocol.RestoreFunctionName = std::string(*RestoreName);
        if (Protocol.EngageFunctionName.has_value() !=
            Protocol.RestoreFunctionName.has_value())
          return Invalid("guard helper names are incomplete");
      } else {
        return Invalid("guard mode is unsupported");
      }
      Protocols.push_back(std::move(Protocol));
    }
    SummaryManifest = Path.str();
    return true;
  }

  static const RecordDecl *recordForType(QualType Type) {
    Type = Type.getCanonicalType().getUnqualifiedType();
    if (Type->isPointerType())
      Type = Type->getPointeeType().getCanonicalType().getUnqualifiedType();
    return Type->getAsRecordDecl();
  }

  static const FieldDecl *uniqueField(const RecordDecl *Record,
                                      StringRef Name) {
    const FieldDecl *Result = nullptr;
    if (!Record)
      return nullptr;
    for (const FieldDecl *Field : Record->fields())
      if (Field->getName() == Name) {
        if (Result)
          return nullptr;
        Result = Field;
      }
    return Result;
  }

  static const MemRegion *projectOwner(const CallEvent &Call,
                                       const ReentrancyProtocol &Protocol,
                                       ProgramStateRef State) {
    if (Protocol.OwnerArgument >= Call.getNumArgs())
      return nullptr;
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || Protocol.OwnerArgument >= FD->getNumParams())
      return nullptr;

    SVal Object = Call.getArgSVal(Protocol.OwnerArgument);
    QualType ObjectType = FD->getParamDecl(Protocol.OwnerArgument)->getType();
    for (StringRef Step : Protocol.OwnerMemberPath) {
      const FieldDecl *Field = uniqueField(recordForType(ObjectType), Step);
      if (!Field)
        return nullptr;
      SVal Location = State->getLValue(Field, Object);
      auto LocValue = Location.getAs<Loc>();
      if (!LocValue)
        return nullptr;
      ObjectType = Field->getType();
      if (ObjectType->isPointerType()) {
        Object = State->getSVal(*LocValue);
        if (!Object.getAs<Loc>())
          return nullptr;
      } else if (ObjectType->isRecordType()) {
        Object = Location;
      } else {
        return nullptr;
      }
    }
    return baseRegion(Object);
  }

  static const MemRegion *guardOwner(SVal Location,
                                     const ReentrancyProtocol &Protocol) {
    const MemRegion *Region = Location.getAsRegion();
    const auto *GuardFieldRegion =
        Region ? dyn_cast<FieldRegion>(Region->StripCasts()) : nullptr;
    const FieldDecl *Field =
        GuardFieldRegion ? GuardFieldRegion->getDecl() : nullptr;
    const auto *Parent =
        Field ? dyn_cast<RecordDecl>(Field->getDeclContext()) : nullptr;
    if (!Field || !Parent || Field->getName() != Protocol.GuardField ||
        Parent->getName() != Protocol.GuardRecord)
      return nullptr;
    return GuardFieldRegion->getSuperRegion()->getBaseRegion();
  }

  static const MemRegion *directCallOwner(const CallEvent &Call,
                                          unsigned Argument) {
    return Argument < Call.getNumArgs() ? baseRegion(Call.getArgSVal(Argument))
                                        : nullptr;
  }

  const ReentrancyProtocol *activeProtocol(ProgramStateRef State) const {
    unsigned Encoded = State->get<QEMUReentrancyActiveProtocol>();
    if (Encoded == 0 || Encoded > Protocols.size())
      return nullptr;
    return &Protocols[Encoded - 1];
  }

public:
  void setSummaryManifest(StringRef Path, CheckerManager &Mgr) {
    loadManifest(Path, Mgr);
  }

  void checkASTDecl(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                    BugReporter &BR) const {
    (void)BR;
    EntryProtocols.clear();
    for (ReentrancyProtocol &Protocol :
         const_cast<llvm::SmallVector<ReentrancyProtocol, 4> &>(Protocols)) {
      Protocol.EntryDecl = nullptr;
      Protocol.PublicationWrapperDecl = nullptr;
      Protocol.EngageDecl = nullptr;
      Protocol.RestoreDecl = nullptr;
      Protocol.GuardFieldDecl = nullptr;
      Protocol.Resolved = false;
    }
    if (SummaryManifest.empty() || Protocols.empty())
      return;

    const SourceManager &SM = Mgr.getSourceManager();
    FileID Main = SM.getMainFileID();
    bool InvalidBuffer = false;
    StringRef Bytes = SM.getBufferData(Main, &InvalidBuffer);
    if (InvalidBuffer)
      return;
    auto MainFile = SM.getFileEntryRefForID(Main);
    if (!MainFile)
      return;
    StringRef MainName = MainFile->getName();

    class Resolver : public DynamicRecursiveASTVisitor {
      llvm::SmallVectorImpl<ReentrancyProtocol> &Protocols;
      llvm::SmallVector<unsigned, 8> EntryCounts;
      llvm::SmallVector<unsigned, 8> WrapperCounts;
      llvm::SmallVector<unsigned, 8> EngageCounts;
      llvm::SmallVector<unsigned, 8> RestoreCounts;
      llvm::SmallVector<unsigned, 8> GuardCounts;

    public:
      explicit Resolver(llvm::SmallVectorImpl<ReentrancyProtocol> &Protocols)
          : Protocols(Protocols), EntryCounts(Protocols.size()),
            WrapperCounts(Protocols.size()), EngageCounts(Protocols.size()),
            RestoreCounts(Protocols.size()), GuardCounts(Protocols.size()) {}

      bool VisitFunctionDecl(FunctionDecl *FD) override {
        if (!FD->doesThisDeclarationHaveABody())
          return true;
        FD = FD->getCanonicalDecl();
        for (unsigned I = 0; I != Protocols.size(); ++I) {
          ReentrancyProtocol &Protocol = Protocols[I];
          if (signatureMatches(FD, Protocol.Entry)) {
            ++EntryCounts[I];
            Protocol.EntryDecl = FD;
          }
          if (signatureMatches(FD, Protocol.PublicationWrapper)) {
            ++WrapperCounts[I];
            Protocol.PublicationWrapperDecl = FD;
          }
          if (Protocol.EngageFunctionName && FD->getIdentifier() &&
              FD->getName() == *Protocol.EngageFunctionName) {
            ++EngageCounts[I];
            Protocol.EngageDecl = FD;
          }
          if (Protocol.RestoreFunctionName && FD->getIdentifier() &&
              FD->getName() == *Protocol.RestoreFunctionName) {
            ++RestoreCounts[I];
            Protocol.RestoreDecl = FD;
          }
        }
        return true;
      }

      bool VisitFieldDecl(FieldDecl *Field) override {
        const auto *Parent = dyn_cast<RecordDecl>(Field->getDeclContext());
        if (!Parent)
          return true;
        for (unsigned I = 0; I != Protocols.size(); ++I) {
          ReentrancyProtocol &Protocol = Protocols[I];
          if (Parent->getName() == Protocol.GuardRecord &&
              Field->getName() == Protocol.GuardField) {
            ++GuardCounts[I];
            Protocol.GuardFieldDecl = Field->getCanonicalDecl();
          }
        }
        return true;
      }

      void finish() {
        for (unsigned I = 0; I != Protocols.size(); ++I) {
          ReentrancyProtocol &Protocol = Protocols[I];
          bool Helpers = !Protocol.EngageFunctionName ||
                         (EngageCounts[I] == 1 && RestoreCounts[I] == 1);
          Protocol.Resolved = EntryCounts[I] == 1 && WrapperCounts[I] == 1 &&
                              GuardCounts[I] == 1 && Helpers;
        }
      }
    };

    auto &MutableProtocols =
        const_cast<llvm::SmallVector<ReentrancyProtocol, 4> &>(Protocols);
    Resolver Visitor(MutableProtocols);
    Visitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));
    Visitor.finish();

    std::string ActualSHA =
        llvm::toHex(llvm::SHA256::hash(llvm::arrayRefFromStringRef(Bytes)),
                    /*LowerCase=*/true);
    for (unsigned I = 0; I != MutableProtocols.size(); ++I) {
      ReentrancyProtocol &Protocol = MutableProtocols[I];
      if (!MainName.ends_with(Protocol.SourcePath) ||
          Bytes.size() != Protocol.SourceBytes ||
          ActualSHA != Protocol.SourceSHA256)
        Protocol.Resolved = false;
      if (Protocol.Resolved)
        EntryProtocols[Protocol.EntryDecl] = I;
    }
  }

  void checkBeginFunction(CheckerContext &C) const {
    if (!C.inTopFrame() || SummaryManifest.empty())
      return;
    const auto *FD =
        dyn_cast_or_null<FunctionDecl>(C.getStackFrame()->getDecl());
    if (!FD)
      return;
    auto Found = EntryProtocols.find(FD->getCanonicalDecl());
    if (Found == EntryProtocols.end())
      return;
    ProgramStateRef State =
        C.getState()
            ->set<QEMUReentrancyActiveProtocol>(Found->second + 1)
            ->set<QEMUReentrancyReported>(0);
    C.addTransition(State);
  }

  void checkEndFunction(const ReturnStmt *, CheckerContext &C) const {
    if (!C.inTopFrame() ||
        C.getState()->get<QEMUReentrancyActiveProtocol>() == 0)
      return;
    ProgramStateRef State = C.getState()
                                ->set<QEMUReentrancyActiveProtocol>(0)
                                ->set<QEMUReentrancyReported>(0);
    C.addTransition(State);
  }

  void checkBind(SVal Location, SVal Value, const Stmt *, bool,
                 CheckerContext &C) const {
    const ReentrancyProtocol *Protocol = activeProtocol(C.getState());
    if (!Protocol)
      return;
    const MemRegion *Owner = guardOwner(Location, *Protocol);
    if (!Owner)
      return;
    auto Concrete = Value.getAs<nonloc::ConcreteInt>();
    if (!Concrete)
      return;
    ProgramStateRef State = C.getState();
    if (Concrete->getValue()->isZero())
      State = State->remove<QEMUReentrancyGuardedOwners>(Owner);
    else
      State = State->add<QEMUReentrancyGuardedOwners>(Owner);
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    const ReentrancyProtocol *Protocol = activeProtocol(State);
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Protocol || !FD)
      return;
    FD = FD->getCanonicalDecl();

    if (Protocol->EngageDecl && FD == Protocol->EngageDecl) {
      const MemRegion *Owner = directCallOwner(Call, 0);
      if (!Owner)
        return;
      if (State->contains<QEMUReentrancyGuardedOwners>(Owner))
        State = State->add<QEMUReentrancyPendingEngagePrior>(Owner);
      else
        State = State->remove<QEMUReentrancyPendingEngagePrior>(Owner);
      State = State->add<QEMUReentrancyGuardedOwners>(Owner);
      if (State != C.getState())
        C.addTransition(State);
      return;
    }

    if (Protocol->RestoreDecl && FD == Protocol->RestoreDecl) {
      const MemRegion *Owner = directCallOwner(Call, 0);
      if (!Owner || Call.getNumArgs() < 2)
        return;
      std::optional<bool> Previous;
      SVal PreviousValue = Call.getArgSVal(1);
      if (auto Concrete = PreviousValue.getAs<nonloc::ConcreteInt>()) {
        Previous = !Concrete->getValue()->isZero();
      } else if (SymbolRef Saved = PreviousValue.getAsSymbol()) {
        const MemRegion *const *SavedOwner =
            State->get<QEMUReentrancySavedGuardOwners>(Saved);
        if (SavedOwner && *SavedOwner == Owner) {
          Previous = State->contains<QEMUReentrancySavedGuardWasEngaged>(Saved);
          State = State->remove<QEMUReentrancySavedGuardOwners>(Saved);
          State = State->remove<QEMUReentrancySavedGuardWasEngaged>(Saved);
        }
      }
      if (Previous.has_value())
        State = *Previous ? State->add<QEMUReentrancyGuardedOwners>(Owner)
                          : State->remove<QEMUReentrancyGuardedOwners>(Owner);
      if (State != C.getState())
        C.addTransition(State);
      return;
    }
    const auto *Caller =
        dyn_cast_or_null<FunctionDecl>(C.getStackFrame()->getDecl());
    if (!Caller || Caller->getCanonicalDecl() != Protocol->EntryDecl)
      return;
    if (FD != Protocol->PublicationWrapperDecl ||
        State->get<QEMUReentrancyReported>() != 0)
      return;

    const MemRegion *Owner = projectOwner(Call, *Protocol, State);
    if (!Owner || State->contains<QEMUReentrancyGuardedOwners>(Owner))
      return;

    if (!BT)
      BT = std::make_unique<BugType>(
          this, "Unguarded reentrant QEMU publication", "QEMU reentrancy");
    ProgramStateRef ReportedState = State->set<QEMUReentrancyReported>(1);
    ExplodedNode *Node = C.generateNonFatalErrorNode(ReportedState);
    if (!Node)
      return;
    std::string Message;
    llvm::raw_string_ostream OS(Message);
    OS << '[' << RuleID << "] external callback '" << Protocol->Entry.Name
       << "' reaches a guest-targetable publication while its device "
          "reentrancy guard is not engaged; sealed evidence '"
       << Protocol->ID
       << "' proves self-MMIO dispatch, destructive aliasing, and resumed "
          "host-object use";
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Call.getSourceRange());
    Report->markInteresting(Owner);
    C.emitReport(std::move(Report));
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    const ReentrancyProtocol *Protocol = activeProtocol(State);
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Protocol || !FD || !Protocol->EngageDecl ||
        FD->getCanonicalDecl() != Protocol->EngageDecl)
      return;
    const MemRegion *Owner = directCallOwner(Call, 0);
    if (!Owner)
      return;
    bool WasEngaged = State->contains<QEMUReentrancyPendingEngagePrior>(Owner);
    if (SymbolRef Saved = Call.getReturnValue().getAsSymbol()) {
      State = State->set<QEMUReentrancySavedGuardOwners>(Saved, Owner);
      if (WasEngaged)
        State = State->add<QEMUReentrancySavedGuardWasEngaged>(Saved);
      else
        State = State->remove<QEMUReentrancySavedGuardWasEngaged>(Saved);
    }
    State = State->remove<QEMUReentrancyPendingEngagePrior>(Owner);
    State = State->add<QEMUReentrancyGuardedOwners>(Owner);
    if (State != C.getState())
      C.addTransition(State);
  }
};

} // namespace

void ento::registerQEMUReentrancyGuardChecker(CheckerManager &Mgr) {
  auto *Checker = Mgr.registerChecker<QEMUReentrancyGuardChecker>();
  Checker->setSummaryManifest(Mgr.getAnalyzerOptions().getCheckerStringOption(
                                  Checker, "ReentrancySummaryManifest"),
                              Mgr);
}

bool ento::shouldRegisterQEMUReentrancyGuardChecker(const CheckerManager &) {
  return true;
}
