//===- QEMUAsyncTeardownChecker.cpp ---------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Consume a source-bound cross-entry summary for a queued asynchronous QEMU
// callback and verify that the corresponding device teardown cancels the exact
// backend/callback/opaque tuple.  The producer must prove the asynchronous
// event schedule; this consumer deliberately emits nothing for incomplete or
// source-drifted summaries.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DynamicRecursiveASTVisitor.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
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
#include <utility>

using namespace clang;
using namespace ento;

namespace clang::ento {
void registerQEMUAsyncTeardownChecker(CheckerManager &Mgr);
bool shouldRegisterQEMUAsyncTeardownChecker(const CheckerManager &Mgr);
} // namespace clang::ento

namespace {

static constexpr llvm::StringLiteral RuleID =
    "qemu.async-teardown-missing-cancel";

struct FunctionSpec {
  std::string Name;
  std::string ReturnType;
  llvm::SmallVector<std::string, 4> Parameters;
};

struct AsyncTeardownProtocol {
  std::string ID;
  std::string SourcePath;
  std::string SourceSHA256;
  uint64_t SourceBytes = 0;
  FunctionSpec Requester;
  FunctionSpec RequestAPI;
  FunctionSpec Callback;
  FunctionSpec Teardown;
  FunctionSpec CancelAPI;
  unsigned RequestBackendArgument = 0;
  unsigned RequestCallbackArgument = 0;
  unsigned RequestOpaqueArgument = 0;
  unsigned CancelBackendArgument = 0;
  unsigned CancelCallbackArgument = 0;
  unsigned CancelOpaqueArgument = 0;
  std::string RequestOwner;
  std::string TeardownOwner;
  std::string BackendMember;

  const FunctionDecl *RequesterDecl = nullptr;
  const FunctionDecl *CallbackDecl = nullptr;
  const FunctionDecl *TeardownDecl = nullptr;
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

static bool evidenceIsComplete(const llvm::json::Object *Evidence) {
  if (!Evidence ||
      Evidence->getString("status") != std::optional<StringRef>("complete"))
    return false;
  for (StringRef Key :
       {"request_can_outlive_entry", "teardown_releases_owner_after_return",
        "completion_invokes_callback", "callback_dereferences_owner",
        "cancellation_is_synchronous"})
    if (Evidence->getBoolean(Key) != std::optional<bool>(true))
      return false;
  const llvm::json::Array *Schedule = Evidence->getArray("schedule");
  if (!Schedule || Schedule->size() != 5)
    return false;
  const StringRef Required[] = {
      "request-enqueued", "frontend-teardown", "frontend-storage-released",
      "backend-completion", "callback-owner-dereference"};
  for (unsigned I = 0; I != 5; ++I)
    if ((*Schedule)[I].getAsString() != std::optional<StringRef>(Required[I]))
      return false;
  return true;
}

static std::optional<unsigned> parseArgument(const llvm::json::Object *Object,
                                             StringRef Key) {
  std::optional<int64_t> Value =
      Object ? Object->getInteger(Key) : std::nullopt;
  if (!Value || *Value < 0 || *Value > 31)
    return std::nullopt;
  return static_cast<unsigned>(*Value);
}

static const Expr *ignore(const Expr *Expression) {
  return Expression ? Expression->IgnoreParenImpCasts() : nullptr;
}

static const ValueDecl *referencedValue(const Expr *Expression) {
  Expression = ignore(Expression);
  if (const auto *UO = dyn_cast_or_null<UnaryOperator>(Expression)) {
    if (UO->getOpcode() == UO_AddrOf)
      Expression = ignore(UO->getSubExpr());
  }
  const auto *DRE = dyn_cast_or_null<DeclRefExpr>(Expression);
  return DRE ? dyn_cast<ValueDecl>(DRE->getDecl()) : nullptr;
}

static bool referencesName(const Expr *Expression, StringRef Name) {
  const ValueDecl *Decl = referencedValue(Expression);
  return Decl && Decl->getIdentifier() && Decl->getName() == Name;
}

static bool referencesFunction(const Expr *Expression,
                               const FunctionDecl *Expected) {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(referencedValue(Expression));
  return FD && Expected &&
         FD->getCanonicalDecl() == Expected->getCanonicalDecl();
}

static bool isMemberOnOwner(const Expr *Expression, StringRef Owner,
                            StringRef Member) {
  const auto *ME = dyn_cast_or_null<MemberExpr>(ignore(Expression));
  const auto *FD = ME ? dyn_cast<FieldDecl>(ME->getMemberDecl()) : nullptr;
  return FD && FD->getIdentifier() && FD->getName() == Member &&
         referencesName(ME->getBase(), Owner);
}

class CallFinder : public DynamicRecursiveASTVisitor {
  const AsyncTeardownProtocol &Protocol;
  bool FindRequest;

public:
  bool ExactMatch = false;

  CallFinder(const AsyncTeardownProtocol &Protocol, bool FindRequest)
      : Protocol(Protocol), FindRequest(FindRequest) {}

  bool VisitCallExpr(CallExpr *Call) override {
    const FunctionDecl *Callee = Call->getDirectCallee();
    const FunctionSpec &API =
        FindRequest ? Protocol.RequestAPI : Protocol.CancelAPI;
    if (!signatureMatches(Callee, API))
      return true;
    unsigned Backend = FindRequest ? Protocol.RequestBackendArgument
                                   : Protocol.CancelBackendArgument;
    unsigned Callback = FindRequest ? Protocol.RequestCallbackArgument
                                    : Protocol.CancelCallbackArgument;
    unsigned Opaque = FindRequest ? Protocol.RequestOpaqueArgument
                                  : Protocol.CancelOpaqueArgument;
    StringRef Owner =
        FindRequest ? Protocol.RequestOwner : Protocol.TeardownOwner;
    if (std::max({Backend, Callback, Opaque}) >= Call->getNumArgs())
      return true;
    ExactMatch =
        isMemberOnOwner(Call->getArg(Backend), Owner, Protocol.BackendMember) &&
        referencesFunction(Call->getArg(Callback), Protocol.CallbackDecl) &&
        referencesName(Call->getArg(Opaque), Owner);
    return !ExactMatch;
  }
};

static bool hasUnconditionalExactCancel(const AsyncTeardownProtocol &Protocol) {
  const auto *Body =
      dyn_cast_or_null<CompoundStmt>(Protocol.TeardownDecl->getBody());
  if (!Body)
    return false;
  for (const Stmt *Statement : Body->body()) {
    if (isa<DeclStmt, NullStmt>(Statement))
      continue;
    const auto *Expression = dyn_cast<Expr>(Statement);
    const auto *Call =
        Expression ? dyn_cast<CallExpr>(ignore(Expression)) : nullptr;
    if (!Call)
      return false;
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!signatureMatches(Callee, Protocol.CancelAPI))
      return false;
    if (std::max({Protocol.CancelBackendArgument,
                  Protocol.CancelCallbackArgument,
                  Protocol.CancelOpaqueArgument}) >= Call->getNumArgs())
      return false;
    if (isMemberOnOwner(Call->getArg(Protocol.CancelBackendArgument),
                        Protocol.TeardownOwner, Protocol.BackendMember) &&
        referencesFunction(Call->getArg(Protocol.CancelCallbackArgument),
                           Protocol.CallbackDecl) &&
        referencesName(Call->getArg(Protocol.CancelOpaqueArgument),
                       Protocol.TeardownOwner))
      return true;
    return false;
  }
  return false;
}

class ParameterUseFinder : public DynamicRecursiveASTVisitor {
  const ParmVarDecl *Parameter;

public:
  bool Used = false;
  explicit ParameterUseFinder(const ParmVarDecl *Parameter)
      : Parameter(Parameter) {}

  bool VisitDeclRefExpr(DeclRefExpr *DRE) override {
    if (DRE->getDecl() == Parameter)
      Used = true;
    return !Used;
  }
};

class QEMUAsyncTeardownChecker
    : public Checker<check::ASTDecl<TranslationUnitDecl>> {
  std::string SummaryManifest;
  llvm::SmallVector<AsyncTeardownProtocol, 4> Protocols;

  void loadManifest(StringRef Path, CheckerManager &Mgr) {
    SummaryManifest.clear();
    Protocols.clear();
    if (Path.empty())
      return;
    auto &VFS = Mgr.getASTContext()
                    .getSourceManager()
                    .getFileManager()
                    .getVirtualFileSystem();
    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> Buffer =
        VFS.getBufferForFile(Path);
    if (Buffer.getError()) {
      Mgr.reportInvalidCheckerOptionValue(this, "AsyncTeardownSummaryManifest",
                                          "a readable JSON file");
      return;
    }
    llvm::Expected<llvm::json::Value> Parsed =
        llvm::json::parse(Buffer.get()->getBuffer());
    if (!Parsed) {
      llvm::consumeError(Parsed.takeError());
      Mgr.reportInvalidCheckerOptionValue(this, "AsyncTeardownSummaryManifest",
                                          "valid JSON");
      return;
    }
    const llvm::json::Object *Root = Parsed ? Parsed->getAsObject() : nullptr;
    const llvm::json::Array *Entries =
        Root ? Root->getArray("protocols") : nullptr;
    if (!Root || Root->getInteger("format") != std::optional<int64_t>(1) ||
        !Entries) {
      Mgr.reportInvalidCheckerOptionValue(this, "AsyncTeardownSummaryManifest",
                                          "a format-1 protocol manifest");
      return;
    }

    for (const llvm::json::Value &Value : *Entries) {
      const llvm::json::Object *Object = Value.getAsObject();
      const llvm::json::Object *Source =
          Object ? Object->getObject("source") : nullptr;
      const llvm::json::Object *Arguments =
          Object ? Object->getObject("arguments") : nullptr;
      std::optional<StringRef> ID =
          Object ? Object->getString("id") : std::nullopt;
      std::optional<StringRef> SourcePath =
          Source ? Source->getString("path") : std::nullopt;
      std::optional<StringRef> SourceSHA =
          Source ? Source->getString("sha256") : std::nullopt;
      std::optional<int64_t> SourceBytes =
          Source ? Source->getInteger("bytes") : std::nullopt;
      auto Requester =
          parseFunctionSpec(Object ? Object->getObject("requester") : nullptr);
      auto RequestAPI = parseFunctionSpec(
          Object ? Object->getObject("request_api") : nullptr);
      auto Callback =
          parseFunctionSpec(Object ? Object->getObject("callback") : nullptr);
      auto Teardown =
          parseFunctionSpec(Object ? Object->getObject("teardown") : nullptr);
      auto CancelAPI =
          parseFunctionSpec(Object ? Object->getObject("cancel_api") : nullptr);
      auto RequestBackend = parseArgument(Arguments, "request_backend");
      auto RequestCallback = parseArgument(Arguments, "request_callback");
      auto RequestOpaque = parseArgument(Arguments, "request_opaque");
      auto CancelBackend = parseArgument(Arguments, "cancel_backend");
      auto CancelCallback = parseArgument(Arguments, "cancel_callback");
      auto CancelOpaque = parseArgument(Arguments, "cancel_opaque");
      std::optional<StringRef> RequestOwner =
          Object ? Object->getString("request_owner") : std::nullopt;
      std::optional<StringRef> TeardownOwner =
          Object ? Object->getString("teardown_owner") : std::nullopt;
      std::optional<StringRef> BackendMember =
          Object ? Object->getString("backend_member") : std::nullopt;

      if (!ID || ID->empty() || !SourcePath || SourcePath->empty() ||
          !SourceSHA || !isLowerHexSHA256(*SourceSHA) || !SourceBytes ||
          *SourceBytes <= 0 || !Requester || !RequestAPI || !Callback ||
          !Teardown || !CancelAPI || !RequestBackend || !RequestCallback ||
          !RequestOpaque || !CancelBackend || !CancelCallback ||
          !CancelOpaque || !RequestOwner || RequestOwner->empty() ||
          !TeardownOwner || TeardownOwner->empty() || !BackendMember ||
          BackendMember->empty() ||
          !evidenceIsComplete(Object->getObject("evidence")))
        continue;

      Protocols.push_back(AsyncTeardownProtocol{
          std::string(*ID), std::string(*SourcePath), std::string(*SourceSHA),
          static_cast<uint64_t>(*SourceBytes), std::move(*Requester),
          std::move(*RequestAPI), std::move(*Callback), std::move(*Teardown),
          std::move(*CancelAPI), *RequestBackend, *RequestCallback,
          *RequestOpaque, *CancelBackend, *CancelCallback, *CancelOpaque,
          std::string(*RequestOwner), std::string(*TeardownOwner),
          std::string(*BackendMember)});
    }
    SummaryManifest = Path.str();
  }

  void report(const AsyncTeardownProtocol &Protocol, BugReporter &BR) const {
    const SourceManager &SM = BR.getSourceManager();
    SourceLocation Location =
        SM.getExpansionLoc(Protocol.TeardownDecl->getBody()->getBeginLoc());
    llvm::SmallString<320> Buffer;
    llvm::raw_svector_ostream Message(Buffer);
    Message << '[' << RuleID << "] teardown '" << Protocol.Teardown.Name
            << "' can release callback owner '" << Protocol.TeardownOwner
            << "' while a queued request can later invoke '"
            << Protocol.Callback.Name << "'; no exact '"
            << Protocol.CancelAPI.Name << "' call cancels backend member '"
            << Protocol.BackendMember << "', callback, and opaque owner tuple"
            << " (sealed schedule '" << Protocol.ID << "')";
    BR.EmitBasicReport(Protocol.TeardownDecl, this,
                       "Queued QEMU callback survives owner teardown",
                       "QEMU asynchronous lifetime", Message.str(),
                       PathDiagnosticLocation(Location, SM),
                       {Protocol.TeardownDecl->getBody()->getSourceRange()});
  }

public:
  void setSummaryManifest(StringRef Path, CheckerManager &Mgr) {
    loadManifest(Path, Mgr);
  }

  void checkASTDecl(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                    BugReporter &BR) const {
    if (SummaryManifest.empty() || Protocols.empty())
      return;
    const SourceManager &SM = Mgr.getSourceManager();
    FileID Main = SM.getMainFileID();
    bool Invalid = false;
    StringRef Bytes = SM.getBufferData(Main, &Invalid);
    auto MainFile = SM.getFileEntryRefForID(Main);
    if (Invalid || !MainFile)
      return;
    std::string SHA =
        llvm::toHex(llvm::SHA256::hash(llvm::arrayRefFromStringRef(Bytes)),
                    /*LowerCase=*/true);

    for (const AsyncTeardownProtocol &Template : Protocols) {
      AsyncTeardownProtocol Protocol = Template;
      Protocol.RequesterDecl = nullptr;
      Protocol.CallbackDecl = nullptr;
      Protocol.TeardownDecl = nullptr;
      Protocol.Resolved = false;
      if (!MainFile->getName().ends_with(Protocol.SourcePath) ||
          Bytes.size() != Protocol.SourceBytes || SHA != Protocol.SourceSHA256)
        continue;

      unsigned RequesterCount = 0, CallbackCount = 0, TeardownCount = 0;
      class Resolver : public DynamicRecursiveASTVisitor {
        AsyncTeardownProtocol &Protocol;
        unsigned &RequesterCount;
        unsigned &CallbackCount;
        unsigned &TeardownCount;

      public:
        Resolver(AsyncTeardownProtocol &Protocol, unsigned &RequesterCount,
                 unsigned &CallbackCount, unsigned &TeardownCount)
            : Protocol(Protocol), RequesterCount(RequesterCount),
              CallbackCount(CallbackCount), TeardownCount(TeardownCount) {}
        bool VisitFunctionDecl(FunctionDecl *FD) override {
          if (!FD->doesThisDeclarationHaveABody())
            return true;
          FD = FD->getCanonicalDecl();
          if (signatureMatches(FD, Protocol.Requester)) {
            ++RequesterCount;
            Protocol.RequesterDecl = FD;
          }
          if (signatureMatches(FD, Protocol.Callback)) {
            ++CallbackCount;
            Protocol.CallbackDecl = FD;
          }
          if (signatureMatches(FD, Protocol.Teardown)) {
            ++TeardownCount;
            Protocol.TeardownDecl = FD;
          }
          return true;
        }
      } Resolver(Protocol, RequesterCount, CallbackCount, TeardownCount);
      Resolver.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));
      if (RequesterCount != 1 || CallbackCount != 1 || TeardownCount != 1)
        continue;

      CallFinder Request(Protocol, /*FindRequest=*/true);
      Request.TraverseStmt(
          const_cast<Stmt *>(Protocol.RequesterDecl->getBody()));
      ParameterUseFinder CallbackUse(Protocol.CallbackDecl->getParamDecl(0));
      CallbackUse.TraverseStmt(
          const_cast<Stmt *>(Protocol.CallbackDecl->getBody()));
      if (!Request.ExactMatch || !CallbackUse.Used)
        continue;

      Protocol.Resolved = true;
      if (!hasUnconditionalExactCancel(Protocol))
        report(Protocol, BR);
    }
  }
};

} // namespace

void ento::registerQEMUAsyncTeardownChecker(CheckerManager &Mgr) {
  auto *Checker = Mgr.registerChecker<QEMUAsyncTeardownChecker>();
  Checker->setSummaryManifest(Mgr.getAnalyzerOptions().getCheckerStringOption(
                                  Checker, "AsyncTeardownSummaryManifest"),
                              Mgr);
}

bool ento::shouldRegisterQEMUAsyncTeardownChecker(const CheckerManager &) {
  return true;
}
