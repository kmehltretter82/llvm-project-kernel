//===- QEMUMigrationConsistencyChecker.cpp -------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This checker validates constant relationships inside QEMU
// VMStateDescription declarations.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DynamicRecursiveASTVisitor.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdint>
#include <optional>
#include <utility>

using namespace clang;
using namespace ento;

namespace {

static const InitListExpr *semanticInitList(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  while (const auto *CE = dyn_cast<ConstantExpr>(E))
    E = CE->getSubExpr()->IgnoreParenImpCasts();
  const auto *ILE = dyn_cast<InitListExpr>(E);
  if (!ILE)
    return nullptr;
  if (!ILE->isSemanticForm())
    if (const InitListExpr *Semantic = ILE->getSemanticForm())
      ILE = Semantic;
  return ILE;
}

static bool initializesRecord(const InitListExpr *ILE, StringRef Name) {
  if (!ILE)
    return false;
  const RecordDecl *RD = ILE->getType()->getAsRecordDecl();
  return RD && RD->getName() == Name;
}

static const Expr *fieldInitializer(const InitListExpr *ILE, StringRef Name) {
  if (!ILE)
    return nullptr;
  if (!ILE->isSemanticForm())
    if (const InitListExpr *Semantic = ILE->getSemanticForm())
      ILE = Semantic;
  const RecordDecl *RD = ILE->getType()->getAsRecordDecl();
  if (!RD)
    return nullptr;

  unsigned Index = 0;
  for (const FieldDecl *FD : RD->fields()) {
    if (FD->getName() == Name)
      return Index < ILE->getNumInits() ? ILE->getInit(Index) : nullptr;
    ++Index;
  }
  return nullptr;
}

static const Expr *referencedInitializer(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  while (const auto *CE = dyn_cast<ConstantExpr>(E))
    E = CE->getSubExpr()->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      if (VD->hasInit())
        return VD->getInit();
  return E;
}

static std::optional<int64_t> integerValue(const Expr *E,
                                           const ASTContext &Ctx) {
  if (!E || isa<ImplicitValueInitExpr>(E))
    return 0;
  std::optional<llvm::APSInt> Value = E->getIntegerConstantExpr(Ctx);
  if (!Value)
    return std::nullopt;
  return Value->getSExtValue();
}

static bool isNullInitializer(const Expr *E, ASTContext &Ctx) {
  if (!E || isa<ImplicitValueInitExpr>(E))
    return true;
  return E->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNotNull);
}

class SizeofFinder : public DynamicRecursiveASTVisitor {
public:
  const UnaryExprOrTypeTraitExpr *Found = nullptr;

  bool VisitUnaryExprOrTypeTraitExpr(UnaryExprOrTypeTraitExpr *E) override {
    if (E->getKind() == UETT_SizeOf) {
      Found = E;
      return false;
    }
    return true;
  }
};

class QEMUMigrationConsistencyChecker
    : public Checker<check::ASTDecl<TranslationUnitDecl>> {
  void report(const VarDecl *Description, const Expr *Where, StringRef Message,
              BugReporter &BR) const {
    const SourceManager &SM = BR.getSourceManager();
    SourceLocation Location = SM.getExpansionLoc(Where->getExprLoc());
    BR.EmitBasicReport(Description, this, "Inconsistent QEMU migration version",
                       "QEMU migration", Message,
                       PathDiagnosticLocation(Location, SM),
                       {Where->getSourceRange()});
  }

  void checkField(const VarDecl *Description, const InitListExpr *Field,
                  int64_t MaximumVersion, BugReporter &BR,
                  llvm::DenseSet<const InitListExpr *> &Seen) const {
    Field = semanticInitList(Field);
    if (!initializesRecord(Field, "VMStateField") || !Seen.insert(Field).second)
      return;

    const Expr *Predicate = fieldInitializer(Field, "field_exists");
    if (!isNullInitializer(Predicate, Description->getASTContext()))
      return;

    const Expr *VersionExpr = fieldInitializer(Field, "version_id");
    std::optional<int64_t> Version =
        integerValue(VersionExpr, Description->getASTContext());
    if (!Version || *Version <= MaximumVersion)
      return;

    llvm::SmallString<192> Buffer;
    llvm::raw_svector_ostream Message(Buffer);
    Message << "migration field requires version " << *Version
            << ", but containing VMStateDescription '" << Description->getName()
            << "' only writes version " << MaximumVersion
            << "; this field can never be present";
    report(Description, VersionExpr, Message.str(), BR);
  }

  void checkDescription(const VarDecl *VD, BugReporter &BR) const {
    const InitListExpr *Description = semanticInitList(VD->getInit());
    if (!initializesRecord(Description, "VMStateDescription"))
      return;

    ASTContext &Ctx = VD->getASTContext();
    const Expr *VersionExpr = fieldInitializer(Description, "version_id");
    const Expr *MinimumExpr =
        fieldInitializer(Description, "minimum_version_id");
    std::optional<int64_t> Version = integerValue(VersionExpr, Ctx);
    std::optional<int64_t> Minimum = integerValue(MinimumExpr, Ctx);

    if (Version && Minimum && *Minimum > *Version) {
      llvm::SmallString<192> Buffer;
      llvm::raw_svector_ostream Message(Buffer);
      Message << "VMStateDescription '" << VD->getName()
              << "' accepts minimum version " << *Minimum
              << " but advertises maximum version " << *Version
              << "; no incoming version can satisfy this range";
      report(VD, MinimumExpr, Message.str(), BR);
    }

    const Expr *ABIDependent = nullptr;
    StringRef ABIDependentMember;
    for (const auto &[Member, Initializer] :
         {std::pair<StringRef, const Expr *>("version_id", VersionExpr),
          std::pair<StringRef, const Expr *>("minimum_version_id",
                                             MinimumExpr)}) {
      if (!Initializer)
        continue;
      SizeofFinder Finder;
      Finder.TraverseStmt(const_cast<Expr *>(Initializer));
      if (Finder.Found) {
        ABIDependent = Finder.Found;
        ABIDependentMember = Member;
        break;
      }
    }
    if (ABIDependent) {
      llvm::SmallString<192> Buffer;
      llvm::raw_svector_ostream Message(Buffer);
      Message << "VMStateDescription '" << VD->getName() << "' derives "
              << ABIDependentMember
              << " from sizeof; migration versions must not depend on host "
                 "ABI layout";
      report(VD, ABIDependent, Message.str(), BR);
    }

    if (!Version)
      return;
    const Expr *Fields = fieldInitializer(Description, "fields");
    if (!Fields || isNullInitializer(Fields, Ctx))
      return;
    Fields = referencedInitializer(Fields);

    class FieldVisitor : public DynamicRecursiveASTVisitor {
      const QEMUMigrationConsistencyChecker &Checker;
      const VarDecl *Description;
      int64_t MaximumVersion;
      BugReporter &BR;
      llvm::DenseSet<const InitListExpr *> Seen;

    public:
      FieldVisitor(const QEMUMigrationConsistencyChecker &Checker,
                   const VarDecl *Description, int64_t MaximumVersion,
                   BugReporter &BR)
          : Checker(Checker), Description(Description),
            MaximumVersion(MaximumVersion), BR(BR) {}

      bool VisitInitListExpr(InitListExpr *ILE) override {
        Checker.checkField(Description, ILE, MaximumVersion, BR, Seen);
        return true;
      }
    } Visitor(*this, VD, *Version, BR);
    Visitor.TraverseStmt(const_cast<Expr *>(Fields));
  }

public:
  void checkASTDecl(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                    BugReporter &BR) const {
    class DescriptionVisitor : public DynamicRecursiveASTVisitor {
      const QEMUMigrationConsistencyChecker &Checker;
      BugReporter &BR;

    public:
      DescriptionVisitor(const QEMUMigrationConsistencyChecker &Checker,
                         BugReporter &BR)
          : Checker(Checker), BR(BR) {}

      bool VisitVarDecl(VarDecl *VD) override {
        if (VD->hasInit())
          Checker.checkDescription(VD, BR);
        return true;
      }
    } Visitor(*this, BR);
    Visitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));
  }
};

} // namespace

void ento::registerQEMUMigrationConsistencyChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<QEMUMigrationConsistencyChecker>();
}

bool ento::shouldRegisterQEMUMigrationConsistencyChecker(
    const CheckerManager &Mgr) {
  return true;
}
