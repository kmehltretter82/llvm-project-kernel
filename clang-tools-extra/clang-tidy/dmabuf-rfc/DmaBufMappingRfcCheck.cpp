//===--- DmaBufMappingRfcCheck.cpp - DMA-buf RFC checks ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "DmaBufMappingRfcCheck.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Lex/Preprocessor.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringMap.h"

#include <memory>
#include <string>

using namespace clang::ast_matchers;

namespace clang::tidy::linuxkernel {
namespace {

struct AssignmentFact {
  const BinaryOperator *Expr;
  std::string Path;
};

struct FunctionFacts {
  const FunctionDecl *Function;
  llvm::SmallVector<const CallExpr *, 16> Calls;
  llvm::SmallVector<const MemberExpr *, 16> Members;
  llvm::SmallVector<const IfStmt *, 8> Ifs;
  llvm::SmallVector<const ConditionalOperator *, 4> Conditionals;
  llvm::SmallVector<const BinaryOperator *, 16> BinaryOperators;
  llvm::SmallVector<AssignmentFact, 8> Assignments;
};

const Expr *ignore(const Expr *E) {
  return E ? E->IgnoreParenImpCasts() : nullptr;
}

std::string memberPath(const Expr *E) {
  E = ignore(E);
  if (!E)
    return {};

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    return DRE->getDecl()->getNameAsString();

  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    std::string Prefix = memberPath(ME->getBase());
    if (!Prefix.empty())
      Prefix.push_back('.');
    Prefix += ME->getMemberDecl()->getNameAsString();
    return Prefix;
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(E))
    return memberPath(UO->getSubExpr());

  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E))
    return memberPath(ASE->getBase());

  return {};
}

StringRef callName(const CallExpr *Call) {
  if (const FunctionDecl *Callee = Call->getDirectCallee())
    return Callee->getName();

  const Expr *Callee = ignore(Call->getCallee());
  if (const auto *ME = dyn_cast_or_null<MemberExpr>(Callee))
    return ME->getMemberDecl()->getName();
  if (const auto *DRE = dyn_cast_or_null<DeclRefExpr>(Callee))
    return DRE->getDecl()->getName();
  return {};
}

bool pathEndsWith(StringRef Path, StringRef Suffix) {
  return Path == Suffix ||
         (Path.size() > Suffix.size() && Path.ends_with(Suffix) &&
          Path[Path.size() - Suffix.size() - 1] == '.');
}

bool before(const SourceManager &SM, SourceLocation A, SourceLocation B) {
  A = SM.getExpansionLoc(A);
  B = SM.getExpansionLoc(B);
  return A.isValid() && B.isValid() && A != B &&
         SM.isBeforeInTranslationUnit(A, B);
}

bool between(const SourceManager &SM, SourceLocation Value,
             SourceLocation Begin, SourceLocation End) {
  return before(SM, Begin, Value) && before(SM, Value, End);
}

bool within(const SourceManager &SM, SourceLocation Value, SourceLocation Begin,
            SourceLocation End) {
  Value = SM.getExpansionLoc(Value);
  Begin = SM.getExpansionLoc(Begin);
  End = SM.getExpansionLoc(End);
  return Value.isValid() && Begin.isValid() && End.isValid() &&
         !before(SM, Value, Begin) && !before(SM, End, Value);
}

class RefVisitor final : public RecursiveASTVisitor<RefVisitor> {
public:
  explicit RefVisitor(const ValueDecl *Needle) : Needle(Needle) {}

  bool VisitDeclRefExpr(const DeclRefExpr *Ref) {
    Found |= Ref->getDecl() == Needle;
    return !Found;
  }

  bool found() const { return Found; }

private:
  const ValueDecl *Needle;
  bool Found = false;
};

bool references(const Stmt *S, const ValueDecl *D) {
  if (!S || !D)
    return false;
  RefVisitor Visitor(D);
  Visitor.TraverseStmt(const_cast<Stmt *>(S));
  return Visitor.found();
}

class CallVisitor final : public RecursiveASTVisitor<CallVisitor> {
public:
  explicit CallVisitor(StringRef Wanted) : Wanted(Wanted) {}

  bool VisitCallExpr(const CallExpr *Call) {
    Found |= callName(Call) == Wanted;
    return !Found;
  }

  bool found() const { return Found; }

private:
  StringRef Wanted;
  bool Found = false;
};

bool containsCall(const Stmt *S, StringRef Name) {
  if (!S)
    return false;
  CallVisitor Visitor(Name);
  Visitor.TraverseStmt(const_cast<Stmt *>(S));
  return Visitor.found();
}

class FunctionFactVisitor final
    : public RecursiveASTVisitor<FunctionFactVisitor> {
public:
  explicit FunctionFactVisitor(FunctionFacts &Facts) : Facts(Facts) {}

  bool VisitCallExpr(const CallExpr *Call) {
    Facts.Calls.push_back(Call);
    return true;
  }

  bool VisitMemberExpr(const MemberExpr *Member) {
    Facts.Members.push_back(Member);
    return true;
  }

  bool VisitIfStmt(const IfStmt *If) {
    Facts.Ifs.push_back(If);
    return true;
  }

  bool VisitConditionalOperator(const ConditionalOperator *Conditional) {
    Facts.Conditionals.push_back(Conditional);
    return true;
  }

  bool VisitBinaryOperator(const BinaryOperator *Binary) {
    Facts.BinaryOperators.push_back(Binary);
    if (Binary->isAssignmentOp())
      Facts.Assignments.push_back({Binary, memberPath(Binary->getLHS())});
    return true;
  }

private:
  FunctionFacts &Facts;
};

class FunctionCollector final : public RecursiveASTVisitor<FunctionCollector> {
public:
  explicit FunctionCollector(const SourceManager &SM) : SM(SM) {}

  bool VisitFunctionDecl(const FunctionDecl *Function) {
    if (!Function->doesThisDeclarationHaveABody())
      return true;
    SourceLocation Loc = SM.getExpansionLoc(Function->getLocation());
    if (!Loc.isValid() || !SM.isWrittenInMainFile(Loc))
      return true;

    const FunctionDecl *Definition = Function->getDefinition();
    if (!Definition)
      return true;
    Functions.try_emplace(Definition->getNameAsString(), Definition);
    return true;
  }

  llvm::StringMap<const FunctionDecl *> Functions;

private:
  const SourceManager &SM;
};

class DmaResvAssertionCallbacks final : public PPCallbacks {
public:
  DmaResvAssertionCallbacks(
      const SourceManager &SM,
      llvm::SmallVectorImpl<SourceLocation> &DmaResvAssertions)
      : SM(SM), DmaResvAssertions(DmaResvAssertions) {}

  void MacroExpands(const Token &MacroNameTok, const MacroDefinition &,
                    SourceRange Range, const MacroArgs *) override {
    const IdentifierInfo *Identifier = MacroNameTok.getIdentifierInfo();
    if (!Identifier || Identifier->getName() != "dma_resv_assert_held")
      return;

    SourceLocation Loc = SM.getExpansionLoc(Range.getBegin());
    if (Loc.isValid() && SM.isWrittenInMainFile(Loc))
      DmaResvAssertions.push_back(Loc);
  }

private:
  const SourceManager &SM;
  llvm::SmallVectorImpl<SourceLocation> &DmaResvAssertions;
};

FunctionFacts collectFacts(const FunctionDecl *Function) {
  FunctionFacts Facts{Function};
  FunctionFactVisitor Visitor(Facts);
  Visitor.TraverseStmt(const_cast<Stmt *>(Function->getBody()));
  return Facts;
}

const ParmVarDecl *findParameter(const FunctionDecl *Function, StringRef Name) {
  for (const ParmVarDecl *Parameter : Function->parameters())
    if (Parameter->getName() == Name)
      return Parameter;
  return nullptr;
}

bool hasGuardBefore(const FunctionFacts &Facts, const ValueDecl *Value,
                    SourceLocation Use, const SourceManager &SM) {
  for (const IfStmt *If : Facts.Ifs)
    if (before(SM, If->getIfLoc(), Use) && references(If->getCond(), Value))
      return true;

  for (const ConditionalOperator *Conditional : Facts.Conditionals) {
    if (!references(Conditional->getCond(), Value))
      continue;
    if (within(SM, Use, Conditional->getTrueExpr()->getBeginLoc(),
               Conditional->getTrueExpr()->getEndLoc()) ||
        within(SM, Use, Conditional->getFalseExpr()->getBeginLoc(),
               Conditional->getFalseExpr()->getEndLoc()))
      return true;
  }

  for (const BinaryOperator *Binary : Facts.BinaryOperators) {
    if (Binary->getOpcode() != BO_LAnd || !references(Binary->getLHS(), Value))
      continue;
    if (within(SM, Use, Binary->getRHS()->getBeginLoc(),
               Binary->getRHS()->getEndLoc()))
      return true;
  }
  return false;
}

const CallExpr *findCall(const FunctionFacts &Facts, StringRef Name) {
  for (const CallExpr *Call : Facts.Calls)
    if (callName(Call) == Name)
      return Call;
  return nullptr;
}

const CallExpr *findCallAfter(const FunctionFacts &Facts, StringRef Name,
                              SourceLocation After, const SourceManager &SM) {
  const CallExpr *Best = nullptr;
  for (const CallExpr *Call : Facts.Calls) {
    if (callName(Call) != Name || !before(SM, After, Call->getExprLoc()))
      continue;
    if (!Best || before(SM, Call->getExprLoc(), Best->getExprLoc()))
      Best = Call;
  }
  return Best;
}

bool hasCallBefore(const FunctionFacts &Facts, StringRef Name,
                   SourceLocation Point, const SourceManager &SM) {
  for (const CallExpr *Call : Facts.Calls)
    if (callName(Call) == Name && before(SM, Call->getExprLoc(), Point))
      return true;
  return false;
}

bool hasMemberBefore(const FunctionFacts &Facts, StringRef Field,
                     SourceLocation Point, const SourceManager &SM) {
  for (const MemberExpr *Member : Facts.Members)
    if (Member->getMemberDecl()->getName() == Field &&
        before(SM, Member->getExprLoc(), Point))
      return true;
  return false;
}

bool rhsIsNull(const BinaryOperator *Assignment, ASTContext &Context) {
  const Expr *RHS = ignore(Assignment->getRHS());
  return RHS &&
         RHS->isNullPointerConstant(Context, Expr::NPC_ValueDependentIsNotNull);
}

bool nullAssignmentBetween(const FunctionFacts &Facts, StringRef Path,
                           SourceLocation Begin, SourceLocation End,
                           ASTContext &Context, const SourceManager &SM) {
  for (const AssignmentFact &Assignment : Facts.Assignments)
    if (Assignment.Path == Path && rhsIsNull(Assignment.Expr, Context) &&
        between(SM, Assignment.Expr->getExprLoc(), Begin, End))
      return true;
  return false;
}

bool callUsesPath(const CallExpr *Call, StringRef Suffix) {
  for (const Expr *Argument : Call->arguments()) {
    class PathVisitor final : public RecursiveASTVisitor<PathVisitor> {
    public:
      explicit PathVisitor(StringRef Suffix) : Suffix(Suffix) {}
      bool VisitMemberExpr(const MemberExpr *Member) {
        Found |= pathEndsWith(memberPath(Member), Suffix);
        return !Found;
      }
      bool found() const { return Found; }

    private:
      StringRef Suffix;
      bool Found = false;
    } Visitor(Suffix);
    Visitor.TraverseStmt(const_cast<Expr *>(Argument));
    if (Visitor.found())
      return true;
  }
  return false;
}

bool hasKvAllocator(const FunctionFacts &Facts) {
  return llvm::any_of(Facts.Calls, [](const CallExpr *Call) {
    StringRef Name = callName(Call);
    return Name.contains("kvmalloc") || Name.contains("kvzalloc") ||
           Name.contains("kvcalloc");
  });
}

void diagnoseNullableImporterOps(DmaBufMappingRfcCheck &Check,
                                 const FunctionFacts &Facts,
                                 const SourceManager &SM) {
  StringRef Name = Facts.Function->getName();
  if (!Name.contains("dma_buf_") || !Name.contains("dynamic_attach"))
    return;

  const ParmVarDecl *ImporterOps =
      findParameter(Facts.Function, "importer_ops");
  if (!ImporterOps)
    return;

  for (const MemberExpr *Member : Facts.Members) {
    if (Member->getMemberDecl()->getName() != "allow_peer2peer" ||
        !pathEndsWith(memberPath(Member->getBase()), "importer_ops") ||
        hasGuardBefore(Facts, ImporterOps, Member->getExprLoc(), SM))
      continue;
    Check.diag(Member->getExprLoc(),
               "DMABUF-RFC-01: nullable importer_ops is dereferenced while "
               "constructing the mapping match; static importers can pass "
               "null operations");
  }
}

void diagnoseCoreCallbackContract(DmaBufMappingRfcCheck &Check,
                                  const FunctionFacts &Facts,
                                  const SourceManager &SM) {
  if (Facts.Function->getName() != "dma_buf_mapping_attach")
    return;

  for (const CallExpr *Call : Facts.Calls) {
    if (Call->getDirectCallee() || callName(Call) != "match_mapping")
      continue;

    llvm::SmallVector<StringRef, 3> Missing;
    for (StringRef Field : {"dmabuf", "importer_ops", "importer_priv"}) {
      bool Initialized = llvm::any_of(
          Facts.Assignments, [&](const AssignmentFact &Assignment) {
            return pathEndsWith(Assignment.Path, ("attach." + Field).str()) &&
                   before(SM, Assignment.Expr->getExprLoc(),
                          Call->getExprLoc());
          });
      if (!Initialized)
        Missing.push_back(Field);
    }

    if (!Missing.empty())
      Check.diag(Call->getExprLoc(),
                 "DMABUF-RFC-02: match_mapping runs before importer-visible "
                 "attachment state is initialized (%0)")
          << llvm::join(Missing, ", ");

    if (!hasCallBefore(Facts, "dma_resv_lock", Call->getExprLoc(), SM))
      Check.diag(Call->getExprLoc(),
                 "DMABUF-RFC-03: match_mapping is invoked without the "
                 "DMA-buf reservation lock; callbacks in this series consume "
                 "state protected by that lock");
  }
}

void diagnoseMatchCallbackUse(DmaBufMappingRfcCheck &Check,
                              const FunctionFacts &Facts,
                              ArrayRef<SourceLocation> DmaResvAssertions,
                              const SourceManager &SM) {
  if (!Facts.Function->getName().ends_with("match_mapping"))
    return;

  if (const CallExpr *Use = findCall(Facts, "dma_buf_attach_adev"))
    Check.diag(
        Use->getExprLoc(),
        "DMABUF-RFC-04: match_mapping reads the importer device from "
        "an attachment which dma_buf_mapping_attach has not initialized");

  SourceLocation AssertLoc;
  if (const CallExpr *Assert = findCall(Facts, "dma_resv_assert_held")) {
    AssertLoc = Assert->getExprLoc();
  } else {
    for (SourceLocation Loc : DmaResvAssertions)
      if (within(SM, Loc, Facts.Function->getBody()->getBeginLoc(),
                 Facts.Function->getBody()->getEndLoc())) {
        AssertLoc = Loc;
        break;
      }
  }

  if (AssertLoc.isValid())
    Check.diag(AssertLoc,
               "DMABUF-RFC-05: this callback requires dma_resv, but "
               "dma_buf_mapping_attach invokes match_mapping before taking it");
}

void diagnosePalRevocation(DmaBufMappingRfcCheck &Check,
                           const FunctionFacts &Facts,
                           const SourceManager &SM) {
  if (!Facts.Function->getName().ends_with("pal_map_phys"))
    return;

  for (const MemberExpr *Member : Facts.Members) {
    if (Member->getMemberDecl()->getName() != "phys_vec" ||
        hasMemberBefore(Facts, "revoked", Member->getExprLoc(), SM))
      continue;
    Check.diag(Member->getExprLoc(),
               "DMABUF-RFC-06: PAL map copies revocable physical ranges "
               "without rejecting a revoked exporter under dma_resv");
    return;
  }
}

void diagnosePalPublication(DmaBufMappingRfcCheck &Check,
                            const FunctionFacts &Facts, ASTContext &Context,
                            const SourceManager &SM) {
  for (const AssignmentFact &Assignment : Facts.Assignments) {
    if (!pathEndsWith(Assignment.Path, "dmabuf.exp_phys") ||
        !containsCall(Assignment.Expr->getRHS(), "dma_buf_pal_map_phys"))
      continue;

    const CallExpr *Unlock = findCallAfter(Facts, "dma_resv_unlock",
                                           Assignment.Expr->getExprLoc(), SM);
    if (!Unlock || !nullAssignmentBetween(Facts, Assignment.Path,
                                          Assignment.Expr->getExprLoc(),
                                          Unlock->getExprLoc(), Context, SM))
      Check.diag(Assignment.Expr->getExprLoc(),
                 "DMABUF-RFC-07: map_phys result is stored directly in live "
                 "exp_phys before ERR_PTR validation and remains published "
                 "on the error path");

    if (!Unlock)
      continue;

    for (const AssignmentFact &AttachAssignment : Facts.Assignments) {
      if (!pathEndsWith(AttachAssignment.Path, "dmabuf.attach") ||
          !before(SM, Unlock->getExprLoc(),
                  AttachAssignment.Expr->getExprLoc()))
        continue;
      Check.diag(Unlock->getExprLoc(),
                 "DMABUF-RFC-08: dma_resv is released after publishing "
                 "exp_phys but before publishing attach; move_notify can "
                 "observe a partially initialized mapping");
      break;
    }
  }

  for (const CallExpr *Unmap : Facts.Calls) {
    if (callName(Unmap) != "dma_buf_pal_unmap_phys" ||
        !callUsesPath(Unmap, "dmabuf.exp_phys"))
      continue;
    const CallExpr *Unlock =
        findCallAfter(Facts, "dma_resv_unlock", Unmap->getExprLoc(), SM);
    if (!Unlock)
      continue;

    StringRef Path;
    for (const AssignmentFact &Assignment : Facts.Assignments)
      if (pathEndsWith(Assignment.Path, "dmabuf.exp_phys")) {
        Path = Assignment.Path;
        break;
      }
    if (Path.empty())
      Path = "pages.dmabuf.exp_phys";

    if (!nullAssignmentBetween(Facts, Path, Unmap->getExprLoc(),
                               Unlock->getExprLoc(), Context, SM))
      Check.diag(Unlock->getExprLoc(),
                 "DMABUF-RFC-09: PAL storage is released while exp_phys "
                 "remains published across dma_resv_unlock");
  }
}

void diagnoseAllocatorPairs(DmaBufMappingRfcCheck &Check,
                            const llvm::StringMap<FunctionFacts> &AllFacts) {
  for (const auto &Entry : AllFacts) {
    StringRef UnmapName = Entry.getKey();
    if (!UnmapName.ends_with("unmap_phys"))
      continue;

    std::string MapName = UnmapName.str();
    size_t Pos = MapName.rfind("unmap_phys");
    MapName.replace(Pos, StringRef("unmap_phys").size(), "map_phys");
    auto MapIt = AllFacts.find(MapName);
    if (MapIt == AllFacts.end())
      continue;

    if (!hasKvAllocator(MapIt->second))
      continue;

    for (const CallExpr *Free : Entry.getValue().Calls)
      if (callName(Free) == "kfree")
        Check.diag(Free->getExprLoc(),
                   "DMABUF-RFC-10: matching map_phys can return vmalloc "
                   "storage from kvmalloc; release it with kvfree, not kfree");
  }
}

} // namespace

void DmaBufMappingRfcCheck::registerPPCallbacks(const SourceManager &SM,
                                                Preprocessor *PP,
                                                Preprocessor *) {
  PP->addPPCallbacks(
      std::make_unique<DmaResvAssertionCallbacks>(SM, DmaResvAssertions));
}

void DmaBufMappingRfcCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(translationUnitDecl().bind("translation-unit"), this);
}

void DmaBufMappingRfcCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *TU =
      Result.Nodes.getNodeAs<TranslationUnitDecl>("translation-unit");
  if (!TU || !Result.Context || !Result.SourceManager)
    return;

  ASTContext &Context = *Result.Context;
  const SourceManager &SM = *Result.SourceManager;
  FunctionCollector Collector(SM);
  Collector.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));

  llvm::StringMap<FunctionFacts> AllFacts;
  for (const auto &Entry : Collector.Functions)
    AllFacts.try_emplace(Entry.getKey(), collectFacts(Entry.getValue()));

  for (const auto &Entry : AllFacts) {
    const FunctionFacts &Facts = Entry.getValue();
    diagnoseNullableImporterOps(*this, Facts, SM);
    diagnoseCoreCallbackContract(*this, Facts, SM);
    diagnoseMatchCallbackUse(*this, Facts, DmaResvAssertions, SM);
    diagnosePalRevocation(*this, Facts, SM);
    diagnosePalPublication(*this, Facts, Context, SM);
  }
  diagnoseAllocatorPairs(*this, AllFacts);
}

} // namespace clang::tidy::linuxkernel
