//=== QEMUErrorOwnershipChecker.cpp - Track QEMU Error ownership -*- C++
//-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This checker models the QEMU Error API rule that reporting, freeing, or
// propagating an Error object consumes it.  It diagnoses a later use or a
// later attempt to reuse a local containing the consumed pointer as an
// Error ** output destination.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include <algorithm>
#include <optional>
#include <string>

using namespace clang;
using namespace ento;

namespace {

class QEMUErrorOwnershipChecker
    : public Checker<check::PreCall, check::DeadSymbols> {
  const BugType UseAfterConsume{this, "Use of consumed QEMU Error object",
                                "QEMU Error ownership"};
  const BugType StaleDestination{
      this, "Reuse of consumed QEMU Error destination", "QEMU Error ownership"};

  static bool isErrorRecord(QualType T) {
    T = T.getCanonicalType().getUnqualifiedType();
    const auto *RT = T->getAs<RecordType>();
    const RecordDecl *RD = RT ? RT->getDecl() : nullptr;
    return RD && RD->getIdentifier() && RD->getName() == "Error";
  }

  static bool isErrorPointer(QualType T) {
    T = T.getCanonicalType().getUnqualifiedType();
    const auto *PT = T->getAs<PointerType>();
    return PT && isErrorRecord(PT->getPointeeType());
  }

  static bool isErrorPointerPointer(QualType T) {
    T = T.getCanonicalType().getUnqualifiedType();
    const auto *PT = T->getAs<PointerType>();
    return PT && isErrorPointer(PT->getPointeeType());
  }

  static std::optional<unsigned> consumedArgument(const CallEvent &Call) {
    const IdentifierInfo *II = Call.getCalleeIdentifier();
    if (!II)
      return std::nullopt;
    StringRef Name = II->getName();
    if (Name == "error_propagate" || Name == "error_propagate_prepend")
      return 1;
    if (Name == "error_free" || Name == "error_report_err" ||
        Name == "warn_report_err" || Name == "error_reportf_err" ||
        Name == "warn_reportf_err" || Name == "warn_report_err_once_cond")
      return Name == "warn_report_err_once_cond" ? 1 : 0;
    return std::nullopt;
  }

  void report(const BugType &Type, StringRef Message, SymbolRef Sym,
              const Expr *Arg, CheckerContext &C) const {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto R = std::make_unique<PathSensitiveBugReport>(Type, Message, N);
    if (Arg)
      R->addRange(Arg->getSourceRange());
    R->markInteresting(Sym);
    C.emitReport(std::move(R));
  }

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const;
};

} // namespace

REGISTER_SET_WITH_PROGRAMSTATE(ConsumedQEMUErrors, SymbolRef)

void QEMUErrorOwnershipChecker::checkPreCall(const CallEvent &Call,
                                             CheckerContext &C) const {
  const auto *CE = dyn_cast_or_null<CallExpr>(Call.getOriginExpr());
  if (!CE)
    return;

  ProgramStateRef State = C.getState();
  std::optional<unsigned> ConsumedArg = consumedArgument(Call);

  for (unsigned I = 0, E = std::min(Call.getNumArgs(), CE->getNumArgs());
       I != E; ++I) {
    const Expr *Arg = CE->getArg(I);
    QualType ArgType = Arg->getType();
    SymbolRef Sym = nullptr;

    if (isErrorPointer(ArgType)) {
      Sym = Call.getArgSVal(I).getAsSymbol();
      if (Sym && State->contains<ConsumedQEMUErrors>(Sym)) {
        StringRef Message =
            ConsumedArg && *ConsumedArg == I
                ? "QEMU Error object is consumed more than once"
                : "QEMU Error object is used after its ownership "
                  "was transferred";
        report(UseAfterConsume, Message, Sym, Arg, C);
        return;
      }
    } else if (isErrorPointerPointer(ArgType)) {
      const MemRegion *Region = Call.getArgSVal(I).getAsRegion();
      Sym = Region ? State->getSVal(Region).getAsSymbol() : nullptr;
      if (Sym && State->contains<ConsumedQEMUErrors>(Sym)) {
        report(StaleDestination,
               "QEMU Error output destination still contains a consumed "
               "pointer; reset it to null before reuse",
               Sym, Arg, C);
        return;
      }
    }
  }

  if (!ConsumedArg || *ConsumedArg >= Call.getNumArgs())
    return;

  SVal V = Call.getArgSVal(*ConsumedArg);
  SymbolRef Sym = V.getAsSymbol();
  std::optional<DefinedOrUnknownSVal> DV = V.getAs<DefinedOrUnknownSVal>();
  if (!Sym || !DV)
    return;

  ProgramStateRef NonNullState;
  ProgramStateRef NullState;
  std::tie(NonNullState, NullState) = State->assume(*DV);
  if (NullState)
    C.addTransition(NullState);
  if (!NonNullState)
    return;

  NonNullState = NonNullState->add<ConsumedQEMUErrors>(Sym);
  const NoteTag *OwnershipNote =
      C.getNoteTag([Sym](PathSensitiveBugReport &BR) -> std::string {
        if (!BR.isInteresting(Sym))
          return "";
        return "Ownership of the QEMU Error object is transferred here";
      });
  C.addTransition(NonNullState, OwnershipNote);
}

void QEMUErrorOwnershipChecker::checkDeadSymbols(SymbolReaper &SymReaper,
                                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  ProgramStateRef Updated = State;
  for (SymbolRef Sym : State->get<ConsumedQEMUErrors>())
    if (SymReaper.isDead(Sym))
      Updated = Updated->remove<ConsumedQEMUErrors>(Sym);
  if (Updated != State)
    C.addTransition(Updated);
}

void ento::registerQEMUErrorOwnershipChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<QEMUErrorOwnershipChecker>();
}

bool ento::shouldRegisterQEMUErrorOwnershipChecker(const CheckerManager &Mgr) {
  return true;
}
