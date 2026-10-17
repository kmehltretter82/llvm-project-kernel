//===- QEMUGuestInputChecker.cpp ----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This checker reports guest-controlled shift amounts that have not been
// constrained to the width of the promoted left operand.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <memory>

using namespace clang;
using namespace ento;

namespace {

class QEMUGuestInputChecker : public Checker<check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> UnboundedShiftBug;

  static bool isProvablyValidShift(const BinaryOperator *Shift,
                                   CheckerContext &C) {
    ProgramStateRef State = C.getState();
    SVal Amount = C.getSVal(Shift->getRHS());
    SValBuilder &SVB = C.getSValBuilder();
    const llvm::APSInt *Minimum = SVB.getMinValue(State, Amount);
    const llvm::APSInt *Maximum = SVB.getMaxValue(State, Amount);
    if (!Minimum || !Maximum || Minimum->isNegative())
      return false;

    unsigned Width = C.getASTContext().getTypeSize(Shift->getLHS()->getType());
    return Maximum->getLimitedValue(Width) < Width;
  }

  static bool isProvablyInvalidShift(const BinaryOperator *Shift,
                                     CheckerContext &C) {
    ProgramStateRef State = C.getState();
    SVal Amount = C.getSVal(Shift->getRHS());
    SValBuilder &SVB = C.getSValBuilder();
    const llvm::APSInt *Minimum = SVB.getMinValue(State, Amount);
    const llvm::APSInt *Maximum = SVB.getMaxValue(State, Amount);
    unsigned Width = C.getASTContext().getTypeSize(Shift->getLHS()->getType());

    if (Maximum && Maximum->isNegative())
      return true;
    return Minimum && !Minimum->isNegative() &&
           Minimum->getLimitedValue(Width) >= Width;
  }

public:
  void checkPreStmt(const BinaryOperator *Shift, CheckerContext &C) const {
    if (!Shift->isShiftOp())
      return;

    ProgramStateRef State = C.getState();
    SVal Amount = C.getSVal(Shift->getRHS());
    if (!taint::isTainted(State, Amount) || isProvablyValidShift(Shift, C) ||
        isProvablyInvalidShift(Shift, C))
      return;

    ExplodedNode *Node = C.generateNonFatalErrorNode();
    if (!Node)
      return;

    if (!UnboundedShiftBug)
      UnboundedShiftBug = std::make_unique<BugType>(
          this, "Unbounded guest-controlled shift", "QEMU guest input");

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *UnboundedShiftBug,
        "guest-controlled shift amount is not bounded to the width of the "
        "promoted left operand",
        Node);
    Report->addRange(Shift->getRHS()->getSourceRange());
    C.emitReport(std::move(Report));
  }
};

} // namespace

void ento::registerQEMUGuestInputChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<QEMUGuestInputChecker>();
}

bool ento::shouldRegisterQEMUGuestInputChecker(const CheckerManager &Mgr) {
  return true;
}
