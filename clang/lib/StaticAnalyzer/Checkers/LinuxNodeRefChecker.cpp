//===- LinuxNodeRefChecker.cpp - Leaked device tree node references -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// alpha.linux.NodeRef finds a device tree node that a function looked up and
// forgot to drop:
//
//   np = of_parse_phandle(dev->of_node, "memory-region", 0);
//   if (!np)
//     return -ENODEV;
//   ret = of_address_to_resource(np, 0, &res);
//   if (ret)
//     return ret;                 <- np is never put
//   of_node_put(np);
//
// The lookup functions of <linux/of.h> return a node with a reference that
// the caller owns.  The reference is dropped by of_node_put(), by passing
// the node as the starting point of the next lookup, or by storing or
// returning the node, which hands the reference on.  A node that goes out of
// reach in any other way is reported.
//
// Passing a node to a function does not hand the reference on: a callee that
// keeps the node takes its own reference.  A variable declared with
// __free(device_node) is left alone, because the analyzer does not run
// cleanup functions.
//
//===----------------------------------------------------------------------===//

#include "LinuxKernelModeling.h"
#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"

using namespace clang;
using namespace ento;
using namespace linuxkernel;

/// The nodes this path owns a reference to, with the lookup that returned
/// each of them.
REGISTER_MAP_WITH_PROGRAMSTATE(OwnedNodes, SymbolRef, const Expr *)

namespace {

class LinuxNodeRefChecker
    : public Checker<check::PreCall, check::PostCall, check::DeadSymbols,
                     check::PointerEscape, check::PreStmt<ReturnStmt>> {
  const BugType Leak{this, "Device tree node reference leak", "Linux kernel",
                     /*SuppressOnSink=*/true};

  static bool storedInCleanupVariable(const Expr *Lookup, CheckerContext &C);

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &Reaper, CheckerContext &C) const;
  ProgramStateRef checkPointerEscape(ProgramStateRef State,
                                     const InvalidatedSymbols &Escaped,
                                     const CallEvent *Call,
                                     PointerEscapeKind Kind) const;
};

} // namespace

static const FunctionDecl *getNamedCallee(const CallEvent &Call) {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  return FD && FD->getIdentifier() && FD->getDeclContext()->isFileContext()
             ? FD
             : nullptr;
}

/// Whether the result of \p Lookup initializes or is assigned to a variable
/// that has a cleanup function.
bool LinuxNodeRefChecker::storedInCleanupVariable(const Expr *Lookup,
                                                  CheckerContext &C) {
  const ParentMap &Parents = C.getCurrentAnalysisDeclContext()->getParentMap();
  const Stmt *Parent = Parents.getParentIgnoreParenCasts(
      const_cast<Stmt *>(cast<Stmt>(Lookup)));
  const VarDecl *VD = nullptr;
  if (const auto *DS = dyn_cast_or_null<DeclStmt>(Parent)) {
    for (const Decl *D : DS->decls())
      if (const auto *Candidate = dyn_cast<VarDecl>(D))
        if (Candidate->getInit() &&
            Candidate->getInit()->IgnoreParenCasts() == Lookup)
          VD = Candidate;
  } else if (const auto *BO = dyn_cast_or_null<BinaryOperator>(Parent)) {
    if (BO->getOpcode() == BO_Assign)
      if (const auto *DRE =
              dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenCasts()))
        VD = dyn_cast<VarDecl>(DRE->getDecl());
  }
  return VD && VD->hasAttr<CleanupAttr>();
}

void LinuxNodeRefChecker::checkPreCall(const CallEvent &Call,
                                       CheckerContext &C) const {
  const FunctionDecl *FD = getNamedCallee(Call);
  if (!FD)
    return;
  // The argument whose reference the callee drops.
  int Dropped = -1;
  if (FD->getName() == "of_node_put")
    Dropped = 0;
  else if (!acquiresNodeReference(FD->getName(), Dropped))
    return;
  if (Dropped < 0 || unsigned(Dropped) >= Call.getNumArgs())
    return;
  SymbolRef Node = Call.getArgSVal(Dropped).getAsSymbol();
  ProgramStateRef State = C.getState();
  if (Node && State->get<OwnedNodes>(Node))
    C.addTransition(State->remove<OwnedNodes>(Node));
}

void LinuxNodeRefChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
  const FunctionDecl *FD = getNamedCallee(Call);
  const Expr *Origin = Call.getOriginExpr();
  SymbolRef Node = Call.getReturnValue().getAsSymbol();
  if (!FD || !Origin || !Node)
    return;
  ProgramStateRef State = C.getState();
  bool Cleanup = storedInCleanupVariable(Origin, C);
  int Dropped;
  if (acquiresNodeReference(FD->getName(), Dropped)) {
    if (!Cleanup)
      C.addTransition(State->set<OwnedNodes>(Node, Origin));
  } else if (Cleanup && State->get<OwnedNodes>(Node)) {
    // An inline wrapper of a lookup whose result goes to such a variable.
    C.addTransition(State->remove<OwnedNodes>(Node));
  }
}

/// The caller of the function under analysis gets the reference.
void LinuxNodeRefChecker::checkPreStmt(const ReturnStmt *RS,
                                       CheckerContext &C) const {
  if (!C.inTopFrame() || !RS->getRetValue())
    return;
  SymbolRef Node = C.getSVal(RS->getRetValue()).getAsSymbol();
  ProgramStateRef State = C.getState();
  if (Node && State->get<OwnedNodes>(Node))
    C.addTransition(State->remove<OwnedNodes>(Node));
}

void LinuxNodeRefChecker::checkDeadSymbols(SymbolReaper &Reaper,
                                           CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  llvm::SmallVector<std::pair<SymbolRef, const Expr *>, 2> Leaked;
  for (const auto &[Node, Lookup] : State->get<OwnedNodes>()) {
    if (!Reaper.isDead(Node))
      continue;
    // A lookup that found nothing has nothing to drop.
    if (!State->getConstraintManager().isNull(State, Node).isConstrainedTrue())
      Leaked.push_back({Node, Lookup});
    State = State->remove<OwnedNodes>(Node);
  }
  if (Leaked.empty()) {
    C.addTransition(State);
    return;
  }

  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;
  for (const auto &[Node, Lookup] : Leaked) {
    const FunctionDecl *Callee = cast<CallExpr>(Lookup)->getDirectCallee();
    std::string Message =
        ("Device tree node returned by '" +
         (Callee ? Callee->getName() : StringRef("the lookup")) +
         "' is not released with of_node_put()")
            .str();
    // One report for each lookup, however many paths lose its result.
    PathDiagnosticLocation Unique = PathDiagnosticLocation::createBegin(
        Lookup, C.getSourceManager(), C.getStackFrame());
    auto R = std::make_unique<PathSensitiveBugReport>(
        Leak, Message, N, Unique, C.getStackFrame()->getDecl());
    R->addRange(Lookup->getSourceRange());
    R->markInteresting(Node);
    C.emitReport(std::move(R));
  }
}

ProgramStateRef LinuxNodeRefChecker::checkPointerEscape(
    ProgramStateRef State, const InvalidatedSymbols &Escaped,
    const CallEvent *Call, PointerEscapeKind Kind) const {
  // A node that is merely passed to a function stays ours, unless the
  // function is named like one that drops what it is given.
  if (Kind == PSK_DirectEscapeOnCall) {
    const FunctionDecl *FD = Call ? getNamedCallee(*Call) : nullptr;
    if (!FD)
      return State;
    StringRef Name = FD->getName();
    bool MayRelease = Name.contains("put") || Name.contains("release") ||
                      Name.contains("free") || Name.contains("destroy") ||
                      Name.contains("unregister") || Name.contains("remove") ||
                      Name.contains("cleanup") || Name.contains("detach");
    if (!MayRelease) {
      // A node that is passed as a "void *" is context data that the callee
      // keeps for later, as devm_add_action_or_reset() does for the
      // function that will drop the reference.
      unsigned NumArgs = std::min<unsigned>(Call->getNumArgs(),
                                            FD->getNumParams());
      for (unsigned I = 0; I != NumArgs; ++I) {
        QualType Type = FD->getParamDecl(I)->getType();
        SymbolRef Node = Call->getArgSVal(I).getAsSymbol();
        if (Node && Type->isVoidPointerType() &&
            !Type->getPointeeType().isConstQualified())
          State = State->remove<OwnedNodes>(Node);
      }
      return State;
    }
  }
  for (SymbolRef Node : Escaped)
    State = State->remove<OwnedNodes>(Node);
  return State;
}

void ento::registerLinuxNodeRefChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<LinuxNodeRefChecker>();
  linuxkernel::addInterest(Mgr, linuxkernel::NodeReferences);
}

bool ento::shouldRegisterLinuxNodeRefChecker(const CheckerManager &Mgr) {
  return true;
}
