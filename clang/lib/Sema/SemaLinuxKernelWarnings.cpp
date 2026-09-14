//===- SemaLinuxKernelWarnings.cpp - Linux kernel diagnostics -----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements opt-in diagnostics for Linux kernel API contracts and
// coding conventions.
//
//===----------------------------------------------------------------------===//

#include "SemaLinuxKernelWarnings.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DynamicRecursiveASTVisitor.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/DiagnosticSema.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/Sema/Sema.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSwitch.h"
#include <optional>
#include <utility>

using namespace clang;

namespace {

enum class LinuxKernelAPIKind {
  None,
  UsercopyResidual,
  NullablePointer,
  KmallocPointer,
  VmallocPointer,
  KvmallocPointer,
  DevmPointer,
  ConstKmallocPointer,
  ErrorPointer,
  IRQNumber,
};

struct LinuxKernelAPIOrigin {
  LinuxKernelAPIKind Kind = LinuxKernelAPIKind::None;
  const FunctionDecl *Callee = nullptr;

  explicit operator bool() const { return Kind != LinuxKernelAPIKind::None; }

  StringRef getName() const {
    return Callee && Callee->getIdentifier() ? Callee->getName() : StringRef();
  }
};

static LinuxKernelAPIKind classifyLinuxKernelAPI(StringRef Name) {
  return llvm::StringSwitch<LinuxKernelAPIKind>(Name)
      // uaccess helpers return a residual byte count: zero means success and
      // any positive value means that some bytes were not copied.
      .Cases({"copy_from_user", "copy_to_user"},
             LinuxKernelAPIKind::UsercopyResidual)
      .Cases({"__copy_from_user", "__copy_to_user"},
             LinuxKernelAPIKind::UsercopyResidual)
      .Cases({"__copy_from_user_inatomic", "__copy_to_user_inatomic"},
             LinuxKernelAPIKind::UsercopyResidual)
      .Cases({"raw_copy_from_user", "raw_copy_to_user"},
             LinuxKernelAPIKind::UsercopyResidual)
      .Cases({"_copy_from_user", "_copy_to_user", "_inline_copy_from_user",
              "_inline_copy_to_user"},
             LinuxKernelAPIKind::UsercopyResidual)
      .Cases({"copy_in_user", "raw_copy_in_user"},
             LinuxKernelAPIKind::UsercopyResidual)
      .Cases({"clear_user", "__clear_user"},
             LinuxKernelAPIKind::UsercopyResidual)

      // Keep allocator families distinct so their matching release helpers
      // can be checked as well as their NULL failure convention.
      .Cases({"kmalloc", "kmalloc_noprof", "__kmalloc"},
             LinuxKernelAPIKind::KmallocPointer)
      .Cases({"__kmalloc_noprof", "__kmalloc_node", "__kmalloc_track_caller",
              "__kmalloc_node_track_caller"},
             LinuxKernelAPIKind::KmallocPointer)
      .Cases({"kmem_cache_alloc_trace", "kmem_cache_alloc_node_trace",
              "kmalloc_order", "kmalloc_order_trace"},
             LinuxKernelAPIKind::KmallocPointer)
      .Cases({"kzalloc", "kzalloc_noprof", "kcalloc"},
             LinuxKernelAPIKind::KmallocPointer)
      .Cases({"kmalloc_array", "kcalloc_noprof", "kmalloc_array_noprof"},
             LinuxKernelAPIKind::KmallocPointer)
      .Cases({"krealloc", "krealloc_noprof", "krealloc_array",
              "krealloc_array_noprof", "krealloc_node_align_noprof"},
             LinuxKernelAPIKind::KmallocPointer)
      .Cases({"kmemdup", "kmemdup_noprof", "kmemdup_nul", "kstrdup"},
             LinuxKernelAPIKind::KmallocPointer)
      .Cases({"kstrndup", "kasprintf", "kvasprintf"},
             LinuxKernelAPIKind::KmallocPointer)
      .Case("kstrdup_const", LinuxKernelAPIKind::ConstKmallocPointer)
      .Cases({"devm_kmalloc", "devm_kzalloc", "devm_kcalloc",
              "devm_kmalloc_array"},
             LinuxKernelAPIKind::DevmPointer)
      .Cases({"devm_kmemdup", "devm_kmemdup_array", "devm_kmemdup_const",
              "devm_kstrdup", "devm_kstrdup_const", "devm_kasprintf"},
             LinuxKernelAPIKind::DevmPointer)
      .Cases({"vmalloc", "vmalloc_noprof", "vzalloc", "vzalloc_noprof",
              "vmalloc_user", "vmalloc_user_noprof"},
             LinuxKernelAPIKind::VmallocPointer)
      .Cases({"vmalloc_node", "vmalloc_node_noprof", "vzalloc_node",
              "vzalloc_node_noprof", "vmalloc_array", "vmalloc_array_noprof"},
             LinuxKernelAPIKind::VmallocPointer)
      .Cases({"vcalloc", "vcalloc_noprof"}, LinuxKernelAPIKind::VmallocPointer)
      .Cases({"kvalloc", "kvzalloc"}, LinuxKernelAPIKind::KvmallocPointer)
      .Cases({"kvmalloc", "kvmalloc_node", "__kvmalloc_node_noprof",
              "kvmalloc_node_align_noprof", "kvcalloc", "kvcalloc_noprof",
              "kvcalloc_node_noprof", "kvmalloc_array",
              "kvmalloc_array_noprof"},
             LinuxKernelAPIKind::KvmallocPointer)
      .Cases({"clk_get_parent", "ioremap", "ioremap_wc", "ioremap_cache"},
             LinuxKernelAPIKind::NullablePointer)
      .Cases({"devm_ioremap", "devm_ioremap_wc", "alloc_workqueue",
              "create_singlethread_workqueue"},
             LinuxKernelAPIKind::NullablePointer)

      // These established interfaces return an ERR_PTR value on failure.
      .Cases({"filp_open", "file_open_root"}, LinuxKernelAPIKind::ErrorPointer)
      .Cases({"dentry_open", "class_create", "device_create"},
             LinuxKernelAPIKind::ErrorPointer)
      .Cases({"device_create_with_groups", "root_device_register",
              "__root_device_register", "kthread_create_on_node"},
             LinuxKernelAPIKind::ErrorPointer)
      .Cases({"kthread_create_worker", "kthread_create_worker_on_cpu",
              "devm_ioremap_resource"},
             LinuxKernelAPIKind::ErrorPointer)
      .Cases({"devm_ioremap_resource_wc", "devm_platform_ioremap_resource",
              "devm_platform_ioremap_resource_byname"},
             LinuxKernelAPIKind::ErrorPointer)
      .Cases({"devm_platform_get_and_ioremap_resource", "clk_get",
              "clk_get_sys", "of_clk_get", "of_clk_get_by_name"},
             LinuxKernelAPIKind::ErrorPointer)
      .Cases({"devm_clk_get", "devm_clk_get_enabled", "devm_clk_get_prepared",
              "regulator_get", "regulator_get_exclusive"},
             LinuxKernelAPIKind::ErrorPointer)
      .Cases({"devm_regulator_get", "devm_regulator_get_exclusive", "gpiod_get",
              "gpiod_get_index"},
             LinuxKernelAPIKind::ErrorPointer)
      .Cases({"devm_gpiod_get", "devm_gpiod_get_index", "pinctrl_get",
              "devm_pinctrl_get"},
             LinuxKernelAPIKind::ErrorPointer)
      .Cases({"__reset_control_get", "__devm_reset_control_get", "memdup_user",
              "memdup_user_nul"},
             LinuxKernelAPIKind::ErrorPointer)
      .Cases({"vmemdup_user", "strndup_user", "sock_alloc_file",
              "anon_inode_getfile"},
             LinuxKernelAPIKind::ErrorPointer)

      // The platform IRQ helpers return a positive IRQ or a negative errno.
      // Current implementations do not return zero.
      .Cases({"platform_get_irq", "platform_get_irq_byname",
              "platform_get_irq_optional", "platform_get_irq_byname_optional"},
             LinuxKernelAPIKind::IRQNumber)
      .Default(LinuxKernelAPIKind::None);
}

static bool isNullReturningKind(LinuxKernelAPIKind Kind) {
  switch (Kind) {
  case LinuxKernelAPIKind::NullablePointer:
  case LinuxKernelAPIKind::KmallocPointer:
  case LinuxKernelAPIKind::VmallocPointer:
  case LinuxKernelAPIKind::KvmallocPointer:
  case LinuxKernelAPIKind::DevmPointer:
  case LinuxKernelAPIKind::ConstKmallocPointer:
    return true;
  default:
    return false;
  }
}

static bool hasLinuxKernelErrnoReturnConvention(const FunctionDecl *FD) {
  if (!FD || !FD->getIdentifier())
    return false;

  StringRef Name = FD->getName();
  return Name.contains("ioctl") || Name.ends_with("_read") ||
         Name.ends_with("_read_iter") || Name.ends_with("_write") ||
         Name.ends_with("_write_iter") || Name.ends_with("_show") ||
         Name.ends_with("_store");
}

static bool returnsPositiveErrnoByContract(const FunctionDecl *FD) {
  if (!FD || !FD->getIdentifier())
    return false;

  StringRef Name = FD->getName();
  // Protocol-to-errno mapping helpers return the positive errno number so a
  // caller can choose how to encode it.  These are not kernel error returns.
  return Name.contains("to_errno") || Name == "get_error";
}

static bool isLinuxErrnoName(StringRef Name) {
  return llvm::StringSwitch<bool>(Name)
      .Cases({"EPERM", "ENOENT", "ESRCH", "EINTR", "EIO", "ENXIO"}, true)
      .Cases({"E2BIG", "ENOEXEC", "EBADF", "ECHILD", "EAGAIN", "ENOMEM"}, true)
      .Cases({"EACCES", "EFAULT", "ENOTBLK", "EBUSY", "EEXIST", "EXDEV"}, true)
      .Cases({"ENODEV", "ENOTDIR", "EISDIR", "EINVAL", "ENFILE", "EMFILE"},
             true)
      .Cases({"ENOTTY", "ETXTBSY", "EFBIG", "ENOSPC", "ESPIPE", "EROFS"}, true)
      .Cases({"EMLINK", "EPIPE", "EDOM", "ERANGE", "EDEADLK", "ENAMETOOLONG"},
             true)
      .Cases(
          {"ENOLCK", "ENOSYS", "ENOTEMPTY", "ELOOP", "EWOULDBLOCK", "ENOMSG"},
          true)
      .Cases({"EIDRM", "ECHRNG", "EL2NSYNC", "EL3HLT", "EL3RST", "ELNRNG"},
             true)
      .Cases({"EUNATCH", "ENOCSI", "EL2HLT", "EBADE", "EBADR", "EXFULL"}, true)
      .Cases({"ENOANO", "EBADRQC", "EBADSLT", "EDEADLOCK", "EBFONT", "ENOSTR"},
             true)
      .Cases({"ENODATA", "ETIME", "ENOSR", "ENONET", "ENOPKG", "EREMOTE"}, true)
      .Cases({"ENOLINK", "EADV", "ESRMNT", "ECOMM", "EPROTO", "EMULTIHOP"},
             true)
      .Cases({"EDOTDOT", "EBADMSG", "EFSBADCRC", "EOVERFLOW", "ENOTUNIQ",
              "EBADFD"},
             true)
      .Cases(
          {"EREMCHG", "ELIBACC", "ELIBBAD", "ELIBSCN", "ELIBMAX", "ELIBEXEC"},
          true)
      .Cases({"EILSEQ", "ERESTART", "ESTRPIPE", "EUSERS", "ENOTSOCK",
              "EDESTADDRREQ"},
             true)
      .Cases({"EMSGSIZE", "EPROTOTYPE", "ENOPROTOOPT", "EPROTONOSUPPORT",
              "ESOCKTNOSUPPORT", "EOPNOTSUPP"},
             true)
      .Cases({"EPFNOSUPPORT", "EAFNOSUPPORT", "EADDRINUSE", "EADDRNOTAVAIL",
              "ENETDOWN", "ENETUNREACH"},
             true)
      .Cases({"ENETRESET", "ECONNABORTED", "ECONNRESET", "ENOBUFS", "EISCONN",
              "ENOTCONN"},
             true)
      .Cases({"ESHUTDOWN", "ETOOMANYREFS", "ETIMEDOUT", "ECONNREFUSED",
              "EHOSTDOWN", "EHOSTUNREACH"},
             true)
      .Cases({"EALREADY", "EINPROGRESS", "ESTALE", "EUCLEAN", "EFSCORRUPTED",
              "ENOTNAM"},
             true)
      .Cases({"ENAVAIL", "EISNAM", "EREMOTEIO", "EDQUOT", "ENOMEDIUM",
              "EMEDIUMTYPE"},
             true)
      .Cases({"ECANCELED", "ECANCELLED", "ENOKEY", "EKEYEXPIRED", "EKEYREVOKED",
              "EKEYREJECTED"},
             true)
      .Cases({"EOWNERDEAD", "ENOTRECOVERABLE", "ERFKILL", "EHWPOISON", "EFTYPE",
              "EPROBE_DEFER"},
             true)
      .Default(false);
}

static StringRef getLinuxErrnoMacroName(const Expr *E, const Sema &S) {
  if (!E)
    return {};
  E = E->IgnoreParenImpCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(E))
    if (UO->getOpcode() == UO_Plus || UO->getOpcode() == UO_Minus)
      return getLinuxErrnoMacroName(UO->getSubExpr(), S);

  SourceLocation Loc = E->getExprLoc();
  if (!Loc.isMacroID())
    return {};
  StringRef Name =
      Lexer::getImmediateMacroName(Loc, S.getSourceManager(), S.getLangOpts());
  return isLinuxErrnoName(Name) ? Name : StringRef();
}

static bool isLinuxAssertionMacroExpansion(const Expr *E, const Sema &S) {
  if (!E)
    return false;

  SourceLocation Loc = E->getExprLoc();
  if (!Loc.isMacroID())
    return false;
  StringRef Name =
      Lexer::getImmediateMacroName(Loc, S.getSourceManager(), S.getLangOpts());
  return llvm::StringSwitch<bool>(Name)
      .Cases({"WARN", "WARN_ON", "WARN_ONCE", "WARN_ON_ONCE"}, true)
      .Cases({"WARN_RATELIMIT", "WARN_ON_RATELIMIT", "BUG_ON"}, true)
      .Cases({"VM_BUG_ON", "VM_BUG_ON_PAGE", "VM_BUG_ON_FOLIO"}, true)
      .Cases({"VM_WARN_ON", "VM_WARN_ON_ONCE"}, true)
      .Default(false);
}

class LinuxKernelWarningsVisitor : public DynamicRecursiveASTVisitor {
  using DirectField = std::pair<const VarDecl *, const FieldDecl *>;

  Sema &S;
  const FunctionDecl *CurrentFunction;
  llvm::DenseMap<const VarDecl *, LinuxKernelAPIOrigin> VariableOrigins;
  llvm::DenseMap<DirectField, LinuxKernelAPIOrigin> FieldOrigins;
  llvm::SmallPtrSet<const Expr *, 4> CoveredNullTests;
  unsigned ControlFlowDepth = 0;
  bool AssignmentTrackingDisabled = false;

  static const VarDecl *getDirectVariable(const Expr *E) {
    if (!E)
      return nullptr;
    const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts());
    return DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  }

  static std::optional<DirectField> getDirectField(const Expr *E) {
    if (!E)
      return std::nullopt;
    const auto *ME = dyn_cast<MemberExpr>(E->IgnoreParenImpCasts());
    if (!ME)
      return std::nullopt;

    const Expr *Base = ME->getBase()->IgnoreParenImpCasts();
    if (!ME->isArrow()) {
      if (const auto *UO = dyn_cast<UnaryOperator>(Base))
        if (UO->getOpcode() == UO_Deref)
          Base = UO->getSubExpr()->IgnoreParenImpCasts();
    }
    const auto *DRE = dyn_cast<DeclRefExpr>(Base);
    const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
    const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
    if (!VD || !FD)
      return std::nullopt;
    return DirectField{VD, FD};
  }

  void forgetDirectStorage(const Expr *E) {
    if (const VarDecl *VD = getDirectVariable(E))
      VariableOrigins.erase(VD);
    if (std::optional<DirectField> Field = getDirectField(E))
      FieldOrigins.erase(*Field);
  }

  bool referToSameDirectValue(const Expr *LHS, const Expr *RHS) const {
    LHS = LHS ? LHS->IgnoreParenImpCasts() : nullptr;
    RHS = RHS ? RHS->IgnoreParenImpCasts() : nullptr;
    if (!LHS || !RHS)
      return false;
    if (LHS == RHS)
      return true;
    const VarDecl *LHSVariable = getDirectVariable(LHS);
    if (LHSVariable && LHSVariable == getDirectVariable(RHS))
      return true;
    std::optional<DirectField> LHSField = getDirectField(LHS);
    return LHSField && LHSField == getDirectField(RHS);
  }

  const Expr *getNegativeNullTestValue(const Expr *E,
                                       const Expr *&NullTest) const {
    E = E ? E->IgnoreParenImpCasts() : nullptr;
    NullTest = E;
    if (const auto *UO = dyn_cast_or_null<UnaryOperator>(E))
      return UO->getOpcode() == UO_LNot ? UO->getSubExpr() : nullptr;
    const auto *Comparison = dyn_cast_or_null<BinaryOperator>(E);
    if (Comparison && Comparison->getOpcode() == BO_EQ) {
      if (Comparison->getLHS()->isNullPointerConstant(
              S.getASTContext(), Expr::NPC_ValueDependentIsNotNull))
        return Comparison->getRHS();
      if (Comparison->getRHS()->isNullPointerConstant(
              S.getASTContext(), Expr::NPC_ValueDependentIsNotNull))
        return Comparison->getLHS();
    }
    return nullptr;
  }

  const Expr *getErrorPointerCheckValue(const Expr *E) const {
    E = E ? E->IgnoreParenImpCasts() : nullptr;
    const auto *Call = dyn_cast_or_null<CallExpr>(E);
    const FunctionDecl *Callee = Call ? Call->getDirectCallee() : nullptr;
    if (!Callee || !Callee->getIdentifier() || Call->getNumArgs() == 0)
      return nullptr;
    StringRef Name = Callee->getName();
    return Name == "IS_ERR" || Name == "IS_ERR_OR_NULL" ? Call->getArg(0)
                                                        : nullptr;
  }

  void recordCombinedErrorPointerGuard(const BinaryOperator *BO) {
    if (BO->getOpcode() != BO_LOr)
      return;

    const Expr *NullTest = nullptr;
    const Expr *NullValue = getNegativeNullTestValue(BO->getLHS(), NullTest);
    const Expr *CheckedValue = getErrorPointerCheckValue(BO->getRHS());
    if (!NullValue || !CheckedValue) {
      NullValue = getNegativeNullTestValue(BO->getRHS(), NullTest);
      CheckedValue = getErrorPointerCheckValue(BO->getLHS());
    }
    if (NullValue && CheckedValue &&
        referToSameDirectValue(NullValue, CheckedValue))
      CoveredNullTests.insert(NullTest);
  }

  void collectVariableValues(const Stmt *Node, const VarDecl *Variable,
                             llvm::SmallVectorImpl<const Expr *> &Values,
                             bool &HasOpaqueMutation) const {
    if (!Node)
      return;

    // Statement-expression wrappers sometimes seed their result temporary
    // with an argument and then replace it through inline assembly (xchg() is
    // a common example).  The initializer does not describe the returned
    // value in that case, so do not infer an API contract through the wrapper.
    if (isa<AsmStmt>(Node)) {
      HasOpaqueMutation = true;
      return;
    }

    if (const auto *DS = dyn_cast<DeclStmt>(Node)) {
      for (const Decl *D : DS->decls()) {
        const auto *VD = dyn_cast<VarDecl>(D);
        if (VD == Variable && VD->hasInit())
          Values.push_back(VD->getInit());
      }
    } else if (const auto *BO = dyn_cast<BinaryOperator>(Node)) {
      const auto *DRE =
          dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts());
      if (DRE && DRE->getDecl() == Variable) {
        if (BO->getOpcode() == BO_Assign)
          Values.push_back(BO->getRHS());
        else if (BO->isAssignmentOp())
          HasOpaqueMutation = true;
      }
    } else if (const auto *UO = dyn_cast<UnaryOperator>(Node)) {
      const auto *DRE =
          dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenImpCasts());
      if (DRE && DRE->getDecl() == Variable &&
          (UO->getOpcode() == UO_AddrOf || UO->isIncrementDecrementOp()))
        HasOpaqueMutation = true;
    }

    for (const Stmt *Child : Node->children())
      collectVariableValues(Child, Variable, Values, HasOpaqueMutation);
  }

  LinuxKernelAPIOrigin
  getOrigin(const Expr *E,
            llvm::SmallPtrSetImpl<const VarDecl *> &SeenVariables) const {
    if (!E)
      return {};

    E = E->IgnoreParenCasts();

    if (const auto *Call = dyn_cast<CallExpr>(E)) {
      const FunctionDecl *Callee = Call->getDirectCallee();
      if (!Callee || !Callee->getIdentifier())
        return {};
      if (Callee->getName() == "ERR_PTR") {
        if (Call->getNumArgs() == 0)
          return {};
        std::optional<llvm::APSInt> Error =
            Call->getArg(0)->getIntegerConstantExpr(S.getASTContext());
        // ERR_PTR(status) can be NULL when status is zero.  Treat it as an
        // error-pointer origin only when the negative status is proven.
        if (!Error || !Error->isNegative())
          return {};
        return {LinuxKernelAPIKind::ErrorPointer, Callee};
      }
      LinuxKernelAPIKind Kind = classifyLinuxKernelAPI(Callee->getName());
      return {Kind, Kind == LinuxKernelAPIKind::None ? nullptr : Callee};
    }

    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
      if (!VD || !SeenVariables.insert(VD).second)
        return {};
      auto It = VariableOrigins.find(VD);
      return It == VariableOrigins.end() ? LinuxKernelAPIOrigin{} : It->second;
    }

    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      (void)ME;
      std::optional<DirectField> Field = getDirectField(E);
      if (!Field)
        return {};
      auto It = FieldOrigins.find(*Field);
      return It == FieldOrigins.end() ? LinuxKernelAPIOrigin{} : It->second;
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_Assign)
        return getOrigin(BO->getRHS(), SeenVariables);
      return {};
    }

    if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
      llvm::SmallPtrSet<const VarDecl *, 8> TrueSeen;
      llvm::SmallPtrSet<const VarDecl *, 8> FalseSeen;
      TrueSeen.insert(SeenVariables.begin(), SeenVariables.end());
      FalseSeen.insert(SeenVariables.begin(), SeenVariables.end());
      LinuxKernelAPIOrigin True = getOrigin(CO->getTrueExpr(), TrueSeen);
      LinuxKernelAPIOrigin False = getOrigin(CO->getFalseExpr(), FalseSeen);
      return True.Kind == False.Kind && True.Callee == False.Callee
                 ? True
                 : LinuxKernelAPIOrigin{};
    }

    if (const auto *GSE = dyn_cast<GenericSelectionExpr>(E))
      if (!GSE->isResultDependent())
        return getOrigin(GSE->getResultExpr(), SeenVariables);

    if (const auto *CE = dyn_cast<ChooseExpr>(E))
      if (!CE->isConditionDependent())
        return getOrigin(CE->getChosenSubExpr(), SeenVariables);

    if (const auto *SE = dyn_cast<StmtExpr>(E)) {
      const CompoundStmt *Body = SE->getSubStmt();
      if (Body->body_empty())
        return {};

      const auto *Result = dyn_cast<Expr>(Body->body_back());
      if (!Result)
        return {};

      const auto *DRE = dyn_cast<DeclRefExpr>(Result->IgnoreParenImpCasts());
      const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
      if (!VD)
        return getOrigin(Result, SeenVariables);
      if (!SeenVariables.insert(VD).second)
        return {};

      llvm::SmallVector<const Expr *, 4> Values;
      bool HasOpaqueMutation = false;
      collectVariableValues(Body, VD, Values, HasOpaqueMutation);
      if (HasOpaqueMutation)
        return {};
      LinuxKernelAPIOrigin Common;
      for (const Expr *Value : Values) {
        llvm::SmallPtrSet<const VarDecl *, 8> ValueSeen;
        ValueSeen.insert(SeenVariables.begin(), SeenVariables.end());
        LinuxKernelAPIOrigin Candidate = getOrigin(Value, ValueSeen);
        if (!Candidate)
          return {};
        if (!Common)
          Common = Candidate;
        else if (Common.Kind != Candidate.Kind ||
                 Common.Callee != Candidate.Callee)
          return {};
      }
      return Common;
    }

    return {};
  }

  LinuxKernelAPIOrigin getOrigin(const Expr *E) const {
    llvm::SmallPtrSet<const VarDecl *, 8> SeenVariables;
    return getOrigin(E, SeenVariables);
  }

  static BinaryOperatorKind reverseComparison(BinaryOperatorKind Opcode) {
    switch (Opcode) {
    case BO_LT:
      return BO_GT;
    case BO_GT:
      return BO_LT;
    case BO_LE:
      return BO_GE;
    case BO_GE:
      return BO_LE;
    default:
      return Opcode;
    }
  }

  void checkUsercopyComparison(const BinaryOperator *BO) {
    if (!BO->isComparisonOp())
      return;

    LinuxKernelAPIOrigin Origin = getOrigin(BO->getLHS());
    const Expr *Other = BO->getRHS();
    BinaryOperatorKind Opcode = BO->getOpcode();
    if (Origin.Kind != LinuxKernelAPIKind::UsercopyResidual) {
      Origin = getOrigin(BO->getRHS());
      Other = BO->getLHS();
      Opcode = reverseComparison(Opcode);
    }
    if (Origin.Kind != LinuxKernelAPIKind::UsercopyResidual)
      return;

    std::optional<llvm::APSInt> Value =
        Other->getIntegerConstantExpr(S.getASTContext());
    if (!Value)
      return;

    const bool IsNegative = Value->isSigned() && Value->isNegative();
    const bool IsBadZeroOrdering = Value->isZero() && Opcode == BO_LT;
    if (!IsNegative && !IsBadZeroOrdering)
      return;

    S.Diag(BO->getOperatorLoc(), diag::warn_linux_kernel_usercopy_negative_test)
        << Origin.getName() << BO->getSourceRange();
  }

  void checkErrorPointerNullComparison(const BinaryOperator *BO) {
    // Diagnose only the negative test.  A positive `pointer != NULL` test is
    // useful after an IS_ERR() guard and cannot be judged without
    // path-sensitive knowledge of that guard.
    if (BO->getOpcode() != BO_EQ || CoveredNullTests.contains(BO) ||
        isLinuxAssertionMacroExpansion(BO, S))
      return;

    const Expr *LHS = BO->getLHS();
    const Expr *RHS = BO->getRHS();
    LinuxKernelAPIOrigin Origin;
    if (RHS->isNullPointerConstant(S.getASTContext(),
                                   Expr::NPC_ValueDependentIsNotNull))
      Origin = getOrigin(LHS);
    else if (LHS->isNullPointerConstant(S.getASTContext(),
                                        Expr::NPC_ValueDependentIsNotNull))
      Origin = getOrigin(RHS);

    if (Origin.Kind == LinuxKernelAPIKind::ErrorPointer)
      S.Diag(BO->getOperatorLoc(), diag::warn_linux_kernel_null_test_on_err_ptr)
          << Origin.getName() << BO->getSourceRange();
  }

  void checkErrorPointerBooleanTest(const UnaryOperator *UO) {
    if (CoveredNullTests.contains(UO) || isLinuxAssertionMacroExpansion(UO, S))
      return;
    const Expr *Value = UO->getSubExpr();
    LinuxKernelAPIOrigin Origin = getOrigin(Value);
    if (Origin.Kind == LinuxKernelAPIKind::ErrorPointer)
      S.Diag(Value->getExprLoc(), diag::warn_linux_kernel_null_test_on_err_ptr)
          << Origin.getName() << Value->getSourceRange();
  }

  void checkAllocatorRelease(const CallExpr *Call, StringRef Releaser) {
    unsigned PointerArgument = Releaser == "devm_kfree" ? 1 : 0;
    if (Call->getNumArgs() <= PointerArgument)
      return;

    const Expr *Pointer = Call->getArg(PointerArgument);
    LinuxKernelAPIOrigin Origin = getOrigin(Pointer);
    StringRef Expected;
    if (Releaser == "kfree" || Releaser == "kfree_sensitive") {
      switch (Origin.Kind) {
      case LinuxKernelAPIKind::VmallocPointer:
        Expected = "vfree";
        break;
      case LinuxKernelAPIKind::KvmallocPointer:
        Expected = "kvfree";
        break;
      case LinuxKernelAPIKind::DevmPointer:
        Expected = "devm_kfree";
        break;
      case LinuxKernelAPIKind::ConstKmallocPointer:
        Expected = "kfree_const";
        break;
      default:
        break;
      }
    } else if (Releaser == "vfree") {
      switch (Origin.Kind) {
      case LinuxKernelAPIKind::KmallocPointer:
        Expected = "kfree";
        break;
      case LinuxKernelAPIKind::KvmallocPointer:
        Expected = "kvfree";
        break;
      case LinuxKernelAPIKind::DevmPointer:
        Expected = "devm_kfree";
        break;
      case LinuxKernelAPIKind::ConstKmallocPointer:
        Expected = "kfree_const";
        break;
      default:
        break;
      }
    } else if (Releaser == "devm_kfree") {
      switch (Origin.Kind) {
      case LinuxKernelAPIKind::KmallocPointer:
        Expected = "kfree";
        break;
      case LinuxKernelAPIKind::VmallocPointer:
        Expected = "vfree";
        break;
      case LinuxKernelAPIKind::KvmallocPointer:
        Expected = "kvfree";
        break;
      case LinuxKernelAPIKind::ConstKmallocPointer:
        Expected = "kfree_const";
        break;
      default:
        break;
      }
    } else if (Releaser == "kvfree" || Releaser == "kvfree_sensitive") {
      if (Origin.Kind == LinuxKernelAPIKind::DevmPointer)
        Expected = "devm_kfree";
      else if (Origin.Kind == LinuxKernelAPIKind::ConstKmallocPointer)
        Expected = "kfree_const";
    } else if (Releaser == "kfree_const") {
      switch (Origin.Kind) {
      case LinuxKernelAPIKind::VmallocPointer:
        Expected = "vfree";
        break;
      case LinuxKernelAPIKind::KvmallocPointer:
        Expected = "kvfree";
        break;
      case LinuxKernelAPIKind::DevmPointer:
        Expected = "devm_kfree";
        break;
      default:
        break;
      }
    }

    if (!Expected.empty())
      S.Diag(Call->getExprLoc(), diag::warn_linux_kernel_allocator_mismatch)
          << Origin.getName() << Releaser << Expected << Call->getSourceRange();

    // A release invalidates the value for subsequent contract checks even
    // when the release helper itself was correct.
    forgetDirectStorage(Pointer);
  }

  void checkIRQComparison(const BinaryOperator *BO) {
    if (!BO->isComparisonOp())
      return;

    LinuxKernelAPIOrigin Origin = getOrigin(BO->getLHS());
    const Expr *Other = BO->getRHS();
    BinaryOperatorKind Opcode = BO->getOpcode();
    if (Origin.Kind != LinuxKernelAPIKind::IRQNumber) {
      Origin = getOrigin(BO->getRHS());
      Other = BO->getLHS();
      Opcode = reverseComparison(Opcode);
    }
    if (Origin.Kind != LinuxKernelAPIKind::IRQNumber)
      return;

    std::optional<llvm::APSInt> Value =
        Other->getIntegerConstantExpr(S.getASTContext());
    if (!Value || !Value->isZero())
      return;

    if (Opcode != BO_EQ && Opcode != BO_NE && Opcode != BO_LE)
      return;

    S.Diag(BO->getOperatorLoc(), diag::warn_linux_kernel_irq_zero_comparison)
        << Origin.getName() << BO->getSourceRange();
  }

public:
  LinuxKernelWarningsVisitor(Sema &S, const FunctionDecl *FD)
      : S(S), CurrentFunction(FD) {
    ShouldVisitImplicitCode = false;
  }

  bool TraverseIfStmt(IfStmt *IS) override {
    ++ControlFlowDepth;
    bool Result = DynamicRecursiveASTVisitor::TraverseIfStmt(IS);
    --ControlFlowDepth;
    return Result;
  }

  bool TraverseSwitchStmt(SwitchStmt *SS) override {
    ++ControlFlowDepth;
    bool Result = DynamicRecursiveASTVisitor::TraverseSwitchStmt(SS);
    --ControlFlowDepth;
    return Result;
  }

  bool TraverseWhileStmt(WhileStmt *WS) override {
    ++ControlFlowDepth;
    bool Result = DynamicRecursiveASTVisitor::TraverseWhileStmt(WS);
    --ControlFlowDepth;
    return Result;
  }

  bool TraverseDoStmt(DoStmt *DS) override {
    ++ControlFlowDepth;
    bool Result = DynamicRecursiveASTVisitor::TraverseDoStmt(DS);
    --ControlFlowDepth;
    return Result;
  }

  bool TraverseForStmt(ForStmt *FS) override {
    ++ControlFlowDepth;
    bool Result = DynamicRecursiveASTVisitor::TraverseForStmt(FS);
    --ControlFlowDepth;
    return Result;
  }

  bool TraverseConditionalOperator(ConditionalOperator *CO) override {
    ++ControlFlowDepth;
    bool Result = DynamicRecursiveASTVisitor::TraverseConditionalOperator(CO);
    --ControlFlowDepth;
    return Result;
  }

  bool VisitVarDecl(VarDecl *VD) override {
    if (AssignmentTrackingDisabled || !VD->hasLocalStorage() || !VD->hasInit())
      return true;
    LinuxKernelAPIOrigin Origin = getOrigin(VD->getInit());
    if (Origin)
      VariableOrigins[VD] = Origin;
    return true;
  }

  bool VisitReturnStmt(ReturnStmt *RS) override {
    if (!CurrentFunction || !RS->getRetValue())
      return true;

    const Expr *ValueExpr = RS->getRetValue()->IgnoreParenImpCasts();
    QualType ReturnType = CurrentFunction->getReturnType();
    std::optional<llvm::APSInt> Value =
        ValueExpr->getIntegerConstantExpr(S.getASTContext());
    if (ReturnType->isBooleanType()) {
      if (Value && Value->isSigned() && Value->isNegative())
        S.Diag(ValueExpr->getExprLoc(),
               diag::warn_linux_kernel_bool_negative_return)
            << ValueExpr->getSourceRange();
    } else if (ReturnType->isSignedIntegerType()) {
      if (hasLinuxKernelErrnoReturnConvention(CurrentFunction)) {
        LinuxKernelAPIOrigin Origin = getOrigin(RS->getRetValue());
        if (Origin.Kind == LinuxKernelAPIKind::UsercopyResidual)
          S.Diag(ValueExpr->getExprLoc(),
                 diag::warn_linux_kernel_usercopy_signed_return)
              << Origin.getName() << ValueExpr->getSourceRange();
      }

      StringRef Errno = getLinuxErrnoMacroName(ValueExpr, S);
      if (Value && !Value->isNegative() && !Value->isZero() && !Errno.empty())
        if (!returnsPositiveErrnoByContract(CurrentFunction))
          S.Diag(ValueExpr->getExprLoc(),
                 diag::warn_linux_kernel_positive_errno_return)
              << Errno << ValueExpr->getSourceRange();
    } else if (ReturnType->isUnsignedIntegerType() && Value &&
               Value->isSigned() && Value->isNegative() &&
               !getLinuxErrnoMacroName(ValueExpr, S).empty()) {
      S.Diag(ValueExpr->getExprLoc(),
             diag::warn_linux_kernel_negative_errno_unsigned_return)
          << ValueExpr->getSourceRange();
    }
    return true;
  }

  bool VisitCallExpr(CallExpr *Call) override {
    const FunctionDecl *Checker = Call->getDirectCallee();
    if (!Checker || !Checker->getIdentifier() || Call->getNumArgs() == 0)
      return true;

    StringRef CheckerName = Checker->getName();
    if (CheckerName == "kfree" || CheckerName == "kfree_sensitive" ||
        CheckerName == "vfree" || CheckerName == "kvfree" ||
        CheckerName == "kvfree_sensitive" || CheckerName == "devm_kfree" ||
        CheckerName == "kfree_const") {
      checkAllocatorRelease(Call, CheckerName);
      return true;
    }

    if (CheckerName == "ERR_PTR") {
      // Kernel macros sometimes use ERR_PTR(0) as an implementation detail to
      // produce a null optional argument.  Diagnosing each expansion is noisy
      // and points at the caller rather than the macro definition.  Keep this
      // check for explicit source calls, where it has found real bugs.
      if (S.getSourceManager().isMacroBodyExpansion(
              Call->getCallee()->getExprLoc()))
        return true;
      std::optional<llvm::APSInt> Error =
          Call->getArg(0)->getIntegerConstantExpr(S.getASTContext());
      if (Error && !Error->isNegative())
        S.Diag(Call->getExprLoc(), diag::warn_linux_kernel_err_ptr_nonnegative)
            << Call->getSourceRange();
      return true;
    }

    if (CheckerName != "IS_ERR" && CheckerName != "PTR_ERR" &&
        CheckerName != "PTR_ERR_OR_ZERO")
      return true;

    LinuxKernelAPIOrigin Origin = getOrigin(Call->getArg(0));
    if (!isNullReturningKind(Origin.Kind))
      return true;

    unsigned Diagnostic = CheckerName == "IS_ERR"
                              ? diag::warn_linux_kernel_is_err_on_nullable
                              : diag::warn_linux_kernel_ptr_err_on_nullable;
    S.Diag(Call->getExprLoc(), Diagnostic)
        << Origin.getName() << CheckerName << Call->getSourceRange();
    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *UO) override {
    if (UO->getOpcode() == UO_LNot) {
      checkErrorPointerBooleanTest(UO);
      LinuxKernelAPIOrigin Origin = getOrigin(UO->getSubExpr());
      if (Origin.Kind == LinuxKernelAPIKind::IRQNumber)
        S.Diag(UO->getExprLoc(), diag::warn_linux_kernel_irq_boolean_test)
            << Origin.getName() << UO->getSourceRange();
    }
    if (UO->getOpcode() == UO_AddrOf || UO->isIncrementDecrementOp())
      forgetDirectStorage(UO->getSubExpr());
    return true;
  }

  bool VisitImplicitCastExpr(ImplicitCastExpr *ICE) override {
    if (ICE->getCastKind() != CK_IntegralToBoolean)
      return true;
    LinuxKernelAPIOrigin Origin = getOrigin(ICE->getSubExpr());
    if (Origin.Kind == LinuxKernelAPIKind::IRQNumber)
      S.Diag(ICE->getExprLoc(), diag::warn_linux_kernel_irq_boolean_test)
          << Origin.getName() << ICE->getSourceRange();
    return true;
  }

  bool VisitAsmStmt(AsmStmt *AS) override {
    // An output operand can replace a tracked value without an assignment in
    // the source.  Retain unrelated origins, but forget direct output
    // variables before considering later statements.
    for (unsigned I = 0; I != AS->getNumOutputs(); ++I)
      forgetDirectStorage(AS->getOutputExpr(I));
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) override {
    recordCombinedErrorPointerGuard(BO);

    if (BO->isAssignmentOp()) {
      const auto *DRE =
          dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts());
      const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
      std::optional<DirectField> Field = getDirectField(BO->getLHS());
      if (VD || Field) {
        const bool CanTrack = BO->getOpcode() == BO_Assign &&
                              ControlFlowDepth == 0 &&
                              !AssignmentTrackingDisabled;
        LinuxKernelAPIOrigin Origin =
            CanTrack ? getOrigin(BO->getRHS()) : LinuxKernelAPIOrigin{};
        if (VD) {
          if (Origin)
            VariableOrigins[VD] = Origin;
          else
            VariableOrigins.erase(VD);
        }
        if (Field) {
          if (Origin)
            FieldOrigins[*Field] = Origin;
          else
            FieldOrigins.erase(*Field);
        }
      }
      return true;
    }

    checkUsercopyComparison(BO);
    checkErrorPointerNullComparison(BO);
    checkIRQComparison(BO);
    return true;
  }

  bool VisitGotoStmt(GotoStmt *) override {
    AssignmentTrackingDisabled = true;
    VariableOrigins.clear();
    FieldOrigins.clear();
    return true;
  }

  bool VisitIndirectGotoStmt(IndirectGotoStmt *) override {
    AssignmentTrackingDisabled = true;
    VariableOrigins.clear();
    FieldOrigins.clear();
    return true;
  }
};

static bool shouldRunLinuxKernelWarnings(const Sema &S, SourceLocation Loc) {
  const DiagnosticsEngine &Diags = S.getDiagnostics();
  return !Diags.isIgnored(diag::warn_linux_kernel_bool_negative_return, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_usercopy_negative_test,
                          Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_usercopy_signed_return,
                          Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_is_err_on_nullable, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_ptr_err_on_nullable, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_null_test_on_err_ptr, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_err_ptr_nonnegative, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_allocator_mismatch, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_irq_boolean_test, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_irq_zero_comparison, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_positive_errno_return, Loc) ||
         !Diags.isIgnored(
             diag::warn_linux_kernel_negative_errno_unsigned_return, Loc);
}

} // namespace

void clang::sema::IssueLinuxKernelWarnings(Sema &S, const FunctionDecl *FD) {
  if (!FD || S.getLangOpts().CPlusPlus ||
      !shouldRunLinuxKernelWarnings(S, FD->getBeginLoc()))
    return;

  LinuxKernelWarningsVisitor(S, FD).TraverseStmt(FD->getBody());
}
