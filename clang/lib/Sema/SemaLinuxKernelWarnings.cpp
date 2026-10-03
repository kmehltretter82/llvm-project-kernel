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
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Analysis/CFG.h"
#include "clang/Basic/Builtins.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/DiagnosticSema.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/Sema/Sema.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/FoldingSet.h"
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
      // Since the kmalloc token was introduced, the kmalloc() family expands
      // to these inline helpers.
      .Cases({"_kmalloc_noprof", "_kzalloc_noprof", "_kmalloc_array_noprof",
              "_kmalloc_node_noprof", "_kmalloc_array_node_noprof"},
             LinuxKernelAPIKind::KmallocPointer)
      .Cases({"kmalloc_node_noprof", "kmalloc_array_node_noprof",
              "__kmalloc_node_noprof", "__kmalloc_cache_noprof",
              "__kmalloc_cache_node_noprof", "__kmalloc_large_noprof",
              "__kmalloc_large_node_noprof"},
             LinuxKernelAPIKind::KmallocPointer)
      .Cases({"_krealloc_array_noprof", "kmalloc_track_caller_noprof",
              "kmalloc_node_track_caller_noprof",
              "__kmalloc_node_track_caller_noprof"},
             LinuxKernelAPIKind::KmallocPointer)
      .Cases({"kvmalloc_noprof", "kvmalloc_node_noprof",
              "kvmalloc_array_node_noprof", "_kvmalloc_array_node_noprof",
              "kvrealloc_node_align_noprof"},
             LinuxKernelAPIKind::KvmallocPointer)
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

/// A declaration can state its contract with an annotation instead of being
/// listed above:
///
///   __attribute__((annotate("linux_kernel::returns_err_ptr")))
///   struct clk *my_clk_get(struct device *dev);
///
/// Kernel headers would hide the attribute behind a macro.
static LinuxKernelAPIKind classifyLinuxKernelAnnotation(const FunctionDecl *FD) {
  for (const auto *A : FD->specific_attrs<AnnotateAttr>()) {
    LinuxKernelAPIKind Kind =
        llvm::StringSwitch<LinuxKernelAPIKind>(A->getAnnotation())
            .Case("linux_kernel::returns_err_ptr",
                  LinuxKernelAPIKind::ErrorPointer)
            .Case("linux_kernel::returns_null_on_failure",
                  LinuxKernelAPIKind::NullablePointer)
            .Case("linux_kernel::returns_uncopied_bytes",
                  LinuxKernelAPIKind::UsercopyResidual)
            .Case("linux_kernel::returns_irq_or_errno",
                  LinuxKernelAPIKind::IRQNumber)
            .Default(LinuxKernelAPIKind::None);
    if (Kind != LinuxKernelAPIKind::None)
      return Kind;
  }
  return LinuxKernelAPIKind::None;
}

static LinuxKernelAPIKind classifyLinuxKernelCallee(const FunctionDecl *FD) {
  LinuxKernelAPIKind Kind = classifyLinuxKernelAnnotation(FD);
  if (Kind == LinuxKernelAPIKind::None && FD->getIdentifier())
    Kind = classifyLinuxKernelAPI(FD->getName());
  return Kind;
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

/// The local variable that \p E names directly, if any.
static const VarDecl *getDirectLinuxVariable(const Expr *E) {
  if (!E)
    return nullptr;
  const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts());
  return DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
}

/// Strip the wrappers that do not change which values make a condition true,
/// such as unlikely(), and fold logical negations into \p Negated.
static const Expr *stripLinuxCondition(const Expr *E, bool &Negated) {
  while (E) {
    E = E->IgnoreParens();
    if (const auto *ICE = dyn_cast<ImplicitCastExpr>(E)) {
      CastKind K = ICE->getCastKind();
      if (K == CK_IntegralToBoolean || K == CK_PointerToBoolean ||
          K == CK_NoOp ||
          (K == CK_IntegralCast &&
           ICE->getSubExpr()->isKnownToHaveBooleanValue())) {
        E = ICE->getSubExpr();
        continue;
      }
      break;
    }
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_LNot) {
        Negated = !Negated;
        E = UO->getSubExpr();
        continue;
      }
      break;
    }
    if (const auto *CE = dyn_cast<CallExpr>(E)) {
      unsigned ID = CE->getBuiltinCallee();
      if ((ID == Builtin::BI__builtin_expect ||
           ID == Builtin::BI__builtin_expect_with_probability) &&
          CE->getNumArgs() >= 1) {
        E = CE->getArg(0);
        continue;
      }
    }
    break;
  }
  return E;
}

static bool isSameLinuxExpr(const ASTContext &Ctx, const Expr *A,
                            const Expr *B) {
  if (!A || !B)
    return false;
  llvm::FoldingSetNodeID IDA, IDB;
  A->IgnoreParenImpCasts()->Profile(IDA, Ctx, /*Canonical=*/true);
  B->IgnoreParenImpCasts()->Profile(IDB, Ctx, /*Canonical=*/true);
  return IDA == IDB;
}

/// A variable, or a chain of member accesses that starts at one.
static bool isSimpleLinuxStorage(const Expr *E) {
  while (E) {
    E = E->IgnoreParenImpCasts();
    if (isa<DeclRefExpr>(E))
      return isa<VarDecl>(cast<DeclRefExpr>(E)->getDecl());
    const auto *ME = dyn_cast<MemberExpr>(E);
    if (!ME || !isa<FieldDecl>(ME->getMemberDecl()))
      return false;
    E = ME->getBase();
  }
  return false;
}

static std::string getLinuxExprText(const Expr *E, const Sema &S) {
  StringRef Text = Lexer::getSourceText(
      CharSourceRange::getTokenRange(E->getSourceRange()),
      S.getSourceManager(), S.getLangOpts());
  return Text.empty() ? std::string("the value") : Text.str();
}

class LinuxKernelWarningsVisitor : public DynamicRecursiveASTVisitor {
  using DirectField = std::pair<const VarDecl *, const FieldDecl *>;

  Sema &S;
  const FunctionDecl *CurrentFunction;
  llvm::DenseMap<const VarDecl *, LinuxKernelAPIOrigin> VariableOrigins;
  llvm::DenseMap<DirectField, LinuxKernelAPIOrigin> FieldOrigins;
  llvm::SmallPtrSet<const Expr *, 4> CoveredNullTests;
  /// IRQ results that have already been tested for a negative value.  A
  /// later boolean test of the same value only handles zero.
  llvm::SmallPtrSet<const VarDecl *, 4> NegativeTestedIRQs;
  unsigned ControlFlowDepth = 0;
  bool AssignmentTrackingDisabled = false;

  static const VarDecl *getDirectVariable(const Expr *E) {
    return getDirectLinuxVariable(E);
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
    if (const VarDecl *VD = getDirectVariable(E)) {
      VariableOrigins.erase(VD);
      NegativeTestedIRQs.erase(VD);
    }
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
      LinuxKernelAPIKind Kind = classifyLinuxKernelCallee(Callee);
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

    if (Opcode == BO_LT || Opcode == BO_GE) {
      const Expr *Tested =
          Other == BO->getRHS() ? BO->getLHS() : BO->getRHS();
      if (const VarDecl *VD = getDirectVariable(Tested))
        NegativeTestedIRQs.insert(VD);
      return;
    }
    if (Opcode != BO_EQ && Opcode != BO_NE && Opcode != BO_LE)
      return;

    S.Diag(BO->getOperatorLoc(), diag::warn_linux_kernel_irq_zero_comparison)
        << Origin.getName() << BO->getSourceRange();
  }

  static const Stmt *stripStatementLabels(const Stmt *St) {
    while (St) {
      if (const auto *LS = dyn_cast<LabelStmt>(St))
        St = LS->getSubStmt();
      else if (const auto *SC = dyn_cast<SwitchCase>(St))
        St = SC->getSubStmt();
      else if (const auto *AS = dyn_cast<AttributedStmt>(St))
        St = AS->getSubStmt();
      else
        break;
    }
    return St;
  }

  /// A value stored by a statement: `target = source;` or a declaration with
  /// an initializer.
  struct StoredValue {
    const Expr *Target = nullptr;
    const VarDecl *Variable = nullptr;
    const Expr *Source = nullptr;

    QualType getType() const {
      return Target ? Target->getType() : Variable->getType();
    }
  };

  static bool getStoredValue(const Stmt *St, StoredValue &Stored) {
    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(St)) {
      if (BO->getOpcode() != BO_Assign)
        return false;
      Stored.Target = BO->getLHS()->IgnoreParens();
      Stored.Variable = getDirectLinuxVariable(Stored.Target);
      Stored.Source = BO->getRHS();
      return true;
    }
    if (const auto *DS = dyn_cast_or_null<DeclStmt>(St)) {
      if (!DS->isSingleDecl())
        return false;
      const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
      if (!VD || !VD->hasLocalStorage() || !VD->hasInit())
        return false;
      Stored.Variable = VD;
      Stored.Source = VD->getInit();
      return true;
    }
    return false;
  }

  bool refersToStoredValue(const StoredValue &Stored, const Expr *E) const {
    if (!E)
      return false;
    if (Stored.Variable && getDirectLinuxVariable(E) == Stored.Variable)
      return true;
    return Stored.Target &&
           isSameLinuxExpr(S.getASTContext(), Stored.Target, E);
  }

  bool mentionsStoredValue(const StoredValue &Stored, const Stmt *St) const {
    if (!St)
      return false;
    if (const auto *E = dyn_cast<Expr>(St))
      if (refersToStoredValue(Stored, E))
        return true;
    for (const Stmt *Child : St->children())
      if (mentionsStoredValue(Stored, Child))
        return true;
    return false;
  }

  std::string getStoredValueText(const StoredValue &Stored) const {
    if (Stored.Target)
      return getLinuxExprText(Stored.Target, S);
    return Stored.Variable->getNameAsString();
  }

  /// The callee if \p Source is a call that returns a signed integer and is
  /// converted without an explicit cast.
  static const FunctionDecl *getSignedResultCallee(const Expr *Source) {
    const auto *Call =
        dyn_cast_or_null<CallExpr>(Source ? Source->IgnoreParenImpCasts()
                                          : nullptr);
    const FunctionDecl *Callee = Call ? Call->getDirectCallee() : nullptr;
    if (!Callee || !Callee->getIdentifier())
      return nullptr;
    QualType RT = Callee->getReturnType();
    if (!RT->isSignedIntegerType() || RT->isBooleanType() ||
        RT->isAnyCharacterType() || RT->isEnumeralType())
      return nullptr;
    return Callee;
  }

  static bool isPlainUnsignedType(QualType T) {
    return T->isUnsignedIntegerType() && !T->isBooleanType() &&
           !T->isEnumeralType() && !T->isAnyCharacterType();
  }

  /// Diagnose `x < 0` and `x >= 0` in \p Cond when x holds, as an unsigned
  /// value, the result of a call that reports errors as negative numbers.
  void diagnoseUnsignedErrorTests(const StoredValue &Stored,
                                  const FunctionDecl *Callee,
                                  const Expr *Cond) {
    if (!Cond)
      return;
    const Expr *E = Cond->IgnoreParenImpCasts();
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_LNot)
        diagnoseUnsignedErrorTests(Stored, Callee, UO->getSubExpr());
      return;
    }
    if (const auto *CE = dyn_cast<CallExpr>(E)) {
      unsigned ID = CE->getBuiltinCallee();
      if ((ID == Builtin::BI__builtin_expect ||
           ID == Builtin::BI__builtin_expect_with_probability) &&
          CE->getNumArgs() >= 1)
        diagnoseUnsignedErrorTests(Stored, Callee, CE->getArg(0));
      return;
    }
    const auto *BO = dyn_cast<BinaryOperator>(E);
    if (!BO)
      return;
    if (BO->isLogicalOp()) {
      diagnoseUnsignedErrorTests(Stored, Callee, BO->getLHS());
      diagnoseUnsignedErrorTests(Stored, Callee, BO->getRHS());
      return;
    }
    if (!BO->isRelationalOp())
      return;

    const Expr *Value = BO->getLHS();
    const Expr *Other = BO->getRHS();
    BinaryOperatorKind Opcode = BO->getOpcode();
    if (!refersToStoredValue(Stored, Value)) {
      std::swap(Value, Other);
      Opcode = reverseComparison(Opcode);
      if (!refersToStoredValue(Stored, Value))
        return;
    }
    if (Opcode != BO_LT && Opcode != BO_GE)
      return;
    std::optional<llvm::APSInt> Zero =
        Other->getIntegerConstantExpr(S.getASTContext());
    if (!Zero || !Zero->isZero())
      return;

    S.Diag(BO->getOperatorLoc(), diag::warn_linux_kernel_unsigned_error_check)
        << Callee->getName() << Stored.getType() << (Opcode == BO_GE)
        << BO->getSourceRange();
  }

  void checkUnsignedErrorTest(const StoredValue &Stored, const Expr *Cond) {
    const FunctionDecl *Callee = getSignedResultCallee(Stored.Source);
    if (Callee && isPlainUnsignedType(Stored.getType()))
      diagnoseUnsignedErrorTests(Stored, Callee, Cond);
  }

  /// `(x = f()) < 0` with an unsigned x.
  void checkInlineUnsignedErrorTest(const BinaryOperator *BO) {
    if (!BO->isRelationalOp())
      return;
    for (const Expr *Side : {BO->getLHS(), BO->getRHS()}) {
      StoredValue Stored;
      if (!getStoredValue(Side->IgnoreParenImpCasts(), Stored))
        continue;
      const FunctionDecl *Callee = getSignedResultCallee(Stored.Source);
      if (!Callee || !isPlainUnsignedType(Stored.getType()))
        continue;
      const Expr *Other = Side == BO->getLHS() ? BO->getRHS() : BO->getLHS();
      BinaryOperatorKind Opcode = Side == BO->getLHS()
                                      ? BO->getOpcode()
                                      : reverseComparison(BO->getOpcode());
      std::optional<llvm::APSInt> Zero =
          Other->getIntegerConstantExpr(S.getASTContext());
      if (!Zero || !Zero->isZero() || (Opcode != BO_LT && Opcode != BO_GE))
        continue;
      S.Diag(BO->getOperatorLoc(), diag::warn_linux_kernel_unsigned_error_check)
          << Callee->getName() << Stored.getType() << (Opcode == BO_GE)
          << BO->getSourceRange();
    }
  }

  /// Diagnose a failure test that follows `x = f();` but tests something
  /// other than x.
  void checkWrongVariableTest(const StoredValue &Stored, const Expr *Cond,
                              ArrayRef<const Stmt *> EarlierStores) {
    const auto *Call =
        dyn_cast<CallExpr>(Stored.Source->IgnoreParenCasts());
    const FunctionDecl *Callee = Call ? Call->getDirectCallee() : nullptr;
    if (!Callee || !Callee->getIdentifier())
      return;

    bool Negated = false;
    const Expr *Test = stripLinuxCondition(Cond, Negated);
    if (!Test)
      return;

    ASTContext &Ctx = S.getASTContext();
    const Expr *Checked = nullptr;
    bool IsErrorPointerTest = false;
    if (const Expr *Value = getErrorPointerCheckValue(Test)) {
      Checked = Value;
      IsErrorPointerTest = true;
    } else if (const auto *BO =
                   dyn_cast<BinaryOperator>(Test->IgnoreParenImpCasts());
               BO && BO->isEqualityOp()) {
      if (BO->getRHS()->isNullPointerConstant(
              Ctx, Expr::NPC_ValueDependentIsNotNull))
        Checked = BO->getLHS();
      else if (BO->getLHS()->isNullPointerConstant(
                   Ctx, Expr::NPC_ValueDependentIsNotNull))
        Checked = BO->getRHS();
    } else if (Test->IgnoreParenImpCasts()->getType()->isPointerType()) {
      Checked = Test;
    }
    if (!Checked)
      return;
    Checked = Checked->IgnoreParenImpCasts();
    if (!isSimpleLinuxStorage(Checked) || mentionsStoredValue(Stored, Cond))
      return;

    // The test names an object that the assignment has just dereferenced.
    for (const Expr *Base = Stored.Target; Base;) {
      const auto *ME = dyn_cast<MemberExpr>(Base->IgnoreParenImpCasts());
      if (!ME)
        break;
      Base = ME->getBase()->IgnoreParenImpCasts();
      if (isSameLinuxExpr(Ctx, Base, Checked)) {
        S.Diag(Checked->getExprLoc(), diag::warn_linux_kernel_wrong_check_base)
            << getLinuxExprText(Checked, S) << getStoredValueText(Stored)
            << Callee->getName() << Cond->getSourceRange();
        return;
      }
    }

    // The test names another value of the same type.  Only failure tests
    // that the stored result clearly needs are diagnosed.
    if (!Ctx.hasSameUnqualifiedType(Stored.getType(), Checked->getType()))
      return;
    bool NullOnFailure = isNullReturningKind(classifyLinuxKernelCallee(Callee));
    if (!IsErrorPointerTest && !NullOnFailure)
      return;
    // "a = get(); b = get(); if (IS_ERR(a)) ...; if (IS_ERR(b)) ..." fetches
    // in a batch and tests afterwards.  The test of 'a' is in order there.
    for (const Stmt *Earlier : EarlierStores) {
      StoredValue EarlierStored;
      if (getStoredValue(Earlier, EarlierStored) &&
          refersToStoredValue(EarlierStored, Checked))
        return;
    }
    S.Diag(Checked->getExprLoc(), diag::warn_linux_kernel_wrong_check_other)
        << getLinuxExprText(Checked, S) << getStoredValueText(Stored)
        << Callee->getName() << Cond->getSourceRange();
  }

  /// \p EarlierStores are the assignments that directly precede \p Previous.
  void checkAdjacentStatements(const Stmt *Previous, const Stmt *Current,
                               ArrayRef<const Stmt *> EarlierStores) {
    StoredValue Stored;
    if (!getStoredValue(Previous, Stored) || !Stored.Source)
      return;
    const auto *If = dyn_cast_or_null<IfStmt>(Current);
    if (!If || !If->getCond())
      return;
    checkUnsignedErrorTest(Stored, If->getCond());
    checkWrongVariableTest(Stored, If->getCond(), EarlierStores);
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

  bool VisitCompoundStmt(CompoundStmt *CS) override {
    const Stmt *Previous = nullptr;
    // The run of assignments that ends right before Previous.
    llvm::SmallVector<const Stmt *, 8> EarlierStores;
    for (const Stmt *Child : CS->body()) {
      const Stmt *Current = stripStatementLabels(Child);
      if (Previous)
        checkAdjacentStatements(Previous, Current, EarlierStores);
      StoredValue Stored;
      if (Previous && getStoredValue(Previous, Stored))
        EarlierStores.push_back(Previous);
      else
        EarlierStores.clear();
      Previous = Current;
    }
    return true;
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
      // A type narrower than int cannot carry the errno back at all.  With a
      // wider unsigned type the caller can still recover it by conversion,
      // which several kernel interfaces rely on.
      ASTContext &Ctx = S.getASTContext();
      bool Truncated = !ReturnType->isEnumeralType() &&
                       Ctx.getIntWidth(ReturnType) < Ctx.getIntWidth(Ctx.IntTy);
      S.Diag(ValueExpr->getExprLoc(),
             Truncated ? diag::warn_linux_kernel_negative_errno_truncated_return
                       : diag::warn_linux_kernel_negative_errno_unsigned_return)
          << ReturnType << ValueExpr->getSourceRange();
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
      if (Origin.Kind == LinuxKernelAPIKind::IRQNumber &&
          !NegativeTestedIRQs.contains(getDirectVariable(UO->getSubExpr())))
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
    if (Origin.Kind == LinuxKernelAPIKind::IRQNumber &&
        !NegativeTestedIRQs.contains(getDirectVariable(ICE->getSubExpr())))
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
    checkInlineUnsignedErrorTest(BO);
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

/// Finds returns that report success on a path that has just reported a
/// failure:
///
///   ret = step_one();
///   if (ret)
///     return ret;
///   if (!resource) {
///     dev_err(dev, "no resource\n");
///     return ret;               // ret is 0 here
///   }
///
/// For every local variable that the function returns and whose name and
/// assignments say that it carries an error code, a forward dataflow pass
/// over the CFG tracks these facts:
///
///   Zero    some path arrives with the variable known to be zero
///   NonZero every path arrives with the variable known not to be zero
///   Message every path arrives after a failure message, and the variable
///           has not changed since
///   Jumped  some path arrives through "failure message; goto" with the
///           variable zero and unchanged since, where the goto leaves for a
///           label that is not inside a loop
///
/// `return var` is diagnosed when Zero and Message both hold, which covers a
/// return that a failure message dominates, or when Jumped holds, which
/// covers the shared exit label.  A message that the code merely passes on
/// its way to the common success path does not make Message hold at the
/// return, because the path around the message does not carry it.
class ErrorPathSuccessChecker {
  Sema &S;
  const FunctionDecl *FD;
  const CFG &Cfg;
  ASTContext &Ctx;

  struct Facts {
    bool Reached = false;
    bool Zero = false;
    /// Every path arrives with the variable known not to be zero.  An edge
    /// that requires it to be zero is then infeasible.
    bool NonZero = false;
    bool Message = false;
    bool Jumped = false;
    /// The calls behind Message and Jumped, for the note.
    const CallExpr *MessageCall = nullptr;
    const CallExpr *JumpMessage = nullptr;

    void assigned(bool IsZero, bool IsNonZero) {
      Zero = IsZero;
      NonZero = IsNonZero;
      Message = Jumped = false;
      MessageCall = JumpMessage = nullptr;
    }
  };

  enum class Knowledge { None, Zero, NonZero };

  llvm::SmallPtrSet<const VarDecl *, 8> AddressTaken;
  /// Variables that are given something other than a non-negative constant
  /// and can therefore hold an error code.  A variable that only ever takes
  /// values such as 0 and 1 is a flag, and returning it after a message is
  /// deliberate.
  llvm::SmallPtrSet<const VarDecl *, 8> ErrorCapable;
  /// Variables that are counted up or down.  Zero is "nothing found" for
  /// them, not a lost error code.
  llvm::SmallPtrSet<const VarDecl *, 8> Counters;
  llvm::SmallVector<const VarDecl *, 4> Candidates;
  llvm::DenseMap<const CFGBlock *, bool> InCycle;

  /// Whether the name of \p VD says that it carries an error code, as "ret",
  /// "err", "rc" or "status" do.  Counts and sizes are returned after a
  /// message as well, and zero is a valid answer for them.
  static bool isNamedLikeErrorCode(const VarDecl *VD) {
    std::string Lower = VD->getName().rtrim("0123456789").lower();
    llvm::SmallVector<StringRef, 4> Words;
    StringRef(Lower).split(Words, '_', -1, /*KeepEmpty=*/false);
    for (StringRef Word : Words)
      if (llvm::StringSwitch<bool>(Word)
              .Cases({"ret", "retval", "rval", "rv", "rc", "r"}, true)
              .Cases({"err", "error", "errno", "errcode", "ec", "e"}, true)
              .Cases({"res", "result", "status"}, true)
              .Default(false))
        return true;
    return false;
  }

  void noteValue(const VarDecl *VD, const Expr *Value) {
    if (!VD || !Value || Value->isValueDependent())
      return;
    std::optional<llvm::APSInt> K = Value->getIntegerConstantExpr(Ctx);
    if (!K || K->isNegative())
      ErrorCapable.insert(VD);
  }

  void collect(const Stmt *St) {
    if (!St)
      return;
    if (const auto *UO = dyn_cast<UnaryOperator>(St)) {
      const VarDecl *VD = getDirectLinuxVariable(UO->getSubExpr());
      if (VD && UO->getOpcode() == UO_AddrOf)
        AddressTaken.insert(VD);
      else if (VD && UO->isIncrementDecrementOp())
        Counters.insert(VD);
    } else if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
      if (BO->isAssignmentOp()) {
        const VarDecl *VD = getDirectLinuxVariable(BO->getLHS());
        if (BO->getOpcode() == BO_Assign)
          noteValue(VD, BO->getRHS());
        else if (BO->getOpcode() == BO_AddAssign ||
                 BO->getOpcode() == BO_SubAssign)
          Counters.insert(VD);
        else if (VD)
          ErrorCapable.insert(VD);
      }
    } else if (const auto *DS = dyn_cast<DeclStmt>(St)) {
      for (const Decl *D : DS->decls())
        if (const auto *VD = dyn_cast<VarDecl>(D))
          noteValue(VD, VD->getInit());
    } else if (const auto *AS = dyn_cast<GCCAsmStmt>(St)) {
      for (unsigned I = 0, E = AS->getNumOutputs(); I != E; ++I)
        if (const VarDecl *VD = getDirectLinuxVariable(AS->getOutputExpr(I)))
          AddressTaken.insert(VD);
    } else if (const auto *RS = dyn_cast<ReturnStmt>(St)) {
      const VarDecl *VD = getDirectLinuxVariable(RS->getRetValue());
      if (VD && VD->hasLocalStorage() && !isa<ParmVarDecl>(VD) &&
          !VD->getType().isVolatileQualified() &&
          VD->getType()->isSignedIntegerType() &&
          !VD->getType()->isEnumeralType() &&
          !VD->getType()->isAnyCharacterType() && isNamedLikeErrorCode(VD) &&
          !llvm::is_contained(Candidates, VD))
        Candidates.push_back(VD);
    }
    for (const Stmt *Child : St->children())
      collect(Child);
  }

  /// Whether \p E is an integer constant, and if so whether it is zero.
  std::optional<bool> isZeroConstant(const Expr *E) const {
    if (!E || E->isValueDependent())
      return std::nullopt;
    std::optional<llvm::APSInt> V = E->getIntegerConstantExpr(Ctx);
    if (!V)
      return std::nullopt;
    return V->isZero();
  }

  static bool hasFailureWords(StringRef Text) {
    std::string Lower = Text.lower();
    StringRef L(Lower);
    for (StringRef Word :
         {"fail", "error", "unable to", "cannot", "can't", "could not",
          "couldn't", "timeout", "timed out"})
      if (L.contains(Word))
        return true;
    return false;
  }

  /// A call that reports an error: an error-level kernel print, or a
  /// driver's own logging helper printing text that describes a failure.
  static bool isFailureMessage(const CallExpr *CE) {
    const FunctionDecl *Callee = CE->getDirectCallee();
    if (!Callee || !Callee->getIdentifier())
      return false;
    StringRef Name = Callee->getName();

    if (llvm::StringSwitch<bool>(Name)
            .Cases({"_dev_err", "_dev_crit", "_dev_alert", "_dev_emerg"}, true)
            .Cases({"netdev_err", "netdev_crit", "netdev_alert",
                    "netdev_emerg"},
                   true)
            .Default(false))
      return true;

    // Standard helpers below the error level never count, whatever they say.
    if (llvm::StringSwitch<bool>(Name)
            .Cases({"_dev_warn", "_dev_notice", "_dev_info", "_dev_dbg"}, true)
            .Cases({"__dynamic_dev_dbg", "__dynamic_pr_debug",
                    "__dynamic_netdev_dbg"},
                   true)
            .Cases({"netdev_warn", "netdev_notice", "netdev_info",
                    "netdev_dbg"},
                   true)
            .Default(false))
      return false;

    bool IsPrintk = llvm::StringSwitch<bool>(Name)
                        .Cases({"_printk", "printk", "_printk_deferred",
                                "_dev_printk", "dev_printk_emit"},
                               true)
                        .Default(false);
    std::string Lower = Name.lower();
    StringRef LowerName(Lower);
    // An audit record documents a decision, it does not report that the
    // calling function failed.
    if (LowerName.contains("audit"))
      return false;
    bool LooksLikeLogger = false;
    for (StringRef Part : {"err", "dbg", "debug", "log", "print", "msg"})
      LooksLikeLogger |= LowerName.contains(Part);
    if (!IsPrintk && !LooksLikeLogger)
      return false;

    for (const Expr *Arg : CE->arguments()) {
      const auto *SL = dyn_cast<StringLiteral>(Arg->IgnoreParenImpCasts());
      if (!SL || !SL->isOrdinary())
        continue;
      StringRef Text = SL->getString();
      // printk() carries its level in the format string: "\001" "3" is
      // KERN_ERR and smaller digits are more severe.
      if (Text.size() >= 2 && Text[0] == '\001')
        return Text[1] >= '0' && Text[1] <= '3';
      if (IsPrintk)
        return false;
      if (hasFailureWords(Text))
        return true;
    }
    return false;
  }

  /// What each outcome of \p Cond says about \p V.
  void classify(const Expr *Cond, const VarDecl *V, Knowledge &OnTrue,
                Knowledge &OnFalse) const {
    OnTrue = OnFalse = Knowledge::None;
    bool Negated = false;
    const Expr *E = stripLinuxCondition(Cond, Negated);
    if (!E)
      return;

    Knowledge T = Knowledge::None, F = Knowledge::None;
    if (getDirectLinuxVariable(E) == V) {
      T = Knowledge::NonZero;
      F = Knowledge::Zero;
    } else if (const auto *BO =
                   dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts());
               BO && BO->isComparisonOp()) {
      const Expr *Other = BO->getRHS();
      BinaryOperatorKind Opcode = BO->getOpcode();
      if (getDirectLinuxVariable(BO->getLHS()) != V) {
        if (getDirectLinuxVariable(BO->getRHS()) != V)
          return;
        Other = BO->getLHS();
        switch (Opcode) {
        case BO_LT: Opcode = BO_GT; break;
        case BO_GT: Opcode = BO_LT; break;
        case BO_LE: Opcode = BO_GE; break;
        case BO_GE: Opcode = BO_LE; break;
        default: break;
        }
      }
      std::optional<llvm::APSInt> K = Other->getIntegerConstantExpr(Ctx);
      if (!K)
        return;
      if (K->isZero()) {
        switch (Opcode) {
        case BO_NE: T = Knowledge::NonZero; F = Knowledge::Zero; break;
        case BO_EQ: T = Knowledge::Zero; F = Knowledge::NonZero; break;
        case BO_LT:
        case BO_GT: T = Knowledge::NonZero; break;
        case BO_LE:
        case BO_GE: F = Knowledge::NonZero; break;
        default: break;
        }
      } else if (Opcode == BO_EQ) {
        T = Knowledge::NonZero;
      } else if (Opcode == BO_NE) {
        F = Knowledge::NonZero;
      }
    } else {
      return;
    }
    if (Negated)
      std::swap(T, F);
    OnTrue = T;
    OnFalse = F;
  }

  void report(const Stmt *At, unsigned DiagID, const VarDecl *V,
              const CallExpr *Message) {
    S.Diag(At->getBeginLoc(), DiagID) << V << At->getSourceRange();
    if (Message)
      S.Diag(Message->getExprLoc(), diag::note_linux_kernel_failure_reported)
          << Message->getSourceRange();
  }

  Facts runBlock(const CFGBlock *B, Facts St, const VarDecl *V, bool Report) {
    for (const CFGElement &Elem : *B) {
      std::optional<CFGStmt> CS = Elem.getAs<CFGStmt>();
      if (!CS)
        continue;
      const Stmt *St_ = CS->getStmt();
      if (const auto *BO = dyn_cast<BinaryOperator>(St_)) {
        if (BO->isAssignmentOp() && getDirectLinuxVariable(BO->getLHS()) == V) {
          std::optional<bool> IsZero;
          if (BO->getOpcode() == BO_Assign)
            IsZero = isZeroConstant(BO->getRHS());
          St.assigned(IsZero && *IsZero, IsZero && !*IsZero);
        }
      } else if (const auto *UO = dyn_cast<UnaryOperator>(St_)) {
        if (UO->isIncrementDecrementOp() &&
            getDirectLinuxVariable(UO->getSubExpr()) == V)
          St.assigned(false, false);
      } else if (const auto *DS = dyn_cast<DeclStmt>(St_)) {
        for (const Decl *D : DS->decls())
          if (D == V) {
            std::optional<bool> IsZero = isZeroConstant(V->getInit());
            St.assigned(IsZero && *IsZero, IsZero && !*IsZero);
          }
      } else if (const auto *CE = dyn_cast<CallExpr>(St_)) {
        const FunctionDecl *Callee = CE->getDirectCallee();
        if (Report && St.Zero && Callee && Callee->getIdentifier() &&
            Callee->getName() == "dev_err_probe" && CE->getNumArgs() >= 2 &&
            getDirectLinuxVariable(CE->getArg(1)) == V)
          report(CE, diag::warn_linux_kernel_error_probe_zero, V, nullptr);
        if (isFailureMessage(CE)) {
          St.Message = true;
          St.MessageCall = CE;
        }
      } else if (const auto *RS = dyn_cast<ReturnStmt>(St_)) {
        if (Report && getDirectLinuxVariable(RS->getRetValue()) == V) {
          if (St.Zero && St.Message)
            report(RS, diag::warn_linux_kernel_error_path_success, V,
                   St.MessageCall);
          else if (St.Jumped)
            report(RS, diag::warn_linux_kernel_error_path_success, V,
                   St.JumpMessage);
        }
      }
    }
    return St;
  }

  /// Whether \p B can reach itself.  A label inside a loop, as in
  /// "report the bad entry; goto skip_one;", is not the way out of the
  /// function, and the work goes on after it.
  bool isInCycle(const CFGBlock *B) {
    auto Known = InCycle.find(B);
    if (Known != InCycle.end())
      return Known->second;
    llvm::SmallPtrSet<const CFGBlock *, 32> Seen;
    llvm::SmallVector<const CFGBlock *, 16> Worklist;
    Worklist.push_back(B);
    bool Result = false;
    while (!Worklist.empty() && !Result) {
      const CFGBlock *Cur = Worklist.pop_back_val();
      for (const CFGBlock::AdjacentBlock &Succ : Cur->succs()) {
        const CFGBlock *Next = Succ.getReachableBlock();
        if (!Next)
          continue;
        if (Next == B || Seen.size() > 512) {
          Result = true;
          break;
        }
        if (Seen.insert(Next).second)
          Worklist.push_back(Next);
      }
    }
    InCycle[B] = Result;
    return Result;
  }

  static bool isConditionalBranch(const CFGBlock *B) {
    const Stmt *Term = B->getTerminatorStmt();
    return Term && B->succ_size() == 2 && !isa<SwitchStmt>(Term) &&
           !isa<GCCAsmStmt>(Term) &&
           isa_and_nonnull<Expr>(B->getTerminatorCondition());
  }

  /// Propagate facts to fixpoint.  With \p JumpPass false only Zero and
  /// Message are computed.  With it true, those are taken as final and only
  /// Jumped is propagated, so that it cannot depend on an early, optimistic
  /// value of Message.
  void solve(const VarDecl *V, std::vector<Facts> &In, bool JumpPass) {
    bool Changed = true;
    unsigned Rounds = 0;
    while (Changed && ++Rounds < 64) {
      Changed = false;
      for (const CFGBlock *B : Cfg) {
        const Facts &Entry = In[B->getBlockID()];
        if (!Entry.Reached)
          continue;
        Facts Out = runBlock(B, Entry, V, /*Report=*/false);

        Knowledge OnTrue = Knowledge::None, OnFalse = Knowledge::None;
        if (isConditionalBranch(B))
          classify(cast<Expr>(B->getTerminatorCondition()), V, OnTrue,
                   OnFalse);
        bool IsGoto = isa_and_nonnull<GotoStmt>(B->getTerminatorStmt());

        unsigned Index = 0;
        for (const CFGBlock::AdjacentBlock &Succ : B->succs()) {
          Knowledge K = Index++ == 0 ? OnTrue : OnFalse;
          const CFGBlock *Next = Succ.getReachableBlock();
          if (!Next)
            continue;
          Facts Edge = Out;
          if (JumpPass && IsGoto && Out.Zero && Out.Message &&
              !isInCycle(Next)) {
            Edge.Jumped = true;
            Edge.JumpMessage = Out.MessageCall;
          }
          if (K == Knowledge::Zero) {
            // The variable cannot be zero on this path, as in a test that
            // sits inside "if (ret)".
            if (Out.NonZero)
              continue;
            Edge.Zero = true;
          } else if (K == Knowledge::NonZero) {
            Edge.Zero = false;
            Edge.NonZero = true;
            Edge.Jumped = false;
          }

          Facts &Target = In[Next->getBlockID()];
          if (JumpPass) {
            if (Edge.Jumped && !Target.Jumped) {
              Target.Jumped = true;
              Target.JumpMessage = Edge.JumpMessage;
              Changed = true;
            }
            continue;
          }
          if (!Target.Reached) {
            Target = Edge;
            Target.Reached = true;
            Target.Jumped = false;
            Target.JumpMessage = nullptr;
            Changed = true;
            continue;
          }
          bool Zero = Target.Zero || Edge.Zero;
          bool NonZero = Target.NonZero && Edge.NonZero;
          bool Message = Target.Message && Edge.Message;
          if (Zero != Target.Zero || NonZero != Target.NonZero ||
              Message != Target.Message) {
            Target.Zero = Zero;
            Target.NonZero = NonZero;
            Target.Message = Message;
            if (!Message)
              Target.MessageCall = nullptr;
            Changed = true;
          }
        }
      }
    }
  }

public:
  ErrorPathSuccessChecker(Sema &S, const FunctionDecl *FD, const CFG &Cfg)
      : S(S), FD(FD), Cfg(Cfg), Ctx(S.getASTContext()) {}

  void run() {
    QualType RT = FD->getReturnType();
    if (!RT->isSignedIntegerType() || RT->isBooleanType() ||
        RT->isEnumeralType() || RT->isAnyCharacterType())
      return;
    collect(FD->getBody());

    for (const VarDecl *V : Candidates) {
      if (AddressTaken.count(V) || Counters.count(V) ||
          !ErrorCapable.count(V))
        continue;
      std::vector<Facts> In(Cfg.getNumBlockIDs());
      In[Cfg.getEntry().getBlockID()].Reached = true;
      solve(V, In, /*JumpPass=*/false);
      solve(V, In, /*JumpPass=*/true);
      for (const CFGBlock *B : Cfg)
        if (In[B->getBlockID()].Reached)
          runBlock(B, In[B->getBlockID()], V, /*Report=*/true);
    }
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
             diag::warn_linux_kernel_negative_errno_unsigned_return, Loc) ||
         !Diags.isIgnored(
             diag::warn_linux_kernel_negative_errno_truncated_return, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_unsigned_error_check, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_wrong_check_base, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_wrong_check_other, Loc);
}

} // namespace

void clang::sema::IssueLinuxKernelWarnings(Sema &S, const FunctionDecl *FD) {
  if (!FD || S.getLangOpts().CPlusPlus ||
      !shouldRunLinuxKernelWarnings(S, FD->getBeginLoc()))
    return;

  LinuxKernelWarningsVisitor(S, FD).TraverseStmt(FD->getBody());
}

bool clang::sema::wantsLinuxKernelFlowWarnings(Sema &S,
                                               const FunctionDecl *FD) {
  if (!FD || S.getLangOpts().CPlusPlus)
    return false;
  const DiagnosticsEngine &Diags = S.getDiagnostics();
  SourceLocation Loc = FD->getBeginLoc();
  return !Diags.isIgnored(diag::warn_linux_kernel_error_path_success, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_error_probe_zero, Loc);
}

void clang::sema::IssueLinuxKernelFlowWarnings(Sema &S, const FunctionDecl *FD,
                                               AnalysisDeclContext &AC) {
  if (!wantsLinuxKernelFlowWarnings(S, FD) || !FD->getBody())
    return;
  if (const CFG *Cfg = AC.getCFG())
    ErrorPathSuccessChecker(S, FD, *Cfg).run();
}
