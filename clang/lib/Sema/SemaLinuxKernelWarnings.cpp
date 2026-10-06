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
#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DynamicRecursiveASTVisitor.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/Stmt.h"
#include "clang/Analysis/Analyses/Dominators.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Analysis/CFG.h"
#include "clang/Basic/Builtins.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/DiagnosticSema.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Lex/Lexer.h"
#include "clang/Sema/Sema.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/SmallBitVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/IOSandbox.h"
#include "llvm/Support/LineIterator.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using namespace clang;

/// Where the pointers that a function returns come from, as far as its body
/// tells.
struct sema::LinuxKernelUnit::Impl {
  struct ReturnSources {
    bool ErrDirect = false;  ///< ERR_PTR() or ERR_CAST()
    bool ErrCallee = false;  ///< the result of an error-pointer function
    bool NullDirect = false; ///< NULL
    bool NullCallee = false; ///< the untested result of a function that
                             ///< returns NULL on failure
    bool Valid = false;      ///< an address, or a value tested for NULL
    bool Memory = false;     ///< a parameter or a field: no call, no constant
    bool Opaque = false;     ///< a call that nothing is known about
    /// Functions without a body in this translation unit that the answer
    /// depends on, and what their result was tested for before it was
    /// returned.
    enum : uint8_t { NullTested = 1, ErrorTested = 2 };
    llvm::SmallVector<std::pair<const FunctionDecl *, uint8_t>, 2> External;

    /// A function that only ever returns ERR_PTR(), or only NULL, stands in
    /// for a real implementation that some other configuration has.  It says
    /// nothing about the convention of that implementation.
    bool isStub() const {
      return (ErrDirect || NullDirect) && !ErrCallee && !NullCallee &&
             !Valid && !Memory && !Opaque && External.empty();
    }
  };

  enum : uint8_t { ErrPtr = 1, Null = 2 };

  bool ContractsLoaded = false;
  llvm::StringMap<uint8_t> Contracts;
  llvm::DenseMap<const FunctionDecl *, ReturnSources> Sources;
  llvm::SmallPtrSet<const FunctionDecl *, 8> InProgress;
  ReturnSources OpaqueSources;
  /// The functions that a function calls whenever it runs to its end.
  llvm::DenseMap<const FunctionDecl *,
                 llvm::SmallVector<const FunctionDecl *, 4>>
      AlwaysCalled;
  /// For a pointer parameter of a function with a body: where the function
  /// dereferences it before its first branch, or null.
  llvm::DenseMap<const ParmVarDecl *, const Expr *> EntryDerefs;
  /// What a function with a body can store to, itself or through the
  /// functions that it calls.
  struct Writes {
    /// A store that cannot be pinned down.
    bool Anything = false;
    /// The members that are assigned, in whatever object.
    llvm::SmallPtrSet<const FieldDecl *, 8> Fields;
    /// The structures that are handed to functions without a body here.
    llvm::SmallPtrSet<const RecordDecl *, 4> Records;
  };
  llvm::DenseMap<const FunctionDecl *, Writes> WriteSummaries;
  /// Whether a function with a body may keep the pointer that a parameter
  /// is given.
  llvm::DenseMap<const ParmVarDecl *, bool> Captures;

  Impl() { OpaqueSources.Opaque = true; }
};

sema::LinuxKernelUnit::LinuxKernelUnit() : State(std::make_unique<Impl>()) {}
sema::LinuxKernelUnit::~LinuxKernelUnit() = default;

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
  /// The contract is not listed or annotated: it was inferred from the
  /// definition of the function.
  bool Inferred = false;
  /// Where a variable was given the value, if it is held by one.
  SourceLocation Assigned = SourceLocation();
  /// The variable was given the value of another variable or of a member,
  /// which the function may have tested under that name.
  bool Copied = false;

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
      .Cases({"memdup_user", "memdup_user_nul"},
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

/// Whether the code at \p Loc was written in the body of a macro, at any
/// level of expansion, and not where the outermost macro is used.  The
/// argument of unlikely() is written by its user.  ERR_PTR(0) that a macro
/// hands to another macro is written by the first macro.
static bool isWrittenInMacro(SourceLocation Loc, const SourceManager &SM) {
  while (Loc.isMacroID()) {
    if (SM.isMacroBodyExpansion(Loc))
      return true;
    Loc = SM.getImmediateMacroCallerLoc(Loc);
  }
  return false;
}

/// The local variable that \p E names directly, if any.
static const VarDecl *getDirectLinuxVariable(const Expr *E) {
  if (!E)
    return nullptr;
  const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts());
  return DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
}

/// Whether the branch at the end of \p B is spelled in the body of a macro:
/// its "if", "while" or "for" keyword, or its "&&", "||" or "?".  The
/// condition can still be an argument that the user of the macro wrote.
static bool isLinuxBranchWrittenInMacro(const CFGBlock *B,
                                        const SourceManager &SM) {
  const Stmt *Term = B->getTerminatorStmt();
  if (!Term)
    return false;
  SourceLocation Loc = Term->getBeginLoc();
  if (const auto *BO = dyn_cast<BinaryOperator>(Term))
    Loc = BO->getOperatorLoc();
  else if (const auto *CO = dyn_cast<ConditionalOperator>(Term))
    Loc = CO->getQuestionLoc();
  else if (const auto *DS = dyn_cast<DoStmt>(Term))
    Loc = DS->getWhileLoc();
  return isWrittenInMacro(Loc, SM);
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

enum class LinuxKernelReturnConvention { Unknown, ErrorPointer, NullOnFailure };

/// Infers what the table above lists by hand: how a function reports failure
/// through the pointer it returns.  The answer comes from the body when this
/// translation unit has one, and from the -flinux-kernel-contracts= file for a
/// function that is only declared here.  That file is the closure, over all
/// translation units, of the facts that emitFacts() writes.
class LinuxKernelInference {
  using Impl = sema::LinuxKernelUnit::Impl;
  using Sources = Impl::ReturnSources;

  Sema &S;
  ASTContext &Ctx;
  Impl &U;

  static const FunctionDecl *getBodyDecl(const FunctionDecl *FD) {
    const FunctionDecl *Def = nullptr;
    return FD->hasBody(Def) ? Def : nullptr;
  }

  void loadContracts() {
    if (U.ContractsLoaded)
      return;
    U.ContractsLoaded = true;
    const std::string &Path = S.getLangOpts().LinuxKernelContractsFile;
    if (Path.empty())
      return;
    auto Buffer = S.getSourceManager().getFileManager().getBufferForFile(Path);
    if (!Buffer) {
      S.Diag(SourceLocation(), diag::err_linux_kernel_contracts_file)
          << Path << Buffer.getError().message();
      return;
    }
    for (llvm::line_iterator Line(**Buffer, /*SkipBlanks=*/true, '#');
         !Line.is_at_end(); ++Line) {
      auto [Kind, Name] = Line->split('\t');
      uint8_t Flag = llvm::StringSwitch<uint8_t>(Kind)
                         .Case("err_ptr", Impl::ErrPtr)
                         .Case("null", Impl::Null)
                         .Default(0);
      Name = Name.trim();
      if (Flag && !Name.empty())
        U.Contracts[Name] |= Flag;
    }
  }

  /// The contract that the file has for \p FD, which has no body here.
  LinuxKernelReturnConvention fileContract(const FunctionDecl *FD) {
    if (!FD->getIdentifier() || !FD->isExternallyVisible())
      return LinuxKernelReturnConvention::Unknown;
    loadContracts();
    auto It = U.Contracts.find(FD->getName());
    if (It == U.Contracts.end())
      return LinuxKernelReturnConvention::Unknown;
    if (It->second == Impl::ErrPtr)
      return LinuxKernelReturnConvention::ErrorPointer;
    if (It->second == Impl::Null)
      return LinuxKernelReturnConvention::NullOnFailure;
    return LinuxKernelReturnConvention::Unknown;
  }

  struct VariableValues {
    llvm::SmallVector<const Expr *, 4> Values;
    /// The address is taken or the variable is changed in some other way
    /// than a plain assignment.
    bool Opaque = false;
    /// The function leaves when a test finds the variable to be NULL.
    bool NullChecked = false;
    /// The function tests the variable with IS_ERR() or takes its PTR_ERR(),
    /// so it may hold an error pointer wherever it came from.
    bool ErrorTested = false;
  };

  static bool leaves(const Stmt *St) {
    while (St) {
      if (isa<ReturnStmt, GotoStmt, BreakStmt, ContinueStmt>(St))
        return true;
      if (const auto *CS = dyn_cast<CompoundStmt>(St))
        St = CS->body_empty() ? nullptr : CS->body_back();
      else if (const auto *AS = dyn_cast<AttributedStmt>(St))
        St = AS->getSubStmt();
      else
        return false;
    }
    return false;
  }

  static bool returnsVariable(const Stmt *St, const VarDecl *V) {
    if (!St)
      return false;
    if (const auto *RS = dyn_cast<ReturnStmt>(St)) {
      const Expr *E = RS->getRetValue();
      return E && getDirectLinuxVariable(E->IgnoreParenCasts()) == V;
    }
    for (const Stmt *Child : St->children())
      if (returnsVariable(Child, V))
        return true;
    return false;
  }

  /// 1 if \p Cond being true means that \p V is NULL, 2 if it means that
  /// \p V is not NULL, and 0 if it says neither.
  int nullTest(const Expr *Cond, const VarDecl *V) const {
    bool Negated = false;
    const Expr *E = stripLinuxCondition(Cond, Negated);
    if (!E)
      return 0;
    int Result = 0;
    if (getDirectLinuxVariable(E) == V) {
      Result = 2;
    } else if (const auto *BO =
                   dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts())) {
      if (BO->isEqualityOp()) {
        const Expr *Other = nullptr;
        if (getDirectLinuxVariable(BO->getLHS()) == V)
          Other = BO->getRHS();
        else if (getDirectLinuxVariable(BO->getRHS()) == V)
          Other = BO->getLHS();
        if (Other && Other->isNullPointerConstant(
                         Ctx, Expr::NPC_ValueDependentIsNotNull))
          Result = BO->getOpcode() == BO_EQ ? 1 : 2;
      } else if (BO->getOpcode() == BO_LOr && !Negated) {
        // "!p || broken(p)" is true whenever p is NULL.
        return nullTest(BO->getLHS(), V) == 1 || nullTest(BO->getRHS(), V) == 1;
      }
    } else if (const auto *CE = dyn_cast<CallExpr>(E->IgnoreParenImpCasts())) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (Callee && Callee->getIdentifier() &&
          Callee->getName() == "IS_ERR_OR_NULL" && CE->getNumArgs() == 1 &&
          getDirectLinuxVariable(CE->getArg(0)->IgnoreParenCasts()) == V)
        Result = 1;
    }
    if (Result && Negated)
      Result = 3 - Result;
    return Result;
  }

  void collectVariable(const Stmt *St, const VarDecl *V,
                       VariableValues &Out) const {
    if (!St)
      return;
    if (const auto *DS = dyn_cast<DeclStmt>(St)) {
      for (const Decl *D : DS->decls())
        if (D == V && V->hasInit())
          Out.Values.push_back(V->getInit());
    } else if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
      if (BO->isAssignmentOp() && getDirectLinuxVariable(BO->getLHS()) == V) {
        if (BO->getOpcode() == BO_Assign)
          Out.Values.push_back(BO->getRHS());
        else
          Out.Opaque = true;
      }
    } else if (const auto *UO = dyn_cast<UnaryOperator>(St)) {
      if ((UO->getOpcode() == UO_AddrOf || UO->isIncrementDecrementOp()) &&
          getDirectLinuxVariable(UO->getSubExpr()) == V)
        Out.Opaque = true;
    } else if (const auto *AS = dyn_cast<GCCAsmStmt>(St)) {
      for (unsigned I = 0, E = AS->getNumOutputs(); I != E; ++I)
        if (getDirectLinuxVariable(AS->getOutputExpr(I)) == V)
          Out.Opaque = true;
    } else if (const auto *IS = dyn_cast<IfStmt>(St)) {
      int Test = nullTest(IS->getCond(), V);
      const Stmt *NullBranch = Test == 1   ? IS->getThen()
                               : Test == 2 ? IS->getElse()
                                           : nullptr;
      // "if (IS_ERR_OR_NULL(p)) return p;" does not keep the NULL from the
      // caller: it is what the function returns there.
      if (NullBranch && leaves(NullBranch) && !returnsVariable(NullBranch, V))
        Out.NullChecked = true;
    } else if (const auto *CE = dyn_cast<CallExpr>(St)) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      // IS_ERR_OR_NULL() is a NULL test, which the "if" above deals with.
      if (Callee && Callee->getIdentifier() && CE->getNumArgs() == 1 &&
          (Callee->getName() == "IS_ERR" ||
           Callee->getName().starts_with("PTR_ERR")) &&
          getDirectLinuxVariable(CE->getArg(0)->IgnoreParenCasts()) == V)
        Out.ErrorTested = true;
    }
    for (const Stmt *Child : St->children())
      collectVariable(Child, V, Out);
  }

  /// What a function hands on from the function it calls keeps the nature of
  /// that function: the wrapper of a stub is a stub.
  static void merge(Sources &R, const Sources &Callee, uint8_t Tests) {
    bool Stub = Callee.isStub();
    bool NullChecked = Tests & Sources::NullTested;
    if (Callee.ErrDirect || Callee.ErrCallee)
      (Stub ? R.ErrDirect : R.ErrCallee) = true;
    if (Callee.NullDirect || Callee.NullCallee) {
      if (NullChecked)
        R.Valid = true;
      else
        (Stub ? R.NullDirect : R.NullCallee) = true;
    }
    if (Callee.Valid)
      R.Valid = true;
    // What the caller tests is an object to its author once the test has
    // passed, wherever the callee has it from.
    if (Callee.Memory)
      (Tests ? R.Valid : R.Memory) = true;
    if (Callee.Opaque)
      (Tests ? R.Valid : R.Opaque) = true;
    for (auto [F, Earlier] : Callee.External)
      R.External.push_back({F, uint8_t(Earlier | Tests)});
  }

  void addCall(const CallExpr *Call, Sources &R, bool NullChecked,
               bool ErrorTested, unsigned Depth) {
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee || !Callee->getIdentifier()) {
      // An indirect call.  What the function tests the result for is what
      // it can be: after a NULL test or an IS_ERR() test, what is left is
      // an object.
      (NullChecked || ErrorTested ? R.Valid : R.Opaque) = true;
      return;
    }
    uint8_t Tests = (NullChecked ? Sources::NullTested : 0) |
                    (ErrorTested ? Sources::ErrorTested : 0);
    StringRef Name = Callee->getName();
    if (Name == "ERR_PTR" || Name == "ERR_CAST") {
      // ERR_PTR(0) is NULL.
      std::optional<llvm::APSInt> Error;
      if (Name == "ERR_PTR" && Call->getNumArgs() == 1)
        Error = Call->getArg(0)->getIntegerConstantExpr(Ctx);
      (Error && Error->isZero() ? R.NullDirect : R.ErrDirect) = true;
      return;
    }
    LinuxKernelAPIKind Kind = classifyLinuxKernelCallee(Callee);
    if (Kind == LinuxKernelAPIKind::ErrorPointer) {
      R.ErrCallee = true;
    } else if (isNullReturningKind(Kind)) {
      (NullChecked ? R.Valid : R.NullCallee) = true;
    } else if (Kind != LinuxKernelAPIKind::None ||
               !Callee->getReturnType()->isPointerType()) {
      R.Opaque = true;
    } else if (const FunctionDecl *Def = getBodyDecl(Callee)) {
      merge(R, sources(Def, Depth + 1), Tests);
    } else {
      R.External.push_back({Callee->getCanonicalDecl(), Tests});
    }
  }

  /// \p NullChecked: the function leaves when it finds the value to be
  /// NULL.  \p ErrorTested: the function tests the value with IS_ERR(), so
  /// its author takes it for an error pointer or an object, wherever it
  /// comes from.
  void addValue(const Expr *E, Sources &R, const Stmt *Body, bool NullChecked,
                llvm::SmallPtrSetImpl<const VarDecl *> &Seen, unsigned Depth,
                bool ErrorTested = false) {
    if (!E || Depth > 12) {
      R.Opaque = true;
      return;
    }
    // What was read from memory is an object once it was tested.
    bool Known = NullChecked || ErrorTested;
    E = E->IgnoreParens();
    if (E->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNotNull)) {
      R.NullDirect = true;
      return;
    }
    E = E->IgnoreParenCasts();

    if (const auto *BCO = dyn_cast<BinaryConditionalOperator>(E)) {
      addValue(BCO->getCommon(), R, Body, NullChecked, Seen, Depth + 1,
               ErrorTested);
      addValue(BCO->getFalseExpr(), R, Body, NullChecked, Seen, Depth + 1,
               ErrorTested);
    } else if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
      addValue(CO->getTrueExpr(), R, Body, NullChecked, Seen, Depth + 1,
               ErrorTested);
      addValue(CO->getFalseExpr(), R, Body, NullChecked, Seen, Depth + 1,
               ErrorTested);
    } else if (const auto *SE = dyn_cast<StmtExpr>(E)) {
      const CompoundStmt *CS = SE->getSubStmt();
      const Stmt *Last = CS->body_empty() ? nullptr : CS->body_back();
      addValue(dyn_cast_or_null<Expr>(Last), R, Body, NullChecked, Seen,
               Depth + 1, ErrorTested);
    } else if (const auto *GSE = dyn_cast<GenericSelectionExpr>(E)) {
      addValue(GSE->isResultDependent() ? nullptr : GSE->getResultExpr(), R,
               Body, NullChecked, Seen, Depth + 1,
               ErrorTested);
    } else if (const auto *CE = dyn_cast<ChooseExpr>(E)) {
      addValue(CE->isConditionDependent() ? nullptr : CE->getChosenSubExpr(), R,
               Body, NullChecked, Seen, Depth + 1,
               ErrorTested);
    } else if (const auto *Call = dyn_cast<CallExpr>(E)) {
      addCall(Call, R, NullChecked, ErrorTested, Depth);
    } else if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_Comma || BO->getOpcode() == BO_Assign)
        addValue(BO->getRHS(), R, Body, NullChecked, Seen, Depth + 1,
               ErrorTested);
      else if (BO->isAdditiveOp() && BO->getType()->isPointerType())
        R.Valid = true; // pointer arithmetic, which container_of() is
      else
        R.Opaque = true;
    } else if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_AddrOf)
        R.Valid = true;
      else
        (Known ? R.Valid : R.Memory) = true;
    } else if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
      if (!VD || VD->getType()->isArrayType()) {
        R.Valid = true; // a function or an array
        return;
      }
      if (!VD->hasLocalStorage()) {
        (Known ? R.Valid : R.Memory) = true;
        return;
      }
      if (!Seen.insert(VD).second)
        return;
      VariableValues Info;
      collectVariable(Body, VD, Info);
      // A parameter starts with what the caller passed and can be given
      // other values like any variable.
      bool IsParameter = isa<ParmVarDecl>(VD);
      if (Info.Opaque || (Info.Values.empty() && !IsParameter)) {
        R.Opaque = true;
        return;
      }
      bool Checked = NullChecked || Info.NullChecked;
      bool Tested = ErrorTested || Info.ErrorTested;
      if (IsParameter)
        (Checked || Tested ? R.Valid : R.Memory) = true;
      if (Info.ErrorTested)
        R.ErrCallee = true;
      for (const Expr *Value : Info.Values) {
        // A NULL that the variable held is gone, or leaves the function
        // through the test, before the variable is returned.
        if (Checked && Value->IgnoreParens()->isNullPointerConstant(
                           Ctx, Expr::NPC_ValueDependentIsNotNull))
          continue;
        addValue(Value, R, Body, Checked, Seen, Depth + 1, Tested);
      }
    } else if (isa<StringLiteral>(E)) {
      R.Valid = true;
    } else if (E->getType()->isPointerType() ||
               E->getType()->isArrayType()) {
      // A field or an array element.
      (Known ? R.Valid : R.Memory) = true;
    } else {
      R.Opaque = true; // an integer cast to a pointer
    }
  }

  static void collectReturns(const Stmt *St,
                             llvm::SmallVectorImpl<const ReturnStmt *> &Out) {
    if (!St)
      return;
    if (const auto *RS = dyn_cast<ReturnStmt>(St)) {
      if (RS->getRetValue())
        Out.push_back(RS);
      return;
    }
    for (const Stmt *Child : St->children())
      collectReturns(Child, Out);
  }

  const Sources &sources(const FunctionDecl *Def, unsigned Depth = 0) {
    auto Known = U.Sources.find(Def);
    if (Known != U.Sources.end())
      return Known->second;
    if (Depth > 6 || !U.InProgress.insert(Def).second)
      return U.OpaqueSources;

    Sources R;
    llvm::SmallVector<const ReturnStmt *, 8> Returns;
    collectReturns(Def->getBody(), Returns);
    for (const ReturnStmt *RS : Returns) {
      llvm::SmallPtrSet<const VarDecl *, 8> Seen;
      addValue(RS->getRetValue(), R, Def->getBody(), /*NullChecked=*/false,
               Seen, Depth);
    }
    U.InProgress.erase(Def);
    return U.Sources.insert({Def, std::move(R)}).first->second;
  }

  /// \p In with the functions resolved whose body has appeared since.
  Sources resolve(const Sources &In, unsigned Depth) {
    Sources R = In;
    R.External.clear();
    for (auto [F, Tests] : In.External) {
      const FunctionDecl *Def = getBodyDecl(F);
      if (!Def)
        R.External.push_back({F, Tests});
      else if (Depth < 6)
        merge(R, resolve(Sources(sources(Def)), Depth + 1), Tests);
      else
        R.Opaque = true;
    }
    return R;
  }

  static void addCallsInExpr(const Expr *E,
                             llvm::SmallVectorImpl<const FunctionDecl *> &Out) {
    if (!E)
      return;
    E = E->IgnoreParenImpCasts();
    if (isa<UnaryExprOrTypeTraitExpr>(E))
      return;
    if (const auto *CO = dyn_cast<AbstractConditionalOperator>(E)) {
      addCallsInExpr(CO->getCond(), Out);
      return;
    }
    if (const auto *BO = dyn_cast<BinaryOperator>(E);
        BO && BO->isLogicalOp()) {
      addCallsInExpr(BO->getLHS(), Out);
      return;
    }
    if (const auto *SE = dyn_cast<StmtExpr>(E)) {
      addAlwaysExecuted(SE->getSubStmt(), Out);
      return;
    }
    if (const auto *CE = dyn_cast<CallExpr>(E)) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (Callee && Callee->getIdentifier()) {
        if (!Callee->getBuiltinID())
          Out.push_back(Callee);
      } else {
        addCallsInExpr(CE->getCallee(), Out);
      }
      for (const Expr *Arg : CE->arguments())
        addCallsInExpr(Arg, Out);
      return;
    }
    for (const Stmt *Child : E->children())
      addCallsInExpr(dyn_cast_or_null<Expr>(Child), Out);
  }

  /// The calls that run whenever control reaches \p St and no branch before
  /// them leaves.
  static void
  addAlwaysExecuted(const Stmt *St,
                    llvm::SmallVectorImpl<const FunctionDecl *> &Out) {
    if (!St)
      return;
    if (const auto *CS = dyn_cast<CompoundStmt>(St)) {
      for (const Stmt *Child : CS->body())
        addAlwaysExecuted(Child, Out);
    } else if (const auto *E = dyn_cast<Expr>(St)) {
      addCallsInExpr(E, Out);
    } else if (const auto *DS = dyn_cast<DeclStmt>(St)) {
      for (const Decl *D : DS->decls())
        if (const auto *VD = dyn_cast<VarDecl>(D))
          addCallsInExpr(VD->getInit(), Out);
    } else if (const auto *RS = dyn_cast<ReturnStmt>(St)) {
      addCallsInExpr(RS->getRetValue(), Out);
    } else if (const auto *IS = dyn_cast<IfStmt>(St)) {
      addAlwaysExecuted(IS->getInit(), Out);
      addCallsInExpr(IS->getCond(), Out);
    } else if (const auto *SS = dyn_cast<SwitchStmt>(St)) {
      addCallsInExpr(SS->getCond(), Out);
    } else if (const auto *WS = dyn_cast<WhileStmt>(St)) {
      addCallsInExpr(WS->getCond(), Out);
    } else if (const auto *FS = dyn_cast<ForStmt>(St)) {
      addAlwaysExecuted(FS->getInit(), Out);
      addCallsInExpr(FS->getCond(), Out);
    } else if (const auto *Do = dyn_cast<DoStmt>(St)) {
      addAlwaysExecuted(Do->getBody(), Out);
    } else if (const auto *LS = dyn_cast<LabelStmt>(St)) {
      addAlwaysExecuted(LS->getSubStmt(), Out);
    } else if (const auto *AS = dyn_cast<AttributedStmt>(St)) {
      addAlwaysExecuted(AS->getSubStmt(), Out);
    }
  }

  /// The functions without a body here that \p Def calls whenever it runs,
  /// directly or through functions that do have one.
  void addAlwaysCalledExternals(
      const FunctionDecl *Def,
      llvm::SmallPtrSetImpl<const FunctionDecl *> &Externals,
      llvm::SmallPtrSetImpl<const FunctionDecl *> &Visited, unsigned Depth) {
    if (Depth > 10 || !Visited.insert(Def).second)
      return;
    auto [It, New] = U.AlwaysCalled.try_emplace(Def);
    if (New) {
      llvm::SmallVector<const FunctionDecl *, 16> Calls;
      addAlwaysExecuted(Def->getBody(), Calls);
      // The map may have grown in between: look the entry up again.
      U.AlwaysCalled[Def].assign(Calls.begin(), Calls.end());
    }
    llvm::SmallVector<const FunctionDecl *, 16> Direct(
        U.AlwaysCalled[Def].begin(), U.AlwaysCalled[Def].end());
    for (const FunctionDecl *Callee : Direct) {
      if (const FunctionDecl *CalleeDef = getBodyDecl(Callee))
        addAlwaysCalledExternals(CalleeDef, Externals, Visited, Depth + 1);
      else if (Callee->isExternallyVisible())
        Externals.insert(Callee->getCanonicalDecl());
    }
  }

  /// A function that is told whether it may sleep cannot be said to sleep
  /// always.
  static bool takesSleepHint(const FunctionDecl *FD) {
    for (const ParmVarDecl *P : FD->parameters()) {
      if (const auto *TT = P->getType()->getAs<TypedefType>())
        if (TT->getDecl()->getName() == "gfp_t")
          return true;
      std::string Name = P->getName().lower();
      for (StringRef Word : {"atomic", "sleep", "wait", "block", "gfp"})
        if (StringRef(Name).contains(Word))
          return true;
    }
    return false;
  }

public:
  LinuxKernelInference(Sema &S, sema::LinuxKernelUnit &Unit)
      : S(S), Ctx(S.getASTContext()), U(*Unit.State) {}

  LinuxKernelReturnConvention convention(const FunctionDecl *FD) {
    if (!FD->getReturnType()->isPointerType())
      return LinuxKernelReturnConvention::Unknown;
    const FunctionDecl *Def = getBodyDecl(FD);
    if (!Def)
      return fileContract(FD);

    Sources R = resolve(Sources(sources(Def)), 0);
    for (auto [F, Tests] : R.External) {
      switch (fileContract(F)) {
      case LinuxKernelReturnConvention::ErrorPointer:
        R.ErrCallee = true;
        break;
      case LinuxKernelReturnConvention::NullOnFailure:
        (Tests & Sources::NullTested ? R.Valid : R.NullCallee) = true;
        break;
      case LinuxKernelReturnConvention::Unknown:
        (Tests ? R.Valid : R.Opaque) = true;
        break;
      }
    }
    bool Err = R.ErrDirect || R.ErrCallee;
    bool Null = R.NullDirect || R.NullCallee;
    // An error pointer function never returns NULL, so nothing it returns
    // may be of unknown origin.  A function that returns NULL on failure may
    // return what it found in memory: that is not an error pointer.
    if (Err && !Null && !R.Memory && !R.Opaque && (R.Valid || R.ErrCallee))
      return LinuxKernelReturnConvention::ErrorPointer;
    if (Null && !Err && !R.Opaque && (R.Valid || R.Memory || R.NullCallee))
      return LinuxKernelReturnConvention::NullOnFailure;
    return LinuxKernelReturnConvention::Unknown;
  }

  /// Append one line for each function of this translation unit that other
  /// translation units can call:
  ///
  ///   fn <name> <file> <return sources> <functions it always calls>
  ///
  /// The return sources are the letters E (ERR_PTR), e (error pointer
  /// callee), N (NULL), n (NULL-on-failure callee), V (valid), M (memory)
  /// and O (opaque), followed by ",c:<name>" for each function defined
  /// elsewhere whose result is returned, ",k:<name>" if that result was
  /// tested for NULL first, or ",t:<name>" if it was only tested with
  /// IS_ERR().
  void emitFacts() {
    const std::string &Path = S.getLangOpts().LinuxKernelFactsFile;
    if (Path.empty())
      return;
    const SourceManager &SM = S.getSourceManager();
    std::string Text;
    llvm::raw_string_ostream OS(Text);
    for (const Decl *D : Ctx.getTranslationUnitDecl()->decls()) {
      const auto *FD = dyn_cast<FunctionDecl>(D);
      if (!FD || !FD->doesThisDeclarationHaveABody() || !FD->getIdentifier() ||
          !FD->isExternallyVisible() || FD->isInlined())
        continue;

      std::string Returns = "-";
      if (FD->getReturnType()->isPointerType()) {
        Sources R = resolve(Sources(sources(FD)), 0);
        Returns.clear();
        if (R.ErrDirect) Returns += 'E';
        if (R.ErrCallee) Returns += 'e';
        if (R.NullDirect) Returns += 'N';
        if (R.NullCallee) Returns += 'n';
        if (R.Valid) Returns += 'V';
        if (R.Memory) Returns += 'M';
        if (R.Opaque) Returns += 'O';
        std::vector<std::string> Callees;
        for (auto [F, Tests] : R.External)
          Callees.push_back((Tests & Sources::NullTested ? "k:"
                             : Tests                     ? "t:"
                                                         : "c:") +
                            F->getName().str());
        llvm::sort(Callees);
        Callees.erase(llvm::unique(Callees), Callees.end());
        for (const std::string &C : Callees)
          Returns += "," + C;
        if (Returns.empty())
          Returns = "-";
      }

      std::string Calls = "-";
      if (!takesSleepHint(FD)) {
        llvm::SmallPtrSet<const FunctionDecl *, 16> Externals, Visited;
        addAlwaysCalledExternals(FD, Externals, Visited, 0);
        std::vector<std::string> Names;
        for (const FunctionDecl *F : Externals)
          Names.push_back(F->getName().str());
        llvm::sort(Names);
        if (!Names.empty())
          Calls = llvm::join(Names, ",");
      }
      if (Returns == "-" && Calls == "-")
        continue;

      PresumedLoc PLoc = SM.getPresumedLoc(SM.getExpansionLoc(FD->getLocation()));
      OS << "fn\t" << FD->getName() << '\t'
         << (PLoc.isValid() ? PLoc.getFilename() : "?") << '\t' << Returns
         << '\t' << Calls << '\n';
    }
    if (Text.empty())
      return;

    // The facts file is an output next to the compilation, like a dependency
    // file: it does not go through the virtual file system.
    auto BypassSandbox = llvm::sys::sandbox::scopedDisable();
    std::error_code EC;
    llvm::raw_fd_ostream Out(Path, EC, llvm::sys::fs::CD_OpenAlways,
                             llvm::sys::fs::FA_Write, llvm::sys::fs::OF_Append);
    if (EC) {
      S.Diag(SourceLocation(), diag::err_linux_kernel_contracts_file)
          << Path << EC.message();
      return;
    }
    // Compilations of other translation units append to the same file.
    llvm::Expected<llvm::sys::fs::FileLocker> Lock = Out.lock();
    if (!Lock)
      llvm::consumeError(Lock.takeError());
    Out << Text;
    Out.flush();
  }
};

class LinuxKernelWarningsVisitor : public DynamicRecursiveASTVisitor {
  using DirectField = std::pair<const VarDecl *, const FieldDecl *>;

  Sema &S;
  const FunctionDecl *CurrentFunction;
  mutable LinuxKernelInference Inference;
  /// __free() variables whose cleanup the function switches off somewhere,
  /// with no_free_ptr() or by storing NULL.
  llvm::DenseMap<const VarDecl *, bool> CleanupDisarmed;
  /// Pointers that the function tests somewhere, for NULL or for an error.
  std::optional<llvm::SmallPtrSet<const VarDecl *, 16>> TestedPointers;
  /// Where the function tests each pointer with IS_ERR(), and where it
  /// assigns it.
  struct TestsAndAssignments {
    llvm::SmallVector<SourceLocation, 2> Tests, Assignments;
  };
  std::optional<llvm::DenseMap<const VarDecl *, TestsAndAssignments>>
      ErrorTests;
  /// "if (IS_ERR(p)) return p;": what is returned there is an error pointer
  /// or NULL, which the cleanup functions of <linux/cleanup.h> leave alone.
  llvm::SmallPtrSet<const ReturnStmt *, 4> NothingToRelease;
  llvm::SmallPtrSet<const VarDecl *, 4> ReportedErrorDerefs;
  /// "x & ~mask" expressions whose result is cut down to the width of the
  /// mask anyway.
  llvm::SmallPtrSet<const Expr *, 4> NarrowedAnds;
  /// Where a diagnostic about a macro argument was already given: the
  /// kernel's bit operation macros expand their argument several times.
  llvm::SmallVector<SourceLocation, 4> ReportedSpellings;
  /// For each parameter of a function with a body: where the function
  /// dereferences it without a test, or null.
  llvm::DenseMap<const ParmVarDecl *, const MemberExpr *> ParameterDerefs;
  llvm::DenseMap<const VarDecl *, LinuxKernelAPIOrigin> VariableOrigins;
  llvm::DenseMap<DirectField, LinuxKernelAPIOrigin> FieldOrigins;
  llvm::SmallPtrSet<const Expr *, 4> CoveredNullTests;
  /// IRQ results that have already been tested for a negative value.  A
  /// later boolean test of the same value only handles zero.
  llvm::SmallPtrSet<const VarDecl *, 4> NegativeTestedIRQs;
  /// Pointers that hold an allocation made with __GFP_NOFAIL.
  llvm::SmallPtrSet<const VarDecl *, 4> AllocationsThatCannotFail;
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
      if (Kind != LinuxKernelAPIKind::None)
        return {Kind, Callee};
      switch (Inference.convention(Callee)) {
      case LinuxKernelReturnConvention::ErrorPointer:
        return {LinuxKernelAPIKind::ErrorPointer, Callee, /*Inferred=*/true};
      case LinuxKernelReturnConvention::NullOnFailure:
        return {LinuxKernelAPIKind::NullablePointer, Callee,
                /*Inferred=*/true};
      case LinuxKernelReturnConvention::Unknown:
        break;
      }
      return {};
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

  /// Where the function hands each variable to IS_ERR(), IS_ERR_OR_NULL()
  /// or PTR_ERR(), and where it assigns each variable.
  void collectErrorTests(const Stmt *St) {
    if (!St)
      return;
    if (const auto *CE = dyn_cast<CallExpr>(St)) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (Callee && Callee->getIdentifier() &&
          (Callee->getName().starts_with("IS_ERR") ||
           Callee->getName().starts_with("PTR_ERR")))
        for (const Expr *Arg : CE->arguments())
          if (const VarDecl *VD =
                  getDirectLinuxVariable(Arg->IgnoreParenCasts()))
            (*ErrorTests)[VD].Tests.push_back(CE->getExprLoc());
    } else if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
      if (BO->isAssignmentOp())
        if (const VarDecl *VD = getDirectLinuxVariable(BO->getLHS()))
          (*ErrorTests)[VD].Assignments.push_back(BO->getOperatorLoc());
    }
    for (const Stmt *Child : St->children())
      collectErrorTests(Child);
  }

  /// Whether the function also tests the value of \p E with IS_ERR(),
  /// between the assignment that \p Origin is from and the next one.  Its
  /// NULL test is then for a configuration in which the callee is a stub
  /// that returns NULL, and the code handles both.
  bool isAlsoErrorTested(const Expr *E, const LinuxKernelAPIOrigin &Origin) {
    const VarDecl *VD = getDirectVariable(E);
    if (!VD || !CurrentFunction || Origin.Assigned.isInvalid())
      return false;
    if (!ErrorTests) {
      ErrorTests.emplace();
      collectErrorTests(CurrentFunction->getBody());
    }
    auto It = ErrorTests->find(VD);
    if (It == ErrorTests->end())
      return false;
    const SourceManager &SM = S.getSourceManager();
    auto After = [&](SourceLocation A, SourceLocation B) {
      return SM.isBeforeInTranslationUnit(SM.getExpansionLoc(A),
                                          SM.getExpansionLoc(B));
    };
    // The next assignment after the one that gave the value.
    SourceLocation Next;
    for (SourceLocation Loc : It->second.Assignments)
      if (After(Origin.Assigned, Loc) && (Next.isInvalid() || After(Loc, Next)))
        Next = Loc;
    for (SourceLocation Loc : It->second.Tests)
      if (After(Origin.Assigned, Loc) && (Next.isInvalid() || After(Loc, Next)))
        return true;
    return false;
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
    const Expr *Tested = nullptr;
    if (RHS->isNullPointerConstant(S.getASTContext(),
                                   Expr::NPC_ValueDependentIsNotNull))
      Tested = LHS;
    else if (LHS->isNullPointerConstant(S.getASTContext(),
                                        Expr::NPC_ValueDependentIsNotNull))
      Tested = RHS;
    if (Tested)
      Origin = getOrigin(Tested);

    if (Origin.Kind == LinuxKernelAPIKind::ErrorPointer &&
        !isAlsoErrorTested(Tested, Origin)) {
      S.Diag(BO->getOperatorLoc(), diag::warn_linux_kernel_null_test_on_err_ptr)
          << Origin.getName() << BO->getSourceRange();
      noteInferred(Origin);
    }
  }

  void checkErrorPointerBooleanTest(const UnaryOperator *UO) {
    if (CoveredNullTests.contains(UO) || isLinuxAssertionMacroExpansion(UO, S))
      return;
    const Expr *Value = UO->getSubExpr();
    LinuxKernelAPIOrigin Origin = getOrigin(Value);
    if (Origin.Kind == LinuxKernelAPIKind::ErrorPointer &&
        !isAlsoErrorTested(Value, Origin)) {
      S.Diag(Value->getExprLoc(), diag::warn_linux_kernel_null_test_on_err_ptr)
          << Origin.getName() << Value->getSourceRange();
      noteInferred(Origin);
    }
  }

  void noteInferred(const LinuxKernelAPIOrigin &Origin) const {
    if (Origin.Inferred && Origin.Callee)
      S.Diag(Origin.Callee->getLocation(),
             diag::note_linux_kernel_contract_inferred)
          << Origin.Callee;
  }

  /// The single argument of a call to the function \p Name.
  static const Expr *getHelperArg(const Expr *E, StringRef Name) {
    const auto *CE =
        dyn_cast_or_null<CallExpr>(E ? E->IgnoreParenImpCasts() : nullptr);
    const FunctionDecl *Callee = CE ? CE->getDirectCallee() : nullptr;
    if (!Callee || !Callee->getIdentifier() || Callee->getName() != Name ||
        CE->getNumArgs() != 1)
      return nullptr;
    return CE->getArg(0)->IgnoreParenCasts();
  }

  /// What a condition says about pointers when it is true.
  struct PointerTests {
    llvm::SmallVector<const Expr *, 2> Errors; ///< IS_ERR(x)
    const Expr *ErrorOrNull = nullptr;         ///< IS_ERR_OR_NULL(x)
    const Expr *Null = nullptr;                ///< !x
  };

  void addPointerTests(const Expr *Cond, bool WhenTrue, PointerTests &Out) {
    bool Negated = false;
    const Expr *E = stripLinuxCondition(Cond, Negated);
    if (!E)
      return;
    bool Holds = WhenTrue != Negated;
    ASTContext &Ctx = S.getASTContext();
    if (const Expr *Arg = getHelperArg(E, "IS_ERR")) {
      if (Holds)
        Out.Errors.push_back(Arg);
    } else if (const Expr *Arg = getHelperArg(E, "IS_ERR_OR_NULL")) {
      if (Holds)
        Out.ErrorOrNull = Arg;
    } else if (const auto *BO =
                   dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts())) {
      if (BO->isLogicalOp()) {
        // "a && b" is true only if both are, "a || b" false only if both are.
        if ((BO->getOpcode() == BO_LAnd) == Holds) {
          addPointerTests(BO->getLHS(), Holds, Out);
          addPointerTests(BO->getRHS(), Holds, Out);
        } else if (Holds) {
          // One of the two holds.  Either error test can be the failure, a
          // NULL test alone cannot be said to be.
          PointerTests L, R;
          addPointerTests(BO->getLHS(), true, L);
          addPointerTests(BO->getRHS(), true, R);
          Out.Errors.append(L.Errors);
          Out.Errors.append(R.Errors);
        }
      } else if (BO->isEqualityOp()) {
        const Expr *Other = nullptr;
        if (BO->getRHS()->isNullPointerConstant(
                Ctx, Expr::NPC_ValueDependentIsNotNull))
          Other = BO->getLHS();
        else if (BO->getLHS()->isNullPointerConstant(
                     Ctx, Expr::NPC_ValueDependentIsNotNull))
          Other = BO->getRHS();
        if (Other && (BO->getOpcode() == BO_EQ) == Holds)
          Out.Null = Other->IgnoreParenCasts();
      }
    } else if (!Holds && E->getType()->isPointerType() &&
               isSimpleLinuxStorage(E)) {
      Out.Null = E->IgnoreParenCasts();
    }
  }

  bool mentionsExpr(const Stmt *St, const Expr *E) const {
    if (!St)
      return false;
    if (const auto *Inner = dyn_cast<Expr>(St))
      if (isSameLinuxExpr(S.getASTContext(), Inner, E))
        return true;
    for (const Stmt *Child : St->children())
      if (mentionsExpr(Child, E))
        return true;
    return false;
  }

  static bool assigns(const Stmt *St, const ASTContext &Ctx, const Expr *To) {
    if (!St)
      return false;
    if (const auto *BO = dyn_cast<BinaryOperator>(St))
      if (BO->isAssignmentOp() && isSameLinuxExpr(Ctx, BO->getLHS(), To))
        return true;
    for (const Stmt *Child : St->children())
      if (assigns(Child, Ctx, To))
        return true;
    return false;
  }

  void checkPtrErrIn(const Stmt *St, const Stmt *Branch,
                     const PointerTests &Tests) {
    // A nested test has its own answer: "t ? PTR_ERR(t) : -ENOMEM".  So has
    // "switch (PTR_ERR(t))", which sorts out the values itself.
    if (!St || isa<IfStmt, AbstractConditionalOperator, SwitchStmt>(St))
      return;
    if (const auto *BO = dyn_cast<BinaryOperator>(St); BO && BO->isLogicalOp())
      return;
    ASTContext &Ctx = S.getASTContext();
    if (const Expr *Arg = getHelperArg(dyn_cast<Expr>(St), "PTR_ERR")) {
      const auto *Call = cast<CallExpr>(cast<Expr>(St)->IgnoreParenImpCasts());
      if (Tests.Null && isSameLinuxExpr(Ctx, Arg, Tests.Null)) {
        S.Diag(Call->getExprLoc(), diag::warn_linux_kernel_ptr_err_null)
            << getLinuxExprText(Arg, S) << 0 << Call->getSourceRange();
      } else if (Tests.ErrorOrNull &&
                 isSameLinuxExpr(Ctx, Arg, Tests.ErrorOrNull)) {
        S.Diag(Call->getExprLoc(), diag::warn_linux_kernel_ptr_err_null)
            << getLinuxExprText(Arg, S) << 1 << Call->getSourceRange();
      } else if (!Tests.Errors.empty() && !Tests.ErrorOrNull && !Tests.Null &&
                 isSimpleLinuxStorage(Arg) &&
                 llvm::all_of(Tests.Errors, isSimpleLinuxStorage) &&
                 llvm::none_of(Tests.Errors,
                               [&](const Expr *T) {
                                 return isSameLinuxExpr(Ctx, Arg, T);
                               }) &&
                 !assigns(Branch, Ctx, Arg)) {
        S.Diag(Call->getExprLoc(), diag::warn_linux_kernel_ptr_err_other)
            << getLinuxExprText(Arg, S)
            << getLinuxExprText(Tests.Errors.front(), S)
            << Call->getSourceRange();
      }
      return;
    }
    for (const Stmt *Child : St->children())
      checkPtrErrIn(Child, Branch, Tests);
  }

  /// PTR_ERR() in the branch that a pointer test leads to: of a pointer
  /// that is NULL there, or of another pointer than the one tested.
  void checkPtrErrAfterTest(const IfStmt *IS) {
    if (!IS->getCond())
      return;
    for (bool WhenTrue : {true, false}) {
      const Stmt *Branch = WhenTrue ? IS->getThen() : IS->getElse();
      if (!Branch)
        continue;
      PointerTests Tests;
      addPointerTests(IS->getCond(), WhenTrue, Tests);
      if (Tests.Errors.empty() && !Tests.ErrorOrNull && !Tests.Null)
        continue;
      if (const auto *CS = dyn_cast<CompoundStmt>(Branch)) {
        for (const Stmt *Child : CS->body()) {
          checkPtrErrIn(Child, Branch, Tests);
          // "if (!t) return -EINVAL;" inside the branch: what comes after
          // it knows more than the outer test.
          const auto *Nested = dyn_cast<IfStmt>(Child);
          if (Nested && Nested->getCond() &&
              ((Tests.Null && mentionsExpr(Nested->getCond(), Tests.Null)) ||
               (Tests.ErrorOrNull &&
                mentionsExpr(Nested->getCond(), Tests.ErrorOrNull))))
            break;
        }
      } else {
        checkPtrErrIn(Branch, Branch, Tests);
      }
    }
  }

  using PointerCopies =
      llvm::SmallVector<std::pair<const VarDecl *, const VarDecl *>, 8>;

  /// The pointers that \p St tests, and the pairs of pointers of which one
  /// is a plain copy of the other.
  static void collectTestedPointers(
      const Stmt *St, llvm::SmallPtrSetImpl<const VarDecl *> &Out,
      PointerCopies *Copies = nullptr) {
    if (!St)
      return;
    auto Add = [&](const Expr *E) {
      if (const VarDecl *VD =
              getDirectLinuxVariable(E ? E->IgnoreParenCasts() : nullptr))
        Out.insert(VD);
    };
    auto AddCopy = [&](const VarDecl *To, const Expr *From) {
      const VarDecl *Source =
          getDirectLinuxVariable(From ? From->IgnoreParenCasts() : nullptr);
      if (Copies && To && Source && To != Source &&
          To->getType()->isPointerType() && Source->getType()->isPointerType())
        Copies->push_back({To, Source});
    };
    if (const auto *DS = dyn_cast<DeclStmt>(St)) {
      for (const Decl *D : DS->decls())
        if (const auto *VD = dyn_cast<VarDecl>(D))
          AddCopy(VD, VD->getInit());
    } else if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
      if (BO->getOpcode() == BO_Assign)
        AddCopy(getDirectLinuxVariable(BO->getLHS()), BO->getRHS());
    }
    if (const auto *CE = dyn_cast<CallExpr>(St)) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (Callee && Callee->getIdentifier() &&
          (Callee->getName().contains("IS_ERR") ||
           Callee->getName().contains("PTR_ERR") ||
           Callee->getName() == "ERR_CAST"))
        for (const Expr *Arg : CE->arguments())
          Add(Arg);
    } else if (const auto *UO = dyn_cast<UnaryOperator>(St)) {
      if (UO->getOpcode() == UO_LNot || UO->getOpcode() == UO_AddrOf)
        Add(UO->getSubExpr());
    } else if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
      if (BO->isEqualityOp() || BO->isLogicalOp()) {
        Add(BO->getLHS());
        Add(BO->getRHS());
      }
    } else if (const auto *IS = dyn_cast<IfStmt>(St)) {
      Add(IS->getCond());
    } else if (const auto *WS = dyn_cast<WhileStmt>(St)) {
      Add(WS->getCond());
    } else if (const auto *CO = dyn_cast<AbstractConditionalOperator>(St)) {
      Add(CO->getCond());
    }
    for (const Stmt *Child : St->children())
      collectTestedPointers(Child, Out, Copies);
  }

  /// The pointers that the function tests somewhere.  A test of a copy
  /// counts for the original and the other way round: the KUnit assertions
  /// test a copy of their argument, and "xdst = (struct xfrm_dst *)dst"
  /// after IS_ERR(dst) is the tested pointer under another type.
  const llvm::SmallPtrSetImpl<const VarDecl *> &getTestedPointers() {
    if (!TestedPointers) {
      TestedPointers.emplace();
      PointerCopies Copies;
      collectTestedPointers(CurrentFunction->getBody(), *TestedPointers,
                            &Copies);
      for (bool Changed = true; Changed;) {
        Changed = false;
        for (auto [To, From] : Copies)
          if (TestedPointers->count(To) != TestedPointers->count(From)) {
            TestedPointers->insert(To);
            TestedPointers->insert(From);
            Changed = true;
          }
      }
    }
    return *TestedPointers;
  }

  /// "p = get(); p->member": the result of an error pointer function is
  /// dereferenced, and the function tests it nowhere.
  void checkErrorPointerDeref(const MemberExpr *ME) {
    if (!ME->isArrow() || !CurrentFunction)
      return;
    const VarDecl *VD =
        getDirectLinuxVariable(ME->getBase()->IgnoreParenCasts());
    if (!VD || !VD->hasLocalStorage() || isa<ParmVarDecl>(VD))
      return;
    auto It = VariableOrigins.find(VD);
    if (It == VariableOrigins.end() ||
        It->second.Kind != LinuxKernelAPIKind::ErrorPointer)
      return;
    if (getTestedPointers().count(VD) || !ReportedErrorDerefs.insert(VD).second)
      return;
    S.Diag(ME->getOperatorLoc(), diag::warn_linux_kernel_err_ptr_deref)
        << VD << It->second.Callee << ME->getSourceRange();
    noteInferred(It->second);
  }

  /// "p = kzalloc(...); p->member = ...": the result of an allocation is
  /// dereferenced, and the function tests it nowhere.
  void checkUncheckedAllocation(const MemberExpr *ME) {
    if (!ME->isArrow() || !CurrentFunction)
      return;
    const VarDecl *VD =
        getDirectLinuxVariable(ME->getBase()->IgnoreParenCasts());
    if (!VD || !VD->hasLocalStorage() || isa<ParmVarDecl>(VD))
      return;
    auto It = VariableOrigins.find(VD);
    if (It == VariableOrigins.end() || It->second.Inferred ||
        It->second.Copied)
      return;
    switch (It->second.Kind) {
    case LinuxKernelAPIKind::KmallocPointer:
    case LinuxKernelAPIKind::VmallocPointer:
    case LinuxKernelAPIKind::KvmallocPointer:
    case LinuxKernelAPIKind::DevmPointer:
      break;
    default:
      return;
    }
    if (AllocationsThatCannotFail.count(VD) || getTestedPointers().count(VD) ||
        !ReportedErrorDerefs.insert(VD).second)
      return;
    S.Diag(ME->getOperatorLoc(), diag::warn_linux_kernel_unchecked_alloc)
        << VD << It->second.Callee << ME->getSourceRange();
  }

  static const MemberExpr *findDeref(const Stmt *St, const VarDecl *VD) {
    if (!St || isa<UnaryExprOrTypeTraitExpr>(St))
      return nullptr;
    if (const auto *ME = dyn_cast<MemberExpr>(St))
      if (ME->isArrow() &&
          getDirectLinuxVariable(ME->getBase()->IgnoreParenCasts()) == VD)
        return ME;
    for (const Stmt *Child : St->children())
      if (const MemberExpr *ME = findDeref(Child, VD))
        return ME;
    return nullptr;
  }

  /// Where a function with a body dereferences its parameter \p Index
  /// without testing it first, or null.
  const MemberExpr *getParameterDeref(const FunctionDecl *Callee,
                                      unsigned Index) {
    const FunctionDecl *Def = nullptr;
    if (!Callee->hasBody(Def) || Index >= Def->getNumParams())
      return nullptr;
    const ParmVarDecl *Param = Def->getParamDecl(Index);
    auto [It, New] = ParameterDerefs.try_emplace(Param, nullptr);
    if (New) {
      llvm::SmallPtrSet<const VarDecl *, 16> Tested;
      collectTestedPointers(Def->getBody(), Tested);
      const MemberExpr *Deref =
          Tested.count(Param) ? nullptr : findDeref(Def->getBody(), Param);
      // The map may have grown: look the entry up again.
      ParameterDerefs[Param] = Deref;
      return Deref;
    }
    return It->second;
  }

  /// "p = get(); use(p);" where use() dereferences its argument and neither
  /// function tests the pointer.
  void checkErrorPointerArgument(const CallExpr *Call) {
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee || !CurrentFunction)
      return;
    for (unsigned I = 0, E = Call->getNumArgs(); I != E; ++I) {
      const VarDecl *VD =
          getDirectLinuxVariable(Call->getArg(I)->IgnoreParenCasts());
      if (!VD || !VD->hasLocalStorage() || isa<ParmVarDecl>(VD))
        continue;
      auto It = VariableOrigins.find(VD);
      if (It == VariableOrigins.end() ||
          It->second.Kind != LinuxKernelAPIKind::ErrorPointer)
        continue;
      const MemberExpr *Deref = getParameterDeref(Callee, I);
      if (!Deref)
        continue;
      if (getTestedPointers().count(VD) ||
          !ReportedErrorDerefs.insert(VD).second)
        continue;
      LinuxKernelAPIOrigin Origin = It->second;
      S.Diag(Call->getArg(I)->getExprLoc(),
             diag::warn_linux_kernel_err_ptr_deref)
          << VD << Origin.Callee << Call->getArg(I)->getSourceRange();
      S.Diag(Deref->getOperatorLoc(),
             diag::note_linux_kernel_dereferenced_here)
          << Deref->getBase()->IgnoreParenCasts() << Deref->getSourceRange();
      noteInferred(Origin);
    }
  }

  /// The cleanup function of a pointer that was declared with __free().
  static const FunctionDecl *getFreeCleanup(const VarDecl *VD) {
    if (!VD || !VD->hasLocalStorage() || !VD->getType()->isPointerType())
      return nullptr;
    const auto *A = VD->getAttr<CleanupAttr>();
    const FunctionDecl *Cleanup = A ? A->getFunctionDecl() : nullptr;
    return Cleanup && Cleanup->getIdentifier() &&
                   Cleanup->getName().starts_with("__free_")
               ? Cleanup
               : nullptr;
  }

  /// "return p;" hands out a pointer that the cleanup function of p releases
  /// while the function returns.  return_ptr(p) is what was meant.
  static void collectReturnsOf(const Stmt *St, const VarDecl *VD,
                               llvm::SmallPtrSetImpl<const ReturnStmt *> &Out) {
    if (!St)
      return;
    if (const auto *RS = dyn_cast<ReturnStmt>(St)) {
      if (RS->getRetValue() &&
          getDirectLinuxVariable(RS->getRetValue()->IgnoreParenCasts()) == VD)
        Out.insert(RS);
      return;
    }
    for (const Stmt *Child : St->children())
      collectReturnsOf(Child, VD, Out);
  }

  void noteNothingToRelease(const IfStmt *IS) {
    if (!IS->getCond())
      return;
    for (bool WhenTrue : {true, false}) {
      const Stmt *Branch = WhenTrue ? IS->getThen() : IS->getElse();
      if (!Branch)
        continue;
      PointerTests Tests;
      addPointerTests(IS->getCond(), WhenTrue, Tests);
      llvm::SmallVector<const Expr *, 4> Pointers(Tests.Errors.begin(),
                                                  Tests.Errors.end());
      Pointers.push_back(Tests.ErrorOrNull);
      Pointers.push_back(Tests.Null);
      for (const Expr *Pointer : Pointers)
        if (const VarDecl *VD = getDirectLinuxVariable(Pointer))
          if (getFreeCleanup(VD))
            collectReturnsOf(Branch, VD, NothingToRelease);
    }
  }

  void checkCleanupReturn(const ReturnStmt *RS) {
    const Expr *Value = RS->getRetValue()->IgnoreParenCasts();
    const VarDecl *VD = getDirectLinuxVariable(Value);
    const FunctionDecl *Cleanup = getFreeCleanup(VD);
    if (!Cleanup || NothingToRelease.count(RS))
      return;
    S.Diag(Value->getExprLoc(), diag::warn_linux_kernel_cleanup_return)
        << VD << Cleanup << RS->getSourceRange();
    S.Diag(VD->getLocation(), diag::note_linux_kernel_cleanup_declared) << VD;
  }

  static void findCleanupDisarm(const Stmt *St, const VarDecl *VD,
                                const ASTContext &Ctx, bool &Found) {
    if (!St || Found)
      return;
    if (const auto *UO = dyn_cast<UnaryOperator>(St)) {
      // no_free_ptr() and retain_and_null_ptr() go through the address.
      if (UO->getOpcode() == UO_AddrOf &&
          getDirectLinuxVariable(UO->getSubExpr()) == VD)
        Found = true;
    } else if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
      if (BO->getOpcode() == BO_Assign &&
          getDirectLinuxVariable(BO->getLHS()) == VD &&
          BO->getRHS()->IgnoreParens()->isNullPointerConstant(
              const_cast<ASTContext &>(Ctx), Expr::NPC_ValueDependentIsNotNull))
        Found = true;
    } else if (const auto *CE = dyn_cast<CallExpr>(St)) {
      // "obj->node = child; fwnode_handle_get(child);" takes a reference
      // of its own for what it stores.
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (Callee && Callee->getIdentifier() && CE->getNumArgs() >= 1 &&
          getDirectLinuxVariable(CE->getArg(0)->IgnoreParenCasts()) == VD) {
        StringRef Name = Callee->getName();
        if (Name.ends_with("_get") || Name.starts_with("get_") ||
            Name.contains("_get_") || Name.ends_with("_hold") ||
            Name.ends_with("_ref"))
          Found = true;
      }
    }
    for (const Stmt *Child : St->children())
      findCleanupDisarm(Child, VD, Ctx, Found);
  }

  /// Whether \p E names storage that outlives the function: an object that
  /// is reached through a pointer, or a global.
  static bool outlivesFunction(const Expr *E) {
    while (E) {
      E = E->IgnoreParenCasts();
      if (const auto *ME = dyn_cast<MemberExpr>(E)) {
        if (ME->isArrow())
          return true;
        E = ME->getBase();
      } else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
        E = ASE->getBase();
      } else if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
        return UO->getOpcode() == UO_Deref;
      } else if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
        const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
        return VD && VD->hasGlobalStorage();
      } else {
        return false;
      }
    }
    return false;
  }

  /// "obj->field = p;" keeps a pointer that the cleanup function of p
  /// releases at the end of the scope, unless the function switches the
  /// cleanup off.
  void checkCleanupEscape(const BinaryOperator *BO) {
    if (BO->getOpcode() != BO_Assign || !CurrentFunction)
      return;
    const VarDecl *VD =
        getDirectLinuxVariable(BO->getRHS()->IgnoreParenCasts());
    const FunctionDecl *Cleanup = getFreeCleanup(VD);
    if (!Cleanup || !outlivesFunction(BO->getLHS()))
      return;
    auto [It, New] = CleanupDisarmed.try_emplace(VD, false);
    if (New)
      findCleanupDisarm(CurrentFunction->getBody(), VD, S.getASTContext(),
                        It->second);
    if (It->second)
      return;
    S.Diag(BO->getOperatorLoc(), diag::warn_linux_kernel_cleanup_escape)
        << VD << Cleanup << BO->getSourceRange();
    S.Diag(VD->getLocation(), diag::note_linux_kernel_cleanup_declared) << VD;
  }

  /// Whether a diagnostic was already given for the code spelled at \p Loc.
  bool alreadyReportedAt(SourceLocation Loc) {
    Loc = S.getSourceManager().getSpellingLoc(Loc);
    if (llvm::is_contained(ReportedSpellings, Loc))
      return true;
    ReportedSpellings.push_back(Loc);
    return false;
  }

  /// "x & ~mask" where x has more bits than the unsigned mask: the
  /// complement is computed in the width of the mask and zero-extended, so
  /// the upper bits of x are cleared along with the bits of the mask.
  ///
  ///   u64 features;
  ///   features &= ~BIT(3);        /* on a 32-bit kernel: clears bits 63:32 */
  void checkZeroExtendedComplement(const BinaryOperator *BO) {
    if (BO->getOpcode() != BO_And && BO->getOpcode() != BO_AndAssign)
      return;
    ASTContext &Ctx = S.getASTContext();
    bool IsAssign = BO->getOpcode() == BO_AndAssign;
    if (!IsAssign && NarrowedAnds.count(BO))
      return;
    for (const Expr *Side : {BO->getLHS(), BO->getRHS()}) {
      if (IsAssign && Side == BO->getLHS())
        continue;
      const Expr *Other = Side == BO->getLHS() ? BO->getRHS() : BO->getLHS();
      const auto *ICE = dyn_cast<ImplicitCastExpr>(Side->IgnoreParens());
      if (!ICE || ICE->getCastKind() != CK_IntegralCast)
        continue;
      const auto *Not = dyn_cast<UnaryOperator>(ICE->getSubExpr()->IgnoreParens());
      if (!Not || Not->getOpcode() != UO_Not)
        continue;
      QualType Narrow = Not->getType();
      QualType Wide = ICE->getType();
      if (!Narrow->isUnsignedIntegerType() || Narrow->isBooleanType() ||
          !Wide->isIntegerType())
        continue;
      unsigned From = Ctx.getIntWidth(Narrow);
      unsigned To = Ctx.getIntWidth(Wide);
      if (To <= From)
        continue;
      // The other operand fits into the width of the mask anyway if it was
      // widened itself, or if it is a small constant.
      const Expr *Value = Other->IgnoreParens();
      if (const auto *OtherCast = dyn_cast<CastExpr>(Value);
          OtherCast && OtherCast->getCastKind() == CK_IntegralCast &&
          Ctx.getIntWidth(OtherCast->getSubExpr()->getType()) <= From)
        continue;
      if (!IsAssign && !Value->isValueDependent()) {
        Expr::EvalResult R;
        if (Value->EvaluateAsInt(R, Ctx) &&
            R.Val.getInt().getActiveBits() <= From)
          continue;
      }
      // "~0U" keeps every bit of the mask's width: the author says how many
      // bits are meant.
      if (!Not->getSubExpr()->isValueDependent()) {
        Expr::EvalResult R;
        if (Not->getSubExpr()->EvaluateAsInt(R, Ctx) && R.Val.getInt().isZero())
          continue;
      }
      S.Diag(Not->getOperatorLoc(), diag::warn_zero_extended_complement)
          << From << To << IsAssign << (To - From) << Not->getSourceRange()
          << Other->getSourceRange();
    }
  }

  /// The object whose address \p E is, under any casts: "(unsigned long *)&x"
  /// gives x.  For a pointer or an array, the type it points to is in
  /// \p Pointee instead.
  static const Expr *getAddressedObject(const Expr *E, QualType &Pointee) {
    E = E->IgnoreParenCasts();
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_AddrOf)
        return UO->getSubExpr()->IgnoreParens();
      return nullptr;
    }
    QualType T = E->getType();
    if (T->isPointerType())
      Pointee = T->getPointeeType();
    else if (const ArrayType *AT = T->getAsArrayTypeUnsafe())
      Pointee = AT->getElementType();
    return nullptr;
  }

  /// set_bit(), test_bit(), find_first_bit(), bitmap_zero() and their
  /// relatives work on arrays of unsigned long.  Handing them the address of
  /// a narrower object makes them read and write past it, and on a
  /// big-endian machine they see other bits than the code that uses the
  /// object as a number:
  ///
  ///   u32 flags;
  ///   set_bit(0, (unsigned long *)&flags);
  void checkBitopsCast(const CallExpr *Call, StringRef Name) {
    Name = Name.ltrim('_');
    Name.consume_front("const");
    Name = Name.ltrim('_');
    Name.consume_front("arch_");
    Name = Name.ltrim('_');
    int Arg = llvm::StringSwitch<int>(Name)
                  .Cases({"set_bit", "clear_bit", "change_bit", "test_bit",
                          "assign_bit"},
                         1)
                  .Cases({"test_and_set_bit", "test_and_clear_bit",
                          "test_and_change_bit", "test_bit_acquire",
                          "clear_bit_unlock", "test_and_set_bit_lock"},
                         1)
                  .Cases({"find_first_bit", "find_next_bit",
                          "find_first_zero_bit", "find_next_zero_bit",
                          "find_last_bit"},
                         0)
                  .Cases({"bitmap_zero", "bitmap_fill", "bitmap_weight",
                          "bitmap_empty", "bitmap_full", "bitmap_set",
                          "bitmap_clear"},
                         0)
                  .Default(-1);
    if (Arg < 0 || Call->getNumArgs() <= unsigned(Arg))
      return;
    ASTContext &Ctx = S.getASTContext();
    const Expr *Address = Call->getArg(Arg);
    // Only what a cast turned into a bitmap: the compiler checks the rest.
    const Expr *Written = Address->IgnoreParenImpCasts();
    if (!isa<CStyleCastExpr>(Written))
      return;
    QualType Pointee;
    const Expr *Object = getAddressedObject(Written, Pointee);
    if (!Object)
      return;
    QualType T = Object->getType();
    if (!T->isIntegerType() || T->isBooleanType())
      return;
    unsigned Have = Ctx.getTypeSize(T);
    unsigned Long = Ctx.getTypeSize(Ctx.UnsignedLongTy);
    if (Have == Long || alreadyReportedAt(Written->getExprLoc()))
      return;
    if (Have < Long) {
      S.Diag(Written->getExprLoc(), diag::warn_linux_kernel_bitops_cast)
          << Name << getLinuxExprText(Object, S) << Long << Have
          << /*big-endian*/ 1 << Written->getSourceRange();
    } else if (Ctx.getTargetInfo().isBigEndian() && Have == 2 * Long) {
      S.Diag(Written->getExprLoc(), diag::warn_linux_kernel_bitops_cast_order)
          << Name << getLinuxExprText(Object, S) << Written->getSourceRange();
    }
  }

  /// The number of bytes of \p T that belong to no member, or std::nullopt
  /// if that cannot be told.  The first hole is described in \p After (the
  /// member before it, null for padding at the end) and \p In.
  std::optional<uint64_t> getPaddingBytes(QualType T, const FieldDecl *&After,
                                          const RecordDecl *&In,
                                          unsigned Depth = 0) const {
    ASTContext &Ctx = S.getASTContext();
    if (const ConstantArrayType *AT = Ctx.getAsConstantArrayType(T)) {
      std::optional<uint64_t> Each =
          getPaddingBytes(AT->getElementType(), After, In, Depth);
      if (!Each)
        return std::nullopt;
      return *Each * AT->getZExtSize();
    }
    const RecordDecl *RD = T->getAsRecordDecl();
    if (!RD)
      return 0;
    RD = RD->getDefinition();
    if (!RD || RD->isUnion() || RD->isInvalidDecl() || Depth > 6 ||
        RD->hasFlexibleArrayMember())
      return std::nullopt;
    const ASTRecordLayout &Layout = Ctx.getASTRecordLayout(RD);
    uint64_t Bits = 0, End = 0;
    const FieldDecl *Previous = nullptr;
    auto Hole = [&](uint64_t Size) {
      if (!Bits && Size >= 8 && !In) {
        After = Previous;
        In = RD;
      }
      Bits += Size;
    };
    for (const FieldDecl *FD : RD->fields()) {
      uint64_t Offset = Layout.getFieldOffset(FD->getFieldIndex());
      if (Offset > End)
        Hole(Offset - End);
      uint64_t Size;
      if (FD->isBitField()) {
        Size = FD->getBitWidthValue();
      } else {
        if (FD->getType()->isIncompleteType())
          return std::nullopt;
        Size = Ctx.getTypeSize(FD->getType());
        const FieldDecl *InnerAfter = nullptr;
        const RecordDecl *InnerIn = nullptr;
        std::optional<uint64_t> Inner =
            getPaddingBytes(FD->getType(), InnerAfter, InnerIn, Depth + 1);
        if (!Inner)
          return std::nullopt;
        if (*Inner && !Bits && !In) {
          After = InnerAfter;
          In = InnerIn;
        }
        Bits += *Inner * 8;
      }
      End = std::max(End, Offset + Size);
      Previous = FD;
    }
    uint64_t Total = Ctx.toBits(Layout.getSize());
    if (Total > End)
      Hole(Total - End);
    return Bits / 8;
  }

  /// Whether a function with a body may set every byte of what its
  /// parameter \p P points to: it stores a whole object through it, or
  /// hands the pointer on.  A function that only sets members does not.
  static bool mayFillWhole(const Stmt *St, const ParmVarDecl *P) {
    if (!St)
      return false;
    if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
      if (BO->isAssignmentOp()) {
        if (getDirectLinuxVariable(BO->getLHS()) == P)
          return true;
        const auto *UO =
            dyn_cast<UnaryOperator>(BO->getLHS()->IgnoreParenCasts());
        if (UO && UO->getOpcode() == UO_Deref &&
            getDirectLinuxVariable(UO->getSubExpr()->IgnoreParenCasts()) == P)
          return true;
      }
    } else if (const auto *CE = dyn_cast<CallExpr>(St)) {
      for (const Expr *Arg : CE->arguments())
        if (getDirectLinuxVariable(Arg->IgnoreParenCasts()) == P)
          return true;
    } else if (const auto *UO = dyn_cast<UnaryOperator>(St)) {
      if (UO->getOpcode() == UO_AddrOf &&
          getDirectLinuxVariable(UO->getSubExpr()) == P)
        return true;
    } else if (isa<GCCAsmStmt>(St)) {
      return true;
    }
    for (const Stmt *Child : St->children())
      if (mayFillWhole(Child, P))
        return true;
    return false;
  }

  /// Whether the function sets every byte of \p VD somewhere: with memset()
  /// or one of its relatives, by assigning a whole structure, or by letting
  /// a function fill it that this translation unit cannot look into.
  bool isWhollyInitialized(const Stmt *St, const VarDecl *VD,
                           const CallExpr *Sink) const {
    if (!St)
      return false;
    if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
      if (BO->getOpcode() == BO_Assign &&
          getDirectLinuxVariable(BO->getLHS()) == VD)
        return true;
    } else if (const auto *CE = dyn_cast<CallExpr>(St); CE && CE != Sink) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      const FunctionDecl *Def = nullptr;
      bool HasBody = Callee && Callee->hasBody(Def);
      for (unsigned I = 0, E = CE->getNumArgs(); I != E; ++I) {
        const auto *UO =
            dyn_cast<UnaryOperator>(CE->getArg(I)->IgnoreParenCasts());
        if (!UO || UO->getOpcode() != UO_AddrOf ||
            getDirectLinuxVariable(UO->getSubExpr()) != VD)
          continue;
        if (!HasBody || I >= Def->getNumParams() ||
            mayFillWhole(Def->getBody(), Def->getParamDecl(I)))
          return true;
      }
    } else if (isa<GCCAsmStmt>(St)) {
      return true;
    }
    for (const Stmt *Child : St->children())
      if (isWhollyInitialized(Child, VD, Sink))
        return true;
    return false;
  }

  /// A local structure with padding is copied to user space as a whole, and
  /// the function only ever set its members: the padding carries whatever
  /// was on the stack.
  void checkStructLeak(const CallExpr *Call, StringRef Name) {
    unsigned From, Size;
    if (Name.ends_with("copy_to_user")) {
      From = 1;
      Size = 2;
    } else if (Name == "nla_put" || Name == "nla_put_nohdr") {
      From = Name == "nla_put" ? 3 : 2;
      Size = From - 1;
    } else if (Name == "copy_to_iter" || Name == "_copy_to_iter") {
      From = 0;
      Size = 1;
    } else {
      return;
    }
    if (Call->getNumArgs() <= std::max(From, Size) || !CurrentFunction)
      return;
    ASTContext &Ctx = S.getASTContext();
    const auto *UO =
        dyn_cast<UnaryOperator>(Call->getArg(From)->IgnoreParenCasts());
    const VarDecl *VD =
        UO && UO->getOpcode() == UO_AddrOf
            ? getDirectLinuxVariable(UO->getSubExpr())
            : nullptr;
    if (!VD || !VD->hasLocalStorage() || isa<ParmVarDecl>(VD) ||
        VD->hasInit() || !VD->getType()->isRecordType())
      return;
    // The whole object has to go out.
    Expr::EvalResult Bytes;
    const Expr *SizeArg = Call->getArg(Size);
    if (SizeArg->isValueDependent() || !SizeArg->EvaluateAsInt(Bytes, Ctx) ||
        Bytes.Val.getInt() !=
            Ctx.getTypeSizeInChars(VD->getType()).getQuantity())
      return;
    const FieldDecl *After = nullptr;
    const RecordDecl *In = nullptr;
    std::optional<uint64_t> Padding =
        getPaddingBytes(VD->getType(), After, In);
    if (!Padding || !*Padding || !In ||
        isWhollyInitialized(CurrentFunction->getBody(), VD, Call))
      return;
    S.Diag(Call->getArg(From)->getExprLoc(),
           diag::warn_linux_kernel_struct_leak)
        << VD << Name << unsigned(*Padding)
        << Call->getArg(From)->getSourceRange();
    if (After)
      S.Diag(After->getLocation(), diag::note_linux_kernel_struct_hole)
          << Ctx.getCanonicalTagType(In) << After;
    else
      S.Diag(In->getLocation(), diag::note_linux_kernel_struct_tail)
          << Ctx.getCanonicalTagType(In);
    S.Diag(VD->getLocation(), diag::note_linux_kernel_declared_no_init) << VD;
  }

  /// snprintf() and its relatives are told how large the buffer is.  A size
  /// that is larger than the array they write to lets them run past it:
  ///
  ///   char buf[128];
  ///   len += scnprintf(buf + len, PAGE_SIZE - len, ...);
  void checkBufferSize(const CallExpr *Call, StringRef Name) {
    if (!llvm::StringSwitch<bool>(Name)
             .Cases({"snprintf", "scnprintf", "vsnprintf", "vscnprintf"}, true)
             .Default(false) ||
        Call->getNumArgs() < 2)
      return;
    ASTContext &Ctx = S.getASTContext();
    // The buffer: an array, or a position inside one.
    const Expr *Buffer = Call->getArg(0)->IgnoreParenCasts();
    if (const auto *BO = dyn_cast<BinaryOperator>(Buffer);
        BO && BO->getOpcode() == BO_Add)
      Buffer = BO->getLHS()->IgnoreParenCasts();
    if (const auto *UO = dyn_cast<UnaryOperator>(Buffer);
        UO && UO->getOpcode() == UO_AddrOf)
      if (const auto *ASE =
              dyn_cast<ArraySubscriptExpr>(UO->getSubExpr()->IgnoreParens()))
        Buffer = ASE->getBase()->IgnoreParenCasts();
    const ConstantArrayType *AT = Ctx.getAsConstantArrayType(Buffer->getType());
    if (!AT || !isSimpleLinuxStorage(Buffer))
      return;
    uint64_t Have = Ctx.getTypeSizeInChars(Buffer->getType()).getQuantity();
    // The size: a constant, or a constant minus what was written so far.
    const Expr *SizeArg = Call->getArg(1)->IgnoreParenImpCasts();
    if (const auto *BO = dyn_cast<BinaryOperator>(SizeArg);
        BO && BO->getOpcode() == BO_Sub)
      SizeArg = BO->getLHS()->IgnoreParenImpCasts();
    Expr::EvalResult Given;
    if (SizeArg->isValueDependent() || !SizeArg->EvaluateAsInt(Given, Ctx) ||
        Given.Val.getInt().isNegative() ||
        Given.Val.getInt().getActiveBits() > 63 ||
        Given.Val.getInt().getZExtValue() <= Have)
      return;
    S.Diag(Call->getArg(1)->getExprLoc(), diag::warn_linux_kernel_buffer_size)
        << Name << toString(Given.Val.getInt(), 10)
        << getLinuxExprText(Buffer, S) << unsigned(Have)
        << Call->getArg(1)->getSourceRange();
  }

  /// What "index > Bound" compares, if \p Cond is such a test.
  struct BoundTest {
    const VarDecl *Index = nullptr;
    const Expr *Bound = nullptr;
    const Expr *Test = nullptr;
  };

  void collectBoundTests(const Expr *Cond, bool WhenTrue,
                         llvm::SmallVectorImpl<BoundTest> &Out) const {
    bool Negated = false;
    const Expr *E = stripLinuxCondition(Cond, Negated);
    if (!E)
      return;
    bool Holds = WhenTrue != Negated;
    const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts());
    if (!BO)
      return;
    if (BO->isLogicalOp()) {
      // "a || b" being false says that both are, "a && b" being true too.
      if ((BO->getOpcode() == BO_LOr) != Holds) {
        collectBoundTests(BO->getLHS(), Holds, Out);
        collectBoundTests(BO->getRHS(), Holds, Out);
      }
      return;
    }
    // The region that is entered when "index > bound" is false, or when
    // "index <= bound" is true, has index <= bound.
    const VarDecl *Index = nullptr;
    const Expr *Bound = nullptr;
    BinaryOperatorKind Op = BO->getOpcode();
    if ((Op == BO_GT && !Holds) || (Op == BO_LE && Holds)) {
      Index = getDirectLinuxVariable(BO->getLHS());
      Bound = BO->getRHS();
    } else if ((Op == BO_LT && !Holds) || (Op == BO_GE && Holds)) {
      Index = getDirectLinuxVariable(BO->getRHS());
      Bound = BO->getLHS();
    }
    if (Index && Bound &&
        !isWrittenInMacro(BO->getOperatorLoc(), S.getSourceManager()))
      Out.push_back({Index, Bound->IgnoreParenImpCasts(), BO});
  }

  /// Whether \p Bound is the number of elements of the array \p Base: its
  /// constant size, or the member that __counted_by() names for it.
  bool isElementCount(const Expr *Bound, const Expr *Base,
                      std::string &Count) const {
    ASTContext &Ctx = S.getASTContext();
    Base = Base->IgnoreParenImpCasts();
    if (const ConstantArrayType *AT =
            Ctx.getAsConstantArrayType(Base->getType())) {
      Expr::EvalResult R;
      if (Bound->isValueDependent() || !Bound->EvaluateAsInt(R, Ctx) ||
          R.Val.getInt().getActiveBits() > 63 ||
          R.Val.getInt().getZExtValue() != AT->getZExtSize() ||
          AT->getZExtSize() < 2)
        return false;
      Count = std::to_string(AT->getZExtSize());
      return true;
    }
    const auto *Array = dyn_cast<MemberExpr>(Base);
    const auto *Counter = dyn_cast<MemberExpr>(Bound);
    const auto *ArrayField =
        Array ? dyn_cast<FieldDecl>(Array->getMemberDecl()) : nullptr;
    if (!ArrayField || !Counter ||
        Counter->getMemberDecl() != ArrayField->findCountedByField() ||
        !isSameLinuxExpr(Ctx, Array->getBase(), Counter->getBase()))
      return false;
    Count = "'" + getLinuxExprText(Counter, S) + "'";
    return true;
  }

  bool findOffByOne(const Stmt *St, const BoundTest &T) {
    if (!St)
      return false;
    if (const auto *BO = dyn_cast<BinaryOperator>(St))
      if (BO->isAssignmentOp() && getDirectLinuxVariable(BO->getLHS()) == T.Index)
        return true; // the index changes: stop looking
    if (const auto *UO = dyn_cast<UnaryOperator>(St))
      if (UO->isIncrementDecrementOp() &&
          getDirectLinuxVariable(UO->getSubExpr()) == T.Index)
        return true;
    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(St)) {
      std::string Count;
      if (getDirectLinuxVariable(ASE->getIdx()) == T.Index &&
          isElementCount(T.Bound, ASE->getBase(), Count)) {
        S.Diag(ASE->getIdx()->getExprLoc(), diag::warn_linux_kernel_off_by_one)
            << T.Index->getName() << Count
            << getLinuxExprText(ASE->getBase()->IgnoreParenImpCasts(), S)
            << ASE->getSourceRange();
        S.Diag(T.Test->getExprLoc(), diag::note_linux_kernel_bounds_test_here)
            << T.Test->getSourceRange();
        return true;
      }
    }
    for (const Stmt *Child : St->children())
      if (findOffByOne(Child, T))
        return true;
    return false;
  }

  /// "if (i > ARRAY_SIZE(table)) return; ... table[i]": the test lets the
  /// index be the number of elements, which is one past the last.
  void checkOffByOne(const Expr *Cond, const Stmt *WhenTrue,
                     const Stmt *WhenFalse, ArrayRef<const Stmt *> After) {
    if (!Cond)
      return;
    for (bool Outcome : {true, false}) {
      const Stmt *Region = Outcome ? WhenTrue : WhenFalse;
      const Stmt *OtherRegion = Outcome ? WhenFalse : WhenTrue;
      llvm::SmallVector<BoundTest, 2> Tests;
      collectBoundTests(Cond, Outcome, Tests);
      for (const BoundTest &T : Tests) {
        if (Region && findOffByOne(Region, T))
          continue;
        // What follows the statement is reached with this outcome if the
        // other branch leaves.
        if (OtherRegion && leavesFunctionOrLoop(OtherRegion))
          for (const Stmt *Next : After)
            if (findOffByOne(Next, T))
              break;
      }
    }
  }

  static bool leavesFunctionOrLoop(const Stmt *St) {
    while (St) {
      if (isa<ReturnStmt, GotoStmt, BreakStmt, ContinueStmt>(St))
        return true;
      if (const auto *CS = dyn_cast<CompoundStmt>(St))
        St = CS->body_empty() ? nullptr : CS->body_back();
      else if (const auto *AS = dyn_cast<AttributedStmt>(St))
        St = AS->getSubStmt();
      else
        return false;
    }
    return false;
  }

  /// The line and the column at which a statement starts, if it is the
  /// first thing on its line.  Tabs count as up to eight columns.
  bool getStatementStart(const Stmt *St, FileID &File, unsigned &Line,
                         unsigned &Column) const {
    const SourceManager &SM = S.getSourceManager();
    SourceLocation Loc = SM.getExpansionLoc(St->getBeginLoc());
    if (Loc.isInvalid())
      return false;
    auto [FID, Offset] = SM.getDecomposedLoc(Loc);
    bool Invalid = false;
    StringRef Text = SM.getBufferData(FID, &Invalid);
    if (Invalid || Offset > Text.size())
      return false;
    size_t Begin = Text.rfind('\n', Offset ? Offset - 1 : 0);
    Begin = Begin == StringRef::npos || Offset == 0 ? 0 : Begin + 1;
    if (Begin > Offset)
      return false;
    unsigned Col = 0;
    for (char C : Text.substr(Begin, Offset - Begin)) {
      if (C == '\t')
        Col = (Col / 8 + 1) * 8;
      else if (C == ' ')
        ++Col;
      else
        return false; // something else comes first on the line
    }
    File = FID;
    Line = SM.getLineNumber(FID, Offset);
    Column = Col;
    return true;
  }

  /// Two statements of one block that start in different columns.  The
  /// second one was often meant to be under the "if" above it.
  void checkIndentation(const CompoundStmt *CS) {
    if (S.getDiagnostics().isIgnored(
            diag::warn_linux_kernel_inconsistent_indent, CS->getLBracLoc()) ||
        CS->getLBracLoc().isMacroID())
      return;
    const Stmt *Previous = nullptr;
    FileID PrevFile;
    unsigned PrevLine = 0, PrevColumn = 0;
    for (const Stmt *Child : CS->body()) {
      // The labels of a switch and of goto sit to the left by convention.
      if (isa<SwitchCase, LabelStmt, NullStmt>(Child) ||
          Child->getBeginLoc().isMacroID()) {
        Previous = nullptr;
        continue;
      }
      FileID File;
      unsigned Line, Column;
      if (!getStatementStart(Child, File, Line, Column)) {
        Previous = nullptr;
        continue;
      }
      if (Previous && File == PrevFile && Line > PrevLine &&
          Column != PrevColumn) {
        S.Diag(Child->getBeginLoc(),
               diag::warn_linux_kernel_inconsistent_indent)
            << Child->getSourceRange();
        S.Diag(Previous->getBeginLoc(),
               diag::note_linux_kernel_previous_statement);
        // One report for a block: what follows is in line with one of the
        // two again.
        return;
      }
      Previous = Child;
      PrevFile = File;
      PrevLine = Line;
      PrevColumn = Column;
    }
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
  LinuxKernelWarningsVisitor(Sema &S, const FunctionDecl *FD,
                             sema::LinuxKernelUnit &Unit)
      : S(S), CurrentFunction(FD), Inference(S, Unit) {
    ShouldVisitImplicitCode = false;
  }

  bool VisitMemberExpr(MemberExpr *ME) override {
    checkErrorPointerDeref(ME);
    checkUncheckedAllocation(ME);
    return true;
  }

  bool TraverseIfStmt(IfStmt *IS) override {
    checkPtrErrAfterTest(IS);
    noteNothingToRelease(IS);
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
    if (!S.getDiagnostics().isIgnored(diag::warn_linux_kernel_off_by_one,
                                      CO->getQuestionLoc()))
      checkOffByOne(CO->getCond(), CO->getTrueExpr(), CO->getFalseExpr(), {});
    ++ControlFlowDepth;
    bool Result = DynamicRecursiveASTVisitor::TraverseConditionalOperator(CO);
    --ControlFlowDepth;
    return Result;
  }

  bool VisitCompoundStmt(CompoundStmt *CS) override {
    checkIndentation(CS);
    if (!S.getDiagnostics().isIgnored(diag::warn_linux_kernel_off_by_one,
                                      CS->getLBracLoc())) {
      ArrayRef<const Stmt *> Body(CS->body_begin(), CS->body_end());
      for (unsigned I = 0, E = Body.size(); I != E; ++I)
        if (const auto *IS = dyn_cast<IfStmt>(stripStatementLabels(Body[I])))
          checkOffByOne(IS->getCond(), IS->getThen(), IS->getElse(),
                        Body.drop_front(I + 1));
    }

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

  /// An allocation with __GFP_NOFAIL does not return NULL.
  void noteAllocationFlags(const VarDecl *VD, const Expr *Value) {
    if (Value && getLinuxExprText(Value, S).find("__GFP_NOFAIL") !=
                     std::string::npos)
      AllocationsThatCannotFail.insert(VD);
    else
      AllocationsThatCannotFail.erase(VD);
  }

  bool VisitVarDecl(VarDecl *VD) override {
    if (AssignmentTrackingDisabled || !VD->hasLocalStorage() || !VD->hasInit())
      return true;
    LinuxKernelAPIOrigin Origin = getOrigin(VD->getInit());
    if (Origin) {
      Origin.Assigned = VD->getLocation();
      Origin.Copied =
          isa<DeclRefExpr, MemberExpr>(VD->getInit()->IgnoreParenCasts());
      VariableOrigins[VD] = Origin;
      noteAllocationFlags(VD, VD->getInit());
    }
    return true;
  }

  bool VisitReturnStmt(ReturnStmt *RS) override {
    if (!CurrentFunction || !RS->getRetValue())
      return true;
    checkCleanupReturn(RS);

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
    checkErrorPointerArgument(Call);
    const FunctionDecl *Checker = Call->getDirectCallee();
    if (!Checker || !Checker->getIdentifier() || Call->getNumArgs() == 0)
      return true;

    StringRef CheckerName = Checker->getName();
    checkBitopsCast(Call, CheckerName);
    checkStructLeak(Call, CheckerName);
    checkBufferSize(Call, CheckerName);
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
      if (isWrittenInMacro(Call->getCallee()->getExprLoc(),
                           S.getSourceManager()))
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
    noteInferred(Origin);
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

  bool VisitCastExpr(CastExpr *CE) override {
    // "(u32)(x & ~mask)" and "u32 y = x & ~mask" do not care about the upper
    // bits.  The cast is visited before the operator below it.
    if (CE->getCastKind() == CK_IntegralCast) {
      ASTContext &Ctx = S.getASTContext();
      const Expr *Sub = CE->getSubExpr()->IgnoreParens();
      if (const auto *BO = dyn_cast<BinaryOperator>(Sub);
          BO && BO->getOpcode() == BO_And &&
          Ctx.getIntWidth(CE->getType()) < Ctx.getIntWidth(Sub->getType()))
        NarrowedAnds.insert(BO);
    }
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
    checkCleanupEscape(BO);
    checkZeroExtendedComplement(BO);

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
          if (Origin) {
            Origin.Assigned = BO->getOperatorLoc();
            Origin.Copied =
                isa<DeclRefExpr, MemberExpr>(BO->getRHS()->IgnoreParenCasts());
            VariableOrigins[VD] = Origin;
            noteAllocationFlags(VD, BO->getRHS());
          } else {
            VariableOrigins.erase(VD);
          }
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
///
/// A failure path that prints nothing is found with three more facts:
///
///   MustZero every path arrives with the variable known to be zero, from its
///            initializer or from a test, not from an explicit "var = 0;"
///   Failed   every path arrives through the failure outcome of a test such
///            as "if (!ptr)" on an allocation, with MustZero holding there
///            and the variable unchanged since
///   Missing  some path arrives through "Failed; goto" to a label that is
///            not inside a loop, with the variable unchanged since
///
/// `return var` with Failed or Missing has lost the error code.
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
    bool MustZero = false;
    bool Failed = false;
    /// The calls behind Message and Jumped, for the note.
    const CallExpr *MessageCall = nullptr;
    const CallExpr *JumpMessage = nullptr;
    /// The test behind Failed, and those behind Missing.
    const Expr *FailedTest = nullptr;
    llvm::SmallVector<const Expr *, 2> Missing;

    void assigned(bool IsZero, bool IsNonZero) {
      Zero = IsZero;
      NonZero = IsNonZero;
      Message = Jumped = MustZero = Failed = false;
      MessageCall = JumpMessage = nullptr;
      FailedTest = nullptr;
      Missing.clear();
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
  /// Variables that are given a positive constant or an enumerator.  Their
  /// zero has a meaning of its own, such as "not found".
  llvm::SmallPtrSet<const VarDecl *, 8> NotErrno;
  /// For each candidate, the other variables that change inside a loop that
  /// assigns the candidate.  A test of one of them after the loop tells how
  /// the loop ended, and with that what the candidate holds.
  llvm::DenseMap<const VarDecl *, llvm::SmallPtrSet<const VarDecl *, 4>>
      LoopCompanions;
  /// Pointers that only ever hold the result of an allocation, and integers
  /// that only ever hold the result of a call.
  llvm::SmallPtrSet<const VarDecl *, 8> AllocationResults;
  llvm::SmallPtrSet<const VarDecl *, 8> NotAllocationResults;
  llvm::SmallPtrSet<const VarDecl *, 8> CallResults;
  llvm::SmallPtrSet<const VarDecl *, 8> NotCallResults;
  llvm::SmallPtrSet<const Expr *, 4> ReportedTests;
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

  static bool containsAllocation(const Stmt *St) {
    if (!St)
      return false;
    if (const auto *CE = dyn_cast<CallExpr>(St)) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (Callee && Callee->getIdentifier()) {
        if (isNullReturningKind(classifyLinuxKernelCallee(Callee)))
          return true;
        if (Callee->getReturnType()->isPointerType() &&
            Callee->getName().contains("alloc"))
          return true;
      }
    }
    for (const Stmt *Child : St->children())
      if (containsAllocation(Child))
        return true;
    return false;
  }

  void noteValue(const VarDecl *VD, const Expr *Value) {
    if (!VD || !Value || Value->isValueDependent())
      return;
    if (VD->getType()->isPointerType())
      (containsAllocation(Value) ? AllocationResults : NotAllocationResults)
          .insert(VD);
    else
      (isa<CallExpr>(Value->IgnoreParenImpCasts()) ? CallResults
                                                   : NotCallResults)
          .insert(VD);
    const auto *DRE = dyn_cast<DeclRefExpr>(Value->IgnoreParenImpCasts());
    if (DRE && isa<EnumConstantDecl>(DRE->getDecl()))
      NotErrno.insert(VD);
    std::optional<llvm::APSInt> K = Value->getIntegerConstantExpr(Ctx);
    if (!K || K->isNegative())
      ErrorCapable.insert(VD);
    else if (K->isStrictlyPositive())
      NotErrno.insert(VD);
  }

  static void collectModified(const Stmt *St,
                              llvm::SmallPtrSetImpl<const VarDecl *> &Out) {
    if (!St)
      return;
    const VarDecl *VD = nullptr;
    if (const auto *UO = dyn_cast<UnaryOperator>(St)) {
      if (UO->isIncrementDecrementOp())
        VD = getDirectLinuxVariable(UO->getSubExpr());
    } else if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
      if (BO->isAssignmentOp())
        VD = getDirectLinuxVariable(BO->getLHS());
    }
    if (VD)
      Out.insert(VD);
    for (const Stmt *Child : St->children())
      collectModified(Child, Out);
  }

  void collectLoops(const Stmt *St) {
    if (!St)
      return;
    if (isa<ForStmt, WhileStmt, DoStmt>(St)) {
      llvm::SmallPtrSet<const VarDecl *, 8> Modified;
      collectModified(St, Modified);
      for (const VarDecl *V : Candidates)
        if (Modified.count(V))
          for (const VarDecl *Other : Modified)
            if (Other != V)
              LoopCompanions[V].insert(Other);
    }
    for (const Stmt *Child : St->children())
      collectLoops(Child);
  }

  static bool mentions(const Stmt *St,
                       const llvm::SmallPtrSetImpl<const VarDecl *> &Vars,
                       const VarDecl *Except, bool &SeesExcept) {
    if (!St)
      return false;
    bool Found = false;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(St)) {
      const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
      if (VD == Except)
        SeesExcept = true;
      else if (VD && Vars.count(VD))
        Found = true;
    }
    for (const Stmt *Child : St->children())
      Found |= mentions(Child, Vars, Except, SeesExcept);
    return Found;
  }

  /// Whether \p Cond tells how a loop ended that assigns \p V.
  bool testsLoopCompanion(const Expr *Cond, const VarDecl *V) const {
    auto It = LoopCompanions.find(V);
    if (It == LoopCompanions.end())
      return false;
    bool SeesV = false;
    return mentions(Cond, It->second, V, SeesV) && !SeesV;
  }

  /// Which outcome of \p Cond is the failure of an operation that is not
  /// recorded in the candidate variable: 1 if the true branch is, 2 if the
  /// false branch is, 0 if \p Cond is no such test.
  int failureOutcome(const Expr *Cond, const VarDecl *V) const {
    bool Negated = false;
    const Expr *E = stripLinuxCondition(Cond, Negated);
    if (!E)
      return 0;
    E = E->IgnoreParenImpCasts();
    // A test inside a macro belongs to the macro, which deals with the
    // failure in its own way.  unlikely() and its like are stripped above,
    // so their argument is still seen as written by the caller.
    if (isWrittenInMacro(E->getExprLoc(), S.getSourceManager()))
      return 0;
    int Result = 0;
    if (const VarDecl *VD = getDirectLinuxVariable(E)) {
      // "if (ptr)": the false branch has the failed allocation.
      if (VD != V && AllocationResults.count(VD) &&
          !NotAllocationResults.count(VD))
        Result = 2;
    } else if (const auto *CE = dyn_cast<CallExpr>(E)) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (Callee && Callee->getIdentifier() &&
          (Callee->getName() == "IS_ERR" ||
           Callee->getName() == "IS_ERR_OR_NULL") &&
          CE->getNumArgs() == 1 &&
          getDirectLinuxVariable(CE->getArg(0)->IgnoreParenCasts()) != V)
        Result = 1;
    } else if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if (BO->isEqualityOp()) {
        const VarDecl *VD = nullptr;
        if (RHS->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNotNull))
          VD = getDirectLinuxVariable(LHS);
        else if (LHS->isNullPointerConstant(Ctx,
                                            Expr::NPC_ValueDependentIsNotNull))
          VD = getDirectLinuxVariable(RHS);
        if (VD && VD != V && AllocationResults.count(VD) &&
            !NotAllocationResults.count(VD))
          Result = BO->getOpcode() == BO_EQ ? 1 : 2;
      } else if (BO->getOpcode() == BO_LT || BO->getOpcode() == BO_GE) {
        // "x < 0" for the result of a call.
        std::optional<llvm::APSInt> K = RHS->getIntegerConstantExpr(Ctx);
        const VarDecl *VD = getDirectLinuxVariable(LHS);
        bool IsCallResult =
            isa<CallExpr>(LHS) ||
            (VD && VD != V && VD->hasLocalStorage() && CallResults.count(VD) &&
             !NotCallResults.count(VD));
        if (K && K->isZero() && IsCallResult &&
            LHS->getType()->isSignedIntegerType())
          Result = BO->getOpcode() == BO_LT ? 1 : 2;
      }
    }
    if (Result && Negated)
      Result = 3 - Result;
    return Result;
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
    // calling function failed.  seq_printf(), snprintf() and their relatives
    // format text for a file or a buffer, whatever the text says.
    if (LowerName.contains("audit") || LowerName.contains("printf") ||
        LowerName.starts_with("seq_") || LowerName.starts_with("sysfs_") ||
        LowerName.starts_with("trace_"))
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
    } else if (const auto *Logical =
                   dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts());
               Logical && Logical->isLogicalOp()) {
      // "a && b" is only true if both are, "a || b" only false if both are.
      Knowledge LT, LF, RT, RF;
      classify(Logical->getLHS(), V, LT, LF);
      classify(Logical->getRHS(), V, RT, RF);
      if (Logical->getOpcode() == BO_LAnd)
        T = LT != Knowledge::None ? LT : RT;
      else
        F = LF != Knowledge::None ? LF : RF;
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

  void reportMissing(const Expr *Test, const VarDecl *V,
                     const ReturnStmt *RS) {
    if (!Test || !ReportedTests.insert(Test).second)
      return;
    S.Diag(Test->getExprLoc(), diag::warn_linux_kernel_missing_error_code)
        << V << Test->getSourceRange();
    S.Diag(RS->getBeginLoc(), diag::note_linux_kernel_returned_here)
        << V << RS->getSourceRange();
  }

  /// What the successor \p Succ of a switch on \p V says about \p V.
  Knowledge switchKnowledge(const SwitchStmt *SS, const CFGBlock *Succ) const {
    bool HasZeroCase = false;
    for (const SwitchCase *SC = SS->getSwitchCaseList(); SC;
         SC = SC->getNextSwitchCase())
      if (const auto *CS = dyn_cast<CaseStmt>(SC))
        if (!CS->getRHS())
          if (std::optional<bool> IsZero = isZeroConstant(CS->getLHS()))
            HasZeroCase |= *IsZero;
    if (const auto *CS = dyn_cast_or_null<CaseStmt>(Succ->getLabel())) {
      if (CS->getRHS())
        return Knowledge::None;
      std::optional<bool> IsZero = isZeroConstant(CS->getLHS());
      if (!IsZero)
        return Knowledge::None;
      return *IsZero ? Knowledge::Zero : Knowledge::NonZero;
    }
    // The default label, or the end of a switch without one.
    return HasZeroCase ? Knowledge::NonZero : Knowledge::None;
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
          // "report the failure; ret = 0;" says that zero is meant.
          bool Deliberate = IsZero && *IsZero && St.Message;
          St.assigned(IsZero && *IsZero && !Deliberate, IsZero && !*IsZero);
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
            St.MustZero = IsZero && *IsZero;
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
          else if (St.Failed && St.MustZero)
            reportMissing(St.FailedTest, V, RS);
          else
            for (const Expr *Test : St.Missing)
              reportMissing(Test, V, RS);
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

  /// Whether the label that \p Goto jumps to is a way out of the function,
  /// going by its name.  "goto no_buffer;" and "goto skip;" carry on with
  /// the work, and success is the right result there.
  static bool leavesByName(const Stmt *Goto) {
    const auto *GS = dyn_cast_or_null<GotoStmt>(Goto);
    if (!GS)
      return false;
    std::string Name = GS->getLabel()->getName().lower();
    for (StringRef Word : {"skip", "next", "no_", "found", "retry", "again",
                           "continue", "repeat", "restart", "loop", "try",
                           "fallback", "default", "legacy", "ok", "success",
                           "finish", "ready"})
      if (StringRef(Name).contains(Word))
        return false;
    return true;
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
        const Stmt *Term = B->getTerminatorStmt();
        const Expr *Cond = nullptr;
        if (isConditionalBranch(B)) {
          // For "if (a && b)" the block that ends in the 'if' only decides
          // on 'b'.
          Cond = B->getLastCondition();
          if (!Cond)
            Cond = cast<Expr>(B->getTerminatorCondition());
          classify(Cond, V, OnTrue, OnFalse);
        }
        const auto *Switch = dyn_cast_or_null<SwitchStmt>(Term);
        if (Switch && getDirectLinuxVariable(Switch->getCond()) != V)
          Switch = nullptr;
        bool IsGoto = isa_and_nonnull<GotoStmt>(Term);
        // A test after a retry loop of what the loop counted.
        bool AfterLoop = Cond && !isa<ForStmt, WhileStmt, DoStmt>(Term) &&
                         testsLoopCompanion(Cond, V);
        int Failure = Cond && Out.MustZero ? failureOutcome(Cond, V) : 0;

        unsigned Index = 0;
        for (const CFGBlock::AdjacentBlock &Succ : B->succs()) {
          unsigned This = Index++;
          Knowledge K = This == 0 ? OnTrue : OnFalse;
          const CFGBlock *Next = Succ.getReachableBlock();
          if (!Next)
            continue;
          if (Switch)
            K = switchKnowledge(Switch, Next);
          Facts Edge = Out;
          if (JumpPass && IsGoto && Out.Zero && Out.Message &&
              !isInCycle(Next)) {
            Edge.Jumped = true;
            Edge.JumpMessage = Out.MessageCall;
          }
          if (JumpPass && IsGoto && Out.Failed && Out.MustZero &&
              !isInCycle(Next) && leavesByName(Term) &&
              !llvm::is_contained(Edge.Missing, Out.FailedTest))
            Edge.Missing.push_back(Out.FailedTest);
          if (AfterLoop)
            Edge.Zero = Edge.MustZero = false;
          if (Failure && This == unsigned(Failure - 1)) {
            Edge.Failed = true;
            Edge.FailedTest = Cond;
          } else if (Cond) {
            // The other outcome, or another test, ends the failure path.
            Edge.Failed = false;
            Edge.FailedTest = nullptr;
          }
          if (K == Knowledge::Zero) {
            // The variable cannot be zero on this path, as in a test that
            // sits inside "if (ret)".
            if (Out.NonZero)
              continue;
            Edge.Zero = true;
            Edge.MustZero = true;
          } else if (K == Knowledge::NonZero) {
            Edge.Zero = false;
            Edge.NonZero = true;
            Edge.Jumped = false;
            Edge.MustZero = Edge.Failed = false;
            Edge.FailedTest = nullptr;
            Edge.Missing.clear();
          }

          Facts &Target = In[Next->getBlockID()];
          if (JumpPass) {
            if (Edge.Jumped && !Target.Jumped) {
              Target.Jumped = true;
              Target.JumpMessage = Edge.JumpMessage;
              Changed = true;
            }
            for (const Expr *Test : Edge.Missing)
              if (!llvm::is_contained(Target.Missing, Test)) {
                Target.Missing.push_back(Test);
                Changed = true;
              }
            continue;
          }
          if (!Target.Reached) {
            Target = Edge;
            Target.Reached = true;
            Target.Jumped = false;
            Target.JumpMessage = nullptr;
            Target.Missing.clear();
            Changed = true;
            continue;
          }
          bool Zero = Target.Zero || Edge.Zero;
          bool NonZero = Target.NonZero && Edge.NonZero;
          bool Message = Target.Message && Edge.Message;
          bool MustZero = Target.MustZero && Edge.MustZero;
          bool Failed = Target.Failed && Edge.Failed;
          if (Zero != Target.Zero || NonZero != Target.NonZero ||
              Message != Target.Message || MustZero != Target.MustZero ||
              Failed != Target.Failed) {
            Target.Zero = Zero;
            Target.NonZero = NonZero;
            Target.Message = Message;
            Target.MustZero = MustZero;
            Target.Failed = Failed;
            if (!Message)
              Target.MessageCall = nullptr;
            if (!Failed)
              Target.FailedTest = nullptr;
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
    collectLoops(FD->getBody());

    for (const VarDecl *V : Candidates) {
      if (AddressTaken.count(V) || Counters.count(V) ||
          !ErrorCapable.count(V) || NotErrno.count(V))
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

/// A flexible array member that is declared with __counted_by() may only be
/// used once its counter holds the number of elements: the bounds checks of
/// the fortified string functions and of the array bounds sanitizer go by
/// the counter, and a freshly allocated object has it at zero.
///
/// For a local pointer that only ever holds allocations of this function,
/// the checker follows one fact through the CFG: whether every path since
/// the allocation left the counter alone.  A use of the array in that state
/// is diagnosed.  A call that is handed the object, and anything that takes
/// the address of one of its members, may set the counter.
class CountedByOrderChecker {
  Sema &S;
  const FunctionDecl *FD;
  const CFG &Cfg;

  struct Object {
    const VarDecl *Pointer;
    const FieldDecl *Array;
    const FieldDecl *Counter;
    bool Fresh = true;
    const Stmt *Allocation = nullptr;
    const Stmt *CounterSet = nullptr;
    bool Reported = false;
  };
  llvm::SmallVector<Object, 2> Objects;

  enum State : uint8_t { Unreached, Unset, Other };

  static State join(State A, State B) {
    if (A == Unreached)
      return B;
    if (B == Unreached)
      return A;
    return A == B ? A : Other;
  }

  /// The local pointer through which \p E names a member, and that member.
  /// Members of anonymous structs and unions count as members of the object.
  static const VarDecl *getObjectMember(const Expr *E,
                                        const FieldDecl *&Field) {
    const auto *ME = dyn_cast_or_null<MemberExpr>(
        E ? E->IgnoreParenImpCasts() : nullptr);
    if (!ME)
      return nullptr;
    Field = dyn_cast<FieldDecl>(ME->getMemberDecl());
    while (Field && !ME->isArrow()) {
      const auto *Outer =
          dyn_cast<MemberExpr>(ME->getBase()->IgnoreParenImpCasts());
      const auto *OuterField =
          Outer ? dyn_cast<FieldDecl>(Outer->getMemberDecl()) : nullptr;
      if (!OuterField || !OuterField->isAnonymousStructOrUnion())
        return nullptr;
      ME = Outer;
    }
    if (!Field || !ME->isArrow())
      return nullptr;
    return getDirectLinuxVariable(ME->getBase()->IgnoreParenCasts());
  }

  static bool setsCounterItself(const Stmt *St) {
    if (!St)
      return false;
    if (const auto *CE = dyn_cast<CallExpr>(St))
      if (CE->getBuiltinCallee() == Builtin::BI__builtin_counted_by_ref)
        return true;
    for (const Stmt *Child : St->children())
      if (setsCounterItself(Child))
        return true;
    return false;
  }

  static bool isAllocation(const Stmt *St) {
    if (!St)
      return false;
    if (const auto *CE = dyn_cast<CallExpr>(St)) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (Callee && Callee->getIdentifier())
        switch (classifyLinuxKernelCallee(Callee)) {
        case LinuxKernelAPIKind::KmallocPointer:
        case LinuxKernelAPIKind::VmallocPointer:
        case LinuxKernelAPIKind::KvmallocPointer:
        case LinuxKernelAPIKind::DevmPointer:
          return true;
        default:
          break;
        }
    }
    for (const Stmt *Child : St->children())
      if (isAllocation(Child))
        return true;
    return false;
  }

  Object *find(const VarDecl *VD) {
    for (Object &O : Objects)
      if (O.Pointer == VD)
        return &O;
    return nullptr;
  }

  void noteValue(const VarDecl *VD, const Expr *Value, const Stmt *At) {
    Object *O = find(VD);
    if (!O)
      return;
    // kzalloc_flex() and its relatives store the counter themselves.
    if (!Value || !isAllocation(Value) || setsCounterItself(Value))
      O->Fresh = false;
    else if (!O->Allocation)
      O->Allocation = At;
  }

  void collect(const Stmt *St) {
    if (!St)
      return;
    if (const auto *DS = dyn_cast<DeclStmt>(St)) {
      for (const Decl *D : DS->decls()) {
        const auto *VD = dyn_cast<VarDecl>(D);
        if (!VD || !VD->hasLocalStorage())
          continue;
        const auto *RT =
            VD->getType()->getPointeeType().isNull()
                ? nullptr
                : VD->getType()->getPointeeType()->getAsRecordDecl();
        const RecordDecl *Def = RT ? RT->getDefinition() : nullptr;
        if (Def && Def->hasFlexibleArrayMember() && !find(VD))
          for (const FieldDecl *F : Def->fields()) {
            // Only the flexible array: a counted pointer member has to be
            // assigned before either order makes sense.
            const FieldDecl *Counter =
                F->getType()->isArrayType() ? F->findCountedByField() : nullptr;
            if (Counter) {
              Objects.push_back({VD, F, Counter});
              break;
            }
          }
        if (VD->hasInit())
          noteValue(VD, VD->getInit(), DS);
      }
    } else if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
      if (BO->isAssignmentOp()) {
        if (const VarDecl *VD = getDirectLinuxVariable(BO->getLHS()))
          noteValue(VD, BO->getOpcode() == BO_Assign ? BO->getRHS() : nullptr,
                    BO);
        const FieldDecl *Field = nullptr;
        if (const VarDecl *VD = getObjectMember(BO->getLHS(), Field))
          if (Object *O = find(VD); O && Field == O->Counter && !O->CounterSet)
            O->CounterSet = BO;
      }
    } else if (const auto *UO = dyn_cast<UnaryOperator>(St)) {
      const FieldDecl *Field = nullptr;
      if (UO->getOpcode() == UO_AddrOf) {
        if (const VarDecl *VD = getDirectLinuxVariable(UO->getSubExpr()))
          if (Object *O = find(VD))
            O->Fresh = false;
      } else if (UO->isIncrementDecrementOp()) {
        if (const VarDecl *VD = getObjectMember(UO->getSubExpr(), Field))
          if (Object *O = find(VD); O && Field == O->Counter && !O->CounterSet)
            O->CounterSet = UO;
      }
    }
    for (const Stmt *Child : St->children())
      collect(Child);
  }

  /// Whether \p E is the array of \p O, or an element of it.
  static bool usesArray(const Expr *E, const Object &O) {
    if (!E)
      return false;
    E = E->IgnoreParenImpCasts();
    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E))
      E = ASE->getBase()->IgnoreParenImpCasts();
    const FieldDecl *Field = nullptr;
    return getObjectMember(E, Field) == O.Pointer && Field == O.Array;
  }

  void report(Object &O, const Expr *Use) {
    if (O.Reported)
      return;
    O.Reported = true;
    S.Diag(Use->getExprLoc(), O.CounterSet
                                  ? diag::warn_linux_kernel_counted_by_order
                                  : diag::warn_linux_kernel_counted_by_never_set)
        << O.Array << O.Counter << Use->getSourceRange();
    if (O.CounterSet)
      S.Diag(O.CounterSet->getBeginLoc(),
             diag::note_linux_kernel_counted_by_set_here)
          << O.Counter << O.CounterSet->getSourceRange();
    if (O.Allocation)
      S.Diag(O.Allocation->getBeginLoc(),
             diag::note_linux_kernel_counted_by_allocated_here)
          << O.Allocation->getSourceRange();
  }

  State runBlock(const CFGBlock *B, State St, Object &O, bool Report) {
    for (const CFGElement &Elem : *B) {
      std::optional<CFGStmt> CS = Elem.getAs<CFGStmt>();
      if (!CS)
        continue;
      const Stmt *Node = CS->getStmt();
      const FieldDecl *Field = nullptr;
      if (const auto *DS = dyn_cast<DeclStmt>(Node)) {
        for (const Decl *D : DS->decls())
          if (D == O.Pointer)
            St = O.Pointer->hasInit() ? Unset : Other;
      } else if (const auto *BO = dyn_cast<BinaryOperator>(Node)) {
        if (!BO->isAssignmentOp())
          continue;
        if (Report && St == Unset && usesArray(BO->getLHS(), O))
          report(O, BO->getLHS());
        if (getDirectLinuxVariable(BO->getLHS()) == O.Pointer)
          St = Unset;
        else if (getObjectMember(BO->getLHS(), Field) == O.Pointer &&
                 Field == O.Counter)
          St = Other;
        else if (const auto *Deref = dyn_cast<UnaryOperator>(
                     BO->getLHS()->IgnoreParenImpCasts());
                 Deref && Deref->getOpcode() == UO_Deref &&
                 getDirectLinuxVariable(Deref->getSubExpr()) == O.Pointer)
          St = Other; // "*p = ..." stores the whole object
      } else if (const auto *UO = dyn_cast<UnaryOperator>(Node)) {
        const Expr *Sub = UO->getSubExpr();
        if (UO->getOpcode() == UO_AddrOf) {
          if (Report && St == Unset && isa<ArraySubscriptExpr>(
                                           Sub->IgnoreParenImpCasts()) &&
              usesArray(Sub, O))
            report(O, Sub);
          else if (getObjectMember(Sub, Field) == O.Pointer &&
                   Field != O.Array)
            St = Other; // the counter can be set through this address
        } else if (UO->isIncrementDecrementOp() &&
                   getObjectMember(Sub, Field) == O.Pointer &&
                   Field == O.Counter) {
          St = Other;
        }
      } else if (const auto *ICE = dyn_cast<ImplicitCastExpr>(Node)) {
        // Reading an element.
        if (Report && St == Unset && ICE->getCastKind() == CK_LValueToRValue &&
            isa<ArraySubscriptExpr>(ICE->getSubExpr()->IgnoreParens()) &&
            usesArray(ICE->getSubExpr(), O))
          report(O, ICE->getSubExpr());
      } else if (const auto *CE = dyn_cast<CallExpr>(Node)) {
        // __builtin_counted_by_ref(p->array) is how kmalloc_flex() and its
        // relatives get at the counter, in order to set it.
        if (CE->getBuiltinCallee() == Builtin::BI__builtin_counted_by_ref) {
          if (CE->getNumArgs() == 1 && usesArray(CE->getArg(0), O))
            St = Other;
          continue;
        }
        for (const Expr *Arg : CE->arguments()) {
          if (Report && St == Unset && usesArray(Arg, O) &&
              !isa<ArraySubscriptExpr>(Arg->IgnoreParenImpCasts()))
            report(O, Arg);
        }
        for (const Expr *Arg : CE->arguments())
          if (getDirectLinuxVariable(Arg->IgnoreParenCasts()) == O.Pointer)
            St = Other; // the callee may set the counter
      }
    }
    return St;
  }

public:
  CountedByOrderChecker(Sema &S, const FunctionDecl *FD, const CFG &Cfg)
      : S(S), FD(FD), Cfg(Cfg) {}

  void run() {
    collect(FD->getBody());
    for (Object &O : Objects) {
      if (!O.Fresh || !O.Allocation)
        continue;
      std::vector<State> In(Cfg.getNumBlockIDs(), Unreached);
      In[Cfg.getEntry().getBlockID()] = Other;
      bool Changed = true;
      unsigned Rounds = 0;
      while (Changed && ++Rounds < 64) {
        Changed = false;
        for (const CFGBlock *B : Cfg) {
          State Entry = In[B->getBlockID()];
          if (Entry == Unreached)
            continue;
          State Out = runBlock(B, Entry, O, /*Report=*/false);
          for (const CFGBlock::AdjacentBlock &Succ : B->succs()) {
            const CFGBlock *Next = Succ.getReachableBlock();
            if (!Next)
              continue;
            State Joined = join(In[Next->getBlockID()], Out);
            if (Joined != In[Next->getBlockID()]) {
              In[Next->getBlockID()] = Joined;
              Changed = true;
            }
          }
        }
      }
      for (const CFGBlock *B : Cfg)
        if (In[B->getBlockID()] != Unreached)
          runBlock(B, In[B->getBlockID()], O, /*Report=*/true);
    }
  }
};

/// A pointer that is tested for NULL after every path has dereferenced it:
///
///   len = req->len;
///   ...
///   if (!req)
///           return -EINVAL;
///
/// Either the test is dead, or the pointer can be NULL and the dereference
/// is the bug.  For each local pointer and pointer parameter the checker
/// follows one fact through the CFG: whether every path has read or written
/// through the pointer since it was last assigned.  Taking the address of a
/// member, as container_of() and "&p->member" do, is not an access.
class DerefBeforeCheckChecker {
  Sema &S;
  const FunctionDecl *FD;
  const CFG &Cfg;
  ASTContext &Ctx;

  llvm::SmallVector<const VarDecl *, 16> Vars;
  llvm::DenseMap<const VarDecl *, unsigned> Index;
  llvm::SmallPtrSet<const VarDecl *, 8> AddressTaken;
  /// Where each pointer is dereferenced first, for the note.
  llvm::DenseMap<const VarDecl *, const Expr *> FirstDeref;
  llvm::SmallPtrSet<const Stmt *, 4> Reported;

  /// The pointer through which the lvalue \p LV is reached.
  static const VarDecl *accessedThrough(const Expr *LV) {
    while (LV) {
      LV = LV->IgnoreParens();
      if (const auto *ME = dyn_cast<MemberExpr>(LV)) {
        if (ME->isArrow())
          return getDirectLinuxVariable(ME->getBase()->IgnoreParenCasts());
        LV = ME->getBase();
      } else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(LV)) {
        const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
        if (const VarDecl *VD = getDirectLinuxVariable(Base))
          return VD->getType()->isPointerType() ? VD : nullptr;
        LV = Base;
      } else if (const auto *UO = dyn_cast<UnaryOperator>(LV)) {
        return UO->getOpcode() == UO_Deref
                   ? getDirectLinuxVariable(
                         UO->getSubExpr()->IgnoreParenCasts())
                   : nullptr;
      } else {
        return nullptr;
      }
    }
    return nullptr;
  }

  void track(const VarDecl *VD) {
    if (!VD->getType()->isPointerType() ||
        VD->getType().isVolatileQualified() || Index.count(VD))
      return;
    Index[VD] = Vars.size();
    Vars.push_back(VD);
  }

  void collect(const Stmt *St) {
    if (!St || isa<UnaryExprOrTypeTraitExpr>(St))
      return;
    if (const auto *DS = dyn_cast<DeclStmt>(St)) {
      for (const Decl *D : DS->decls())
        if (const auto *VD = dyn_cast<VarDecl>(D); VD && VD->hasLocalStorage())
          track(VD);
    } else if (const auto *UO = dyn_cast<UnaryOperator>(St)) {
      if (UO->getOpcode() == UO_AddrOf)
        if (const VarDecl *VD = getDirectLinuxVariable(UO->getSubExpr()))
          AddressTaken.insert(VD);
    } else if (const auto *AS = dyn_cast<GCCAsmStmt>(St)) {
      for (unsigned I = 0, E = AS->getNumOutputs(); I != E; ++I)
        if (const VarDecl *VD = getDirectLinuxVariable(AS->getOutputExpr(I)))
          AddressTaken.insert(VD);
    }
    for (const Stmt *Child : St->children())
      collect(Child);
  }

  /// The pointer that \p Node reads or writes through, with the access.
  const VarDecl *getAccess(const Stmt *Node, const Expr *&Access) const {
    if (const auto *ICE = dyn_cast<ImplicitCastExpr>(Node)) {
      if (ICE->getCastKind() != CK_LValueToRValue)
        return nullptr;
      Access = ICE->getSubExpr();
    } else if (const auto *BO = dyn_cast<BinaryOperator>(Node)) {
      if (!BO->isAssignmentOp())
        return nullptr;
      Access = BO->getLHS();
    } else if (const auto *UO = dyn_cast<UnaryOperator>(Node)) {
      if (!UO->isIncrementDecrementOp())
        return nullptr;
      Access = UO->getSubExpr();
    } else {
      return nullptr;
    }
    return accessedThrough(Access);
  }

  /// The pointer that \p Node gives a new value.
  static const VarDecl *getAssigned(const Stmt *Node) {
    if (const auto *BO = dyn_cast<BinaryOperator>(Node))
      return BO->isAssignmentOp() ? getDirectLinuxVariable(BO->getLHS())
                                  : nullptr;
    if (const auto *UO = dyn_cast<UnaryOperator>(Node))
      return UO->isIncrementDecrementOp()
                 ? getDirectLinuxVariable(UO->getSubExpr())
                 : nullptr;
    return nullptr;
  }

  void runBlock(const CFGBlock *B, llvm::SmallBitVector &St) {
    for (const CFGElement &Elem : *B) {
      std::optional<CFGStmt> CS = Elem.getAs<CFGStmt>();
      if (!CS)
        continue;
      const Stmt *Node = CS->getStmt();
      if (const auto *DS = dyn_cast<DeclStmt>(Node)) {
        for (const Decl *D : DS->decls())
          if (auto It = Index.find(dyn_cast<VarDecl>(D)); It != Index.end())
            St.reset(It->second);
        continue;
      }
      const Expr *Access = nullptr;
      if (const VarDecl *VD = getAccess(Node, Access))
        if (auto It = Index.find(VD); It != Index.end()) {
          St.set(It->second);
          FirstDeref.try_emplace(VD, Access);
        }
      if (const VarDecl *VD = getAssigned(Node))
        if (auto It = Index.find(VD); It != Index.end())
          St.reset(It->second);
    }
  }

  /// The pointer that the branch at the end of \p B tests for NULL.
  const VarDecl *getNullTest(const CFGBlock *B, const Expr *&Cond) const {
    const Stmt *Term = B->getTerminatorStmt();
    if (!Term || B->succ_size() != 2 || isa<SwitchStmt, GCCAsmStmt>(Term))
      return nullptr;
    // A test that a macro makes is not the author's statement about this
    // pointer: dev_err(), kfree() and many others test whatever they get.
    SourceLocation Loc = Term->getBeginLoc();
    if (const auto *BO = dyn_cast<BinaryOperator>(Term))
      Loc = BO->getOperatorLoc();
    else if (const auto *CO = dyn_cast<ConditionalOperator>(Term))
      Loc = CO->getQuestionLoc();
    if (isWrittenInMacro(Loc, S.getSourceManager()))
      return nullptr;

    Cond = B->getLastCondition();
    if (!Cond)
      Cond = dyn_cast_or_null<Expr>(B->getTerminatorCondition());
    bool Negated = false;
    const Expr *E = stripLinuxCondition(Cond, Negated);
    if (!E || isLinuxAssertionMacroExpansion(Cond, S))
      return nullptr;
    if (const VarDecl *VD = getDirectLinuxVariable(E))
      return VD;
    const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts());
    if (!BO || !BO->isEqualityOp())
      return nullptr;
    if (BO->getRHS()->isNullPointerConstant(Ctx,
                                            Expr::NPC_ValueDependentIsNotNull))
      return getDirectLinuxVariable(BO->getLHS());
    if (BO->getLHS()->isNullPointerConstant(Ctx,
                                            Expr::NPC_ValueDependentIsNotNull))
      return getDirectLinuxVariable(BO->getRHS());
    return nullptr;
  }

public:
  DerefBeforeCheckChecker(Sema &S, const FunctionDecl *FD, const CFG &Cfg)
      : S(S), FD(FD), Cfg(Cfg), Ctx(S.getASTContext()) {}

  void run() {
    for (const ParmVarDecl *P : FD->parameters())
      track(P);
    collect(FD->getBody());
    if (Vars.empty())
      return;

    // In[B]: the pointers that every path to B has dereferenced.
    std::vector<llvm::SmallBitVector> In(Cfg.getNumBlockIDs());
    llvm::BitVector Reached(Cfg.getNumBlockIDs());
    In[Cfg.getEntry().getBlockID()].resize(Vars.size());
    Reached.set(Cfg.getEntry().getBlockID());
    bool Changed = true;
    unsigned Rounds = 0;
    while (Changed && ++Rounds < 64) {
      Changed = false;
      for (const CFGBlock *B : Cfg) {
        if (!Reached.test(B->getBlockID()))
          continue;
        llvm::SmallBitVector Out = In[B->getBlockID()];
        runBlock(B, Out);
        for (const CFGBlock::AdjacentBlock &Succ : B->succs()) {
          const CFGBlock *Next = Succ.getReachableBlock();
          if (!Next)
            continue;
          unsigned ID = Next->getBlockID();
          if (!Reached.test(ID)) {
            Reached.set(ID);
            In[ID] = Out;
            Changed = true;
          } else if ((In[ID] & Out) != In[ID]) {
            In[ID] &= Out;
            Changed = true;
          }
        }
      }
    }

    for (const CFGBlock *B : Cfg) {
      if (!Reached.test(B->getBlockID()))
        continue;
      const Expr *Cond = nullptr;
      const VarDecl *VD = getNullTest(B, Cond);
      auto It = VD ? Index.find(VD) : Index.end();
      if (It == Index.end() || AddressTaken.count(VD))
        continue;
      llvm::SmallBitVector Out = In[B->getBlockID()];
      runBlock(B, Out);
      if (!Out.test(It->second) || !Reported.insert(Cond).second)
        continue;
      S.Diag(Cond->getExprLoc(), diag::warn_linux_kernel_deref_before_check)
          << VD << Cond->getSourceRange();
      if (const Expr *Deref = FirstDeref.lookup(VD))
        S.Diag(Deref->getExprLoc(), diag::note_linux_kernel_dereferenced_here)
            << VD << Deref->getSourceRange();
    }
  }
};

/// What a path knows about an integer or a pointer: whether it can still be
/// negative, zero or positive, and the number itself once a test or an
/// assignment has pinned it down.  For a pointer, negative stands for an
/// ERR_PTR() value and positive for a valid address.
struct LinuxPathValue {
  enum : uint8_t { Neg = 1, Zero = 2, Pos = 4, Any = Neg | Zero | Pos };
  uint8_t Mask = Any;
  bool HasConst = false;
  int64_t Const = 0;

  static LinuxPathValue constant(int64_t V) {
    LinuxPathValue R;
    R.Mask = V < 0 ? Neg : V == 0 ? Zero : Pos;
    R.HasConst = true;
    R.Const = V;
    return R;
  }

  static LinuxPathValue ofMask(uint8_t M) {
    if (M == Zero)
      return constant(0);
    LinuxPathValue R;
    R.Mask = M;
    return R;
  }

  static LinuxPathValue join(const LinuxPathValue &A, const LinuxPathValue &B) {
    return A == B ? A : ofMask(A.Mask | B.Mask);
  }

  bool isAny() const { return Mask == Any; }

  bool operator==(const LinuxPathValue &O) const {
    return Mask == O.Mask && HasConst == O.HasConst &&
           (!HasConst || Const == O.Const);
  }

  /// The value as a condition, if it is decided.
  std::optional<bool> truth() const {
    if (Mask == Zero)
      return false;
    if (!(Mask & Zero))
      return true;
    return std::nullopt;
  }
};

/// A function that returns or tests an error pointer, or converts one:
/// these have no side effect and the path search knows what they compute.
static bool isLinuxErrorPointerHelper(const FunctionDecl *FD) {
  if (!FD->getIdentifier())
    return false;
  return llvm::StringSwitch<bool>(FD->getName())
      .Cases({"IS_ERR", "IS_ERR_OR_NULL", "PTR_ERR", "ERR_PTR", "ERR_CAST",
              "PTR_ERR_OR_ZERO"},
             true)
      .Default(false);
}

/// A function that prints, compares or frees what it is given and stores
/// nothing through its arguments that a later test could read.
static bool isLinuxReadOnlyCallee(const FunctionDecl *FD) {
  if (!FD->getIdentifier())
    return false;
  if (isLinuxErrorPointerHelper(FD))
    return true;
  StringRef Name = FD->getName();
  if (llvm::StringSwitch<bool>(Name)
          .Cases({"_printk", "printk", "_dev_printk", "dev_printk_emit",
                  "dev_err_probe", "dev_warn_probe", "dump_stack"},
                 true)
          .Cases({"strlen", "strcmp", "strncmp", "strcasecmp", "memcmp",
                  "strnlen", "strchr", "strrchr", "strstr"},
                 true)
          .Cases({"kfree", "kvfree", "vfree", "kfree_sensitive"}, true)
          .Default(false))
    return true;
  return Name.starts_with("_dev_") || Name.starts_with("netdev_") ||
         Name.starts_with("__dynamic_") || Name.starts_with("__warn") ||
         Name.starts_with("trace_") || Name.starts_with("__trace");
}

/// What the function \p Def can store to: the members that it or the
/// functions it calls assign, and the structures that it hands to functions
/// whose body is not here.  A call of such a function leaves every other
/// member of every object as it was.
static const sema::LinuxKernelUnit::Impl::Writes &
getLinuxWrites(const FunctionDecl *Def, sema::LinuxKernelUnit::Impl &Unit,
               unsigned Depth = 0) {
  using Writes = sema::LinuxKernelUnit::Impl::Writes;
  auto Known = Unit.WriteSummaries.find(Def);
  if (Known != Unit.WriteSummaries.end())
    return Known->second;
  // The answer while this is being worked out, for recursion.
  Unit.WriteSummaries[Def].Anything = true;

  struct Scan {
    sema::LinuxKernelUnit::Impl &Unit;
    unsigned Depth;
    Writes W;

    void store(const Expr *LHS) {
      LHS = LHS->IgnoreParens();
      // Every member on the way: "a->b.c = x" changes b as well.
      while (const auto *ME = dyn_cast<MemberExpr>(LHS)) {
        if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl()))
          W.Fields.insert(FD);
        if (ME->isArrow())
          return;
        LHS = ME->getBase()->IgnoreParens();
      }
      // "*p = s" and "a[i] = s" for a whole structure.
      if (!isa<DeclRefExpr>(LHS) && LHS->getType()->isRecordType())
        W.Anything = true;
    }

    void pass(const Expr *Arg) {
      QualType T = Arg->IgnoreParenImpCasts()->getType();
      if (!T->isPointerType())
        return;
      QualType Pointee = T->getPointeeType();
      if (Pointee.isConstQualified() || Pointee->isFunctionType())
        return;
      if (const RecordDecl *RD = Pointee->getAsRecordDecl())
        W.Records.insert(RD->getDefinition() ? RD->getDefinition() : RD);
      else if (Pointee->isVoidType() || Pointee->isPointerType())
        W.Anything = true;
    }

    void visit(const Stmt *St) {
      if (!St || W.Anything)
        return;
      if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
        if (BO->isAssignmentOp())
          store(BO->getLHS());
      } else if (const auto *UO = dyn_cast<UnaryOperator>(St)) {
        if (UO->isIncrementDecrementOp())
          store(UO->getSubExpr());
      } else if (isa<GCCAsmStmt>(St)) {
        W.Anything = true;
      } else if (const auto *CE = dyn_cast<CallExpr>(St)) {
        const FunctionDecl *Callee = CE->getDirectCallee();
        const FunctionDecl *CalleeDef = nullptr;
        unsigned ID = CE->getBuiltinCallee();
        if (ID == Builtin::BI__builtin_expect ||
            ID == Builtin::BI__builtin_expect_with_probability ||
            ID == Builtin::BI__builtin_constant_p ||
            (Callee && (Callee->hasAttr<ConstAttr>() ||
                        Callee->hasAttr<PureAttr>() ||
                        isLinuxReadOnlyCallee(Callee)))) {
          // Nothing is stored.
        } else if (!Callee || ID) {
          W.Anything = true;
        } else if (Callee->hasBody(CalleeDef)) {
          if (Depth >= 3) {
            W.Anything = true;
          } else {
            const Writes &Inner = getLinuxWrites(CalleeDef, Unit, Depth + 1);
            W.Anything |= Inner.Anything;
            W.Fields.insert(Inner.Fields.begin(), Inner.Fields.end());
            W.Records.insert(Inner.Records.begin(), Inner.Records.end());
          }
        } else {
          for (const Expr *Arg : CE->arguments())
            pass(Arg);
        }
      }
      for (const Stmt *Child : St->children())
        visit(Child);
    }
  } S{Unit, Depth, {}};
  S.visit(Def->getBody());
  return Unit.WriteSummaries[Def] = std::move(S.W);
}

/// A bounded search over the paths of one function, for checks that need to
/// know that a single path does something wrong: that it dereferences a
/// pointer after a test has found it to be NULL, or that it returns an error
/// while it still holds a resource.
///
/// The search starts at a point that the check chooses and walks the CFG
/// forward.  Each path carries what it has learned on its way: the values of
/// some locations, as far as assignments and branch conditions have pinned
/// them down, and the outcome of some conditions without side effects.  A
/// location is a local variable or a chain of members that starts at one
/// ("dev->priv").  At a branch whose condition the path already decides,
/// only the matching edge is followed, so that in
///
///   if (!p)
///     ret = -ENODEV;
///   if (ret)
///     return ret;
///   use(p->member);
///
/// no path arrives at the dereference with p being NULL.
///
/// To keep the number of states small, a path only keeps what can make a
/// difference later: values of locations that some branch condition of the
/// function reads, and outcomes of conditions that occur more than once.
/// The search gives up when it exceeds its budget, and a check then reports
/// nothing.
class LinuxPathSearch {
public:
  using Value = LinuxPathValue;

  struct State {
    /// Sorted by location and by condition.  A location without an entry
    /// can have any value.
    llvm::SmallVector<std::pair<unsigned, Value>, 4> Vals;
    llvm::SmallVector<std::pair<unsigned, bool>, 4> Preds;
    /// Pairs of locations of which one was assigned to the other and that
    /// have held the same value since: "meta = cpu->meta".
    llvm::SmallVector<std::pair<unsigned, unsigned>, 2> Same;
    /// Outcomes of conditions that the check takes for granted for the
    /// whole search, whatever the path does.
    llvm::SmallVector<std::pair<unsigned, bool>, 2> Fixed;
    /// For the check that runs the search.
    uint32_t Client = 0;

    bool operator==(const State &O) const {
      return Client == O.Client && Vals == O.Vals && Preds == O.Preds &&
             Same == O.Same && Fixed == O.Fixed;
    }
  };

  class Client {
  public:
    virtual ~Client() = default;
    /// The path executes \p S.  This is called before the statement changes
    /// the state.  Returning false ends the path.
    virtual bool statement(const Stmt *S, State &St) = 0;
    /// The path leaves \p From for \p To.  Returning false ends the path.
    virtual bool edge(const CFGBlock *From, const CFGBlock *To, State &St) {
      return true;
    }
  };

private:
  static constexpr unsigned MaxLocations = 96;
  static constexpr unsigned MaxConditions = 64;
  static constexpr unsigned MaxStatesPerBlock = 16;
  /// Budget for one search: block visits plus statements.
  static constexpr unsigned MaxSteps = 20000;
  /// Budget for all searches in one function.
  static constexpr unsigned MaxFunctionSteps = 600000;

  const CFG &Cfg;
  ASTContext &Ctx;
  sema::LinuxKernelUnit::Impl &Unit;

  struct Location {
    const VarDecl *Root = nullptr;
    /// The members from the root down.  Empty for the variable itself.
    llvm::SmallVector<const FieldDecl *, 3> Path;
    /// The number of branch conditions that read the location.
    unsigned Sites = 0;
    /// A check asked for the value to be kept.
    bool Pinned = false;
  };

  struct Condition {
    llvm::FoldingSetNodeID ID;
    llvm::SmallVector<unsigned, 2> Locations;
    bool ReadsMemory = false;
    unsigned Sites = 0;
  };

  std::vector<Location> Locations;
  std::vector<Condition> Conditions;
  llvm::SmallPtrSet<const VarDecl *, 16> AddressTaken;
  unsigned FunctionSteps = 0;
  unsigned Steps = 0;
  bool Stopped = false;
  bool GaveUp = false;
  /// The blocks that the search has entered, each with the one it came
  /// from, and the one it is in.
  std::vector<std::pair<const CFGBlock *, int>> Trail;
  int Current = -1;

  struct Item {
    const CFGBlock *Block;
    State St;
    int Node;
  };

  /// Strip what does not change the value or the object that \p E names.
  static const Expr *stripNoOps(const Expr *E) {
    while (E) {
      E = E->IgnoreParens();
      const auto *ICE = dyn_cast<ImplicitCastExpr>(E);
      if (!ICE || (ICE->getCastKind() != CK_LValueToRValue &&
                   ICE->getCastKind() != CK_NoOp))
        break;
      E = ICE->getSubExpr();
    }
    return E;
  }

  static bool decompose(const Expr *E, const VarDecl *&Root,
                        llvm::SmallVectorImpl<const FieldDecl *> &Path) {
    E = stripNoOps(E);
    if (!E)
      return false;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      Root = dyn_cast<VarDecl>(DRE->getDecl());
      return Root && Root->hasLocalStorage() &&
             !Root->getType().isVolatileQualified();
    }
    const auto *ME = dyn_cast<MemberExpr>(E);
    const auto *FD = ME ? dyn_cast<FieldDecl>(ME->getMemberDecl()) : nullptr;
    if (!FD || FD->getType().isVolatileQualified() ||
        !decompose(ME->getBase(), Root, Path) || Path.size() >= 4)
      return false;
    Path.push_back(FD);
    return true;
  }

  static bool isTrackedType(QualType T) {
    return !T.isVolatileQualified() &&
           (T->isIntegralOrEnumerationType() || T->isPointerType());
  }

  void collectAddressTaken(const Stmt *St) {
    if (!St)
      return;
    if (const auto *UO = dyn_cast<UnaryOperator>(St)) {
      if (UO->getOpcode() == UO_AddrOf)
        if (const VarDecl *VD = getDirectLinuxVariable(UO->getSubExpr()))
          AddressTaken.insert(VD);
    } else if (const auto *AS = dyn_cast<GCCAsmStmt>(St)) {
      for (unsigned I = 0, E = AS->getNumOutputs(); I != E; ++I)
        if (const VarDecl *VD = getDirectLinuxVariable(AS->getOutputExpr(I)))
          AddressTaken.insert(VD);
    }
    for (const Stmt *Child : St->children())
      collectAddressTaken(Child);
  }

  static bool mentions(const Stmt *St, const VarDecl *VD) {
    if (!St)
      return false;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(St))
      if (DRE->getDecl() == VD)
        return true;
    for (const Stmt *Child : St->children())
      if (mentions(Child, VD))
        return true;
    return false;
  }

  /// Collect what a condition reads.  Returns false if evaluating it could
  /// have a side effect.
  bool scanCondition(const Stmt *St, Condition &C) {
    if (!St)
      return true;
    if (const auto *E = dyn_cast<Expr>(St)) {
      if (E->getType().isVolatileQualified())
        return false;
      int Loc = locate(E);
      if (Loc >= 0) {
        if (!llvm::is_contained(C.Locations, unsigned(Loc)))
          C.Locations.push_back(Loc);
        if (!Locations[Loc].Path.empty())
          C.ReadsMemory = true;
        return true;
      }
    }
    switch (St->getStmtClass()) {
    case Stmt::DeclRefExprClass:
      if (isa<VarDecl>(cast<DeclRefExpr>(St)->getDecl()))
        C.ReadsMemory = true;
      return true;
    case Stmt::MemberExprClass:
    case Stmt::ArraySubscriptExprClass:
      C.ReadsMemory = true;
      break;
    case Stmt::UnaryOperatorClass: {
      const auto *UO = cast<UnaryOperator>(St);
      if (UO->isIncrementDecrementOp())
        return false;
      if (UO->getOpcode() == UO_Deref)
        C.ReadsMemory = true;
      break;
    }
    case Stmt::BinaryOperatorClass:
      if (cast<BinaryOperator>(St)->isAssignmentOp())
        return false;
      break;
    case Stmt::CallExprClass: {
      const auto *CE = cast<CallExpr>(St);
      unsigned ID = CE->getBuiltinCallee();
      if (ID != Builtin::BI__builtin_expect &&
          ID != Builtin::BI__builtin_expect_with_probability &&
          ID != Builtin::BI__builtin_constant_p) {
        const FunctionDecl *FD = CE->getDirectCallee();
        if (!FD || !(FD->hasAttr<ConstAttr>() || FD->hasAttr<PureAttr>() ||
                     isErrorPointerHelper(FD)))
          return false;
        if (FD->hasAttr<PureAttr>())
          C.ReadsMemory = true;
      }
      break;
    }
    case Stmt::CompoundAssignOperatorClass:
    case Stmt::StmtExprClass:
    case Stmt::VAArgExprClass:
    case Stmt::AtomicExprClass:
    case Stmt::ConditionalOperatorClass:
    case Stmt::BinaryConditionalOperatorClass:
      return false;
    default:
      break;
    }
    for (const Stmt *Child : St->children())
      if (!scanCondition(Child, C))
        return false;
    return true;
  }

  /// The index of the condition \p E, which is already stripped, or -1 if
  /// it has a side effect or there is no room for it.
  int conditionIndex(const Expr *E, bool Create) {
    llvm::FoldingSetNodeID ID;
    E->Profile(ID, Ctx, /*Canonical=*/true);
    for (unsigned I = 0, N = Conditions.size(); I != N; ++I)
      if (Conditions[I].ID == ID)
        return I;
    if (!Create || Conditions.size() >= MaxConditions)
      return -1;
    Condition C;
    if (!scanCondition(E, C))
      return -1;
    C.ID = ID;
    Conditions.push_back(std::move(C));
    return Conditions.size() - 1;
  }

  /// Count how often the function branches on each location and on each
  /// condition.
  void countSites() {
    for (const CFGBlock *B : Cfg) {
      const Expr *Cond = nullptr;
      if (isConditionalBranch(B))
        Cond = getBranchCondition(B);
      else if (const auto *SS =
                   dyn_cast_or_null<SwitchStmt>(B->getTerminatorStmt()))
        Cond = SS->getCond();
      if (!Cond)
        continue;
      bool Negated = false;
      const Expr *E = stripLinuxCondition(Cond, Negated);
      if (!E)
        continue;
      Condition Reads;
      scanCondition(E, Reads);
      for (unsigned Loc : Reads.Locations)
        Locations[Loc].Sites += isa<SwitchStmt>(B->getTerminatorStmt()) ? 2 : 1;
      if (isConditionalBranch(B) && locate(E) < 0) {
        int I = conditionIndex(E, /*Create=*/true);
        if (I >= 0)
          ++Conditions[I].Sites;
      }
    }
    // What the function returns says whether a path ends in an error.
    for (const CFGBlock *B : Cfg)
      for (const CFGElement &Elem : *B)
        if (std::optional<CFGStmt> CS = Elem.getAs<CFGStmt>())
          if (const auto *RS = dyn_cast<ReturnStmt>(CS->getStmt())) {
            int Loc = locate(RS->getRetValue());
            if (Loc >= 0)
              Locations[Loc].Pinned = true;
          }
  }

  bool keeps(unsigned Loc) const {
    return Locations[Loc].Pinned || Locations[Loc].Sites >= 1;
  }

  /// Whether \p L is the object that \p Root and \p Path name, or a member
  /// chain that goes through it.
  static bool isUnder(const Location &L, const VarDecl *Root,
                      ArrayRef<const FieldDecl *> Path, bool Strictly) {
    if (L.Root != Root || L.Path.size() < Path.size() ||
        (Strictly && L.Path.size() == Path.size()))
      return false;
    return std::equal(Path.begin(), Path.end(), L.Path.begin());
  }

  /// The object that \p Root and \p Path name gets a new value: forget the
  /// conditions that read it and the member chains that go through it.
  void invalidate(const VarDecl *Root, ArrayRef<const FieldDecl *> Path,
                  State &St) const {
    llvm::erase_if(St.Preds, [&](const std::pair<unsigned, bool> &P) {
      return llvm::any_of(Conditions[P.first].Locations, [&](unsigned L) {
        return isUnder(Locations[L], Root, Path, /*Strictly=*/false);
      });
    });
    llvm::erase_if(St.Vals, [&](const std::pair<unsigned, Value> &V) {
      return isUnder(Locations[V.first], Root, Path, /*Strictly=*/true);
    });
    llvm::erase_if(St.Same, [&](const std::pair<unsigned, unsigned> &P) {
      return isUnder(Locations[P.first], Root, Path, /*Strictly=*/false) ||
             isUnder(Locations[P.second], Root, Path, /*Strictly=*/false);
    });
  }

  /// "To = From" for two locations: they hold the same value from here on.
  void link(unsigned To, const Expr *From, State &St) {
    if (!From || St.Same.size() >= 4)
      return;
    int Source = locate(From->IgnoreParenCasts(), /*Create=*/false);
    if (Source < 0 || unsigned(Source) == To ||
        isUnder(Locations[Source], Locations[To].Root, Locations[To].Path,
                /*Strictly=*/false))
      return;
    std::pair<unsigned, unsigned> P = std::minmax(To, unsigned(Source));
    if (!llvm::is_contained(St.Same, P))
      St.Same.insert(llvm::upper_bound(St.Same, P), P);
  }

  /// Forget the member chains that \p Gone names, with their pairs.
  template <typename Pred> void forgetChains(State &St, Pred Gone) const {
    llvm::erase_if(St.Vals, [&](const std::pair<unsigned, Value> &V) {
      return Gone(V.first);
    });
    llvm::erase_if(St.Same, [&](const std::pair<unsigned, unsigned> &P) {
      return Gone(P.first) || Gone(P.second);
    });
  }

  int find(const VarDecl *Root, ArrayRef<const FieldDecl *> Path) const {
    for (unsigned I = 0, N = Locations.size(); I != N; ++I)
      if (Locations[I].Root == Root && ArrayRef(Locations[I].Path) == Path)
        return I;
    return -1;
  }

  /// "LHS = RHS", or another change of LHS if \p RHS is null.
  void assign(const Expr *LHS, const Expr *RHS, State &St) {
    // The new value first: it can depend on the old one.
    Value V = RHS ? value(RHS, St) : Value();
    const VarDecl *Root = nullptr;
    llvm::SmallVector<const FieldDecl *, 3> Path;
    if (!decompose(LHS, Root, Path)) {
      storeToMemory(LHS, St);
      return;
    }
    invalidate(Root, Path, St);
    if (!Path.empty()) {
      // The same member of another object may be the same memory.
      forgetMemoryConditions(St);
      const FieldDecl *FD = Path.back();
      forgetChains(St, [&](unsigned O) {
        return llvm::is_contained(Locations[O].Path, FD);
      });
    }
    int Loc = find(Root, Path);
    if (Loc >= 0 && (Path.empty() ? !AddressTaken.count(Root) : true)) {
      set(St, Loc, keeps(Loc) ? V : Value());
      link(Loc, RHS, St);
    }
  }

  void forgetMemoryConditions(State &St) const {
    llvm::erase_if(St.Preds, [&](const std::pair<unsigned, bool> &P) {
      return Conditions[P.first].ReadsMemory;
    });
  }

  /// A store to memory that is not a location of its own: it may hit any
  /// member chain that ends in the same member or has the same type.
  void storeToMemory(const Expr *LHS, State &St) const {
    forgetMemoryConditions(St);
    const auto *ME = dyn_cast<MemberExpr>(LHS->IgnoreParens());
    const auto *FD = ME ? dyn_cast<FieldDecl>(ME->getMemberDecl()) : nullptr;
    QualType T = LHS->getType().getCanonicalType().getUnqualifiedType();
    forgetChains(St, [&](unsigned O) {
      const Location &L = Locations[O];
      if (L.Path.empty())
        return false;
      if (FD)
        return llvm::is_contained(L.Path, FD);
      return L.Path.back()->getType().getCanonicalType().getUnqualifiedType() ==
             T;
    });
  }

  static bool takesAddress(const Stmt *St, const VarDecl *VD) {
    if (!St)
      return false;
    if (const auto *UO = dyn_cast<UnaryOperator>(St))
      if (UO->getOpcode() == UO_AddrOf && mentions(UO->getSubExpr(), VD))
        return true;
    for (const Stmt *Child : St->children())
      if (takesAddress(Child, VD))
        return true;
    return false;
  }

  /// A call can change every member chain whose root object it can reach
  /// through its arguments.  If the body of the callee is here, it is known
  /// which members it stores to and which structures it hands on, and
  /// everything else stays as it was.
  void call(const CallExpr *CE, State &St) {
    unsigned ID = CE->getBuiltinCallee();
    if (ID == Builtin::BI__builtin_expect ||
        ID == Builtin::BI__builtin_expect_with_probability ||
        ID == Builtin::BI__builtin_constant_p)
      return;
    const FunctionDecl *FD = CE->getDirectCallee();
    if (FD && (FD->hasAttr<ConstAttr>() || FD->hasAttr<PureAttr>() ||
               isErrorPointerHelper(FD) || isLinuxReadOnlyCallee(FD)))
      return;
    forgetMemoryConditions(St);
    const FunctionDecl *Def = nullptr;
    const sema::LinuxKernelUnit::Impl::Writes *W = nullptr;
    if (FD && FD->hasBody(Def))
      W = &getLinuxWrites(Def, Unit);
    forgetChains(St, [&](unsigned O) {
      const Location &L = Locations[O];
      if (L.Path.empty())
        return false;
      bool Mentioned = mentions(CE->getCallee(), L.Root);
      bool Address = false;
      for (const Expr *Arg : CE->arguments()) {
        Mentioned |= mentions(Arg, L.Root);
        Address |= takesAddress(Arg, L.Root);
      }
      if (!W || W->Anything)
        return Mentioned;
      // "fill(&dev->priv)" stores through a plain pointer.
      if (Address)
        return true;
      const RecordDecl *RootRecord =
          L.Root->getType()->isPointerType()
              ? L.Root->getType()->getPointeeType()->getAsRecordDecl()
              : L.Root->getType()->getAsRecordDecl();
      if (RootRecord && RootRecord->getDefinition())
        RootRecord = RootRecord->getDefinition();
      if (RootRecord && W->Records.count(RootRecord))
        return true;
      for (const FieldDecl *Member : L.Path)
        if (W->Fields.count(Member) || W->Records.count(Member->getParent()))
          return true;
      return false;
    });
  }

  void transfer(const Stmt *Node, State &St) {
    if (const auto *DS = dyn_cast<DeclStmt>(Node)) {
      for (const Decl *D : DS->decls())
        if (const auto *VD = dyn_cast<VarDecl>(D); VD && VD->hasLocalStorage())
          if (int Loc = find(VD, {}); Loc >= 0) {
            store(Loc, VD->getInit() ? value(VD->getInit(), St) : Value(), St);
            link(Loc, VD->getInit(), St);
          }
    } else if (const auto *BO = dyn_cast<BinaryOperator>(Node)) {
      if (BO->isAssignmentOp())
        assign(BO->getLHS(),
               BO->getOpcode() == BO_Assign ? BO->getRHS() : nullptr, St);
    } else if (const auto *UO = dyn_cast<UnaryOperator>(Node)) {
      if (UO->isIncrementDecrementOp())
        assign(UO->getSubExpr(), nullptr, St);
    } else if (const auto *CE = dyn_cast<CallExpr>(Node)) {
      call(CE, St);
    } else if (isa<GCCAsmStmt>(Node)) {
      // Inline assembly can change whatever its operands reach.
      St.Vals.clear();
      St.Preds.clear();
      St.Same.clear();
    }
  }

  /// Whether the switch \p SS, on a value known to be \p K, goes to \p Next.
  bool switchSelects(const SwitchStmt *SS, const CFGBlock *Next,
                     int64_t K) const {
    auto Matches = [&](const CaseStmt *CS) {
      llvm::APSInt Low = CS->getLHS()->EvaluateKnownConstInt(Ctx);
      llvm::APSInt High =
          CS->getRHS() ? CS->getRHS()->EvaluateKnownConstInt(Ctx) : Low;
      llvm::APSInt V(llvm::APInt(64, uint64_t(K), /*isSigned=*/true),
                     /*isUnsigned=*/false);
      return llvm::APSInt::compareValues(Low, V) <= 0 &&
             llvm::APSInt::compareValues(V, High) <= 0;
    };
    bool AnyCase = false;
    for (const SwitchCase *SC = SS->getSwitchCaseList(); SC;
         SC = SC->getNextSwitchCase())
      if (const auto *CS = dyn_cast<CaseStmt>(SC))
        AnyCase |= Matches(CS);
    bool HasLabel = false;
    for (const Stmt *L = Next->getLabel(); L && isa<SwitchCase>(L);
         L = cast<SwitchCase>(L)->getSubStmt()) {
      HasLabel = true;
      if (const auto *CS = dyn_cast<CaseStmt>(L)) {
        if (Matches(CS))
          return true;
      } else if (!AnyCase) {
        return true; // the default label
      }
    }
    // The statement after a switch without a default label.
    return !HasLabel && !AnyCase;
  }

  bool push(const CFGBlock *B, const State &St,
            llvm::DenseMap<unsigned, llvm::SmallVector<State, 2>> &Seen,
            llvm::SmallVectorImpl<Item> &Work) {
    llvm::SmallVectorImpl<State> &Set = Seen[B->getBlockID()];
    if (llvm::is_contained(Set, St))
      return false;
    if (Set.size() >= MaxStatesPerBlock) {
      GaveUp = true;
      return false;
    }
    Set.push_back(St);
    Trail.push_back({B, Current});
    Work.push_back({B, St, int(Trail.size()) - 1});
    return true;
  }

public:
  LinuxPathSearch(ASTContext &Ctx, const FunctionDecl *FD, const CFG &Cfg,
                  sema::LinuxKernelUnit::Impl &Unit)
      : Cfg(Cfg), Ctx(Ctx), Unit(Unit) {
    collectAddressTaken(FD->getBody());
    countSites();
  }

  static bool isErrorPointerHelper(const FunctionDecl *FD) {
    return isLinuxErrorPointerHelper(FD);
  }

  /// The condition that decides which way \p B branches.  A block that ends
  /// in "if (a && b)" evaluates only b: a was decided by an earlier block,
  /// and this one is reached with the outcome of a that leaves the result
  /// open.  The condition of "do ... while (a && b)" is different: the CFG
  /// computes its value like that of any other expression and the block
  /// that ends the loop branches on the whole of it.
  static const Expr *getBranchCondition(const CFGBlock *B) {
    const Expr *Cond = cast<Expr>(B->getTerminatorCondition());
    if (B->getLastCondition() == Cond->IgnoreParens())
      return Cond;
    for (;;) {
      const auto *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParens());
      if (!BO || !BO->isLogicalOp())
        return Cond;
      Cond = BO->getRHS();
    }
  }

  static bool isConditionalBranch(const CFGBlock *B) {
    const Stmt *Term = B->getTerminatorStmt();
    return Term && B->succ_size() == 2 && !isa<SwitchStmt>(Term) &&
           !isa<GCCAsmStmt>(Term) &&
           isa_and_nonnull<Expr>(B->getTerminatorCondition());
  }

  /// The pointer through which \p Node reads or writes memory, if it does.
  /// Taking the address of a member is not an access.
  static const Expr *accessedPointer(const Stmt *Node) {
    const Expr *LV = nullptr;
    if (const auto *ICE = dyn_cast<ImplicitCastExpr>(Node)) {
      if (ICE->getCastKind() != CK_LValueToRValue)
        return nullptr;
      LV = ICE->getSubExpr();
    } else if (const auto *BO = dyn_cast<BinaryOperator>(Node)) {
      if (!BO->isAssignmentOp())
        return nullptr;
      LV = BO->getLHS();
    } else if (const auto *UO = dyn_cast<UnaryOperator>(Node)) {
      if (!UO->isIncrementDecrementOp())
        return nullptr;
      LV = UO->getSubExpr();
    }
    while (LV) {
      LV = LV->IgnoreParens();
      if (const auto *ME = dyn_cast<MemberExpr>(LV)) {
        if (ME->isArrow())
          return ME->getBase();
        LV = ME->getBase();
      } else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(LV)) {
        const Expr *Base = ASE->getBase()->IgnoreParens();
        const auto *ICE = dyn_cast<ImplicitCastExpr>(Base);
        if (!ICE || ICE->getCastKind() != CK_ArrayToPointerDecay)
          return Base;
        LV = ICE->getSubExpr();
      } else if (const auto *UO = dyn_cast<UnaryOperator>(LV)) {
        if (UO->getOpcode() != UO_Deref)
          return nullptr;
        // "*(T *)&lvalue" is how READ_ONCE() reads the lvalue.
        const auto *Inner =
            dyn_cast<UnaryOperator>(UO->getSubExpr()->IgnoreParenCasts());
        if (!Inner || Inner->getOpcode() != UO_AddrOf)
          return UO->getSubExpr();
        LV = Inner->getSubExpr();
      } else {
        return nullptr;
      }
    }
    return nullptr;
  }

  /// The location that \p E names, or -1.
  int locate(const Expr *E, bool Create = true) {
    const VarDecl *Root = nullptr;
    llvm::SmallVector<const FieldDecl *, 3> Path;
    if (!E || !isTrackedType(E->getType()) || !decompose(E, Root, Path))
      return -1;
    if (Path.empty() && AddressTaken.count(Root))
      return -1;
    if (int Loc = find(Root, Path); Loc >= 0)
      return Loc;
    if (!Create || Locations.size() >= MaxLocations)
      return -1;
    Location L;
    L.Root = Root;
    L.Path = std::move(Path);
    Locations.push_back(std::move(L));
    return Locations.size() - 1;
  }

  /// "dev->priv" for the location \p Loc.
  std::string text(unsigned Loc) const {
    const Location &L = Locations[Loc];
    std::string Text = L.Root->getNameAsString();
    QualType T = L.Root->getType();
    for (const FieldDecl *FD : L.Path) {
      if (!FD->isAnonymousStructOrUnion()) {
        Text += T->isPointerType() ? "->" : ".";
        Text += FD->getName();
      }
      T = FD->getType();
    }
    return Text;
  }

  /// The location of the variable \p VD, or -1.
  int locate(const VarDecl *VD) {
    if (!VD->hasLocalStorage() || !isTrackedType(VD->getType()) ||
        AddressTaken.count(VD))
      return -1;
    if (int Loc = find(VD, {}); Loc >= 0)
      return Loc;
    if (Locations.size() >= MaxLocations)
      return -1;
    Location L;
    L.Root = VD;
    Locations.push_back(std::move(L));
    return Locations.size() - 1;
  }

  const VarDecl *root(unsigned Loc) const { return Locations[Loc].Root; }
  bool isVariable(unsigned Loc) const { return Locations[Loc].Path.empty(); }

  /// Keep the value of \p Loc on every path, whether or not a branch
  /// condition reads it.
  void pin(unsigned Loc) { Locations[Loc].Pinned = true; }

  static Value get(const State &St, unsigned Loc) {
    for (const auto &[L, V] : St.Vals)
      if (L == Loc)
        return V;
    return Value();
  }

  static void set(State &St, unsigned Loc, Value V) {
    auto It = llvm::lower_bound(
        St.Vals, Loc, [](const std::pair<unsigned, Value> &P, unsigned L) {
          return P.first < L;
        });
    bool Found = It != St.Vals.end() && It->first == Loc;
    if (V.isAny()) {
      if (Found)
        St.Vals.erase(It);
    } else if (Found) {
      It->second = V;
    } else {
      St.Vals.insert(It, {Loc, V});
    }
  }

  /// The location \p Loc gets a new value.
  void store(unsigned Loc, Value V, State &St) const {
    invalidate(Locations[Loc].Root, Locations[Loc].Path, St);
    set(St, Loc, keeps(Loc) ? V : Value());
  }

  /// What the path knows about the value of \p E.
  Value value(const Expr *E, const State &St) {
    if (!E)
      return Value();
    E = E->IgnoreParens();
    QualType T = E->getType();
    if (!T->isIntegralOrEnumerationType() && !T->isPointerType())
      return Value();

    if (int Loc = locate(E, /*Create=*/false); Loc >= 0) {
      Value V = get(St, Loc);
      if (!T->isPointerType() && T->isUnsignedIntegerOrEnumerationType() &&
          (V.Mask & ~Value::Neg))
        V.Mask &= ~Value::Neg;
      return V;
    }

    if (const auto *CE = dyn_cast<CastExpr>(E)) {
      const Expr *Sub = CE->getSubExpr();
      switch (CE->getCastKind()) {
      case CK_LValueToRValue:
      case CK_NoOp:
      case CK_BitCast:
      case CK_IntegralToPointer:
      case CK_PointerToIntegral:
        return value(Sub, St);
      case CK_NullToPointer:
        return Value::constant(0);
      case CK_ArrayToPointerDecay:
      case CK_FunctionToPointerDecay:
        return Value::ofMask(Value::Pos);
      case CK_IntegralToBoolean:
      case CK_PointerToBoolean: {
        std::optional<bool> B = value(Sub, St).truth();
        return B ? Value::constant(*B) : Value::ofMask(Value::Zero | Value::Pos);
      }
      case CK_IntegralCast: {
        Value V = value(Sub, St);
        unsigned From = Ctx.getIntWidth(Sub->getType());
        unsigned To = Ctx.getIntWidth(T);
        bool Unsigned = T->isUnsignedIntegerOrEnumerationType();
        if (V.HasConst) {
          llvm::APSInt K(llvm::APInt(64, uint64_t(V.Const), /*isSigned=*/true),
                         /*isUnsigned=*/false);
          K = K.extOrTrunc(To);
          K.setIsUnsigned(Unsigned);
          if (std::optional<int64_t> Fits = K.tryExtValue())
            return Value::constant(*Fits);
          return Value::ofMask(Value::Pos);
        }
        if (To < From)
          return Value();
        if (Unsigned && (V.Mask & Value::Neg))
          V.Mask = (V.Mask & ~Value::Neg) | Value::Pos;
        return Value::ofMask(V.Mask);
      }
      default:
        return Value();
      }
    }

    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      switch (UO->getOpcode()) {
      case UO_LNot: {
        std::optional<bool> B = truth(UO->getSubExpr(), St);
        return B ? Value::constant(!*B) : Value::ofMask(Value::Zero | Value::Pos);
      }
      case UO_Plus:
        return value(UO->getSubExpr(), St);
      case UO_Minus: {
        Value V = value(UO->getSubExpr(), St);
        if (V.HasConst)
          return Value::constant(-V.Const);
        uint8_t M = V.Mask & Value::Zero;
        if (V.Mask & Value::Neg)
          M |= Value::Pos;
        if (V.Mask & Value::Pos)
          M |= Value::Neg;
        return Value::ofMask(M);
      }
      case UO_AddrOf:
        return Value::ofMask(Value::Pos);
      default:
        return Value();
      }
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_Comma || BO->getOpcode() == BO_Assign)
        return value(BO->getRHS(), St);
      if (BO->isLogicalOp()) {
        bool IsAnd = BO->getOpcode() == BO_LAnd;
        std::optional<bool> L = truth(BO->getLHS(), St);
        std::optional<bool> R = truth(BO->getRHS(), St);
        if ((L && *L != IsAnd) || (R && *R != IsAnd))
          return Value::constant(!IsAnd);
        if (L && R)
          return Value::constant(IsAnd);
        return Value::ofMask(Value::Zero | Value::Pos);
      }
      if (BO->isComparisonOp()) {
        std::optional<bool> B = compare(BO, St);
        return B ? Value::constant(*B) : Value::ofMask(Value::Zero | Value::Pos);
      }
      return Value();
    }

    if (const auto *CO = dyn_cast<AbstractConditionalOperator>(E)) {
      std::optional<bool> B = truth(CO->getCond(), St);
      if (B)
        return value(*B ? CO->getTrueExpr() : CO->getFalseExpr(), St);
      if (isa<BinaryConditionalOperator>(CO))
        return Value::join(Value::ofMask(Value::Neg | Value::Pos),
                           value(CO->getFalseExpr(), St));
      return Value::join(value(CO->getTrueExpr(), St),
                         value(CO->getFalseExpr(), St));
    }

    if (const auto *SE = dyn_cast<StmtExpr>(E)) {
      const CompoundStmt *CS = SE->getSubStmt();
      return CS->body_empty() ? Value()
                              : value(dyn_cast<Expr>(CS->body_back()), St);
    }
    if (const auto *GSE = dyn_cast<GenericSelectionExpr>(E))
      return GSE->isResultDependent() ? Value()
                                      : value(GSE->getResultExpr(), St);
    if (const auto *CE = dyn_cast<ChooseExpr>(E))
      return CE->isConditionDependent() ? Value()
                                        : value(CE->getChosenSubExpr(), St);

    if (const auto *CE = dyn_cast<CallExpr>(E)) {
      unsigned ID = CE->getBuiltinCallee();
      if ((ID == Builtin::BI__builtin_expect ||
           ID == Builtin::BI__builtin_expect_with_probability) &&
          CE->getNumArgs() >= 1)
        return value(CE->getArg(0), St);
      const FunctionDecl *FD = CE->getDirectCallee();
      if (!FD || !FD->getIdentifier() || CE->getNumArgs() != 1)
        return Value();
      StringRef Name = FD->getName();
      if (!isErrorPointerHelper(FD))
        return Value();
      Value V = value(CE->getArg(0), St);
      if (Name == "IS_ERR") {
        if (!(V.Mask & Value::Neg))
          return Value::constant(0);
        return V.Mask == Value::Neg ? Value::constant(1)
                                    : Value::ofMask(Value::Zero | Value::Pos);
      }
      if (Name == "IS_ERR_OR_NULL") {
        if (V.Mask == Value::Pos)
          return Value::constant(0);
        return !(V.Mask & Value::Pos) ? Value::constant(1)
                                      : Value::ofMask(Value::Zero | Value::Pos);
      }
      if (Name == "PTR_ERR_OR_ZERO") {
        uint8_t M = V.Mask & Value::Neg;
        if (V.Mask & (Value::Zero | Value::Pos))
          M |= Value::Zero;
        return Value::ofMask(M);
      }
      // ERR_PTR(), PTR_ERR() and ERR_CAST() keep the sign.
      return V.HasConst ? Value::constant(V.Const) : Value::ofMask(V.Mask);
    }

    if (isa<IntegerLiteral, CharacterLiteral, UnaryExprOrTypeTraitExpr>(E) ||
        (isa<DeclRefExpr>(E) &&
         isa<EnumConstantDecl>(cast<DeclRefExpr>(E)->getDecl()))) {
      Expr::EvalResult R;
      if (!E->isValueDependent() && E->EvaluateAsInt(R, Ctx)) {
        if (std::optional<int64_t> Fits = R.Val.getInt().tryExtValue())
          return Value::constant(*Fits);
        return Value::ofMask(Value::Pos);
      }
      return Value();
    }
    if (isa<StringLiteral>(E))
      return Value::ofMask(Value::Pos);
    return Value();
  }

  /// The outcome of the comparison \p BO, if the path decides it.
  std::optional<bool> compare(const BinaryOperator *BO, const State &St) {
    Value L = value(BO->getLHS(), St);
    Value R = value(BO->getRHS(), St);
    BinaryOperatorKind Op = BO->getOpcode();
    if (L.HasConst && R.HasConst) {
      switch (Op) {
      case BO_LT: return L.Const < R.Const;
      case BO_GT: return L.Const > R.Const;
      case BO_LE: return L.Const <= R.Const;
      case BO_GE: return L.Const >= R.Const;
      case BO_EQ: return L.Const == R.Const;
      case BO_NE: return L.Const != R.Const;
      default: return std::nullopt;
      }
    }
    // One side is a number: bring it to the right.
    if (L.HasConst) {
      std::swap(L, R);
      switch (Op) {
      case BO_LT: Op = BO_GT; break;
      case BO_GT: Op = BO_LT; break;
      case BO_LE: Op = BO_GE; break;
      case BO_GE: Op = BO_LE; break;
      default: break;
      }
    }
    if (!R.HasConst)
      return std::nullopt;
    uint8_t M = L.Mask;
    uint8_t Sign = R.Const < 0 ? Value::Neg
                   : R.Const == 0 ? Value::Zero : Value::Pos;
    // The values on each side of the number, and the number's own class.
    uint8_t Below = R.Const < 0 ? Value::Neg
                    : R.Const == 0 ? Value::Neg
                    : Value::Neg | Value::Zero | Value::Pos;
    uint8_t Above = R.Const > 0 ? Value::Pos
                    : R.Const == 0 ? Value::Pos
                    : Value::Neg | Value::Zero | Value::Pos;
    bool Exact = R.Const == 0;
    switch (Op) {
    case BO_EQ:
      if (!(M & Sign)) return false;
      if (Exact && M == Value::Zero) return true;
      return std::nullopt;
    case BO_NE:
      if (!(M & Sign)) return true;
      if (Exact && M == Value::Zero) return false;
      return std::nullopt;
    case BO_LT:
      if (!(M & Below)) return false;
      if (Exact && M == Value::Neg) return true;
      return std::nullopt;
    case BO_GE:
      if (!(M & Below)) return true;
      if (Exact && M == Value::Neg) return false;
      return std::nullopt;
    case BO_GT:
      if (!(M & Above)) return false;
      if (Exact && M == Value::Pos) return true;
      return std::nullopt;
    case BO_LE:
      if (!(M & Above)) return true;
      if (Exact && M == Value::Pos) return false;
      return std::nullopt;
    default:
      return std::nullopt;
    }
  }

  /// Whether \p Cond holds, if the path decides it.
  std::optional<bool> truth(const Expr *Cond, const State &St) {
    bool Negated = false;
    const Expr *E = stripLinuxCondition(Cond, Negated);
    if (!E)
      return std::nullopt;
    if (std::optional<bool> B = value(E, St).truth())
      return *B != Negated;
    if (St.Preds.empty() && St.Fixed.empty())
      return std::nullopt;
    int I = conditionIndex(E, /*Create=*/false);
    if (I < 0)
      return std::nullopt;
    for (const auto &[C, Holds] : St.Fixed)
      if (C == unsigned(I))
        return Holds != Negated;
    for (const auto &[C, Holds] : St.Preds)
      if (C == unsigned(I))
        return Holds != Negated;
    return std::nullopt;
  }

  /// Take the outcome \p Outcome of \p Cond for granted in \p St and in
  /// every state that comes from it.  This is for a condition that the code
  /// itself relies on not to change: "if (c) lock(); ... if (c) unlock();".
  void fix(const Expr *Cond, bool Outcome, State &St) {
    bool Negated = false;
    const Expr *E = stripLinuxCondition(Cond, Negated);
    if (!E || St.Fixed.size() >= 4)
      return;
    int I = conditionIndex(E, /*Create=*/true);
    if (I >= 0)
      St.Fixed.push_back({unsigned(I), Outcome != Negated});
  }

  /// Narrow \p Loc to the values in \p Mask, and with it the locations that
  /// hold the same value.  Returns false if no value is left.
  bool narrow(unsigned Loc, uint8_t Mask, State &St) const {
    Value V = get(St, Loc);
    uint8_t M = V.Mask & Mask;
    if (!M)
      return false;
    if (M != V.Mask && (Locations[Loc].Pinned || Locations[Loc].Sites >= 2))
      set(St, Loc, V.HasConst ? V : Value::ofMask(M));
    for (auto [A, B] : St.Same) {
      if (A != Loc && B != Loc)
        continue;
      unsigned Other = A == Loc ? B : A;
      Value OV = get(St, Other);
      uint8_t OM = OV.Mask & Mask;
      if (!OM)
        return false;
      if (OM != OV.Mask && keeps(Other))
        set(St, Other, OV.HasConst ? OV : Value::ofMask(OM));
    }
    return true;
  }

  /// The path takes the branch on which \p Cond is \p Outcome.  Returns
  /// false if what the path knows rules that out.
  bool assume(const Expr *Cond, bool Outcome, State &St) {
    bool Negated = false;
    const Expr *E = stripLinuxCondition(Cond, Negated);
    if (!E)
      return true;
    if (Negated)
      Outcome = !Outcome;
    if (std::optional<bool> Known = value(E, St).truth())
      return *Known == Outcome;

    if (int Loc = locate(E, /*Create=*/false); Loc >= 0)
      return narrow(Loc, Outcome ? uint8_t(Value::Neg | Value::Pos) : Value::Zero,
                    St);

    const Expr *Plain = E->IgnoreParenImpCasts();
    if (const auto *BO = dyn_cast<BinaryOperator>(Plain)) {
      if (BO->isLogicalOp()) {
        // "a && b" is true only if both are, "a || b" false only if both
        // are.  The other outcomes say too little.
        if ((BO->getOpcode() == BO_LAnd) == Outcome)
          return assume(BO->getLHS(), Outcome, St) &&
                 assume(BO->getRHS(), Outcome, St);
        return true;
      }
      if (BO->isComparisonOp()) {
        const Expr *Side = BO->getLHS();
        const Expr *Other = BO->getRHS();
        BinaryOperatorKind Op = BO->getOpcode();
        int Loc = locate(Side, /*Create=*/false);
        if (Loc < 0) {
          std::swap(Side, Other);
          Loc = locate(Side, /*Create=*/false);
          switch (Op) {
          case BO_LT: Op = BO_GT; break;
          case BO_GT: Op = BO_LT; break;
          case BO_LE: Op = BO_GE; break;
          case BO_GE: Op = BO_LE; break;
          default: break;
          }
        }
        Value K = Loc >= 0 ? value(Other, St) : Value();
        if (Loc >= 0 && K.HasConst) {
          // Turn the false outcome into the opposite comparison.
          if (!Outcome)
            switch (Op) {
            case BO_LT: Op = BO_GE; break;
            case BO_GE: Op = BO_LT; break;
            case BO_GT: Op = BO_LE; break;
            case BO_LE: Op = BO_GT; break;
            case BO_EQ: Op = BO_NE; break;
            case BO_NE: Op = BO_EQ; break;
            default: break;
            }
          const uint8_t N = Value::Neg, Z = Value::Zero, P = Value::Pos;
          uint8_t Mask = Value::Any;
          int64_t C = K.Const;
          switch (Op) {
          case BO_EQ:
            if (!narrow(Loc, C < 0 ? N : C == 0 ? Z : P, St))
              return false;
            if (Locations[Loc].Pinned || Locations[Loc].Sites >= 2)
              set(St, Loc, Value::constant(C));
            return true;
          case BO_NE: Mask = C == 0 ? uint8_t(N | P) : Value::Any; break;
          case BO_LT: Mask = C <= 0 ? N : Value::Any; break;
          case BO_LE: Mask = C < 0 ? N : C == 0 ? uint8_t(N | Z) : Value::Any; break;
          case BO_GT: Mask = C >= 0 ? P : Value::Any; break;
          case BO_GE: Mask = C > 0 ? P : C == 0 ? uint8_t(Z | P) : Value::Any; break;
          default: break;
          }
          if (Mask != Value::Any)
            return narrow(Loc, Mask, St);
        }
      }
    } else if (const auto *CE = dyn_cast<CallExpr>(Plain)) {
      const FunctionDecl *FD = CE->getDirectCallee();
      if (FD && FD->getIdentifier() && CE->getNumArgs() == 1) {
        int Loc = locate(CE->getArg(0)->IgnoreParenCasts(), /*Create=*/false);
        if (Loc >= 0 && FD->getName() == "IS_ERR")
          return narrow(Loc,
                        Outcome ? Value::Neg : uint8_t(Value::Zero | Value::Pos),
                        St);
        if (Loc >= 0 && FD->getName() == "IS_ERR_OR_NULL")
          return narrow(Loc,
                        Outcome ? uint8_t(Value::Neg | Value::Zero) : Value::Pos,
                        St);
      }
    }

    int I = conditionIndex(E, /*Create=*/false);
    if (I >= 0 && Conditions[I].Sites >= 2) {
      auto It = llvm::lower_bound(
          St.Preds, unsigned(I),
          [](const std::pair<unsigned, bool> &P, unsigned C) {
            return P.first < C;
          });
      if (It != St.Preds.end() && It->first == unsigned(I))
        It->second = Outcome;
      else
        St.Preds.insert(It, {unsigned(I), Outcome});
    }
    return true;
  }

  /// End the search: the check has what it was looking for.
  void stop() { Stopped = true; }

  /// The blocks from the start of the search to the one it is in.
  void getPath(llvm::SmallVectorImpl<const CFGBlock *> &Out) const {
    for (int Node = Current; Node >= 0; Node = Trail[Node].second)
      Out.push_back(Trail[Node].first);
    std::reverse(Out.begin(), Out.end());
  }

  /// Walk the paths that start at element \p First of \p Start in the state
  /// \p Init.  Returns false if the search ran out of budget, in which case
  /// it has not seen every path.
  bool run(const CFGBlock *Start, unsigned First, const State &Init,
           Client &C) {
    Stopped = GaveUp = false;
    Steps = 0;
    if (FunctionSteps > MaxFunctionSteps)
      return false;

    llvm::DenseMap<unsigned, llvm::SmallVector<State, 2>> Seen;
    llvm::SmallVector<Item, 16> Work;
    Trail.clear();
    Trail.push_back({Start, -1});
    Work.push_back({Start, Init, 0});
    bool AtStart = true;

    while (!Work.empty() && !Stopped) {
      Item Popped = Work.pop_back_val();
      const CFGBlock *B = Popped.Block;
      State St = std::move(Popped.St);
      Current = Popped.Node;
      unsigned Skip = AtStart ? First : 0;
      AtStart = false;
      if (++Steps > MaxSteps)
        break;

      bool Alive = true;
      unsigned Index = 0;
      for (const CFGElement &Elem : *B) {
        if (Index++ < Skip)
          continue;
        std::optional<CFGStmt> CS = Elem.getAs<CFGStmt>();
        if (!CS)
          continue;
        if (++Steps > MaxSteps || !C.statement(CS->getStmt(), St) || Stopped) {
          Alive = false;
          break;
        }
        transfer(CS->getStmt(), St);
      }
      if (!Alive)
        continue;

      const Stmt *Term = B->getTerminatorStmt();
      if (const auto *AS = dyn_cast_or_null<GCCAsmStmt>(Term))
        transfer(AS, St);

      if (isConditionalBranch(B)) {
        const Expr *Cond = getBranchCondition(B);
        std::optional<bool> Known = truth(Cond, St);
        unsigned SuccIndex = 0;
        for (const CFGBlock::AdjacentBlock &Succ : B->succs()) {
          bool Outcome = SuccIndex++ == 0;
          const CFGBlock *Next = Succ.getReachableBlock();
          if (!Next || (Known && *Known != Outcome))
            continue;
          State Refined = St;
          if (!Known && !assume(Cond, Outcome, Refined))
            continue;
          if (C.edge(B, Next, Refined))
            push(Next, Refined, Seen, Work);
        }
        continue;
      }

      const auto *SS = dyn_cast_or_null<SwitchStmt>(Term);
      int Switched = SS ? locate(SS->getCond(), /*Create=*/false) : -1;
      Value SwitchValue = SS ? value(SS->getCond(), St) : Value();
      for (const CFGBlock::AdjacentBlock &Succ : B->succs()) {
        const CFGBlock *Next = Succ.getReachableBlock();
        if (!Next)
          continue;
        State Refined = St;
        if (SS && SwitchValue.HasConst) {
          if (!switchSelects(SS, Next, SwitchValue.Const))
            continue;
        } else if (Switched >= 0) {
          // A single case label pins the value down.
          const auto *CS = dyn_cast_or_null<CaseStmt>(Next->getLabel());
          if (CS && !CS->getRHS() && !isa<SwitchCase>(CS->getSubStmt())) {
            llvm::APSInt K = CS->getLHS()->EvaluateKnownConstInt(Ctx);
            if (std::optional<int64_t> Fits = K.tryExtValue()) {
              int64_t V = *Fits;
              if (!narrow(Switched,
                          V < 0 ? Value::Neg : V == 0 ? Value::Zero : Value::Pos,
                          Refined))
                continue;
              if (keeps(Switched))
                set(Refined, Switched, Value::constant(V));
            }
          }
        }
        if (C.edge(B, Next, Refined))
          push(Next, Refined, Seen, Work);
      }
    }
    FunctionSteps += Steps;
    return Steps <= MaxSteps && !GaveUp;
  }
};

/// Whether the experimental check \p Name was asked for with
/// -flinux-kernel-experimental= and its warning group is on.  "all" stands
/// for every check, but not for a switch that changes how a check works
/// (\p IsCheck false).
static bool isLinuxExperimentEnabled(const Sema &S, StringRef Name,
                                     SourceLocation Loc, bool IsCheck = true) {
  const auto &Names = S.getLangOpts().LinuxKernelExperimentalChecks;
  if (!llvm::is_contained(Names, Name) &&
      !(IsCheck && llvm::is_contained(Names, "all")))
    return false;
  return !S.getDiagnostics().isIgnored(diag::warn_linux_kernel_experimental,
                                       Loc);
}

/// Where a function with a body reads or writes through its pointer
/// parameter \p Index whenever it is called: in the code that runs before
/// its first branch, directly or in a function that it hands the parameter
/// to.  Null if it does not, or if it tests the parameter anywhere: a
/// function that tests its argument is prepared for NULL.
static const Expr *getUnconditionalParameterDeref(
    const FunctionDecl *Callee, unsigned Index,
    sema::LinuxKernelUnit::Impl &Unit, unsigned Depth = 0) {
  const FunctionDecl *Def = nullptr;
  if (!Callee->hasBody(Def) || Index >= Def->getNumParams())
    return nullptr;
  const ParmVarDecl *Param = Def->getParamDecl(Index);
  if (!Param->getType()->isPointerType())
    return nullptr;
  auto Known = Unit.EntryDerefs.find(Param);
  if (Known != Unit.EntryDerefs.end())
    return Known->second;
  // Also the answer while this is being worked out, for recursion.
  Unit.EntryDerefs[Param] = nullptr;

  // Is the parameter tested, or given another value, anywhere?
  struct Scan {
    const VarDecl *P;
    bool Hit = false;
    bool is(const Expr *E) const {
      return E && getDirectLinuxVariable(E->IgnoreParenCasts()) == P;
    }
    void visit(const Stmt *St) {
      if (!St || Hit)
        return;
      if (const auto *UO = dyn_cast<UnaryOperator>(St)) {
        if (UO->getOpcode() == UO_LNot || UO->getOpcode() == UO_AddrOf ||
            UO->isIncrementDecrementOp())
          Hit |= is(UO->getSubExpr());
      } else if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
        if (BO->isAssignmentOp())
          Hit |= is(BO->getLHS());
        else if (BO->isComparisonOp() || BO->isLogicalOp())
          Hit |= is(BO->getLHS()) || is(BO->getRHS());
      } else if (const auto *IS = dyn_cast<IfStmt>(St)) {
        Hit |= is(IS->getCond());
      } else if (const auto *WS = dyn_cast<WhileStmt>(St)) {
        Hit |= is(WS->getCond());
      } else if (const auto *DS = dyn_cast<DoStmt>(St)) {
        Hit |= is(DS->getCond());
      } else if (const auto *FS = dyn_cast<ForStmt>(St)) {
        Hit |= is(FS->getCond());
      } else if (const auto *CO = dyn_cast<AbstractConditionalOperator>(St)) {
        Hit |= is(CO->getCond());
      } else if (const auto *CE = dyn_cast<CallExpr>(St)) {
        const FunctionDecl *F = CE->getDirectCallee();
        if (F && F->getIdentifier() &&
            (F->getName().contains("IS_ERR") ||
             F->getName().contains("PTR_ERR") || F->getName() == "ERR_CAST"))
          for (const Expr *Arg : CE->arguments())
            Hit |= is(Arg);
      } else if (isa<GCCAsmStmt>(St)) {
        Hit = true;
      }
      for (const Stmt *Child : St->children())
        visit(Child);
    }
  } Tested{Param};
  Tested.visit(Def->getBody());
  if (Tested.Hit)
    return nullptr;

  AnalysisDeclContext AC(/*ADCMgr=*/nullptr, Def);
  AC.getCFGBuildOptions()
      .setAlwaysAdd(Stmt::BinaryOperatorClass)
      .setAlwaysAdd(Stmt::CompoundAssignOperatorClass)
      .setAlwaysAdd(Stmt::ImplicitCastExprClass)
      .setAlwaysAdd(Stmt::UnaryOperatorClass);
  const CFG *Cfg = AC.getCFG();
  if (!Cfg)
    return nullptr;

  const Expr *Result = nullptr;
  const CFGBlock *B = &Cfg->getEntry();
  for (unsigned Blocks = 0; B && !Result && Blocks < 16; ++Blocks) {
    for (const CFGElement &Elem : *B) {
      std::optional<CFGStmt> CS = Elem.getAs<CFGStmt>();
      if (!CS)
        continue;
      const Stmt *Node = CS->getStmt();
      if (const Expr *Pointer = LinuxPathSearch::accessedPointer(Node)) {
        if (getDirectLinuxVariable(Pointer->IgnoreParenCasts()) == Param) {
          Result = Pointer;
          break;
        }
      } else if (const auto *CE = dyn_cast<CallExpr>(Node)) {
        const FunctionDecl *Next = CE->getDirectCallee();
        if (!Next || Depth >= 2)
          continue;
        for (unsigned I = 0, E = CE->getNumArgs(); I != E && !Result; ++I)
          if (getDirectLinuxVariable(CE->getArg(I)->IgnoreParenCasts()) ==
                  Param &&
              getUnconditionalParameterDeref(Next, I, Unit, Depth + 1))
            Result = CE->getArg(I);
        if (Result)
          break;
      }
    }
    if (B->succ_size() != 1)
      break;
    B = B->succ_begin()->getReachableBlock();
  }
  Unit.EntryDerefs[Param] = Result;
  return Result;
}

/// Misuse of a value on a path where a test has just said what it is.
/// Three rules share the machinery:
///
///   if (!dev->priv)                        a pointer that was found to be
///           dev_warn(dev->parent, "...");  NULL is dereferenced
///   ...
///   dev->priv->count++;
///
///   if (IS_ERR(folio))                     PTR_ERR() of a pointer that was
///           goto rollback;                 found not to be an error pointer
///   if (cnt <= 0)
///           goto rollback;
///   ...
///   rollback:
///           return PTR_ERR(folio);
///
///   if (err)                               ERR_PTR() of an error code that
///           goto out;                      was found to be zero, in a
///   ...                                    function whose callers expect a
///   out:                                   valid pointer or an error pointer
///           return ERR_PTR(err);
///
/// For each such test that the author wrote, the checker walks the paths
/// that leave through that outcome (see LinuxPathSearch) and reports the
/// first place where one of them misuses the value.  For a pointer that is
/// NULL this includes handing it to a function that dereferences its
/// parameter before it does anything else.  A path ends when the value is
/// assigned, when a call may have changed the member that holds it, and at a
/// branch that it contradicts.
///
/// The test says what the author expects.  If the outcome cannot happen the
/// test is what is wrong, and the report is still worth a look.
class LinuxTestedValueChecker : LinuxPathSearch::Client {
  using Value = LinuxPathValue;

  Sema &S;
  const FunctionDecl *FD;
  const CFG &Cfg;
  ASTContext &Ctx;
  LinuxPathSearch &Search;
  sema::LinuxKernelUnit::Impl &Unit;

  enum Rule { DerefNull, DerefError, DerefNullOrError, PtrErrOfValid,
              ErrPtrOfZero };

  // Per search.
  Rule Active = DerefNull;
  unsigned Place = 0;
  /// The path is followed for as long as the value stays within this mask.
  uint8_t Within = Value::Zero;
  const Expr *Misuse = nullptr;
  const CallExpr *Call = nullptr;
  const Expr *CalleeAccess = nullptr;
  /// The second search starts at the entry of the function and has to come
  /// through the test before a misuse counts.
  bool FromEntry = false;
  const CFGBlock *TestBlock = nullptr;
  llvm::BitVector ReachesTest;
  enum : uint32_t { PastTest = 1 };
  llvm::SmallVector<const CFGBlock *, 16> FoundPath;

  llvm::SmallVector<std::pair<unsigned, unsigned>, 8> Reported;
  std::optional<bool> ReturnsValidPointer;

  bool isPlace(const Expr *E) {
    return E && Search.locate(E->IgnoreParenCasts(), /*Create=*/false) ==
                    int(Place);
  }

  bool found(const Expr *At) {
    Misuse = At;
    FoundPath.clear();
    Search.getPath(FoundPath);
    Search.stop();
    return false;
  }

  bool edge(const CFGBlock *From, const CFGBlock *To,
            LinuxPathSearch::State &St) override {
    if (!FromEntry)
      return true;
    // The outcome of the test that leaves the value within the mask is the
    // one to follow.
    if (From == TestBlock) {
      if (LinuxPathSearch::get(St, Place).Mask & ~Within)
        St.Client &= ~uint32_t(PastTest);
      else
        St.Client |= PastTest;
    }
    // A path that cannot come to the test any more is of no interest.
    return (St.Client & PastTest) || ReachesTest.test(To->getBlockID());
  }

  bool statement(const Stmt *Node, LinuxPathSearch::State &St) override {
    if (FromEntry && !(St.Client & PastTest))
      return true;
    // The path has given the location a new value, or a call may have.
    if (LinuxPathSearch::get(St, Place).Mask & ~Within) {
      if (!FromEntry)
        return false;
      St.Client &= ~uint32_t(PastTest);
      return true;
    }

    const auto *CE = dyn_cast<CallExpr>(Node);
    const FunctionDecl *Callee = CE ? CE->getDirectCallee() : nullptr;
    switch (Active) {
    case DerefNull:
    case DerefError:
    case DerefNullOrError:
      if (const Expr *Pointer = LinuxPathSearch::accessedPointer(Node)) {
        if (isPlace(Pointer))
          return found(Pointer);
      } else if (Callee) {
        for (unsigned I = 0, E = CE->getNumArgs(); I != E; ++I)
          if (isPlace(CE->getArg(I)))
            if (const Expr *Inner =
                    getUnconditionalParameterDeref(Callee, I, Unit)) {
              Call = CE;
              CalleeAccess = Inner;
              return found(CE->getArg(I));
            }
      }
      break;
    case PtrErrOfValid:
      if (Callee && Callee->getIdentifier() && CE->getNumArgs() == 1 &&
          (Callee->getName() == "PTR_ERR" || Callee->getName() == "ERR_CAST") &&
          isPlace(CE->getArg(0)))
        return found(CE);
      break;
    case ErrPtrOfZero:
      if (Callee && Callee->getIdentifier() && CE->getNumArgs() == 1 &&
          Callee->getName() == "ERR_PTR" && isPlace(CE->getArg(0)) &&
          !isWrittenInMacro(CE->getExprLoc(), S.getSourceManager()))
        return found(CE);
      break;
    }
    return true;
  }

  /// Whether the function returns the address of something on some path
  /// and a literal NULL on none: its callers then take what they get for a
  /// valid pointer unless IS_ERR() says otherwise.
  bool returnsValidPointer() {
    if (!ReturnsValidPointer) {
      bool Valid = false, Null = false;
      struct Returns {
        ASTContext &Ctx;
        bool &Valid, &Null;
        void visit(const Stmt *St) {
          if (!St)
            return;
          if (const auto *RS = dyn_cast<ReturnStmt>(St)) {
            const Expr *E = RS->getRetValue();
            if (!E)
              return;
            if (E->IgnoreParenCasts()->isNullPointerConstant(
                    Ctx, Expr::NPC_ValueDependentIsNotNull)) {
              Null = true;
              return;
            }
            const auto *CE = dyn_cast<CallExpr>(E->IgnoreParenCasts());
            const FunctionDecl *F = CE ? CE->getDirectCallee() : nullptr;
            if (!F || !F->getIdentifier() ||
                !LinuxPathSearch::isErrorPointerHelper(F))
              Valid = true;
            return;
          }
          for (const Stmt *Child : St->children())
            visit(Child);
        }
      } R{Ctx, Valid, Null};
      R.visit(FD->getBody());
      ReturnsValidPointer = Valid && !Null;
    }
    return *ReturnsValidPointer;
  }

  struct Test {
    const Expr *Tested = nullptr;
    Rule Kind = DerefNull;
    unsigned Succ = 0;
  };

  /// What the branch at the end of \p B tests, with the rules to apply to
  /// each of its outcomes.
  void getTests(const CFGBlock *B, const Expr *&Cond,
                llvm::SmallVectorImpl<Test> &Out) {
    if (!LinuxPathSearch::isConditionalBranch(B))
      return;
    Cond = LinuxPathSearch::getBranchCondition(B);
    bool Negated = false;
    const Expr *E = stripLinuxCondition(Cond, Negated);
    // A test inside a macro is not the author's statement about this
    // value: dev_err(), kfree() and many others test whatever they get.
    if (!E || isWrittenInMacro(E->getExprLoc(), S.getSourceManager()) ||
        isLinuxBranchWrittenInMacro(B, S.getSourceManager()) ||
        isLinuxAssertionMacroExpansion(Cond, S))
      return;

    // Successor 0 is taken when the whole condition is true.
    auto SuccFor = [&](bool Outcome) { return (Outcome != Negated) ? 0u : 1u; };
    const Expr *Plain = E->IgnoreParenImpCasts();
    if (const auto *BO = dyn_cast<BinaryOperator>(Plain)) {
      if (!BO->isEqualityOp())
        return;
      const Expr *Tested = nullptr;
      const Expr *Other = nullptr;
      if (Search.locate(BO->getLHS(), /*Create=*/false) >= 0 ||
          Search.locate(BO->getLHS()) >= 0) {
        Tested = BO->getLHS();
        Other = BO->getRHS();
      } else if (Search.locate(BO->getRHS()) >= 0) {
        Tested = BO->getRHS();
        Other = BO->getLHS();
      }
      if (!Tested)
        return;
      bool IsPointer = Tested->IgnoreParenImpCasts()->getType()->isPointerType();
      bool IsZero =
          IsPointer ? Other->isNullPointerConstant(
                          Ctx, Expr::NPC_ValueDependentIsNotNull) !=
                          Expr::NPCK_NotNull
                    : [&] {
                        std::optional<llvm::APSInt> K =
                            Other->isValueDependent()
                                ? std::nullopt
                                : Other->getIntegerConstantExpr(Ctx);
                        return K && K->isZero();
                      }();
      if (!IsZero)
        return;
      Out.push_back({Tested, IsPointer ? DerefNull : ErrPtrOfZero,
                     SuccFor(BO->getOpcode() == BO_EQ)});
    } else if (const auto *CE = dyn_cast<CallExpr>(Plain)) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (!Callee || !Callee->getIdentifier() || CE->getNumArgs() != 1)
        return;
      const Expr *Tested = CE->getArg(0)->IgnoreParenCasts();
      if (Callee->getName() == "IS_ERR") {
        Out.push_back({Tested, DerefError, SuccFor(true)});
        Out.push_back({Tested, PtrErrOfValid, SuccFor(false)});
      } else if (Callee->getName() == "IS_ERR_OR_NULL") {
        Out.push_back({Tested, DerefNullOrError, SuccFor(true)});
      }
    } else if (Plain->getType()->isPointerType()) {
      Out.push_back({E, DerefNull, SuccFor(false)});
    } else if (Plain->getType()->isIntegralOrEnumerationType()) {
      Out.push_back({E, ErrPtrOfZero, SuccFor(false)});
    }
  }

  bool enabled(Rule R, SourceLocation Loc) {
    const DiagnosticsEngine &Diags = S.getDiagnostics();
    switch (R) {
    case DerefNull:
    case DerefNullOrError:
      return !Diags.isIgnored(diag::warn_linux_kernel_deref_after_check, Loc);
    case DerefError:
      return isLinuxExperimentEnabled(S, "error-deref-after-check", Loc);
    case PtrErrOfValid:
      return !Diags.isIgnored(diag::warn_linux_kernel_ptr_err_valid, Loc);
    case ErrPtrOfZero:
      return !Diags.isIgnored(diag::warn_linux_kernel_err_ptr_zero, Loc) &&
             FD->getReturnType()->isPointerType() && returnsValidPointer();
    }
    return false;
  }

  void report(const Expr *Cond) {
    std::string Text = Search.text(Place);
    switch (Active) {
    case DerefError: {
      // No diagnostic of its own yet.
      std::string Message =
          "'" + Text +
          "' is dereferenced here on a path where the earlier test found it "
          "to be an error pointer";
      S.Diag(Misuse->getExprLoc(), diag::warn_linux_kernel_experimental)
          << Message << "error-deref-after-check" << Misuse->getSourceRange();
      S.Diag(Cond->getExprLoc(), diag::note_linux_kernel_experimental)
          << "the test is here" << Cond->getSourceRange();
      return;
    }
    case DerefNull:
    case DerefNullOrError:
      if (Call) {
        S.Diag(Misuse->getExprLoc(),
               diag::warn_linux_kernel_deref_after_check_call)
            << Text << Call->getDirectCallee() << Misuse->getSourceRange();
        S.Diag(CalleeAccess->getExprLoc(),
               diag::note_linux_kernel_dereferenced_here)
            << CalleeAccess << CalleeAccess->getSourceRange();
      } else {
        S.Diag(Misuse->getExprLoc(), diag::warn_linux_kernel_deref_after_check)
            << Text << Misuse->getSourceRange();
      }
      S.Diag(Cond->getExprLoc(), diag::note_linux_kernel_null_tested_here)
          << Text << Cond->getSourceRange();
      return;
    case PtrErrOfValid:
      S.Diag(Misuse->getExprLoc(), diag::warn_linux_kernel_ptr_err_valid)
          << Text << Misuse->getSourceRange();
      S.Diag(Cond->getExprLoc(), diag::note_linux_kernel_is_err_tested_here)
          << Cond->getSourceRange();
      return;
    case ErrPtrOfZero:
      S.Diag(Misuse->getExprLoc(), diag::warn_linux_kernel_err_ptr_zero)
          << Search.root(Place) << Misuse->getSourceRange();
      S.Diag(Cond->getExprLoc(), diag::note_linux_kernel_zero_known_here)
          << Search.root(Place) << Cond->getSourceRange();
      return;
    }
  }

  /// The blocks from which the test can be reached.
  void computeReachesTest() {
    ReachesTest.clear();
    ReachesTest.resize(Cfg.getNumBlockIDs());
    llvm::SmallVector<const CFGBlock *, 16> Work;
    ReachesTest.set(TestBlock->getBlockID());
    Work.push_back(TestBlock);
    while (!Work.empty()) {
      const CFGBlock *B = Work.pop_back_val();
      for (const CFGBlock::AdjacentBlock &Pred : B->preds()) {
        const CFGBlock *P = Pred.getReachableBlock();
        if (P && !ReachesTest.test(P->getBlockID())) {
          ReachesTest.set(P->getBlockID());
          Work.push_back(P);
        }
      }
    }
  }

  /// The branches that the path takes from the test to the misuse.
  void notePath() {
    unsigned From = 0;
    for (unsigned I = 0, E = FoundPath.size(); I != E; ++I)
      if (FoundPath[I] == TestBlock)
        From = I + 1;
    unsigned Notes = 0;
    for (unsigned I = From; I + 1 < FoundPath.size() && Notes < 16; ++I) {
      const CFGBlock *B = FoundPath[I];
      if (!LinuxPathSearch::isConditionalBranch(B))
        continue;
      const Expr *Cond = LinuxPathSearch::getBranchCondition(B);
      bool Outcome = B->succ_begin()->getReachableBlock() == FoundPath[I + 1];
      S.Diag(Cond->getExprLoc(), diag::note_linux_kernel_experimental)
          << (Outcome ? "the path takes the true branch here"
                      : "the path takes the false branch here")
          << Cond->getSourceRange();
      ++Notes;
    }
  }

public:
  LinuxTestedValueChecker(Sema &S, const FunctionDecl *FD, const CFG &Cfg,
                          LinuxPathSearch &Search,
                          sema::LinuxKernelUnit::Impl &Unit)
      : S(S), FD(FD), Cfg(Cfg), Ctx(S.getASTContext()), Search(Search),
        Unit(Unit) {}

  static bool wanted(const Sema &S, SourceLocation Loc) {
    const DiagnosticsEngine &Diags = S.getDiagnostics();
    return !Diags.isIgnored(diag::warn_linux_kernel_deref_after_check, Loc) ||
           !Diags.isIgnored(diag::warn_linux_kernel_ptr_err_valid, Loc) ||
           !Diags.isIgnored(diag::warn_linux_kernel_err_ptr_zero, Loc) ||
           isLinuxExperimentEnabled(S, "error-deref-after-check", Loc);
  }

  void run() {
    SourceLocation Loc = FD->getBeginLoc();
    for (const CFGBlock *B : Cfg) {
      const Expr *Cond = nullptr;
      llvm::SmallVector<Test, 2> Tests;
      getTests(B, Cond, Tests);
      for (const Test &T : Tests) {
        if (!enabled(T.Kind, Loc))
          continue;
        int Where = Search.locate(T.Tested);
        // ERR_PTR(0) is about error codes in local variables.
        if (Where < 0 || (T.Kind == ErrPtrOfZero && !Search.isVariable(Where)))
          continue;
        unsigned Group = T.Kind <= DerefNullOrError ? 0 : unsigned(T.Kind);
        if (llvm::is_contained(Reported, std::make_pair(unsigned(Where), Group)))
          continue;
        const CFGBlock *Next = (B->succ_begin() + T.Succ)->getReachableBlock();
        if (!Next)
          continue;

        Active = T.Kind;
        Place = Where;
        Misuse = CalleeAccess = nullptr;
        Call = nullptr;
        switch (T.Kind) {
        case DerefNull: Within = Value::Zero; break;
        case DerefError: Within = Value::Neg; break;
        case DerefNullOrError: Within = Value::Neg | Value::Zero; break;
        case PtrErrOfValid: Within = Value::Zero | Value::Pos; break;
        case ErrPtrOfZero: Within = Value::Zero; break;
        }
        Search.pin(Place);
        TestBlock = B;
        // First from the test on, which is cheap and rules most tests out.
        FromEntry = false;
        LinuxPathSearch::State Init;
        LinuxPathSearch::set(Init, Place, Value::ofMask(Within));
        Search.run(Next, 0, Init, *this);
        if (!Misuse)
          continue;
        // Then from the entry of the function, with what the code before
        // the test establishes: "n = 0" before "if (p) n = p->count;" makes
        // "for (i = 0; i < n; i++) p->item[i]" safe.
        if (!isLinuxExperimentEnabled(S, "unconfirmed-paths", Loc,
                                      /*IsCheck=*/false)) {
          Misuse = CalleeAccess = nullptr;
          Call = nullptr;
          FromEntry = true;
          computeReachesTest();
          Search.run(&Cfg.getEntry(), 0, LinuxPathSearch::State(), *this);
          if (!Misuse)
            continue;
        }
        Reported.push_back({Place, Group});
        report(Cond);
        if (isLinuxExperimentEnabled(S, "path-notes", Loc, /*IsCheck=*/false))
          notePath();
      }
    }
  }
};

/// How a pair of kernel functions acquires and releases a resource.
struct LinuxResourceKind {
  enum ResultKind : uint8_t {
    Status,  ///< returns 0, or a negative errno when nothing was acquired
    Pointer, ///< returns the resource, or NULL or an error pointer
    Always,  ///< cannot fail: a lock
  };
  ResultKind Result = Status;
  /// The argument of the acquiring call that names the resource.  -1 if the
  /// result does, -2 if nothing does ("rcu_read_lock()").
  int HandleArg = 0;
  /// "request_firmware(&fw, ...)": the argument is the address of the handle.
  bool HandleByAddress = false;
  /// The resource is memory that belongs to whoever holds the pointer: a
  /// function that is given the pointer may keep it or free it.
  bool Owned = false;
  /// The argument of the releasing call that names the resource.
  int ReleaseArg = 0;
  /// The functions that release, and one that releases by prefix.
  llvm::SmallVector<StringRef, 4> Releases;
  StringRef ReleasePrefix;

  bool isRelease(StringRef Name) const {
    return llvm::is_contained(Releases, Name) ||
           (!ReleasePrefix.empty() && Name.starts_with(ReleasePrefix));
  }
};

static bool getLinuxResourceKind(const FunctionDecl *Callee,
                                 LinuxResourceKind &K) {
  if (!Callee->getIdentifier())
    return false;
  StringRef Name = Callee->getName();
  using R = LinuxResourceKind;

  // The allocators, by the family that the table at the top has them in.
  switch (classifyLinuxKernelCallee(Callee)) {
  case LinuxKernelAPIKind::KmallocPointer:
    K = {R::Pointer, -1, false, true, 0,
         {"kfree", "kfree_sensitive", "kvfree"}, {}};
    return true;
  case LinuxKernelAPIKind::VmallocPointer:
    K = {R::Pointer, -1, false, true, 0, {"vfree", "kvfree"}, {}};
    return true;
  case LinuxKernelAPIKind::KvmallocPointer:
    K = {R::Pointer, -1, false, true, 0, {"kvfree", "kvfree_sensitive"}, {}};
    return true;
  default:
    break;
  }

  struct Entry {
    StringRef Acquire;
    R::ResultKind Result;
    int HandleArg;
    bool ByAddress;
    bool Owned;
    int ReleaseArg;
    StringRef Release[4];
  };
  static const Entry Table[] = {
      // Clocks, regulators, power.
      {"clk_prepare_enable", R::Status, 0, false, false, 0,
       {"clk_disable_unprepare"}},
      {"clk_enable", R::Status, 0, false, false, 0, {"clk_disable"}},
      {"clk_prepare", R::Status, 0, false, false, 0, {"clk_unprepare"}},
      {"clk_bulk_prepare_enable", R::Status, 1, false, false, 1,
       {"clk_bulk_disable_unprepare"}},
      {"regulator_enable", R::Status, 0, false, false, 0,
       {"regulator_disable"}},
      {"regulator_bulk_enable", R::Status, 1, false, false, 1,
       {"regulator_bulk_disable"}},
      {"phy_init", R::Status, 0, false, false, 0, {"phy_exit"}},
      {"phy_power_on", R::Status, 0, false, false, 0, {"phy_power_off"}},
      {"reset_control_deassert", R::Status, 0, false, false, 0,
       {"reset_control_assert"}},
      // Interrupts, PCI, firmware.
      {"request_irq", R::Status, 0, false, false, 0, {"free_irq"}},
      {"request_threaded_irq", R::Status, 0, false, false, 0, {"free_irq"}},
      {"pci_enable_device", R::Status, 0, false, false, 0,
       {"pci_disable_device"}},
      {"pci_enable_device_mem", R::Status, 0, false, false, 0,
       {"pci_disable_device"}},
      {"pci_request_regions", R::Status, 0, false, false, 0,
       {"pci_release_regions"}},
      {"request_firmware", R::Status, 0, true, false, 0, {"release_firmware"}},
      {"firmware_request_nowarn", R::Status, 0, true, false, 0,
       {"release_firmware"}},
      // Locks that can fail to be taken.
      {"mutex_lock_interruptible", R::Status, 0, false, false, 0,
       {"mutex_unlock"}},
      {"mutex_lock_interruptible_nested", R::Status, 0, false, false, 0,
       {"mutex_unlock"}},
      {"mutex_lock_killable", R::Status, 0, false, false, 0, {"mutex_unlock"}},
      {"mutex_lock_killable_nested", R::Status, 0, false, false, 0,
       {"mutex_unlock"}},
      {"down_interruptible", R::Status, 0, false, false, 0, {"up"}},
      {"down_killable", R::Status, 0, false, false, 0, {"up"}},
      {"down_read_interruptible", R::Status, 0, false, false, 0, {"up_read"}},
      {"down_read_killable", R::Status, 0, false, false, 0, {"up_read"}},
      {"down_write_killable", R::Status, 0, false, false, 0, {"up_write"}},
      // Locks.
      {"mutex_lock", R::Always, 0, false, false, 0, {"mutex_unlock"}},
      {"mutex_lock_nested", R::Always, 0, false, false, 0, {"mutex_unlock"}},
      {"spin_lock", R::Always, 0, false, false, 0, {"spin_unlock"}},
      {"spin_lock_bh", R::Always, 0, false, false, 0, {"spin_unlock_bh"}},
      {"spin_lock_irq", R::Always, 0, false, false, 0, {"spin_unlock_irq"}},
      {"_raw_spin_lock_irqsave", R::Always, 0, false, false, 0,
       {"spin_unlock_irqrestore", "_raw_spin_unlock_irqrestore"}},
      {"_raw_spin_lock", R::Always, 0, false, false, 0, {"_raw_spin_unlock"}},
      {"_raw_spin_lock_irq", R::Always, 0, false, false, 0,
       {"_raw_spin_unlock_irq"}},
      {"_raw_spin_lock_bh", R::Always, 0, false, false, 0,
       {"_raw_spin_unlock_bh"}},
      {"down", R::Always, 0, false, false, 0, {"up"}},
      {"down_read", R::Always, 0, false, false, 0, {"up_read"}},
      {"down_read_nested", R::Always, 0, false, false, 0, {"up_read"}},
      {"down_write", R::Always, 0, false, false, 0, {"up_write"}},
      {"down_write_nested", R::Always, 0, false, false, 0, {"up_write"}},
      // Mappings and handles that the result names.
      {"ioremap", R::Pointer, -1, false, false, 0, {"iounmap"}},
      {"ioremap_wc", R::Pointer, -1, false, false, 0, {"iounmap"}},
      {"ioremap_np", R::Pointer, -1, false, false, 0, {"iounmap"}},
      {"of_iomap", R::Pointer, -1, false, false, 0, {"iounmap"}},
      {"pci_ioremap_bar", R::Pointer, -1, false, false, 0, {"iounmap"}},
      {"pci_iomap", R::Pointer, -1, false, false, 1, {"pci_iounmap"}},
      {"clk_get", R::Pointer, -1, false, false, 0, {"clk_put"}},
      {"of_clk_get", R::Pointer, -1, false, false, 0, {"clk_put"}},
      {"of_clk_get_by_name", R::Pointer, -1, false, false, 0, {"clk_put"}},
      {"regulator_get", R::Pointer, -1, false, false, 0, {"regulator_put"}},
      {"alloc_workqueue", R::Pointer, -1, false, false, 0,
       {"destroy_workqueue"}},
      {"alloc_workqueue_noprof", R::Pointer, -1, false, false, 0,
       {"destroy_workqueue"}},
      {"crypto_alloc_shash", R::Pointer, -1, false, false, 0,
       {"crypto_free_shash"}},
      {"crypto_alloc_skcipher", R::Pointer, -1, false, false, 0,
       {"crypto_free_skcipher"}},
      {"crypto_alloc_aead", R::Pointer, -1, false, false, 0,
       {"crypto_free_aead"}},
      {"crypto_alloc_ahash", R::Pointer, -1, false, false, 0,
       {"crypto_free_ahash"}},
      {"dma_alloc_attrs", R::Pointer, -1, false, false, 2, {"dma_free_attrs"}},
      // Device tree nodes with a reference.
      {"of_find_node_by_name", R::Pointer, -1, false, false, 0,
       {"of_node_put"}},
      {"of_find_node_by_path", R::Pointer, -1, false, false, 0,
       {"of_node_put"}},
      {"of_find_compatible_node", R::Pointer, -1, false, false, 0,
       {"of_node_put"}},
      {"of_find_matching_node", R::Pointer, -1, false, false, 0,
       {"of_node_put"}},
      {"of_find_node_by_phandle", R::Pointer, -1, false, false, 0,
       {"of_node_put"}},
      {"of_parse_phandle", R::Pointer, -1, false, false, 0, {"of_node_put"}},
      {"of_get_child_by_name", R::Pointer, -1, false, false, 0,
       {"of_node_put"}},
      {"of_get_compatible_child", R::Pointer, -1, false, false, 0,
       {"of_node_put"}},
      {"of_get_parent", R::Pointer, -1, false, false, 0, {"of_node_put"}},
      // Objects that are handed on once they are registered.
      {"usb_alloc_urb", R::Pointer, -1, false, true, 0, {"usb_free_urb"}},
      {"alloc_netdev_mqs", R::Pointer, -1, false, true, 0, {"free_netdev"}},
      {"alloc_etherdev_mqs", R::Pointer, -1, false, true, 0, {"free_netdev"}},
      {"platform_device_alloc", R::Pointer, -1, false, true, 0,
       {"platform_device_put"}},
      {"input_allocate_device", R::Pointer, -1, false, true, 0,
       {"input_free_device"}},
  };
  for (const Entry &E : Table)
    if (E.Acquire == Name) {
      K.Result = E.Result;
      K.HandleArg = E.HandleArg;
      K.HandleByAddress = E.ByAddress;
      K.Owned = E.Owned;
      K.ReleaseArg = E.ReleaseArg;
      K.Releases.clear();
      for (StringRef Rel : E.Release)
        if (!Rel.empty())
          K.Releases.push_back(Rel);
      K.ReleasePrefix = {};
      return true;
    }
  if (Name == "pm_runtime_resume_and_get") {
    K = {R::Status, 0, false, false, 0, {}, "pm_runtime_put"};
    K.Releases.push_back("__pm_runtime_put_autosuspend");
    return true;
  }
  return false;
}

/// A function of the kernel that reads from or writes to the memory it is
/// given and does not keep the pointer.
static bool isLinuxNonCapturingCallee(const FunctionDecl *FD) {
  if (!FD->getIdentifier())
    return false;
  if (isLinuxReadOnlyCallee(FD))
    return true;
  StringRef Name = FD->getName();
  if (Name.starts_with("mem") || Name.starts_with("str") ||
      Name.starts_with("__builtin_mem") || Name.starts_with("__builtin_str") ||
      Name.ends_with("printf") || Name.starts_with("sysfs_emit") ||
      Name.starts_with("seq_") || Name.starts_with("kstrto") ||
      Name.contains("copy_from_user") || Name.contains("copy_to_user") ||
      Name.starts_with("regmap_") || Name.starts_with("i2c_smbus_") ||
      Name.starts_with("print_hex_dump") || Name.starts_with("crc"))
    return true;
  return llvm::StringSwitch<bool>(Name)
      .Cases({"i2c_master_send", "i2c_master_recv", "i2c_transfer",
              "i2c_transfer_buffer_flags"},
             true)
      .Cases({"spi_write", "spi_read", "spi_write_then_read",
              "spi_sync_transfer"},
             true)
      .Cases({"usb_control_msg", "usb_bulk_msg", "usb_interrupt_msg",
              "usb_control_msg_send", "usb_control_msg_recv"},
             true)
      .Cases({"kernel_read", "kernel_write", "sscanf", "hex2bin", "bin2hex",
              "get_random_bytes", "simple_read_from_buffer",
              "simple_write_to_buffer"},
             true)
      .Cases({"sg_init_one", "nla_put", "skb_put_data", "kmemdup", "kstrdup",
              "kmemdup_noprof", "kstrdup_noprof"},
             true)
      .Default(false);
}

/// Whether the function \p Def may keep, free or hand on the pointer that
/// its parameter \p Index is given, as opposed to only reading and writing
/// through it.
static bool mayCaptureParameter(const FunctionDecl *Def, unsigned Index,
                                sema::LinuxKernelUnit::Impl &Unit,
                                unsigned Depth = 0) {
  if (Index >= Def->getNumParams())
    return true;
  const ParmVarDecl *Param = Def->getParamDecl(Index);
  auto Known = Unit.Captures.find(Param);
  if (Known != Unit.Captures.end())
    return Known->second;
  Unit.Captures[Param] = true;

  // The uses that leave the pointer where it is: an access through it, a
  // test, and a call that does not keep it.  Any other use may.
  struct Scan {
    const ParmVarDecl *P;
    sema::LinuxKernelUnit::Impl &Unit;
    unsigned Depth;
    llvm::SmallPtrSet<const Expr *, 16> Benign;
    bool Captured = false;

    const Expr *use(const Expr *E) const {
      E = E ? E->IgnoreParenCasts() : nullptr;
      const auto *DRE = dyn_cast_or_null<DeclRefExpr>(E);
      return DRE && DRE->getDecl() == P ? DRE : nullptr;
    }
    void benign(const Expr *E) {
      if (const Expr *U = use(E))
        Benign.insert(U);
    }
    bool mentions(const Stmt *St) const {
      if (!St)
        return false;
      if (const auto *DRE = dyn_cast<DeclRefExpr>(St))
        if (DRE->getDecl() == P)
          return true;
      for (const Stmt *Child : St->children())
        if (mentions(Child))
          return true;
      return false;
    }
    /// "&p->member" or "p->array": the address of a part of the object.
    bool addressOfPart(const Expr *E) const {
      E = E ? E->IgnoreParenCasts() : nullptr;
      if (!E)
        return false;
      if (const auto *UO = dyn_cast<UnaryOperator>(E))
        return UO->getOpcode() == UO_AddrOf && mentions(UO->getSubExpr());
      return E->getType()->isArrayType() && mentions(E);
    }
    void collect(const Stmt *St) {
      if (!St)
        return;
      if (const auto *ME = dyn_cast<MemberExpr>(St)) {
        if (ME->isArrow())
          benign(ME->getBase());
      } else if (const auto *UO = dyn_cast<UnaryOperator>(St)) {
        if (UO->getOpcode() == UO_Deref || UO->getOpcode() == UO_LNot)
          benign(UO->getSubExpr());
      } else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(St)) {
        benign(ASE->getBase());
      } else if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
        if (BO->isComparisonOp() || BO->isLogicalOp()) {
          benign(BO->getLHS());
          benign(BO->getRHS());
        }
      } else if (const auto *IS = dyn_cast<IfStmt>(St)) {
        benign(IS->getCond());
      } else if (const auto *WS = dyn_cast<WhileStmt>(St)) {
        benign(WS->getCond());
      } else if (const auto *CO = dyn_cast<AbstractConditionalOperator>(St)) {
        benign(CO->getCond());
      } else if (const auto *CE = dyn_cast<CallExpr>(St)) {
        const FunctionDecl *Callee = CE->getDirectCallee();
        const FunctionDecl *CalleeDef = nullptr;
        for (unsigned I = 0, E = CE->getNumArgs(); I != E; ++I) {
          const Expr *Arg = CE->getArg(I);
          bool Keeps = !Callee ||
                       !(isLinuxNonCapturingCallee(Callee) ||
                         (Depth < 2 && Callee->hasBody(CalleeDef) &&
                          !mayCaptureParameter(CalleeDef, I, Unit, Depth + 1)));
          if (use(Arg)) {
            if (!Keeps)
              benign(Arg);
          } else if (Keeps && addressOfPart(Arg)) {
            // "&p->member" in the hands of a function that may keep it.
            Captured = true;
          }
        }
      }
      if (const auto *BO = dyn_cast<BinaryOperator>(St))
        if (BO->isAssignmentOp() && addressOfPart(BO->getRHS()))
          Captured = true;
      if (const auto *DS = dyn_cast<DeclStmt>(St))
        for (const Decl *D : DS->decls())
          if (const auto *VD = dyn_cast<VarDecl>(D))
            if (VD->getInit() && addressOfPart(VD->getInit()))
              Captured = true;
      for (const Stmt *Child : St->children())
        collect(Child);
    }
    void check(const Stmt *St) {
      if (!St || Captured)
        return;
      if (const auto *DRE = dyn_cast<DeclRefExpr>(St))
        if (DRE->getDecl() == P && !Benign.count(DRE))
          Captured = true;
      if (isa<UnaryExprOrTypeTraitExpr>(St))
        return;
      for (const Stmt *Child : St->children())
        check(Child);
    }
  } S{Param, Unit, Depth, {}};
  S.collect(Def->getBody());
  S.check(Def->getBody());
  return Unit.Captures[Param] = S.Captured;
}

/// A resource that an error path keeps although other paths of the function
/// release it:
///
///   ret = clk_prepare_enable(priv->clk);
///   if (ret)
///           return ret;
///   ret = setup(priv);
///   if (ret)
///           return ret;                 /* the clock stays enabled */
///   ...
///   err:
///           clk_disable_unprepare(priv->clk);
///           return ret;
///
/// and a local allocation that is neither freed nor handed on when the
/// function returns.
///
/// For each call that acquires something (getLinuxResourceKind()), the
/// checker walks the paths that start behind it (see LinuxPathSearch).  A
/// path ends where the acquisition turns out to have failed, where the
/// resource is released, and where something else may have taken it over: a
/// call of a function whose name says that it cleans up and that is given
/// the object, a devm action, and for memory any call that may keep the
/// pointer and any store of it.  A return that such a path reaches with an
/// error is reported.
///
/// For everything but a local allocation, the function has to release the
/// resource somewhere itself.  That is what tells a function that cleans up
/// after itself from one whose resource is released by a remove callback or
/// by devres.
class LinuxUnwindChecker : LinuxPathSearch::Client {
  using Value = LinuxPathValue;

  Sema &S;
  const FunctionDecl *FD;
  const CFG &Cfg;
  ASTContext &Ctx;
  LinuxPathSearch &Search;
  sema::LinuxKernelUnit::Impl &Unit;

  // Per acquisition.
  LinuxResourceKind Kind;
  const CallExpr *Acquire = nullptr;
  /// The expression that names the resource, or the variable that does.
  const Expr *Handle = nullptr;
  const VarDecl *HandleVar = nullptr;
  /// The variable at the bottom of the handle, and every variable in it.
  const VarDecl *Root = nullptr;
  llvm::SmallVector<const VarDecl *, 2> HandleVars;
  /// Where the search keeps the value of the handle and of the status.
  int HandleLoc = -1;
  int StatusLoc = -1;
  /// A local allocation: every return matters, not only those that report
  /// an error, and no other release in the function is needed.
  bool Local = false;
  const ReturnStmt *Found = nullptr;
  std::unique_ptr<CFGDomTree> DomTree;

  enum : uint32_t { StatusOpen = 1 };

  static void collectVars(const Stmt *St,
                          llvm::SmallVectorImpl<const VarDecl *> &Out) {
    if (!St)
      return;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(St))
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
        if (!llvm::is_contained(Out, VD))
          Out.push_back(VD);
    for (const Stmt *Child : St->children())
      collectVars(Child, Out);
  }

  static bool mentionsVar(const Stmt *St, const VarDecl *VD) {
    if (!St)
      return false;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(St))
      if (DRE->getDecl() == VD)
        return true;
    for (const Stmt *Child : St->children())
      if (mentionsVar(Child, VD))
        return true;
    return false;
  }

  bool isHandle(const Expr *E) const {
    if (!E)
      return false;
    E = E->IgnoreParenCasts();
    // "spin_lock_irqsave(lock, flags)" checks the type of its argument.
    if (const auto *CE = dyn_cast<CallExpr>(E)) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (Callee && Callee->getIdentifier() &&
          Callee->getName() == "spinlock_check" && CE->getNumArgs() == 1)
        E = CE->getArg(0)->IgnoreParenCasts();
    }
    if (HandleVar)
      return getDirectLinuxVariable(E) == HandleVar;
    return Handle && isSameLinuxExpr(Ctx, E, Handle);
  }

  bool isReleaseOf(const CallExpr *CE, const LinuxResourceKind &K) const {
    const FunctionDecl *Callee = CE->getDirectCallee();
    if (!Callee || !Callee->getIdentifier() ||
        !K.isRelease(Callee->getName()))
      return false;
    if (K.ReleaseArg < 0)
      return true;
    return CE->getNumArgs() > unsigned(K.ReleaseArg) &&
           isHandle(CE->getArg(K.ReleaseArg));
  }

  /// A call that releases the resource, behind the acquisition in the
  /// source.  A release before it belongs to "disable, change, enable
  /// again", where an error return after the acquisition leaves things as
  /// the function found them.
  const CallExpr *findRelease(const Stmt *St) const {
    if (!St)
      return nullptr;
    if (const auto *CE = dyn_cast<CallExpr>(St)) {
      const SourceManager &SM = S.getSourceManager();
      if (isReleaseOf(CE, Kind) &&
          SM.isBeforeInTranslationUnit(SM.getExpansionLoc(Acquire->getExprLoc()),
                                       SM.getExpansionLoc(CE->getExprLoc())))
        return CE;
    }
    for (const Stmt *Child : St->children())
      if (const CallExpr *CE = findRelease(Child))
        return CE;
    return nullptr;
  }

  /// Whether \p Def, or a function that it calls, releases a resource of
  /// this kind.
  bool releasesInside(const Stmt *St, unsigned Depth) const {
    if (!St)
      return false;
    if (const auto *CE = dyn_cast<CallExpr>(St)) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      const FunctionDecl *Def = nullptr;
      if (Callee && Callee->getIdentifier()) {
        if (Kind.isRelease(Callee->getName()))
          return true;
        if (Depth < 2 && Callee->hasBody(Def) &&
            releasesInside(Def->getBody(), Depth + 1))
          return true;
      }
    }
    for (const Stmt *Child : St->children())
      if (releasesInside(Child, Depth))
        return true;
    return false;
  }

  static bool hasCleanupName(StringRef Name) {
    std::string Lower = Name.lower();
    for (StringRef Word :
         {"free", "release", "put", "destroy", "unregister", "remove",
          "disable", "unprepare", "close", "exit", "cleanup", "clean_up",
          "kill", "unmap", "stop", "shutdown", "fini", "teardown", "uninit",
          "deinit", "unlock", "unref", "cancel", "abort", "drop", "delete",
          "undo", "unwind", "detach", "power_off", "poweroff", "suspend"})
      if (StringRef(Lower).contains(Word))
        return true;
    return false;
  }

  /// Whether the argument \p Arg hands the pointer in \p HandleVar itself to
  /// the callee, as opposed to something that was read through it.
  bool passesPointer(const Expr *Arg) const {
    Arg = Arg->IgnoreParenCasts();
    if (getDirectLinuxVariable(Arg) == HandleVar)
      return true;
    // "p + off", "&p->member" and "p->array" are still the object.
    if (const auto *BO = dyn_cast<BinaryOperator>(Arg))
      return BO->isAdditiveOp() && mentionsVar(BO, HandleVar);
    if (const auto *UO = dyn_cast<UnaryOperator>(Arg))
      return UO->getOpcode() == UO_AddrOf && mentionsVar(UO, HandleVar);
    return Arg->getType()->isArrayType() && mentionsVar(Arg, HandleVar);
  }

  /// A call on the path.  Returns false if the resource is released by it,
  /// or may be taken over.
  bool call(const CallExpr *CE) {
    if (CE == Acquire)
      return true;
    if (isReleaseOf(CE, Kind))
      return false;
    const FunctionDecl *Callee = CE->getDirectCallee();
    StringRef Name =
        Callee && Callee->getIdentifier() ? Callee->getName() : StringRef();
    // Another resource of the same kind: none of our business.
    if (!Name.empty() && Kind.isRelease(Name))
      return true;

    bool GivenHandle = false, GivenRoot = false;
    for (const Expr *Arg : CE->arguments()) {
      GivenHandle |= isHandle(Arg);
      GivenRoot |= Root && mentionsVar(Arg, Root);
    }
    if (!GivenHandle && !GivenRoot)
      return true;
    // devres releases it from here on.
    if (Name.starts_with("devm_"))
      return false;

    if (Kind.Owned && HandleVar) {
      // Memory: whoever gets the pointer may keep it.
      const FunctionDecl *Def = nullptr;
      for (unsigned I = 0, E = CE->getNumArgs(); I != E; ++I) {
        if (!passesPointer(CE->getArg(I)))
          continue;
        if (!Callee)
          return false;
        if (isLinuxNonCapturingCallee(Callee))
          continue;
        if (!Callee->hasBody(Def) || mayCaptureParameter(Def, I, Unit))
          return false;
      }
      return true;
    }

    // Anything else: a function that cleans up, by its name or because its
    // body releases something of this kind.
    if (!Name.empty() && hasCleanupName(Name))
      return false;
    const FunctionDecl *Def = nullptr;
    if (Callee && Callee->hasBody(Def) && releasesInside(Def->getBody(), 0))
      return false;
    return true;
  }

  bool isErrorReturn(const ReturnStmt *RS, const LinuxPathSearch::State &St) {
    const Expr *E = RS->getRetValue();
    if (!E)
      return false;
    // "return PTR_ERR(p);" and "return dev_err_probe(...);" say it.
    if (const auto *CE = dyn_cast<CallExpr>(E->IgnoreParenCasts())) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (Callee && Callee->getIdentifier() &&
          llvm::StringSwitch<bool>(Callee->getName())
              .Cases({"PTR_ERR", "ERR_PTR", "ERR_CAST", "dev_err_probe"}, true)
              .Default(false))
        return true;
    }
    Value V = Search.value(E, St);
    if (FD->getReturnType()->isPointerType())
      return !(V.Mask & Value::Pos);
    if (!FD->getReturnType()->isSignedIntegerType() ||
        FD->getReturnType()->isBooleanType())
      return false;
    return !(V.Mask & Value::Zero);
  }

  bool statement(const Stmt *Node, LinuxPathSearch::State &St) override {
    // Has the acquisition failed on this path?
    if (HandleLoc >= 0) {
      Value V = LinuxPathSearch::get(St, HandleLoc);
      if (Kind.Result == LinuxResourceKind::Pointer && !(V.Mask & Value::Pos))
        return false;
    }
    if ((St.Client & StatusOpen) && StatusLoc >= 0) {
      Value V = LinuxPathSearch::get(St, StatusLoc);
      if (!(V.Mask & Value::Zero))
        return false;
      if (!(V.Mask & Value::Neg))
        St.Client &= ~uint32_t(StatusOpen);
    }

    if (const auto *CE = dyn_cast<CallExpr>(Node))
      return call(CE);

    const Expr *Target = nullptr, *Source = nullptr;
    if (const auto *BO = dyn_cast<BinaryOperator>(Node)) {
      if (!BO->isAssignmentOp())
        return true;
      Target = BO->getLHS();
      Source = BO->getRHS();
      // The status of the acquisition goes into a variable.
      if (Source->IgnoreParenCasts() == Acquire) {
        if (Kind.Result == LinuxResourceKind::Status && StatusLoc >= 0)
          St.Client |= StatusOpen;
        return true;
      }
      if (StatusLoc >= 0 &&
          Search.locate(Target, /*Create=*/false) == StatusLoc)
        St.Client &= ~uint32_t(StatusOpen);
    } else if (const auto *UO = dyn_cast<UnaryOperator>(Node)) {
      if (!UO->isIncrementDecrementOp())
        return true;
      Target = UO->getSubExpr();
    } else if (const auto *DS = dyn_cast<DeclStmt>(Node)) {
      for (const Decl *D : DS->decls())
        if (const auto *VD = dyn_cast<VarDecl>(D); VD && VD->getInit()) {
          if (VD->getInit()->IgnoreParenCasts() == Acquire) {
            if (Kind.Result == LinuxResourceKind::Status && StatusLoc >= 0)
              St.Client |= StatusOpen;
            continue;
          }
          // A copy of the pointer: it has another name now.
          if (Kind.Owned && HandleVar && mentionsVar(VD->getInit(), HandleVar))
            return false;
        }
      return true;
    } else if (const auto *RS = dyn_cast<ReturnStmt>(Node)) {
      const Expr *E = RS->getRetValue();
      // The caller gets it.
      if (E && (isHandle(E) ||
                (Kind.Owned && HandleVar && mentionsVar(E, HandleVar))))
        return false;
      if (Local || isErrorReturn(RS, St)) {
        Found = RS;
        Search.stop();
      }
      return false;
    } else if (isa<GCCAsmStmt>(Node)) {
      return false;
    }
    if (!Target)
      return true;

    // The handle, or something it is named by, gets another value: what the
    // path holds has no name any more.
    if (isHandle(Target))
      return false;
    const VarDecl *Assigned = getDirectLinuxVariable(Target);
    if (Assigned && llvm::is_contained(HandleVars, Assigned))
      return false;
    // The pointer is stored somewhere else.
    if (Source && Kind.Owned && HandleVar && mentionsVar(Source, HandleVar))
      return false;
    if (Source && !HandleVar && Handle &&
        isSameLinuxExpr(Ctx, Source->IgnoreParenCasts(), Handle))
      return false;
    return true;
  }

  /// A branch on the call itself: "if (clk_prepare_enable(clk)) return ...".
  bool edge(const CFGBlock *From, const CFGBlock *To,
            LinuxPathSearch::State &St) override {
    if (Kind.Result != LinuxResourceKind::Status ||
        !LinuxPathSearch::isConditionalBranch(From))
      return true;
    bool Negated = false;
    const Expr *E =
        stripLinuxCondition(LinuxPathSearch::getBranchCondition(From), Negated);
    if (!E)
      return true;
    E = E->IgnoreParenImpCasts();
    // Whether the condition as written is true when the call failed.
    bool TrueIsFailure = true;
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getLHS()->IgnoreParenImpCasts() != Acquire)
        return true;
      switch (BO->getOpcode()) {
      case BO_LT:
      case BO_NE:
        break;
      case BO_EQ:
      case BO_GE:
        TrueIsFailure = false;
        break;
      default:
        return true;
      }
    } else if (E != Acquire) {
      return true;
    }
    bool TakenWhenTrue = From->succ_begin()->getReachableBlock() == To;
    return (TakenWhenTrue != Negated) != TrueIsFailure;
  }

  static bool isLockRelease(StringRef Name) {
    return Name.contains("unlock") || Name == "up" || Name == "up_read" ||
           Name == "up_write";
  }

  /// Whether the acquisition takes back what the function has released
  /// before: a release of the same resource in the block of the
  /// acquisition or in one that dominates it, with no other acquisition in
  /// between.  The function is then entered with the resource held, as one
  /// is that drops its caller's lock around a call that sleeps, and
  /// returning with it held is what its caller expects.
  bool retakesAfterRelease(const CFGBlock *AcquireBlock) {
    const FunctionDecl *AcquireCallee = Acquire->getDirectCallee();
    if (!DomTree)
      DomTree = std::make_unique<CFGDomTree>(const_cast<CFG *>(&Cfg));
    bool BeforeAcquire = false;
    const CFGBlock *B = AcquireBlock;
    for (unsigned Depth = 0; B && Depth < 64; ++Depth) {
      for (auto It = B->rbegin(), End = B->rend(); It != End; ++It) {
        std::optional<CFGStmt> CS = It->getAs<CFGStmt>();
        const auto *CE = CS ? dyn_cast<CallExpr>(CS->getStmt()) : nullptr;
        if (CE == Acquire) {
          BeforeAcquire = true;
          continue;
        }
        if (B == AcquireBlock && !BeforeAcquire)
          continue;
        const FunctionDecl *Callee = CE ? CE->getDirectCallee() : nullptr;
        if (!Callee || !Callee->getIdentifier())
          continue;
        if (isReleaseOf(CE, Kind))
          return true;
        // Any way of unlocking this lock: up_read() before down_write().
        if (Kind.Result != LinuxResourceKind::Pointer &&
            isLockRelease(Callee->getName()) && CE->getNumArgs() >= 1 &&
            isHandle(CE->getArg(0)))
          return true;
        if (Callee == AcquireCallee && Kind.HandleArg >= 0 &&
            CE->getNumArgs() > unsigned(Kind.HandleArg) &&
            isHandle(CE->getArg(Kind.HandleArg)))
          return false;
      }
      DomTreeNode *N = DomTree->getBase().getNode(const_cast<CFGBlock *>(B));
      DomTreeNode *IDom = N ? N->getIDom() : nullptr;
      B = IDom ? IDom->getBlock() : nullptr;
    }
    return false;
  }

  /// The conditions under which the acquisition happens: the branches that
  /// lead to its block and to nothing else.  "if (c) get(); ... if (c)
  /// put();" relies on c not changing, and so does the search.
  void fixGuards(const CFGBlock *B, LinuxPathSearch::State &St) {
    for (unsigned Depth = 0; Depth < 4 && B->pred_size() == 1; ++Depth) {
      const CFGBlock *Pred = B->pred_begin()->getReachableBlock();
      if (!Pred)
        break;
      if (LinuxPathSearch::isConditionalBranch(Pred)) {
        const CFGBlock *OnTrue = Pred->succ_begin()->getReachableBlock();
        const CFGBlock *OnFalse = (Pred->succ_begin() + 1)->getReachableBlock();
        if (OnTrue != OnFalse)
          Search.fix(LinuxPathSearch::getBranchCondition(Pred), OnTrue == B,
                     St);
      }
      B = Pred;
    }
  }

  /// Set up the handle of the acquisition \p CE in \p B.  Returns the index
  /// of the CFG element behind it, or 0 if there is nothing to follow.
  unsigned prepare(const CFGBlock *B, unsigned Index, const CallExpr *CE) {
    Acquire = CE;
    Handle = nullptr;
    HandleVar = Root = nullptr;
    HandleVars.clear();
    HandleLoc = StatusLoc = -1;
    Local = false;
    Found = nullptr;

    // What the result is stored in: the statements that follow in the
    // block.
    const Expr *ResultTarget = nullptr;
    const VarDecl *ResultVar = nullptr;
    unsigned Next = 0;
    for (const CFGElement &Elem : *B) {
      if (Next++ <= Index)
        continue;
      std::optional<CFGStmt> CS = Elem.getAs<CFGStmt>();
      if (!CS)
        continue;
      if (const auto *BO = dyn_cast<BinaryOperator>(CS->getStmt())) {
        if (BO->getOpcode() == BO_Assign &&
            BO->getRHS()->IgnoreParenCasts() == CE)
          ResultTarget = BO->getLHS()->IgnoreParens();
      } else if (const auto *DS = dyn_cast<DeclStmt>(CS->getStmt())) {
        for (const Decl *D : DS->decls())
          if (const auto *VD = dyn_cast<VarDecl>(D);
              VD && VD->getInit() && VD->getInit()->IgnoreParenCasts() == CE)
            ResultVar = VD;
      }
      if (ResultTarget || ResultVar)
        break;
    }

    if (Kind.HandleArg >= 0) {
      if (CE->getNumArgs() <= unsigned(Kind.HandleArg))
        return 0;
      const Expr *Arg = CE->getArg(Kind.HandleArg)->IgnoreParenCasts();
      if (const auto *Inner = dyn_cast<CallExpr>(Arg)) {
        const FunctionDecl *Callee = Inner->getDirectCallee();
        if (Callee && Callee->getIdentifier() &&
            Callee->getName() == "spinlock_check" && Inner->getNumArgs() == 1)
          Arg = Inner->getArg(0)->IgnoreParenCasts();
      }
      if (Kind.HandleByAddress) {
        const auto *UO = dyn_cast<UnaryOperator>(Arg);
        if (!UO || UO->getOpcode() != UO_AddrOf)
          return 0;
        Arg = UO->getSubExpr()->IgnoreParens();
      }
      Handle = Arg;
      if (Kind.Result == LinuxResourceKind::Status) {
        if (ResultTarget)
          StatusLoc = Search.locate(ResultTarget);
        else if (ResultVar)
          StatusLoc = Search.locate(ResultVar);
        if (StatusLoc >= 0)
          Search.pin(StatusLoc);
      }
    } else if (Kind.HandleArg == -1) {
      if (ResultVar) {
        HandleVar = ResultVar;
        HandleLoc = Search.locate(ResultVar);
      } else if (ResultTarget) {
        Handle = ResultTarget;
        HandleLoc = Search.locate(ResultTarget);
      } else {
        return 0;
      }
      if (HandleLoc >= 0)
        Search.pin(HandleLoc);
    }
    if (Handle) {
      // A variable, a chain of members, or the address of one.
      const Expr *Storage = Handle;
      if (const auto *UO = dyn_cast<UnaryOperator>(Storage);
          UO && UO->getOpcode() == UO_AddrOf)
        Storage = UO->getSubExpr();
      if (!isSimpleLinuxStorage(Storage))
        return 0;
      HandleVar = getDirectLinuxVariable(Handle);
      collectVars(Handle, HandleVars);
      Root = HandleVars.empty() ? nullptr : HandleVars.front();
    } else if (HandleVar) {
      HandleVars.push_back(HandleVar);
      Root = HandleVar;
    }
    // A local allocation is this function's alone.
    Local = Kind.Owned && HandleVar && HandleVar->hasLocalStorage() &&
            !isa<ParmVarDecl>(HandleVar) && !HandleVar->hasAttr<CleanupAttr>() &&
            Kind.Result == LinuxResourceKind::Pointer;
    return Index + 1;
  }

public:
  LinuxUnwindChecker(Sema &S, const FunctionDecl *FD, const CFG &Cfg,
                     LinuxPathSearch &Search,
                     sema::LinuxKernelUnit::Impl &Unit)
      : S(S), FD(FD), Cfg(Cfg), Ctx(S.getASTContext()), Search(Search),
        Unit(Unit) {}

  static bool wanted(const Sema &S, SourceLocation Loc) {
    const DiagnosticsEngine &Diags = S.getDiagnostics();
    return !Diags.isIgnored(diag::warn_linux_kernel_missing_unwind, Loc) ||
           !Diags.isIgnored(diag::warn_linux_kernel_memory_leak, Loc);
  }

  void run() {
    SourceLocation Loc = FD->getBeginLoc();
    const DiagnosticsEngine &Diags = S.getDiagnostics();
    bool WantUnwind =
        !Diags.isIgnored(diag::warn_linux_kernel_missing_unwind, Loc);
    bool WantLeak = !Diags.isIgnored(diag::warn_linux_kernel_memory_leak, Loc);
    unsigned Searches = 0;

    for (const CFGBlock *B : Cfg) {
      unsigned Index = 0;
      for (const CFGElement &Elem : *B) {
        unsigned This = Index++;
        std::optional<CFGStmt> CS = Elem.getAs<CFGStmt>();
        const auto *CE = CS ? dyn_cast<CallExpr>(CS->getStmt()) : nullptr;
        const FunctionDecl *Callee = CE ? CE->getDirectCallee() : nullptr;
        if (!Callee || !getLinuxResourceKind(Callee, Kind))
          continue;
        // A call that a macro makes is the macro's to pair up.
        if (isWrittenInMacro(CE->getExprLoc(), S.getSourceManager()))
          continue;
        unsigned First = prepare(B, This, CE);
        if (!First)
          continue;
        const CallExpr *Release = findRelease(FD->getBody());
        if (Local ? !WantLeak : (!WantUnwind || !Release))
          continue;
        if (!Local && retakesAfterRelease(B))
          continue;
        if (++Searches > 24)
          return;
        LinuxPathSearch::State Init;
        fixGuards(B, Init);
        Search.run(B, First, Init, *this);
        if (!Found)
          continue;
        std::string Text = HandleVar ? HandleVar->getNameAsString()
                           : Handle  ? getLinuxExprText(Handle, S)
                                     : std::string("the lock");
        if (Local) {
          S.Diag(Found->getBeginLoc(), diag::warn_linux_kernel_memory_leak)
              << HandleVar << Callee->getName() << Found->getSourceRange();
          S.Diag(CE->getExprLoc(), diag::note_linux_kernel_allocated_here)
              << CE->getSourceRange();
        } else {
          const FunctionDecl *Releaser = Release->getDirectCallee();
          S.Diag(Found->getBeginLoc(), diag::warn_linux_kernel_missing_unwind)
              << Text << Callee->getName() << Releaser->getName()
              << Found->getSourceRange();
          S.Diag(CE->getExprLoc(), diag::note_linux_kernel_acquired_here)
              << CE->getSourceRange();
          S.Diag(Release->getExprLoc(), diag::note_linux_kernel_released_here)
              << Release->getSourceRange();
        }
      }
    }
  }
};

/// Memory that is used after every path has freed it:
///
///   list_for_each_entry(item, &head, list) {
///           list_del(&item->list);
///           kfree(item);                  /* the loop reads item->list.next */
///   }
///
/// and memory that is freed a second time.  For each variable or member
/// chain that the function hands to kfree() or one of its relatives, the
/// checker follows one fact through the CFG: whether every path has freed
/// it since it was last assigned.  A dereference or another free in that
/// state is reported.
class UseAfterFreeChecker {
  Sema &S;
  const FunctionDecl *FD;
  const CFG &Cfg;
  ASTContext &Ctx;

  struct Place {
    const VarDecl *Root = nullptr;
    llvm::SmallVector<const FieldDecl *, 3> Path;
    /// The first call in the source that frees it, and its argument.
    const CallExpr *FirstFree = nullptr;
    const Expr *Freed = nullptr;
    bool Reported = false;
  };
  llvm::SmallVector<Place, 8> Places;
  llvm::SmallPtrSet<const VarDecl *, 8> AddressTaken;

  static bool decompose(const Expr *E, const VarDecl *&Root,
                        llvm::SmallVectorImpl<const FieldDecl *> &Path) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      Root = dyn_cast<VarDecl>(DRE->getDecl());
      return Root && Root->hasLocalStorage();
    }
    const auto *ME = dyn_cast<MemberExpr>(E);
    const auto *Field = ME ? dyn_cast<FieldDecl>(ME->getMemberDecl()) : nullptr;
    if (!Field || !decompose(ME->getBase(), Root, Path) || Path.size() >= 4)
      return false;
    Path.push_back(Field);
    return true;
  }

  int find(const Expr *E) const {
    const VarDecl *Root = nullptr;
    llvm::SmallVector<const FieldDecl *, 3> Path;
    if (!decompose(E, Root, Path))
      return -1;
    for (unsigned I = 0, N = Places.size(); I != N; ++I)
      if (Places[I].Root == Root && Places[I].Path == Path)
        return I;
    return -1;
  }

  /// The argument that \p CE frees, if it is a call of a function that
  /// frees memory at once.
  static const Expr *getFreed(const CallExpr *CE) {
    const FunctionDecl *Callee = CE->getDirectCallee();
    if (!Callee || !Callee->getIdentifier())
      return nullptr;
    int Arg = llvm::StringSwitch<int>(Callee->getName())
                  .Cases({"kfree", "kfree_sensitive", "kvfree",
                          "kvfree_sensitive", "vfree", "kfree_const"},
                         0)
                  .Cases({"kmem_cache_free", "devm_kfree"}, 1)
                  .Cases({"mempool_free", "free_netdev"}, 0)
                  .Cases({"kfree_skb", "consume_skb", "dev_kfree_skb",
                          "dev_kfree_skb_any", "dev_kfree_skb_irq",
                          "dev_consume_skb_any", "__kfree_skb",
                          "kfree_skb_reason"},
                         0)
                  .Default(-1);
    if (Arg < 0 || CE->getNumArgs() <= unsigned(Arg))
      return nullptr;
    return CE->getArg(Arg);
  }

  void collect(const Stmt *St) {
    if (!St)
      return;
    if (const auto *UO = dyn_cast<UnaryOperator>(St)) {
      if (UO->getOpcode() == UO_AddrOf)
        if (const VarDecl *VD = getDirectLinuxVariable(UO->getSubExpr()))
          AddressTaken.insert(VD);
    } else if (const auto *CE = dyn_cast<CallExpr>(St)) {
      if (const Expr *Freed = getFreed(CE)) {
        Place P;
        if (decompose(Freed, P.Root, P.Path) && find(Freed) < 0 &&
            Places.size() < 16 &&
            !isWrittenInMacro(CE->getExprLoc(), S.getSourceManager())) {
          P.FirstFree = CE;
          P.Freed = Freed;
          Places.push_back(std::move(P));
        }
      }
    }
    for (const Stmt *Child : St->children())
      collect(Child);
  }

  static bool mentions(const Stmt *St, const VarDecl *VD) {
    if (!St)
      return false;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(St))
      if (DRE->getDecl() == VD)
        return true;
    for (const Stmt *Child : St->children())
      if (mentions(Child, VD))
        return true;
    return false;
  }

  /// The object that \p Target names gets a new value: so does every place
  /// that goes through it.
  void assigned(const Expr *Target, llvm::SmallBitVector &St) const {
    const VarDecl *Root = nullptr;
    llvm::SmallVector<const FieldDecl *, 3> Path;
    bool Known = decompose(Target, Root, Path);
    const auto *ME = dyn_cast<MemberExpr>(Target->IgnoreParens());
    const auto *Field = ME ? dyn_cast<FieldDecl>(ME->getMemberDecl()) : nullptr;
    for (unsigned I = 0, N = Places.size(); I != N; ++I) {
      const Place &P = Places[I];
      if (Known && P.Root == Root && P.Path.size() >= Path.size() &&
          std::equal(Path.begin(), Path.end(), P.Path.begin()))
        St.reset(I);
      // The same member of another object may be the same memory.
      else if (Field && llvm::is_contained(P.Path, Field))
        St.reset(I);
    }
  }

  void runBlock(const CFGBlock *B, llvm::SmallBitVector &St, bool Report) {
    for (const CFGElement &Elem : *B) {
      std::optional<CFGStmt> CS = Elem.getAs<CFGStmt>();
      if (!CS)
        continue;
      const Stmt *Node = CS->getStmt();
      if (const Expr *Pointer = LinuxPathSearch::accessedPointer(Node)) {
        int I = find(Pointer);
        if (Report && I >= 0 && St.test(I) && !Places[I].Reported) {
          Places[I].Reported = true;
          S.Diag(Pointer->getExprLoc(), diag::warn_linux_kernel_use_after_free)
              << getLinuxExprText(Places[I].Freed, S)
              << Pointer->getSourceRange();
          S.Diag(Places[I].FirstFree->getExprLoc(),
                 diag::note_linux_kernel_freed_here)
              << Places[I].FirstFree->getSourceRange();
        }
      }
      if (const auto *DS = dyn_cast<DeclStmt>(Node)) {
        for (const Decl *D : DS->decls())
          for (unsigned I = 0, N = Places.size(); I != N; ++I)
            if (Places[I].Root == D)
              St.reset(I);
      } else if (const auto *BO = dyn_cast<BinaryOperator>(Node)) {
        if (BO->isAssignmentOp())
          assigned(BO->getLHS(), St);
      } else if (const auto *UO = dyn_cast<UnaryOperator>(Node)) {
        if (UO->isIncrementDecrementOp())
          assigned(UO->getSubExpr(), St);
      } else if (const auto *CE = dyn_cast<CallExpr>(Node)) {
        const Expr *Freed = getFreed(CE);
        int I = Freed ? find(Freed) : -1;
        if (I >= 0) {
          if (Report && St.test(I) && !Places[I].Reported &&
              CE != Places[I].FirstFree) {
            Places[I].Reported = true;
            S.Diag(CE->getExprLoc(), diag::warn_linux_kernel_double_free)
                << getLinuxExprText(Freed, S) << CE->getSourceRange();
            S.Diag(Places[I].FirstFree->getExprLoc(),
                   diag::note_linux_kernel_freed_here)
                << Places[I].FirstFree->getSourceRange();
          }
          St.set(I);
          continue;
        }
        // Another call may have put something new into a member.
        const FunctionDecl *Callee = CE->getDirectCallee();
        if (Callee && isLinuxReadOnlyCallee(Callee))
          continue;
        for (unsigned P = 0, N = Places.size(); P != N; ++P) {
          if (Places[P].Path.empty() || !St.test(P))
            continue;
          for (const Expr *Arg : CE->arguments())
            if (mentions(Arg, Places[P].Root)) {
              St.reset(P);
              break;
            }
        }
      } else if (isa<GCCAsmStmt>(Node)) {
        St.reset();
      }
    }
  }

public:
  UseAfterFreeChecker(Sema &S, const FunctionDecl *FD, const CFG &Cfg)
      : S(S), FD(FD), Cfg(Cfg), Ctx(S.getASTContext()) {}

  void run() {
    collect(FD->getBody());
    llvm::erase_if(Places, [&](const Place &P) {
      return P.Path.empty() && AddressTaken.count(P.Root);
    });
    if (Places.empty())
      return;

    // In[B]: the places that every path to B has freed.
    std::vector<llvm::SmallBitVector> In(Cfg.getNumBlockIDs());
    llvm::BitVector Reached(Cfg.getNumBlockIDs());
    In[Cfg.getEntry().getBlockID()].resize(Places.size());
    Reached.set(Cfg.getEntry().getBlockID());
    bool Changed = true;
    unsigned Rounds = 0;
    while (Changed && ++Rounds < 64) {
      Changed = false;
      for (const CFGBlock *B : Cfg) {
        if (!Reached.test(B->getBlockID()))
          continue;
        llvm::SmallBitVector Out = In[B->getBlockID()];
        runBlock(B, Out, /*Report=*/false);
        for (const CFGBlock::AdjacentBlock &Succ : B->succs()) {
          const CFGBlock *Next = Succ.getReachableBlock();
          if (!Next)
            continue;
          unsigned ID = Next->getBlockID();
          if (!Reached.test(ID)) {
            Reached.set(ID);
            In[ID] = Out;
            Changed = true;
          } else if ((In[ID] & Out) != In[ID]) {
            In[ID] &= Out;
            Changed = true;
          }
        }
      }
    }
    for (const CFGBlock *B : Cfg)
      if (Reached.test(B->getBlockID())) {
        llvm::SmallBitVector Out = In[B->getBlockID()];
        runBlock(B, Out, /*Report=*/true);
      }
  }
};

/// A test whose outcome an earlier test has decided:
///
///   err = step_one();
///   if (err)
///           goto out;
///   step_two();             /* "err =" is missing */
///   if (err)
///           goto out;
///
/// For each local integer or pointer that the function tests more than
/// once, the checker follows through the CFG which of "negative", "zero"
/// and "positive" the tests on every path have left possible, with the
/// variable unchanged since.  A test that this decides is reported.  Either
/// it is dead code or, more often, the assignment that was meant to come
/// between the two tests is missing or went to another variable.
///
/// Only tests that the author wrote count, not those inside macros.  A test
/// is not reported when the source has an assignment to the variable or a
/// preprocessor conditional between the two tests: the assignment may be in
/// code that this configuration does not compile.
class DuplicateCheckChecker {
  using Value = LinuxPathValue;

  Sema &S;
  const FunctionDecl *FD;
  const CFG &Cfg;
  ASTContext &Ctx;

  struct Fact {
    uint8_t Mask = Value::Any;
    /// The test that narrowed the mask last, and the statement that
    /// branches on it.
    const Expr *From = nullptr;
    const Stmt *FromBranch = nullptr;
  };
  using Facts = llvm::SmallVector<Fact, 8>;

  static bool contains(const Stmt *St, const Stmt *Inner) {
    if (!St)
      return false;
    if (St == Inner)
      return true;
    for (const Stmt *Child : St->children())
      if (contains(Child, Inner))
        return true;
    return false;
  }

  /// Whether the second test only spells out what the first one leaves:
  /// "if (c <= 0) ... else if (c > 0) ...", or a test of the same variable
  /// further on in one condition, as in "!p || (q && p && ...)".  Both are
  /// a matter of style.
  static bool spellsOutTheRest(const Stmt *FirstBranch, const CFGBlock *B,
                               const Expr *Cond) {
    if (!FirstBranch)
      return false;
    if (const auto *First = dyn_cast<IfStmt>(FirstBranch)) {
      const Stmt *Else = First->getElse();
      while (const auto *CS = dyn_cast_or_null<CompoundStmt>(Else))
        Else = CS->size() == 1 ? CS->body_front() : nullptr;
      return Else && Else == B->getTerminatorStmt();
    }
    return isa<Expr>(FirstBranch) && contains(FirstBranch, Cond);
  }

  llvm::SmallVector<const VarDecl *, 8> Vars;
  llvm::DenseMap<const VarDecl *, unsigned> Index;
  llvm::SmallPtrSet<const VarDecl *, 8> AddressTaken;
  llvm::DenseMap<const VarDecl *, llvm::SmallVector<SourceLocation, 4>>
      Assignments;

  static bool isCandidate(const VarDecl *VD) {
    if (!VD || !VD->hasLocalStorage())
      return false;
    QualType T = VD->getType();
    return !T.isVolatileQualified() &&
           (T->isPointerType() || T->isIntegralOrEnumerationType());
  }

  void collect(const Stmt *St) {
    if (!St)
      return;
    const VarDecl *Assigned = nullptr;
    if (const auto *UO = dyn_cast<UnaryOperator>(St)) {
      const VarDecl *VD = getDirectLinuxVariable(UO->getSubExpr());
      if (UO->getOpcode() == UO_AddrOf && VD)
        AddressTaken.insert(VD);
      else if (UO->isIncrementDecrementOp())
        Assigned = VD;
    } else if (const auto *BO = dyn_cast<BinaryOperator>(St)) {
      if (BO->isAssignmentOp())
        Assigned = getDirectLinuxVariable(BO->getLHS());
    } else if (const auto *AS = dyn_cast<GCCAsmStmt>(St)) {
      for (unsigned I = 0, E = AS->getNumOutputs(); I != E; ++I)
        if (const VarDecl *VD = getDirectLinuxVariable(AS->getOutputExpr(I)))
          AddressTaken.insert(VD);
    }
    if (Assigned)
      Assignments[Assigned].push_back(St->getBeginLoc());
    for (const Stmt *Child : St->children())
      collect(Child);
  }

  /// Whether the branch at the end of \p B tests a variable against zero,
  /// and which values each outcome leaves.
  const VarDecl *getTest(const CFGBlock *B, const Expr *Cond, uint8_t &OnTrue,
                         uint8_t &OnFalse) const {
    const uint8_t N = Value::Neg, Z = Value::Zero, P = Value::Pos;
    bool Negated = false;
    const Expr *E = stripLinuxCondition(Cond, Negated);
    if (!E || isWrittenInMacro(E->getExprLoc(), S.getSourceManager()) ||
        isLinuxBranchWrittenInMacro(B, S.getSourceManager()))
      return nullptr;
    const VarDecl *VD = nullptr;
    uint8_t T = Value::Any, F = Value::Any;
    const Expr *Plain = E->IgnoreParenImpCasts();
    if (const VarDecl *Direct = getDirectLinuxVariable(E)) {
      VD = Direct;
      T = N | P;
      F = Z;
    } else if (const auto *BO = dyn_cast<BinaryOperator>(Plain)) {
      if (!BO->isComparisonOp())
        return nullptr;
      const Expr *Other = BO->getRHS();
      BinaryOperatorKind Op = BO->getOpcode();
      VD = getDirectLinuxVariable(BO->getLHS());
      if (!VD) {
        VD = getDirectLinuxVariable(BO->getRHS());
        Other = BO->getLHS();
        switch (Op) {
        case BO_LT: Op = BO_GT; break;
        case BO_GT: Op = BO_LT; break;
        case BO_LE: Op = BO_GE; break;
        case BO_GE: Op = BO_LE; break;
        default: break;
        }
      }
      if (!VD)
        return nullptr;
      bool IsZero = false;
      if (VD->getType()->isPointerType()) {
        IsZero = Other->isNullPointerConstant(
                     Ctx, Expr::NPC_ValueDependentIsNotNull) !=
                 Expr::NPCK_NotNull;
      } else if (!Other->isValueDependent()) {
        std::optional<llvm::APSInt> K = Other->getIntegerConstantExpr(Ctx);
        IsZero = K && K->isZero();
      }
      if (!IsZero)
        return nullptr;
      switch (Op) {
      case BO_EQ: T = Z; F = N | P; break;
      case BO_NE: T = N | P; F = Z; break;
      case BO_LT: T = N; F = Z | P; break;
      case BO_GE: T = Z | P; F = N; break;
      case BO_GT: T = P; F = N | Z; break;
      case BO_LE: T = N | Z; F = P; break;
      default: return nullptr;
      }
      // The compiler has its own warning for "unsigned < 0".
      if (!VD->getType()->isPointerType() &&
          VD->getType()->isUnsignedIntegerOrEnumerationType() &&
          Op != BO_EQ && Op != BO_NE)
        return nullptr;
    } else if (const auto *CE = dyn_cast<CallExpr>(Plain)) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (!Callee || !Callee->getIdentifier() || CE->getNumArgs() != 1)
        return nullptr;
      VD = getDirectLinuxVariable(CE->getArg(0)->IgnoreParenCasts());
      if (Callee->getName() == "IS_ERR") {
        T = N;
        F = Z | P;
      } else if (Callee->getName() == "IS_ERR_OR_NULL") {
        T = N | Z;
        F = P;
      } else {
        return nullptr;
      }
    }
    if (!VD)
      return nullptr;
    if (Negated)
      std::swap(T, F);
    OnTrue = T;
    OnFalse = F;
    return VD;
  }

  static bool isConditionalBranch(const CFGBlock *B) {
    return LinuxPathSearch::isConditionalBranch(B);
  }

  void runBlock(const CFGBlock *B, Facts &St) const {
    auto Forget = [&](const VarDecl *VD) {
      if (auto It = Index.find(VD); It != Index.end())
        St[It->second] = Fact();
    };
    for (const CFGElement &Elem : *B) {
      std::optional<CFGStmt> CS = Elem.getAs<CFGStmt>();
      if (!CS)
        continue;
      const Stmt *Node = CS->getStmt();
      if (const auto *DS = dyn_cast<DeclStmt>(Node)) {
        for (const Decl *D : DS->decls())
          Forget(dyn_cast<VarDecl>(D));
      } else if (const auto *BO = dyn_cast<BinaryOperator>(Node)) {
        if (BO->isAssignmentOp())
          Forget(getDirectLinuxVariable(BO->getLHS()));
      } else if (const auto *UO = dyn_cast<UnaryOperator>(Node)) {
        if (UO->isIncrementDecrementOp())
          Forget(getDirectLinuxVariable(UO->getSubExpr()));
      }
    }
  }

  /// Whether the source has something between the two tests that can make
  /// the second one meaningful in another configuration.
  bool mayChangeBetween(const VarDecl *VD, const Expr *First,
                        const Expr *Second) const {
    const SourceManager &SM = S.getSourceManager();
    SourceLocation A = SM.getExpansionLoc(First->getExprLoc());
    SourceLocation B = SM.getExpansionLoc(Second->getExprLoc());
    if (!SM.isBeforeInTranslationUnit(A, B))
      return true; // a loop: the first test comes later in the source
    auto It = Assignments.find(VD);
    if (It != Assignments.end())
      for (SourceLocation Loc : It->second) {
        Loc = SM.getExpansionLoc(Loc);
        if (SM.isBeforeInTranslationUnit(A, Loc) &&
            SM.isBeforeInTranslationUnit(Loc, B))
          return true;
      }
    auto [FileA, OffA] = SM.getDecomposedLoc(A);
    auto [FileB, OffB] = SM.getDecomposedLoc(B);
    if (FileA != FileB)
      return true;
    bool Invalid = false;
    StringRef Text = SM.getBufferData(FileA, &Invalid);
    if (Invalid || OffB > Text.size())
      return true;
    Text = Text.substr(OffA, OffB - OffA);
    while (!Text.empty()) {
      StringRef Line;
      std::tie(Line, Text) = Text.split('\n');
      Line = Line.ltrim();
      if (Line.consume_front("#")) {
        Line = Line.ltrim();
        if (Line.starts_with("if") || Line.starts_with("el") ||
            Line.starts_with("endif"))
          return true;
      }
    }
    return false;
  }

public:
  DuplicateCheckChecker(Sema &S, const FunctionDecl *FD, const CFG &Cfg)
      : S(S), FD(FD), Cfg(Cfg), Ctx(S.getASTContext()) {}

  void run() {
    collect(FD->getBody());

    // The variables that are tested at least twice.
    llvm::DenseMap<const VarDecl *, unsigned> Tests;
    for (const CFGBlock *B : Cfg) {
      if (!isConditionalBranch(B))
        continue;
      uint8_t T, F;
      const VarDecl *VD =
          getTest(B, LinuxPathSearch::getBranchCondition(B), T, F);
      if (isCandidate(VD) && !AddressTaken.count(VD) && ++Tests[VD] == 2 &&
          Vars.size() < 32) {
        Index[VD] = Vars.size();
        Vars.push_back(VD);
      }
    }
    if (Vars.empty())
      return;

    std::vector<Facts> In(Cfg.getNumBlockIDs());
    llvm::BitVector Reached(Cfg.getNumBlockIDs());
    In[Cfg.getEntry().getBlockID()].assign(Vars.size(), Fact());
    Reached.set(Cfg.getEntry().getBlockID());
    bool Changed = true;
    unsigned Rounds = 0;
    while (Changed && ++Rounds < 64) {
      Changed = false;
      for (const CFGBlock *B : Cfg) {
        if (!Reached.test(B->getBlockID()))
          continue;
        Facts Out = In[B->getBlockID()];
        runBlock(B, Out);

        const Expr *Cond = nullptr;
        const VarDecl *Tested = nullptr;
        uint8_t OnTrue = Value::Any, OnFalse = Value::Any;
        if (isConditionalBranch(B)) {
          Cond = LinuxPathSearch::getBranchCondition(B);
          Tested = getTest(B, Cond, OnTrue, OnFalse);
        }
        auto TestedIndex = Tested ? Index.find(Tested) : Index.end();

        unsigned SuccIndex = 0;
        for (const CFGBlock::AdjacentBlock &Succ : B->succs()) {
          unsigned This = SuccIndex++;
          const CFGBlock *Next = Succ.getReachableBlock();
          if (!Next)
            continue;
          Facts Edge = Out;
          if (TestedIndex != Index.end()) {
            Fact &F = Edge[TestedIndex->second];
            uint8_t Narrowed = F.Mask & (This == 0 ? OnTrue : OnFalse);
            // The outcome that the earlier test excludes is not a path.
            if (!Narrowed)
              continue;
            if (Narrowed != F.Mask) {
              F.Mask = Narrowed;
              F.From = Cond;
              F.FromBranch = B->getTerminatorStmt();
            }
          }
          unsigned ID = Next->getBlockID();
          if (!Reached.test(ID)) {
            Reached.set(ID);
            In[ID] = Edge;
            Changed = true;
            continue;
          }
          for (unsigned I = 0, E = Vars.size(); I != E; ++I) {
            Fact &Have = In[ID][I];
            uint8_t Joined = Have.Mask | Edge[I].Mask;
            if (Joined != Have.Mask) {
              Have.Mask = Joined;
              Changed = true;
            }
            if (!Have.From) {
              Have.From = Edge[I].From;
              Have.FromBranch = Edge[I].FromBranch;
            }
          }
        }
      }
    }

    for (const CFGBlock *B : Cfg) {
      if (!Reached.test(B->getBlockID()) || !isConditionalBranch(B))
        continue;
      const Expr *Cond = LinuxPathSearch::getBranchCondition(B);
      uint8_t OnTrue = Value::Any, OnFalse = Value::Any;
      const VarDecl *VD = getTest(B, Cond, OnTrue, OnFalse);
      auto It = VD ? Index.find(VD) : Index.end();
      if (It == Index.end())
        continue;
      Facts Out = In[B->getBlockID()];
      runBlock(B, Out);
      const Fact &F = Out[It->second];
      if (F.Mask == Value::Any || !F.From || F.From == Cond)
        continue;
      bool NeverTrue = !(F.Mask & OnTrue);
      bool NeverFalse = !(F.Mask & OnFalse);
      if (NeverTrue == NeverFalse || mayChangeBetween(VD, F.From, Cond) ||
          spellsOutTheRest(F.FromBranch, B, Cond))
        continue;
      // "Not negative" has no wording yet: only zero and not zero.
      if (F.Mask != Value::Zero && (F.Mask & Value::Zero))
        continue;
      S.Diag(Cond->getExprLoc(), diag::warn_linux_kernel_duplicate_check)
          << VD << !(F.Mask & Value::Zero) << Cond->getSourceRange();
      S.Diag(F.From->getExprLoc(), diag::note_linux_kernel_previous_test)
          << F.From->getSourceRange();
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
         !Diags.isIgnored(diag::warn_linux_kernel_wrong_check_other, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_cleanup_return, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_cleanup_escape, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_err_ptr_deref, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_ptr_err_null, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_ptr_err_other, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_unchecked_alloc, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_bitops_cast, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_bitops_cast_order, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_struct_leak, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_buffer_size, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_off_by_one, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_inconsistent_indent, Loc) ||
         !Diags.isIgnored(diag::warn_zero_extended_complement, Loc);
}

} // namespace

void clang::sema::IssueLinuxKernelWarnings(Sema &S, const FunctionDecl *FD,
                                           LinuxKernelUnit &Unit) {
  if (!FD || S.getLangOpts().CPlusPlus ||
      !shouldRunLinuxKernelWarnings(S, FD->getBeginLoc()))
    return;

  LinuxKernelWarningsVisitor(S, FD, Unit).TraverseStmt(FD->getBody());
}

void clang::sema::FinishLinuxKernelWarnings(Sema &S, LinuxKernelUnit &Unit) {
  if (S.getLangOpts().CPlusPlus || S.getLangOpts().LinuxKernelFactsFile.empty())
    return;
  LinuxKernelInference(S, Unit).emitFacts();
}

bool clang::sema::wantsLinuxKernelFlowWarnings(Sema &S,
                                               const FunctionDecl *FD) {
  if (!FD || S.getLangOpts().CPlusPlus)
    return false;
  const DiagnosticsEngine &Diags = S.getDiagnostics();
  SourceLocation Loc = FD->getBeginLoc();
  return !Diags.isIgnored(diag::warn_linux_kernel_error_path_success, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_error_probe_zero, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_missing_error_code, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_counted_by_order, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_counted_by_never_set, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_deref_before_check, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_deref_after_check, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_ptr_err_valid, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_err_ptr_zero, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_duplicate_check, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_missing_unwind, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_memory_leak, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_double_free, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_use_after_free, Loc) ||
         !Diags.isIgnored(diag::warn_linux_kernel_experimental, Loc);
}

void clang::sema::IssueLinuxKernelFlowWarnings(Sema &S, const FunctionDecl *FD,
                                               AnalysisDeclContext &AC,
                                               LinuxKernelUnit &Unit) {
  if (!wantsLinuxKernelFlowWarnings(S, FD) || !FD->getBody())
    return;
  const CFG *Cfg = AC.getCFG();
  if (!Cfg)
    return;
  const DiagnosticsEngine &Diags = S.getDiagnostics();
  SourceLocation Loc = FD->getBeginLoc();
  if (!Diags.isIgnored(diag::warn_linux_kernel_error_path_success, Loc) ||
      !Diags.isIgnored(diag::warn_linux_kernel_error_probe_zero, Loc) ||
      !Diags.isIgnored(diag::warn_linux_kernel_missing_error_code, Loc))
    ErrorPathSuccessChecker(S, FD, *Cfg).run();
  if (!Diags.isIgnored(diag::warn_linux_kernel_counted_by_order, Loc) ||
      !Diags.isIgnored(diag::warn_linux_kernel_counted_by_never_set, Loc))
    CountedByOrderChecker(S, FD, *Cfg).run();
  if (!Diags.isIgnored(diag::warn_linux_kernel_deref_before_check, Loc))
    DerefBeforeCheckChecker(S, FD, *Cfg).run();

  if (!Diags.isIgnored(diag::warn_linux_kernel_duplicate_check, Loc))
    DuplicateCheckChecker(S, FD, *Cfg).run();
  if (!Diags.isIgnored(diag::warn_linux_kernel_double_free, Loc) ||
      !Diags.isIgnored(diag::warn_linux_kernel_use_after_free, Loc))
    UseAfterFreeChecker(S, FD, *Cfg).run();

  // The checks that follow single paths share one search.
  bool WantTestedValue = LinuxTestedValueChecker::wanted(S, Loc);
  bool WantUnwind = LinuxUnwindChecker::wanted(S, Loc);
  if (!WantTestedValue && !WantUnwind)
    return;
  LinuxPathSearch Search(S.getASTContext(), FD, *Cfg, *Unit.State);
  if (WantTestedValue)
    LinuxTestedValueChecker(S, FD, *Cfg, Search, *Unit.State).run();
  if (WantUnwind)
    LinuxUnwindChecker(S, FD, *Cfg, Search, *Unit.State).run();
}
