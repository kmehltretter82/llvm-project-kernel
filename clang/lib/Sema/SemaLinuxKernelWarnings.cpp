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
#include "clang/AST/Stmt.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Analysis/CFG.h"
#include "clang/Basic/Builtins.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/DiagnosticSema.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/SourceManager.h"
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
#include <optional>
#include <string>
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
    /// depends on, and whether their result was tested for NULL first.
    llvm::SmallVector<std::pair<const FunctionDecl *, bool>, 2> External;

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
      if ((Test == 1 && leaves(IS->getThen())) ||
          (Test == 2 && IS->getElse() && leaves(IS->getElse())))
        Out.NullChecked = true;
    } else if (const auto *CE = dyn_cast<CallExpr>(St)) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (Callee && Callee->getIdentifier() && CE->getNumArgs() == 1 &&
          (Callee->getName().starts_with("IS_ERR") ||
           Callee->getName().starts_with("PTR_ERR")) &&
          getDirectLinuxVariable(CE->getArg(0)->IgnoreParenCasts()) == V)
        Out.ErrorTested = true;
    }
    for (const Stmt *Child : St->children())
      collectVariable(Child, V, Out);
  }

  /// What a function hands on from the function it calls keeps the nature of
  /// that function: the wrapper of a stub is a stub.
  static void merge(Sources &R, const Sources &Callee, bool NullChecked) {
    bool Stub = Callee.isStub();
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
    if (Callee.Memory)
      (NullChecked ? R.Valid : R.Memory) = true;
    if (Callee.Opaque)
      R.Opaque = true;
    for (auto [F, Checked] : Callee.External)
      R.External.push_back({F, Checked || NullChecked});
  }

  void addCall(const CallExpr *Call, Sources &R, bool NullChecked,
               unsigned Depth) {
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee || !Callee->getIdentifier()) {
      R.Opaque = true;
      return;
    }
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
      merge(R, sources(Def, Depth + 1), NullChecked);
    } else {
      R.External.push_back({Callee->getCanonicalDecl(), NullChecked});
    }
  }

  void addValue(const Expr *E, Sources &R, const Stmt *Body, bool NullChecked,
                llvm::SmallPtrSetImpl<const VarDecl *> &Seen, unsigned Depth) {
    if (!E || Depth > 12) {
      R.Opaque = true;
      return;
    }
    E = E->IgnoreParens();
    if (E->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNotNull)) {
      R.NullDirect = true;
      return;
    }
    E = E->IgnoreParenCasts();

    if (const auto *BCO = dyn_cast<BinaryConditionalOperator>(E)) {
      addValue(BCO->getCommon(), R, Body, NullChecked, Seen, Depth + 1);
      addValue(BCO->getFalseExpr(), R, Body, NullChecked, Seen, Depth + 1);
    } else if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
      addValue(CO->getTrueExpr(), R, Body, NullChecked, Seen, Depth + 1);
      addValue(CO->getFalseExpr(), R, Body, NullChecked, Seen, Depth + 1);
    } else if (const auto *SE = dyn_cast<StmtExpr>(E)) {
      const CompoundStmt *CS = SE->getSubStmt();
      const Stmt *Last = CS->body_empty() ? nullptr : CS->body_back();
      addValue(dyn_cast_or_null<Expr>(Last), R, Body, NullChecked, Seen,
               Depth + 1);
    } else if (const auto *GSE = dyn_cast<GenericSelectionExpr>(E)) {
      addValue(GSE->isResultDependent() ? nullptr : GSE->getResultExpr(), R,
               Body, NullChecked, Seen, Depth + 1);
    } else if (const auto *CE = dyn_cast<ChooseExpr>(E)) {
      addValue(CE->isConditionDependent() ? nullptr : CE->getChosenSubExpr(), R,
               Body, NullChecked, Seen, Depth + 1);
    } else if (const auto *Call = dyn_cast<CallExpr>(E)) {
      addCall(Call, R, NullChecked, Depth);
    } else if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_Comma || BO->getOpcode() == BO_Assign)
        addValue(BO->getRHS(), R, Body, NullChecked, Seen, Depth + 1);
      else if (BO->isAdditiveOp() && BO->getType()->isPointerType())
        R.Valid = true; // pointer arithmetic, which container_of() is
      else
        R.Opaque = true;
    } else if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_AddrOf)
        R.Valid = true;
      else
        (NullChecked ? R.Valid : R.Memory) = true;
    } else if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
      if (!VD || VD->getType()->isArrayType()) {
        R.Valid = true; // a function or an array
        return;
      }
      if (!VD->hasLocalStorage()) {
        (NullChecked ? R.Valid : R.Memory) = true;
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
      if (IsParameter)
        (Checked ? R.Valid : R.Memory) = true;
      if (Info.ErrorTested)
        R.ErrCallee = true;
      for (const Expr *Value : Info.Values) {
        // A NULL that the variable held is gone, or leaves the function
        // through the test, before the variable is returned.
        if (Checked && Value->IgnoreParens()->isNullPointerConstant(
                           Ctx, Expr::NPC_ValueDependentIsNotNull))
          continue;
        addValue(Value, R, Body, Checked, Seen, Depth + 1);
      }
    } else if (isa<StringLiteral>(E)) {
      R.Valid = true;
    } else if (E->getType()->isPointerType() ||
               E->getType()->isArrayType()) {
      // A field or an array element.
      (NullChecked ? R.Valid : R.Memory) = true;
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
    for (auto [F, Checked] : In.External) {
      const FunctionDecl *Def = getBodyDecl(F);
      if (!Def)
        R.External.push_back({F, Checked});
      else if (Depth < 6)
        merge(R, resolve(Sources(sources(Def)), Depth + 1), Checked);
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
    for (auto [F, Checked] : R.External) {
      switch (fileContract(F)) {
      case LinuxKernelReturnConvention::ErrorPointer:
        R.ErrCallee = true;
        break;
      case LinuxKernelReturnConvention::NullOnFailure:
        (Checked ? R.Valid : R.NullCallee) = true;
        break;
      case LinuxKernelReturnConvention::Unknown:
        R.Opaque = true;
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
  /// elsewhere whose result is returned, or ",k:<name>" if that result was
  /// tested for NULL first.
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
        for (auto [F, Checked] : R.External)
          Callees.push_back((Checked ? "k:" : "c:") + F->getName().str());
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
  /// "if (IS_ERR(p)) return p;": what is returned there is an error pointer
  /// or NULL, which the cleanup functions of <linux/cleanup.h> leave alone.
  llvm::SmallPtrSet<const ReturnStmt *, 4> NothingToRelease;
  llvm::SmallPtrSet<const VarDecl *, 4> ReportedErrorDerefs;
  /// For each parameter of a function with a body: where the function
  /// dereferences it without a test, or null.
  llvm::DenseMap<const ParmVarDecl *, const MemberExpr *> ParameterDerefs;
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

    if (Origin.Kind == LinuxKernelAPIKind::ErrorPointer) {
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
    if (Origin.Kind == LinuxKernelAPIKind::ErrorPointer) {
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
    // A nested test has its own answer: "t ? PTR_ERR(t) : -ENOMEM".
    if (!St || isa<IfStmt, AbstractConditionalOperator>(St))
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
        for (const Stmt *Child : CS->body())
          checkPtrErrIn(Child, Branch, Tests);
      } else {
        checkPtrErrIn(Branch, Branch, Tests);
      }
    }
  }

  static void collectTestedPointers(
      const Stmt *St, llvm::SmallPtrSetImpl<const VarDecl *> &Out) {
    if (!St)
      return;
    auto Add = [&](const Expr *E) {
      if (const VarDecl *VD =
              getDirectLinuxVariable(E ? E->IgnoreParenCasts() : nullptr))
        Out.insert(VD);
    };
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
      collectTestedPointers(Child, Out);
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
    if (!TestedPointers) {
      TestedPointers.emplace();
      collectTestedPointers(CurrentFunction->getBody(), *TestedPointers);
    }
    if (TestedPointers->count(VD) || !ReportedErrorDerefs.insert(VD).second)
      return;
    S.Diag(ME->getOperatorLoc(), diag::warn_linux_kernel_err_ptr_deref)
        << VD << It->second.Callee << ME->getSourceRange();
    noteInferred(It->second);
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
      if (!TestedPointers) {
        TestedPointers.emplace();
        collectTestedPointers(CurrentFunction->getBody(), *TestedPointers);
      }
      if (TestedPointers->count(VD) || !ReportedErrorDerefs.insert(VD).second)
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
         !Diags.isIgnored(diag::warn_linux_kernel_ptr_err_other, Loc);
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
         !Diags.isIgnored(diag::warn_linux_kernel_deref_before_check, Loc);
}

void clang::sema::IssueLinuxKernelFlowWarnings(Sema &S, const FunctionDecl *FD,
                                               AnalysisDeclContext &AC) {
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
}
