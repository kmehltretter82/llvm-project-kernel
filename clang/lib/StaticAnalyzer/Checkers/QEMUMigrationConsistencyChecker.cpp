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
#include "clang/AST/RecordLayout.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>

using namespace clang;
using namespace ento;

namespace {

static constexpr llvm::StringLiteral InlineVArrayRuleID =
    "qemu.migration-inline-varray-count";
static constexpr llvm::StringLiteral FlexibleVArrayRuleID =
    "qemu.migration-flex-varray-capacity";

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
  if (!RD)
    return false;
  if (RD->getName() == Name)
    return true;
  const TypedefNameDecl *Typedef = RD->getTypedefNameForAnonDecl();
  return Typedef && Typedef->getName() == Name;
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

static const VarDecl *directVariable(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  while (const auto *CE = dyn_cast<ConstantExpr>(E))
    E = CE->getSubExpr()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  return VD ? VD->getCanonicalDecl() : nullptr;
}

static const VarDecl *directAddressedVariable(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  const auto *Address = dyn_cast<UnaryOperator>(E);
  if (!Address || Address->getOpcode() != UO_AddrOf)
    return nullptr;
  return directVariable(Address->getSubExpr());
}

static bool expressionReferencesVariable(const Expr *E,
                                         const VarDecl *Variable) {
  if (!E || !Variable)
    return false;
  class ReferenceVisitor : public DynamicRecursiveASTVisitor {
    const VarDecl *Variable;

  public:
    bool Found = false;
    explicit ReferenceVisitor(const VarDecl *Variable) : Variable(Variable) {}

    bool VisitDeclRefExpr(DeclRefExpr *Reference) override {
      if (Reference->getDecl()->getCanonicalDecl() == Variable) {
        Found = true;
        return false;
      }
      return true;
    }
  } Visitor(Variable->getCanonicalDecl());
  Visitor.TraverseStmt(const_cast<Expr *>(E));
  return Visitor.Found;
}

static const FieldDecl *directMemberForObject(const Expr *E,
                                              const VarDecl *Object) {
  if (!E || !Object)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  const auto *Member = dyn_cast<MemberExpr>(E);
  const auto *Field =
      Member ? dyn_cast<FieldDecl>(Member->getMemberDecl()) : nullptr;
  if (!Field || directVariable(Member->getBase()) != Object)
    return nullptr;
  return Field->getCanonicalDecl();
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

static const InitListExpr *arrayInitializer(const Expr *E) {
  E = referencedInitializer(E);
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  while (const auto *CE = dyn_cast<ConstantExpr>(E))
    E = CE->getSubExpr()->IgnoreParenImpCasts();
  if (const auto *Compound = dyn_cast<CompoundLiteralExpr>(E))
    E = Compound->getInitializer();
  return semanticInitList(E);
}

static const FieldDecl *directOffsetField(const Expr *E) {
  if (!E)
    return nullptr;

  class OffsetVisitor : public DynamicRecursiveASTVisitor {
  public:
    const FieldDecl *Found = nullptr;
    bool Unsupported = false;
    unsigned OffsetCount = 0;

    bool VisitOffsetOfExpr(OffsetOfExpr *Offset) override {
      ++OffsetCount;
      const FieldDecl *Direct = nullptr;
      unsigned FieldCount = 0;
      for (unsigned I = 0; I < Offset->getNumComponents(); ++I) {
        const OffsetOfNode &Component = Offset->getComponent(I);
        if (Component.getKind() != OffsetOfNode::Field) {
          Unsupported = true;
          continue;
        }
        ++FieldCount;
        Direct = Component.getField()->getCanonicalDecl();
      }
      if (FieldCount != 1 || !Direct || (Found && Found != Direct))
        Unsupported = true;
      Found = Direct;
      return true;
    }
  } Visitor;
  Visitor.TraverseStmt(const_cast<Expr *>(E));
  return Visitor.Unsupported || Visitor.OffsetCount != 1 ? nullptr
                                                         : Visitor.Found;
}

static std::optional<uint64_t> unsignedIntegerValue(const Expr *E,
                                                    const ASTContext &Ctx) {
  if (!E)
    return std::nullopt;
  std::optional<llvm::APSInt> Value = E->getIntegerConstantExpr(Ctx);
  if (!Value || Value->isNegative() || Value->getActiveBits() > 64)
    return std::nullopt;
  return Value->getZExtValue();
}

static const VarDecl *referencedInfoDeclaration(const Expr *E,
                                                unsigned Depth = 0) {
  if (!E || Depth > 8)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  while (const auto *CE = dyn_cast<ConstantExpr>(E))
    E = CE->getSubExpr()->IgnoreParenImpCasts();
  if (const auto *Choice = dyn_cast<ChooseExpr>(E)) {
    const Expr *Chosen = Choice->getChosenSubExpr();
    return Chosen ? referencedInfoDeclaration(Chosen, Depth + 1) : nullptr;
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_AddrOf)
      return referencedInfoDeclaration(UO->getSubExpr(), Depth + 1);
    return nullptr;
  }
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
  if (!VD)
    return nullptr;

  if (VD->getType()->isPointerType()) {
    if (!VD->hasInit())
      return nullptr;
    return referencedInfoDeclaration(VD->getInit(), Depth + 1);
  }

  const RecordDecl *RD = VD->getType()->getAsRecordDecl();
  return RD && RD->getName() == "VMStateInfo" ? VD->getCanonicalDecl()
                                              : nullptr;
}

enum class VMStateInfoKind { OrdinaryInteger, EqualInteger, Unsupported };

static VMStateInfoKind classifyVMStateInfo(const Expr *E) {
  const VarDecl *Info = referencedInfoDeclaration(E);
  if (!Info)
    return VMStateInfoKind::Unsupported;

  StringRef Name = Info->getName();
  if (Name == "vmstate_info_uint8_equal" ||
      Name == "vmstate_info_uint16_equal" ||
      Name == "vmstate_info_int32_equal" ||
      Name == "vmstate_info_uint32_equal" ||
      Name == "vmstate_info_uint64_equal")
    return VMStateInfoKind::EqualInteger;

  if (Name == "vmstate_info_bool" || Name == "vmstate_info_int8" ||
      Name == "vmstate_info_int16" || Name == "vmstate_info_int32" ||
      Name == "vmstate_info_int64" || Name == "vmstate_info_uint8" ||
      Name == "vmstate_info_uint16" || Name == "vmstate_info_uint32" ||
      Name == "vmstate_info_uint64")
    return VMStateInfoKind::OrdinaryInteger;

  return VMStateInfoKind::Unsupported;
}

static const FunctionDecl *referencedFunction(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  while (const auto *CE = dyn_cast<ConstantExpr>(E))
    E = CE->getSubExpr()->IgnoreParenImpCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_AddrOf)
      E = UO->getSubExpr()->IgnoreParenImpCasts();
  }
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  const auto *FD = DRE ? dyn_cast<FunctionDecl>(DRE->getDecl()) : nullptr;
  return FD ? FD->getCanonicalDecl() : nullptr;
}

static std::optional<llvm::DenseSet<const FieldDecl *>>
validatorReferencedFields(const Expr *Predicate) {
  const FunctionDecl *FD = referencedFunction(Predicate);
  if (!FD || !FD->doesThisDeclarationHaveABody())
    return std::nullopt;

  class ValidatorVisitor : public DynamicRecursiveASTVisitor {
  public:
    llvm::DenseSet<const FieldDecl *> Fields;
    bool Unsupported = false;

    bool VisitMemberExpr(MemberExpr *Member) override {
      const auto *Field = dyn_cast<FieldDecl>(Member->getMemberDecl());
      if (!Field || !Field->getType()->isIntegerType() ||
          Field->getParent()->isUnion()) {
        Unsupported = true;
      } else {
        Fields.insert(Field->getCanonicalDecl());
      }
      return true;
    }

    bool VisitCallExpr(CallExpr *) override {
      Unsupported = true;
      return true;
    }

    bool VisitArraySubscriptExpr(ArraySubscriptExpr *) override {
      Unsupported = true;
      return true;
    }

    bool VisitUnaryOperator(UnaryOperator *Operation) override {
      if (Operation->getOpcode() == UO_Deref)
        Unsupported = true;
      return true;
    }

    bool VisitBinaryOperator(BinaryOperator *Operation) override {
      if (Operation->isAssignmentOp())
        Unsupported = true;
      return true;
    }
  } Visitor;
  Visitor.TraverseStmt(const_cast<Stmt *>(FD->getBody()));
  if (Visitor.Unsupported)
    return std::nullopt;
  return std::move(Visitor.Fields);
}

static std::optional<unsigned> supportedMemberSize(const Expr *E,
                                                   const ASTContext &Ctx) {
  std::optional<uint64_t> Size = unsignedIntegerValue(E, Ctx);
  if (!Size || (*Size != 1 && *Size != 2 && *Size != 4 && *Size != 8))
    return std::nullopt;
  return static_cast<unsigned>(*Size);
}

enum class VMStateFieldLayout { ModernIndirect, LegacyOffset, Unsupported };

static bool isPointerToRecordNamed(QualType Type, StringRef Name);
static bool isVoidPointer(QualType Type);

static bool recordHasField(const InitListExpr *ILE, StringRef Name) {
  if (!ILE)
    return false;
  const RecordDecl *RD = ILE->getType()->getAsRecordDecl();
  if (!RD)
    return false;
  for (const FieldDecl *FD : RD->fields())
    if (FD->getName() == Name)
      return true;
  return false;
}

static const FieldDecl *recordField(const RecordDecl *Record, StringRef Name) {
  if (!Record)
    return nullptr;
  if (const RecordDecl *Definition = Record->getDefinition())
    Record = Definition;
  for (const FieldDecl *Field : Record->fields())
    if (Field->getName() == Name)
      return Field;
  return nullptr;
}

static bool isCharacterPointer(QualType Type) {
  return Type->isPointerType() &&
         Type->getPointeeType().getUnqualifiedType()->isCharType();
}

static bool isFunctionPointer(QualType Type) {
  return Type->isPointerType() && Type->getPointeeType()->isFunctionType();
}

static const FunctionProtoType *functionPointerPrototype(QualType Type) {
  if (!Type->isPointerType())
    return nullptr;
  return Type->getPointeeType()->getAs<FunctionProtoType>();
}

static bool isExactVMStateInfoRecord(const RecordDecl *Record) {
  if (!Record || Record->getName() != "VMStateInfo")
    return false;
  const FieldDecl *Name = recordField(Record, "name");
  const FieldDecl *Get = recordField(Record, "get");
  const FunctionProtoType *Getter =
      Get ? functionPointerPrototype(Get->getType()) : nullptr;
  return Name && isCharacterPointer(Name->getType()) && Getter &&
         Getter->getNumParams() == 4 &&
         isPointerToRecordNamed(Getter->getParamType(0), "QEMUFile") &&
         isVoidPointer(Getter->getParamType(1)) &&
         Getter->getParamType(2)->isIntegerType() &&
         isPointerToRecordNamed(Getter->getParamType(3), "VMStateField");
}

static bool isExactVMStateInfoDecl(const VarDecl *Info) {
  if (!Info)
    return false;
  return isExactVMStateInfoRecord(Info->getType()->getAsRecordDecl());
}

static bool isExactVMStateFieldRecord(const RecordDecl *Record,
                                      ASTContext &Ctx) {
  if (!Record || Record->getName() != "VMStateField")
    return false;
  const FieldDecl *Name = recordField(Record, "name");
  const FieldDecl *Offset = recordField(Record, "offset");
  const FieldDecl *Size = recordField(Record, "size");
  const FieldDecl *Info = recordField(Record, "info");
  const FieldDecl *Flags = recordField(Record, "flags");
  const FieldDecl *Version = recordField(Record, "version_id");
  const FieldDecl *Exists = recordField(Record, "field_exists");
  const FieldDecl *Count = recordField(Record, "num_indirect");
  if (!Count)
    Count = recordField(Record, "num_offset");
  return Name && isCharacterPointer(Name->getType()) && Offset && Size &&
         Ctx.hasSameType(Offset->getType().getUnqualifiedType(),
                         Ctx.getSizeType().getUnqualifiedType()) &&
         Ctx.hasSameType(Size->getType().getUnqualifiedType(),
                         Ctx.getSizeType().getUnqualifiedType()) &&
         Info && isPointerToRecordNamed(Info->getType(), "VMStateInfo") &&
         Flags && Flags->getType()->isIntegralOrEnumerationType() && Version &&
         Ctx.hasSameType(Version->getType().getUnqualifiedType(), Ctx.IntTy) &&
         Exists && isFunctionPointer(Exists->getType()) && Count &&
         ((Count->getName() == "num_indirect" &&
           Count->getType()->getAsRecordDecl() &&
           Count->getType()->getAsRecordDecl()->getName() ==
               "VMStateStructMember") ||
          (Count->getName() == "num_offset" &&
           Count->getType()->isIntegerType()));
}

static bool isExactVMStateFieldInit(const InitListExpr *Field,
                                    ASTContext &Ctx) {
  return Field &&
         isExactVMStateFieldRecord(Field->getType()->getAsRecordDecl(), Ctx);
}

static bool isExactVMStateDescriptionRecord(const RecordDecl *Record,
                                            ASTContext &Ctx) {
  if (!Record || Record->getName() != "VMStateDescription")
    return false;
  const FieldDecl *Name = recordField(Record, "name");
  const FieldDecl *Version = recordField(Record, "version_id");
  const FieldDecl *Minimum = recordField(Record, "minimum_version_id");
  const FieldDecl *PreLoad = recordField(Record, "pre_load");
  const FieldDecl *PreLoadErrp = recordField(Record, "pre_load_errp");
  const FieldDecl *Fields = recordField(Record, "fields");
  return Name && isCharacterPointer(Name->getType()) && Version && Minimum &&
         Ctx.hasSameType(Version->getType().getUnqualifiedType(), Ctx.IntTy) &&
         Ctx.hasSameType(Minimum->getType().getUnqualifiedType(), Ctx.IntTy) &&
         PreLoad && isFunctionPointer(PreLoad->getType()) && PreLoadErrp &&
         isFunctionPointer(PreLoadErrp->getType()) && Fields &&
         isPointerToRecordNamed(Fields->getType(), "VMStateField");
}

static bool isExactVMStateDescriptionInit(const InitListExpr *Description,
                                          ASTContext &Ctx) {
  return Description && isExactVMStateDescriptionRecord(
                            Description->getType()->getAsRecordDecl(), Ctx);
}

static VMStateFieldLayout fieldLayout(const InitListExpr *Field) {
  bool HasModernCount = recordHasField(Field, "num_indirect");
  bool HasLegacyCount = recordHasField(Field, "num_offset");
  if (HasModernCount == HasLegacyCount)
    return VMStateFieldLayout::Unsupported;
  return HasModernCount ? VMStateFieldLayout::ModernIndirect
                        : VMStateFieldLayout::LegacyOffset;
}

struct VArrayCountDescriptor {
  const Expr *Offset;
  unsigned Bytes;
  uint64_t TypeMaximum;
};

static bool isVArray(VMStateFieldLayout Layout, uint64_t Flags) {
  constexpr uint64_t ModernVArray = 0x010;
  constexpr uint64_t LegacyVArrayInt32 = 0x010;
  constexpr uint64_t LegacyVArrayUInt16 = 0x080;
  constexpr uint64_t LegacyVArrayUInt8 = 0x400;
  constexpr uint64_t LegacyVArrayUInt32 = 0x800;
  constexpr uint64_t LegacyVArrayMask = LegacyVArrayInt32 | LegacyVArrayUInt16 |
                                        LegacyVArrayUInt8 | LegacyVArrayUInt32;

  if (Layout == VMStateFieldLayout::ModernIndirect)
    return Flags & ModernVArray;
  if (Layout == VMStateFieldLayout::LegacyOffset)
    return Flags & LegacyVArrayMask;
  return false;
}

static std::optional<VArrayCountDescriptor>
varrayCountDescriptor(const InitListExpr *Field, VMStateFieldLayout Layout,
                      uint64_t Flags, const ASTContext &Ctx) {
  if (Layout == VMStateFieldLayout::ModernIndirect) {
    constexpr uint64_t ModernVArray = 0x010;
    if (!(Flags & ModernVArray))
      return std::nullopt;
    const InitListExpr *Indirect =
        semanticInitList(fieldInitializer(Field, "num_indirect"));
    if (!Indirect)
      return std::nullopt;
    std::optional<unsigned> Bytes =
        supportedMemberSize(fieldInitializer(Indirect, "size"), Ctx);
    if (!Bytes)
      return std::nullopt;
    uint64_t TypeMaximum =
        *Bytes == 8 ? UINT64_MAX : (uint64_t(1) << (*Bytes * 8)) - 1;
    return VArrayCountDescriptor{fieldInitializer(Indirect, "offset"), *Bytes,
                                 TypeMaximum};
  }

  if (Layout != VMStateFieldLayout::LegacyOffset)
    return std::nullopt;

  constexpr uint64_t LegacyVArrayInt32 = 0x010;
  constexpr uint64_t LegacyVArrayUInt16 = 0x080;
  constexpr uint64_t LegacyVArrayUInt8 = 0x400;
  constexpr uint64_t LegacyVArrayUInt32 = 0x800;
  constexpr uint64_t LegacyVArrayMask = LegacyVArrayInt32 | LegacyVArrayUInt16 |
                                        LegacyVArrayUInt8 | LegacyVArrayUInt32;
  uint64_t Kind = Flags & LegacyVArrayMask;
  unsigned Bytes;
  uint64_t TypeMaximum;
  switch (Kind) {
  case LegacyVArrayInt32:
    Bytes = 4;
    TypeMaximum = (uint64_t(1) << 31) - 1;
    break;
  case LegacyVArrayUInt16:
    Bytes = 2;
    TypeMaximum = (uint64_t(1) << 16) - 1;
    break;
  case LegacyVArrayUInt8:
    Bytes = 1;
    TypeMaximum = (uint64_t(1) << 8) - 1;
    break;
  case LegacyVArrayUInt32:
    Bytes = 4;
    TypeMaximum = (uint64_t(1) << 32) - 1;
    break;
  default:
    return std::nullopt;
  }
  return VArrayCountDescriptor{fieldInitializer(Field, "num_offset"), Bytes,
                               TypeMaximum};
}

static bool isLegacyValidator(const InitListExpr *Field, uint64_t Flags,
                              ASTContext &Ctx) {
  constexpr uint64_t LegacyArray = 0x004;
  constexpr uint64_t LegacyMustExist = 0x1000;
  if (Flags != (LegacyArray | LegacyMustExist))
    return false;
  std::optional<int64_t> Num =
      integerValue(fieldInitializer(Field, "num"), Ctx);
  return Num && *Num == 0 &&
         !isNullInitializer(fieldInitializer(Field, "field_exists"), Ctx) &&
         isNullInitializer(fieldInitializer(Field, "info"), Ctx) &&
         isNullInitializer(fieldInitializer(Field, "vmsd"), Ctx);
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

struct FlexibleAllocationContract {
  const VarDecl *Description;
  const FieldDecl *Count;
  const FieldDecl *Array;
  const Expr *Allocation;
  uint64_t ElementBytes;
  llvm::SmallVector<uint64_t, 8> Capacities;
};

struct AllocationCountExpression {
  const VarDecl *Count;
  const BinaryOperator *Multiply;
};

static const RecordDecl *pointerRecord(const VarDecl *VD) {
  if (!VD || !VD->getType()->isPointerType())
    return nullptr;
  const RecordDecl *RD =
      VD->getType()->getPointeeType().getUnqualifiedType()->getAsRecordDecl();
  if (!RD)
    return nullptr;
  if (const RecordDecl *Definition = RD->getDefinition())
    RD = Definition;
  return RD;
}

static const FieldDecl *trailingFlexibleArray(const RecordDecl *RD,
                                              ASTContext &Ctx) {
  if (!RD || !RD->hasFlexibleArrayMember())
    return nullptr;
  const FieldDecl *Last = nullptr;
  for (const FieldDecl *Field : RD->fields())
    Last = Field;
  return Last && Ctx.getAsIncompleteArrayType(Last->getType())
             ? Last->getCanonicalDecl()
             : nullptr;
}

static const CallExpr *directCall(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  while (const auto *CE = dyn_cast<ConstantExpr>(E))
    E = CE->getSubExpr()->IgnoreParenImpCasts();
  return dyn_cast<CallExpr>(E);
}

static bool isPointerToRecordNamed(QualType Type, StringRef Name) {
  if (!Type->isPointerType())
    return false;
  const RecordDecl *Record =
      Type->getPointeeType().getUnqualifiedType()->getAsRecordDecl();
  return Record && Record->getName() == Name;
}

static bool isVoidPointer(QualType Type) {
  return Type->isPointerType() &&
         Type->getPointeeType().getUnqualifiedType()->isVoidType();
}

static bool hasExactGMalloc0Prototype(const CallExpr *Call, ASTContext &Ctx) {
  const FunctionDecl *Function = Call ? Call->getDirectCallee() : nullptr;
  return Function && Function->getName() == "g_malloc0" &&
         !Function->isVariadic() && Function->getNumParams() == 1 &&
         isVoidPointer(Function->getReturnType()) &&
         Ctx.hasSameType(
             Function->getParamDecl(0)->getType().getUnqualifiedType(),
             Ctx.getSizeType().getUnqualifiedType());
}

static bool hasExactVMStateRegisterAnyPrototype(const CallExpr *Call,
                                                ASTContext &Ctx) {
  const FunctionDecl *Function = Call ? Call->getDirectCallee() : nullptr;
  return Function && Function->getName() == "vmstate_register_any" &&
         !Function->isVariadic() && Function->getNumParams() == 3 &&
         Ctx.hasSameType(Function->getReturnType().getUnqualifiedType(),
                         Ctx.IntTy) &&
         isPointerToRecordNamed(Function->getParamDecl(0)->getType(),
                                "VMStateIf") &&
         isPointerToRecordNamed(Function->getParamDecl(1)->getType(),
                                "VMStateDescription") &&
         isVoidPointer(Function->getParamDecl(2)->getType());
}

static bool hasExactQEMUGetUBytePrototype(const CallExpr *Call,
                                          ASTContext &Ctx) {
  const FunctionDecl *Function = Call ? Call->getDirectCallee() : nullptr;
  return Function && Function->getName() == "qemu_get_ubyte" &&
         !Function->isVariadic() && Function->getNumParams() == 1 &&
         Ctx.hasSameType(Function->getReturnType().getUnqualifiedType(),
                         Ctx.UnsignedIntTy) &&
         isPointerToRecordNamed(Function->getParamDecl(0)->getType(),
                                "QEMUFile");
}

static bool hasExactVMStateGetterPrototype(const FunctionDecl *Function,
                                           ASTContext &Ctx) {
  return Function && !Function->isVariadic() && Function->getNumParams() == 4 &&
         Ctx.hasSameType(Function->getReturnType().getUnqualifiedType(),
                         Ctx.IntTy) &&
         isPointerToRecordNamed(Function->getParamDecl(0)->getType(),
                                "QEMUFile") &&
         isVoidPointer(Function->getParamDecl(1)->getType()) &&
         Ctx.hasSameType(
             Function->getParamDecl(2)->getType().getUnqualifiedType(),
             Ctx.getSizeType().getUnqualifiedType()) &&
         isPointerToRecordNamed(Function->getParamDecl(3)->getType(),
                                "VMStateField");
}

static bool hasExactFieldExistsPrototype(const FunctionDecl *Function,
                                         ASTContext &Ctx) {
  return Function && !Function->isVariadic() && Function->getNumParams() == 2 &&
         Ctx.hasSameType(Function->getReturnType().getUnqualifiedType(),
                         Ctx.BoolTy) &&
         isVoidPointer(Function->getParamDecl(0)->getType()) &&
         Ctx.hasSameType(
             Function->getParamDecl(1)->getType().getUnqualifiedType(),
             Ctx.IntTy);
}

static bool isSizeofRecord(const Expr *E, const RecordDecl *Record) {
  if (!E || !Record)
    return false;
  E = E->IgnoreParenImpCasts();
  const auto *Sizeof = dyn_cast<UnaryExprOrTypeTraitExpr>(E);
  if (!Sizeof || Sizeof->getKind() != UETT_SizeOf)
    return false;
  QualType Type = Sizeof->isArgumentType()
                      ? Sizeof->getArgumentType()
                      : Sizeof->getArgumentExpr()->getType();
  const RecordDecl *Sized = Type.getUnqualifiedType()->getAsRecordDecl();
  return Sized && Sized->getCanonicalDecl() == Record->getCanonicalDecl();
}

static std::optional<AllocationCountExpression>
allocationCountVariable(const Expr *E, uint64_t ElementBytes, ASTContext &Ctx) {
  if (!E || !ElementBytes)
    return std::nullopt;
  E = E->IgnoreParenImpCasts();
  const auto *Multiply = dyn_cast<BinaryOperator>(E);
  if (!Multiply || Multiply->getOpcode() != BO_Mul ||
      !Multiply->getType()->isIntegerType())
    return std::nullopt;

  for (unsigned VariableOperand = 0; VariableOperand != 2; ++VariableOperand) {
    const VarDecl *Count = directVariable(VariableOperand ? Multiply->getRHS()
                                                          : Multiply->getLHS());
    const Expr *Scale =
        VariableOperand ? Multiply->getLHS() : Multiply->getRHS();
    std::optional<uint64_t> ScaleValue = unsignedIntegerValue(Scale, Ctx);
    if (Count && Count->getType()->isIntegerType() && ScaleValue &&
        *ScaleValue == ElementBytes)
      return AllocationCountExpression{Count, Multiply};
  }
  return std::nullopt;
}

static std::optional<AllocationCountExpression>
allocationCountFor(const CallExpr *Call, const RecordDecl *Record,
                   uint64_t ElementBytes, ASTContext &Ctx) {
  if (!hasExactGMalloc0Prototype(Call, Ctx) || Call->getNumArgs() != 1)
    return std::nullopt;
  const Expr *Size = Call->getArg(0)->IgnoreParenImpCasts();
  const auto *Add = dyn_cast<BinaryOperator>(Size);
  if (!Add || Add->getOpcode() != BO_Add ||
      !Ctx.hasSameType(Add->getType().getUnqualifiedType(),
                       Ctx.getSizeType().getUnqualifiedType()))
    return std::nullopt;

  if (isSizeofRecord(Add->getLHS(), Record))
    return allocationCountVariable(Add->getRHS(), ElementBytes, Ctx);
  if (isSizeofRecord(Add->getRHS(), Record))
    return allocationCountVariable(Add->getLHS(), ElementBytes, Ctx);
  return std::nullopt;
}

static bool sourceBefore(SourceLocation Left, SourceLocation Right,
                         const SourceManager &SM) {
  Left = SM.getExpansionLoc(Left);
  Right = SM.getExpansionLoc(Right);
  return Left.isValid() && Right.isValid() &&
         SM.isBeforeInTranslationUnit(Left, Right);
}

class FunctionFactVisitor : public DynamicRecursiveASTVisitor {
public:
  llvm::SmallVector<const BinaryOperator *, 16> Assignments;
  llvm::SmallVector<const UnaryOperator *, 4> UnaryWrites;
  llvm::SmallVector<const UnaryOperator *, 4> AddressEscapes;
  llvm::SmallVector<const CallExpr *, 8> Calls;
  llvm::SmallVector<const SwitchStmt *, 4> Switches;
  llvm::SmallVector<const VarDecl *, 8> Declarations;

  bool VisitBinaryOperator(BinaryOperator *Operation) override {
    if (Operation->isAssignmentOp())
      Assignments.push_back(Operation);
    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *Operation) override {
    if (Operation->isIncrementDecrementOp())
      UnaryWrites.push_back(Operation);
    if (Operation->getOpcode() == UO_AddrOf)
      AddressEscapes.push_back(Operation);
    return true;
  }

  bool VisitCallExpr(CallExpr *Call) override {
    Calls.push_back(Call);
    return true;
  }

  bool VisitSwitchStmt(SwitchStmt *Switch) override {
    Switches.push_back(Switch);
    return true;
  }

  bool VisitVarDecl(VarDecl *Declaration) override {
    Declarations.push_back(Declaration);
    return true;
  }
};

static bool countAssignment(const BinaryOperator *Assignment,
                            const VarDecl *Count) {
  return Assignment && Assignment->isAssignmentOp() &&
         directVariable(Assignment->getLHS()) == Count;
}

static bool countUnaryWrite(const UnaryOperator *Operation,
                            const VarDecl *Count) {
  return Operation && Operation->isIncrementDecrementOp() &&
         directVariable(Operation->getSubExpr()) == Count;
}

struct FiniteCountSet {
  const SwitchStmt *Switch;
  llvm::SmallVector<uint64_t, 8> Values;
};

static std::optional<FiniteCountSet>
finiteCountValues(const VarDecl *Count, SourceLocation Before,
                  const FunctionFactVisitor &Facts, ASTContext &Ctx) {
  const SourceManager &SM = Ctx.getSourceManager();
  const SwitchStmt *Matched = nullptr;
  for (const SwitchStmt *Switch : Facts.Switches) {
    if (directVariable(Switch->getCond()) != Count ||
        !sourceBefore(Switch->getBeginLoc(), Before, SM))
      continue;
    if (Matched)
      return std::nullopt;
    Matched = Switch;
  }
  if (!Matched)
    return std::nullopt;

  const auto *Body = dyn_cast<CompoundStmt>(Matched->getBody());
  if (!Body)
    return std::nullopt;

  const DefaultStmt *Default = nullptr;
  llvm::SmallVector<uint64_t, 8> Values;
  for (const SwitchCase *Label = Matched->getSwitchCaseList(); Label;
       Label = Label->getNextSwitchCase()) {
    if (const auto *Case = dyn_cast<CaseStmt>(Label)) {
      if (Case->getRHS())
        return std::nullopt;
      std::optional<uint64_t> Value = unsignedIntegerValue(Case->getLHS(), Ctx);
      if (!Value)
        return std::nullopt;
      Values.push_back(*Value);
      continue;
    }
    const auto *Candidate = dyn_cast<DefaultStmt>(Label);
    if (!Candidate || Default)
      return std::nullopt;
    Default = Candidate;
  }
  if (!Default || Values.empty())
    return std::nullopt;

  const BinaryOperator *DefaultAssignment = nullptr;
  for (const BinaryOperator *Assignment : Facts.Assignments) {
    if (!countAssignment(Assignment, Count))
      continue;
    if (DefaultAssignment)
      return std::nullopt;
    DefaultAssignment = Assignment;
  }
  for (const UnaryOperator *Operation : Facts.UnaryWrites)
    if (countUnaryWrite(Operation, Count))
      return std::nullopt;
  for (const UnaryOperator *Operation : Facts.AddressEscapes)
    if (directVariable(Operation->getSubExpr()) == Count)
      return std::nullopt;
  if (!DefaultAssignment || DefaultAssignment->getOpcode() != BO_Assign)
    return std::nullopt;

  std::optional<uint64_t> DefaultValue =
      unsignedIntegerValue(DefaultAssignment->getRHS(), Ctx);
  if (!DefaultValue)
    return std::nullopt;

  unsigned DefaultIndex = 0;
  unsigned AssignmentIndex = 0;
  bool FoundDefault = false;
  bool FoundAssignment = false;
  unsigned Index = 0;
  for (const Stmt *Child : Body->body()) {
    if (Child == Default) {
      DefaultIndex = Index;
      FoundDefault = true;
    }
    if (Child == DefaultAssignment) {
      AssignmentIndex = Index;
      FoundAssignment = true;
    }
    ++Index;
  }
  if (!FoundDefault || !FoundAssignment || AssignmentIndex != DefaultIndex + 1)
    return std::nullopt;

  for (const SwitchCase *Label = Matched->getSwitchCaseList(); Label;
       Label = Label->getNextSwitchCase())
    if (Label != Default &&
        !sourceBefore(Label->getBeginLoc(), Default->getBeginLoc(), SM))
      return std::nullopt;

  class AbruptControlVisitor : public DynamicRecursiveASTVisitor {
  public:
    bool Unsupported = false;

    bool VisitReturnStmt(ReturnStmt *) override {
      Unsupported = true;
      return false;
    }
    bool VisitGotoStmt(GotoStmt *) override {
      Unsupported = true;
      return false;
    }
    bool VisitContinueStmt(ContinueStmt *) override {
      Unsupported = true;
      return false;
    }
    bool VisitSwitchStmt(SwitchStmt *) override {
      Unsupported = true;
      return false;
    }
  } Abrupt;
  Abrupt.TraverseStmt(const_cast<Stmt *>(Matched->getBody()));
  if (Abrupt.Unsupported)
    return std::nullopt;

  Values.push_back(*DefaultValue);
  std::sort(Values.begin(), Values.end());
  Values.erase(std::unique(Values.begin(), Values.end()), Values.end());
  return FiniteCountSet{Matched, std::move(Values)};
}

static std::optional<unsigned> directChildIndex(const CompoundStmt *Body,
                                                const Stmt *Target) {
  if (!Body || !Target)
    return std::nullopt;
  unsigned Index = 0;
  for (const Stmt *Child : Body->body()) {
    if (Child == Target)
      return Index;
    ++Index;
  }
  return std::nullopt;
}

static bool isStraightLineRange(const CompoundStmt *Body, unsigned First,
                                unsigned Last) {
  unsigned Index = 0;
  for (const Stmt *Child : Body->body()) {
    if (Index > First && Index < Last && !isa<Expr, DeclStmt, NullStmt>(Child))
      return false;
    ++Index;
  }
  return true;
}

static const FieldDecl *
assignedCountField(const VarDecl *Object, const VarDecl *Count,
                   SourceLocation After, SourceLocation Before,
                   const FunctionFactVisitor &Facts, const SourceManager &SM,
                   const BinaryOperator **CountAssignment) {
  const FieldDecl *Found = nullptr;
  for (const BinaryOperator *Assignment : Facts.Assignments) {
    if (Assignment->getOpcode() != BO_Assign ||
        directVariable(Assignment->getRHS()) != Count ||
        !sourceBefore(After, Assignment->getExprLoc(), SM) ||
        !sourceBefore(Assignment->getExprLoc(), Before, SM))
      continue;
    const FieldDecl *Field =
        directMemberForObject(Assignment->getLHS(), Object);
    if (!Field || !Field->getType()->isIntegerType())
      continue;
    if (Found)
      return nullptr;
    Found = Field;
    *CountAssignment = Assignment;
  }
  if (!Found)
    return nullptr;

  for (const BinaryOperator *Assignment : Facts.Assignments) {
    if (directMemberForObject(Assignment->getLHS(), Object) == Found &&
        directVariable(Assignment->getRHS()) != Count)
      return nullptr;
  }
  return Found;
}

static const VarDecl *
registeredDescription(const VarDecl *Object, SourceLocation After,
                      const FunctionFactVisitor &Facts, const SourceManager &SM,
                      ASTContext &Ctx, const CallExpr **Registration) {
  const VarDecl *Description = nullptr;
  for (const CallExpr *Call : Facts.Calls) {
    if (!hasExactVMStateRegisterAnyPrototype(Call, Ctx) ||
        Call->getNumArgs() != 3 || directVariable(Call->getArg(2)) != Object ||
        !sourceBefore(After, Call->getExprLoc(), SM))
      continue;
    const VarDecl *Candidate = directAddressedVariable(Call->getArg(1));
    if (!Candidate || (Description && Description != Candidate))
      return nullptr;
    Description = Candidate;
    *Registration = Call;
  }
  return Description;
}

static llvm::SmallVector<FlexibleAllocationContract, 4>
collectFlexibleAllocationContracts(const TranslationUnitDecl *TU,
                                   ASTContext &Ctx) {
  class FunctionVisitor : public DynamicRecursiveASTVisitor {
    ASTContext &Ctx;
    llvm::SmallVector<FlexibleAllocationContract, 4> Contracts;

  public:
    explicit FunctionVisitor(ASTContext &Ctx) : Ctx(Ctx) {}

    bool VisitFunctionDecl(FunctionDecl *Function) override {
      if (!Function->doesThisDeclarationHaveABody())
        return true;
      const auto *FunctionBody = dyn_cast<CompoundStmt>(Function->getBody());
      if (!FunctionBody)
        return true;

      FunctionFactVisitor Facts;
      Facts.TraverseStmt(Function->getBody());
      const SourceManager &SM = Ctx.getSourceManager();

      for (const BinaryOperator *Assignment : Facts.Assignments) {
        if (Assignment->getOpcode() != BO_Assign)
          continue;
        const VarDecl *Object = directVariable(Assignment->getLHS());
        const RecordDecl *Record = pointerRecord(Object);
        const FieldDecl *Array = trailingFlexibleArray(Record, Ctx);
        const IncompleteArrayType *ArrayType =
            Array ? Ctx.getAsIncompleteArrayType(Array->getType()) : nullptr;
        if (!Object || !Record || !Array || !ArrayType)
          continue;

        QualType ElementType = ArrayType->getElementType();
        if (ElementType->isIncompleteType())
          continue;
        uint64_t ElementBytes =
            Ctx.getTypeSizeInChars(ElementType).getQuantity();
        const CallExpr *Allocation = directCall(Assignment->getRHS());
        std::optional<AllocationCountExpression> AllocationCount =
            allocationCountFor(Allocation, Record, ElementBytes, Ctx);
        const VarDecl *Count =
            AllocationCount ? AllocationCount->Count : nullptr;
        if (!Count || !Count->getType()->isUnsignedIntegerType())
          continue;

        bool ObjectReassigned = false;
        for (const BinaryOperator *Other : Facts.Assignments) {
          if (Other != Assignment &&
              directVariable(Other->getLHS()) == Object) {
            ObjectReassigned = true;
            break;
          }
        }
        if (ObjectReassigned)
          continue;

        std::optional<FiniteCountSet> CountValues =
            finiteCountValues(Count, Assignment->getExprLoc(), Facts, Ctx);
        if (!CountValues)
          continue;

        const CallExpr *Registration = nullptr;
        const VarDecl *Description = registeredDescription(
            Object, Assignment->getExprLoc(), Facts, SM, Ctx, &Registration);
        const InitListExpr *DescriptionInit =
            Description && Description->hasInit()
                ? semanticInitList(Description->getInit())
                : nullptr;
        if (!Description || !Registration ||
            !isExactVMStateDescriptionInit(DescriptionInit, Ctx))
          continue;

        const BinaryOperator *CountAssignment = nullptr;
        const FieldDecl *CountField = assignedCountField(
            Object, Count, Assignment->getExprLoc(), Registration->getExprLoc(),
            Facts, SM, &CountAssignment);
        if (!CountField ||
            CountField->getParent()->getCanonicalDecl() !=
                Record->getCanonicalDecl() ||
            !Ctx.hasSameType(CountField->getType().getUnqualifiedType(),
                             Count->getType().getUnqualifiedType()))
          continue;

        std::optional<unsigned> SwitchIndex =
            directChildIndex(FunctionBody, CountValues->Switch);
        std::optional<unsigned> AllocationIndex =
            directChildIndex(FunctionBody, Assignment);
        std::optional<unsigned> CountAssignmentIndex =
            directChildIndex(FunctionBody, CountAssignment);
        std::optional<unsigned> RegistrationIndex =
            directChildIndex(FunctionBody, Registration);
        if (!SwitchIndex || !AllocationIndex || !CountAssignmentIndex ||
            !RegistrationIndex ||
            !(*SwitchIndex < *AllocationIndex &&
              *AllocationIndex < *CountAssignmentIndex &&
              *CountAssignmentIndex < *RegistrationIndex) ||
            !isStraightLineRange(FunctionBody, *SwitchIndex,
                                 *RegistrationIndex))
          continue;

        bool EscapesOrUnknownCall = false;
        for (const UnaryOperator *Escape : Facts.AddressEscapes) {
          const VarDecl *Escaped = directVariable(Escape->getSubExpr());
          if ((Escaped == Count || Escaped == Object) &&
              sourceBefore(Escape->getExprLoc(), Registration->getExprLoc(),
                           SM)) {
            EscapesOrUnknownCall = true;
            break;
          }
        }
        for (const BinaryOperator *Other : Facts.Assignments) {
          if (expressionReferencesVariable(Other->getRHS(), Object) &&
              sourceBefore(Assignment->getExprLoc(), Other->getExprLoc(), SM) &&
              sourceBefore(Other->getExprLoc(), Registration->getExprLoc(),
                           SM)) {
            EscapesOrUnknownCall = true;
            break;
          }
        }
        for (const VarDecl *Declaration : Facts.Declarations) {
          if (Declaration->hasInit() &&
              expressionReferencesVariable(Declaration->getInit(), Object) &&
              sourceBefore(Assignment->getExprLoc(), Declaration->getLocation(),
                           SM) &&
              sourceBefore(Declaration->getLocation(),
                           Registration->getExprLoc(), SM)) {
            EscapesOrUnknownCall = true;
            break;
          }
        }
        for (const CallExpr *Call : Facts.Calls) {
          if (Call == Allocation || Call == Registration)
            continue;
          if (sourceBefore(Assignment->getExprLoc(), Call->getExprLoc(), SM) &&
              sourceBefore(Call->getExprLoc(), Registration->getExprLoc(),
                           SM)) {
            EscapesOrUnknownCall = true;
            break;
          }
        }
        if (EscapesOrUnknownCall)
          continue;

        uint64_t RecordBytes =
            Ctx.getTypeSizeInChars(Object->getType()->getPointeeType())
                .getQuantity();
        uint64_t OffsetBits = Ctx.getASTRecordLayout(Record).getFieldOffset(
            Array->getFieldIndex());
        unsigned CharWidth = Ctx.getCharWidth();
        if (!ElementBytes || !CharWidth || OffsetBits % CharWidth)
          continue;
        uint64_t OffsetBytes = OffsetBits / CharWidth;
        if (RecordBytes < OffsetBytes)
          continue;
        uint64_t BaseTailBytes = RecordBytes - OffsetBytes;

        unsigned SizeBits = Ctx.getTypeSize(Ctx.getSizeType());
        uint64_t MaximumSize = SizeBits >= 64
                                   ? std::numeric_limits<uint64_t>::max()
                                   : (uint64_t(1) << SizeBits) - 1;
        QualType ProductType = AllocationCount->Multiply->getType();
        unsigned ProductBits = Ctx.getIntWidth(ProductType);
        if (!ProductBits || ProductBits > 64)
          continue;
        uint64_t ProductMaximum;
        if (ProductType->isSignedIntegerType()) {
          ProductMaximum = ProductBits == 64
                               ? uint64_t(std::numeric_limits<int64_t>::max())
                               : (uint64_t(1) << (ProductBits - 1)) - 1;
        } else {
          ProductMaximum = ProductBits == 64
                               ? std::numeric_limits<uint64_t>::max()
                               : (uint64_t(1) << ProductBits) - 1;
        }
        llvm::SmallVector<uint64_t, 8> Capacities;
        bool Overflow = false;
        for (uint64_t Value : CountValues->Values) {
          if (Value > ProductMaximum / ElementBytes ||
              Value > MaximumSize / ElementBytes) {
            Overflow = true;
            break;
          }
          uint64_t ExtraBytes = Value * ElementBytes;
          if (RecordBytes > MaximumSize - ExtraBytes ||
              BaseTailBytes > MaximumSize - ExtraBytes) {
            Overflow = true;
            break;
          }
          Capacities.push_back((BaseTailBytes + ExtraBytes) / ElementBytes);
        }
        if (Overflow || Capacities.empty())
          continue;
        std::sort(Capacities.begin(), Capacities.end());
        Capacities.erase(std::unique(Capacities.begin(), Capacities.end()),
                         Capacities.end());

        Contracts.push_back(FlexibleAllocationContract{
            Description->getCanonicalDecl(), CountField->getCanonicalDecl(),
            Array->getCanonicalDecl(), Allocation, ElementBytes,
            std::move(Capacities)});
      }
      return true;
    }

    llvm::SmallVector<FlexibleAllocationContract, 4> takeContracts() {
      return std::move(Contracts);
    }
  } Visitor(Ctx);

  Visitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));
  return Visitor.takeContracts();
}

static std::optional<int64_t> simpleVersionEquality(const Expr *Predicate,
                                                    ASTContext &Ctx) {
  const FunctionDecl *Function = referencedFunction(Predicate);
  if (!Function)
    return std::nullopt;
  if (const FunctionDecl *Definition = Function->getDefinition())
    Function = Definition;
  if (!hasExactFieldExistsPrototype(Function, Ctx) ||
      !Function->doesThisDeclarationHaveABody())
    return std::nullopt;

  const auto *Body = dyn_cast<CompoundStmt>(Function->getBody());
  if (!Body || Body->size() != 1)
    return std::nullopt;
  const auto *Return = dyn_cast<ReturnStmt>(*Body->body_begin());
  const Expr *Value = Return ? Return->getRetValue() : nullptr;
  Value = Value ? Value->IgnoreParenImpCasts() : nullptr;
  const auto *Equal = dyn_cast_or_null<BinaryOperator>(Value);
  if (!Equal || Equal->getOpcode() != BO_EQ)
    return std::nullopt;

  const VarDecl *Version = Function->getParamDecl(1)->getCanonicalDecl();
  for (unsigned VersionOperand = 0; VersionOperand != 2; ++VersionOperand) {
    const Expr *MaybeVersion =
        VersionOperand ? Equal->getRHS() : Equal->getLHS();
    const Expr *MaybeConstant =
        VersionOperand ? Equal->getLHS() : Equal->getRHS();
    if (directVariable(MaybeVersion) != Version)
      continue;
    return integerValue(MaybeConstant, Ctx);
  }
  return std::nullopt;
}

static std::optional<bool> fieldActiveAtVersion(const InitListExpr *Field,
                                                int64_t Version,
                                                ASTContext &Ctx) {
  const Expr *Predicate = fieldInitializer(Field, "field_exists");
  if (!isNullInitializer(Predicate, Ctx)) {
    std::optional<int64_t> PredicateVersion =
        simpleVersionEquality(Predicate, Ctx);
    if (!PredicateVersion)
      return std::nullopt;
    return *PredicateVersion == Version;
  }

  std::optional<int64_t> FieldVersion =
      integerValue(fieldInitializer(Field, "version_id"), Ctx);
  if (!FieldVersion)
    return std::nullopt;
  return *FieldVersion <= Version;
}

static std::optional<uint64_t> customUnsignedByteMaximum(const Expr *InfoExpr,
                                                         QualType CountType,
                                                         ASTContext &Ctx) {
  const VarDecl *Info = referencedInfoDeclaration(InfoExpr);
  if (!isExactVMStateInfoDecl(Info))
    return std::nullopt;
  if (const VarDecl *Definition = Info->getDefinition())
    Info = Definition;
  const InitListExpr *Initializer =
      Info->hasInit() ? semanticInitList(Info->getInit()) : nullptr;
  if (!initializesRecord(Initializer, "VMStateInfo"))
    return std::nullopt;

  const FunctionDecl *Getter =
      referencedFunction(fieldInitializer(Initializer, "get"));
  if (!Getter)
    return std::nullopt;
  if (const FunctionDecl *Definition = Getter->getDefinition())
    Getter = Definition;
  if (!hasExactVMStateGetterPrototype(Getter, Ctx) ||
      !Getter->doesThisDeclarationHaveABody())
    return std::nullopt;

  const auto *Body = dyn_cast<CompoundStmt>(Getter->getBody());
  if (!Body || Body->size() != 3)
    return std::nullopt;
  auto Statement = Body->body_begin();
  const auto *Declaration = dyn_cast<DeclStmt>(*Statement++);
  const auto *Store = dyn_cast<BinaryOperator>(*Statement++);
  const auto *Return = dyn_cast<ReturnStmt>(*Statement++);
  if (!Declaration || !Declaration->isSingleDecl() || !Store || !Return ||
      Store->getOpcode() != BO_Assign)
    return std::nullopt;

  const auto *Alias = dyn_cast<VarDecl>(Declaration->getSingleDecl());
  if (!Alias || !Alias->hasInit() || !Alias->getType()->isPointerType() ||
      directVariable(Alias->getInit()) !=
          Getter->getParamDecl(1)->getCanonicalDecl() ||
      !Ctx.hasSameType(Alias->getType()->getPointeeType().getUnqualifiedType(),
                       CountType.getUnqualifiedType()))
    return std::nullopt;

  const Expr *StoreTarget = Store->getLHS()->IgnoreParenImpCasts();
  const auto *Dereference = dyn_cast<UnaryOperator>(StoreTarget);
  if (!Dereference || Dereference->getOpcode() != UO_Deref ||
      directVariable(Dereference->getSubExpr()) != Alias->getCanonicalDecl())
    return std::nullopt;

  const CallExpr *Read = directCall(Store->getRHS());
  if (!hasExactQEMUGetUBytePrototype(Read, Ctx) ||
      directVariable(Read->getArg(0)) !=
          Getter->getParamDecl(0)->getCanonicalDecl())
    return std::nullopt;

  std::optional<int64_t> ReturnValue = integerValue(Return->getRetValue(), Ctx);
  if (!ReturnValue || *ReturnValue != 0)
    return std::nullopt;
  return UINT8_MAX;
}

static std::optional<uint64_t> streamMaximum(const InitListExpr *Field,
                                             const FieldDecl *Count,
                                             ASTContext &Ctx) {
  const Expr *InfoExpr = fieldInitializer(Field, "info");
  const VarDecl *Info = referencedInfoDeclaration(InfoExpr);
  if (isExactVMStateInfoDecl(Info)) {
    StringRef Name = Info->getName();
    if (Name == "vmstate_info_uint8")
      return UINT8_MAX;
    if (Name == "vmstate_info_uint16")
      return UINT16_MAX;
    if (Name == "vmstate_info_uint32")
      return UINT32_MAX;
    if (Name == "vmstate_info_uint64")
      return UINT64_MAX;
  }
  return customUnsignedByteMaximum(InfoExpr, Count->getType(), Ctx);
}

static bool isExactUnusedBuffer(const InitListExpr *Field, uint64_t Flags,
                                ASTContext &Ctx) {
  constexpr uint64_t VMSBuffer = 0x020;
  if (Flags != VMSBuffer ||
      directOffsetField(fieldInitializer(Field, "offset")))
    return false;
  const VarDecl *Info =
      referencedInfoDeclaration(fieldInitializer(Field, "info"));
  std::optional<uint64_t> Size =
      unsignedIntegerValue(fieldInitializer(Field, "size"), Ctx);
  return isExactVMStateInfoDecl(Info) &&
         Info->getName() == "vmstate_info_unused_buffer" && Size && *Size;
}

class QEMUMigrationConsistencyChecker
    : public Checker<check::ASTDecl<TranslationUnitDecl>> {
  bool EnableInlineVArrayDiagnostics = false;
  bool EnableFlexibleVArrayDiagnostics = false;

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

  void reportArrayCount(const VarDecl *Description, const Expr *Where,
                        const FieldDecl *Count, const FieldDecl *Array,
                        uint64_t Capacity, BugReporter &BR) const {
    llvm::SmallString<256> Buffer;
    llvm::raw_svector_ostream Message(Buffer);
    Message << '[' << InlineVArrayRuleID << "] migration-loaded count '"
            << Count->getName() << "' controls fixed array '"
            << Array->getName() << "' with capacity " << Capacity
            << " without a recognized earlier validation of that count; an "
               "incoming count can make VMState load beyond the array";

    const SourceManager &SM = BR.getSourceManager();
    SourceLocation Location = SM.getExpansionLoc(Where->getExprLoc());
    BR.EmitBasicReport(Description, this,
                       "Unbounded QEMU migration array count", "QEMU migration",
                       Message.str(), PathDiagnosticLocation(Location, SM),
                       {Where->getSourceRange()});
  }

  void reportFlexibleArrayCount(
      const VarDecl *Description, const Expr *Where,
      const FlexibleAllocationContract &Contract, int64_t Version,
      uint64_t Maximum, const llvm::SmallVectorImpl<uint64_t> &UnsafeCapacities,
      BugReporter &BR) const {
    llvm::SmallString<320> Buffer;
    llvm::raw_svector_ostream Message(Buffer);
    Message << '[' << FlexibleVArrayRuleID << "] migration version " << Version
            << " loads count '" << Contract.Count->getName()
            << "' with maximum " << Maximum << " before flexible array '"
            << Contract.Array->getName() << "'; registered capacities {";
    for (unsigned I = 0; I < Contract.Capacities.size(); ++I) {
      if (I)
        Message << ", ";
      Message << Contract.Capacities[I];
    }
    Message << "} include unsafe capacities {";
    for (unsigned I = 0; I < UnsafeCapacities.size(); ++I) {
      if (I)
        Message << ", ";
      Message << UnsafeCapacities[I];
    }
    Message << "}, and no applicable equality validation preserves the "
               "allocation bound";

    const SourceManager &SM = BR.getSourceManager();
    SourceLocation Location = SM.getExpansionLoc(Where->getExprLoc());
    BR.EmitBasicReport(
        Description, this,
        "Migration count can exceed flexible-array allocation",
        "QEMU migration", Message.str(), PathDiagnosticLocation(Location, SM),
        {Where->getSourceRange(), Contract.Allocation->getSourceRange()});
  }

  void checkFlexibleArrayCounts(
      const VarDecl *Description, const Expr *FieldsExpr,
      int64_t MinimumVersion, int64_t MaximumVersion,
      const llvm::SmallVectorImpl<FlexibleAllocationContract> &Contracts,
      BugReporter &BR) const {
    const InitListExpr *Fields = arrayInitializer(FieldsExpr);
    if (!Fields)
      return;
    const InitListExpr *DescriptionInit =
        semanticInitList(Description->getInit());
    ASTContext &Ctx = Description->getASTContext();
    if (!isExactVMStateDescriptionInit(DescriptionInit, Ctx) ||
        !isNullInitializer(fieldInitializer(DescriptionInit, "pre_load"),
                           Ctx) ||
        !isNullInitializer(fieldInitializer(DescriptionInit, "pre_load_errp"),
                           Ctx))
      return;

    constexpr uint64_t VMSSingle = 0x001;
    constexpr uint64_t VMSPointer = 0x002;
    constexpr uint64_t VMSArray = 0x004;
    constexpr uint64_t VMSStruct = 0x008;
    constexpr uint64_t VMSNoState = 0x080;
    constexpr uint64_t VMSMustExist = 0x1000;
    constexpr uint64_t ModernVArray = 0x010;
    constexpr uint64_t LegacyVArrayMask = 0x010 | 0x080 | 0x400 | 0x800;

    for (const FlexibleAllocationContract &Contract : Contracts) {
      if (Contract.Description != Description->getCanonicalDecl())
        continue;

      llvm::SmallVector<int64_t, 4> CandidateVersions;
      for (const Expr *Entry : Fields->inits()) {
        const InitListExpr *Field = semanticInitList(Entry);
        if (!isExactVMStateFieldInit(Field, Ctx) ||
            directOffsetField(fieldInitializer(Field, "offset")) !=
                Contract.Count)
          continue;
        std::optional<int64_t> Version =
            simpleVersionEquality(fieldInitializer(Field, "field_exists"), Ctx);
        if (!Version || *Version < MinimumVersion ||
            *Version > MaximumVersion ||
            !streamMaximum(Field, Contract.Count, Ctx))
          continue;
        CandidateVersions.push_back(*Version);
      }
      std::sort(CandidateVersions.begin(), CandidateVersions.end());
      CandidateVersions.erase(
          std::unique(CandidateVersions.begin(), CandidateVersions.end()),
          CandidateVersions.end());

      for (int64_t Version : CandidateVersions) {
        enum class CountState {
          CapacityBound,
          StreamLoaded,
          Unknown
        } State = CountState::CapacityBound;
        uint64_t LoadedMaximum = 0;

        for (const Expr *Entry : Fields->inits()) {
          const InitListExpr *Field = semanticInitList(Entry);
          if (!isExactVMStateFieldInit(Field, Ctx)) {
            State = CountState::Unknown;
            break;
          }
          std::optional<bool> Active =
              fieldActiveAtVersion(Field, Version, Ctx);
          if (!Active) {
            State = CountState::Unknown;
            break;
          }
          if (!*Active)
            continue;

          std::optional<uint64_t> Flags =
              unsignedIntegerValue(fieldInitializer(Field, "flags"), Ctx);
          if (!Flags) {
            State = CountState::Unknown;
            break;
          }
          VMStateFieldLayout Layout = fieldLayout(Field);
          if (Layout == VMStateFieldLayout::Unsupported) {
            State = CountState::Unknown;
            break;
          }

          bool IsValidator = Layout == VMStateFieldLayout::ModernIndirect &&
                             (*Flags & (VMSNoState | VMSMustExist)) ==
                                 (VMSNoState | VMSMustExist);
          if (IsValidator || isLegacyValidator(Field, *Flags, Ctx)) {
            State = CountState::Unknown;
            break;
          }

          const FieldDecl *Target =
              directOffsetField(fieldInitializer(Field, "offset"));
          if (isVArray(Layout, *Flags) && !(*Flags & VMSPointer) &&
              Target == Contract.Array) {
            std::optional<VArrayCountDescriptor> CountDescriptor =
                varrayCountDescriptor(Field, Layout, *Flags, Ctx);
            std::optional<uint64_t> ElementBytes =
                unsignedIntegerValue(fieldInitializer(Field, "size"), Ctx);
            if (!CountDescriptor ||
                directOffsetField(CountDescriptor->Offset) != Contract.Count ||
                CountDescriptor->Bytes !=
                    Ctx.getTypeSizeInChars(Contract.Count->getType())
                        .getQuantity() ||
                !ElementBytes || *ElementBytes != Contract.ElementBytes) {
              State = CountState::Unknown;
              break;
            }

            if (State == CountState::StreamLoaded) {
              llvm::SmallVector<uint64_t, 8> UnsafeCapacities;
              for (uint64_t Capacity : Contract.Capacities)
                if (Capacity < LoadedMaximum)
                  UnsafeCapacities.push_back(Capacity);
              if (!UnsafeCapacities.empty())
                reportFlexibleArrayCount(Description, CountDescriptor->Offset,
                                         Contract, Version, LoadedMaximum,
                                         UnsafeCapacities, BR);
            }
            break;
          }

          if (Target != Contract.Count) {
            if (State == CountState::StreamLoaded &&
                classifyVMStateInfo(fieldInitializer(Field, "info")) ==
                    VMStateInfoKind::Unsupported &&
                !isExactUnusedBuffer(Field, *Flags, Ctx)) {
              State = CountState::Unknown;
              break;
            }
            continue;
          }

          uint64_t LayoutVArrayFlags =
              Layout == VMStateFieldLayout::ModernIndirect ? ModernVArray
                                                           : LegacyVArrayMask;
          bool IsScalar =
              !(*Flags &
                (VMSPointer | VMSArray | VMSStruct | LayoutVArrayFlags |
                 (Layout == VMStateFieldLayout::ModernIndirect ? VMSNoState
                                                               : 0))) &&
              (*Flags & VMSSingle);
          std::optional<uint64_t> FieldBytes =
              unsignedIntegerValue(fieldInitializer(Field, "size"), Ctx);
          uint64_t CountBytes =
              Ctx.getTypeSizeInChars(Contract.Count->getType()).getQuantity();
          if (!IsScalar || !FieldBytes || *FieldBytes != CountBytes) {
            State = CountState::Unknown;
            break;
          }

          VMStateInfoKind Info =
              classifyVMStateInfo(fieldInitializer(Field, "info"));
          if (Info == VMStateInfoKind::EqualInteger) {
            continue;
          }
          std::optional<uint64_t> Maximum =
              streamMaximum(Field, Contract.Count, Ctx);
          if (!Maximum) {
            State = CountState::Unknown;
            break;
          }
          State = CountState::StreamLoaded;
          LoadedMaximum = *Maximum;
        }
      }
    }
  }

  void checkArrayCounts(const VarDecl *Description, const Expr *FieldsExpr,
                        int64_t MaximumVersion, BugReporter &BR) const {
    const InitListExpr *Fields = arrayInitializer(FieldsExpr);
    if (!Fields)
      return;

    ASTContext &Ctx = Description->getASTContext();
    llvm::DenseMap<const FieldDecl *, unsigned> LoadedCounts;
    constexpr uint64_t VMSSingle = 0x001;
    constexpr uint64_t VMSPointer = 0x002;
    constexpr uint64_t VMSArray = 0x004;
    constexpr uint64_t VMSStruct = 0x008;
    constexpr uint64_t VMSNoState = 0x080;
    constexpr uint64_t VMSMustExist = 0x1000;
    constexpr uint64_t ModernVArray = 0x010;
    constexpr uint64_t LegacyVArrayMask = 0x010 | 0x080 | 0x400 | 0x800;

    for (const Expr *Entry : Fields->inits()) {
      const InitListExpr *Field = semanticInitList(Entry);
      if (!initializesRecord(Field, "VMStateField"))
        continue;

      std::optional<uint64_t> Flags =
          unsignedIntegerValue(fieldInitializer(Field, "flags"), Ctx);
      if (!Flags) {
        if (const FieldDecl *MaybeWritten =
                directOffsetField(fieldInitializer(Field, "offset")))
          LoadedCounts.erase(MaybeWritten);
        else
          LoadedCounts.clear();
        continue;
      }

      VMStateFieldLayout Layout = fieldLayout(Field);
      if (Layout == VMStateFieldLayout::Unsupported) {
        LoadedCounts.clear();
        continue;
      }

      bool IsModernValidator =
          Layout == VMStateFieldLayout::ModernIndirect &&
          (*Flags & (VMSNoState | VMSMustExist)) == (VMSNoState | VMSMustExist);
      bool IsLegacyValidation = Layout == VMStateFieldLayout::LegacyOffset &&
                                isLegacyValidator(Field, *Flags, Ctx);
      if (IsModernValidator || IsLegacyValidation) {
        std::optional<llvm::DenseSet<const FieldDecl *>> Referenced =
            validatorReferencedFields(fieldInitializer(Field, "field_exists"));
        if (!Referenced) {
          // An opaque validator might inspect any migrated member.  Retire
          // precision rather than issuing a diagnostic past an unknown proof.
          LoadedCounts.clear();
        } else {
          // Mentioning a count is not proof of a useful upper bound.  Treat
          // that count as unsupported; unrelated active counts remain exact.
          for (const FieldDecl *ReferencedField : *Referenced)
            LoadedCounts.erase(ReferencedField);
        }
        continue;
      }

      if (isVArray(Layout, *Flags) && !(*Flags & VMSPointer)) {
        const Expr *Predicate = fieldInitializer(Field, "field_exists");
        std::optional<int64_t> Version =
            integerValue(fieldInitializer(Field, "version_id"), Ctx);
        if (!isNullInitializer(Predicate, Ctx) || !Version || *Version < 0 ||
            *Version > MaximumVersion)
          continue;

        std::optional<VArrayCountDescriptor> CountDescriptor =
            varrayCountDescriptor(Field, Layout, *Flags, Ctx);
        const FieldDecl *Count =
            CountDescriptor ? directOffsetField(CountDescriptor->Offset)
                            : nullptr;
        const FieldDecl *Array =
            directOffsetField(fieldInitializer(Field, "offset"));
        const ConstantArrayType *ArrayType =
            Array ? Ctx.getAsConstantArrayType(Array->getType()) : nullptr;
        auto Loaded = Count ? LoadedCounts.find(Count) : LoadedCounts.end();
        if (CountDescriptor && Count && Array &&
            !Count->getParent()->isUnion() && !Array->getParent()->isUnion() &&
            ArrayType && Loaded != LoadedCounts.end() &&
            Loaded->second == CountDescriptor->Bytes) {
          uint64_t Capacity = ArrayType->getSize().getLimitedValue();
          bool TypeCanExceed = CountDescriptor->TypeMaximum > Capacity;
          if (TypeCanExceed)
            reportArrayCount(Description, CountDescriptor->Offset, Count, Array,
                             Capacity, BR);
        }
      }

      const FieldDecl *Loaded =
          directOffsetField(fieldInitializer(Field, "offset"));
      bool IsNoState =
          Layout == VMStateFieldLayout::ModernIndirect && (*Flags & VMSNoState);
      if (IsNoState)
        continue;
      if (!Loaded) {
        // An unsupported write target may alias a count we were tracking.
        LoadedCounts.clear();
        continue;
      }
      if (!Loaded->getType()->isIntegerType()) {
        if (Loaded->getParent()->isUnion())
          LoadedCounts.clear();
        continue;
      }
      if (Loaded->getParent()->isUnion()) {
        LoadedCounts.clear();
        continue;
      }

      std::optional<int64_t> Version =
          integerValue(fieldInitializer(Field, "version_id"), Ctx);
      if (Version && *Version > MaximumVersion)
        continue;

      VMStateInfoKind Info =
          classifyVMStateInfo(fieldInitializer(Field, "info"));
      if (Info == VMStateInfoKind::EqualInteger)
        continue;

      bool IsUnconditional =
          isNullInitializer(fieldInitializer(Field, "field_exists"), Ctx);
      uint64_t LayoutVArrayFlags = Layout == VMStateFieldLayout::ModernIndirect
                                       ? ModernVArray
                                       : LegacyVArrayMask;
      bool IsScalar =
          !(*Flags & (VMSPointer | VMSArray | VMSStruct | LayoutVArrayFlags |
                      (Layout == VMStateFieldLayout::ModernIndirect ? VMSNoState
                                                                    : 0))) &&
          (*Flags & VMSSingle);
      std::optional<unsigned> LoadedBytes =
          supportedMemberSize(fieldInitializer(Field, "size"), Ctx);
      if (!Version || *Version < 0 || !IsUnconditional || !IsScalar ||
          Info != VMStateInfoKind::OrdinaryInteger || !LoadedBytes) {
        LoadedCounts.erase(Loaded);
        continue;
      }
      LoadedCounts[Loaded] = *LoadedBytes;
    }
  }

  void checkDescription(
      const VarDecl *VD,
      const llvm::SmallVectorImpl<FlexibleAllocationContract> &Contracts,
      BugReporter &BR) const {
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
    if (EnableInlineVArrayDiagnostics) {
      checkArrayCounts(VD, Fields, *Version, BR);
    }
    if (EnableFlexibleVArrayDiagnostics && Minimum)
      checkFlexibleArrayCounts(VD, Fields, *Minimum, *Version, Contracts, BR);
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
  void setEnableInlineVArrayDiagnostics(bool Enable) {
    EnableInlineVArrayDiagnostics = Enable;
  }

  void setEnableFlexibleVArrayDiagnostics(bool Enable) {
    EnableFlexibleVArrayDiagnostics = Enable;
  }

  void checkASTDecl(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                    BugReporter &BR) const {
    llvm::SmallVector<FlexibleAllocationContract, 4> Contracts;
    if (EnableFlexibleVArrayDiagnostics)
      Contracts = collectFlexibleAllocationContracts(TU, Mgr.getASTContext());
    class DescriptionVisitor : public DynamicRecursiveASTVisitor {
      const QEMUMigrationConsistencyChecker &Checker;
      const llvm::SmallVectorImpl<FlexibleAllocationContract> &Contracts;
      BugReporter &BR;

    public:
      DescriptionVisitor(
          const QEMUMigrationConsistencyChecker &Checker,
          const llvm::SmallVectorImpl<FlexibleAllocationContract> &Contracts,
          BugReporter &BR)
          : Checker(Checker), Contracts(Contracts), BR(BR) {}

      bool VisitVarDecl(VarDecl *VD) override {
        if (VD->hasInit())
          Checker.checkDescription(VD, Contracts, BR);
        return true;
      }
    } Visitor(*this, Contracts, BR);
    Visitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));
  }
};

} // namespace

void ento::registerQEMUMigrationConsistencyChecker(CheckerManager &Mgr) {
  auto *Checker = Mgr.registerChecker<QEMUMigrationConsistencyChecker>();
  Checker->setEnableInlineVArrayDiagnostics(
      Mgr.getAnalyzerOptions().getCheckerBooleanOption(
          Checker, "EnableInlineVArrayDiagnostics"));
  Checker->setEnableFlexibleVArrayDiagnostics(
      Mgr.getAnalyzerOptions().getCheckerBooleanOption(
          Checker, "EnableFlexibleVArrayDiagnostics"));
}

bool ento::shouldRegisterQEMUMigrationConsistencyChecker(
    const CheckerManager &Mgr) {
  return true;
}
