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
#include <string>
#include <utility>

using namespace clang;
using namespace ento;

namespace {

static constexpr llvm::StringLiteral InlineVArrayRuleID =
    "qemu.migration-inline-varray-count";
static constexpr llvm::StringLiteral FlexibleVArrayRuleID =
    "qemu.migration-flex-varray-capacity";
static constexpr llvm::StringLiteral PointerVArrayRuleID =
    "qemu.migration-pointer-varray-capacity";

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

static bool isRecordNamed(const RecordDecl *Record, StringRef Name) {
  if (!Record)
    return false;
  if (Record->getName() == Name)
    return true;
  const TypedefNameDecl *Typedef = Record->getTypedefNameForAnonDecl();
  return Typedef && Typedef->getName() == Name;
}

static bool initializesRecord(const InitListExpr *ILE, StringRef Name) {
  return ILE && isRecordNamed(ILE->getType()->getAsRecordDecl(), Name);
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
  return isRecordNamed(RD, "VMStateInfo") ? VD->getCanonicalDecl() : nullptr;
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
  if (!isRecordNamed(Record, "VMStateInfo"))
    return false;
  const FieldDecl *Name = recordField(Record, "name");
  const FieldDecl *Get = recordField(Record, "get");
  const FunctionProtoType *Getter =
      Get ? functionPointerPrototype(Get->getType()) : nullptr;
  if (!Name || !isCharacterPointer(Name->getType()) || !Getter ||
      (Getter->getNumParams() != 3 && Getter->getNumParams() != 4) ||
      !isPointerToRecordNamed(Getter->getParamType(0), "QEMUFile") ||
      !isVoidPointer(Getter->getParamType(1)) ||
      !Getter->getParamType(2)->isIntegerType())
    return false;
  return Getter->getNumParams() == 3 ||
         isPointerToRecordNamed(Getter->getParamType(3), "VMStateField");
}

static bool isExactVMStateInfoDecl(const VarDecl *Info) {
  if (!Info)
    return false;
  return isExactVMStateInfoRecord(Info->getType()->getAsRecordDecl());
}

static bool isExactVMStateFieldRecord(const RecordDecl *Record,
                                      ASTContext &Ctx) {
  if (!isRecordNamed(Record, "VMStateField"))
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
           isRecordNamed(Count->getType()->getAsRecordDecl(),
                         "VMStateStructMember")) ||
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
  if (!isRecordNamed(Record, "VMStateDescription"))
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

static bool
isExactPointerVMStateDescriptionInit(const InitListExpr *Description,
                                     ASTContext &Ctx) {
  if (!Description)
    return false;
  const RecordDecl *Record = Description->getType()->getAsRecordDecl();
  if (!isRecordNamed(Record, "VMStateDescription"))
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
         PreLoad && isFunctionPointer(PreLoad->getType()) &&
         (!PreLoadErrp || isFunctionPointer(PreLoadErrp->getType())) &&
         Fields && isPointerToRecordNamed(Fields->getType(), "VMStateField");
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

struct PointerAllocationContract {
  const FieldDecl *Array;
  const FieldDecl *Capacity;
  const Expr *Allocation;
  uint64_t ElementBytes;
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
  return isRecordNamed(Record, Name);
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

static bool hasExactGArrayAllocationPrototype(const CallExpr *Call,
                                              ASTContext &Ctx) {
  const FunctionDecl *Function = Call ? Call->getDirectCallee() : nullptr;
  if (!Function ||
      (Function->getName() != "g_malloc_n" &&
       Function->getName() != "g_malloc0_n") ||
      Function->isVariadic() || Function->getNumParams() != 2 ||
      !isVoidPointer(Function->getReturnType()))
    return false;
  for (const ParmVarDecl *Parameter : Function->parameters())
    if (!Ctx.hasSameType(Parameter->getType().getUnqualifiedType(),
                         Ctx.getSizeType().getUnqualifiedType()))
      return false;
  return true;
}

static const Expr *valueExpression(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  while (const auto *CE = dyn_cast<ConstantExpr>(E))
    E = CE->getSubExpr()->IgnoreParenImpCasts();
  return E;
}

static bool sameValueExpression(const Expr *Left, const Expr *Right,
                                unsigned Depth = 0) {
  if (Depth > 16)
    return false;
  Left = valueExpression(Left);
  Right = valueExpression(Right);
  if (!Left || !Right)
    return false;

  if (const auto *LeftReference = dyn_cast<DeclRefExpr>(Left)) {
    const auto *RightReference = dyn_cast<DeclRefExpr>(Right);
    return RightReference && LeftReference->getDecl()->getCanonicalDecl() ==
                                 RightReference->getDecl()->getCanonicalDecl();
  }

  if (const auto *LeftMember = dyn_cast<MemberExpr>(Left)) {
    const auto *RightMember = dyn_cast<MemberExpr>(Right);
    return RightMember && LeftMember->isArrow() == RightMember->isArrow() &&
           LeftMember->getMemberDecl()->getCanonicalDecl() ==
               RightMember->getMemberDecl()->getCanonicalDecl() &&
           sameValueExpression(LeftMember->getBase(), RightMember->getBase(),
                               Depth + 1);
  }

  if (const auto *LeftUnary = dyn_cast<UnaryOperator>(Left)) {
    const auto *RightUnary = dyn_cast<UnaryOperator>(Right);
    return RightUnary && LeftUnary->getOpcode() == RightUnary->getOpcode() &&
           (LeftUnary->getOpcode() == UO_Deref ||
            LeftUnary->getOpcode() == UO_AddrOf) &&
           sameValueExpression(LeftUnary->getSubExpr(),
                               RightUnary->getSubExpr(), Depth + 1);
  }

  return false;
}

static const MemberExpr *directMemberExpression(const Expr *E) {
  E = valueExpression(E);
  const auto *Member = dyn_cast_or_null<MemberExpr>(E);
  return Member && isa<FieldDecl>(Member->getMemberDecl()) ? Member : nullptr;
}

static const CallExpr *directPointerAllocationCall(const Expr *E) {
  E = valueExpression(E);
  while (const auto *Cast = dyn_cast_or_null<ExplicitCastExpr>(E)) {
    if (Cast->getCastKind() != CK_BitCast && Cast->getCastKind() != CK_NoOp)
      return nullptr;
    E = valueExpression(Cast->getSubExpr());
  }
  return dyn_cast_or_null<CallExpr>(E);
}

static bool sizeofMatchesType(const Expr *E, QualType Expected,
                              ASTContext &Ctx) {
  E = valueExpression(E);
  const auto *Sizeof = dyn_cast_or_null<UnaryExprOrTypeTraitExpr>(E);
  if (!Sizeof || Sizeof->getKind() != UETT_SizeOf)
    return false;
  QualType Sized = Sizeof->isArgumentType()
                       ? Sizeof->getArgumentType()
                       : Sizeof->getArgumentExpr()->getType();
  return Ctx.hasSameType(Sized.getUnqualifiedType(),
                         Expected.getUnqualifiedType());
}

static const MemberExpr *sizeofArrayElement(const Expr *E, ASTContext &Ctx) {
  E = valueExpression(E);
  const auto *Sizeof = dyn_cast_or_null<UnaryExprOrTypeTraitExpr>(E);
  if (!Sizeof || Sizeof->getKind() != UETT_SizeOf || Sizeof->isArgumentType())
    return nullptr;

  const Expr *Argument = valueExpression(Sizeof->getArgumentExpr());
  const auto *Subscript = dyn_cast_or_null<ArraySubscriptExpr>(Argument);
  std::optional<uint64_t> Index =
      Subscript ? unsignedIntegerValue(Subscript->getIdx(), Ctx) : std::nullopt;
  if (!Subscript || !Index || *Index != 0)
    return nullptr;
  return directMemberExpression(Subscript->getBase());
}

static std::optional<PointerAllocationContract>
pointerAllocationContract(const BinaryOperator *Assignment, ASTContext &Ctx) {
  if (!Assignment || Assignment->getOpcode() != BO_Assign)
    return std::nullopt;

  const MemberExpr *ArrayMember = directMemberExpression(Assignment->getLHS());
  const auto *Array =
      ArrayMember ? dyn_cast<FieldDecl>(ArrayMember->getMemberDecl()) : nullptr;
  if (!Array || !Array->getType()->isPointerType() ||
      Array->getParent()->isUnion())
    return std::nullopt;

  QualType ElementType = Array->getType()->getPointeeType();
  if (ElementType->isIncompleteType())
    return std::nullopt;
  uint64_t ElementBytes = Ctx.getTypeSizeInChars(ElementType).getQuantity();
  if (!ElementBytes)
    return std::nullopt;

  const CallExpr *Allocation =
      directPointerAllocationCall(Assignment->getRHS());
  if (hasExactGArrayAllocationPrototype(Allocation, Ctx)) {
    for (unsigned CapacityOperand = 0; CapacityOperand != 2;
         ++CapacityOperand) {
      const Expr *MaybeCapacity = Allocation->getArg(CapacityOperand);
      const Expr *MaybeSizeof = Allocation->getArg(1 - CapacityOperand);
      const MemberExpr *CapacityMember = directMemberExpression(MaybeCapacity);
      const auto *Capacity =
          CapacityMember ? dyn_cast<FieldDecl>(CapacityMember->getMemberDecl())
                         : nullptr;
      if (!Capacity || !Capacity->getType()->isUnsignedIntegerType() ||
          Capacity->getParent()->isUnion() ||
          Capacity->getParent()->getCanonicalDecl() !=
              Array->getParent()->getCanonicalDecl() ||
          !sameValueExpression(CapacityMember->getBase(),
                               ArrayMember->getBase()) ||
          !sizeofMatchesType(MaybeSizeof, ElementType, Ctx))
        continue;
      return PointerAllocationContract{Array->getCanonicalDecl(),
                                       Capacity->getCanonicalDecl(), Allocation,
                                       ElementBytes};
    }
    return std::nullopt;
  }

  if (!hasExactGMalloc0Prototype(Allocation, Ctx) ||
      Allocation->getNumArgs() != 1)
    return std::nullopt;
  const auto *Multiply =
      dyn_cast_or_null<BinaryOperator>(valueExpression(Allocation->getArg(0)));
  if (!Multiply || Multiply->getOpcode() != BO_Mul ||
      !Ctx.hasSameType(Multiply->getType().getUnqualifiedType(),
                       Ctx.getSizeType().getUnqualifiedType()))
    return std::nullopt;

  for (unsigned CapacityOperand = 0; CapacityOperand != 2; ++CapacityOperand) {
    const Expr *MaybeCapacity =
        CapacityOperand ? Multiply->getRHS() : Multiply->getLHS();
    const Expr *MaybeSizeof =
        CapacityOperand ? Multiply->getLHS() : Multiply->getRHS();
    const MemberExpr *SizedArray = sizeofArrayElement(MaybeSizeof, Ctx);
    const MemberExpr *CapacityMember = directMemberExpression(MaybeCapacity);
    const auto *Capacity =
        CapacityMember ? dyn_cast<FieldDecl>(CapacityMember->getMemberDecl())
                       : nullptr;
    if (!SizedArray || !Capacity ||
        !Capacity->getType()->isUnsignedIntegerType() ||
        Capacity->getParent()->isUnion() ||
        SizedArray->getMemberDecl()->getCanonicalDecl() !=
            Array->getCanonicalDecl() ||
        Capacity->getParent()->getCanonicalDecl() !=
            Array->getParent()->getCanonicalDecl() ||
        !sameValueExpression(SizedArray->getBase(), ArrayMember->getBase()) ||
        !sameValueExpression(CapacityMember->getBase(),
                             ArrayMember->getBase()) ||
        !SizedArray->getType()->isPointerType() ||
        !Ctx.hasSameType(
            SizedArray->getType()->getPointeeType().getUnqualifiedType(),
            ElementType.getUnqualifiedType()))
      continue;

    unsigned CapacityBits = Ctx.getIntWidth(Capacity->getType());
    unsigned SizeBits = Ctx.getTypeSize(Ctx.getSizeType());
    if (!CapacityBits || CapacityBits > 64 || !SizeBits || SizeBits > 64)
      continue;
    uint64_t CapacityMaximum = CapacityBits == 64
                                   ? std::numeric_limits<uint64_t>::max()
                                   : (uint64_t(1) << CapacityBits) - 1;
    uint64_t SizeMaximum = SizeBits == 64 ? std::numeric_limits<uint64_t>::max()
                                          : (uint64_t(1) << SizeBits) - 1;
    if (CapacityMaximum > SizeMaximum / ElementBytes)
      continue;
    return PointerAllocationContract{Array->getCanonicalDecl(),
                                     Capacity->getCanonicalDecl(), Allocation,
                                     ElementBytes};
  }
  return std::nullopt;
}

static llvm::SmallVector<PointerAllocationContract, 8>
collectPointerAllocationContracts(const TranslationUnitDecl *TU,
                                  ASTContext &Ctx) {
  class AllocationVisitor : public DynamicRecursiveASTVisitor {
    ASTContext &Ctx;

  public:
    llvm::SmallVector<PointerAllocationContract, 16> Candidates;
    llvm::DenseMap<const FieldDecl *, unsigned> Writes;

    explicit AllocationVisitor(ASTContext &Ctx) : Ctx(Ctx) {}

    bool VisitBinaryOperator(BinaryOperator *Assignment) override {
      if (Assignment->getOpcode() == BO_Assign) {
        const MemberExpr *Member = directMemberExpression(Assignment->getLHS());
        const auto *Field =
            Member ? dyn_cast<FieldDecl>(Member->getMemberDecl()) : nullptr;
        if (Field && Field->getType()->isPointerType())
          ++Writes[Field->getCanonicalDecl()];
      }
      if (std::optional<PointerAllocationContract> Contract =
              pointerAllocationContract(Assignment, Ctx))
        Candidates.push_back(*Contract);
      return true;
    }
  } Visitor(Ctx);
  Visitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));

  llvm::DenseMap<const FieldDecl *, unsigned> Occurrences;
  for (const PointerAllocationContract &Contract : Visitor.Candidates)
    ++Occurrences[Contract.Array];

  llvm::SmallVector<PointerAllocationContract, 8> Contracts;
  for (const PointerAllocationContract &Contract : Visitor.Candidates)
    if (Occurrences.lookup(Contract.Array) == 1 &&
        Visitor.Writes.lookup(Contract.Array) == 1)
      Contracts.push_back(Contract);
  return Contracts;
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

static bool isKnownVMStateRegistration(StringRef Name) {
  return Name == "vmstate_register" || Name == "vmstate_register_any" ||
         Name == "vmstate_register_with_alias_id" ||
         Name == "vmstate_replace_hack_for_ppc";
}

static const VarDecl *registeredVMStateDescription(const CallExpr *Call) {
  const FunctionDecl *Function = Call ? Call->getDirectCallee() : nullptr;
  if (!Function || !isKnownVMStateRegistration(Function->getName()) ||
      Function->isVariadic() || Function->getNumParams() != Call->getNumArgs())
    return nullptr;

  const VarDecl *Description = nullptr;
  for (unsigned I = 0; I != Call->getNumArgs(); ++I) {
    if (!isPointerToRecordNamed(Function->getParamDecl(I)->getType(),
                                "VMStateDescription"))
      continue;
    const VarDecl *Candidate = directAddressedVariable(Call->getArg(I));
    if (!Candidate || Description)
      return nullptr;
    Description = Candidate;
  }
  return Description;
}

static llvm::DenseSet<const VarDecl *>
collectReachableVMStateDescriptions(const TranslationUnitDecl *TU) {
  class ReachabilityVisitor : public DynamicRecursiveASTVisitor {
  public:
    llvm::DenseSet<const VarDecl *> Reachable;

    bool VisitCallExpr(CallExpr *Call) override {
      if (const VarDecl *Description = registeredVMStateDescription(Call))
        Reachable.insert(Description->getCanonicalDecl());
      return true;
    }

    bool VisitBinaryOperator(BinaryOperator *Assignment) override {
      if (Assignment->getOpcode() != BO_Assign)
        return true;
      const MemberExpr *Member = directMemberExpression(Assignment->getLHS());
      const auto *Field =
          Member ? dyn_cast<FieldDecl>(Member->getMemberDecl()) : nullptr;
      if (!Field || Field->getName() != "vmsd" ||
          !isPointerToRecordNamed(Field->getType(), "VMStateDescription"))
        return true;
      if (const VarDecl *Description =
              directAddressedVariable(Assignment->getRHS()))
        Reachable.insert(Description->getCanonicalDecl());
      return true;
    }

    bool VisitInitListExpr(InitListExpr *Initializer) override {
      Initializer = const_cast<InitListExpr *>(semanticInitList(Initializer));
      const RecordDecl *Record =
          Initializer ? Initializer->getType()->getAsRecordDecl() : nullptr;
      const FieldDecl *Field = recordField(Record, "vmsd");
      if (!Field ||
          !isPointerToRecordNamed(Field->getType(), "VMStateDescription"))
        return true;
      if (const VarDecl *Description =
              directAddressedVariable(fieldInitializer(Initializer, "vmsd")))
        Reachable.insert(Description->getCanonicalDecl());
      return true;
    }
  } Visitor;
  Visitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TU));
  return std::move(Visitor.Reachable);
}

static bool validatorProvesUpperBound(const Expr *Predicate,
                                      const FieldDecl *Count,
                                      const FieldDecl *Capacity,
                                      ASTContext &Ctx) {
  const FunctionDecl *Function = referencedFunction(Predicate);
  if (!Function)
    return false;
  if (const FunctionDecl *Definition = Function->getDefinition())
    Function = Definition;
  if (!hasExactFieldExistsPrototype(Function, Ctx) ||
      !Function->doesThisDeclarationHaveABody())
    return false;

  const auto *Body = dyn_cast<CompoundStmt>(Function->getBody());
  if (!Body || Body->size() != 2)
    return false;
  auto Statement = Body->body_begin();
  const auto *Declaration = dyn_cast<DeclStmt>(*Statement++);
  const auto *Return = dyn_cast<ReturnStmt>(*Statement++);
  if (!Declaration || !Declaration->isSingleDecl() || !Return)
    return false;

  const auto *Alias = dyn_cast<VarDecl>(Declaration->getSingleDecl());
  const RecordDecl *AliasRecord = Alias && Alias->getType()->isPointerType()
                                      ? Alias->getType()
                                            ->getPointeeType()
                                            .getUnqualifiedType()
                                            ->getAsRecordDecl()
                                      : nullptr;
  if (!Alias || !Alias->hasInit() || !Alias->getType()->isPointerType() ||
      directVariable(Alias->getInit()) !=
          Function->getParamDecl(0)->getCanonicalDecl() ||
      !AliasRecord ||
      AliasRecord->getCanonicalDecl() !=
          Count->getParent()->getCanonicalDecl() ||
      Count->getParent()->getCanonicalDecl() !=
          Capacity->getParent()->getCanonicalDecl())
    return false;

  const Expr *Value = valueExpression(Return->getRetValue());
  const auto *Compare = dyn_cast_or_null<BinaryOperator>(Value);
  if (!Compare || Compare->getOpcode() != BO_LE)
    return false;
  return directMemberForObject(Compare->getLHS(), Alias) ==
             Count->getCanonicalDecl() &&
         directMemberForObject(Compare->getRHS(), Alias) ==
             Capacity->getCanonicalDecl();
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

static bool isExactScalarField(const InitListExpr *Field,
                               VMStateFieldLayout Layout, uint64_t Flags,
                               const FieldDecl *Target,
                               VMStateInfoKind RequiredInfo, ASTContext &Ctx) {
  constexpr uint64_t VMSSingle = 0x001;
  constexpr uint64_t VMSPointer = 0x002;
  constexpr uint64_t VMSArray = 0x004;
  constexpr uint64_t VMSStruct = 0x008;
  constexpr uint64_t VMSNoState = 0x080;
  constexpr uint64_t ModernVArray = 0x010;
  constexpr uint64_t LegacyVArrayMask = 0x010 | 0x080 | 0x400 | 0x800;

  uint64_t VArrayFlags = Layout == VMStateFieldLayout::ModernIndirect
                             ? ModernVArray
                             : LegacyVArrayMask;
  std::optional<uint64_t> Size =
      unsignedIntegerValue(fieldInitializer(Field, "size"), Ctx);
  return directOffsetField(fieldInitializer(Field, "offset")) == Target &&
         !Target->getParent()->isUnion() &&
         !(Flags &
           (VMSPointer | VMSArray | VMSStruct | VArrayFlags |
            (Layout == VMStateFieldLayout::ModernIndirect ? VMSNoState : 0))) &&
         (Flags & VMSSingle) && Size &&
         *Size ==
             static_cast<uint64_t>(
                 Ctx.getTypeSizeInChars(Target->getType()).getQuantity()) &&
         classifyVMStateInfo(fieldInitializer(Field, "info")) == RequiredInfo;
}

class QEMUMigrationConsistencyChecker
    : public Checker<check::ASTDecl<TranslationUnitDecl>> {
  bool EnableInlineVArrayDiagnostics = false;
  bool EnableFlexibleVArrayDiagnostics = false;
  bool EnablePointerVArrayDiagnostics = false;
  std::string ReachablePointerVArrayDescriptions;

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

  void reportPointerArrayCount(const VarDecl *Description, const Expr *Where,
                               const FieldDecl *Count,
                               const PointerAllocationContract &Contract,
                               bool HasCapacityEquality,
                               bool HasUpperBoundValidation,
                               BugReporter &BR) const {
    llvm::SmallString<320> Buffer;
    llvm::raw_svector_ostream Message(Buffer);
    Message << '[' << PointerVArrayRuleID << "] migration-loaded count '"
            << Count->getName() << "' controls preallocated pointer array '"
            << Contract.Array->getName() << "' whose destination capacity is '"
            << Contract.Capacity->getName() << "'; before the array, the "
            << (HasCapacityEquality ? "capacity equality is present"
                                    : "capacity equality is missing")
            << " and the "
            << (HasUpperBoundValidation
                    ? "count-to-capacity upper-bound validation is present"
                    : "count-to-capacity upper-bound validation is missing");

    const SourceManager &SM = BR.getSourceManager();
    SourceLocation Location = SM.getExpansionLoc(Where->getExprLoc());
    BR.EmitBasicReport(
        Description, this,
        "Migration count can exceed preallocated pointer-array capacity",
        "QEMU migration", Message.str(), PathDiagnosticLocation(Location, SM),
        {Where->getSourceRange(), Contract.Allocation->getSourceRange()});
  }

  bool isPointerDescriptionReachable(
      const VarDecl *Description,
      const llvm::DenseSet<const VarDecl *> &Reachable) const {
    if (Reachable.contains(Description->getCanonicalDecl()))
      return true;

    StringRef Remaining = ReachablePointerVArrayDescriptions;
    while (!Remaining.empty()) {
      auto [Name, Rest] = Remaining.split(';');
      if (Name.trim() == Description->getName())
        return true;
      Remaining = Rest;
    }
    return false;
  }

  void checkPointerArrayCounts(
      const VarDecl *Description, const Expr *FieldsExpr,
      int64_t MaximumVersion,
      const llvm::SmallVectorImpl<PointerAllocationContract> &Contracts,
      const llvm::DenseSet<const VarDecl *> &Reachable, BugReporter &BR) const {
    if (!isPointerDescriptionReachable(Description, Reachable))
      return;

    const InitListExpr *DescriptionInit =
        semanticInitList(Description->getInit());
    ASTContext &Ctx = Description->getASTContext();
    if (!isExactPointerVMStateDescriptionInit(DescriptionInit, Ctx) ||
        !isNullInitializer(fieldInitializer(DescriptionInit, "pre_load"),
                           Ctx) ||
        !isNullInitializer(fieldInitializer(DescriptionInit, "pre_load_errp"),
                           Ctx))
      return;

    const InitListExpr *Fields = arrayInitializer(FieldsExpr);
    if (!Fields)
      return;

    constexpr uint64_t VMSPointer = 0x002;
    constexpr uint64_t VMSArrayOfPointer = 0x040;
    constexpr uint64_t VMSNoState = 0x080;
    constexpr uint64_t VMSMustExist = 0x1000;
    constexpr uint64_t VMSAlloc = 0x2000;
    constexpr uint64_t VMSArrayOfPointerAutoAlloc = 0x10000;

    for (const Expr *CandidateEntry : Fields->inits()) {
      const InitListExpr *Candidate = semanticInitList(CandidateEntry);
      if (!isExactVMStateFieldInit(Candidate, Ctx))
        continue;
      std::optional<uint64_t> CandidateFlags =
          unsignedIntegerValue(fieldInitializer(Candidate, "flags"), Ctx);
      VMStateFieldLayout CandidateLayout = fieldLayout(Candidate);
      if (!CandidateFlags ||
          CandidateLayout == VMStateFieldLayout::Unsupported ||
          !isVArray(CandidateLayout, *CandidateFlags) ||
          !(*CandidateFlags & VMSPointer) || (*CandidateFlags & VMSAlloc))
        continue;
      if ((*CandidateFlags & VMSArrayOfPointerAutoAlloc) &&
          !(*CandidateFlags & VMSArrayOfPointer))
        continue;

      const Expr *Predicate = fieldInitializer(Candidate, "field_exists");
      std::optional<int64_t> Version =
          integerValue(fieldInitializer(Candidate, "version_id"), Ctx);
      if (!isNullInitializer(Predicate, Ctx) || !Version || *Version < 0 ||
          *Version > MaximumVersion)
        continue;

      const FieldDecl *Array =
          directOffsetField(fieldInitializer(Candidate, "offset"));
      std::optional<VArrayCountDescriptor> CountDescriptor =
          varrayCountDescriptor(Candidate, CandidateLayout, *CandidateFlags,
                                Ctx);
      const FieldDecl *Count = CountDescriptor
                                   ? directOffsetField(CountDescriptor->Offset)
                                   : nullptr;
      if (!Array || !Count || !Array->getType()->isPointerType() ||
          Array->getParent()->isUnion() || Count->getParent()->isUnion() ||
          Array->getParent()->getCanonicalDecl() !=
              Count->getParent()->getCanonicalDecl() ||
          CountDescriptor->Bytes !=
              Ctx.getTypeSizeInChars(Count->getType()).getQuantity())
        continue;

      const PointerAllocationContract *Contract = nullptr;
      for (const PointerAllocationContract &CandidateContract : Contracts) {
        if (CandidateContract.Array != Array->getCanonicalDecl())
          continue;
        if (Contract) {
          Contract = nullptr;
          break;
        }
        Contract = &CandidateContract;
      }
      std::optional<uint64_t> ElementBytes =
          unsignedIntegerValue(fieldInitializer(Candidate, "size"), Ctx);
      bool ElementSizeMatches =
          Contract && ElementBytes && *ElementBytes == Contract->ElementBytes;
      if (Contract && (*CandidateFlags & VMSArrayOfPointer)) {
        QualType PointerElement = Array->getType()->getPointeeType();
        ElementSizeMatches =
            PointerElement->isPointerType() &&
            (!(*CandidateFlags & VMSArrayOfPointerAutoAlloc) ||
             (ElementBytes &&
              !PointerElement->getPointeeType()->isIncompleteType() &&
              *ElementBytes ==
                  static_cast<uint64_t>(
                      Ctx.getTypeSizeInChars(PointerElement->getPointeeType())
                          .getQuantity())));
      }
      if (!Contract || !ElementSizeMatches ||
          Contract->Capacity->getParent()->getCanonicalDecl() !=
              Array->getParent()->getCanonicalDecl() ||
          !Count->getType()->isUnsignedIntegerType())
        continue;

      bool CountLoaded = false;
      bool CapacityEqual = false;
      bool UpperBoundValidated = false;
      bool Unsupported = false;
      for (const Expr *Entry : Fields->inits()) {
        const InitListExpr *Field = semanticInitList(Entry);
        if (Field == Candidate)
          break;
        if (!isExactVMStateFieldInit(Field, Ctx)) {
          Unsupported = true;
          break;
        }
        std::optional<uint64_t> Flags =
            unsignedIntegerValue(fieldInitializer(Field, "flags"), Ctx);
        VMStateFieldLayout Layout = fieldLayout(Field);
        if (!Flags || Layout == VMStateFieldLayout::Unsupported) {
          Unsupported = true;
          break;
        }

        std::optional<int64_t> FieldVersion =
            integerValue(fieldInitializer(Field, "version_id"), Ctx);
        if (!FieldVersion || *FieldVersion < 0) {
          Unsupported = true;
          break;
        }
        if (*FieldVersion > MaximumVersion)
          continue;

        bool IsValidator = Layout == VMStateFieldLayout::ModernIndirect &&
                           (*Flags & (VMSNoState | VMSMustExist)) ==
                               (VMSNoState | VMSMustExist);
        if (IsValidator || isLegacyValidator(Field, *Flags, Ctx)) {
          const Expr *Validator = fieldInitializer(Field, "field_exists");
          if (validatorProvesUpperBound(Validator, Count, Contract->Capacity,
                                        Ctx)) {
            if (CountLoaded)
              UpperBoundValidated = true;
            continue;
          }
          std::optional<llvm::DenseSet<const FieldDecl *>> Referenced =
              validatorReferencedFields(Validator);
          if (!Referenced || Referenced->contains(Count->getCanonicalDecl()) ||
              Referenced->contains(Contract->Capacity)) {
            Unsupported = true;
            break;
          }
          continue;
        }

        if (!isNullInitializer(fieldInitializer(Field, "field_exists"), Ctx)) {
          Unsupported = true;
          break;
        }

        const FieldDecl *Target =
            directOffsetField(fieldInitializer(Field, "offset"));
        if (Target == Count->getCanonicalDecl()) {
          if (isExactScalarField(Field, Layout, *Flags, Count,
                                 VMStateInfoKind::OrdinaryInteger, Ctx)) {
            CountLoaded = true;
            UpperBoundValidated = false;
          } else if (!isExactScalarField(Field, Layout, *Flags, Count,
                                         VMStateInfoKind::EqualInteger, Ctx)) {
            Unsupported = true;
            break;
          }
          continue;
        }
        if (Target == Contract->Capacity) {
          if (isExactScalarField(Field, Layout, *Flags, Contract->Capacity,
                                 VMStateInfoKind::EqualInteger, Ctx)) {
            CapacityEqual = true;
          } else if (isExactScalarField(
                         Field, Layout, *Flags, Contract->Capacity,
                         VMStateInfoKind::OrdinaryInteger, Ctx)) {
            CapacityEqual = false;
            UpperBoundValidated = false;
          } else {
            Unsupported = true;
            break;
          }
          continue;
        }
        if (!Target && !isExactUnusedBuffer(Field, *Flags, Ctx)) {
          Unsupported = true;
          break;
        }
        if (Target && classifyVMStateInfo(fieldInitializer(Field, "info")) ==
                          VMStateInfoKind::Unsupported) {
          Unsupported = true;
          break;
        }
      }

      if (!Unsupported && CountLoaded &&
          !(CapacityEqual && UpperBoundValidated))
        reportPointerArrayCount(Description, CountDescriptor->Offset, Count,
                                *Contract, CapacityEqual, UpperBoundValidated,
                                BR);
    }
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
      const llvm::SmallVectorImpl<PointerAllocationContract> &PointerContracts,
      const llvm::DenseSet<const VarDecl *> &ReachableDescriptions,
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
    if (EnablePointerVArrayDiagnostics)
      checkPointerArrayCounts(VD, Fields, *Version, PointerContracts,
                              ReachableDescriptions, BR);
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

  void setEnablePointerVArrayDiagnostics(bool Enable) {
    EnablePointerVArrayDiagnostics = Enable;
  }

  void setReachablePointerVArrayDescriptions(StringRef Descriptions) {
    ReachablePointerVArrayDescriptions = std::string(Descriptions);
  }

  void checkASTDecl(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                    BugReporter &BR) const {
    llvm::SmallVector<FlexibleAllocationContract, 4> Contracts;
    if (EnableFlexibleVArrayDiagnostics)
      Contracts = collectFlexibleAllocationContracts(TU, Mgr.getASTContext());
    llvm::SmallVector<PointerAllocationContract, 8> PointerContracts;
    llvm::DenseSet<const VarDecl *> ReachableDescriptions;
    if (EnablePointerVArrayDiagnostics) {
      PointerContracts =
          collectPointerAllocationContracts(TU, Mgr.getASTContext());
      ReachableDescriptions = collectReachableVMStateDescriptions(TU);
    }
    class DescriptionVisitor : public DynamicRecursiveASTVisitor {
      const QEMUMigrationConsistencyChecker &Checker;
      const llvm::SmallVectorImpl<FlexibleAllocationContract> &Contracts;
      const llvm::SmallVectorImpl<PointerAllocationContract> &PointerContracts;
      const llvm::DenseSet<const VarDecl *> &ReachableDescriptions;
      BugReporter &BR;

    public:
      DescriptionVisitor(
          const QEMUMigrationConsistencyChecker &Checker,
          const llvm::SmallVectorImpl<FlexibleAllocationContract> &Contracts,
          const llvm::SmallVectorImpl<PointerAllocationContract>
              &PointerContracts,
          const llvm::DenseSet<const VarDecl *> &ReachableDescriptions,
          BugReporter &BR)
          : Checker(Checker), Contracts(Contracts),
            PointerContracts(PointerContracts),
            ReachableDescriptions(ReachableDescriptions), BR(BR) {}

      bool VisitVarDecl(VarDecl *VD) override {
        if (VD->hasInit())
          Checker.checkDescription(VD, Contracts, PointerContracts,
                                   ReachableDescriptions, BR);
        return true;
      }
    } Visitor(*this, Contracts, PointerContracts, ReachableDescriptions, BR);
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
  Checker->setEnablePointerVArrayDiagnostics(
      Mgr.getAnalyzerOptions().getCheckerBooleanOption(
          Checker, "EnablePointerVArrayDiagnostics"));
  Checker->setReachablePointerVArrayDescriptions(
      Mgr.getAnalyzerOptions().getCheckerStringOption(
          Checker, "ReachablePointerVArrayDescriptions"));
}

bool ento::shouldRegisterQEMUMigrationConsistencyChecker(
    const CheckerManager &Mgr) {
  return true;
}
