//===- QEMUIOMMUNotifierLifetimeChecker.cpp ---------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Model the same-path lifetime of QEMU IOMMU notifier registrations.  A
// notifier becomes active only when memory_region_register_iommu_notifier()
// returns zero.  Unregister removes the notifier node even if its MemoryRegion
// argument is wrong; that mismatch is diagnosed before the active record is
// retired.  This deliberately does not infer cross-entry-point state.
//
//===----------------------------------------------------------------------===//

#include "QEMUContractCatalog.inc"
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include <algorithm>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <string>

using namespace clang;
using namespace ento;

namespace clang::ento {
void registerQEMUIOMMUNotifierLifetimeChecker(CheckerManager &Mgr);
bool shouldRegisterQEMUIOMMUNotifierLifetimeChecker(const CheckerManager &Mgr);
} // namespace clang::ento

namespace {

struct IOMMURegistrationKey {
  const MemRegion *MemoryRegion = nullptr;
  const MemRegion *Notifier = nullptr;

  bool operator<(const IOMMURegistrationKey &Other) const {
    if (MemoryRegion != Other.MemoryRegion)
      return std::less<const MemRegion *>()(MemoryRegion, Other.MemoryRegion);
    return std::less<const MemRegion *>()(Notifier, Other.Notifier);
  }

  bool operator==(const IOMMURegistrationKey &Other) const {
    return MemoryRegion == Other.MemoryRegion && Notifier == Other.Notifier;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(MemoryRegion);
    ID.AddPointer(Notifier);
  }
};

enum class IOMMUCallKind {
  None,
  Initialize,
  Register,
  Unregister,
};

struct GArrayDescriptor {
  const FieldDecl *Data = nullptr;
  const FieldDecl *Length = nullptr;

  explicit operator bool() const { return Data && Length; }
};

struct IOMMUCallDescriptor {
  IOMMUCallKind Kind = IOMMUCallKind::None;
  unsigned NotifierArgument = 0;
  std::optional<unsigned> MemoryRegionArgument;
  std::optional<unsigned> CallbackArgument;
};

static std::string normalizeCatalogType(StringRef Type) {
  std::string Normalized;
  Normalized.reserve(Type.size());
  for (size_t I = 0; I != Type.size();) {
    if (llvm::isSpace(Type[I])) {
      ++I;
      continue;
    }
    if (Type.substr(I).starts_with("_Bool")) {
      size_t End = I + StringRef("_Bool").size();
      bool BeginsToken =
          I == 0 || (!llvm::isAlnum(Type[I - 1]) && Type[I - 1] != '_');
      bool EndsToken =
          End == Type.size() || (!llvm::isAlnum(Type[End]) && Type[End] != '_');
      if (BeginsToken && EndsToken) {
        Normalized += "bool";
        I = End;
        continue;
      }
    }
    Normalized.push_back(Type[I++]);
  }
  return Normalized;
}

static bool catalogTypeMatches(QualType Actual, StringRef Expected) {
  return normalizeCatalogType(Actual.getAsString()) ==
         normalizeCatalogType(Expected);
}

static bool catalogRangeIsValid(unsigned Begin, unsigned Count,
                                unsigned Total) {
  return Begin <= Total && Count <= Total - Begin;
}

static bool catalogPrototypeMatches(
    const FunctionDecl *FD,
    const qemu_contracts_generated::ContractRecord &Contract) {
  if (!FD || !FD->getIdentifier() ||
      !FD->getDeclContext()->getRedeclContext()->isTranslationUnit() ||
      !FD->getLexicalDeclContext()->getRedeclContext()->isTranslationUnit() ||
      FD->isVariadic() || FD->getNumParams() != Contract.ParameterCount ||
      !catalogTypeMatches(FD->getReturnType(), Contract.ReturnType) ||
      !catalogRangeIsValid(Contract.ParameterBegin, Contract.ParameterCount,
                           qemu_contracts_generated::ParameterRecordCount))
    return false;

  for (unsigned I = 0; I != Contract.ParameterCount; ++I) {
    const auto &Parameter =
        qemu_contracts_generated::Parameters[Contract.ParameterBegin + I];
    if (StringRef(Parameter.ContractID) != Contract.ID ||
        Parameter.Index != I ||
        !catalogTypeMatches(FD->getParamDecl(I)->getType(), Parameter.Type))
      return false;
  }
  return true;
}

static const qemu_contracts_generated::OperandRecord *
catalogOperand(const qemu_contracts_generated::ContractRecord &Contract,
               StringRef Role) {
  if (!catalogRangeIsValid(Contract.OperandBegin, Contract.OperandCount,
                           qemu_contracts_generated::OperandRecordCount))
    return nullptr;
  const qemu_contracts_generated::OperandRecord *Found = nullptr;
  for (unsigned I = Contract.OperandBegin,
                E = Contract.OperandBegin + Contract.OperandCount;
       I != E; ++I) {
    const auto &Operand = qemu_contracts_generated::Operands[I];
    if (StringRef(Operand.ContractID) != Contract.ID ||
        StringRef(Operand.Role) != Role)
      continue;
    if (Found)
      return nullptr;
    Found = &Operand;
  }
  return Found;
}

static bool
catalogEffectMatches(const qemu_contracts_generated::ContractRecord &Contract,
                     StringRef Kind) {
  if (Contract.EffectCount != 1 ||
      !catalogRangeIsValid(Contract.EffectBegin, Contract.EffectCount,
                           qemu_contracts_generated::EffectRecordCount))
    return false;
  const auto &Effect = qemu_contracts_generated::Effects[Contract.EffectBegin];
  if (StringRef(Effect.ContractID) != Contract.ID ||
      StringRef(Effect.Kind) != Kind || StringRef(Effect.When) != "success" ||
      StringRef(Effect.Target) != "notifier")
    return false;
  if (Kind == "initialize-resource")
    return StringRef(Effect.Callback) == "callback" &&
           StringRef(Effect.MemoryRegion).empty() &&
           StringRef(Effect.Epoch) == "create";
  return StringRef(Effect.Callback).empty() &&
         StringRef(Effect.MemoryRegion) == "memory_region" &&
         StringRef(Effect.Epoch) ==
             (Kind == "register-callback" ? "create" : "retire");
}

static bool
catalogOutcomeMatches(const qemu_contracts_generated::ContractRecord &Contract,
                      StringRef Kind) {
  constexpr llvm::StringLiteral Always = "{\"constant\":true}";
  constexpr llvm::StringLiteral Never = "{\"constant\":false}";
  constexpr llvm::StringLiteral Zero =
      "{\"operand\":\"result\",\"operator\":\"eq\",\"rhs\":{\"integer\":0}}";
  constexpr llvm::StringLiteral NonZero =
      "{\"operand\":\"result\",\"operator\":\"ne\",\"rhs\":{\"integer\":0}}";
  if (StringRef(Contract.PartialSuccessPredicateJSON) != Never)
    return false;
  if (Kind == "register-callback")
    return StringRef(Contract.SuccessPredicateJSON) == Zero &&
           StringRef(Contract.FailurePredicateJSON) == NonZero &&
           StringRef(Contract.PairID) == "qemu.iommu.notifier-unregister" &&
           StringRef(Contract.PairRelation) ==
               "register-callback-to-unregister-callback";
  if (Kind == "initialize-resource")
    return StringRef(Contract.SuccessPredicateJSON) == Always &&
           StringRef(Contract.FailurePredicateJSON) == Never &&
           StringRef(Contract.PairID).empty() &&
           StringRef(Contract.PairRelation).empty();
  return Kind == "unregister-callback" &&
         StringRef(Contract.SuccessPredicateJSON) == Always &&
         StringRef(Contract.FailurePredicateJSON) == Never &&
         StringRef(Contract.PairID) == "qemu.iommu.notifier-register" &&
         StringRef(Contract.PairRelation) ==
             "unregister-callback-to-register-callback";
}

static std::optional<unsigned>
argumentForRole(const qemu_contracts_generated::ContractRecord &Contract,
                StringRef Role) {
  const auto *Operand = catalogOperand(Contract, Role);
  if (!Operand || StringRef(Operand->Source) != "argument" ||
      StringRef(Operand->Phase) != "pre" || Operand->ArgumentIndex < 0)
    return std::nullopt;
  return static_cast<unsigned>(Operand->ArgumentIndex);
}

static IOMMUCallDescriptor classifyIOMMUCall(const FunctionDecl *FD) {
  if (!FD || !FD->getIdentifier())
    return {};
  for (const auto &Contract : qemu_contracts_generated::Contracts) {
    StringRef Kind = Contract.Kind;
    if (StringRef(Contract.Family) != "iommu-notifier" ||
        StringRef(Contract.RuleID) != "qemu.iommu-notifier-lifetime" ||
        StringRef(Contract.SelectorName) != FD->getName() ||
        !catalogPrototypeMatches(FD, Contract) ||
        !catalogEffectMatches(Contract, Kind) ||
        !catalogOutcomeMatches(Contract, Kind))
      continue;

    std::optional<unsigned> Notifier = argumentForRole(Contract, "notifier");
    if (!Notifier)
      return {};
    if (Kind == "initialize-resource") {
      std::optional<unsigned> Callback = argumentForRole(Contract, "callback");
      if (!Callback)
        return {};
      return {IOMMUCallKind::Initialize, *Notifier, std::nullopt, Callback};
    }
    std::optional<unsigned> MemoryRegion =
        argumentForRole(Contract, "memory_region");
    if (!MemoryRegion)
      return {};
    if (Kind == "register-callback")
      return {IOMMUCallKind::Register, *Notifier, MemoryRegion, std::nullopt};
    if (Kind == "unregister-callback")
      return {IOMMUCallKind::Unregister, *Notifier, MemoryRegion, std::nullopt};
  }
  return {};
}

static const FunctionDecl *directCallee(const CallEvent &Call) {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  return FD && FD->getIdentifier() ? FD : nullptr;
}

static const MemRegion *objectRegion(SVal Value) {
  const MemRegion *Region = Value.getAsRegion();
  return Region ? Region->getBaseRegion() : nullptr;
}

static const MemRegion *notifierOwner(const MemRegion *Notifier) {
  if (!Notifier)
    return nullptr;
  if (const auto *Field = dyn_cast<FieldRegion>(Notifier))
    return Field->getSuperRegion()->getBaseRegion();
  return Notifier->getBaseRegion();
}

static QualType regionValueType(const MemRegion *Region) {
  if (!Region)
    return {};
  Region = Region->StripCasts();
  if (const auto *Typed = dyn_cast<TypedValueRegion>(Region))
    return Typed->getValueType();
  if (const auto *Symbolic = dyn_cast<SymbolicRegion>(Region))
    return Symbolic->getPointeeStaticType();
  return {};
}

static const FieldDecl *findOpaqueField(const MemRegion *Notifier) {
  QualType Type = regionValueType(Notifier);
  const RecordDecl *Record = Type.isNull() ? nullptr : Type->getAsRecordDecl();
  if (!Record)
    return nullptr;
  for (const FieldDecl *Field : Record->fields())
    if (Field->getName() == "opaque" && Field->getType()->isPointerType())
      return Field;
  return nullptr;
}

static const FieldDecl *findPointerField(const MemRegion *Object,
                                         StringRef RecordName,
                                         StringRef FieldName) {
  QualType Type = regionValueType(Object);
  const RecordDecl *Record = Type.isNull() ? nullptr : Type->getAsRecordDecl();
  if (!Record || Record->getName() != RecordName)
    return nullptr;
  for (const FieldDecl *Field : Record->fields())
    if (Field->getName() == FieldName && Field->getType()->isPointerType())
      return Field;
  return nullptr;
}

static const MemRegion *notifierOpaque(ProgramStateRef State,
                                       const MemRegion *Notifier) {
  const FieldDecl *Opaque = findOpaqueField(Notifier);
  if (!Opaque)
    return nullptr;
  SVal Location = State->getLValue(Opaque, loc::MemRegionVal(Notifier));
  std::optional<Loc> FieldLocation = Location.getAs<Loc>();
  if (!FieldLocation)
    return nullptr;
  return objectRegion(State->getSVal(*FieldLocation));
}

// MemoryRegion aliases are recursively resolved by the real register and
// unregister functions.  A distinct C object is therefore not enough to prove
// that two API arguments denote distinct notifier lists.  Return a region only
// when every alias link through the terminal non-alias region is known.
static std::optional<const MemRegion *>
resolveMemoryRegionAlias(ProgramStateRef State, const MemRegion *Region) {
  llvm::SmallVector<const MemRegion *, 8> Seen;
  for (unsigned Depth = 0; Region && Depth != 16; ++Depth) {
    Region = Region->StripCasts();
    if (std::find(Seen.begin(), Seen.end(), Region) != Seen.end())
      return std::nullopt;
    Seen.push_back(Region);

    const FieldDecl *Alias = findPointerField(Region, "MemoryRegion", "alias");
    if (!Alias)
      return std::nullopt;
    SVal Location = State->getLValue(Alias, loc::MemRegionVal(Region));
    std::optional<Loc> FieldLocation = Location.getAs<Loc>();
    if (!FieldLocation)
      return std::nullopt;
    SVal Value = State->getSVal(*FieldLocation);
    ConditionTruthVal Nullness = State->isNull(Value);
    if (Nullness.isConstrainedTrue())
      return Region;
    const MemRegion *Next = Value.getAsRegion();
    if (!Next)
      return std::nullopt;
    // The constraint manager does not classify addresses of concrete regions
    // (for example, &local) as constrained non-null.  They are nevertheless
    // definite addresses.  A bare SymbolicRegion remains possibly null unless
    // the constraint manager proved otherwise.
    if (!Nullness.isConstrainedFalse() &&
        isa<SymbolicRegion>(Next->StripCasts()))
      return std::nullopt;
    Region = Next;
  }
  return std::nullopt;
}

static SymbolRef regionSymbol(const MemRegion *Region) {
  if (!Region)
    return nullptr;
  const SymbolicRegion *Symbolic = Region->getSymbolicBase();
  return Symbolic ? Symbolic->getSymbol() : nullptr;
}

static bool isReleaseFunction(const FunctionDecl *FD) {
  if (!FD || !FD->getIdentifier() || FD->isVariadic() ||
      FD->getNumParams() != 1 || !FD->getReturnType()->isVoidType() ||
      !FD->getParamDecl(0)->getType()->isPointerType())
    return false;
  StringRef Name = FD->getName();
  return Name == "g_free" || Name == "free" || Name.starts_with("qapi_free_");
}

static bool declarationPathEndsWith(const Decl *Declaration, StringRef Suffix,
                                    const SourceManager &SM) {
  if (!Declaration)
    return false;
  PresumedLoc Location = SM.getPresumedLoc(Declaration->getLocation());
  if (Location.isInvalid())
    return false;
  StringRef Path = Location.getFilename();
  return Path == Suffix ||
         (Path.size() > Suffix.size() && Path.ends_with(Suffix) &&
          (Path[Path.size() - Suffix.size() - 1] == '/' ||
           Path[Path.size() - Suffix.size() - 1] == '\\'));
}

static GArrayDescriptor classifyGArraySetSize(const FunctionDecl *FD,
                                              ASTContext &Ctx,
                                              const SourceManager &SM) {
  constexpr llvm::StringLiteral Header = "glib/garray.h";
  if (!FD || !FD->getIdentifier() || FD->getName() != "g_array_set_size" ||
      !FD->getDeclContext()->getRedeclContext()->isTranslationUnit() ||
      !FD->getLexicalDeclContext()->getRedeclContext()->isTranslationUnit() ||
      FD->isVariadic() || FD->getNumParams() != 2 ||
      !FD->getReturnType()->isPointerType() ||
      !FD->getParamDecl(0)->getType()->isPointerType() ||
      !Ctx.hasSameType(FD->getReturnType(), FD->getParamDecl(0)->getType()) ||
      !Ctx.hasSameType(FD->getParamDecl(1)->getType().getUnqualifiedType(),
                       Ctx.UnsignedIntTy) ||
      !declarationPathEndsWith(FD, Header, SM))
    return {};

  QualType ArrayType = FD->getParamDecl(0)->getType()->getPointeeType();
  const RecordDecl *Array = ArrayType->getAsRecordDecl();
  if (!Array)
    return {};
  if (const RecordDecl *Definition = Array->getDefinition())
    Array = Definition;
  if (Array->getName() != "_GArray" ||
      !declarationPathEndsWith(Array, Header, SM))
    return {};

  GArrayDescriptor Descriptor;
  for (const FieldDecl *Field : Array->fields()) {
    if (Field->getName() == "data" && Field->getType()->isPointerType() &&
        Ctx.hasSameType(Field->getType()->getPointeeType().getUnqualifiedType(),
                        Ctx.CharTy) &&
        declarationPathEndsWith(Field, Header, SM))
      Descriptor.Data = Field;
    else if (Field->getName() == "len" &&
             Ctx.hasSameType(Field->getType().getUnqualifiedType(),
                             Ctx.UnsignedIntTy) &&
             declarationPathEndsWith(Field, Header, SM))
      Descriptor.Length = Field;
  }
  return Descriptor;
}

static const MemRegion *gArrayDataRegion(ProgramStateRef State,
                                         const MemRegion *Array,
                                         const FieldDecl *Data) {
  if (!Array || !Data)
    return nullptr;
  SVal Location = State->getLValue(Data, loc::MemRegionVal(Array));
  std::optional<Loc> DataLocation = Location.getAs<Loc>();
  if (!DataLocation)
    return nullptr;
  return objectRegion(State->getSVal(*DataLocation));
}

static ProgramStateRef gArrayGrowthState(const CallEvent &Call,
                                         const GArrayDescriptor &Descriptor,
                                         ProgramStateRef State,
                                         CheckerContext &C) {
  if (!Descriptor || Call.getNumArgs() != 2)
    return nullptr;
  const MemRegion *Array = Call.getArgSVal(0).getAsRegion();
  if (!Array)
    return nullptr;
  SVal LengthLocation =
      State->getLValue(Descriptor.Length, loc::MemRegionVal(Array));
  std::optional<Loc> LengthLoc = LengthLocation.getAs<Loc>();
  if (!LengthLoc)
    return nullptr;
  SVal OldLength = State->getSVal(*LengthLoc);
  SVal NewLength = Call.getArgSVal(1);
  if (OldLength.isUnknownOrUndef() || NewLength.isUnknownOrUndef())
    return nullptr;

  const Expr *NewLengthExpr = Call.getArgExpr(1)->IgnoreParenImpCasts();
  if (const auto *Subtract = dyn_cast<BinaryOperator>(NewLengthExpr)) {
    if (Subtract->getOpcode() == BO_Sub) {
      SVal Base = C.getSVal(Subtract->getLHS());
      SVal SameBase = C.getSValBuilder().evalEQ(State, Base, OldLength);
      std::optional<DefinedOrUnknownSVal> SameCondition =
          SameBase.getAs<DefinedOrUnknownSVal>();
      if (SameCondition) {
        auto [Same, Different] = State->assume(*SameCondition);
        if (!Same || Different)
          return nullptr;
        SVal Amount = C.getSVal(Subtract->getRHS());
        SVal Underflows = C.getSValBuilder().evalBinOp(
            Same, BO_LT, OldLength, Amount, C.getASTContext().BoolTy);
        std::optional<DefinedOrUnknownSVal> UnderflowCondition =
            Underflows.getAs<DefinedOrUnknownSVal>();
        if (UnderflowCondition) {
          auto [Underflow, NoUnderflow] = Same->assume(*UnderflowCondition);
          if (!Underflow && NoUnderflow)
            return nullptr;
        }
      }
    }
  }

  SVal Greater = C.getSValBuilder().evalBinOp(
      State, BO_GT, NewLength, OldLength, C.getASTContext().BoolTy);
  std::optional<DefinedOrUnknownSVal> Condition =
      Greater.getAs<DefinedOrUnknownSVal>();
  if (!Condition)
    return nullptr;
  auto [Growth, NoGrowth] = State->assume(*Condition);
  return Growth;
}

} // namespace

REGISTER_SET_WITH_PROGRAMSTATE(QEMUIOMMUInitializedNotifiers, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUIOMMUInitializedCallbacks, const MemRegion *,
                               const FunctionDecl *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUIOMMUInitializationOrigins,
                               const MemRegion *, const Expr *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUIOMMUInitializedOpaques, const MemRegion *,
                               const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUIOMMUNextEpochs, const MemRegion *, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUIOMMUPendingInitializationOpaques,
                               const Expr *, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUIOMMUPendingRegistrationOpaques,
                               const Expr *, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUIOMMUPendingRegistrationMemoryRegions,
                               const Expr *, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(QEMUIOMMUPendingPreciseOpaqueBinds,
                               const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(QEMUIOMMUActiveRegistrations,
                               IOMMURegistrationKey)
REGISTER_SET_WITH_PROGRAMSTATE(QEMUIOMMURetiredRegistrations,
                               IOMMURegistrationKey)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUIOMMURegistrationOwners,
                               IOMMURegistrationKey, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUIOMMURegistrationOpaques,
                               IOMMURegistrationKey, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUIOMMURegistrationCallbacks,
                               IOMMURegistrationKey, const FunctionDecl *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUIOMMURegistrationOrigins,
                               IOMMURegistrationKey, const Expr *)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUIOMMURegistrationEpochs,
                               IOMMURegistrationKey, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(QEMUIOMMURegistrationMemoryRegions,
                               IOMMURegistrationKey, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(QEMUIOMMUInvalidatedRegistrationAliases,
                               IOMMURegistrationKey)

namespace {

static ProgramStateRef retireRegistration(ProgramStateRef State,
                                          IOMMURegistrationKey Key) {
  return State->remove<QEMUIOMMUActiveRegistrations>(Key)
      ->add<QEMUIOMMURetiredRegistrations>(Key)
      ->remove<QEMUIOMMURegistrationOwners>(Key)
      ->remove<QEMUIOMMURegistrationOpaques>(Key)
      ->remove<QEMUIOMMURegistrationCallbacks>(Key)
      ->remove<QEMUIOMMURegistrationOrigins>(Key)
      ->remove<QEMUIOMMURegistrationEpochs>(Key)
      ->remove<QEMUIOMMURegistrationMemoryRegions>(Key)
      ->remove<QEMUIOMMUInvalidatedRegistrationAliases>(Key);
}

static bool definitelyDifferentRegions(ProgramStateRef State,
                                       const MemRegion *Left,
                                       const MemRegion *Right,
                                       CheckerContext &C) {
  if (!Left || !Right || Left == Right)
    return false;
  SVal Equality = C.getSValBuilder().evalEQ(State, loc::MemRegionVal(Left),
                                            loc::MemRegionVal(Right));
  std::optional<DefinedOrUnknownSVal> Condition =
      Equality.getAs<DefinedOrUnknownSVal>();
  if (!Condition)
    return false;
  auto [Equal, Different] = State->assume(*Condition);
  return !Equal && Different;
}

static bool definitelySameRegions(ProgramStateRef State, const MemRegion *Left,
                                  const MemRegion *Right, CheckerContext &C) {
  if (!Left || !Right)
    return false;
  if (Left == Right)
    return true;
  SVal Equality = C.getSValBuilder().evalEQ(State, loc::MemRegionVal(Left),
                                            loc::MemRegionVal(Right));
  std::optional<DefinedOrUnknownSVal> Condition =
      Equality.getAs<DefinedOrUnknownSVal>();
  if (!Condition)
    return false;
  auto [Equal, Different] = State->assume(*Condition);
  return Equal && !Different;
}

static bool registrationMatchesMemoryRegion(ProgramStateRef State,
                                            IOMMURegistrationKey Registration,
                                            const MemRegion *CurrentRaw,
                                            const MemRegion *CurrentResolved,
                                            CheckerContext &C) {
  const MemRegion *const *SavedResolved =
      State->get<QEMUIOMMURegistrationMemoryRegions>(Registration);
  if (SavedResolved && CurrentResolved)
    return definitelySameRegions(State, *SavedResolved, CurrentResolved, C);
  if (State->contains<QEMUIOMMUInvalidatedRegistrationAliases>(Registration))
    return false;
  // A modeled register/unregister may make the generic store forget alias
  // fields even though the exact API does not change them.  Preserve equality
  // when the current raw argument is the saved terminal or the unchanged raw
  // registration root.
  return (SavedResolved &&
          definitelySameRegions(State, *SavedResolved, CurrentRaw, C)) ||
         definitelySameRegions(State, Registration.MemoryRegion, CurrentRaw, C);
}

static ProgramStateRef setNotifierOpaque(ProgramStateRef State,
                                         const MemRegion *Notifier,
                                         const MemRegion *Opaque) {
  if (State->contains<QEMUIOMMUInitializedNotifiers>(Notifier)) {
    if (Opaque)
      State = State->set<QEMUIOMMUInitializedOpaques>(Notifier, Opaque);
    else
      State = State->remove<QEMUIOMMUInitializedOpaques>(Notifier);
  }
  for (IOMMURegistrationKey Key : State->get<QEMUIOMMUActiveRegistrations>()) {
    if (Key.Notifier != Notifier)
      continue;
    if (Opaque)
      State = State->set<QEMUIOMMURegistrationOpaques>(Key, Opaque);
    else
      State = State->remove<QEMUIOMMURegistrationOpaques>(Key);
  }
  return State;
}

static ProgramStateRef abandonNotifierFieldPrecision(ProgramStateRef State,
                                                     const MemRegion *Notifier,
                                                     bool Opaque, bool Callback,
                                                     bool Initialization) {
  if (Opaque)
    State = State->remove<QEMUIOMMUInitializedOpaques>(Notifier);
  if (Callback)
    State = State->remove<QEMUIOMMUInitializedCallbacks>(Notifier);
  if (Initialization) {
    State = State->remove<QEMUIOMMUInitializedNotifiers>(Notifier)
                ->remove<QEMUIOMMUInitializationOrigins>(Notifier);
  }
  for (IOMMURegistrationKey Key : State->get<QEMUIOMMUActiveRegistrations>()) {
    if (Key.Notifier != Notifier)
      continue;
    if (Opaque)
      State = State->remove<QEMUIOMMURegistrationOpaques>(Key);
    if (Callback)
      State = State->remove<QEMUIOMMURegistrationCallbacks>(Key);
  }
  return State;
}

static bool regionsOverlap(const MemRegion *Left, const MemRegion *Right) {
  if (!Left || !Right)
    return false;
  Left = Left->StripCasts();
  Right = Right->StripCasts();
  return Left == Right || Left->isSubRegionOf(Right) ||
         Right->isSubRegionOf(Left);
}

static ProgramStateRef
notePossibleMemoryRegionAliasMutation(ProgramStateRef State) {
  for (IOMMURegistrationKey Key : State->get<QEMUIOMMUActiveRegistrations>())
    State = State->add<QEMUIOMMUInvalidatedRegistrationAliases>(Key);
  return State;
}

static bool isMemoryRegionStorage(const MemRegion *Region) {
  if (!Region)
    return false;
  Region = Region->StripCasts();
  if (const auto *Field = dyn_cast<FieldRegion>(Region)) {
    const RecordDecl *Parent = Field->getDecl()->getParent();
    if (Parent && Parent->getName() == "MemoryRegion")
      return true;
    Region = Field->getSuperRegion()->StripCasts();
  }
  QualType Type = regionValueType(Region);
  const RecordDecl *Record = Type.isNull() ? nullptr : Type->getAsRecordDecl();
  return Record && Record->getName() == "MemoryRegion";
}

class QEMUIOMMUNotifierLifetimeChecker
    : public Checker<check::PreCall, check::PostCall, check::Bind,
                     check::RegionChanges, check::LiveSymbols> {
  const BugType LifetimeBug{this, "Invalid QEMU IOMMU notifier lifetime",
                            "QEMU resource lifetime"};

  bool report(StringRef Message, const Expr *At, const Expr *Origin,
              StringRef OriginNote, ProgramStateRef State,
              CheckerContext &C) const {
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return false;
    auto Report =
        std::make_unique<PathSensitiveBugReport>(LifetimeBug, Message, Node);
    if (At)
      Report->addRange(At->getSourceRange());
    if (Origin)
      Report->addNote(OriginNote,
                      {Origin, C.getSourceManager(), C.getStackFrame()});
    C.emitReport(std::move(Report));
    return true;
  }

  bool reportActiveRelease(const MemRegion *Released, const Expr *At,
                           ProgramStateRef State, CheckerContext &C) const {
    if (!Released)
      return false;
    for (IOMMURegistrationKey Key :
         State->get<QEMUIOMMUActiveRegistrations>()) {
      const MemRegion *const *Owner =
          State->get<QEMUIOMMURegistrationOwners>(Key);
      const MemRegion *const *Opaque =
          State->get<QEMUIOMMURegistrationOpaques>(Key);
      bool ReleasesOwner = Owner && *Owner == Released;
      bool ReleasesOpaque = !ReleasesOwner && Opaque && *Opaque == Released;
      if (!ReleasesOwner && !ReleasesOpaque)
        continue;
      const Expr *Origin = State->get<QEMUIOMMURegistrationOrigins>(Key)
                               ? *State->get<QEMUIOMMURegistrationOrigins>(Key)
                               : nullptr;
      report(ReleasesOwner
                 ? "Object containing an active IOMMU notifier is released "
                   "before the notifier is unregistered"
                 : "IOMMU notifier opaque object is released while its "
                   "callback remains registered",
             At, Origin, "IOMMU notifier registered here", State, C);
      return true;
    }
    return false;
  }

  bool reportActiveInlineGArrayResize(const CallEvent &Call,
                                      const GArrayDescriptor &Descriptor,
                                      ProgramStateRef State,
                                      CheckerContext &C) const {
    ProgramStateRef Growth = gArrayGrowthState(Call, Descriptor, State, C);
    if (!Growth)
      return false;
    const MemRegion *Array = Call.getArgSVal(0).getAsRegion();
    const MemRegion *Data = gArrayDataRegion(Growth, Array, Descriptor.Data);
    if (!Data)
      return false;

    for (IOMMURegistrationKey Key :
         State->get<QEMUIOMMUActiveRegistrations>()) {
      const MemRegion *const *Owner =
          Growth->get<QEMUIOMMURegistrationOwners>(Key);
      if (!Owner || !definitelySameRegions(Growth, *Owner, Data, C))
        continue;
      const Expr *Origin = Growth->get<QEMUIOMMURegistrationOrigins>(Key)
                               ? *Growth->get<QEMUIOMMURegistrationOrigins>(Key)
                               : nullptr;
      return report(
          "Resizing a GArray may relocate storage containing an active "
          "IOMMU notifier",
          Call.getOriginExpr(), Origin, "Inline IOMMU notifier registered here",
          Growth, C);
    }
    return false;
  }

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    const FunctionDecl *FD = directCallee(Call);
    if (!FD)
      return;
    ProgramStateRef State = C.getState();

    GArrayDescriptor GArrayResize =
        classifyGArraySetSize(FD, C.getASTContext(), C.getSourceManager());
    if (GArrayResize &&
        reportActiveInlineGArrayResize(Call, GArrayResize, State, C))
      return;

    IOMMUCallDescriptor Descriptor = classifyIOMMUCall(FD);
    if (Descriptor.Kind == IOMMUCallKind::Initialize &&
        Descriptor.NotifierArgument < Call.getNumArgs()) {
      const MemRegion *Notifier =
          Call.getArgSVal(Descriptor.NotifierArgument).getAsRegion();
      llvm::SmallVector<IOMMURegistrationKey, 2> ActiveForNotifier;
      for (IOMMURegistrationKey Active :
           State->get<QEMUIOMMUActiveRegistrations>())
        if (Notifier &&
            definitelySameRegions(State, Active.Notifier, Notifier, C))
          ActiveForNotifier.push_back(Active);
      if (!ActiveForNotifier.empty()) {
        const Expr *Origin =
            State->get<QEMUIOMMURegistrationOrigins>(ActiveForNotifier.front())
                ? *State->get<QEMUIOMMURegistrationOrigins>(
                      ActiveForNotifier.front())
                : nullptr;
        ProgramStateRef Retired = State;
        for (IOMMURegistrationKey Active : ActiveForNotifier)
          Retired = retireRegistration(Retired, Active);
        if (!report("Active IOMMU notifier is reinitialized before it is "
                    "unregistered",
                    Call.getOriginExpr(), Origin,
                    "IOMMU notifier registered here", Retired, C))
          C.addTransition(Retired);
        return;
      }
      if (const MemRegion *Opaque = notifierOpaque(State, Notifier)) {
        C.addTransition(State->set<QEMUIOMMUPendingInitializationOpaques>(
            Call.getOriginExpr(), Opaque));
        return;
      }
    }

    if (Descriptor.Kind == IOMMUCallKind::Register &&
        Descriptor.NotifierArgument < Call.getNumArgs()) {
      const MemRegion *Notifier =
          Call.getArgSVal(Descriptor.NotifierArgument).getAsRegion();
      if (Notifier &&
          State->contains<QEMUIOMMUInitializedNotifiers>(Notifier)) {
        const MemRegion *MemoryRegion =
            Descriptor.MemoryRegionArgument &&
                    *Descriptor.MemoryRegionArgument < Call.getNumArgs()
                ? Call.getArgSVal(*Descriptor.MemoryRegionArgument)
                      .getAsRegion()
                : nullptr;
        std::optional<const MemRegion *> Resolved =
            resolveMemoryRegionAlias(State, MemoryRegion);
        for (IOMMURegistrationKey Active :
             State->get<QEMUIOMMUActiveRegistrations>()) {
          if (!definitelySameRegions(State, Active.Notifier, Notifier, C))
            continue;
          bool SameRegion = registrationMatchesMemoryRegion(
              State, Active, MemoryRegion, Resolved ? *Resolved : nullptr, C);
          const Expr *Origin =
              State->get<QEMUIOMMURegistrationOrigins>(Active)
                  ? *State->get<QEMUIOMMURegistrationOrigins>(Active)
                  : nullptr;
          report(SameRegion
                     ? "IOMMU notifier is registered twice with the same "
                       "memory region"
                     : "IOMMU notifier is registered again while it is "
                       "already active",
                 Call.getOriginExpr(), Origin,
                 "IOMMU notifier first registered here", State, C);
          return;
        }

        ProgramStateRef Pending = State;
        // Initialization and precise binds maintain this cache.  Reading the
        // store here would mistake a conjured value from generic call
        // invalidation for the notifier's real opaque object.
        if (const MemRegion *const *Opaque =
                State->get<QEMUIOMMUInitializedOpaques>(Notifier))
          Pending = Pending->set<QEMUIOMMUPendingRegistrationOpaques>(
              Call.getOriginExpr(), *Opaque);

        if (Descriptor.MemoryRegionArgument &&
            *Descriptor.MemoryRegionArgument < Call.getNumArgs()) {
          if (Resolved)
            Pending = Pending->set<QEMUIOMMUPendingRegistrationMemoryRegions>(
                Call.getOriginExpr(), *Resolved);
        }
        if (Pending != State)
          C.addTransition(Pending);
        return;
      }
    }

    if (Descriptor.Kind == IOMMUCallKind::Unregister &&
        Descriptor.MemoryRegionArgument &&
        *Descriptor.MemoryRegionArgument < Call.getNumArgs() &&
        Descriptor.NotifierArgument < Call.getNumArgs()) {
      const MemRegion *MemoryRegion =
          Call.getArgSVal(*Descriptor.MemoryRegionArgument).getAsRegion();
      const MemRegion *Notifier =
          Call.getArgSVal(Descriptor.NotifierArgument).getAsRegion();
      if (!MemoryRegion || !Notifier)
        return;

      llvm::SmallVector<IOMMURegistrationKey, 4> Registrations;
      llvm::SmallVector<IOMMURegistrationKey, 4> PossiblyRemoved;
      for (IOMMURegistrationKey Active :
           State->get<QEMUIOMMUActiveRegistrations>()) {
        if (definitelySameRegions(State, Active.Notifier, Notifier, C)) {
          Registrations.push_back(Active);
        } else if (!definitelyDifferentRegions(State, Active.Notifier, Notifier,
                                               C)) {
          PossiblyRemoved.push_back(Active);
        }
      }
      if (Registrations.empty() && PossiblyRemoved.empty())
        return;

      std::optional<const MemRegion *> CurrentResolved =
          resolveMemoryRegionAlias(State, MemoryRegion);
      bool HasSameRegion = false;
      bool HasDefinitelyDifferentRegion = false;
      const Expr *DifferentOrigin = nullptr;
      for (IOMMURegistrationKey Active : Registrations) {
        const MemRegion *const *SavedResolved =
            State->get<QEMUIOMMURegistrationMemoryRegions>(Active);
        bool Same = registrationMatchesMemoryRegion(
            State, Active, MemoryRegion,
            CurrentResolved ? *CurrentResolved : nullptr, C);
        if (Same) {
          HasSameRegion = true;
          continue;
        }
        if (SavedResolved && CurrentResolved &&
            definitelyDifferentRegions(State, *SavedResolved, *CurrentResolved,
                                       C)) {
          HasDefinitelyDifferentRegion = true;
          if (!DifferentOrigin)
            DifferentOrigin =
                State->get<QEMUIOMMURegistrationOrigins>(Active)
                    ? *State->get<QEMUIOMMURegistrationOrigins>(Active)
                    : nullptr;
        }
      }

      // QLIST_REMOVE() removes the notifier node even when the supplied
      // MemoryRegion is wrong.  Retire every modeled registration for this
      // notifier after the call attempt; retain a diagnostic only when both
      // alias chains terminate in definitely distinct regions.
      ProgramStateRef Retired = State;
      for (IOMMURegistrationKey Active : Registrations)
        Retired = retireRegistration(Retired, Active);
      for (IOMMURegistrationKey Active : PossiblyRemoved)
        Retired = retireRegistration(Retired, Active);
      if (!HasSameRegion && HasDefinitelyDifferentRegion) {
        if (!report(
                "IOMMU notifier is unregistered from a different memory region",
                Call.getOriginExpr(), DifferentOrigin,
                "IOMMU notifier registered here", Retired, C))
          C.addTransition(Retired);
        return;
      }
      C.addTransition(Retired);
      return;
    }

    if (isReleaseFunction(FD) && Call.getNumArgs() == 1)
      reportActiveRelease(objectRegion(Call.getArgSVal(0)), Call.getArgExpr(0),
                          State, C);
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const FunctionDecl *FD = directCallee(Call);
    IOMMUCallDescriptor Descriptor = classifyIOMMUCall(FD);
    if (Descriptor.Kind == IOMMUCallKind::None ||
        Descriptor.NotifierArgument >= Call.getNumArgs())
      return;

    const MemRegion *Notifier =
        Call.getArgSVal(Descriptor.NotifierArgument).getAsRegion();
    if (!Notifier)
      return;
    ProgramStateRef State = C.getState();

    if (Descriptor.Kind == IOMMUCallKind::Initialize) {
      const MemRegion *PendingOpaque =
          State->get<QEMUIOMMUPendingInitializationOpaques>(
              Call.getOriginExpr())
              ? *State->get<QEMUIOMMUPendingInitializationOpaques>(
                    Call.getOriginExpr())
              : nullptr;
      State = State->add<QEMUIOMMUInitializedNotifiers>(Notifier)
                  ->set<QEMUIOMMUInitializationOrigins>(Notifier,
                                                        Call.getOriginExpr())
                  ->remove<QEMUIOMMUInitializedCallbacks>(Notifier)
                  ->remove<QEMUIOMMUPendingInitializationOpaques>(
                      Call.getOriginExpr());
      if (PendingOpaque)
        State =
            State->set<QEMUIOMMUInitializedOpaques>(Notifier, PendingOpaque);
      if (Descriptor.CallbackArgument &&
          *Descriptor.CallbackArgument < Call.getNumArgs())
        if (const FunctionDecl *Callback =
                Call.getArgSVal(*Descriptor.CallbackArgument)
                    .getAsFunctionDecl())
          State = State->set<QEMUIOMMUInitializedCallbacks>(Notifier, Callback);
      C.addTransition(State);
      return;
    }

    if (Descriptor.Kind != IOMMUCallKind::Register ||
        !Descriptor.MemoryRegionArgument ||
        *Descriptor.MemoryRegionArgument >= Call.getNumArgs() ||
        !State->contains<QEMUIOMMUInitializedNotifiers>(Notifier))
      return;

    const MemRegion *PendingOpaque =
        State->get<QEMUIOMMUPendingRegistrationOpaques>(Call.getOriginExpr())
            ? *State->get<QEMUIOMMUPendingRegistrationOpaques>(
                  Call.getOriginExpr())
            : nullptr;
    const MemRegion *PendingMemoryRegion =
        State->get<QEMUIOMMUPendingRegistrationMemoryRegions>(
            Call.getOriginExpr())
            ? *State->get<QEMUIOMMUPendingRegistrationMemoryRegions>(
                  Call.getOriginExpr())
            : nullptr;
    State =
        State->remove<QEMUIOMMUPendingRegistrationOpaques>(Call.getOriginExpr())
            ->remove<QEMUIOMMUPendingRegistrationMemoryRegions>(
                Call.getOriginExpr());

    const MemRegion *MemoryRegion =
        Call.getArgSVal(*Descriptor.MemoryRegionArgument).getAsRegion();
    if (!MemoryRegion) {
      C.addTransition(State);
      return;
    }

    // A repeated call has already damaged the notifier's single QLIST node
    // before its return value is known.  checkPreCall diagnoses that attempt;
    // retain the first registration rather than modeling a second one here.
    for (IOMMURegistrationKey Active :
         State->get<QEMUIOMMUActiveRegistrations>()) {
      if (definitelySameRegions(State, Active.Notifier, Notifier, C)) {
        C.addTransition(State);
        return;
      }
    }

    std::optional<DefinedOrUnknownSVal> Result =
        Call.getReturnValue().getAs<DefinedOrUnknownSVal>();
    if (!Result) {
      C.addTransition(State);
      return;
    }

    // A zero return is the only activating outcome.  Keep the failure path
    // explicitly inactive, including for an unconstrained symbolic result.
    auto [Failure, Success] = State->assume(*Result);
    if (Failure)
      C.addTransition(Failure);
    if (!Success)
      return;

    IOMMURegistrationKey Key{MemoryRegion, Notifier};
    unsigned Epoch = 1;
    if (const unsigned *Previous = Success->get<QEMUIOMMUNextEpochs>(Notifier))
      Epoch = *Previous == std::numeric_limits<unsigned>::max() ? *Previous
                                                                : *Previous + 1;
    ProgramStateRef Active =
        Success->add<QEMUIOMMUActiveRegistrations>(Key)
            ->remove<QEMUIOMMURetiredRegistrations>(Key)
            ->remove<QEMUIOMMUInvalidatedRegistrationAliases>(Key)
            ->set<QEMUIOMMURegistrationOwners>(Key, notifierOwner(Notifier))
            ->set<QEMUIOMMURegistrationOrigins>(Key, Call.getOriginExpr())
            ->set<QEMUIOMMURegistrationEpochs>(Key, Epoch)
            ->set<QEMUIOMMUNextEpochs>(Notifier, Epoch);
    if (PendingMemoryRegion)
      Active = Active->set<QEMUIOMMURegistrationMemoryRegions>(
          Key, PendingMemoryRegion);
    if (PendingOpaque)
      Active = Active->set<QEMUIOMMURegistrationOpaques>(Key, PendingOpaque);
    if (const FunctionDecl *const *Callback =
            Success->get<QEMUIOMMUInitializedCallbacks>(Notifier))
      Active = Active->set<QEMUIOMMURegistrationCallbacks>(Key, *Callback);
    C.addTransition(Active);
  }

  void checkBind(SVal Location, SVal Value, const Stmt *S, bool AtDeclInit,
                 CheckerContext &C) const {
    const auto *Field = dyn_cast_or_null<FieldRegion>(Location.getAsRegion());
    const FieldDecl *Declaration = Field ? Field->getDecl() : nullptr;
    const RecordDecl *Parent = Declaration ? Declaration->getParent() : nullptr;
    if (!Declaration || Declaration->getName() != "opaque" || !Parent ||
        Parent->getName() != "IOMMUNotifier")
      return;
    const MemRegion *Notifier = Field->getSuperRegion();
    ProgramStateRef Initial = C.getState();
    bool Tracked = Initial->contains<QEMUIOMMUInitializedNotifiers>(Notifier);
    if (!Tracked)
      for (IOMMURegistrationKey Key :
           Initial->get<QEMUIOMMUActiveRegistrations>())
        if (Key.Notifier == Notifier) {
          Tracked = true;
          break;
        }
    if (!Tracked)
      return;
    ProgramStateRef State =
        setNotifierOpaque(Initial, Notifier, objectRegion(Value));
    // evalBind calls checkBind before the direct region-change notification.
    // Mark this exact field write so that checkRegionChanges preserves the
    // precise value above while still abandoning opaque identity for whole-
    // object stores and unknown calls.
    if (!AtDeclInit)
      State = State->add<QEMUIOMMUPendingPreciseOpaqueBinds>(Notifier);
    if (State != Initial)
      C.addTransition(State);
  }

  ProgramStateRef
  checkRegionChanges(ProgramStateRef State,
                     const InvalidatedSymbols *Invalidated,
                     ArrayRef<const MemRegion *> ExplicitRegions,
                     ArrayRef<const MemRegion *> InvalidatedRegions,
                     const StackFrame *Frame, const CallEvent *Call) const {
    // The three modeled APIs have exact field and registration semantics.  In
    // particular, register/unregister do not mutate callback or opaque even
    // though their non-const pointer arguments trigger generic invalidation.
    if (Call &&
        classifyIOMMUCall(directCallee(*Call)).Kind != IOMMUCallKind::None)
      return State;

    // Any unmodeled call can mutate an intermediate alias node that is not
    // retained in the compact registration record.  Keep a fully resolved
    // terminal as historical registration-time identity, but stop treating the
    // same raw root as proof that an unresolved alias chain stayed unchanged.
    // Direct writes to any MemoryRegion storage have the same effect.
    if (Call) {
      State = notePossibleMemoryRegionAliasMutation(State);
    } else {
      for (const MemRegion *InvalidatedRegion : InvalidatedRegions)
        if (isMemoryRegionStorage(InvalidatedRegion)) {
          State = notePossibleMemoryRegionAliasMutation(State);
          break;
        }
    }

    llvm::SmallVector<const MemRegion *, 8> Notifiers;
    for (const MemRegion *Notifier :
         State->get<QEMUIOMMUInitializedNotifiers>())
      Notifiers.push_back(Notifier);
    for (IOMMURegistrationKey Key : State->get<QEMUIOMMUActiveRegistrations>())
      if (std::find(Notifiers.begin(), Notifiers.end(), Key.Notifier) ==
          Notifiers.end())
        Notifiers.push_back(Key.Notifier);

    const bool DirectBindNotification = !Call && !Invalidated;
    for (const MemRegion *InvalidatedRegion : InvalidatedRegions) {
      if (!InvalidatedRegion)
        continue;
      InvalidatedRegion = InvalidatedRegion->StripCasts();
      for (const MemRegion *Notifier : Notifiers) {
        const MemRegion *StrippedNotifier = Notifier->StripCasts();
        if (!regionsOverlap(StrippedNotifier, InvalidatedRegion))
          continue;

        if (DirectBindNotification) {
          if (const auto *Field = dyn_cast<FieldRegion>(InvalidatedRegion)) {
            if (Field->getSuperRegion()->StripCasts() == StrippedNotifier) {
              if (Field->getDecl()->getName() == "opaque") {
                if (State->contains<QEMUIOMMUPendingPreciseOpaqueBinds>(
                        Notifier)) {
                  State = State->remove<QEMUIOMMUPendingPreciseOpaqueBinds>(
                      Notifier);
                } else {
                  State = setNotifierOpaque(State, Notifier, nullptr);
                }
              } else if (Field->getDecl()->getName() == "notify") {
                State = abandonNotifierFieldPrecision(State, Notifier, false,
                                                      true, false);
              }
              // Other direct field writes, such as notifier_flags, do not
              // invalidate callback or opaque identity.
              continue;
            }
          }
        }

        State = abandonNotifierFieldPrecision(State, Notifier, true, true, true)
                    ->remove<QEMUIOMMUPendingPreciseOpaqueBinds>(Notifier);
      }
    }

    // A precise bind normally consumes its own notification above.  Never let
    // an unmatched marker exempt a later whole-object invalidation.
    if (DirectBindNotification)
      for (const MemRegion *Notifier :
           State->get<QEMUIOMMUPendingPreciseOpaqueBinds>())
        State = State->remove<QEMUIOMMUPendingPreciseOpaqueBinds>(Notifier);
    return State;
  }

  void checkLiveSymbols(ProgramStateRef State, SymbolReaper &SymReaper) const {
    auto Mark = [&](const MemRegion *Region) {
      if (SymbolRef Symbol = regionSymbol(Region))
        SymReaper.markLive(Symbol);
    };
    for (const MemRegion *Notifier :
         State->get<QEMUIOMMUInitializedNotifiers>())
      Mark(Notifier);
    for (IOMMURegistrationKey Key :
         State->get<QEMUIOMMUActiveRegistrations>()) {
      Mark(Key.MemoryRegion);
      Mark(Key.Notifier);
      if (const MemRegion *const *Owner =
              State->get<QEMUIOMMURegistrationOwners>(Key))
        Mark(*Owner);
      if (const MemRegion *const *Opaque =
              State->get<QEMUIOMMURegistrationOpaques>(Key))
        Mark(*Opaque);
      if (const MemRegion *const *MemoryRegion =
              State->get<QEMUIOMMURegistrationMemoryRegions>(Key))
        Mark(*MemoryRegion);
    }
    for (auto [Notifier, Opaque] : State->get<QEMUIOMMUInitializedOpaques>()) {
      Mark(Notifier);
      Mark(Opaque);
    }
    for (auto [Origin, Opaque] :
         State->get<QEMUIOMMUPendingInitializationOpaques>())
      Mark(Opaque);
    for (auto [Origin, Opaque] :
         State->get<QEMUIOMMUPendingRegistrationOpaques>())
      Mark(Opaque);
    for (auto [Origin, MemoryRegion] :
         State->get<QEMUIOMMUPendingRegistrationMemoryRegions>())
      Mark(MemoryRegion);
    for (const MemRegion *Notifier :
         State->get<QEMUIOMMUPendingPreciseOpaqueBinds>())
      Mark(Notifier);
  }
};

} // namespace

void ento::registerQEMUIOMMUNotifierLifetimeChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<QEMUIOMMUNotifierLifetimeChecker>();
}

bool ento::shouldRegisterQEMUIOMMUNotifierLifetimeChecker(
    const CheckerManager &Mgr) {
  return true;
}
