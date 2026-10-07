//===- SuperH.cpp ---------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The calling conventions of GCC for SuperH.  There are two, and the
// processor decides which one a translation unit has:
//
// - Without a floating point unit (-m4-nofpu, SH-2, SH-3) every argument is
//   a row of words.  The first four words of all arguments go to r4 to r7
//   and the rest to the stack, wherever that cuts an argument.  va_list is
//   a pointer.
//
// - With a floating point unit an argument is in registers only if all of
//   it fits.  float goes to fr4 to fr11, and double as well if the unit
//   computes it.  va_list is a structure of five pointers.
//
// The code generator does the counting of registers.  What it needs from
// here is the type that an argument is passed as: a floating point type, or
// integers that hold the bytes of the value.
//
// A result is in r0 and r1 (or fr0 to fr3) if its type has a machine mode
// in GCC, and otherwise in memory that r2 points to.
//
//===----------------------------------------------------------------------===//

#include "ABIInfoImpl.h"
#include "TargetInfo.h"
#include "clang/Basic/TargetOptions.h"
#include "llvm/TargetParser/SHTargetParser.h"

using namespace clang;
using namespace clang::CodeGen;

namespace {

class SuperHABIInfo : public DefaultABIInfo {
  const llvm::SH::CPUInfo &CPU;

public:
  SuperHABIInfo(CodeGen::CodeGenTypes &CGT, const llvm::SH::CPUInfo &CPU)
      : DefaultABIInfo(CGT), CPU(CPU) {}

  void computeInfo(CGFunctionInfo &FI) const override;

  RValue EmitVAArg(CodeGenFunction &CGF, Address VAListAddr, QualType Ty,
                   AggValueSlot Slot) const override;

private:
  /// What GCC calls the mode of a type, as far as a result depends on it.
  enum ModeKind {
    /// The value fits a register, or two, or four.
    MK_Registers,
    /// The size would fit and the alignment does not.  Such a member does
    /// not keep the structure around it from fitting.
    MK_Unaligned,
    /// A block of memory, and so is every structure that has it as a member.
    MK_Block,
  };

  ABIArgInfo classifyReturnType(QualType RetTy) const;
  ABIArgInfo classifyArgumentType(QualType Ty) const;

  QualType getSoleMember(QualType Ty) const;
  ModeKind getModeKind(QualType Ty) const;
  llvm::Type *getFloatType(QualType Ty, bool IsReturn) const;
  llvm::Type *getWordsType(uint64_t Bits) const;
  bool isScalarForABI(QualType Ty) const;
};

} // end anonymous namespace

/// A structure that consists of one member is passed and returned like that
/// member, and so on inwards: the type that is left at the end, or the type
/// itself.  A union is never like its member.
QualType SuperHABIInfo::getSoleMember(QualType Ty) const {
  ASTContext &Ctx = getContext();
  while (true) {
    // An array is met as the type of a member only, and counts if it has
    // one element.
    if (const ConstantArrayType *AT = Ctx.getAsConstantArrayType(Ty)) {
      if (AT->getZExtSize() != 1)
        return QualType();
      Ty = AT->getElementType();
      continue;
    }
    const RecordDecl *RD = Ty->getAsRecordDecl();
    if (!RD)
      return Ty;
    if (RD->isUnion() || RD->hasFlexibleArrayMember())
      return QualType();

    QualType Member;
    auto Add = [&](QualType T) {
      if (Ctx.getTypeSize(T) == 0)
        return true;
      if (!Member.isNull())
        return false;
      Member = T;
      return true;
    };
    if (const auto *CXXRD = dyn_cast<CXXRecordDecl>(RD)) {
      if (CXXRD->isDynamicClass())
        return QualType();
      for (const CXXBaseSpecifier &Base : CXXRD->bases())
        if (!isEmptyRecord(Ctx, Base.getType(), true) && !Add(Base.getType()))
          return QualType();
    }
    for (const FieldDecl *FD : RD->fields()) {
      if (FD->isZeroLengthBitField())
        continue;
      if (FD->isBitField() || !Add(FD->getType()))
        return QualType();
    }
    // The member has to be all of the structure, and the structure must
    // not be packed to less than the member needs.
    if (Member.isNull() || Ctx.getTypeSize(Member) != Ctx.getTypeSize(Ty) ||
        Ctx.getTypeAlign(Ty) < Ctx.getTypeAlign(Member))
      return QualType();
    Ty = Member;
  }
}

SuperHABIInfo::ModeKind SuperHABIInfo::getModeKind(QualType Ty) const {
  ASTContext &Ctx = getContext();
  uint64_t Bytes = Ctx.getTypeSizeInChars(Ty).getQuantity();
  uint64_t Align = Ctx.getTypeAlignInChars(Ty).getQuantity();
  // One, two, four or eight bytes fit an integer register or two, if the
  // alignment is that of the integer.
  auto BySize = [&] {
    if (Bytes != 1 && Bytes != 2 && Bytes != 4 && Bytes != 8)
      return MK_Block;
    return Align >= std::min<uint64_t>(Bytes, 4) ? MK_Registers : MK_Unaligned;
  };

  // A vector has a mode of its own up to sixteen bytes.
  if (Ty->isVectorType())
    return Bytes <= 16 && llvm::isPowerOf2_64(Bytes) ? MK_Registers : MK_Block;

  if (const ConstantArrayType *AT = Ctx.getAsConstantArrayType(Ty)) {
    if (Bytes == 0)
      return MK_Registers;
    ModeKind Element = getModeKind(AT->getElementType());
    if (Element == MK_Block)
      return MK_Block;
    // An array of one element is like the element.
    if (AT->getZExtSize() == 1)
      return Element == MK_Registers ? MK_Registers : MK_Block;
    return BySize();
  }
  if (Ty->isArrayType())
    return MK_Block;

  const RecordDecl *RD = Ty->getAsRecordDecl();
  if (!RD)
    return MK_Registers;
  if (RD->hasFlexibleArrayMember())
    return MK_Block;
  // A structure that is one complex number or one vector.
  if (QualType Member = getSoleMember(Ty); !Member.isNull())
    if (Member->isAnyComplexType() || Member->isVectorType())
      return getModeKind(Member);

  if (const auto *CXXRD = dyn_cast<CXXRecordDecl>(RD))
    for (const CXXBaseSpecifier &Base : CXXRD->bases())
      if (Ctx.getTypeSize(Base.getType()) != 0 &&
          getModeKind(Base.getType()) == MK_Block)
        return MK_Block;
  for (const FieldDecl *FD : RD->fields()) {
    if (FD->isBitField())
      continue;
    if (Ctx.getTypeSize(FD->getType()) != 0 &&
        getModeKind(FD->getType()) == MK_Block)
      return MK_Block;
  }
  return BySize();
}

/// The floating point type that a value is passed in floating point
/// registers as, or null if it goes with the integers: float, double, or
/// an array of two of one of them for a complex number.
llvm::Type *SuperHABIInfo::getFloatType(QualType Ty, bool IsReturn) const {
  if (!CPU.hasFPU())
    return nullptr;
  QualType Member = getSoleMember(Ty);
  if (Member.isNull())
    return nullptr;

  ASTContext &Ctx = getContext();
  auto IsReal = [&](QualType T) {
    const auto *BT = T->getAs<BuiltinType>();
    return BT && BT->isFloatingPoint() && Ctx.getTypeSize(T) <= 64 &&
           Ctx.getTypeSize(T) >= 32;
  };
  if (IsReal(Member)) {
    if (Ctx.getTypeSize(Member) == 64 && !CPU.hasDoubleFPU())
      return nullptr;
    return CGT.ConvertType(Member);
  }
  if (const auto *CT = Member->getAs<ComplexType>()) {
    QualType Element = CT->getElementType();
    if (!IsReal(Element))
      return nullptr;
    // A unit that computes float only takes a complex float as a result
    // and not as an argument.
    bool IsDouble = Ctx.getTypeSize(Element) == 64;
    if (CPU.hasDoubleFPU() || (IsReturn && !IsDouble))
      return llvm::ArrayType::get(CGT.ConvertType(Element), 2);
  }
  return nullptr;
}

/// The integers that hold a value of this size in registers and on the
/// stack: one that is as wide as the value if it has less than four bytes,
/// which puts it at the low end of a word in either byte order, and words
/// with the bytes in the order of memory otherwise.
llvm::Type *SuperHABIInfo::getWordsType(uint64_t Bits) const {
  uint64_t Bytes = (Bits + 7) / 8;
  llvm::LLVMContext &Ctx = getVMContext();
  if (Bytes <= 4)
    return llvm::IntegerType::get(Ctx, Bytes * 8);
  return llvm::ArrayType::get(llvm::Type::getInt32Ty(Ctx), (Bytes + 3) / 4);
}

/// Numbers and pointers, which go as they are.
bool SuperHABIInfo::isScalarForABI(QualType Ty) const {
  return !isAggregateTypeForABI(Ty) && !Ty->isAnyComplexType() &&
         !Ty->isVectorType();
}

ABIArgInfo SuperHABIInfo::classifyReturnType(QualType RetTy) const {
  if (RetTy->isVoidType())
    return ABIArgInfo::getIgnore();
  uint64_t Bits = getContext().getTypeSize(RetTy);
  if (Bits == 0)
    return ABIArgInfo::getIgnore();

  if (llvm::Type *FloatTy = getFloatType(RetTy, /*IsReturn=*/true))
    return ABIArgInfo::getDirect(FloatTy);

  if (isScalarForABI(RetTy)) {
    if (const auto *ED = RetTy->getAsEnumDecl())
      RetTy = ED->getIntegerType();
    if (const auto *BIT = RetTy->getAs<BitIntType>())
      if (BIT->getNumBits() > 64)
        return getNaturalAlignIndirect(
            RetTy, getDataLayout().getAllocaAddrSpace(), /*ByVal=*/false);
    // A function extends what it returns to a word.
    return isPromotableIntegerTypeForABI(RetTy) ? ABIArgInfo::getExtend(RetTy)
                                                : ABIArgInfo::getDirect();
  }

  // A complex number always has a mode: up to four words in r0 to r3.
  if (RetTy->isAnyComplexType() || getModeKind(RetTy) == MK_Registers)
    return ABIArgInfo::getDirect(getWordsType(Bits));
  return getNaturalAlignIndirect(RetTy, getDataLayout().getAllocaAddrSpace(),
                                 /*ByVal=*/false);
}

ABIArgInfo SuperHABIInfo::classifyArgumentType(QualType Ty) const {
  Ty = useFirstFieldIfTransparentUnion(Ty);

  // What C++ cannot copy bit by bit is passed by reference.
  if (CGCXXABI::RecordArgABI RAA = getRecordArgABI(Ty, getCXXABI()))
    return getNaturalAlignIndirect(Ty, getDataLayout().getAllocaAddrSpace(),
                                   RAA == CGCXXABI::RAA_DirectInMemory);

  uint64_t Bits = getContext().getTypeSize(Ty);
  if (Bits == 0)
    return ABIArgInfo::getIgnore();

  if (llvm::Type *FloatTy = getFloatType(Ty, /*IsReturn=*/false))
    return ABIArgInfo::getDirect(FloatTy);

  if (isScalarForABI(Ty)) {
    if (const auto *ED = Ty->getAsEnumDecl())
      Ty = ED->getIntegerType();
    const auto *BIT = Ty->getAs<BitIntType>();
    if (!BIT || BIT->getNumBits() <= 64)
      return isPromotableIntegerTypeForABI(Ty) ? ABIArgInfo::getExtend(Ty)
                                               : ABIArgInfo::getDirect();
  }

  // The bytes of the value, as words.  A large structure is copied to the
  // stack by the code generator, which also loads the registers that the
  // first words of it belong in.
  // An argument is never aligned to more than a word.
  if (Bits > 64 * 8 && isAggregateTypeForABI(Ty)) {
    CharUnits Word = CharUnits::fromQuantity(4);
    CharUnits Align = getContext().getTypeAlignInChars(Ty);
    return ABIArgInfo::getIndirect(std::min(Align, Word),
                                   getDataLayout().getAllocaAddrSpace(),
                                   /*ByVal=*/true, /*Realign=*/Align > Word);
  }
  return ABIArgInfo::getDirect(getWordsType(Bits));
}

void SuperHABIInfo::computeInfo(CGFunctionInfo &FI) const {
  if (!getCXXABI().classifyReturnType(FI))
    FI.getReturnInfo() = classifyReturnType(FI.getReturnType());
  for (auto &Arg : FI.arguments())
    Arg.info = classifyArgumentType(Arg.type);
}

RValue SuperHABIInfo::EmitVAArg(CodeGenFunction &CGF, Address VAListAddr,
                                QualType Ty, AggValueSlot Slot) const {
  ASTContext &Ctx = getContext();
  bool IsIndirect = getRecordArgABI(Ty, getCXXABI()) != CGCXXABI::RAA_Default;
  TypeInfoChars Info = Ctx.getTypeInfoInChars(Ty);
  // Nothing was passed for a structure without members.
  if (Info.Width.isZero() && !IsIndirect)
    return Slot.asRValue();

  CharUnits SlotSize = CharUnits::fromQuantity(4);
  // Nothing is aligned to more than a word on the stack.
  Info.Align = std::min(Info.Align, SlotSize);

  // va_list is a pointer to the next word.  A value of less than a word is
  // at the end of its word on a big-endian processor, a structure too.
  if (!CPU.hasFPU())
    return emitVoidPtrVAArg(CGF, VAListAddr, Ty, IsIndirect, Info, SlotSize,
                            /*AllowHigherAlign=*/false, Slot,
                            /*ForceRightAdjust=*/true);

  // va_list is
  //
  //   struct { void *next_o, *next_o_limit;    the integer registers
  //            void *next_fp, *next_fp_limit;  the floating point registers
  //            void *next_stack; }             the arguments on the stack
  //
  // The registers that hold no named parameter were stored by the function,
  // each kind in a row.  An argument was passed in registers only if all of
  // it fitted, so it is taken from a row only if all of it is left there.
  CGBuilderTy &Builder = CGF.Builder;
  CharUnits Size = IsIndirect ? SlotSize : Info.Width;
  CharUnits RoundedSize = Size.alignTo(SlotSize);
  llvm::Type *FloatTy = IsIndirect ? nullptr : getFloatType(Ty, false);
  bool BigEndian = getDataLayout().isBigEndian();

  auto Field = [&](unsigned Index, const char *Name) {
    return Builder.CreateStructGEP(VAListAddr, Index, Name);
  };
  auto Advance = [&](llvm::Value *Ptr, int64_t Bytes) {
    return Builder.CreateConstInBoundsGEP1_32(CGF.Int8Ty, Ptr, Bytes);
  };
  // Where a value of less than a word is in the word at Ptr.
  auto ValueIn = [&](llvm::Value *Ptr) {
    if (BigEndian && Size < SlotSize && !FloatTy)
      return Advance(Ptr, (SlotSize - Size).getQuantity());
    return Ptr;
  };

  llvm::BasicBlock *InRegs = CGF.createBasicBlock("vaarg.in_regs");
  llvm::BasicBlock *OnStack = CGF.createBasicBlock("vaarg.on_stack");
  llvm::BasicBlock *End = CGF.createBasicBlock("vaarg.end");
  llvm::Value *RegAddr;

  if (FloatTy) {
    bool IsDouble = FloatTy->isDoubleTy();
    Address NextFP = Field(2, "next_fp.addr");
    llvm::Value *Ptr = Builder.CreateLoad(NextFP, "next_fp");
    llvm::Value *Limit =
        Builder.CreateLoad(Field(3, "next_fp_limit.addr"), "next_fp_limit");
    // A double lies at an address that eight divides.
    auto Align = [&](llvm::Value *P) {
      llvm::Value *Odd = Builder.CreateAnd(
          Builder.CreatePtrToInt(P, CGF.Int32Ty), 4, "next_fp.odd");
      return Builder.CreateInBoundsGEP(CGF.Int8Ty, P, Odd, "next_fp.aligned");
    };
    // A complex number needs room for both parts.
    if (Size > SlotSize && !IsDouble)
      Limit = Advance(Limit, (SlotSize - Size).getQuantity());
    if (IsDouble)
      Ptr = Align(Ptr);
    Builder.CreateCondBr(Builder.CreateICmpUGE(Ptr, Limit), OnStack, InRegs);

    CGF.EmitBlock(InRegs);
    if (Size.getQuantity() == 16)
      Ptr = Align(Ptr);
    Builder.CreateStore(Advance(Ptr, RoundedSize.getQuantity()), NextFP);
    RegAddr = Ptr;
    // The registers were stored in pairs, as doubles.  On a little-endian
    // SH-4 that puts the second register of a pair first, and the
    // imaginary part of a complex float in front of the real part.
    if (FloatTy->isArrayTy() && Size.getQuantity() == 8 && CPU.isSH4FPU() &&
        !BigEndian) {
      Address Temp = CGF.CreateMemTemp(Ty, "vaarg.complex");
      CharUnits Four = CharUnits::fromQuantity(4);
      auto Float = [&](Address Bytes, bool Second) {
        if (Second)
          Bytes = Builder.CreateConstInBoundsByteGEP(Bytes, Four);
        return Bytes.withElementType(CGF.FloatTy);
      };
      Address Saved(Ptr, CGF.Int8Ty, Four);
      Address Parts = Temp.withElementType(CGF.Int8Ty);
      llvm::Value *Imag = Builder.CreateLoad(Float(Saved, false), "vaarg.imag");
      llvm::Value *Real = Builder.CreateLoad(Float(Saved, true), "vaarg.real");
      Builder.CreateStore(Real, Float(Parts, false));
      Builder.CreateStore(Imag, Float(Parts, true));
      RegAddr = Temp.emitRawPointer(CGF);
    }
  } else {
    Address NextO = Field(0, "next_o.addr");
    llvm::Value *Ptr = Builder.CreateLoad(NextO, "next_o");
    llvm::Value *Limit =
        Builder.CreateLoad(Field(1, "next_o_limit.addr"), "next_o_limit");
    llvm::Value *Next = Advance(Ptr, RoundedSize.getQuantity());
    Builder.CreateCondBr(Builder.CreateICmpUGT(Next, Limit), OnStack, InRegs);

    CGF.EmitBlock(InRegs);
    Builder.CreateStore(Next, NextO);
    RegAddr = ValueIn(Ptr);
    InRegs = Builder.GetInsertBlock();
    CGF.EmitBranch(End);

    // Where an argument that did not fit takes the registers with it, no
    // later argument comes from them.
    CGF.EmitBlock(OnStack);
    if (Size > SlotSize && !CPU.leavesRegistersFree())
      Builder.CreateStore(Limit, NextO);
  }
  if (FloatTy) {
    InRegs = Builder.GetInsertBlock();
    CGF.EmitBranch(End);
    CGF.EmitBlock(OnStack);
  }

  Address NextStack = Field(4, "next_stack.addr");
  llvm::Value *StackPtr = Builder.CreateLoad(NextStack, "next_stack");
  Builder.CreateStore(Advance(StackPtr, RoundedSize.getQuantity()), NextStack);
  llvm::Value *StackAddr = ValueIn(StackPtr);
  OnStack = Builder.GetInsertBlock();
  CGF.EmitBranch(End);

  CGF.EmitBlock(End);
  llvm::PHINode *Phi = Builder.CreatePHI(RegAddr->getType(), 2, "vaarg.addr");
  Phi->addIncoming(RegAddr, InRegs);
  Phi->addIncoming(StackAddr, OnStack);

  if (IsIndirect) {
    Address Pointer(Phi, CGF.DefaultPtrTy, SlotSize);
    Address Object(Builder.CreateLoad(Pointer, "vaarg.object"),
                   CGF.ConvertTypeForMem(Ty), Ctx.getTypeAlignInChars(Ty));
    return CGF.EmitLoadOfAnyValue(CGF.MakeAddrLValue(Object, Ty), Slot);
  }
  Address Addr(Phi, CGF.ConvertTypeForMem(Ty), Info.Align);
  return CGF.EmitLoadOfAnyValue(CGF.MakeAddrLValue(Addr, Ty), Slot);
}

namespace {
class SuperHTargetCodeGenInfo : public TargetCodeGenInfo {
public:
  SuperHTargetCodeGenInfo(CodeGen::CodeGenTypes &CGT,
                          const llvm::SH::CPUInfo &CPU)
      : TargetCodeGenInfo(std::make_unique<SuperHABIInfo>(CGT, CPU)) {}

  // r15.
  int getDwarfEHStackPointer(CodeGen::CodeGenModule &M) const override {
    return 15;
  }
};
} // end anonymous namespace

std::unique_ptr<TargetCodeGenInfo>
CodeGen::createSuperHTargetCodeGenInfo(CodeGenModule &CGM) {
  const TargetInfo &Target = CGM.getTarget();
  StringRef Name = Target.getTargetOpts().CPU;
  const llvm::SH::CPUInfo *CPU = llvm::SH::parseCPU(Name);
  if (!CPU)
    CPU = llvm::SH::parseCPU(llvm::SH::getDefaultCPU(Target.getTriple()));
  assert(CPU && "the default processor of a triple is in the table");
  return std::make_unique<SuperHTargetCodeGenInfo>(CGM.getTypes(), *CPU);
}
