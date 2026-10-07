add_llvm_component_library(LLVMSHDisassembler
  SHDisassembler.cpp

  LINK_COMPONENTS
  MC
  MCDisassembler
  SHDesc
  SHInfo
  Support

  ADD_TO_COMPONENT
  SH
  )
