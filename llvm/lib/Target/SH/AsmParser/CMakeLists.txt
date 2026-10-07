add_llvm_component_library(LLVMSHAsmParser
  SHAsmParser.cpp

  LINK_COMPONENTS
  MC
  MCParser
  SHDesc
  SHInfo
  Support

  ADD_TO_COMPONENT
  SH
  )
