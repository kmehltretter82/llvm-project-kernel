add_llvm_component_library(LLVMSHInfo
  SHTargetInfo.cpp

  LINK_COMPONENTS
  MC
  Support

  ADD_TO_COMPONENT
  SH
  )
