add_llvm_component_library(LLVMSHDesc
  SHInstPrinter.cpp
  SHMCAsmInfo.cpp
  SHMCTargetDesc.cpp

  LINK_COMPONENTS
  MC
  SHInfo
  Support
  TargetParser

  ADD_TO_COMPONENT
  SH
  )
