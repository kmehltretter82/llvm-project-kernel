add_llvm_component_library(LLVMSHDesc
  SHAsmBackend.cpp
  SHELFObjectWriter.cpp
  SHInstPrinter.cpp
  SHMCAsmInfo.cpp
  SHMCCodeEmitter.cpp
  SHMCTargetDesc.cpp

  LINK_COMPONENTS
  MC
  SHInfo
  Support
  TargetParser

  ADD_TO_COMPONENT
  SH
  )
