add_llvm_component_group(SH)

set(LLVM_TARGET_DEFINITIONS SH.td)

tablegen(LLVM SHGenAsmWriter.inc -gen-asm-writer)
tablegen(LLVM SHGenCallingConv.inc -gen-callingconv)
tablegen(LLVM SHGenDAGISel.inc -gen-dag-isel)
tablegen(LLVM SHGenInstrInfo.inc -gen-instr-info)
tablegen(LLVM SHGenRegisterInfo.inc -gen-register-info)
tablegen(LLVM SHGenSDNodeInfo.inc -gen-sd-node-info)
tablegen(LLVM SHGenSubtargetInfo.inc -gen-subtarget)

add_public_tablegen_target(SHCommonTableGen)

add_llvm_target(SHCodeGen
  SHAsmPrinter.cpp
  SHConstantIslands.cpp
  SHDelaySlotFiller.cpp
  SHFPModeSwitch.cpp
  SHFrameLowering.cpp
  SHISelDAGToDAG.cpp
  SHISelLowering.cpp
  SHInstrInfo.cpp
  SHRegisterInfo.cpp
  SHSelectionDAGInfo.cpp
  SHSubtarget.cpp
  SHTargetMachine.cpp

  LINK_COMPONENTS
  AsmPrinter
  CodeGen
  CodeGenTypes
  Core
  MC
  SelectionDAG
  SHDesc
  SHInfo
  Support
  Target
  TargetParser
  TransformUtils

  ADD_TO_COMPONENT
  SH
  )

add_subdirectory(MCTargetDesc)
add_subdirectory(TargetInfo)
