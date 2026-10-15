if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  cmake_minimum_required(VERSION 3.20)
  project(ClangKernelLab LANGUAGES C CXX)

  find_package(LLVM REQUIRED CONFIG)
  list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
  include(AddLLVM)
  include(HandleLLVMOptions)

  include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
  add_definitions(${LLVM_DEFINITIONS})
endif()

add_llvm_pass_plugin(ClangKernelLab
  ClangKernelLab.cpp
  PARTIAL_SOURCES_INTENDED
  )

add_llvm_pass_plugin(ClangKernelLabMap
  ClangKernelLabMap.cpp
  PARTIAL_SOURCES_INTENDED
  )

set_target_properties(ClangKernelLab PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  )

set_target_properties(ClangKernelLabMap PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  )

target_include_directories(ClangKernelLabMap PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
  )

llvm_map_components_to_libnames(KERNEL_LAB_LLVM_LIBS
  Object
  Support
  )

add_executable(llvm-riscv-irq-sites
  llvm-riscv-irq-sites.cpp
  )

llvm_update_compile_flags(llvm-riscv-irq-sites)
target_include_directories(llvm-riscv-irq-sites PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
  )
target_link_libraries(llvm-riscv-irq-sites PRIVATE ${KERNEL_LAB_LLVM_LIBS})

set_target_properties(llvm-riscv-irq-sites PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  )
