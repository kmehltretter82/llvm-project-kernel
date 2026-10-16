cmake_minimum_required(VERSION 3.20)
project(DmaBufRfcTidyModule LANGUAGES C CXX)

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

add_library(DmaBufRfcTidyModule MODULE
  ../DmaBufMappingRfcCheck.cpp
  ../DmaBufRfcTidyModule.cpp
  )

target_compile_features(DmaBufRfcTidyModule PRIVATE cxx_std_17)
target_include_directories(DmaBufRfcTidyModule PRIVATE
  ${LLVM_INCLUDE_DIRS}
  ${CLANG_INCLUDE_DIRS}
  )
target_compile_definitions(DmaBufRfcTidyModule PRIVATE ${LLVM_DEFINITIONS})
target_link_libraries(DmaBufRfcTidyModule PRIVATE clang-cpp LLVM)

if(APPLE)
  # clang-tidy owns the registry and ClangTidyCheck implementation.  Resolve
  # those symbols from the loading executable, as LLVM's in-tree
  # PLUGIN_TOOL support does.
  target_link_options(DmaBufRfcTidyModule PRIVATE
    "LINKER:-undefined,dynamic_lookup"
    )
endif()

set_target_properties(DmaBufRfcTidyModule PROPERTIES
  PREFIX ""
  )

