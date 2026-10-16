set(LLVM_LINK_COMPONENTS
  Support
  )

# This is intentionally a loadable module.  The checks describe an RFC API
# contract and should not become part of clang-tidy's default Linux checks.
llvm_add_library(DmaBufRfcTidyModule
  MODULE
  DmaBufMappingRfcCheck.cpp
  DmaBufRfcTidyModule.cpp

  PLUGIN_TOOL
  clang-tidy
  )

target_include_directories(DmaBufRfcTidyModule
  PRIVATE
  ${CLANG_TOOLS_SOURCE_DIR}
  )

clang_target_link_libraries(DmaBufRfcTidyModule
  PRIVATE
  clangAST
  clangASTMatchers
  clangBasic
  clangLex
  clangTidy
  )

