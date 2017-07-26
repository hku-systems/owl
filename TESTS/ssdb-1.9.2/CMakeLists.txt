configure_file(autotest.sh autotest.sh COPYONLY)
configure_file(autotestConAnalysis.sh autotestConAnalysis.sh COPYONLY)
configure_file(autotestInst2Int.sh autotestInst2Int.sh COPYONLY)
configure_file(autotestSyncLoop.sh autotestSyncLoop.sh COPYONLY)
configure_file(danMemFuncLists.txt danMemFuncLists.txt COPYONLY)
configure_file(danPrivilegedFuncLists.txt danPrivilegedFuncLists.txt COPYONLY)
configure_file(ssdb-1.9.2.bc ssdb-1.9.2.bc COPYONLY)

set(SOURCE_NAME ssdb-1.9.2)
set(src_bc_compiler clang)

add_custom_command(
  OUTPUT  ${SOURCE_NAME}.bc 
  #COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR} && make
  #DEPENDS ${SOURCE_NAME}.c
  #IMPLICIT_DEPENDS CXX ${SOURCE_NAME}.c
  COMMENT "Building LLVM bitcode ${SOURCE_NAME}.bc"
  VERBATIM
)
set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${SOURCE_NAME}.bc)

add_custom_target(
  ssdb-1.9.2 ALL
  DEPENDS ${SOURCE_NAME}.bc)
