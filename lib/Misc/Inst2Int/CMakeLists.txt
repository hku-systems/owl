add_library(Inst2Int SHARED Inst2Int.cpp)

# We mostly use a PUBLIC scope here so that we build
# with those options/defines/includes and any targets that link
# with Inst2Int also build with those options/defines/includes.
target_include_directories(Inst2Int PUBLIC ${LLVM_INCLUDE_DIRS})
target_compile_definitions(Inst2Int PUBLIC ${LLVM_DEFINITIONS})

set(CMAKE_C_FLAGS "-Wall -Werror")
set(CMAKE_CXX_FLAGS "-Wall -Werror")

if (NOT LLVM_ENABLE_RTTI)
  if (NOT MSVC)
      target_compile_options(Inst2Int PUBLIC "-fno-rtti")
  else()
      target_compile_options(Inst2Int PUBLIC "/GR-")
  endif()
endif()

if (NOT LLVM_ENABLE_EH)
  if (NOT MSVC)
      target_compile_options(Inst2Int PUBLIC "-fno-exceptions")
  else()
      target_compile_options(Inst2Int PUBLIC "/EHs-c-")
      target_compile_definitions(Inst2Int PUBLIC "_HAS_EXCEPTIONS=0")
  endif()
endif()

# LLVM requires C++11
if (NOT MSVC)
    target_compile_options(Inst2Int PUBLIC "-std=c++11")
endif()

# The INTERFACE scope means that any target that links
# against Inst2Int will also implicitly link against
# the requested LLVM libraries.
llvm_map_components_to_libnames(LLVM_LIBS support)
target_link_libraries(Inst2Int INTERFACE ${LLVM_LIBS})
