add_library(CDG SHARED ControlDependenceGraph.cpp)

# We mostly use a PUBLIC scope here so that we build
# with those options/defines/includes and any targets that link
# with CDG also build with those options/defines/includes.
target_include_directories(CDG PUBLIC ${LLVM_INCLUDE_DIRS})
target_compile_definitions(CDG PUBLIC ${LLVM_DEFINITIONS})

set(CMAKE_C_FLAGS "-Wall -Werror")
set(CMAKE_CXX_FLAGS "-Wall -Werror")

if (NOT LLVM_ENABLE_RTTI)
  if (NOT MSVC)
      target_compile_options(CDG PUBLIC "-fno-rtti")
  else()
      target_compile_options(CDG PUBLIC "/GR-")
  endif()
endif()

if (NOT LLVM_ENABLE_EH)
  if (NOT MSVC)
      target_compile_options(CDG PUBLIC "-fno-exceptions")
  else()
      target_compile_options(CDG PUBLIC "/EHs-c-")
      target_compile_definitions(CDG PUBLIC "_HAS_EXCEPTIONS=0")
  endif()
endif()

# LLVM requires C++11
if (NOT MSVC)
    target_compile_options(CDG PUBLIC "-std=c++11")
endif()

# The INTERFACE scope means that any target that links
# against CDG will also implicitly link against
# the requested LLVM libraries.
llvm_map_components_to_libnames(LLVM_LIBS support)
target_link_libraries(CDG INTERFACE ${LLVM_LIBS})
