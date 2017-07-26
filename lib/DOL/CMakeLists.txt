add_library(DOL SHARED DangerOpLabel.cpp)

# We mostly use a PUBLIC scope here so that we build
# with those options/defines/includes and any targets that link
# with DOL also build with those options/defines/includes.
target_include_directories(DOL PUBLIC ${LLVM_INCLUDE_DIRS})
target_compile_definitions(DOL PUBLIC ${LLVM_DEFINITIONS})

set(CMAKE_C_FLAGS "-Wall -Werror")
set(CMAKE_CXX_FLAGS "-Wall -Werror")

if (NOT LLVM_ENABLE_RTTI)
  if (NOT MSVC)
    target_compile_options(DOL PUBLIC "-fno-rtti")
  else()
    target_compile_options(DOL PUBLIC "/GR-")
  endif()
endif()

if (NOT LLVM_ENABLE_EH)
  if (NOT MSVC)
    target_compile_options(DOL PUBLIC "-fno-exceptions")
  else()
    target_compile_options(DOL PUBLIC "/EHs-c-")
    target_compile_definitions(DOL PUBLIC "_HAS_EXCEPTIONS=0")
  endif()
endif()

# LLVM requires C++11
if (NOT MSVC)
  target_compile_options(DOL PUBLIC "-std=c++11")
endif()

# The INTERFACE scope means that any target that links
# against DOL will also implicitly link against
# the requested LLVM libraries.
llvm_map_components_to_libnames(LLVM_LIBS support)
target_link_libraries(DOL INTERFACE ${LLVM_LIBS})
