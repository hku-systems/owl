# Install script for directory: /home/shixiong/owl

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/shixiong/owl/lib/Misc/Inst2Int/cmake_install.cmake")
  include("/home/shixiong/owl/lib/CDG/cmake_install.cmake")
  include("/home/shixiong/owl/lib/SyncLoop/cmake_install.cmake")
  include("/home/shixiong/owl/lib/DOL/cmake_install.cmake")
  include("/home/shixiong/owl/lib/ConAnal/cmake_install.cmake")
  include("/home/shixiong/owl/TESTS/libsafe-cve-1125/cmake_install.cmake")
  include("/home/shixiong/owl/TESTS/libvirt-cve-1447/cmake_install.cmake")
  include("/home/shixiong/owl/TESTS/apache-21287/cmake_install.cmake")
  include("/home/shixiong/owl/TESTS/apache-25520/cmake_install.cmake")
  include("/home/shixiong/owl/TESTS/apache-46215/cmake_install.cmake")
  include("/home/shixiong/owl/TESTS/apache-2.4.18/cmake_install.cmake")
  include("/home/shixiong/owl/TESTS/mysql-24988/cmake_install.cmake")
  include("/home/shixiong/owl/TESTS/mysql-35589/cmake_install.cmake")
  include("/home/shixiong/owl/TESTS/memcached-1.4.25/cmake_install.cmake")
  include("/home/shixiong/owl/TESTS/ssdb-1.9.2/cmake_install.cmake")
  include("/home/shixiong/owl/TESTS/mongoose-3.6/cmake_install.cmake")
  include("/home/shixiong/owl/TESTS/linux-4.4.1/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/home/shixiong/owl/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
