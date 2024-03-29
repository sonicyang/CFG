cmake_minimum_required(VERSION 3.13.0)
project(syscall_anaylsis)

# User must provide location of Dyninst cmake files either as a cache or
# environment variable
if(NOT Dyninst_DIR)
  if("$ENV{Dyninst_DIR}" STREQUAL "")
    message(
      FATAL_ERROR
        "Dyninst_DIR not found: define as a cache or environment variable")
  else()
    set(_dyninst_dir $ENV{Dyninst_DIR})
  endif()
else()
  set(_dyninst_dir ${Dyninst_DIR})
  set($ENV{Dyninst_DIR} ${_dyninst_dir})
endif()

# Make sure it's an absolute path
if(NOT IS_ABSOLUTE ${_dyninst_dir})
  get_filename_component(_tmp ${_dyninst_dir} ABSOLUTE)
  set(_dyninst_dir ${_tmp})
  unset(_tmp)
endif()

# Save the munged path in the global name
set(Dyninst_DIR ${_dyninst_dir})
unset(_dyninst_dir)

# Use the Dyninst-provided CMake modules
set(CMAKE_MODULE_PATH
    "${Dyninst_DIR}"
    "${Dyninst_DIR}/Modules"
    ${CMAKE_MODULE_PATH})

# Import the Dyninst components
find_package(Dyninst REQUIRED
             COMPONENTS common
                        dyninstAPI
                        instructionAPI
                        parseAPI
                        symtabAPI
                        common)

find_package(absl REQUIRED)

find_package(spdlog REQUIRED)

# Read the cache generated from building Dyninst
load_cache(${Dyninst_DIR}
           READ_WITH_PREFIX DYNINST_
           Boost_LIBRARIES
           Boost_INCLUDE_DIRS
           Boost_LIBRARY_DIRS
           Boost_DEFINES
           TBB_INCLUDE_DIRS)

# Set default configuration type
if(NOT CMAKE_BUILD_TYPE)
  set(
    CMAKE_BUILD_TYPE RelWithDebInfo
    CACHE
      STRING
      "Choose the build type (None, Debug, Release, RelWithDebInfo, MinSizeRel)"
    FORCE)
endif()

# Use the same optimization settings used to build Dyninst
include(optimization)

# ----------------------------------------------------------------------------#

# Set up the individual examples
get_filename_component(EXAMPLE_ROOT ${CMAKE_CURRENT_SOURCE_DIR} ABSOLUTE)
add_subdirectory(syscall_list)
