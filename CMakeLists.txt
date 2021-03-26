# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

file(STRINGS "VERSION" SPICY_ZEEK_PLUGIN_VERSION)

string(REGEX MATCH "(([0-9]*)\.([0-9]*)\.([0-9]*)).*" _ ${SPICY_ZEEK_PLUGIN_VERSION})
set(SPICY_ZEEK_PLUGIN_VERSION_MAIN  ${CMAKE_MATCH_1})
set(SPICY_ZEEK_PLUGIN_VERSION_MAJOR ${CMAKE_MATCH_2})
set(SPICY_ZEEK_PLUGIN_VERSION_MINOR ${CMAKE_MATCH_3})
set(SPICY_ZEEK_PLUGIN_VERSION_PATCH ${CMAKE_MATCH_4})
math(EXPR SPICY_ZEEK_PLUGIN_VERSION_NUMBER "${SPICY_ZEEK_PLUGIN_VERSION_MAJOR} * 10000 + ${SPICY_ZEEK_PLUGIN_VERSION_MINOR} * 100 + ${SPICY_ZEEK_PLUGIN_VERSION_PATCH}")

project(SpicyPlugin VERSION "${SPICY_ZEEK_PLUGIN_VERSION_MAIN}" LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package(Spicy)
find_package(Zeek)

if ( NOT Zeek_FOUND )
    if ( "${SPICY_IN_TREE_BUILD}" )
        # Ok to build without Zeek
        return ()
    else ()
        message(FATAL_ERROR "cannot find Zeek, aborting")
    endif ()
endif()

include(InstallHelpers)
include(GNUInstallDirs)

spicy_require_version("0.4" 00400)
zeek_require_version("3.0" 30000)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if ( NOT "${SPICY_IN_TREE_BUILD}" )
    set(ZEEK_SPICY_PLUGIN_BUILD_DIR ${CMAKE_BINARY_DIR}/plugin)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${ZEEK_SPICY_PLUGIN_BUILD_DIR}/bin)

    if ( NOT "${CMAKE_BUILD_TYPE}" )
        # We follow Zeek's build mode by default.
        if ( ZEEK_DEBUG_BUILD )
            set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "" FORCE)
        else ()
            set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "" FORCE)
        endif ()
    endif ()

    # CMake uses -O2 by default with RelWithDebInfo.
    string(REPLACE "-O2" "-O3" CMAKE_CXX_FLAGS_RELWITHDEBINFO ${CMAKE_CXX_FLAGS_RELWITHDEBINFO})
    set(SPICY_CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}") # treat as same
else ()
    set(SPICY_CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}) # save this
    set(ZEEK_SPICY_PLUGIN_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/plugin)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${ZEEK_SPICY_PLUGIN_BUILD_DIR}/bin)
endif ()

include_directories(BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/plugin)
include_directories(BEFORE PRIVATE ${ZEEK_SPICY_PLUGIN_BUILD_DIR}/include)

if ( NOT SPICY_IN_TREE_BUILD )
        spicy_print_summary()
endif ()

zeek_print_summary()

if ( ZEEK_DEBUG_BUILD )
    set(ZEEK_DEBUG_BUILD "yes") # Prettify output
else ()
    set(ZEEK_DEBUG_BUILD "no")
endif ()

if ( SPICY_HAVE_TOOLCHAIN )
    add_subdirectory(compiler)
endif ()

add_subdirectory(plugin)

message(
    "\n====================|  Spicy Zeek Plugin  |===================="
    "\n"
    "\nVersion:               ${SPICY_ZEEK_PLUGIN_VERSION} (${SPICY_ZEEK_PLUGIN_VERSION_NUMBER})"
    "\nBuild type:            ${CMAKE_BUILD_TYPE}"
    "\nModules directory:     ${SPICY_ZEEK_MODULE_DIR}"
    "\nScripts directory:     ${SPICY_ZEEK_SCRIPTS_DIR}"
    "\nZeek debug build:      ${ZEEK_DEBUG_BUILD}"
    "\nspicy-config:          ${SPICY_CONFIG}"
    "\nzeek-config:           ${ZEEK_CONFIG}"
    "\n"
    "\n========================================================================\n")
