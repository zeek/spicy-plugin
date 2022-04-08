# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

###
### Set up project.
###

file(STRINGS "VERSION" ZEEK_SPICY_PLUGIN_VERSION)
string(REGEX MATCH "(([0-9]*)\.([0-9]*)\.([0-9]*)).*" _ ${ZEEK_SPICY_PLUGIN_VERSION})
set(ZEEK_SPICY_PLUGIN_VERSION_MAIN "${CMAKE_MATCH_1}" CACHE STRING "")
set(ZEEK_SPICY_PLUGIN_VERSION_MAJOR "${CMAKE_MATCH_2}" CACHE STRING "")
set(ZEEK_SPICY_PLUGIN_VERSION_MINOR "${CMAKE_MATCH_3}" CACHE STRING "")
set(ZEEK_SPICY_PLUGIN_VERSION_PATCH "${CMAKE_MATCH_4}" CACHE STRING "")
math(EXPR ZEEK_SPICY_PLUGIN_VERSION_NUMBER "${ZEEK_SPICY_PLUGIN_VERSION_MAJOR} * 10000 \
    + ${ZEEK_SPICY_PLUGIN_VERSION_MINOR} * 100 \
    + ${ZEEK_SPICY_PLUGIN_VERSION_PATCH}")

# Add the variable to the CMake cache so it becomes visible to other projects.
set(ZEEK_SPICY_PLUGIN_VERSION_NUMBER "${ZEEK_SPICY_PLUGIN_VERSION_NUMBER}" CACHE STRING "")

project(SpicyPlugin VERSION "${ZEEK_SPICY_PLUGIN_VERSION_MAIN}" LANGUAGES CXX)

###
### Extra dist files.
###

set(AUX_CMAKE cmake/FindSpicy.cmake cmake/FindZeek.cmake cmake/ZeekSpicyAnalyzerSupport.cmake)

set(AUX_HEADERS
    include/zeek-spicy/cookie.h
    include/zeek-spicy/debug.h
    include/zeek-spicy/driver.h
    include/zeek-spicy/file-analyzer.h
    include/zeek-spicy/packet-analyzer.h
    include/zeek-spicy/plugin.h
    include/zeek-spicy/protocol-analyzer.h
    include/zeek-spicy/runtime-support.h
    include/zeek-spicy/zeek-compat.h
    include/zeek-spicy/zeek-reporter.h)

set(AUX_SPICY spicy/zeek.spicy spicy/zeek_file.spicy spicy/zeek_rt.hlt)

set(AUX_TESTS tests/random.seed)

set(AUX_TESTS_SCRIPTS
    tests/Scripts/canonify-zeek-log
    tests/Scripts/canonify-zeek-log-sorted
    tests/Scripts/diff-remove-abspath
    tests/Scripts/diff-remove-timestamps
    tests/Scripts/diff-sort
    tests/Scripts/spicy-version
    tests/Scripts/zeek-version)

###
### Set up dependencies.
###

include(GNUInstallDirs)

list(PREPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package(Spicy REQUIRED)
find_package(Zeek REQUIRED)

spicy_require_version("1.3.0")
zeek_require_version("3.0.0")

###
### Configure build
####

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# CMake uses -O2 by default with RelWithDebInfo.
string(REPLACE "-O2" "-O3" CMAKE_CXX_FLAGS_RELWITHDEBINFO ${CMAKE_CXX_FLAGS_RELWITHDEBINFO})

include_directories(BEFORE ${PROJECT_BINARY_DIR}/include)
include_directories(BEFORE ${PROJECT_SOURCE_DIR}/include)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

if (ZEEK_PLUGIN_INTERNAL_BUILD)
    set(ZEEK_SPICY_PLUGIN_INTERNAL_BUILD "yes")
else ()
    set(ZEEK_SPICY_PLUGIN_INTERNAL_BUILD "no")
endif ()

if (ZEEK_DEBUG_BUILD)
    set(ZEEK_DEBUG_BUILD "yes") # Prettify output
else ()
    set(ZEEK_DEBUG_BUILD "no")
endif ()

if (NOT CMAKE_BUILD_TYPE)
    # We follow Zeek's build mode by default.
    if (ZEEK_DEBUG_BUILD)
        set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "" FORCE)
    else ()
        set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "" FORCE)
    endif ()
endif ()

if (SPICY_HAVE_TOOLCHAIN)
    set(ZEEK_SPICY_PLUGIN_USE_JIT "yes")
else ()
    set(ZEEK_SPICY_PLUGIN_USE_JIT "no")
endif ()

if (SPICY_HAVE_TOOLCHAIN)
    add_subdirectory(src/compiler)
endif ()

###
### Setup Zeek plugin
###

list(APPEND CMAKE_MODULE_PATH "${ZEEK_CMAKE_DIR}")

# Prepare environment for Zeek's BroPlugin
set(BROKER_ROOT_DIR "${ZEEK_PREFIX}")
set(BRO_CONFIG_CMAKE_DIR "${ZEEK_CMAKE_DIR}")
set(BRO_CONFIG_INCLUDE_DIR "${ZEEK_INCLUDE_DIRS}")
set(BRO_CONFIG_PLUGIN_DIR "${ZEEK_PLUGIN_DIR}")
set(BRO_CONFIG_PREFIX "${ZEEK_PREFIX}")
set(BRO_PLUGIN_BASE "${PROJECT_SOURCE_DIR}")
set(BinPAC_ROOT_DIR "${ZEEK_PREFIX}")
set(CAF_ROOT_DIR "${ZEEK_PREFIX}")

set(save_c_flags ${CMAKE_C_FLAGS})
set(save_cxx_flags ${CMAKE_CXX_FLAGS})
include(BroPlugin)
set(CMAKE_C_FLAGS ${save_c_flags})
set(CMAKE_CXX_FLAGS ${save_cxx_flags})

zeek_plugin_begin(_Zeek Spicy)

if (SPICY_HAVE_TOOLCHAIN)
    zeek_plugin_cc(src/driver.cc)
endif ()

zeek_plugin_cc(src/file-analyzer.cc)
zeek_plugin_cc(src/plugin.cc)
zeek_plugin_cc(src/packet-analyzer.cc)
zeek_plugin_cc(src/protocol-analyzer.cc)
zeek_plugin_cc(src/runtime-support.cc)
zeek_plugin_cc(src/zeek-reporter.cc)

zeek_plugin_bif(src/consts.bif)
zeek_plugin_bif(src/events.bif)
zeek_plugin_bif(src/functions.bif)

if (ZEEK_DEBUG_BUILD)
    # This one needs the DEBUG defined earlier than zeek-compat would.
    set_source_files_properties(functions.bif.cc PROPERTIES COMPILE_DEFINITIONS DEBUG=1)
endif ()

zeek_plugin_dist_files(include/zeek-spicy/autogen/config.h)

foreach (i ${AUX_CMAKE} ${AUX_HEADERS} ${AUX_SPICY} ${AUX_TESTS} ${AUX_TESTS_SCRIPTS})
    zeek_plugin_dist_files(${i})
endforeach ()

zeek_plugin_end()

if (ZEEK_SPICY_PLUGIN_INTERNAL_BUILD)
    if (SPICY_HAVE_TOOLCHAIN)
        zeek_plugin_link_library($<TARGET_OBJECTS:zeek-compiler>)
        # This gets picked up when linking the "zeek" binary.
        set(zeekdeps ${zeekdeps} ${HILTI_LIBRARY} ${SPICY_LIBRARY} PARENT_SCOPE)
    endif ()
else ()
    if (SPICY_HAVE_TOOLCHAIN)
        target_link_libraries(${_plugin_lib} zeek-compiler)
    endif ()

    spicy_link_libraries(${_plugin_lib})
endif ()

spicy_include_directories(${_plugin_lib} PRIVATE)
set_property(TARGET ${_plugin_lib} PROPERTY ENABLE_EXPORTS true)

####
#### Prepare the plugin build directory so that it resembles our installation layout.
####

# Generate autogen headers directly inside the plugin's build directory.
set(AUTOGEN_H "${PROJECT_BINARY_DIR}/include/zeek-spicy/autogen")
file(MAKE_DIRECTORY ${AUTOGEN_H})

if (ZEEK_SPICY_PLUGIN_INTERNAL_BUILD)
    # The static build doesn't put the aux files into the build directory
    # We create links to get the same effect.
    file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")
    file(CREATE_LINK "${PROJECT_BINARY_DIR}"
         "${PROJECT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}/zeek-spicy" SYMBOLIC)

    file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/cmake")
    file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/spicy")
    file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/tests")
    file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/tests/Scripts")

    add_custom_target(
        copy-zeek-spicy-dist-files ALL
        COMMENT "Copying distribution files"
        COMMAND ${CMAKE_COMMAND} -E copy ${AUX_HEADERS} ${PROJECT_BINARY_DIR}/include/zeek-spicy/
        COMMAND ${CMAKE_COMMAND} -E copy ${AUX_CMAKE} ${PROJECT_BINARY_DIR}/cmake/
        COMMAND ${CMAKE_COMMAND} -E copy ${AUX_SPICY} ${PROJECT_BINARY_DIR}/spicy/
        COMMAND ${CMAKE_COMMAND} -E copy ${AUX_TESTS} ${PROJECT_BINARY_DIR}/tests/
        COMMAND ${CMAKE_COMMAND} -E copy ${AUX_TESTS_SCRIPTS} ${PROJECT_BINARY_DIR}/tests/Scripts/
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

    # Note for static builds: We can't easily make Zeek's include headers
    # available inside the build directory. They need to be already installed
    # somewhere. Then set HILTI_CXX_INCLUDE_DIRS accordingly.
endif ()

####
#### Set up installation.
####

set(ZEEK_SPICY_MODULE_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/zeek-spicy/modules" CACHE PATH "")
install(DIRECTORY DESTINATION "${ZEEK_SPICY_MODULE_DIR}")

set(plugin_base "${CMAKE_INSTALL_FULL_LIBDIR}/zeek-spicy")

install(DIRECTORY "${PROJECT_SOURCE_DIR}/spicy" DESTINATION "${plugin_base}")
install(DIRECTORY "${PROJECT_BINARY_DIR}/include" DESTINATION "${plugin_base}")

foreach (aux ${AUX_CMAKE} ${AUX_SPICY} ${AUX_TESTS} ${AUX_TESTS_SCRIPTS})
    get_filename_component(dir "${aux}" DIRECTORY)
    install(PROGRAMS "${aux}" DESTINATION "${plugin_base}/${dir}/")
endforeach ()

if (ZEEK_SPICY_PLUGIN_INTERNAL_BUILD)
    # Install along with Zeek.
    set(ZEEK_SPICY_SCRIPTS_DIR "" CACHE PATH "") # not needed when running from inside Zeek
    get_filename_component(ZEEK_SPICY_STATIC_BUILD_NAME "${PROJECT_SOURCE_DIR}" NAME)
else ()
    # Standard standalone install.
    set(PLUGIN_INSTALL_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/zeek-spicy")
    set(ZEEK_SPICY_SCRIPTS_DIR "${plugin_base}/scripts" CACHE PATH "")

    install(DIRECTORY "${PROJECT_BINARY_DIR}/lib" DESTINATION "${plugin_base}")
    install(DIRECTORY "${PROJECT_SOURCE_DIR}/scripts" DESTINATION "${plugin_base}")
    install(FILES "${PROJECT_BINARY_DIR}/__bro_plugin__" DESTINATION "${plugin_base}")

    install(DIRECTORY DESTINATION "${plugin_base}/${CMAKE_INSTALL_LIBDIR}")

    # Build + Install: Set absolute RPATH to Spicy libs.
    set_target_properties(${_plugin_lib} PROPERTIES BUILD_RPATH "${SPICY_LIBRARY_DIRS_RUNTIME}")
    set_target_properties(spicyz PROPERTIES BUILD_RPATH "${SPICY_LIBRARY_DIRS_RUNTIME}")
    set_target_properties(${_plugin_lib} PROPERTIES INSTALL_RPATH "${SPICY_LIBRARY_DIRS_RUNTIME}")
    set_target_properties(spicyz PROPERTIES INSTALL_RPATH "${SPICY_LIBRARY_DIRS_RUNTIME}")
endif ()

###
### Create config file.
###

configure_file(${PROJECT_SOURCE_DIR}/include/config.h.in ${AUTOGEN_H}/config.h)

###
### Print summaries
###

spicy_print_summary()
zeek_print_summary()

message(
    "\n====================|  Spicy Zeek Plugin  |===================="
    "\n"
    "\nVersion:               ${ZEEK_SPICY_PLUGIN_VERSION} (${ZEEK_SPICY_PLUGIN_VERSION_NUMBER})"
    "\nBuild type:            ${CMAKE_BUILD_TYPE}"
    "\nModules directory:     ${ZEEK_SPICY_MODULE_DIR}"
    "\nScripts directory:     ${ZEEK_SPICY_SCRIPTS_DIR}"
    "\nBuild directory:       ${PROJECT_BINARY_DIR}"
    "\nHave JIT:              ${ZEEK_SPICY_PLUGIN_USE_JIT}"
    "\nZeek debug build:      ${ZEEK_DEBUG_BUILD}"
    "\nZeek-internal build:   ${ZEEK_SPICY_PLUGIN_INTERNAL_BUILD}"
    "\nspicy-config:          ${SPICY_CONFIG}"
    "\nzeek-config:           ${ZEEK_CONFIG}"
    "\n"
    "\n========================================================================\n")
