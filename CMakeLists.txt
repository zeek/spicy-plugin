# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

###
### Configure build.
###

OPTION(SPICY_ZEEK_INSTALL_PLUGIN "Install Zeek plugin into Zeek installation with in-tree build" ON)

file(STRINGS "VERSION.dat" SPICY_ZEEK_PLUGIN_VERSION)

string(REGEX MATCH "(([0-9]*)\.([0-9]*)\.([0-9]*)).*" _ ${SPICY_ZEEK_PLUGIN_VERSION})
set(SPICY_ZEEK_PLUGIN_VERSION_MAIN  ${CMAKE_MATCH_1} CACHE STRING "")
set(SPICY_ZEEK_PLUGIN_VERSION_MAJOR ${CMAKE_MATCH_2} CACHE STRING "")
set(SPICY_ZEEK_PLUGIN_VERSION_MINOR ${CMAKE_MATCH_3} CACHE STRING "")
set(SPICY_ZEEK_PLUGIN_VERSION_PATCH ${CMAKE_MATCH_4} CACHE STRING "")
math(EXPR SPICY_ZEEK_PLUGIN_VERSION_NUMBER "${SPICY_ZEEK_PLUGIN_VERSION_MAJOR} * 10000 + ${SPICY_ZEEK_PLUGIN_VERSION_MINOR} * 100 + ${SPICY_ZEEK_PLUGIN_VERSION_PATCH}")
set(SPICY_ZEEK_PLUGIN_VERSION_NUMBER "${SPICY_ZEEK_PLUGIN_VERSION_NUMBER}" CACHE STRING "")

# Add the variable to the CMake cache so it becomes visible to other projects.
set(SPICY_ZEEK_PLUGIN_VERSION_NUMBER "${SPICY_ZEEK_PLUGIN_VERSION_NUMBER}" CACHE STRING "")

project(SpicyPlugin VERSION "${SPICY_ZEEK_PLUGIN_VERSION_MAIN}" LANGUAGES CXX)

list(PREPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_package(Spicy)
find_package(Zeek)

if ( NOT Zeek_FOUND )
    if ( "${SPICY_IN_TREE_BUILD}" )
        # Ok to build without Zeek executable
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

if ( SPICY_HAVE_TOOLCHAIN AND NOT ZEEK_PLUGIN_INTERNAL_BUILD )
    set(SPICY_PLUGIN_USE_JIT "yes")
else ()
    set(SPICY_PLUGIN_USE_JIT "no")
endif ()

if ( ZEEK_PLUGIN_INTERNAL_BUILD )
    set(SPICY_ZEEK_PLUGIN_INTERNAL_BUILD "yes")

    # Install along with Zeek.
    set(SPICY_ZEEK_INSTALL_PREFIX "${CMAKE_INSTALL_DATAROOTDIR}")
    set(plugin_base "${CMAKE_INSTALL_FULL_DATAROOTDIR}/zeek-spicy") # no binary stuff, use "share/" like Zeek
else ()
    set(SPICY_ZEEK_PLUGIN_INTERNAL_BUILD "no")

    # Standard standalone install.
    set(SPICY_ZEEK_INSTALL_PREFIX "${CMAKE_INSTALL_LIBDIR}")
    set(plugin_base "${CMAKE_INSTALL_FULL_LIBDIR}/zeek-spicy")
endif ()

if ( ZEEK_DEBUG_BUILD )
    set(ZEEK_DEBUG_BUILD "yes") # Prettify output
else ()
    set(ZEEK_DEBUG_BUILD "no")
endif ()

if ( NOT "${SPICY_IN_TREE_BUILD}" )
    set(ZEEK_SPICY_PLUGIN_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

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
    set(ZEEK_SPICY_PLUGIN_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
endif ()

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(BEFORE ${ZEEK_SPICY_PLUGIN_BUILD_DIR}/include)

if ( NOT SPICY_IN_TREE_BUILD )
        spicy_print_summary()
endif ()

zeek_print_summary()

if ( SPICY_HAVE_TOOLCHAIN )
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
set(BRO_PLUGIN_BASE "${CMAKE_CURRENT_SOURCE_DIR}")
set(BinPAC_ROOT_DIR "${ZEEK_PREFIX}")
set(CAF_ROOT_DIR "${ZEEK_PREFIX}")

set(save_c_flags ${CMAKE_C_FLAGS})
set(save_cxx_flags ${CMAKE_CXX_FLAGS})
include(BroPlugin)
set(CMAKE_C_FLAGS ${save_c_flags})
set(CMAKE_CXX_FLAGS ${save_cxx_flags})

set(HEADERS
    cookie.h
    debug.h
    driver.h
    file-analyzer.h
    packet-analyzer.h
    plugin.h
    protocol-analyzer.h
    runtime-support.h
    zeek-compat.h
    zeek-reporter.h)

set(AUX_FILES
    cmake/FindSpicy.cmake
    cmake/FindZeek.cmake
    tests/Scripts/build-directory
    tests/Scripts/canonify-zeek-log
    tests/Scripts/diff-remove-abspath
    tests/Scripts/diff-remove-timestamps
    tests/Scripts/diff-sort
    tests/Scripts/get-path
    tests/Scripts/run-spicy-config
    tests/Scripts/run-zeek
    tests/Scripts/run-zeek-config
    tests/Scripts/spicy-version
    tests/Scripts/zeek-version
    )

zeek_plugin_begin(_Zeek Spicy)

if ( SPICY_HAVE_TOOLCHAIN )
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

if ( ZEEK_DEBUG_BUILD )
    # This one needs the DEBUG defined earlier than zeek-compat would.
    set_source_files_properties(functions.bif.cc PROPERTIES COMPILE_DEFINITIONS DEBUG=1)
endif ()

foreach (hdr ${HEADERS})
    zeek_plugin_dist_files(include/zeek-spicy/${hdr})
endforeach()

foreach (spcy ${HEADERS})
    zeek_plugin_dist_files({spcy})
endforeach()

foreach (aux ${AUX_FILES})
    zeek_plugin_dist_files(${aux})
endforeach()

zeek_plugin_dist_files(include/zeek-spicy/autogen/config.h)

if ( SPICY_IN_TREE_BUILD )
    # We disable Zeek's standard installation logic so that we control
    # things better (like RPATHs etc.). Unfortunately Zeek doesn't just
    # have a "no install, please" switch, so we change its destination
    # to some scratch space.
    set(BRO_PLUGIN_BRO_PLUGIN_INSTALL_PATH "${CMAKE_CURRENT_BINARY_DIR}/zeek-install-scratch")
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/zeek-install-scratch") # suppress warning by Zeek
endif ()

zeek_plugin_end()

if ( ZEEK_PLUGIN_INTERNAL_BUILD )
    zeek_plugin_link_library($<TARGET_OBJECTS:zeek-compiler>)
    set(zeekdeps ${zeekdeps} ${HILTI_LIBRARY} ${SPICY_LIBRARY} PARENT_SCOPE) # this gets picked up when linking the "zeek" binary
else ()
    if ( SPICY_HAVE_TOOLCHAIN )
        target_link_libraries(${_plugin_lib} zeek-compiler)
    endif ()

    spicy_link_libraries(${_plugin_lib})
endif()

spicy_include_directories(${_plugin_lib} PRIVATE)
target_include_directories(${_plugin_lib} BEFORE PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
set_property(TARGET ${_plugin_lib} PROPERTY ENABLE_EXPORTS true)

####
#### Prepare the plugin build directory so that it contains the full Zeek plugin.
####

# Generate autogen headers directly inside the plugin's build directory.
set(AUTOGEN_H "${ZEEK_SPICY_PLUGIN_BUILD_DIR}/include/zeek-spicy/autogen")
file(MAKE_DIRECTORY ${AUTOGEN_H})

# Copy runtime headers into plugin directory.
foreach (hdr ${HEADERS})
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/${hdr} ${ZEEK_SPICY_PLUGIN_BUILD_DIR}/include/zeek-spicy/${hdr} COPYONLY)
endforeach()

# Create link inside the build directory to mimic installation layout so that things work without installation.
set(build_base "${CMAKE_CURRENT_BINARY_DIR}/${SPICY_ZEEK_INSTALL_PREFIX}/zeek-spicy")
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${SPICY_ZEEK_INSTALL_PREFIX}")

file(CREATE_LINK "${ZEEK_SPICY_PLUGIN_BUILD_DIR}" "${build_base}" SYMBOLIC)
file(CREATE_LINK "${CMAKE_CURRENT_SOURCE_DIR}/spicy" "${build_base}/spicy" SYMBOLIC)

# Note: We can't easily make the Zeek include headers available inside the build directory.
# Either install them once, or set ZEEK_SPICY_INCLUDE_DIRS to the corresponding locations
# inside the Zeek tree ("ZEEK_SPICY_INCLUDE_DIRS=<build>/../src:<build>/src:<build>/src/include").

####
#### Set up installation.
####

set(SPICY_ZEEK_MODULE_DIR  "${CMAKE_INSTALL_FULL_LIBDIR}/zeek-spicy/modules" CACHE PATH "")
install(DIRECTORY DESTINATION "${SPICY_ZEEK_MODULE_DIR}")

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/spicy"       DESTINATION "${plugin_base}")
install(DIRECTORY "${ZEEK_SPICY_PLUGIN_BUILD_DIR}/include"  DESTINATION "${plugin_base}")

foreach (aux ${AUX_FILES})
    get_filename_component(dir "${aux}" DIRECTORY)
    install(FILES "${aux}" DESTINATION "${plugin_base}/${dir}/")
endforeach()

install(TARGETS spicyz DESTINATION ${CMAKE_INSTALL_BINDIR})

if ( SPICY_ZEEK_PLUGIN_INTERNAL_BUILD )
    # Install along with Zeek.
    set(SPICY_ZEEK_SCRIPTS_DIR "" CACHE PATH "") # not needed when running from inside Zeek
else ()
    # Standard standalone install.
    set(PLUGIN_INSTALL_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/zeek-spicy")
    set(SPICY_ZEEK_SCRIPTS_DIR "${plugin_base}/scripts" CACHE PATH "")

    install(DIRECTORY "${ZEEK_SPICY_PLUGIN_BUILD_DIR}/lib"                  DESTINATION "${plugin_base}")
    install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/scripts"                 DESTINATION "${plugin_base}")
    install(FILES     "${ZEEK_SPICY_PLUGIN_BUILD_DIR}/__bro_plugin__"       DESTINATION "${plugin_base}")

    install(DIRECTORY DESTINATION "${plugin_base}/${CMAKE_INSTALL_LIBDIR}")
    install_symlink("${plugin_base}" "${plugin_base}/${CMAKE_INSTALL_LIBDIR}/zeek-spicy")

    if ( SPICY_IN_TREE_BUILD )
        # Build: Set RPATH relative inside build tree, and also add an absolute RPATH to Spicy install.
        # Note that this is also used when manually moving the built plugin around.
        make_install_rpath(rpath_build ${BRO_PLUGIN_LIB} ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
        set_target_properties(${_plugin_lib} PROPERTIES BUILD_RPATH "${rpath_build};${CMAKE_INSTALL_FULL_LIBDIR}")
        set_target_properties(spicyz         PROPERTIES BUILD_RPATH "${rpath_build};${CMAKE_INSTALL_FULL_LIBDIR}")

        # Install: Set RPATH relative inside install tree. (Note that we don't install spicyz, just symlink it.)
        make_install_rpath(rpath_install "${PLUGIN_INSTALL_DIR}" "${CMAKE_INSTALL_FULL_LIBDIR}")
        set_target_properties(${_plugin_lib} PROPERTIES INSTALL_RPATH "${rpath_install}")

        if ( SPICY_ZEEK_INSTALL_PLUGIN )
            # This may need additional permissions, but we just leave it fail in that case.
            install_symlink("${PLUGIN_INSTALL_DIR}" "${ZEEK_PLUGIN_DIR}/zeek-spicy")
        endif ()
    else ()
        # Build + Install: Set absolute RPATH to Spicy libs.
        set_target_properties(${_plugin_lib} PROPERTIES BUILD_RPATH   "${SPICY_LIBRARY_DIRS_RUNTIME}")
        set_target_properties(spicyz         PROPERTIES BUILD_RPATH   "${SPICY_LIBRARY_DIRS_RUNTIME}")
        set_target_properties(${_plugin_lib} PROPERTIES INSTALL_RPATH "${SPICY_LIBRARY_DIRS_RUNTIME}")
        set_target_properties(spicyz         PROPERTIES INSTALL_RPATH "${SPICY_LIBRARY_DIRS_RUNTIME}")
    endif ()
endif ()

add_custom_target(zeek-spicy-plugin DEPENDS ${_plugin_lib})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/config.h.in ${AUTOGEN_H}/config.h)

### Print summary

message(
    "\n====================|  Spicy Zeek Plugin  |===================="
    "\n"
    "\nVersion:               ${SPICY_ZEEK_PLUGIN_VERSION} (${SPICY_ZEEK_PLUGIN_VERSION_NUMBER})"
    "\nBuild type:            ${CMAKE_BUILD_TYPE}"
    "\nModules directory:     ${SPICY_ZEEK_MODULE_DIR}"
    "\nScripts directory:     ${SPICY_ZEEK_SCRIPTS_DIR}"
    "\nBuild directory:       ${ZEEK_SPICY_PLUGIN_BUILD_DIR}"
    "\nHave JIT:              ${SPICY_PLUGIN_USE_JIT}"
    "\nZeek debug build:      ${ZEEK_DEBUG_BUILD}"
    "\nZeek-internal build:   ${SPICY_ZEEK_PLUGIN_INTERNAL_BUILD}"
    "\nspicy-config:          ${SPICY_CONFIG}"
    "\nzeek-config:           ${ZEEK_CONFIG}"
    "\n"
    "\n========================================================================\n")
