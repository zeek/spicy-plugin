# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.
#
# Helpers for building analyzers. This is can be included from analyzer packages.
#
# Needs SPICYZ to point to the "spicyz" binary in either CMake or environment.

include(GNUInstallDirs)

# Add target to build an analyzer. Arguments are the name of the analyzer and a
# variable number of source files for `spicyz`.
function(spicy_add_analyzer name)
    set(sources "${ARGN}")
    string(TOLOWER "${name}" name_lower)
    set(output "${SPICY_MODULE_OUTPUT_DIR_BUILD}/${name_lower}.hlto")
    set(output_install "${SPICY_MODULE_OUTPUT_DIR_INSTALL}/${name_lower}.hlto")
    set(deps "spicyz")

    add_custom_command(
        OUTPUT ${output}
        DEPENDS ${sources} ${deps}
        COMMENT "Compiling ${name} analyzer"
        COMMAND mkdir -p ${SPICY_MODULE_OUTPUT_DIR_BUILD}
        COMMAND spicyz -o ${output} ${SPICYZ_FLAGS} ${sources}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )

    add_custom_target(${name} ALL DEPENDS ${output})

    if ( SPICY_MODULE_OUTPUT_DIR_INSTALL )
        install(FILES ${output} DESTINATION "${SPICY_MODULE_OUTPUT_DIR_INSTALL}")
    endif ()

    get_property(tmp GLOBAL PROPERTY __spicy_included_analyzers)
    list(APPEND tmp "${name}")
    set_property(GLOBAL PROPERTY __spicy_included_analyzers "${tmp}")
endfunction()

# Flag that analyzer is *not* being built. This is purely informational:
# the cmake output will contain a corresponding note. Arguments are the
# name of the analyzers and a descriptive string explaining why it's
# being skipped.
function(spicy_skip_analyzer name reason)
    get_property(tmp GLOBAL PROPERTY __spicy_skipped_analyzers)
    list(APPEND tmp "${name} ${reason}")
    set_property(GLOBAL PROPERTY __spicy_skipped_analyzers "${tmp}")
endfunction()

function(print_analyzers)
    message("\n======================|  Spicy Analyzer Summary  |======================")

    message(
        "\nspicy-config:          ${SPICY_CONFIG}"
        "\nzeek-config:           ${ZEEK_CONFIG}"
        "\nSpicy compiler:        ${SPICYZ}"
        "\nModule directory:      ${SPICY_MODULE_OUTPUT_DIR_INSTALL}"
        "\nScripts directory:     ${SPICY_SCRIPTS_OUTPUT_DIR_INSTALL}"
        "\nPlugin version:        ${ZEEK_SPICY_PLUGIN_VERSION} (${ZEEK_SPICY_PLUGIN_VERSION_NUMBER})"
        )

    if ( NOT SPICYZ )
        message("\n    Make sure spicyz is in your PATH, or set SPICYZ to its location.")
    endif ()

    get_property(included GLOBAL PROPERTY __spicy_included_analyzers)
    message("\nAvailable analyzers:\n")
    foreach ( x ${included})
        message("    ${x}")
    endforeach ()

    get_property(skipped GLOBAL PROPERTY __spicy_skipped_analyzers)
    if ( skipped )
        message("\nSkipped analyzers:\n")
        foreach ( x ${skipped})
            message("    ${x}")
        endforeach ()
    endif ()

    message("\n========================================================================\n")
endfunction()

### Main

set_property(GLOBAL PROPERTY __spicy_included_analyzers)
set_property(GLOBAL PROPERTY __spicy_skipped_analyzers)

if ( NOT SPICYZ )
    set(SPICYZ "$ENV{SPICYZ}")
endif ()

if ( SPICYZ )
    message(STATUS "spicyz: ${SPICYZ}")

    add_executable(spicyz IMPORTED)
    set_property(TARGET spicyz PROPERTY IMPORTED_LOCATION "${SPICYZ}")

    if ( "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" )
        set(SPICYZ_FLAGS "-d")
    else ()
        set(SPICYZ_FLAGS "")
    endif ()

    set(SPICY_MODULE_OUTPUT_DIR_BUILD "${PROJECT_BINARY_DIR}/spicy-modules")

    execute_process(COMMAND "${SPICYZ}" "--print-module-path"
        OUTPUT_VARIABLE output
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(SPICY_MODULE_OUTPUT_DIR_INSTALL "${output}" CACHE STRING "")

    execute_process(COMMAND "${SPICYZ}" "--print-scripts-path"
        OUTPUT_VARIABLE output
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(SPICY_SCRIPTS_OUTPUT_DIR_INSTALL "${output}" CACHE STRING "")

    execute_process(COMMAND "${SPICYZ}" "--version"
        OUTPUT_VARIABLE output
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(ZEEK_SPICY_PLUGIN_VERSION "${output}" CACHE STRING "")

    execute_process(COMMAND "${SPICYZ}" "--version-number"
        OUTPUT_VARIABLE output
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(ZEEK_SPICY_PLUGIN_VERSION_NUMBER "${output}" CACHE STRING "")
else ()
    message(WARNING "spicyz: not specified")
endif ()
