# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${ZEEK_CMAKE_DIR}")

OPTION(SPICY_ZEEK_INSTALL_PLUGIN "Install Zeek plugin into Zeek installation with in-tree build" ON)

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

set(ZEEK_SCRIPTS
    scripts/__load__.zeek
    scripts/base/spicy/__load__.zeek
    scripts/base/spicy/main.zeek
    scripts/misc/record-spicy-batch.zeek
    )

set(SPICY_SCRIPTS
    spicy/zeek.spicy
    spicy/zeek_rt.hlt
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

zeek_plugin_dist_files(spicy/zeek.spicy)
zeek_plugin_dist_files(spicy/zeek_rt.hlt)
zeek_plugin_dist_files(bin/spicyz)

foreach (hdr ${HEADERS})
    zeek_plugin_dist_files(include/zeek-spicy/${hdr})
endforeach()

zeek_plugin_dist_files(include/zeek-spicy/autogen/config.h)

set_source_files_properties(src/plugin.cc PROPERTIES OBJECT_DEPENDS "${deps}")

if ( SPICY_IN_TREE_BUILD )
    # We disable Zeek's standard installation logic so that we control
    # things better (like RPATHs etc.). Unfortunately Zeek doesn't just
    # have a "no install, please" switch, so we change its destination
    # to some scratch space.
    set(BRO_PLUGIN_BRO_PLUGIN_INSTALL_PATH "${CMAKE_CURRENT_BINARY_DIR}/zeek-install-scratch")
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/zeek-install-scratch") # suppress warning by Zeek
endif ()

zeek_plugin_end()

if ( SPICY_HAVE_TOOLCHAIN )
    target_link_libraries(${_plugin_lib} zeek-compiler)
endif ()

spicy_include_directories(${_plugin_lib} PRIVATE)
spicy_link_libraries(${_plugin_lib})
target_include_directories(${_plugin_lib} BEFORE PRIVATE include)
set_property(TARGET ${_plugin_lib} PROPERTY ENABLE_EXPORTS true)

# Copy Spicy & Zeek scripts into plugin directory. This nixes the "scripts" symlink that
# the Zeek plugin infrastructure puts in place.
add_custom_target(copy-scripts DEPENDS ${ZEEK_SCRIPTS} ${SPICY_SCRIPTS}
                   COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_BINARY_DIR}/spicy
                   COMMAND ${CMAKE_COMMAND} -E remove -f ${CMAKE_CURRENT_BINARY_DIR}/scripts
                   COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_BINARY_DIR}/scripts
                   COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/spicy ${ZEEK_SPICY_PLUGIN_BUILD_DIR}/spicy
                   COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/scripts ${ZEEK_SPICY_PLUGIN_BUILD_DIR}/scripts
                   )

add_dependencies(${_plugin_lib} copy-scripts)

# Generate autogen headers directly inside the plugin's build directory.
set(AUTOGEN_H "${ZEEK_SPICY_PLUGIN_BUILD_DIR}/include/zeek-spicy/autogen")
file(MAKE_DIRECTORY ${AUTOGEN_H})

# Copy runtime headers into plugin directory.
foreach (hdr ${HEADERS})
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/zeek-spicy/${hdr} ${ZEEK_SPICY_PLUGIN_BUILD_DIR}/include/zeek-spicy/${hdr} COPYONLY)
endforeach()

# Set up installation of the plugin. A "normal" zkg build won't use this, but
# this faciliates a manual "make install".

set(PLUGIN_INSTALL_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/spicy/_Zeek_Spicy")

install(FILES     ${CMAKE_CURRENT_BINARY_DIR}/__bro_plugin__
    DESTINATION "${PLUGIN_INSTALL_DIR}")

foreach(i bin include lib scripts spicy)
    install(DIRECTORY ${ZEEK_SPICY_PLUGIN_BUILD_DIR}/${i} DESTINATION "${PLUGIN_INSTALL_DIR}" USE_SOURCE_PERMISSIONS)
endforeach ()

set(SPICY_ZEEK_MODULE_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/spicy/zeek")
install(DIRECTORY DESTINATION "${SPICY_ZEEK_MODULE_DIR}")

install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})
install_symlink("${PLUGIN_INSTALL_DIR}/bin/spicyz" ${CMAKE_INSTALL_FULL_BINDIR}/spicyz)

if ( SPICY_IN_TREE_BUILD )
    # Build: Set RPATH relative inside build tree, and also add an absolute RPATH to Spicy install.
    # Note that this is also used when manually moving the built plugin around.
    make_install_rpath(rpath_build ${BRO_PLUGIN_LIB} ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    set_target_properties(${_plugin_lib} PROPERTIES BUILD_RPATH "${rpath_build};${CMAKE_INSTALL_FULL_LIBDIR}")
    set_target_properties(spicyz         PROPERTIES BUILD_RPATH "${rpath_build};${CMAKE_INSTALL_FULL_LIBDIR}")

    # Install: Set RPATH relative inside install tree. (Note that we don't install spicyz, just symlink it.)
    make_install_rpath(rpath_install ${PLUGIN_INSTALL_DIR} ${CMAKE_INSTALL_FULL_LIBDIR})
    set_target_properties(${_plugin_lib} PROPERTIES INSTALL_RPATH "${rpath_install}")

    if ( SPICY_ZEEK_INSTALL_PLUGIN )
        # This may need additional permissions, but we just leave it fail in that case.
        install_symlink("${PLUGIN_INSTALL_DIR}" "${ZEEK_PLUGIN_DIR}/_Zeek_Spicy")
    endif ()
else ()
    # Build + Install: Set absolute RPATH to Spicy libs.
    set_target_properties(${_plugin_lib} PROPERTIES INSTALL_RPATH "${SPICY_LIBRARY_DIRS_RUNTIME}")
    set_target_properties(spicyz         PROPERTIES BUILD_RPATH   "${SPICY_LIBRARY_DIRS_RUNTIME}")
    set_target_properties(${_plugin_lib} PROPERTIES INSTALL_RPATH "${SPICY_LIBRARY_DIRS_RUNTIME}")
endif ()

add_custom_target(zeek-spicy-plugin DEPENDS ${_plugin_lib})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/config.h.in ${AUTOGEN_H}/config.h)
