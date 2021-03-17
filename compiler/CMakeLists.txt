# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

set(SOURCES driver.cc glue-compiler.cc)

add_library(zeek-compiler OBJECT ${SOURCES})
spicy_include_directories(zeek-compiler PRIVATE)
spicy_link_libraries(zeek-compiler PRIVATE)
target_compile_options(zeek-compiler PRIVATE "-fPIC")
target_link_libraries(zeek-compiler PRIVATE spicy)

if ( ${ZEEK_VERSION_NUMBER} GREATER_EQUAL 30300 ) # Zeek >= 3.3 (aka 4.0)
    target_compile_definitions(zeek-compiler PUBLIC "HAVE_PACKET_ANALYZERS")
endif ()

add_executable(spicyz bin/spicyz.cc)
spicy_include_directories(spicyz PRIVATE)
spicy_link_executable(spicyz)
target_compile_options(spicyz PRIVATE "-Wall")
target_link_libraries(spicyz PRIVATE zeek-compiler)

# Note we don't install spicyz, but instead symlink it into the plugin directory
# so that you relative search paths keep working.

if ( SPICY_IN_TREE_BUILD )
    # By default, the spicyz binary will land only inside the plugin directory.
    # Link it into the binary output directory as well.
    add_custom_command(TARGET spicyz POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/spicyz
                                                   ${SPICY_CMAKE_RUNTIME_OUTPUT_DIRECTORY}/spicyz)
endif ()
