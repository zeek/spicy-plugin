# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

set(SOURCES driver.cc glue-compiler.cc)

add_library(zeek-compiler OBJECT ${SOURCES})
spicy_include_directories(zeek-compiler PRIVATE)
spicy_link_libraries(zeek-compiler PRIVATE)
target_compile_options(zeek-compiler PRIVATE "-fPIC")
target_link_libraries(zeek-compiler PRIVATE spicy)

if (${ZEEK_VERSION_NUMBER} GREATER_EQUAL 30300) # Zeek >= 3.3 (aka 4.0)
    target_compile_definitions(zeek-compiler PUBLIC "HAVE_PACKET_ANALYZERS")
endif ()

add_executable(spicyz bin/spicyz.cc)
target_link_libraries(spicyz PRIVATE zeek-compiler)
spicy_include_directories(spicyz PRIVATE)
spicy_link_executable(spicyz)
target_compile_options(spicyz PRIVATE "-Wall")
install(TARGETS spicyz DESTINATION ${CMAKE_INSTALL_BINDIR})
