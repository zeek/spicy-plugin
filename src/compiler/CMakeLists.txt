# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

add_executable(spicyz driver.cc glue-compiler.cc main.cc)
target_compile_options(spicyz PRIVATE "-Wall")

spicy_include_directories(spicyz PRIVATE)
spicy_link_executable(spicyz)

install(TARGETS spicyz DESTINATION ${CMAKE_INSTALL_BINDIR})
