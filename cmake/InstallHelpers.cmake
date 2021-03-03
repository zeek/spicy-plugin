
# Install a set of header files from a directory location.
function(install_headers src dst)
    if ( NOT IS_ABSOLUTE "${src}" )
        set(src "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
    endif ()

    if ( NOT IS_ABSOLUTE "${dst}" )
        set(dst_msg "${CMAKE_INSTALL_FULL_INCLUDEDIR}/${dst}")
        set(dst "${CMAKE_INSTALL_INCLUDEDIR}/${dst}")
    endif ()

    if ( ARGN )
        foreach ( i ${ARGN} )
            install(FILES ${src}/${i} DESTINATION ${dst})
        endforeach ()
    else ()
        install(CODE "message(STATUS \"Installing: ${dst_msg}/*\")")

        install(DIRECTORY ${src}/
                          DESTINATION ${dst}
                          MESSAGE_NEVER
                          FILES_MATCHING PATTERN "*.h"
                                         PATTERN "*.hpp"
                                         PATTERN "*.hh"
                                         PATTERN "3rdparty*" EXCLUDE
                          )
    endif ()
endfunction ()

# Add a symlink at installation time.
function(install_symlink filepath sympath)
    install(CODE "message(\"-- Creating symbolic link: ${sympath} -> ${filepath}\")")
    install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${filepath} ${sympath})")
endfunction(install_symlink)

# Initialize a variable that'll go into a {hilti,spicy}/config.cc
# file. This performans some normalization: turn lists into
# space-separated strings and strip/reduce whitespace.
function(set_config_val dst val)
    if ( NOT "${val}" STREQUAL "" )
        string(REPLACE ";" " " _x "${val}")
        string(STRIP "${_x}" _x)
        string(REGEX REPLACE "  *" " " _x "${_x}")
        set(${dst} "${_x}" PARENT_SCOPE)
    else ()
        set(${dst} "" PARENT_SCOPE)
    endif ()
endfunction()
