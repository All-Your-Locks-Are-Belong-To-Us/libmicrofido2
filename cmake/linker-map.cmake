set(command ${CMAKE_C_COMPILER} ${flags} -Wl,--version)


function(add_linker_map_for_target TARGET)
    if (APPLE)
        # LLVM only understands this flag.
        # The map output differs from GNU ld.
        target_link_options(${TARGET} PRIVATE "-Wl,-map,${TARGET}.map")
    else()
        target_link_options(${TARGET} PRIVATE "-Wl,-Map=${TARGET}.map")
    endif()
endfunction()
