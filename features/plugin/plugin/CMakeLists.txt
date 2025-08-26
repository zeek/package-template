configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

include(ZeekPlugin)

zeek_plugin_begin(@NS@ @NAME@)

file(GLOB cc_files RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "src/*.cc")
foreach(file ${cc_files})
    zeek_plugin_cc(${file})
endforeach ()

file(GLOB bif_files RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "src/*.bif")
foreach(file ${bif_files})
    zeek_plugin_bif(${file})
endforeach ()

# Copy the dist files to package with the tarball into the top-level
# build directory to fulfill zeek-plugin-create-package.sh assumptions
# about them being located in the parent directory.
set(dist_files README CHANGES COPYING VERSION)
foreach(file ${dist_files})
    if ( EXISTS ../${file} )
        file(COPY ../${file} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/../)
    endif()
endforeach ()

zeek_plugin_dist_files(${dist_files})

zeek_plugin_end()
