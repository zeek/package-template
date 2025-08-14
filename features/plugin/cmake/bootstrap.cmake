# Do not change this file if at all possible. If anything, use the most
# recent one from the zeek/package-template repo. Thanks!
execute_process(
    COMMAND zeek-config --cmake_dir
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE zeek_config_result
    ERROR_VARIABLE zeek_config_error
    OUTPUT_VARIABLE zeek_cmake_dir
)

if ( NOT zeek_config_result EQUAL 0)
    message(FATAL_ERROR "zeek-config failed: ${zeek_config_error} ${zeek_config_result}")
endif()

message(STATUS "Looking for Zeek CMake modules in ${zeek_cmake_dir}")
list(PREPEND CMAKE_MODULE_PATH "${zeek_cmake_dir}")
