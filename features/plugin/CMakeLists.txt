cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

find_program(ZEEK_CONFIG zeek-config REQUIRED)

execute_process(
  COMMAND ${ZEEK_CONFIG} --cmake_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE
  OUTPUT_VARIABLE zeek_cmake_dir COMMAND_ERROR_IS_FATAL ANY)

list(PREPEND CMAKE_MODULE_PATH "${zeek_cmake_dir}")

project(
  ZeekPlugin@NAME@
  VERSION 0.1.0
  LANGUAGES CXX)

configure_file("plugin/src/config.h.in" "config.h" @ONLY)

set(BRO_PLUGIN_BASE "${CMAKE_CURRENT_SOURCE_DIR}/plugin")

include(ZeekPlugin)

file(GLOB cc_files
  RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
  "plugin/src/*.cc"
  CONFIGURE_DEPENDS)
file(GLOB bif_files
  RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
  "plugin/src/*.bif"
  CONFIGURE_DEPENDS)

zeek_add_plugin(
  @NS@
  @NAME@
  SOURCES
  ${cc_files}
  BIFS
  ${bif_files}
  DIST_FILES
  README
  COPYING)

target_include_directories(@NS@_@NAME@
                           PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/plugin/src)
