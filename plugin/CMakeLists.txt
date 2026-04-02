cmake_minimum_required(VERSION 3.20)
project(x64dbg_mcp_plugin LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "x64dbg plugins can only be built on Windows")
endif()

set(SDK_DIR "${CMAKE_CURRENT_LIST_DIR}/../vendor/pluginsdk")
if(NOT EXISTS "${SDK_DIR}/_plugins.h")
  message(FATAL_ERROR "x64dbg plugin SDK not found at ${SDK_DIR}")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(X64DBG_SUFFIX "dp64")
  set(X64DBG_PREFIX "x64")
  set(JANSSON_ARCH "x64")
else()
  set(X64DBG_SUFFIX "dp32")
  set(X64DBG_PREFIX "x32")
  set(JANSSON_ARCH "x86")
endif()

add_library(x64dbg_mcp SHARED src/pluginmain.cpp)
target_compile_features(x64dbg_mcp PRIVATE cxx_std_17)
target_include_directories(
  x64dbg_mcp
  PRIVATE
    "${SDK_DIR}"
    "${SDK_DIR}/jansson"
)
target_link_libraries(
  x64dbg_mcp
  PRIVATE
    ws2_32
    "${SDK_DIR}/${X64DBG_PREFIX}bridge.lib"
    "${SDK_DIR}/${X64DBG_PREFIX}dbg.lib"
    "${SDK_DIR}/jansson/jansson_${JANSSON_ARCH}.lib"
)
target_compile_definitions(x64dbg_mcp PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
set_target_properties(
  x64dbg_mcp
  PROPERTIES
    OUTPUT_NAME "x64dbg_mcp"
    PREFIX ""
    SUFFIX ".${X64DBG_SUFFIX}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/dist"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/dist"
)
