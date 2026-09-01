cmake_minimum_required(VERSION 3.19)

include(cmake/msvc-static-runtime.cmake)

project(x64dbg-mcp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(cmake/x64dbg-sdk.cmake)

x64dbg_plugin(x64dbg-mcp
    src/plugin/pluginmain.h
    src/plugin/pluginmain.cpp
    src/plugin/plugin.h
    src/plugin/plugin.cpp
    src/plugin/debugger.h
    src/plugin/debugger.cpp
    src/plugin/service.h
    src/plugin/service.cpp
)

# The plugin version is derived from the project version — a single source of truth.
# x64dbg displays pluginVersion as a single integer, so we encode
# major.minor.patch into one number: 0.1.0 -> 100, 1.2.3 -> 10203.
math(EXPR PLUGIN_VERSION_INT "${PROJECT_VERSION_MAJOR} * 10000 + ${PROJECT_VERSION_MINOR} * 100 + ${PROJECT_VERSION_PATCH}")

target_compile_definitions(x64dbg-mcp PRIVATE
    PLUGIN_VERSION=${PLUGIN_VERSION_INT}
    PLUGIN_VERSION_STR="${PROJECT_VERSION}"
)

# Vendored header-only dependencies. Versions and licenses — third_party/README.md.
add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

add_library(doctest INTERFACE)
target_include_directories(doctest INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

# Plugin core: debug state and the task queue.
# Does not depend on the x64dbg SDK, so it is tested without the debugger.
add_library(x64dbg-mcp-plugin-core STATIC
    src/plugin/debug_state.h
    src/plugin/debug_state.cpp
    src/plugin/worker.h
    src/plugin/worker.cpp
)
target_include_directories(x64dbg-mcp-plugin-core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(x64dbg-mcp PRIVATE x64dbg-mcp-plugin-core nlohmann_json)

# Code shared between the bridge and the plugin: the exchange format, frame parsing.
# Depends on neither the Windows API nor the x64dbg SDK — so it is tested separately.
add_library(x64dbg-mcp-common STATIC
    src/common/framing.h
    src/common/framing.cpp
    src/common/ipc_protocol.h
    src/common/pipe_server.h
    src/common/pipe_server.cpp
    src/common/pipe_client.h
    src/common/pipe_client.cpp
)
target_include_directories(x64dbg-mcp-common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(x64dbg-mcp-common PUBLIC nlohmann_json)
# Advapi32: ConvertStringSecurityDescriptorToSecurityDescriptorA in pipe_server.cpp
# (explicit access rights for the named pipe).
target_link_libraries(x64dbg-mcp-common PRIVATE Advapi32)

# service.cpp ties together the task queue, the pipe, and the x64dbg API.
target_link_libraries(x64dbg-mcp PRIVATE x64dbg-mcp-common)

# MCP server core. Contains no I/O, so it is tested separately.
add_library(x64dbg-mcp-bridge-core STATIC
    src/bridge/logging.h
    src/bridge/logging.cpp
    src/bridge/plugin_link.h
    src/bridge/plugin_link.cpp
    src/bridge/debugger_tools.h
    src/bridge/debugger_tools.cpp
    src/bridge/tool_registry.h
    src/bridge/tool_registry.cpp
    src/bridge/resource_registry.h
    src/bridge/resource_registry.cpp
    src/bridge/prompt_registry.h
    src/bridge/prompt_registry.cpp
    src/bridge/debugger_prompts.h
    src/bridge/debugger_prompts.cpp
    src/bridge/mcp_server.h
    src/bridge/mcp_server.cpp
)
target_include_directories(x64dbg-mcp-bridge-core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(x64dbg-mcp-bridge-core PUBLIC nlohmann_json x64dbg-mcp-common)
target_compile_definitions(x64dbg-mcp-bridge-core PUBLIC SERVER_VERSION_STR="${PROJECT_VERSION}")

# Server executable: the stdio transport on top of the protocol core.
add_executable(x64dbg-mcp-server
    src/bridge/main.cpp
    src/bridge/stdio_transport.h
    src/bridge/stdio_transport.cpp
)
set_target_properties(x64dbg-mcp-server PROPERTIES OUTPUT_NAME "x64dbg-mcp")
target_link_libraries(x64dbg-mcp-server PRIVATE x64dbg-mcp-bridge-core)

# Target program for manually exercising the tools.
# Built only on explicit request: cmake -B build64 -A x64 -DX64DBG_MCP_BUILD_TARGET=ON
option(X64DBG_MCP_BUILD_TARGET "Build the target program for manual checks" OFF)

if(X64DBG_MCP_BUILD_TARGET)
    enable_language(C)
    add_executable(crackme tests/target/crackme.c)
    # Optimization is disabled on purpose: functions must remain separate
    # and recognizable in the disassembler, otherwise exercising the tools is pointless.
    target_compile_options(crackme PRIVATE /Od)
    set_target_properties(crackme PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION OFF
    )

    add_executable(envtarget tests/target/envtarget.c)
    target_compile_options(envtarget PRIVATE /Od)
    target_link_libraries(envtarget PRIVATE Ws2_32)
    set_target_properties(envtarget PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION OFF
    )
endif()

# Unit tests. Do not require a running x64dbg and are not linked against its SDK.
option(X64DBG_MCP_BUILD_TESTS "Build unit tests" ON)

if(X64DBG_MCP_BUILD_TESTS)
    enable_testing()
    add_executable(x64dbg-mcp-tests
        tests/unit/test_main.cpp
        tests/unit/test_smoke.cpp
        tests/unit/test_framing.cpp
        tests/unit/test_mcp_server.cpp
        tests/unit/test_pipe.cpp
        tests/unit/test_plugin_link.cpp
        tests/unit/test_debug_state.cpp
        tests/unit/test_worker.cpp
    )
    target_link_libraries(x64dbg-mcp-tests PRIVATE nlohmann_json doctest x64dbg-mcp-common x64dbg-mcp-bridge-core x64dbg-mcp-plugin-core)
    add_test(NAME unit COMMAND x64dbg-mcp-tests)
endif()
