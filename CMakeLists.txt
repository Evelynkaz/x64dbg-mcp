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
)

# Версия плагина выводится из версии проекта — единый источник истины.
# x64dbg показывает pluginVersion как целое число, поэтому кодируем
# major.minor.patch в одно число: 0.1.0 -> 100, 1.2.3 -> 10203.
math(EXPR PLUGIN_VERSION_INT "${PROJECT_VERSION_MAJOR} * 10000 + ${PROJECT_VERSION_MINOR} * 100 + ${PROJECT_VERSION_PATCH}")

target_compile_definitions(x64dbg-mcp PRIVATE
    PLUGIN_VERSION=${PLUGIN_VERSION_INT}
    PLUGIN_VERSION_STR="${PROJECT_VERSION}"
)

# Вендоренные header-only зависимости. Версии и лицензии — third_party/README.md.
add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

add_library(doctest INTERFACE)
target_include_directories(doctest INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

# Общий код моста и плагина: формат обмена, разбор кадров.
# Не зависит ни от Windows API, ни от SDK x64dbg — поэтому тестируется отдельно.
add_library(x64dbg-mcp-common STATIC
    src/common/framing.h
    src/common/framing.cpp
    src/common/ipc_protocol.h
)
target_include_directories(x64dbg-mcp-common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(x64dbg-mcp-common PUBLIC nlohmann_json)

# Ядро MCP-сервера. Не содержит ввода-вывода, поэтому тестируется отдельно.
add_library(x64dbg-mcp-bridge-core STATIC
    src/bridge/logging.h
    src/bridge/logging.cpp
    src/bridge/tool_registry.h
    src/bridge/tool_registry.cpp
    src/bridge/mcp_server.h
    src/bridge/mcp_server.cpp
)
target_include_directories(x64dbg-mcp-bridge-core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(x64dbg-mcp-bridge-core PUBLIC nlohmann_json x64dbg-mcp-common)
target_compile_definitions(x64dbg-mcp-bridge-core PUBLIC SERVER_VERSION_STR="${PROJECT_VERSION}")

# Исполняемый файл сервера: транспорт stdio поверх ядра протокола.
add_executable(x64dbg-mcp-server
    src/bridge/main.cpp
    src/bridge/stdio_transport.h
    src/bridge/stdio_transport.cpp
)
set_target_properties(x64dbg-mcp-server PROPERTIES OUTPUT_NAME "x64dbg-mcp")
target_link_libraries(x64dbg-mcp-server PRIVATE x64dbg-mcp-bridge-core)

# Подопытная программа для ручной проверки инструментов.
# Собирается только по явному запросу: cmake -B build64 -A x64 -DX64DBG_MCP_BUILD_TARGET=ON
option(X64DBG_MCP_BUILD_TARGET "Собрать подопытную программу для ручных проверок" OFF)

if(X64DBG_MCP_BUILD_TARGET)
    enable_language(C)
    add_executable(crackme tests/target/crackme.c)
    # Оптимизация отключена намеренно: функции должны остаться отдельными
    # и узнаваемыми в дизассемблере, иначе проверять инструменты бессмысленно.
    target_compile_options(crackme PRIVATE /Od)
    set_target_properties(crackme PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION OFF
    )
endif()

# Юнит-тесты. Не требуют запущенного x64dbg и не линкуются с его SDK.
option(X64DBG_MCP_BUILD_TESTS "Собрать юнит-тесты" ON)

if(X64DBG_MCP_BUILD_TESTS)
    enable_testing()
    add_executable(x64dbg-mcp-tests
        tests/unit/test_main.cpp
        tests/unit/test_smoke.cpp
        tests/unit/test_framing.cpp
        tests/unit/test_mcp_server.cpp
    )
    target_link_libraries(x64dbg-mcp-tests PRIVATE nlohmann_json doctest x64dbg-mcp-common x64dbg-mcp-bridge-core)
    add_test(NAME unit COMMAND x64dbg-mcp-tests)
endif()
