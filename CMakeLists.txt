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
    )
    target_link_libraries(x64dbg-mcp-tests PRIVATE nlohmann_json doctest)
    add_test(NAME unit COMMAND x64dbg-mcp-tests)
endif()
