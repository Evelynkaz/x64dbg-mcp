#pragma once

#include "bridge/plugin_link.h"
#include "bridge/tool_registry.h"

#include <memory>

namespace x64dbg_mcp::bridge
{

// Регистрирует тринадцать инструментов отладчика: debugger_status,
// read_memory, disassemble, debug_control, step, wait_until_paused,
// set_breakpoint, manage_breakpoint, list_breakpoints, list_modules,
// module_info, memory_map и list_threads. Каждый обращается к плагину
// x64dbg через link. Вместе с server_status, регистрируемым отдельно в
// tool_registry.cpp, сервер предоставляет модели четырнадцать инструментов.
void RegisterDebuggerTools(ToolRegistry& registry, std::shared_ptr<PluginLink> link);

} // namespace x64dbg_mcp::bridge
