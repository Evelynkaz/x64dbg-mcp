#pragma once

#include "bridge/plugin_link.h"
#include "bridge/tool_registry.h"

#include <memory>

namespace x64dbg_mcp::bridge
{

// Регистрирует девять инструментов отладчика: debugger_status, read_memory,
// disassemble, debug_control, step, wait_until_paused, set_breakpoint,
// manage_breakpoint и list_breakpoints. Каждый обращается к плагину x64dbg
// через link.
void RegisterDebuggerTools(ToolRegistry& registry, std::shared_ptr<PluginLink> link);

} // namespace x64dbg_mcp::bridge
