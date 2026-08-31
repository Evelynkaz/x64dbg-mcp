#pragma once

#include "bridge/plugin_link.h"
#include "bridge/tool_registry.h"

#include <memory>

namespace x64dbg_mcp::bridge
{

// Registers twenty-nine debugger tools: debugger_status,
// read_memory, disassemble, debug_control, step, wait_until_paused,
// set_breakpoint, manage_breakpoint, list_breakpoints, list_modules,
// module_info, memory_map, list_threads, read_registers, call_stack,
// read_stack, read_string, evaluate_expression, find_pattern,
// find_references, disassemble_function, execute_command, run_script,
// read_log, write_memory, set_register, assemble_at, patches and
// set_page_rights. Each talks to the x64dbg plugin through link. Together
// with server_status, registered separately in tool_registry.cpp, the
// server exposes thirty tools to the model.
void RegisterDebuggerTools(ToolRegistry& registry, std::shared_ptr<PluginLink> link);

} // namespace x64dbg_mcp::bridge
