#pragma once

#include "bridge/plugin_link.h"
#include "bridge/resource_registry.h"
#include "bridge/tool_registry.h"

#include <memory>

namespace x64dbg_mcp::bridge
{

// Registers forty-six debugger tools: debugger_status,
// read_memory, disassemble, debug_control, step, wait_until_paused,
// set_breakpoint, manage_breakpoint, list_breakpoints, list_modules,
// module_info, memory_map, list_threads, read_registers, call_stack,
// read_stack, read_string, evaluate_expression, find_pattern,
// find_references, disassemble_function, function_graph, execute_command,
// run_script, read_log, write_memory, set_register, assemble_at, patches,
// set_page_rights, trace_until, trace_record, run_to_user_code,
// code_coverage, list_symbols, annotate, list_handles, list_windows,
// list_connections, seh_chain, list_processes, attach_process,
// detach_process, allocate_memory, free_memory and dump_memory. Each
// talks to the x64dbg plugin through link. Together with server_status,
// registered separately in tool_registry.cpp, the server exposes
// forty-seven tools to the model.
void RegisterDebuggerTools(ToolRegistry& registry, std::shared_ptr<PluginLink> link);

// Registers the debugger's resources: x64dbg://memory-map and
// x64dbg://disassembly/current, which reuse the formatting helper and the
// plugin method of the equivalent tool, and the static x64dbg://commands
// command reference, which needs no plugin call. link may be empty (nullptr).
void RegisterDebuggerResources(ResourceRegistry& registry, std::shared_ptr<PluginLink> link);

} // namespace x64dbg_mcp::bridge
