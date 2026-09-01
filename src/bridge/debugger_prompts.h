#pragma once

#include "bridge/prompt_registry.h"

namespace x64dbg_mcp::bridge
{

// Registers the server's four reverse-engineering prompts: analyze_function,
// trace_to_api_call, defeat_anti_debugging, and analyze_virtualized_code.
// Each renders a block of instructions naming the real tools to call and in
// what order, rather than performing any debugger action itself.
void RegisterDebuggerPrompts(PromptRegistry& registry);

} // namespace x64dbg_mcp::bridge
