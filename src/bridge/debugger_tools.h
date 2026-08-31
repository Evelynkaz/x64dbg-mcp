#pragma once

#include "bridge/plugin_link.h"
#include "bridge/tool_registry.h"

#include <memory>

namespace x64dbg_mcp::bridge
{

// Регистрирует три инструмента отладчика: debugger_status, read_memory и
// disassemble. Каждый обращается к плагину x64dbg через link.
void RegisterDebuggerTools(ToolRegistry& registry, std::shared_ptr<PluginLink> link);

} // namespace x64dbg_mcp::bridge
