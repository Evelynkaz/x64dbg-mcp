#pragma once

#include "bridge/mcp_server.h"

namespace x64dbg_mcp::bridge
{

// Читает строки из stdin и передаёт их серверу, ответы пишет в stdout.
// Возвращается, когда stdin закрыт (EOF) — это штатный сигнал завершения.
void RunStdioLoop(McpServer& server);

} // namespace x64dbg_mcp::bridge
