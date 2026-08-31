#pragma once

#include "bridge/mcp_server.h"

namespace x64dbg_mcp::bridge
{

// Reads lines from stdin and passes them to the server, writes responses to stdout.
// Returns when stdin is closed (EOF) — that is the normal shutdown signal.
void RunStdioLoop(McpServer& server);

} // namespace x64dbg_mcp::bridge
