#pragma once

#include <string>

namespace x64dbg_mcp::bridge
{

// Log levels, from most important to most verbose.
enum class LogLevel { Error, Warn, Info, Debug };

// Sets the minimum log level: messages of lower importance are dropped.
// Affects all subsequent calls to Log() from any thread.
void SetLogLevel(LogLevel level);

// Writes a log line to stderr. Never writes to stdout — that is reserved
// for MCP protocol messages, and any stray write there would break the transport.
void Log(LogLevel level, const std::string& message);

} // namespace x64dbg_mcp::bridge
