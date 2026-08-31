#pragma once

#include "bridge/tool_registry.h"
#include "nlohmann/json.hpp"

#include <optional>
#include <string>

namespace x64dbg_mcp::bridge
{

// The newest protocol revision supported by the modern (stateless) model.
constexpr const char* kModernVersion = "2026-07-28";

// Legacy model versions accepted during the initialize handshake, from
// newest to oldest. The first element is the version the server calls its
// own if the client sent a version not in this list.
constexpr const char* kLegacyVersions[] = { "2025-11-25", "2025-06-18", "2025-03-26" };

// The core of the MCP protocol: parsing and handling a single message. Does
// no I/O, so it is fully covered by unit tests without running a real
// transport.
class McpServer
{
public:
    explicit McpServer(ToolRegistry registry);

    // Handles one incoming message (one line of JSON). Returns a response
    // string, or std::nullopt if no reply is needed (notifications require
    // no response). Never throws: any internal error is turned into a valid
    // JSON-RPC response.
    std::optional<std::string> HandleMessage(const std::string& line);

private:
    ToolRegistry registry_;

    nlohmann::json HandleToolsList() const;
    nlohmann::json HandleToolsCall(const nlohmann::json& params) const;
    nlohmann::json HandleDiscover() const;
};

} // namespace x64dbg_mcp::bridge
