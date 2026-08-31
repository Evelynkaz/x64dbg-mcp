#pragma once

#include "nlohmann/json.hpp"

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace x64dbg_mcp::bridge
{

class PluginLink;

// A tool execution error. The message will be read by the model, not just by
// a human: it should explain the reason for the failure and suggest what to
// do to make the operation succeed (e.g. which method to connect with first).
class ToolError : public std::runtime_error
{
public:
    explicit ToolError(const std::string& message);
};

// Result of a tool: structured data separate from the human-readable
// representation. The model reads text, while structuredContent is parsed
// programmatically, so the two must not be mixed.
struct ToolResult
{
    nlohmann::json structuredContent;
    // Human-readable representation. If empty, it is generated automatically
    // as a serialization of structuredContent.
    std::string text;
};

// Description of a single tool exposed to the model via tools/list and tools/call.
struct Tool
{
    std::string name;
    std::string description;    // documentation for the model: what it does, when to use it, what it returns
    nlohmann::json inputSchema; // JSON Schema 2020-12
    std::function<ToolResult(const nlohmann::json& arguments)> handler;
};

class ToolRegistry
{
public:
    void Add(Tool tool);
    const Tool* Find(const std::string& name) const;
    nlohmann::json ListJson() const; // array of descriptions for the tools/list response
    size_t Size() const;

private:
    std::vector<Tool> tools_;
};

// Creates a registry with the server's default set of tools, including
// debugger tools that talk to the plugin through link. link may be empty
// (nullptr) — in that case server_status honestly reports no connection,
// and calling a debugger tool fails with ToolError.
ToolRegistry CreateDefaultRegistry(std::shared_ptr<PluginLink> link = nullptr);

} // namespace x64dbg_mcp::bridge
