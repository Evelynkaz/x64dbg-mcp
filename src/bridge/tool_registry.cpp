#include "bridge/tool_registry.h"
#include "bridge/debugger_tools.h"
#include "bridge/plugin_link.h"

#include <sstream>

namespace x64dbg_mcp::bridge
{

ToolError::ToolError(const std::string& message) : std::runtime_error(message)
{
}

void ToolRegistry::Add(Tool tool)
{
    tools_.push_back(std::move(tool));
}

const Tool* ToolRegistry::Find(const std::string& name) const
{
    for (const auto& tool : tools_)
    {
        if (tool.name == name)
            return &tool;
    }
    return nullptr;
}

nlohmann::json ToolRegistry::ListJson() const
{
    nlohmann::json list = nlohmann::json::array();
    for (const auto& tool : tools_)
    {
        list.push_back({
            {"name", tool.name},
            {"description", tool.description},
            {"inputSchema", tool.inputSchema}
        });
    }
    return list;
}

size_t ToolRegistry::Size() const
{
    return tools_.size();
}

ToolRegistry CreateDefaultRegistry(std::shared_ptr<PluginLink> link)
{
    ToolRegistry registry;

    Tool serverStatus;
    serverStatus.name = "server_status";
    serverStatus.description =
        "Reports the version of the x64dbg-mcp server, the name of the named "
        "pipe it connects to, and whether the plugin running inside x64dbg is "
        "currently reachable on that pipe. Does not require an active "
        "debugging session. Call this tool first whenever another tool returns "
        "a connection error, to check whether x64dbg is running with the "
        "x64dbg-mcp plugin installed before investigating further.";
    serverStatus.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", nlohmann::json::object()},
        {"additionalProperties", false}
    };
    serverStatus.handler = [link](const nlohmann::json& /*arguments*/) -> ToolResult
    {
        const bool connected = link ? link->IsAvailable() : false;
        const std::string pipeName = link ? link->PipeName() : std::string();

        ToolResult result;
        result.structuredContent = {
            {"server_version", SERVER_VERSION_STR},
            {"plugin_connected", connected},
            {"pipe_name", pipeName}
        };

        std::ostringstream text;
        text << "x64dbg-mcp server " << SERVER_VERSION_STR << ", pipe \"" << pipeName << "\": ";
        if (connected)
            text << "plugin connected.";
        else
            text << "plugin not connected. Start x64dbg with the x64dbg-mcp plugin installed.";
        result.text = text.str();
        return result;
    };

    registry.Add(std::move(serverStatus));
    RegisterDebuggerTools(registry, link);
    return registry;
}

} // namespace x64dbg_mcp::bridge
