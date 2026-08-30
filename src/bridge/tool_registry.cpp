#include "bridge/tool_registry.h"

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

ToolRegistry CreateDefaultRegistry()
{
    ToolRegistry registry;

    Tool serverStatus;
    serverStatus.name = "server_status";
    serverStatus.description =
        "Reports the version of the x64dbg-mcp server and the connection state "
        "with the plugin running inside x64dbg. Does not require an active "
        "debugging session. Call this tool first whenever another tool returns "
        "a connection error, to check whether x64dbg is running with the "
        "x64dbg-mcp plugin installed before investigating further.";
    serverStatus.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", nlohmann::json::object()},
        {"additionalProperties", false}
    };
    serverStatus.handler = [](const nlohmann::json& /*arguments*/) -> nlohmann::json
    {
        return nlohmann::json{
            {"server_version", SERVER_VERSION_STR},
            // Подключение к плагину появится вместе со слоем канала (framing/ipc);
            // до тех пор инструмент честно сообщает, что канала ещё нет.
            {"plugin_connected", false}
        };
    };

    registry.Add(std::move(serverStatus));
    return registry;
}

} // namespace x64dbg_mcp::bridge
