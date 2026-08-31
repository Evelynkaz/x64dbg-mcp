#include "bridge/plugin_link.h"
#include "common/ipc_protocol.h"

#include <utility>

namespace x64dbg_mcp::bridge
{

PluginLink::PluginLink(std::string pipeName, int connectTimeoutMs, int requestTimeoutMs)
    : pipeName_(std::move(pipeName))
    , connectTimeoutMs_(connectTimeoutMs)
    , requestTimeoutMs_(requestTimeoutMs)
{
}

std::string PluginLink::PipeName() const
{
    return pipeName_;
}

bool PluginLink::IsAvailable()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (client_.IsConnected())
        return true;
    return client_.Connect(pipeName_, connectTimeoutMs_);
}

bool PluginLink::SendLocked(const std::string& method, const nlohmann::json& params, std::string& response)
{
    if (!client_.IsConnected() && !client_.Connect(pipeName_, connectTimeoutMs_))
        return false;

    const nlohmann::json request = {
        {ipc::kFieldId, nextId_++},
        {ipc::kFieldMethod, method},
        {ipc::kFieldParams, params}
    };

    return client_.SendRequest(request.dump(), response, requestTimeoutMs_);
}

std::string PluginLink::TransportErrorMessage(const std::string& method) const
{
    return "Failed to call '" + method + "' on the x64dbg-mcp plugin: " + client_.LastError();
}

nlohmann::json PluginLink::Call(const std::string& method, const nlohmann::json& params)
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::string response;
    if (!SendLocked(method, params, response))
    {
        // Reconnect EXACTLY once: the user may have restarted x64dbg
        // without restarting the MCP client, and the first failure may just
        // mean the old connection went stale. Retrying indefinitely would
        // turn plugin unavailability into a hanging call instead of a fast,
        // clear error — so the second failure is already returned to the
        // caller as-is.
        if (!SendLocked(method, params, response))
            throw ToolError(TransportErrorMessage(method));
    }

    return ParseResponse(method, response);
}

nlohmann::json PluginLink::ParseResponse(const std::string& method, const std::string& response) const
{
    const nlohmann::json parsed = nlohmann::json::parse(response, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object())
        throw ToolError("Plugin returned a malformed (non-JSON) response to '" + method + "'");

    if (!parsed.contains(ipc::kFieldOk) || !parsed[ipc::kFieldOk].is_boolean())
        throw ToolError("Plugin response to '" + method + "' is missing the required '" +
                          std::string(ipc::kFieldOk) + "' field");

    if (!parsed[ipc::kFieldOk].get<bool>())
    {
        std::string message;
        if (parsed.contains(ipc::kFieldError) && parsed[ipc::kFieldError].is_object())
            message = parsed[ipc::kFieldError].value(ipc::kFieldErrorMessage, std::string());
        if (message.empty())
            message = "Plugin returned an error responding to '" + method + "'";
        throw ToolError(message);
    }

    if (!parsed.contains(ipc::kFieldResult))
        throw ToolError("Plugin response to '" + method + "' is missing the required '" +
                          std::string(ipc::kFieldResult) + "' field");

    return parsed[ipc::kFieldResult];
}

} // namespace x64dbg_mcp::bridge
