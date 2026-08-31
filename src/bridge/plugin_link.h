#pragma once

#include "bridge/tool_registry.h"
#include "common/pipe_client.h"
#include "nlohmann/json.hpp"

#include <mutex>
#include <string>

namespace x64dbg_mcp::bridge
{

// Wraps PipeClient: turns calls to plugin methods into a convenient
// request-response interface (Call), hiding the details of the named pipe
// and the protocol handshake. Lives in the bridge process for its entire lifetime.
class PluginLink
{
public:
    explicit PluginLink(std::string pipeName, int connectTimeoutMs = 3000, int requestTimeoutMs = 15000);

    // Performs a call to a plugin method. Connects on first use — the
    // bridge starts before the user opens x64dbg, and must not fail because
    // of that (see the .cpp). Nothing escapes outward except ToolError with
    // English text suitable for showing to the model.
    //
    // requestTimeoutMs, if non-zero, overrides the link's default wait for
    // THIS call only. How long a caller needs to wait is a property of the
    // requested operation (e.g. a multi-minute trace), not of the
    // transport — a single fixed transport timeout would silently
    // truncate every legitimate long operation.
    nlohmann::json Call(const std::string& method, const nlohmann::json& params, int requestTimeoutMs = 0);

    // Checks whether the plugin is available, without throwing.
    bool IsAvailable();

    std::string PipeName() const;

private:
    // Sends a single request over the already established (or just
    // established) connection, waiting up to timeoutMs for the response.
    // Returns false on a transport failure — then Call() decides whether to
    // reconnect and retry.
    bool SendLocked(const std::string& method, const nlohmann::json& params, std::string& response, int timeoutMs);

    // Parses and validates the plugin's response; throws ToolError on any
    // protocol mismatch or on an error from the plugin itself (passing its
    // text through as-is, without inventing anything).
    nlohmann::json ParseResponse(const std::string& method, const std::string& response) const;

    // Builds a transport error message based on the client's LastError().
    // If the transport gave up waiting for the response, says so
    // explicitly and states how long it waited (timeoutMs), so the model
    // can tell a stuck plugin from an operation that just needs a longer
    // 'timeout_ms' instead of confusing the two.
    std::string TransportErrorMessage(const std::string& method, int timeoutMs) const;

    std::string pipeName_;
    int connectTimeoutMs_;
    int requestTimeoutMs_;

    std::mutex mutex_;
    x64dbg_mcp::PipeClient client_;
    int nextId_ = 1;
};

} // namespace x64dbg_mcp::bridge
