#pragma once

#include "common/pipe_server.h"
#include "plugin/debug_state.h"
#include "plugin/worker.h"

#include <string>

namespace x64dbg_mcp::plugin
{

// Singleton: x64dbg callbacks are free functions with no user data (see
// CBPLUGIN in _plugins.h), so they need a shared access point to the state.
class McpService
{
public:
    static McpService& Instance();

    McpService(const McpService&) = delete;
    McpService& operator=(const McpService&) = delete;

    // Starts the worker thread and the pipe server. Returns false on failure.
    bool Start();
    // Stops everything in a safe order (see the .cpp).
    void Stop();

    // Enables log capture, logging the outcome to the x64dbg log. Must be
    // called once the GUI is up (see the call site in plugin.cpp) — a
    // snapshot request issued before then is otherwise silently dropped.
    // Must be called ON THE GUI THREAD: it issues GUI-side requests
    // directly, without going through DebuggerWorker::Submit (see the .cpp
    // for why).
    void EnableLogCapture();

    DebugStateTracker& Tracker();

    // The name of the pipe the server is listening on (for logging).
    std::string PipeName() const;

private:
    McpService() = default;
    ~McpService() = default;

    std::string HandleRequest(const std::string& request);

    DebugStateTracker tracker_;
    DebuggerWorker worker_;
    PipeServer pipeServer_;
};

// Registers debug state callbacks that update McpService::Instance().Tracker().
// Call once during plugin initialization.
void RegisterDebugCallbacks(int pluginHandle);

// Unregisters the callbacks registered by RegisterDebugCallbacks. Call on unload.
void UnregisterDebugCallbacks(int pluginHandle);

} // namespace x64dbg_mcp::plugin
