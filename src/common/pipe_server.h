#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace x64dbg_mcp
{

namespace detail
{

// Shared state of a running server: the pipe handle, the stop event, the
// request handler, and the running flag. Lives behind a std::shared_ptr
// rather than as fields of PipeServer, and the worker thread captures its
// own copy of the shared_ptr rather than a raw this pointer (see defect 2 in
// the review). Thanks to that, if Stop() fails to join the thread in time
// and detaches it, the state (including the handles) stays alive exactly as
// long as the thread itself does — touching an already-freed object from
// the detached thread becomes impossible by construction, not just by convention.
struct PipeServerState
{
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    HANDLE stopEvent = nullptr;
    std::function<std::string(const std::string&)> handler;
    std::atomic<bool> running{false};

    ~PipeServerState();
};

} // namespace detail

// Windows named pipe server. Meant to run inside the x64dbg plugin process,
// so it knows nothing about x64dbg itself: it takes a request handler from
// the outside and operates on arbitrary byte messages. This lets the
// transport be tested with an ordinary unit test, without a running debugger.
class PipeServer
{
public:
    // Request handler: receives the request body, returns the response body.
    // Called on the connection thread. Should not throw, but if it does,
    // PipeServer catches the exception itself (see the .cpp).
    using RequestHandler = std::function<std::string(const std::string& request)>;

    PipeServer();
    ~PipeServer();

    PipeServer(const PipeServer&) = delete;
    PipeServer& operator=(const PipeServer&) = delete;

    // Starts the server on the given pipe name. Serves one connection at a
    // time — the bridge connects as a single client. If a second client
    // tries to connect while the server is busy with the first, its
    // CreateFileA gets ERROR_PIPE_BUSY: it waits its turn via WaitNamedPipe
    // and retries (see PipeClient::Connect) — that is enough for a single
    // bridge. The pipe is created with an explicit security descriptor
    // (owner and system only) — if building that descriptor fails, the pipe
    // is not created at all: working with weakened access rights is worse
    // than not working (see risk 4 in the review — untrusted debuggee code
    // could be running alongside).
    // Returns false if the pipe is busy or could not be created.
    bool Start(const std::string& pipeName, RequestHandler handler);

    // Stops the server and waits for its thread to finish within a
    // reasonable time. Signals the stop event and cancels pending I/O on the
    // pipe — so it does not wait for the client to disconnect. The accept
    // loop only exits because of this request, never because of a routine
    // pipe error (see defect 1). If the thread does not finish in time (for
    // example, it is stuck inside a third-party request handler), Stop()
    // detaches it: the server releases its own reference to the shared
    // state, and the thread keeps it alive on its own until it finishes (see
    // defect 2). Safe to call repeatedly and without a preceding Start.
    void Stop();

    bool IsRunning() const;

    // The name of the pipe the server is actually running on.
    std::string PipeName() const;

private:
    std::shared_ptr<detail::PipeServerState> state_;
    std::thread thread_;

    mutable std::mutex nameMutex_;
    std::string pipeName_;
};

} // namespace x64dbg_mcp
