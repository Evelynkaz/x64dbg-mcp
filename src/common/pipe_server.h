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
#include <vector>

namespace x64dbg_mcp
{

namespace detail
{

// Shared state of a running server: the stop event, the request handler, the
// pipe name (needed to open further instances of the pipe as connections are
// accepted), and the running flag, plus bookkeeping for every connection
// thread currently serving a client. Lives behind a std::shared_ptr rather
// than as fields of PipeServer, and every thread that touches it — the
// accept-loop thread and every connection thread — captures its own copy of
// the shared_ptr rather than a raw this pointer (see defect 2 in the
// review). Thanks to that, if Stop() fails to join a thread in time and
// detaches it, the state (including the handles) stays alive exactly as long
// as the thread itself does — touching an already-freed object from a
// detached thread becomes impossible by construction, not just by convention.
struct PipeServerState
{
    HANDLE stopEvent = nullptr;
    std::function<std::string(const std::string&)> handler;
    std::atomic<bool> running{false};
    std::string pipeName;

    // Bookkeeping for connection threads, so Stop() can wait for every one
    // of them, not just the accept loop, and so the accept loop can enforce
    // a bound on how many connections it serves concurrently. Guarded by
    // connectionsMutex; connectionCount is also read outside the lock as a
    // quick, approximate check before deciding whether to accept one more
    // connection.
    std::mutex connectionsMutex;
    std::vector<std::thread> connectionThreads;
    std::atomic<int> connectionCount{0};

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

    // Starts the server on the given pipe name. Serves multiple connections
    // concurrently, each on its own thread — accepting the next client never
    // waits for the current one to finish (see the defect this fixes: a
    // client that vanishes mid-conversation used to leave the pipe stuck
    // forever). Concurrent connections are bounded (see kMaxConcurrentConnections
    // in the .cpp); once the bound is reached, the newest incoming connection
    // is closed immediately rather than served. The pipe is created with an
    // explicit security descriptor (owner and system only) — if building that
    // descriptor fails, the pipe is not created at all: working with
    // weakened access rights is worse than not working (see risk 4 in the
    // review — untrusted debuggee code could be running alongside).
    // Returns false if the pipe is busy or could not be created.
    bool Start(const std::string& pipeName, RequestHandler handler);

    // Stops the server and waits for the accept-loop thread and every
    // connection thread to finish within a reasonable, shared time budget.
    // Signals the stop event, which every wait in this module (accepting a
    // connection, reading, writing) already watches — so Stop() does not
    // wait for clients to disconnect on their own. If a thread does not
    // finish within the budget (for example, it is stuck inside a
    // third-party request handler), Stop() detaches it: the server releases
    // its own reference to the shared state, and the thread keeps it alive
    // on its own until it finishes (see defect 2). Safe to call repeatedly
    // and without a preceding Start.
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
