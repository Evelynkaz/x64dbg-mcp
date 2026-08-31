#include "common/pipe_server.h"
#include "common/framing.h"
#include "common/ipc_protocol.h"
#include "nlohmann/json.hpp"

#include <sddl.h>

#include <chrono>

namespace x64dbg_mcp
{

namespace detail
{

PipeServerState::~PipeServerState()
{
    // Every thread that was ever given a copy of the shared_ptr this state
    // lives behind must have already dropped it (and therefore already
    // finished running) by the time this destructor runs, because otherwise
    // the refcount could not have reached zero. So any std::thread objects
    // still sitting in connectionThreads at this point wrap OS threads that
    // have already finished — they just were never reaped or joined by
    // Stop() (a narrow race: the connection was accepted right as Stop()
    // finished draining the list). detach() on an already-finished thread is
    // safe and just avoids std::terminate on a still-joinable std::thread.
    for (auto& t : connectionThreads)
    {
        if (t.joinable())
            t.detach();
    }

    if (stopEvent)
        CloseHandle(stopEvent);
}

} // namespace detail

namespace
{

// Size of the internal read buffer and the pipe buffers. Matches the shrink
// threshold of FrameReader — both numbers are chosen for the same reason
// (small messages should not require extra allocations).
constexpr DWORD kIoBufferSize = 64u * 1024u;

// Limit on how long Stop() waits, in total, for the accept-loop thread and
// every connection thread to join. Also used as a diagnostic reference point
// in the comments below.
constexpr DWORD kJoinTimeoutMs = 5000;

// Upper bound on how many connections the server serves at once, and also
// the pipe's nMaxInstances. A bound — rather than PIPE_UNLIMITED_INSTANCES —
// keeps the number of connection threads (and everything each one holds)
// predictable during a long debugging session. 8 is comfortably more than
// the single bridge client this server is meant for, with headroom for a
// client restart racing a still-closing old connection. When the bound is
// reached, the accept loop closes the newest connection outright instead of
// growing without limit.
constexpr DWORD kMaxConcurrentConnections = 8;

// The pipe's nMaxInstances. One more than kMaxConcurrentConnections: at any
// moment there is one instance waiting to accept the next client, in
// addition to however many are already being served (up to
// kMaxConcurrentConnections) — without the +1, the last connection allowed
// by the bound above would leave no room for a fresh listening instance.
constexpr DWORD kPipeMaxInstances = kMaxConcurrentConnections + 1;

// How long a connection's read wait may sit idle, after the handshake, with
// no request from the client, before the server treats it as abandoned and
// closes it. This only reclaims connections whose client vanished without
// closing the pipe (e.g. it hung or its process was suspended) — it must
// stay long enough to never interrupt an idle but genuinely live client.
constexpr DWORD kIdleTimeoutMs = 10 * 60 * 1000;

// Field names of the protocol version handshake frame — a private contract
// between PipeServer and PipeClient (see defect 3 in the review). This is
// not part of the public ipc_protocol.h, so it is defined here and
// duplicated (under the same names) in pipe_client.cpp — if you change
// these, change both places.
constexpr const char* kFieldProtocolVersion = "protocolVersion";
constexpr const char* kFieldMajor = "major";
constexpr const char* kFieldMinor = "minor";

// Result of an I/O operation that can be interrupted by the stop event, or
// (for a per-connection read) by an idle timeout.
enum class IoResult { Ok, Disconnected, Stopped, TimedOut, Error };

IoResult WaitIoCompletion(HANDLE hPipe, HANDLE stopEvent, OVERLAPPED& ov, DWORD& transferred, DWORD timeoutMs)
{
    HANDLE waitHandles[2] = { ov.hEvent, stopEvent };
    const DWORD wr = WaitForMultipleObjects(2, waitHandles, FALSE, timeoutMs);
    if (wr == WAIT_OBJECT_0)
    {
        if (GetOverlappedResult(hPipe, &ov, &transferred, FALSE))
            return IoResult::Ok;

        const DWORD err = GetLastError();
        return (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED)
            ? IoResult::Disconnected
            : IoResult::Error;
    }

    // Either a stop was requested, the idle timeout elapsed, or the wait
    // itself failed — in every case, cancel the operation and wait for it to
    // actually finish: the OVERLAPPED here lives on the stack of the caller,
    // and the OS must not write into it after this function returns.
    CancelIoEx(hPipe, &ov);
    GetOverlappedResult(hPipe, &ov, &transferred, TRUE);
    return (wr == WAIT_TIMEOUT) ? IoResult::TimedOut : IoResult::Stopped;
}

IoResult ReadBytes(HANDLE hPipe, HANDLE stopEvent, char* buffer, DWORD size, DWORD& transferred, DWORD timeoutMs = INFINITE)
{
    OVERLAPPED ov{};
    ov.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent)
        return IoResult::Error;

    IoResult result;
    if (ReadFile(hPipe, buffer, size, nullptr, &ov))
    {
        result = GetOverlappedResult(hPipe, &ov, &transferred, FALSE) ? IoResult::Ok : IoResult::Error;
    }
    else
    {
        const DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING)
        {
            result = WaitIoCompletion(hPipe, stopEvent, ov, transferred, timeoutMs);
        }
        else if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED)
        {
            result = IoResult::Disconnected;
        }
        else
        {
            result = IoResult::Error;
        }
    }

    CloseHandle(ov.hEvent);
    return result;
}

IoResult WriteBytes(HANDLE hPipe, HANDLE stopEvent, const char* data, DWORD size, DWORD& transferred)
{
    OVERLAPPED ov{};
    ov.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent)
        return IoResult::Error;

    IoResult result;
    if (WriteFile(hPipe, data, size, nullptr, &ov))
    {
        result = GetOverlappedResult(hPipe, &ov, &transferred, FALSE) ? IoResult::Ok : IoResult::Error;
    }
    else
    {
        const DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING)
        {
            result = WaitIoCompletion(hPipe, stopEvent, ov, transferred, INFINITE);
        }
        else if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED)
        {
            result = IoResult::Disconnected;
        }
        else
        {
            result = IoResult::Error;
        }
    }

    CloseHandle(ov.hEvent);
    return result;
}

bool WriteAll(HANDLE hPipe, HANDLE stopEvent, const std::string& data)
{
    size_t totalWritten = 0;
    while (totalWritten < data.size())
    {
        DWORD chunkWritten = 0;
        const size_t remaining = data.size() - totalWritten;
        const DWORD toWrite = static_cast<DWORD>((remaining > 0xFFFFFFFFu) ? 0xFFFFFFFFu : remaining);

        if (WriteBytes(hPipe, stopEvent, data.data() + totalWritten, toWrite, chunkWritten) != IoResult::Ok)
            return false;

        if (chunkWritten == 0)
            return false; // guard against hanging on an anomalous zero write progress

        totalWritten += chunkWritten;
    }
    return true;
}

std::string InvokeHandler(const std::function<std::string(const std::string&)>& handler, const std::string& request)
{
    // The handler is implemented outside (in the plugin) and may call into
    // the x64dbg API. catch (...) here only catches C++ exceptions — that is
    // enough for std::bad_alloc, nlohmann::json exceptions, and so on.
    // Structured exceptions (SEH) — for example, an access violation inside
    // the debugger API — are NOT caught by catch (...), since this target is
    // built with the synchronous exception model: they will pass through
    // this handler and take down the whole of x64dbg along with the
    // debuggee (see risk 6 in the review). Protection against those has to
    // live in the wrapper layer over the debugger API, not here.
    try
    {
        return handler(request);
    }
    catch (...)
    {
        const nlohmann::json error = {
            {ipc::kFieldOk, false},
            {ipc::kFieldError, {
                {ipc::kFieldErrorCode, static_cast<int>(ipc::ErrorCode::Internal)},
                {ipc::kFieldErrorMessage, "Internal error: request handler threw an exception"}
            }}
        };
        return error.dump();
    }
}

bool AcceptConnection(HANDLE hPipe, HANDLE stopEvent)
{
    // Defect 1: ERROR_NO_DATA — the client closed its end of the pipe before
    // we managed to accept the connection (a liveness check, Ctrl-C, a
    // client restart). This is a routine transport situation, not a fatal
    // pipe error: disconnect the pipe and try accepting again, up to a
    // limited number of times, checking the stop event between attempts.
    constexpr int kMaxNoDataRetries = 16;

    for (int attempt = 0; attempt < kMaxNoDataRetries; ++attempt)
    {
        OVERLAPPED ov{};
        ov.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent)
            return false;

        bool ok;
        DWORD err = ERROR_SUCCESS;
        bool stopped = false;

        if (ConnectNamedPipe(hPipe, &ov))
        {
            ok = true; // the client connected synchronously — a rare case
        }
        else
        {
            err = GetLastError();
            if (err == ERROR_PIPE_CONNECTED)
            {
                ok = true; // the client connected before ConnectNamedPipe was called
            }
            else if (err == ERROR_IO_PENDING)
            {
                DWORD transferred = 0;
                const IoResult r = WaitIoCompletion(hPipe, stopEvent, ov, transferred, INFINITE);
                ok = (r == IoResult::Ok);
                stopped = (r == IoResult::Stopped);
                if (!ok && !stopped)
                    err = GetLastError(); // the reason GetOverlappedResult failed inside WaitIoCompletion
            }
            else
            {
                ok = false;
            }
        }

        CloseHandle(ov.hEvent);

        if (ok)
            return true;
        if (stopped)
            return false; // the caller will see the stop event signaled and exit on its own

        if (err == ERROR_NO_DATA)
        {
            DisconnectNamedPipe(hPipe);
            if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0)
                return false;
            continue; // retry the accept
        }

        // Any other accept error is NOT considered fatal for the server as a
        // whole — it just means this particular connection could not be
        // accepted. Disconnect the pipe and return false: the caller (the
        // accept loop) will check the stop event and, if it is not
        // signaled, simply try to accept a connection again on the same
        // instance. The accept loop exits ONLY on a stop request, never
        // because of a routine pipe error.
        DisconnectNamedPipe(hPipe);
        return false;
    }

    // Ran out of retry attempts on a repeating ERROR_NO_DATA. Not fatal:
    // return false and let the caller decide — if a stop was not requested,
    // it will call AcceptConnection again.
    return false;
}

// Creates one more instance of an already-existing named pipe, so the accept
// loop can go back to waiting for the next client without waiting for the
// connection just handed off to finish. Per CreateNamedPipe's own
// documentation, the security descriptor passed to the first instance is
// what governs the pipe as a whole and is ignored on every later instance,
// so this always passes nullptr for the security attributes.
HANDLE CreateNamedPipeInstance(const std::string& pipeName)
{
    return CreateNamedPipeA(
        pipeName.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        kPipeMaxInstances,
        kIoBufferSize,
        kIoBufferSize,
        0,
        nullptr);
}

// Protocol version handshake (defect 3): the first frame after connecting.
// The server receives a frame with the client version, replies with its own
// version, and if the major versions diverge, does not service the
// connection any further.
bool PerformHandshake(HANDLE hPipe, HANDLE stopEvent, FrameReader& reader, std::string& readBuf)
{
    std::string payload;
    while (!reader.Next(payload))
    {
        DWORD bytesRead = 0;
        if (ReadBytes(hPipe, stopEvent, readBuf.data(), static_cast<DWORD>(readBuf.size()), bytesRead) != IoResult::Ok)
            return false;

        if (bytesRead == 0)
            return false; // risk 7: do not spin the loop on zero read progress

        if (reader.Feed(readBuf.data(), bytesRead) == FrameReader::Status::Overflow)
            return false;
    }

    int clientMajor = -1;
    try
    {
        const nlohmann::json parsed = nlohmann::json::parse(payload);
        clientMajor = parsed.at(kFieldProtocolVersion).at(kFieldMajor).get<int>();
    }
    catch (...)
    {
        clientMajor = -1; // a corrupted handshake frame — treat as a version mismatch
    }

    const nlohmann::json response = {
        {kFieldProtocolVersion, {
            {kFieldMajor, ipc::kProtocolVersionMajor},
            {kFieldMinor, ipc::kProtocolVersionMinor}
        }}
    };

    std::string frame;
    if (!EncodeFrame(response.dump(), frame))
        return false;
    if (!WriteAll(hPipe, stopEvent, frame))
        return false;

    return clientMajor == ipc::kProtocolVersionMajor;
}

void ServeConnection(HANDLE hPipe, HANDLE stopEvent, const std::function<std::string(const std::string&)>& handler)
{
    FrameReader reader;
    std::string readBuf(kIoBufferSize, '\0');

    if (!PerformHandshake(hPipe, stopEvent, reader, readBuf))
        return; // versions did not match, or the handshake was corrupted — close the connection

    auto flushReady = [&](std::string& payload) -> bool
    {
        while (reader.Next(payload))
        {
            const std::string responseBody = InvokeHandler(handler, payload);

            std::string frame;
            if (!EncodeFrame(responseBody, frame))
                return false; // the response did not fit in a frame — the connection has to be closed

            if (!WriteAll(hPipe, stopEvent, frame))
                return false;
        }
        return true;
    };

    std::string payload;
    // The handshake read may have pulled in more data in one read than just
    // the version negotiation frame — do not lose what is already sitting in
    // the parser buffer.
    if (!flushReady(payload))
        return;

    for (;;)
    {
        DWORD bytesRead = 0;
        // Bounded idle timeout (kIdleTimeoutMs): reclaims a connection whose
        // client vanished without closing the pipe. IoResult::TimedOut is
        // handled the same as a disconnect or an error below — the
        // connection is simply closed and its instance freed.
        const IoResult r = ReadBytes(hPipe, stopEvent, readBuf.data(), static_cast<DWORD>(readBuf.size()), bytesRead, kIdleTimeoutMs);
        if (r != IoResult::Ok)
            return; // a stop, the client disconnecting, an idle timeout, or an error — close the connection

        if (bytesRead == 0)
            return; // risk 7: do not allow an idle loop on zero read progress

        if (reader.Feed(readBuf.data(), bytesRead) == FrameReader::Status::Overflow)
            return; // the parser failed — the connection has to be closed

        if (!flushReady(payload))
            return;
    }
}

// Removes connection threads that have already finished from the tracking
// list, so it does not grow without bound over a long-running session.
// Finished-ness is checked without blocking: a std::thread's native handle
// becomes signaled as soon as the underlying OS thread exits.
void ReapFinishedConnections(detail::PipeServerState& state)
{
    std::lock_guard<std::mutex> lock(state.connectionsMutex);
    for (auto it = state.connectionThreads.begin(); it != state.connectionThreads.end();)
    {
        if (WaitForSingleObject(it->native_handle(), 0) == WAIT_OBJECT_0)
        {
            it->join();
            it = state.connectionThreads.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

// Defect 2 (continued): if Stop() fails to join a worker thread within the
// allotted time, the thread is detached and keeps executing this module's
// code on its own. If the module (the plugin) gets unloaded at that point,
// the thread would start executing instructions at addresses that have
// already been freed — a guaranteed crash of x64dbg.
// GET_MODULE_HANDLE_EX_FLAG_PIN permanently bumps the module reference
// count, so it will not be unloaded while the process is alive — this is the
// only reliable way to guard against this scenario without rewriting the
// plugin unload mechanism.
void PinThisModuleInMemory()
{
    HMODULE h = nullptr;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCSTR>(&PinThisModuleInMemory),
        &h);
}

// Runs one accepted connection to completion, on its own thread, and then
// releases the connection's own pipe instance and slot. Holds its own copy
// of the shared state — see the comment on PipeServerState in the header.
void ConnectionThreadMain(std::shared_ptr<detail::PipeServerState> state, HANDLE hPipe)
{
    // Risk 5: do not let an exception escape the thread function — that
    // would tear down the whole x64dbg process. See InvokeHandler for the
    // structured-exception caveat.
    try
    {
        ServeConnection(hPipe, state->stopEvent, state->handler);
    }
    catch (...)
    {
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    state->connectionCount.fetch_sub(1, std::memory_order_relaxed);
}

void RunLoop(const std::shared_ptr<detail::PipeServerState>& state, HANDLE firstInstance)
{
    HANDLE listenPipe = firstInstance;

    for (;;)
    {
        // Main rule (defect 1): the accept loop exits ONLY on a stop
        // request — check it here and nowhere else. Any error while
        // accepting a single connection (see AcceptConnection) is a routine
        // per-client situation, not a reason to stop the whole server.
        if (WaitForSingleObject(state->stopEvent, 0) == WAIT_OBJECT_0)
            break;

        ReapFinishedConnections(*state);

        if (!AcceptConnection(listenPipe, state->stopEvent))
        {
            if (WaitForSingleObject(state->stopEvent, 0) == WAIT_OBJECT_0)
                break;
            continue; // AcceptConnection already reset listenPipe for a retry on the same instance
        }

        // Bound concurrent connections (kMaxConcurrentConnections): once the
        // bound is reached, close the newest connection outright rather than
        // growing the number of connection threads without limit.
        if (state->connectionCount.load(std::memory_order_relaxed) >= static_cast<int>(kMaxConcurrentConnections))
        {
            DisconnectNamedPipe(listenPipe);
            CloseHandle(listenPipe);
        }
        else
        {
            state->connectionCount.fetch_add(1, std::memory_order_relaxed);
            try
            {
                std::thread connThread(&ConnectionThreadMain, state, listenPipe);
                std::lock_guard<std::mutex> lock(state->connectionsMutex);
                state->connectionThreads.push_back(std::move(connThread));
            }
            catch (...)
            {
                // Risk 8: a failure to create the thread must not leave the
                // count or the handle stranded.
                state->connectionCount.fetch_sub(1, std::memory_order_relaxed);
                DisconnectNamedPipe(listenPipe);
                CloseHandle(listenPipe);
            }
        }

        // Accepting the next connection must never wait for the one just
        // handed off, so open a fresh instance of the pipe for it right away.
        listenPipe = CreateNamedPipeInstance(state->pipeName);
        if (listenPipe == INVALID_HANDLE_VALUE)
            break; // cannot continue accepting further clients
    }

    if (listenPipe != INVALID_HANDLE_VALUE)
        CloseHandle(listenPipe);
}

void ServerThreadMain(std::shared_ptr<detail::PipeServerState> state, HANDLE firstInstance)
{
    // Risk 5: do not let an exception escape the thread function — that
    // would tear down the whole x64dbg process. Only C++ exceptions are
    // caught; for structured exceptions, see the comment in InvokeHandler.
    try
    {
        RunLoop(state, firstInstance);
    }
    catch (...)
    {
    }

    state->running = false;
}

// Joins a thread within the shared deadline, or detaches it if the deadline
// passes first. Used for the accept-loop thread and every connection thread
// so Stop() stays prompt regardless of how many connections were open — the
// budget is shared across all of them rather than repeated per thread.
void JoinOrDetach(std::thread& t, std::chrono::steady_clock::time_point deadline)
{
    if (!t.joinable())
        return;

    const auto now = std::chrono::steady_clock::now();
    const DWORD remaining = (now >= deadline)
        ? 0
        : static_cast<DWORD>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());

    // Wait limit: after SetEvent, the thread must react almost instantly if
    // it is waiting on I/O — every wait in this module already watches the
    // stop event (see WaitIoCompletion) and cancels its own pending I/O once
    // it notices the stop, so no separate external CancelIoEx is needed
    // here. If a thread still does not finish within its share of the
    // deadline, it is most likely stuck inside a third-party request
    // handler. TerminateThread is deliberately not used here: it could stop
    // the thread while it holds a critical section or is in the middle of
    // working with the heap, leaving the process (which is x64dbg) in an
    // unpredictable state — that is worse than a detached thread that
    // finishes carrying its own state on its own.
    if (WaitForSingleObject(t.native_handle(), remaining) == WAIT_OBJECT_0)
    {
        t.join();
    }
    else
    {
        OutputDebugStringA("x64dbg-mcp: PipeServer worker thread did not stop in time; detaching\n");
        PinThisModuleInMemory();
        t.detach();
    }
}

} // namespace

PipeServer::PipeServer() = default;

PipeServer::~PipeServer()
{
    Stop();
}

bool PipeServer::Start(const std::string& pipeName, RequestHandler handler)
{
    if (IsRunning())
        return false;

    // In case a previous Stop() was never called — guarantee a clean state
    // before starting again.
    Stop();

    auto state = std::make_shared<detail::PipeServerState>();
    state->stopEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!state->stopEvent)
        return false;

    // Risk 4: by default the pipe is accessible to any local process, and
    // untrusted debuggee code is running right next to us and is entitled to
    // use it — occupy the pipe or read someone else's responses. Build the
    // security descriptor by hand: owner and system only. If that fails, the
    // pipe is not created at all: working with weakened access rights is
    // worse than not working at all.
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;GA;;;OW)(A;;GA;;;SY)", SDDL_REVISION_1, &sd, nullptr))
    {
        CloseHandle(state->stopEvent);
        return false;
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    HANDLE pipe = CreateNamedPipeA(
        pipeName.c_str(),
        // FILE_FLAG_FIRST_PIPE_INSTANCE: with kPipeMaxInstances > 1, a plain
        // CreateNamedPipeA on a name that already has a running server would
        // otherwise succeed (it would just become one more instance of that
        // existing pipe) — this flag makes it fail instead, so two
        // PipeServer::Start() calls on the same name still cannot both
        // succeed. Only this, the very first instance, needs the flag; the
        // instances CreateNamedPipeInstance() opens later are additional
        // instances of this same pipe by design and must not set it.
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        kPipeMaxInstances, // nMaxInstances: see the comment on kPipeMaxInstances above.
        kIoBufferSize,
        kIoBufferSize,
        0,
        &sa);

    // The security descriptor is copied into the internal pipe structures on
    // success and is not needed by the OS on failure — free it on both paths.
    LocalFree(sd);

    if (pipe == INVALID_HANDLE_VALUE)
    {
        CloseHandle(state->stopEvent);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(nameMutex_);
        pipeName_ = pipeName;
    }

    state->pipeName = pipeName;
    state->handler = std::move(handler);
    state->running = true;

    try
    {
        thread_ = std::thread(&ServerThreadMain, state, pipe);
    }
    catch (...)
    {
        // Risk 8: a failure to create the thread must not leave the running
        // flag set or the handles orphaned.
        state->running = false;
        CloseHandle(pipe);
        CloseHandle(state->stopEvent);
        state->stopEvent = nullptr;
        return false;
    }

    state_ = std::move(state);
    return true;
}

void PipeServer::Stop()
{
    if (!state_)
        return; // not running, or already stopped

    // Defect 2: release the server's own reference to the shared state. If
    // a thread has to be detached below, its own copy of the shared_ptr is
    // already the only thing keeping the state (and the handles) alive,
    // right up until it actually finishes.
    std::shared_ptr<detail::PipeServerState> state = state_;
    state_.reset();

    SetEvent(state->stopEvent);

    // Wait budget shared across the accept-loop thread and every connection
    // thread (see JoinOrDetach) — this is what keeps Stop() prompt even when
    // several clients are connected at once.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kJoinTimeoutMs);

    JoinOrDetach(thread_, deadline);

    std::vector<std::thread> connectionThreads;
    {
        std::lock_guard<std::mutex> lock(state->connectionsMutex);
        connectionThreads = std::move(state->connectionThreads);
    }
    for (auto& t : connectionThreads)
        JoinOrDetach(t, deadline);

    // If every thread joined, `state` here is the only reference, and its
    // destruction now closes the stop event. If any thread was detached, its
    // own copy of the shared_ptr keeps the state alive until it finishes on
    // its own, and closes the stop event at that point.
}

bool PipeServer::IsRunning() const
{
    return state_ && state_->running.load();
}

std::string PipeServer::PipeName() const
{
    std::lock_guard<std::mutex> lock(nameMutex_);
    return pipeName_;
}

} // namespace x64dbg_mcp
