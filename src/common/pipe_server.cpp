#include "common/pipe_server.h"
#include "common/framing.h"
#include "common/ipc_protocol.h"
#include "nlohmann/json.hpp"

#include <sddl.h>

namespace x64dbg_mcp
{

namespace detail
{

PipeServerState::~PipeServerState()
{
    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);
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

// Limit on how long Stop() waits for the worker thread to join. Also used as
// a diagnostic reference point in the comments below.
constexpr DWORD kJoinTimeoutMs = 5000;

// Field names of the protocol version handshake frame — a private contract
// between PipeServer and PipeClient (see defect 3 in the review). This is
// not part of the public ipc_protocol.h, so it is defined here and
// duplicated (under the same names) in pipe_client.cpp — if you change
// these, change both places.
constexpr const char* kFieldProtocolVersion = "protocolVersion";
constexpr const char* kFieldMajor = "major";
constexpr const char* kFieldMinor = "minor";

// Result of an I/O operation that can be interrupted by the stop event.
enum class IoResult { Ok, Disconnected, Stopped, Error };

IoResult WaitIoCompletion(detail::PipeServerState& state, OVERLAPPED& ov, DWORD& transferred)
{
    HANDLE waitHandles[2] = { ov.hEvent, state.stopEvent };
    const DWORD wr = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
    if (wr == WAIT_OBJECT_0)
    {
        if (GetOverlappedResult(state.hPipe, &ov, &transferred, FALSE))
            return IoResult::Ok;

        const DWORD err = GetLastError();
        return (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED)
            ? IoResult::Disconnected
            : IoResult::Error;
    }

    // A stop was requested (or the wait itself failed) — cancel the
    // operation and wait for it to actually finish: the OVERLAPPED here
    // lives on the stack of the caller, and the OS must not write into it
    // after this function returns.
    CancelIoEx(state.hPipe, &ov);
    GetOverlappedResult(state.hPipe, &ov, &transferred, TRUE);
    return IoResult::Stopped;
}

IoResult ReadBytes(detail::PipeServerState& state, char* buffer, DWORD size, DWORD& transferred)
{
    OVERLAPPED ov{};
    ov.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent)
        return IoResult::Error;

    IoResult result;
    if (ReadFile(state.hPipe, buffer, size, nullptr, &ov))
    {
        result = GetOverlappedResult(state.hPipe, &ov, &transferred, FALSE) ? IoResult::Ok : IoResult::Error;
    }
    else
    {
        const DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING)
        {
            result = WaitIoCompletion(state, ov, transferred);
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

IoResult WriteBytes(detail::PipeServerState& state, const char* data, DWORD size, DWORD& transferred)
{
    OVERLAPPED ov{};
    ov.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent)
        return IoResult::Error;

    IoResult result;
    if (WriteFile(state.hPipe, data, size, nullptr, &ov))
    {
        result = GetOverlappedResult(state.hPipe, &ov, &transferred, FALSE) ? IoResult::Ok : IoResult::Error;
    }
    else
    {
        const DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING)
        {
            result = WaitIoCompletion(state, ov, transferred);
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

bool WriteAll(detail::PipeServerState& state, const std::string& data)
{
    size_t totalWritten = 0;
    while (totalWritten < data.size())
    {
        DWORD chunkWritten = 0;
        const size_t remaining = data.size() - totalWritten;
        const DWORD toWrite = static_cast<DWORD>((remaining > 0xFFFFFFFFu) ? 0xFFFFFFFFu : remaining);

        if (WriteBytes(state, data.data() + totalWritten, toWrite, chunkWritten) != IoResult::Ok)
            return false;

        if (chunkWritten == 0)
            return false; // guard against hanging on an anomalous zero write progress

        totalWritten += chunkWritten;
    }
    return true;
}

std::string InvokeHandler(detail::PipeServerState& state, const std::string& request)
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
        return state.handler(request);
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

bool AcceptConnection(detail::PipeServerState& state)
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

        if (ConnectNamedPipe(state.hPipe, &ov))
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
                const IoResult r = WaitIoCompletion(state, ov, transferred);
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
            return false; // Run() will see the stop event signaled and exit on its own

        if (err == ERROR_NO_DATA)
        {
            DisconnectNamedPipe(state.hPipe);
            if (WaitForSingleObject(state.stopEvent, 0) == WAIT_OBJECT_0)
                return false;
            continue; // retry the accept
        }

        // Any other accept error is NOT considered fatal for the server as a
        // whole — it just means this particular connection could not be
        // accepted. Disconnect the pipe and return false: the main loop
        // (Run()) will check the stop event and, if it is not signaled,
        // simply try to accept a connection again. The accept loop exits
        // ONLY on a stop request, never because of a routine pipe error.
        DisconnectNamedPipe(state.hPipe);
        return false;
    }

    // Ran out of retry attempts on a repeating ERROR_NO_DATA. Not fatal:
    // return false and let the main loop decide — if a stop was not
    // requested, it will call AcceptConnection again.
    return false;
}

// Protocol version handshake (defect 3): the first frame after connecting.
// The server receives a frame with the client version, replies with its own
// version, and if the major versions diverge, does not service the
// connection any further.
bool PerformHandshake(detail::PipeServerState& state, FrameReader& reader, std::string& readBuf)
{
    std::string payload;
    while (!reader.Next(payload))
    {
        DWORD bytesRead = 0;
        if (ReadBytes(state, readBuf.data(), static_cast<DWORD>(readBuf.size()), bytesRead) != IoResult::Ok)
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
    if (!WriteAll(state, frame))
        return false;

    return clientMajor == ipc::kProtocolVersionMajor;
}

void ServeConnection(detail::PipeServerState& state)
{
    FrameReader reader;
    std::string readBuf(kIoBufferSize, '\0');

    if (!PerformHandshake(state, reader, readBuf))
        return; // versions did not match, or the handshake was corrupted — close the connection

    auto flushReady = [&](std::string& payload) -> bool
    {
        while (reader.Next(payload))
        {
            const std::string responseBody = InvokeHandler(state, payload);

            std::string frame;
            if (!EncodeFrame(responseBody, frame))
                return false; // the response did not fit in a frame — the connection has to be closed

            if (!WriteAll(state, frame))
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
        const IoResult r = ReadBytes(state, readBuf.data(), static_cast<DWORD>(readBuf.size()), bytesRead);
        if (r != IoResult::Ok)
            return; // a stop, the client disconnecting, or an error — close the connection

        if (bytesRead == 0)
            return; // risk 7: do not allow an idle loop on zero read progress

        if (reader.Feed(readBuf.data(), bytesRead) == FrameReader::Status::Overflow)
            return; // the parser failed — the connection has to be closed

        if (!flushReady(payload))
            return;
    }
}

void RunLoop(detail::PipeServerState& state)
{
    for (;;)
    {
        // Main rule (defect 1): the accept loop exits ONLY on a stop
        // request — check it here and nowhere else. Any error while
        // accepting or serving a single connection (see AcceptConnection and
        // ServeConnection) is a routine per-client situation, not a reason
        // to stop the whole server.
        if (WaitForSingleObject(state.stopEvent, 0) == WAIT_OBJECT_0)
            break;

        if (AcceptConnection(state))
        {
            ServeConnection(state);
            DisconnectNamedPipe(state.hPipe);
        }
    }
}

// Defect 2 (continued): if Stop() fails to join the worker thread within the
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

void ServerThreadMain(std::shared_ptr<detail::PipeServerState> state)
{
    // Risk 5: do not let an exception escape the thread function — that
    // would tear down the whole x64dbg process. Only C++ exceptions are
    // caught (including std::bad_alloc when allocating the read buffer or
    // building JSON inside InvokeHandler); for structured exceptions, see
    // the comment there.
    try
    {
        RunLoop(*state);
    }
    catch (...)
    {
    }

    state->running = false;
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
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, // nMaxInstances: see the comment on Start() in the header.
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

    state->hPipe = pipe;
    state->handler = std::move(handler);
    state->running = true;

    try
    {
        thread_ = std::thread(&ServerThreadMain, state);
    }
    catch (...)
    {
        // Risk 8: a failure to create the thread must not leave the running
        // flag set or the handles orphaned.
        state->running = false;
        CloseHandle(state->hPipe);
        CloseHandle(state->stopEvent);
        state->hPipe = INVALID_HANDLE_VALUE;
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
    // the thread has to be detached below, its own copy of the shared_ptr is
    // already the only thing keeping the state (and the handles) alive,
    // right up until it actually finishes.
    std::shared_ptr<detail::PipeServerState> state = state_;
    state_.reset();

    SetEvent(state->stopEvent);

    // Cancels every I/O operation pending on this handle, regardless of
    // which call (ConnectNamedPipe, ReadFile, or WriteFile) the thread is
    // currently stuck in. This is what lets Stop() avoid waiting for the
    // client to disconnect.
    CancelIoEx(state->hPipe, nullptr);

    if (thread_.joinable())
    {
        // Wait limit: after SetEvent and CancelIoEx, the thread must react
        // almost instantly if it is waiting on I/O. If that did not happen,
        // the thread is most likely stuck inside a third-party request
        // handler. TerminateThread is deliberately not used here: it could
        // stop the thread while it holds a critical section or is in the
        // middle of working with the heap, leaving the process (which is
        // x64dbg) in an unpredictable state — that is worse than a detached
        // thread that finishes carrying its own state on its own.
        if (WaitForSingleObject(thread_.native_handle(), kJoinTimeoutMs) == WAIT_OBJECT_0)
        {
            thread_.join();
        }
        else
        {
            OutputDebugStringA("x64dbg-mcp: PipeServer worker thread did not stop in time; detaching\n");
            PinThisModuleInMemory();
            thread_.detach();
        }
    }

    // If the thread joined, `state` here is the only reference, and its
    // destruction now closes the handles. If the thread was detached, its
    // own copy of the shared_ptr keeps the state alive until it finishes on
    // its own, and closes the handles at that point.
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
