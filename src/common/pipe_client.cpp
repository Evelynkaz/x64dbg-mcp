#include "common/pipe_client.h"
#include "common/framing.h"
#include "common/ipc_protocol.h"
#include "nlohmann/json.hpp"

#include <algorithm>

namespace x64dbg_mcp
{

namespace
{

// Size of the internal read buffer. Matches what PipeServer uses — both are
// chosen for the same reasons.
constexpr DWORD kIoBufferSize = 64u * 1024u;

// Field names of the protocol version handshake frame — a private contract
// between PipeClient and PipeServer (see defect 3 in the review and the
// matching comment in pipe_server.cpp). If you change these, change both places.
constexpr const char* kFieldProtocolVersion = "protocolVersion";
constexpr const char* kFieldMajor = "major";
constexpr const char* kFieldMinor = "minor";

} // namespace

PipeClient::PipeClient(int protocolMajorOverride, int protocolMinorOverride)
    : protocolMajorOverride_(protocolMajorOverride)
    , protocolMinorOverride_(protocolMinorOverride)
{
    abortEvent_ = CreateEventA(nullptr, TRUE, FALSE, nullptr);
}

PipeClient::~PipeClient()
{
    Disconnect();
    if (abortEvent_)
    {
        CloseHandle(abortEvent_);
        abortEvent_ = nullptr;
    }
}

bool PipeClient::Connect(const std::string& pipeName, int timeoutMs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    ClosePipe();

    if (!abortEvent_)
    {
        SetError("Failed to create a synchronization event");
        return false;
    }
    ResetEvent(abortEvent_); // in case of reconnecting after Disconnect()

    const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>((std::max)(timeoutMs, 0));

    for (;;)
    {
        const HANDLE h = CreateFileA(
            pipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            nullptr);

        if (h != INVALID_HANDLE_VALUE)
        {
            hPipe_ = h;
            lastError_.clear();

            const ULONGLONG now = GetTickCount64();
            const int handshakeTimeoutMs = static_cast<int>((now < deadline) ? (deadline - now) : 0);
            if (!PerformHandshake(handshakeTimeoutMs))
            {
                ClosePipe(); // lastError_ has already been set inside PerformHandshake
                return false;
            }
            return true;
        }

        const DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND)
        {
            SetError("Named pipe not found: x64dbg is not running or the plugin is not loaded");
            return false;
        }

        if (err != ERROR_PIPE_BUSY)
        {
            SetError("Failed to open the named pipe (error " + std::to_string(err) + ")");
            return false;
        }

        // The pipe exists but is busy with another client — wait our turn.
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline)
        {
            SetError("Timed out waiting for the named pipe (pipe is busy)");
            return false;
        }

        if (!WaitNamedPipeA(pipeName.c_str(), static_cast<DWORD>(deadline - now)))
        {
            const DWORD waitErr = GetLastError();
            if (waitErr == ERROR_FILE_NOT_FOUND)
                SetError("Named pipe not found: x64dbg is not running or the plugin is not loaded");
            else
                SetError("Timed out waiting for the named pipe (pipe is busy)");
            return false;
        }

        // The pipe freed up — retry the connection attempt.
    }
}

// Defect 3: protocol version handshake, performed transparently inside
// Connect(). The client advertises its own version in the first frame, the
// server replies with its own; if the major versions differ, the connection is unusable.
bool PipeClient::PerformHandshake(int timeoutMs)
{
    const int major = (protocolMajorOverride_ >= 0) ? protocolMajorOverride_ : ipc::kProtocolVersionMajor;
    const int minor = (protocolMinorOverride_ >= 0) ? protocolMinorOverride_ : ipc::kProtocolVersionMinor;

    const nlohmann::json request = {
        {kFieldProtocolVersion, {
            {kFieldMajor, major},
            {kFieldMinor, minor}
        }}
    };

    std::string frame;
    if (!EncodeFrame(request.dump(), frame))
    {
        SetError("Failed to encode the protocol handshake frame");
        return false;
    }

    const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>((std::max)(timeoutMs, 0));
    if (!WriteAll(frame, deadline))
        return false; // lastError_ has already been set inside WriteAll

    FrameReader reader;
    std::string chunk(kIoBufferSize, '\0');
    std::string payload;

    for (;;)
    {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline)
        {
            SetError("Timed out waiting for the protocol handshake response");
            return false;
        }

        DWORD transferred = 0;
        const IoResult r = ReadBytes(chunk.data(), static_cast<DWORD>(chunk.size()), transferred,
                                      static_cast<int>(deadline - now));
        if (r == IoResult::TimedOut)
        {
            SetError("Timed out waiting for the protocol handshake response");
            return false;
        }
        if (r != IoResult::Ok)
            return false; // lastError_ has already been set inside ReadBytes

        if (transferred == 0)
            return false; // risk 7: do not spin the loop on zero read progress

        if (reader.Feed(chunk.data(), transferred) == FrameReader::Status::Overflow)
        {
            SetError("Received a malformed protocol handshake response");
            return false;
        }

        if (reader.Next(payload))
            break;
    }

    int serverMajor = -1;
    try
    {
        const nlohmann::json parsed = nlohmann::json::parse(payload);
        serverMajor = parsed.at(kFieldProtocolVersion).at(kFieldMajor).get<int>();
    }
    catch (...)
    {
        SetError("Received a malformed protocol handshake response");
        return false;
    }

    if (serverMajor != major)
    {
        SetError("Protocol version mismatch: plugin speaks major " + std::to_string(serverMajor) +
                  ", bridge speaks major " + std::to_string(major) +
                  ". Update both the plugin and the server to the same release.");
        return false;
    }

    return true;
}

void PipeClient::Disconnect()
{
    // Risk 9: signal the abort event without holding the lock. If SendRequest
    // is currently holding mutex_ while waiting on I/O, it will wake up and
    // release the lock almost immediately, without waiting out its own timeout.
    if (abortEvent_)
        SetEvent(abortEvent_);

    std::lock_guard<std::mutex> lock(mutex_);
    ClosePipe();
}

void PipeClient::ClosePipe()
{
    if (hPipe_ != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hPipe_);
        hPipe_ = INVALID_HANDLE_VALUE;
    }
}

bool PipeClient::IsConnected() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return hPipe_ != INVALID_HANDLE_VALUE;
}

std::string PipeClient::LastError() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return lastError_;
}

void PipeClient::SetError(std::string message)
{
    lastError_ = std::move(message);
}

bool PipeClient::SendRequest(const std::string& request, std::string& response, int timeoutMs)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (hPipe_ == INVALID_HANDLE_VALUE)
    {
        SetError("Not connected");
        return false;
    }

    std::string frame;
    if (!EncodeFrame(request, frame))
    {
        SetError("Request payload is too large to encode");
        return false;
    }

    const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>((std::max)(timeoutMs, 0));

    if (!WriteAll(frame, deadline))
    {
        ClosePipe();
        return false; // lastError_ has already been set inside WriteAll
    }

    FrameReader reader;
    std::string chunk(kIoBufferSize, '\0');
    std::string payload;

    for (;;)
    {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline)
        {
            SetError("Timed out waiting for a response");
            ClosePipe();
            return false;
        }

        DWORD transferred = 0;
        const IoResult r = ReadBytes(chunk.data(), static_cast<DWORD>(chunk.size()), transferred,
                                      static_cast<int>(deadline - now));
        if (r == IoResult::TimedOut)
        {
            SetError("Timed out waiting for a response");
            ClosePipe();
            return false;
        }
        if (r != IoResult::Ok)
        {
            ClosePipe(); // lastError_ has already been set inside ReadBytes
            return false;
        }

        if (transferred == 0)
        {
            SetError("Read from the pipe made no progress");
            ClosePipe();
            return false; // risk 7: do not spin the loop on zero read progress
        }

        if (reader.Feed(chunk.data(), transferred) == FrameReader::Status::Overflow)
        {
            SetError("Received a malformed or oversized response frame");
            ClosePipe();
            return false;
        }

        if (reader.Next(payload))
        {
            response = std::move(payload);
            return true;
        }
    }
}

PipeClient::IoResult PipeClient::WaitForIo(OVERLAPPED& ov, DWORD& transferred, int timeoutMs, const char* verb)
{
    // Risk 9: wait on both the operation completing and the abort event —
    // Disconnect() may signal it at any moment, without waiting out our timeout.
    HANDLE waitHandles[2] = { ov.hEvent, abortEvent_ };
    const DWORD wr = WaitForMultipleObjects(2, waitHandles, FALSE, static_cast<DWORD>((std::max)(timeoutMs, 0)));

    if (wr == WAIT_OBJECT_0)
    {
        if (GetOverlappedResult(hPipe_, &ov, &transferred, FALSE))
            return IoResult::Ok;

        SetError(std::string("Failed to ") + verb + " the pipe (error " + std::to_string(GetLastError()) + ")");
        return IoResult::Error;
    }

    if (wr == WAIT_OBJECT_0 + 1)
    {
        // Interrupted via Disconnect(). Cancel the operation and wait for it
        // to actually finish, for the same reason as the timeout case
        // below: the OVERLAPPED lives on the stack of the caller.
        CancelIoEx(hPipe_, &ov);
        GetOverlappedResult(hPipe_, &ov, &transferred, TRUE);
        SetError("Operation aborted: Disconnect() was called");
        return IoResult::Aborted;
    }

    // Timeout (or a failed wait) — cancel the operation and wait for it to
    // actually finish, otherwise the stack-allocated OVERLAPPED would be
    // destroyed before the OS is done writing to it.
    CancelIoEx(hPipe_, &ov);
    GetOverlappedResult(hPipe_, &ov, &transferred, TRUE);
    return IoResult::TimedOut;
}

PipeClient::IoResult PipeClient::ReadBytes(char* buffer, DWORD size, DWORD& transferred, int timeoutMs)
{
    OVERLAPPED ov{};
    ov.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent)
    {
        SetError("Failed to create a synchronization event");
        return IoResult::Error;
    }

    IoResult result;
    if (ReadFile(hPipe_, buffer, size, nullptr, &ov))
    {
        if (GetOverlappedResult(hPipe_, &ov, &transferred, FALSE))
            result = IoResult::Ok;
        else
        {
            SetError("Failed to read from the pipe (error " + std::to_string(GetLastError()) + ")");
            result = IoResult::Error;
        }
    }
    else
    {
        const DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING)
        {
            result = WaitForIo(ov, transferred, timeoutMs, "read from");
        }
        else
        {
            SetError("Failed to read from the pipe (error " + std::to_string(err) + ")");
            result = IoResult::Error;
        }
    }

    CloseHandle(ov.hEvent);
    return result;
}

PipeClient::IoResult PipeClient::WriteBytes(const char* data, DWORD size, DWORD& transferred, int timeoutMs)
{
    OVERLAPPED ov{};
    ov.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent)
    {
        SetError("Failed to create a synchronization event");
        return IoResult::Error;
    }

    IoResult result;
    if (WriteFile(hPipe_, data, size, nullptr, &ov))
    {
        if (GetOverlappedResult(hPipe_, &ov, &transferred, FALSE))
            result = IoResult::Ok;
        else
        {
            SetError("Failed to write to the pipe (error " + std::to_string(GetLastError()) + ")");
            result = IoResult::Error;
        }
    }
    else
    {
        const DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING)
        {
            result = WaitForIo(ov, transferred, timeoutMs, "write to");
        }
        else
        {
            SetError("Failed to write to the pipe (error " + std::to_string(err) + ")");
            result = IoResult::Error;
        }
    }

    CloseHandle(ov.hEvent);
    return result;
}

bool PipeClient::WriteAll(const std::string& data, unsigned long long deadlineTick)
{
    size_t totalWritten = 0;
    while (totalWritten < data.size())
    {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadlineTick)
        {
            SetError("Timed out sending the request");
            return false;
        }

        DWORD chunkWritten = 0;
        const size_t remaining = data.size() - totalWritten;
        const DWORD toWrite = static_cast<DWORD>((remaining > 0xFFFFFFFFu) ? 0xFFFFFFFFu : remaining);

        const IoResult r = WriteBytes(data.data() + totalWritten, toWrite, chunkWritten,
                                       static_cast<int>(deadlineTick - now));
        if (r == IoResult::TimedOut)
        {
            SetError("Timed out sending the request");
            return false;
        }
        if (r != IoResult::Ok)
            return false; // lastError_ has already been set inside WriteBytes

        if (chunkWritten == 0)
        {
            SetError("Write to the pipe made no progress");
            return false;
        }

        totalWritten += chunkWritten;
    }
    return true;
}

} // namespace x64dbg_mcp
