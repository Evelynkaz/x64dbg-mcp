#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <mutex>
#include <string>

namespace x64dbg_mcp
{

// Windows named pipe client. Lives in the bridge process and connects
// to the server running inside the x64dbg plugin.
class PipeClient
{
public:
    // protocolMajorOverride / protocolMinorOverride — with the default value
    // (-1), the client advertises the real protocol version from
    // ipc_protocol.h. These parameters exist purely for unit tests of the
    // version handshake (see defect 3 in the review): they let the client
    // advertise a version different from its own without touching ipc_protocol.h.
    explicit PipeClient(int protocolMajorOverride = -1, int protocolMinorOverride = -1);
    ~PipeClient();

    PipeClient(const PipeClient&) = delete;
    PipeClient& operator=(const PipeClient&) = delete;

    // Connects to the pipe. timeoutMs is the wait limit. Internally, transparently
    // to the caller, performs the protocol version handshake: if the server's
    // major version differs from its own, the connection is closed and
    // false is returned (see LastError() for details).
    // Returns false if the pipe is unavailable (x64dbg isn't running or the
    // plugin isn't loaded) or the timeout expired; see LastError() for details.
    bool Connect(const std::string& pipeName, int timeoutMs);

    // Tears down the connection. Does not wait for the lock held by
    // SendRequest for the duration of the current request — it first signals
    // the abort event so that pending I/O inside SendRequest completes
    // immediately (see risk 9 in the review), and only then closes the
    // handles under the lock.
    void Disconnect();
    bool IsConnected() const;

    // Sends a request and waits for the response.
    // Returns false on a communication error, a dropped connection (see
    // Disconnect), or a timed-out wait; in that case the connection is
    // considered unusable and is closed.
    bool SendRequest(const std::string& request, std::string& response, int timeoutMs);

    // Text of the last error — for reporting to the user. Always in English.
    std::string LastError() const;

private:
    // Result of an I/O operation waited on with a timeout.
    enum class IoResult { Ok, TimedOut, Aborted, Error };

    // All private methods below assume mutex_ is already held by the
    // calling public method.
    void ClosePipe();
    void SetError(std::string message);
    bool PerformHandshake(int timeoutMs);
    IoResult WaitForIo(OVERLAPPED& ov, DWORD& transferred, int timeoutMs, const char* verb);
    IoResult ReadBytes(char* buffer, DWORD size, DWORD& transferred, int timeoutMs);
    IoResult WriteBytes(const char* data, DWORD size, DWORD& transferred, int timeoutMs);
    bool WriteAll(const std::string& data, unsigned long long deadlineTick);

    HANDLE hPipe_ = INVALID_HANDLE_VALUE;
    // Risk 9: signaled in Disconnect() without holding mutex_, so it can
    // interrupt I/O waiting inside SendRequest without waiting for its timeout.
    HANDLE abortEvent_ = nullptr;
    mutable std::mutex mutex_;
    std::string lastError_;

    int protocolMajorOverride_;
    int protocolMinorOverride_;
};

} // namespace x64dbg_mcp
