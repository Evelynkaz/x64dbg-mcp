#include "common/pipe_client.h"
#include "common/framing.h"
#include "common/ipc_protocol.h"
#include "nlohmann/json.hpp"

#include <algorithm>

namespace x64dbg_mcp
{

namespace
{

// Размер внутреннего буфера чтения. Совпадает с тем, что использует
// PipeServer — оба выбраны из одних и тех же соображений.
constexpr DWORD kIoBufferSize = 64u * 1024u;

// Названия полей кадра рукопожатия версии протокола — приватный контракт
// между PipeClient и PipeServer (см. дефект 3 в ревью и одноимённый
// комментарий в pipe_server.cpp). При изменении менять оба места.
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
    ResetEvent(abortEvent_); // на случай повторного подключения после Disconnect()

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
                ClosePipe(); // lastError_ уже установлен внутри PerformHandshake
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

        // Канал существует, но занят другим клиентом — ждём своей очереди.
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

        // Канал освободился — повторяем попытку подключения.
    }
}

// Дефект 3: рукопожатие версии протокола, выполняется прозрачно внутри
// Connect(). Клиент заявляет свою версию первым кадром, сервер отвечает
// своей; при расхождении мажорных версий соединение непригодно.
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
        return false; // lastError_ уже установлен внутри WriteAll

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
            return false; // lastError_ уже установлен внутри ReadBytes

        if (transferred == 0)
            return false; // риск 7: не крутим цикл при нулевом прогрессе чтения

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
    // Риск 9: взводим событие прерывания без блокировки. Если SendRequest
    // сейчас удерживает mutex_ в ожидании ввода-вывода, он проснётся и
    // отпустит блокировку почти сразу, не дожидаясь истечения своего
    // таймаута.
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
        return false; // lastError_ уже установлен внутри WriteAll
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
            ClosePipe(); // lastError_ уже установлен внутри ReadBytes
            return false;
        }

        if (transferred == 0)
        {
            SetError("Read from the pipe made no progress");
            ClosePipe();
            return false; // риск 7: не крутим цикл при нулевом прогрессе чтения
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
    // Риск 9: ждём одновременно завершения операции и события прерывания —
    // Disconnect() может взвести его в любой момент, не дожидаясь нашего
    // таймаута.
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
        // Прервано через Disconnect(). Отменяем операцию и дожидаемся её
        // фактического завершения по тем же причинам, что и при таймауте
        // ниже: OVERLAPPED находится на стеке вызывающего.
        CancelIoEx(hPipe_, &ov);
        GetOverlappedResult(hPipe_, &ov, &transferred, TRUE);
        SetError("Operation aborted: Disconnect() was called");
        return IoResult::Aborted;
    }

    // Таймаут (или сбой ожидания) — отменяем операцию и дожидаемся её
    // фактического завершения, иначе OVERLAPPED на стеке разрушится раньше,
    // чем ОС перестанет с ней работать.
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
            return false; // lastError_ уже установлен внутри WriteBytes

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
