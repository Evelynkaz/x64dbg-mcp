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

// Размер внутреннего буфера чтения и буферов канала. Совпадает с порогом
// сжатия буфера FrameReader — оба числа выбраны из одних и тех же
// соображений (мелкие сообщения не должны требовать лишних выделений памяти).
constexpr DWORD kIoBufferSize = 64u * 1024u;

// Предел ожидания присоединения рабочего потока в Stop(). Используется и как
// диагностический ориентир в комментариях ниже.
constexpr DWORD kJoinTimeoutMs = 5000;

// Названия полей кадра рукопожатия версии протокола — приватный контракт
// между PipeServer и PipeClient (см. дефект 3 в ревью). Это не часть
// публичного ipc_protocol.h, поэтому определены здесь и продублированы (под
// теми же именами) в pipe_client.cpp — при изменении менять оба места.
constexpr const char* kFieldProtocolVersion = "protocolVersion";
constexpr const char* kFieldMajor = "major";
constexpr const char* kFieldMinor = "minor";

// Результат операции ввода-вывода с ожиданием прерывания по событию
// остановки.
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

    // Остановка запрошена (либо ожидание само по себе не удалось) — отменяем
    // операцию и дожидаемся её фактического завершения: OVERLAPPED здесь
    // находится на стеке вызывающего, и ОС не должна писать в неё после того,
    // как эта функция вернёт управление.
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
            return false; // защита от зависания при аномальном нулевом прогрессе

        totalWritten += chunkWritten;
    }
    return true;
}

std::string InvokeHandler(detail::PipeServerState& state, const std::string& request)
{
    // Обработчик реализуется снаружи (в плагине) и может ходить в API
    // x64dbg. catch (...) здесь перехватывает только исключения C++ — этого
    // достаточно для std::bad_alloc, исключений nlohmann::json и т.п.
    // Структурные исключения (SEH) — например, обращение по недопустимому
    // адресу внутри API отладчика — эта цель собирает с синхронной моделью
    // исключений, и catch (...) их НЕ перехватывает: они пройдут мимо этого
    // обработчика и уронят весь x64dbg вместе с отлаживаемой программой (см.
    // риск 6 в ревью). Защита от них должна появиться в слое обёртки над API
    // отладчика, а не здесь.
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
    // Дефект 1: ERROR_NO_DATA — клиент закрыл свой конец канала до того, как
    // мы успели принять соединение (проверка живости, Ctrl-C, перезапуск
    // клиента). Это штатная ситуация транспорта, а не фатальная ошибка
    // канала: отсоединяем канал и пробуем принять заново, ограниченное число
    // раз, проверяя между попытками событие остановки.
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
            ok = true; // клиент подключился синхронно — редкий случай
        }
        else
        {
            err = GetLastError();
            if (err == ERROR_PIPE_CONNECTED)
            {
                ok = true; // клиент успел подключиться до вызова ConnectNamedPipe
            }
            else if (err == ERROR_IO_PENDING)
            {
                DWORD transferred = 0;
                const IoResult r = WaitIoCompletion(state, ov, transferred);
                ok = (r == IoResult::Ok);
                stopped = (r == IoResult::Stopped);
                if (!ok && !stopped)
                    err = GetLastError(); // причина сбоя GetOverlappedResult внутри WaitIoCompletion
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
            return false; // Run() увидит взведённое событие остановки и выйдет сам

        if (err == ERROR_NO_DATA)
        {
            DisconnectNamedPipe(state.hPipe);
            if (WaitForSingleObject(state.stopEvent, 0) == WAIT_OBJECT_0)
                return false;
            continue; // повторяем попытку приёма
        }

        // Любая другая ошибка приёма НЕ считается фатальной для сервера в
        // целом — она означает лишь то, что не удалось принять именно это
        // соединение. Отсоединяем канал и возвращаем false: главный цикл
        // (Run()) проверит событие остановки и, если оно не взведено, просто
        // попробует принять соединение заново. Цикл приёма завершается
        // ТОЛЬКО по запросу остановки, а не из-за штатных ошибок канала.
        DisconnectNamedPipe(state.hPipe);
        return false;
    }

    // Исчерпан лимит попыток при повторяющемся ERROR_NO_DATA. Не фатально:
    // возвращаем false и даём главному циклу решить — если остановка не
    // запрошена, он снова вызовет AcceptConnection.
    return false;
}

// Рукопожатие версии протокола (дефект 3): первый кадр после подключения.
// Сервер получает кадр с версией клиента, отвечает своей версией и, если
// мажорные версии разошлись, дальше соединение не обслуживает.
bool PerformHandshake(detail::PipeServerState& state, FrameReader& reader, std::string& readBuf)
{
    std::string payload;
    while (!reader.Next(payload))
    {
        DWORD bytesRead = 0;
        if (ReadBytes(state, readBuf.data(), static_cast<DWORD>(readBuf.size()), bytesRead) != IoResult::Ok)
            return false;

        if (bytesRead == 0)
            return false; // риск 7: не крутим цикл при нулевом прогрессе чтения

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
        clientMajor = -1; // испорченный кадр рукопожатия — трактуем как несовпадение версий
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
        return; // версии не совпали либо рукопожатие испорчено — соединение закрывается

    auto flushReady = [&](std::string& payload) -> bool
    {
        while (reader.Next(payload))
        {
            const std::string responseBody = InvokeHandler(state, payload);

            std::string frame;
            if (!EncodeFrame(responseBody, frame))
                return false; // ответ не влез в кадр — соединение придётся закрыть

            if (!WriteAll(state, frame))
                return false;
        }
        return true;
    };

    std::string payload;
    // Рукопожатие могло получить за одно чтение больше данных, чем сам кадр
    // согласования версии — не теряем то, что уже лежит в буфере разборщика.
    if (!flushReady(payload))
        return;

    for (;;)
    {
        DWORD bytesRead = 0;
        const IoResult r = ReadBytes(state, readBuf.data(), static_cast<DWORD>(readBuf.size()), bytesRead);
        if (r != IoResult::Ok)
            return; // остановка, отключение клиента или ошибка — соединение закрывается

        if (bytesRead == 0)
            return; // риск 7: не допускаем холостого цикла при нулевом прогрессе чтения

        if (reader.Feed(readBuf.data(), bytesRead) == FrameReader::Status::Overflow)
            return; // разборщик отказал — соединение подлежит закрытию

        if (!flushReady(payload))
            return;
    }
}

void RunLoop(detail::PipeServerState& state)
{
    for (;;)
    {
        // Главное правило (дефект 1): цикл приёма завершается ТОЛЬКО по
        // запросу остановки — проверяем его здесь и нигде иначе. Любая
        // ошибка приёма или обслуживания одного соединения (см.
        // AcceptConnection и ServeConnection) — штатная ситуация уровня
        // отдельного клиента, а не повод остановить сервер целиком.
        if (WaitForSingleObject(state.stopEvent, 0) == WAIT_OBJECT_0)
            break;

        if (AcceptConnection(state))
        {
            ServeConnection(state);
            DisconnectNamedPipe(state.hPipe);
        }
    }
}

// Дефект 2 (продолжение): если Stop() не дождался рабочего потока в
// отведённый срок, поток отсоединяется и продолжает исполнять код этого
// модуля самостоятельно. Если в этот момент модуль (плагин) выгрузят, поток
// начнёт исполнять инструкции по уже освобождённым адресам — гарантированный
// крах x64dbg. GET_MODULE_HANDLE_EX_FLAG_PIN навсегда увеличивает счётчик
// ссылок на модуль, так что он не будет выгружен, пока жив процесс — это
// единственный надёжный способ защититься от этого сценария, не переписывая
// механизм выгрузки плагина.
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
    // Риск 5: не даём исключению выйти из функции потока — это оборвёт весь
    // процесс x64dbg. Перехватываются только исключения C++ (в том числе
    // std::bad_alloc при выделении буфера чтения или при построении JSON
    // внутри InvokeHandler); про структурные исключения — см. комментарий
    // там же.
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

    // На случай, если предыдущий Stop() не вызывался — гарантируем чистое
    // состояние перед повторным запуском.
    Stop();

    auto state = std::make_shared<detail::PipeServerState>();
    state->stopEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!state->stopEvent)
        return false;

    // Риск 4: канал доступен по умолчанию любому локальному процессу, а рядом
    // с нами работает недоверенный отлаживаемый код, который вправе им
    // воспользоваться — занять канал или прочитать чужие ответы. Строим
    // дескриптор безопасности вручную: только владелец и система. Если это
    // не удалось — канал вообще не создаётся: работать с ослабленными
    // правами доступа хуже, чем не работать совсем.
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
        1, // nMaxInstances: см. комментарий к Start() в заголовке.
        kIoBufferSize,
        kIoBufferSize,
        0,
        &sa);

    // Дескриптор безопасности копируется во внутренние структуры канала при
    // успехе и не нужен ОС при неудаче — освобождаем его на обоих путях.
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
        // Риск 8: сбой создания потока не должен оставлять признак работы
        // взведённым, а дескрипторы — бесхозными.
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
        return; // не запущен либо уже остановлен

    // Дефект 2: отпускаем ссылку сервера на разделяемое состояние. Если ниже
    // поток придётся отсоединить, его собственная копия shared_ptr — это уже
    // единственное, что удерживает состояние (и дескрипторы) живыми, ровно до
    // его фактического завершения.
    std::shared_ptr<detail::PipeServerState> state = state_;
    state_.reset();

    SetEvent(state->stopEvent);

    // Отменяет все операции ввода-вывода, ожидающие на этом дескрипторе,
    // независимо от того, в каком именно вызове (ConnectNamedPipe, ReadFile
    // или WriteFile) сейчас застрял поток. Благодаря этому Stop() не ждёт
    // отключения клиента.
    CancelIoEx(state->hPipe, nullptr);

    if (thread_.joinable())
    {
        // Предел ожидания: после SetEvent и CancelIoEx поток обязан
        // отреагировать почти мгновенно, если он ждёт ввода-вывода. Если
        // этого не произошло — скорее всего, поток застрял внутри стороннего
        // обработчика запроса. TerminateThread здесь не применяется
        // намеренно: он может остановить поток внутри захваченной
        // критической секции или посреди работы с кучей, оставив процесс (а
        // это процесс x64dbg) в непредсказуемом состоянии — это хуже, чем
        // отсоединённый поток, который донашивает своё состояние сам.
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

    // Если поток присоединился — `state` здесь единственная ссылка, и его
    // разрушение сейчас закроет дескрипторы. Если поток отсоединён — его
    // собственная копия shared_ptr удерживает состояние живым до тех пор,
    // пока он сам не завершится, и тогда же закроет дескрипторы.
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
