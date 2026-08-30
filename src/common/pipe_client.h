#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <mutex>
#include <string>

namespace x64dbg_mcp
{

// Клиент именованного канала Windows. Живёт в процессе моста и подключается
// к серверу, работающему внутри плагина x64dbg.
class PipeClient
{
public:
    // protocolMajorOverride / protocolMinorOverride — со значением по
    // умолчанию (-1) клиент заявляет реальную версию протокола из
    // ipc_protocol.h. Параметры существуют исключительно для юнит-тестов
    // рукопожатия версии (см. дефект 3 в ревью): позволяют клиенту заявить
    // версию, отличную от собственной, не трогая ipc_protocol.h.
    explicit PipeClient(int protocolMajorOverride = -1, int protocolMinorOverride = -1);
    ~PipeClient();

    PipeClient(const PipeClient&) = delete;
    PipeClient& operator=(const PipeClient&) = delete;

    // Подключается к каналу. timeoutMs — предел ожидания. Внутри, прозрачно
    // для вызывающего, выполняет рукопожатие версии протокола: если мажорная
    // версия сервера отличается от собственной, соединение закрывается и
    // возвращается false (подробности — в LastError()).
    // Возвращает false, если канал недоступен (x64dbg не запущен или плагин
    // не загружен) либо истёк таймаут; подробности — в LastError().
    bool Connect(const std::string& pipeName, int timeoutMs);

    // Разрывает соединение. Не ждёт блокировку, удерживаемую SendRequest на
    // время текущего запроса — сначала взводит событие прерывания, чтобы
    // ожидающий ввод-вывод в SendRequest завершился немедленно (см. риск 9
    // в ревью), и лишь затем закрывает дескрипторы под блокировкой.
    void Disconnect();
    bool IsConnected() const;

    // Отправляет запрос и дожидается ответа.
    // Возвращает false при ошибке связи, разрыве соединения (см. Disconnect)
    // или истечении таймаута; в этом случае соединение считается непригодным
    // и закрывается.
    bool SendRequest(const std::string& request, std::string& response, int timeoutMs);

    // Текст последней ошибки — для сообщения пользователю. Всегда на английском.
    std::string LastError() const;

private:
    // Результат операции ввода-вывода с ожиданием по таймауту.
    enum class IoResult { Ok, TimedOut, Aborted, Error };

    // Все приватные методы ниже предполагают, что mutex_ уже захвачен
    // вызывающим публичным методом.
    void ClosePipe();
    void SetError(std::string message);
    bool PerformHandshake(int timeoutMs);
    IoResult WaitForIo(OVERLAPPED& ov, DWORD& transferred, int timeoutMs, const char* verb);
    IoResult ReadBytes(char* buffer, DWORD size, DWORD& transferred, int timeoutMs);
    IoResult WriteBytes(const char* data, DWORD size, DWORD& transferred, int timeoutMs);
    bool WriteAll(const std::string& data, unsigned long long deadlineTick);

    HANDLE hPipe_ = INVALID_HANDLE_VALUE;
    // Риск 9: взводится в Disconnect() без захвата mutex_, чтобы прервать
    // ввод-вывод, ожидающий внутри SendRequest, не дожидаясь его таймаута.
    HANDLE abortEvent_ = nullptr;
    mutable std::mutex mutex_;
    std::string lastError_;

    int protocolMajorOverride_;
    int protocolMinorOverride_;
};

} // namespace x64dbg_mcp
