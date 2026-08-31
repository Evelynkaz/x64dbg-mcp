#pragma once

#include "common/pipe_server.h"
#include "plugin/debug_state.h"
#include "plugin/worker.h"

#include <string>

namespace x64dbg_mcp::plugin
{

// Синглтон: коллбэки x64dbg — свободные функции без пользовательских данных
// (см. CBPLUGIN в _plugins.h), им нужна общая точка доступа к состоянию.
class McpService
{
public:
    static McpService& Instance();

    McpService(const McpService&) = delete;
    McpService& operator=(const McpService&) = delete;

    // Запускает рабочий поток и сервер канала. Возвращает false при неудаче.
    bool Start();
    // Останавливает всё в безопасном порядке (см. .cpp).
    void Stop();

    DebugStateTracker& Tracker();

    // Имя канала, на котором работает сервер (для сообщения в лог).
    std::string PipeName() const;

private:
    McpService() = default;
    ~McpService() = default;

    std::string HandleRequest(const std::string& request);

    DebugStateTracker tracker_;
    DebuggerWorker worker_;
    PipeServer pipeServer_;
};

// Регистрирует коллбэки состояния отладки, обновляющие McpService::Instance().Tracker().
// Вызывать один раз при инициализации плагина.
void RegisterDebugCallbacks(int pluginHandle);

// Снимает коллбэки, зарегистрированные RegisterDebugCallbacks. Вызывать при выгрузке.
void UnregisterDebugCallbacks(int pluginHandle);

} // namespace x64dbg_mcp::plugin
