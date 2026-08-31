#pragma once

#include "bridge/tool_registry.h"
#include "common/pipe_client.h"
#include "nlohmann/json.hpp"

#include <mutex>
#include <string>

namespace x64dbg_mcp::bridge
{

// Обёртка над PipeClient: превращает вызовы методов плагина в удобный
// интерфейс "запрос-ответ" (Call), скрывая детали именованного канала и
// рукопожатия протокола. Живёт в процессе моста весь срок его работы.
class PluginLink
{
public:
    explicit PluginLink(std::string pipeName, int connectTimeoutMs = 3000, int requestTimeoutMs = 15000);

    // Выполняет вызов метода плагина. Подключается при первом обращении —
    // мост запускается раньше, чем пользователь откроет x64dbg, и не должен
    // падать из-за этого (см. .cpp). Наружу не выходит ничего, кроме
    // ToolError с английским текстом, пригодным для показа модели.
    nlohmann::json Call(const std::string& method, const nlohmann::json& params);

    // Проверяет доступность плагина, не бросая исключений.
    bool IsAvailable();

    std::string PipeName() const;

private:
    // Отправляет один запрос по уже установленному (или только что
    // установленному) соединению. Возвращает false при сбое транспорта —
    // тогда Call() решает, стоит ли переподключаться и повторять.
    bool SendLocked(const std::string& method, const nlohmann::json& params, std::string& response);

    // Разбирает и проверяет ответ плагина; бросает ToolError на любое
    // несоответствие протоколу или на ошибку от самого плагина (передавая
    // её текст как есть, ничего не выдумывая).
    nlohmann::json ParseResponse(const std::string& method, const std::string& response) const;

    // Формирует сообщение об ошибке транспорта на основе LastError() клиента.
    std::string TransportErrorMessage(const std::string& method) const;

    std::string pipeName_;
    int connectTimeoutMs_;
    int requestTimeoutMs_;

    std::mutex mutex_;
    x64dbg_mcp::PipeClient client_;
    int nextId_ = 1;
};

} // namespace x64dbg_mcp::bridge
