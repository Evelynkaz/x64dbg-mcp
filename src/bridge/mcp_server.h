#pragma once

#include "bridge/tool_registry.h"
#include "nlohmann/json.hpp"

#include <optional>
#include <string>

namespace x64dbg_mcp::bridge
{

// Самая новая ревизия протокола, поддерживаемая современной (stateless) моделью.
constexpr const char* kModernVersion = "2026-07-28";

// Версии устаревшей модели, принимаемые на рукопожатии initialize, от новой
// к старой. Первый элемент — версия, которую сервер называет своей, если
// клиент прислал версию не из этого списка.
constexpr const char* kLegacyVersions[] = { "2025-11-25", "2025-06-18", "2025-03-26" };

// Ядро протокола MCP: разбор и обработка одного сообщения. Не выполняет
// ввода-вывода, поэтому полностью покрывается юнит-тестами без запуска
// настоящего транспорта.
class McpServer
{
public:
    explicit McpServer(ToolRegistry registry);

    // Обрабатывает одно входящее сообщение (одну строку JSON). Возвращает
    // строку ответа либо std::nullopt, если отвечать не нужно (уведомления
    // ответа не требуют). Никогда не бросает исключений: любая внутренняя
    // ошибка превращается в корректный ответ JSON-RPC.
    std::optional<std::string> HandleMessage(const std::string& line);

private:
    ToolRegistry registry_;

    nlohmann::json HandleToolsList() const;
    nlohmann::json HandleToolsCall(const nlohmann::json& params) const;
    nlohmann::json HandleDiscover() const;
};

} // namespace x64dbg_mcp::bridge
