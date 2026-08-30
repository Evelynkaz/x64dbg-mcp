#pragma once

#include <string>

namespace x64dbg_mcp::bridge
{

// Уровни журнала, от самого важного к самому подробному.
enum class LogLevel { Error, Warn, Info, Debug };

// Устанавливает минимальный уровень журналирования: сообщения менее важного
// уровня отбрасываются. Влияет на все последующие вызовы Log() из любого потока.
void SetLogLevel(LogLevel level);

// Пишет строку журнала в stderr. Никогда не пишет в stdout — тот зарезервирован
// под сообщения протокола MCP, и любая посторонняя запись туда сломает транспорт.
void Log(LogLevel level, const std::string& message);

} // namespace x64dbg_mcp::bridge
