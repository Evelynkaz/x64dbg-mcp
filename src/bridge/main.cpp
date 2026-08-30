#include "bridge/logging.h"
#include "bridge/mcp_server.h"
#include "bridge/stdio_transport.h"
#include "bridge/tool_registry.h"

#include <iostream>
#include <string>

using namespace x64dbg_mcp::bridge;

namespace
{

void PrintHelp()
{
    std::cerr <<
        "x64dbg-mcp: MCP-сервер для отладчика x64dbg (транспорт stdio)\n"
        "Использование: x64dbg-mcp [--log-level <error|warn|info|debug>] [--help]\n"
        "  --log-level <уровень>  минимальный уровень журнала в stderr (по умолчанию info)\n"
        "  --help                 показать эту справку и выйти\n";
}

bool ParseLogLevel(const std::string& value, LogLevel& out)
{
    if (value == "error") { out = LogLevel::Error; return true; }
    if (value == "warn")  { out = LogLevel::Warn;  return true; }
    if (value == "info")  { out = LogLevel::Info;  return true; }
    if (value == "debug") { out = LogLevel::Debug; return true; }
    return false;
}

} // namespace

int main(int argc, char** argv)
{
    // Любое исключение обязано быть перехвачено здесь: это точка входа
    // процесса, и её падение означает аварийное завершение сервера.
    try
    {
        LogLevel level = LogLevel::Info;

        for (int i = 1; i < argc; ++i)
        {
            const std::string arg = argv[i];
            if (arg == "--help")
            {
                PrintHelp();
                return 0;
            }
            else if (arg == "--log-level")
            {
                if (i + 1 >= argc)
                {
                    std::cerr << "--log-level требует значение\n";
                    return 1;
                }
                const std::string value = argv[++i];
                if (!ParseLogLevel(value, level))
                {
                    std::cerr << "Неизвестный уровень журнала: " << value << "\n";
                    return 1;
                }
            }
            else
            {
                std::cerr << "Неизвестный аргумент: " << arg << "\n";
                return 1;
            }
        }

        SetLogLevel(level);

        McpServer server(CreateDefaultRegistry());
        RunStdioLoop(server);
        return 0;
    }
    catch (const std::exception& e)
    {
        Log(LogLevel::Error, std::string("Необработанное исключение: ") + e.what());
        return 1;
    }
    catch (...)
    {
        Log(LogLevel::Error, "Необработанное исключение неизвестного типа");
        return 1;
    }
}
