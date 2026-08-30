#include "bridge/stdio_transport.h"
#include "bridge/logging.h"

#include <iostream>
#include <optional>
#include <string>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace x64dbg_mcp::bridge
{

void RunStdioLoop(McpServer& server)
{
#ifdef _WIN32
    // По умолчанию поток stdout на Windows открыт в текстовом режиме, в
    // котором рантайм превращает каждый '\n' в пару CR LF. Протокол требует
    // ровно один перевод строки на сообщение, поэтому без двоичного режима
    // ответ будет перенесён построчным парсером клиента как два сообщения
    // и сломает транспорт.
    _setmode(_fileno(stdout), _O_BINARY);
#endif

    std::string line;
    while (std::getline(std::cin, line))
    {
        if (line.empty())
            continue;

        const std::optional<std::string> response = server.HandleMessage(line);
        if (!response)
            continue;

        // Немедленный сброс буфера обязателен: клиент ждёт ответ на этой же
        // строке синхронно, буферизация stdout заставила бы его зависнуть.
        std::cout << *response << "\n";
        std::cout.flush();
    }

    Log(LogLevel::Info, "stdin closed (EOF), shutting down");
}

} // namespace x64dbg_mcp::bridge
