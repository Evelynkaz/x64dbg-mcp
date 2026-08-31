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
    // By default the stdout stream on Windows is opened in text mode, where
    // the runtime turns every '\n' into a CR LF pair. The protocol requires
    // exactly one newline per message, so without binary mode the response
    // would be split by the client's line-based parser into two messages
    // and break the transport.
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

        // Flushing the buffer immediately is mandatory: the client waits for
        // the response synchronously, buffering stdout would make it hang.
        std::cout << *response << "\n";
        std::cout.flush();
    }

    Log(LogLevel::Info, "stdin closed (EOF), shutting down");
}

} // namespace x64dbg_mcp::bridge
