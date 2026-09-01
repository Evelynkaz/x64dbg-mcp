#include "bridge/logging.h"
#include "bridge/mcp_server.h"
#include "bridge/plugin_link.h"
#include "bridge/stdio_transport.h"
#include "bridge/tool_registry.h"
#include "common/ipc_protocol.h"

#include <iostream>
#include <memory>
#include <string>

using namespace x64dbg_mcp::bridge;

namespace
{

void PrintHelp()
{
    std::cerr <<
        "x64dbg-mcp: MCP server for the x64dbg debugger (stdio transport)\n"
        "Usage: x64dbg-mcp [--log-level <error|warn|info|debug>] [--pipe <name>] [--help]\n"
        "  --log-level <level>  minimum log level written to stderr (default: info)\n"
        "  --pipe <name>         named pipe of the x64dbg-mcp plugin to connect to\n"
        "                        (default: " << x64dbg_mcp::ipc::kDefaultPipeName << ")\n"
        "                        use this when multiple x64dbg instances are running\n"
        "                        and the plugin picked a name suffixed with its process id\n"
        "  --help                show this help message and exit\n";
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
    // Any exception must be caught here: this is the process entry point,
    // and letting it fall through would mean the server crashing.
    try
    {
        LogLevel level = LogLevel::Info;
        std::string pipeName = x64dbg_mcp::ipc::kDefaultPipeName;

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
                    std::cerr << "--log-level requires a value\n";
                    return 1;
                }
                const std::string value = argv[++i];
                if (!ParseLogLevel(value, level))
                {
                    std::cerr << "Unknown log level: " << value << "\n";
                    return 1;
                }
            }
            else if (arg == "--pipe")
            {
                if (i + 1 >= argc)
                {
                    std::cerr << "--pipe requires a value\n";
                    return 1;
                }
                pipeName = argv[++i];
            }
            else
            {
                std::cerr << "Unknown argument: " << arg << "\n";
                return 1;
            }
        }

        SetLogLevel(level);

        auto link = std::make_shared<PluginLink>(pipeName);
        McpServer server(CreateDefaultRegistry(link), CreateDefaultResourceRegistry(link));
        RunStdioLoop(server);
        return 0;
    }
    catch (const std::exception& e)
    {
        Log(LogLevel::Error, std::string("Unhandled exception: ") + e.what());
        return 1;
    }
    catch (...)
    {
        Log(LogLevel::Error, "Unhandled exception of unknown type");
        return 1;
    }
}
