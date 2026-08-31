#include "plugin.h"
#include "plugin/service.h"

// Plugin initialization: log the load and start the MCP service.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
#ifdef _WIN64
    const char* arch = "x64";
#else
    const char* arch = "x86";
#endif
    dprintf("plugin loaded (version %s, %s)\n", PLUGIN_VERSION_STR, arch);

    // A failed service start must not block the plugin from loading — a plugin
    // without a working server is still better than failing the whole load.
    if (x64dbg_mcp::plugin::McpService::Instance().Start())
    {
        x64dbg_mcp::plugin::RegisterDebugCallbacks(initStruct->pluginHandle);
        dprintf("MCP service listening on pipe \"%s\"\n", x64dbg_mcp::plugin::McpService::Instance().PipeName().c_str());
    }
    else
    {
        dputs("failed to start the MCP service, plugin will run without it");
    }

    return true;
}

// GUI setup. Runs on the GUI thread.
void pluginSetup()
{
    dputs("plugin setup done");
}

// Plugin unload. Does NOT run on the GUI thread — here we need to wait for
// the plugin's worker threads to stop.
void pluginStop()
{
    x64dbg_mcp::plugin::UnregisterDebugCallbacks(pluginHandle);
    x64dbg_mcp::plugin::McpService::Instance().Stop();
    dputs("plugin unloading");
}
