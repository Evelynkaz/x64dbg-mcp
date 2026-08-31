#include "plugin.h"
#include "plugin/service.h"

// Инициализация плагина: журналирование факта загрузки и запуск сервиса MCP.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
#ifdef _WIN64
    const char* arch = "x64";
#else
    const char* arch = "x86";
#endif
    dprintf("plugin loaded (version %s, %s)\n", PLUGIN_VERSION_STR, arch);

    // Неудачный запуск сервиса не должен мешать загрузке плагина — плагин
    // без работающего сервера всё же лучше, чем отказ загрузки целиком.
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

// Настройка GUI. Выполняется в потоке GUI.
void pluginSetup()
{
    dputs("plugin setup done");
}

// Выгрузка плагина. Выполняется НЕ в потоке GUI — здесь нужно дождаться
// остановки рабочих потоков плагина.
void pluginStop()
{
    x64dbg_mcp::plugin::UnregisterDebugCallbacks(pluginHandle);
    x64dbg_mcp::plugin::McpService::Instance().Stop();
    dputs("plugin unloading");
}
