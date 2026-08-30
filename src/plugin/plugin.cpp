#include "plugin.h"

// Инициализация плагина: пока только журналирование факта загрузки.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
#ifdef _WIN64
    const char* arch = "x64";
#else
    const char* arch = "x86";
#endif
    dprintf("plugin loaded (version %s, %s)\n", PLUGIN_VERSION_STR, arch);
    return true;
}

// Настройка GUI. Выполняется в потоке GUI.
void pluginSetup()
{
    dputs("plugin setup done");
}

// Выгрузка плагина. Выполняется НЕ в потоке GUI — в будущем здесь нужно
// будет дождаться остановки рабочих потоков плагина.
void pluginStop()
{
    dputs("plugin unloading");
}
