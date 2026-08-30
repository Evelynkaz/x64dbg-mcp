#pragma once

// Plugin information
#ifndef PLUGIN_NAME
#error You need to define PLUGIN_NAME
#endif // PLUGIN_NAME

#ifndef PLUGIN_VERSION
#error You need to define PLUGIN_VERSION
#endif // PLUGIN_VERSION

#ifndef PLUGIN_VERSION_STR
#error You need to define PLUGIN_VERSION_STR
#endif // PLUGIN_VERSION_STR

#include "pluginsdk/bridgemain.h"
#include "pluginsdk/_plugins.h"
#include "pluginsdk/_dbgfunctions.h"

#define dprintf(x, ...) _plugin_logprintf("[" PLUGIN_NAME "] " x, __VA_ARGS__)
#define dputs(x) _plugin_logprintf("[" PLUGIN_NAME "] %s\n", x)
#define PLUG_EXPORT extern "C" __declspec(dllexport)

// Global variables required by some of the _plugin_xxx functions
extern int pluginHandle;
extern HWND hwndDlg;
extern int hMenu;
extern int hMenuDisasm;
extern int hMenuDump;
extern int hMenuStack;
extern int hMenuGraph;
extern int hMenuMemmap;
extern int hMenuSymmod;
