# Заметка: проверенные сигнатуры x64dbg Plugin SDK

Источник: SDK из релиза x64dbg `2026.05.27` (ассет `x64dbg-pluginsdk-cmake.zip`) и клон `https://github.com/x64dbg/x64dbg` (ветка development). `PLUG_SDKVERSION == 1` (из `_plugins.h`).

## Точка входа плагина

Плагин экспортирует функции инициализации/настройки/выгрузки, структуры описаны в `_plugins.h`:

```c
typedef struct { int pluginHandle; int sdkVersion; int pluginVersion; char pluginName[256]; } PLUG_INITSTRUCT;
typedef struct { HWND hwndDlg; int hMenu; int hMenuDisasm; int hMenuDump; int hMenuStack; int hMenuGraph; int hMenuMemmap; int hMenuSymmod; } PLUG_SETUPSTRUCT;
```

`_plugins.h` форсирует выравнивание структур: `#pragma pack(push, 16)` на x64 и `#pragma pack(push, 8)` на x86.

## Регистрация и логирование (из _plugins.h)

```c
void _plugin_registercallback(int pluginHandle, CBTYPE cbType, CBPLUGIN cbPlugin);
bool _plugin_unregistercallback(int pluginHandle, CBTYPE cbType);
bool _plugin_registercommand(int pluginHandle, const char* command, CBPLUGINCOMMAND cbCommand, bool debugonly);
bool _plugin_unregistercommand(int pluginHandle, const char* command);
void _plugin_logprintf(const char* format, ...);
void _plugin_logputs(const char* text);
void _plugin_debugpause();
bool _plugin_waituntilpaused();
```

## ВАЖНО: почему _plugin_waituntilpaused() нельзя звать из своего потока

Реальная реализация (файл `src/dbg/_plugins.cpp`):

```c
PLUG_IMPEXP bool _plugin_waituntilpaused()
{
    while(bIsDebugging && dbgisrunning()) //wait until the debugger paused
    {
        Sleep(1);
        GuiProcessEvents(); //workaround for scripts being executed on the GUI thread
    }
    return DbgIsDebugging();
}
```

Вывод, который надо зафиксировать: функция крутит цикл с `GuiProcessEvents()` и рассчитана на вызов из потока скриптов/GUI. Вызывать её из произвольного рабочего потока плагина нельзя. Кроме того, у неё нет таймаута — она может висеть вечно. Поэтому ожидание паузы реализуется своими средствами: подписка на коллбэки состояния плюс событие с таймаутом.

## Коллбэки состояния отладки (enum CBTYPE из _plugins.h)

`CB_INITDEBUG` (PLUG_CB_INITDEBUG), `CB_STOPDEBUG` (PLUG_CB_STOPDEBUG), `CB_STOPPINGDEBUG`, `CB_CREATEPROCESS` (PLUG_CB_CREATEPROCESS), `CB_EXITPROCESS`, `CB_CREATETHREAD`, `CB_EXITTHREAD`, `CB_SYSTEMBREAKPOINT`, `CB_LOADDLL`, `CB_UNLOADDLL`, `CB_EXCEPTION`, `CB_BREAKPOINT` (PLUG_CB_BREAKPOINT, поле `BRIDGEBP* breakpoint`), `CB_PAUSEDEBUG`, `CB_RESUMEDEBUG`, `CB_STEPPED`, `CB_ATTACH`, `CB_DETACH`, `CB_DEBUGEVENT`.

Именно `CB_PAUSEDEBUG`, `CB_RESUMEDEBUG`, `CB_STEPPED`, `CB_BREAKPOINT`, `CB_INITDEBUG`, `CB_STOPDEBUG`, `CB_CREATEPROCESS`, `CB_EXITPROCESS` используются для отслеживания состояния.

## Выполнение команд (из bridgemain.h)

```c
bool DbgCmdExec(const char* cmd);        // асинхронно
bool DbgCmdExecDirect(const char* cmd);  // синхронно, в вызывающем потоке
```

Проверенная семантика:
- `DbgCmdExec` реализован как `MsgSend(gMsgQueue, 0, (duint)newcmd, 0)` (файл `src/dbg/x64dbg.cpp`) — команда ставится в штатную очередь и исполняется командным потоком x64dbg. Возвращаемое значение говорит лишь о постановке в очередь, не о результате команды.
- `DbgCmdExecDirect` вызывает `cmddirectexec(cmd)` (файл `src/dbg/command.cpp`) — команда разбирается и исполняется синхронно в потоке вызывающего; возвращает результат выполнения.

Вывод для проекта: команды, меняющие состояние выполнения (run, step, stop), отправляются через `DbgCmdExec`, а факт остановки ожидается через собственное событие; `DbgCmdExecDirect` применяется там, где нужен немедленный результат и команда не переводит отладчик в состояние выполнения.

## Состояние и осмотр (bridgemain.h)

```c
bool DbgIsDebugging();
bool DbgIsRunning();
bool DbgIsRunLocked();
DWORD DbgGetProcessId();
DWORD DbgGetThreadId();
HANDLE DbgGetProcessHandle();
HANDLE DbgGetThreadHandle();
duint DbgGetPebAddress(DWORD ProcessId);
duint DbgGetTebAddress(DWORD ThreadId);
DEBUG_ENGINE DbgGetDebugEngine();
void DbgGetThreadList(THREADLIST* list);
bool DbgGetRegDumpEx(REGDUMP_AVX512* regdump, size_t size);
```

## Память (bridgemain.h)

```c
bool DbgMemRead(duint va, void* dest, duint size);
bool DbgMemWrite(duint va, const void* src, duint size);
bool DbgMemIsValidReadPtr(duint addr);
duint DbgMemGetPageSize(duint base);
duint DbgMemFindBaseAddr(duint addr, duint* size);
bool DbgMemMap(MEMMAP* memmap);
```

Структуры:

```c
typedef struct { MEMORY_BASIC_INFORMATION mbi; char info[MAX_MODULE_SIZE]; } MEMPAGE;
typedef struct { int count; MEMPAGE* page; } MEMMAP;
```

## Выражения, символы, дизассемблирование (bridgemain.h)

```c
duint DbgValFromString(const char* string);
bool DbgIsValidExpression(const char* expression);
duint DbgEval(const char* expression, bool* success);
bool DbgGetLabelAt(duint addr, SEGMENTREG segment, char* text);
bool DbgSetLabelAt(duint addr, const char* text);
bool DbgGetCommentAt(duint addr, char* text);
bool DbgSetCommentAt(duint addr, const char* text);
bool DbgGetModuleAt(duint addr, char* text);
bool DbgGetStringAt(duint addr, char* text);
duint DbgModBaseFromName(const char* name);
void DbgDisasmAt(duint addr, DISASM_INSTR* instr);
void DbgDisasmFastAt(duint addr, BASIC_INSTRUCTION_INFO* basicinfo);
bool DbgAssembleAt(duint addr, const char* instruction);
bool DbgFunctionGet(duint addr, duint* start, duint* end);
bool DbgSymbolEnum(duint base, CBSYMBOLENUM cbSymbolEnum, void* user);
bool DbgGetSymbolInfoAt(duint addr, SYMBOLINFO* info);
void DbgGetSymbolInfo(const SYMBOLPTR* symbolptr, SYMBOLINFO* info);
bool DbgXrefGet(duint addr, XREF_INFO* info);
size_t DbgGetXrefCountAt(duint addr);
```

## Точки останова (bridgemain.h)

```c
BPXTYPE DbgGetBpxTypeAt(duint addr);
int DbgGetBpList(BPXTYPE type, BPMAP* list);
bool DbgIsBpDisabled(duint addr);
```

`BPXTYPE` — битовая маска, поэтому в `DbgGetBpList` значения можно комбинировать:

```c
typedef enum
{
    bp_none = 0,
    bp_normal = 1,
    bp_hardware = 2,
    bp_memory = 4,
    bp_dll = 8,
    bp_exception = 16
} BPXTYPE;
```

## DbgFunctions() — расширенные возможности (_dbgfunctions.h)

```c
const DBGFUNCTIONS* DbgFunctions();
```

Поля структуры `DBGFUNCTIONS`, которые планируем использовать (указатели на функции):

```c
bool (*AssembleAtEx)(duint addr, const char* instruction, char* error, bool fillnop);
bool (*Assemble)(duint addr, unsigned char* dest, int* size, const char* instruction, char* error);
bool (*SectionFromAddr)(duint addr, char* section);
bool (*ModNameFromAddr)(duint addr, char* modname, bool extension);
duint (*ModBaseFromAddr)(duint addr);
duint (*ModSizeFromAddr)(duint addr);
int (*ModPathFromAddr)(duint addr, char* path, int size);
bool (*MemPatch)(duint va, const unsigned char* src, duint size);
bool (*PatchGetEx)(duint addr, DBGPATCHINFO* info);
bool (*PatchEnum)(DBGPATCHINFO* patchlist, size_t* cbsize);
bool (*PatchRestore)(duint addr);
void (*PatchRestoreRange)(duint start, duint end);
int (*PatchFile)(DBGPATCHINFO* patchlist, int count, const char* szFileName, char* error);
void (*MemUpdateMap)();
void (*GetCallStack)(DBGCALLSTACK* callstack);
void (*GetCallStackEx)(DBGCALLSTACK* callstack, bool cache);
void (*GetCallStackByThread)(HANDLE thread, DBGCALLSTACK* callstack);
void (*GetSEHChain)(DBGSEHCHAIN* sehchain);
bool (*GetPageRights)(duint addr, char* rights);
bool (*SetPageRights)(duint addr, const char* rights);
bool (*PageRightsToString)(DWORD protect, char* rights);
bool (*ValFromString)(const char* string, duint* value);
bool (*GetBridgeBp)(BPXTYPE type, duint addr, BRIDGEBP* bp);
bool (*ThreadGetName)(DWORD tid, char* name);
duint (*FileOffsetToVa)(const char* modname, duint offset);
duint (*VaToFileOffset)(duint va);
bool (*GetCmdline)(char* cmdline, size_t* cbsize);
void (*RefreshModuleList)();
```

Современный API точек останова через ссылки:

```c
BP_REF* (*BpRefList)(duint* count);
bool (*BpRefVa)(BP_REF* ref, BPXTYPE type, duint va);
bool (*BpRefRva)(BP_REF* ref, BPXTYPE type, const char* module, duint rva);
bool (*BpRefExists)(const BP_REF* ref);
bool (*BpGetFieldNumber)(const BP_REF* ref, BP_FIELD field, duint* value);
bool (*BpSetFieldNumber)(const BP_REF* ref, BP_FIELD field, duint value);
bool (*BpGetFieldText)(const BP_REF* ref, BP_FIELD field, CBSTRING callback, void* userdata);
bool (*BpSetFieldText)(const BP_REF* ref, BP_FIELD field, const char* value);
```

Перечисление `BP_FIELD`: `bpf_type`, `bpf_offset`, `bpf_address`, `bpf_enabled`, `bpf_singleshoot`, `bpf_active`, `bpf_silent`, `bpf_typeex`, `bpf_hwsize`, `bpf_hwslot`, `bpf_oldbytes`, `bpf_fastresume`, `bpf_hitcount`, `bpf_module`, `bpf_name`, `bpf_breakcondition`, `bpf_logtext`, `bpf_logcondition`, `bpf_commandtext`, `bpf_commandcondition`, `bpf_logfile`.

Структура:

```c
struct BP_REF { BPXTYPE type; duint module; duint offset; };
```

Комментарий из заголовка: список `DBGFUNCTIONS` только дополняется в конец, вставлять в середину нельзя — иначе плагины ломаются.

## Script API (пространство имён Script)

`_scriptapi_module.h`: `Script::Module::GetList(ListOf(ModuleInfo) list)`, `InfoFromAddr`, `InfoFromName`, `SectionListFromAddr`, `SectionListFromName`, `GetExports(const ModuleInfo* mod, ListOf(ModuleExport) list)`, `GetImports(const ModuleInfo* mod, ListOf(ModuleImport) list)`, `GetMainModuleInfo`. Со структурами `ModuleInfo { duint base; duint size; duint entry; int sectionCount; char name[MAX_MODULE_SIZE]; char path[MAX_PATH]; }`, `ModuleSectionInfo`, `ModuleExport`, `ModuleImport`. Вызывающая сторона обязана освободить список.

`_scriptapi_memory.h`: `Script::Memory::Read(duint addr, void* data, duint size, duint* sizeRead)`, `Write`, `IsValidPtr`, `GetProtect`, `SetProtect`, `GetBase`, `GetSize`, `RemoteAlloc`, `RemoteFree`.

`_scriptapi_pattern.h`: `Script::Pattern::FindMem(duint start, duint size, const char* pattern)`, `Find`, `WriteMem`, `SearchAndReplaceMem`.

`_scriptapi_register.h`: `Script::Register::Get(RegisterEnum reg)`, `Set(RegisterEnum reg, duint value)`, `Size()`, а также именованные `GetCIP/SetCIP`, `GetCSP/SetCSP`, `GetCFLAGS/SetCFLAGS`.

`_scriptapi_assembler.h`: `Script::Assembler::AssembleMemEx(duint addr, const char* instruction, int* size, char* error, bool fillnop)`, `AssembleEx(duint addr, unsigned char* dest, int* size, const char* instruction, char* error)`. Буфер `dest` размером 16 байт, `error` размером `MAX_ERROR_SIZE`.

`_scriptapi_misc.h`: `Script::Misc::ParseExpression(const char* expression, duint* value)`, `RemoteGetProcAddress(const char* module, const char* api)`, `ResolveLabel(const char* label)`.

`_scriptapi_stack.h`: `Script::Stack::Peek(int offset)`, `Push`, `Pop`. Offset задаётся в кратных `Register::Size()`.

## ПРЕДУПРЕЖДЕНИЕ: Script::Debug вызывает Wait()

Проверенный факт из `src/dbg/_scriptapi_debug.cpp`: функции `Script::Debug::Run/Pause/Stop/StepIn/StepOver/StepOut` реализованы как `DbgCmdExecDirect(команда)` с последующим вызовом `Wait()`, а `Wait()` — это `_plugin_waituntilpaused()`. Следовательно, их использовать в проекте нельзя по той же причине, что и `_plugin_waituntilpaused`: цикл с `GuiProcessEvents()` и без таймаута. Вместо них — `DbgCmdExec` плюс собственное ожидание.

```c
SCRIPT_EXPORT void Script::Debug::Run()
{
    if(DbgCmdExecDirect("run"))
        Wait();
}
```

Команды, которые эти обёртки шлют, поскольку мы будем слать те же команды напрямую: `run`, `pause`, `StopDebug`, `StepInto`, `StepOver`, `StepOut`, `bp <адрес>`, `bc <адрес>`, `bd <адрес>`, `bphws <адрес>, <rw|w|x>`, `bphwc <адрес>`.

## GUI-поток и лог

```c
void GuiExecuteOnGuiThread(GUICALLBACK cbGuiThread);
void GuiExecuteOnGuiThreadEx(GUICALLBACKEX cbGuiThread, void* userdata);
DWORD GuiGetMainThreadId();
void GuiLogRedirect(const char* filename);
void GuiLogRedirectStop();
void GuiLogSave(const char* filename);
void GuiAddLogMessage(const char* msg);
bool GuiGetDisassembly(duint addr, char* text);
void GuiUpdateAllViews();
void GuiUpdateDisassemblyView();
void GuiUpdateRegisterView();
void GuiUpdateBreakpointsView();
```

Проверенный факт о захвате лога: в `src/gui/Src/Gui/LogView.cpp` при активном перенаправлении сообщение записывается в файл и при этом продолжает попадать в окно лога (переменная `msgUtf16` заполняется, если логирование включено). То есть `GuiLogRedirect` работает как ответвление копии, а не как замена вывода. Ограничение: слот перенаправления один, поэтому если его занимает плагин, пользователь не сможет пользоваться перенаправлением лога сам — захват лога должен быть отключаемым в конфигурации.

## Что ещё требуется проверить перед реализацией

- Синхронность `_gui_sendmessage`, через который реализованы `GuiLogSave` и `GuiLogRedirect`.
- Какие именно `Dbg*`-функции безопасны при вызове из произвольного потока, а какие требуют, чтобы отладчик был в состоянии паузы.
- Точный размер и раскладка `REGDUMP_AVX512` в текущей версии SDK, а также поведение `DbgGetRegDumpEx` при несовпадении размера.
- Поведение перечисленных функций, когда отладка не запущена.
