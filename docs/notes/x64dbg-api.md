# Note: verified x64dbg Plugin SDK signatures

Source: SDK from x64dbg release `2026.05.27` (asset `x64dbg-pluginsdk-cmake.zip`) and a clone of `https://github.com/x64dbg/x64dbg` (development branch). `PLUG_SDKVERSION == 1` (from `_plugins.h`).

## Plugin entry point

The plugin exports init/setup/unload functions; the structures are described in `_plugins.h`:

```c
typedef struct { int pluginHandle; int sdkVersion; int pluginVersion; char pluginName[256]; } PLUG_INITSTRUCT;
typedef struct { HWND hwndDlg; int hMenu; int hMenuDisasm; int hMenuDump; int hMenuStack; int hMenuGraph; int hMenuMemmap; int hMenuSymmod; } PLUG_SETUPSTRUCT;
```

`_plugins.h` forces structure alignment: `#pragma pack(push, 16)` on x64 and `#pragma pack(push, 8)` on x86.

## Registration and logging (from _plugins.h)

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

## IMPORTANT: why _plugin_waituntilpaused() must not be called from our own thread

The actual implementation (file `src/dbg/_plugins.cpp`):

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

The takeaway to record: this function spins a loop with `GuiProcessEvents()` and is meant to run on the script/GUI thread. It must not be called from an arbitrary plugin worker thread. On top of that, it has no timeout: it can hang forever. So waiting for a pause has to be implemented ourselves, using state-change callbacks plus an event with a timeout.

## Debug state callbacks (enum CBTYPE from _plugins.h)

`CB_INITDEBUG` (PLUG_CB_INITDEBUG), `CB_STOPDEBUG` (PLUG_CB_STOPDEBUG), `CB_STOPPINGDEBUG`, `CB_CREATEPROCESS` (PLUG_CB_CREATEPROCESS), `CB_EXITPROCESS`, `CB_CREATETHREAD`, `CB_EXITTHREAD`, `CB_SYSTEMBREAKPOINT`, `CB_LOADDLL`, `CB_UNLOADDLL`, `CB_EXCEPTION`, `CB_BREAKPOINT` (PLUG_CB_BREAKPOINT, field `BRIDGEBP* breakpoint`), `CB_PAUSEDEBUG`, `CB_RESUMEDEBUG`, `CB_STEPPED`, `CB_ATTACH`, `CB_DETACH`, `CB_DEBUGEVENT`.

`CB_PAUSEDEBUG`, `CB_RESUMEDEBUG`, `CB_STEPPED`, `CB_BREAKPOINT`, `CB_INITDEBUG`, `CB_STOPDEBUG`, `CB_CREATEPROCESS`, `CB_EXITPROCESS` are the ones actually used for state tracking.

## Executing commands (from bridgemain.h)

```c
bool DbgCmdExec(const char* cmd);        // asynchronous
bool DbgCmdExecDirect(const char* cmd);  // synchronous, on the calling thread
```

Verified semantics:
- `DbgCmdExec` is implemented as `MsgSend(gMsgQueue, 0, (duint)newcmd, 0)` (file `src/dbg/x64dbg.cpp`): the command is placed on x64dbg's regular queue and executed by the command thread. The return value only indicates that it was queued, not the command's result.
- `DbgCmdExecDirect` calls `cmddirectexec(cmd)` (file `src/dbg/command.cpp`): the command is parsed and executed synchronously on the calling thread; it returns the execution result.

Conclusion for the project: commands that change the execution state (run, step, stop) are sent through `DbgCmdExec`, and the actual halt is awaited via our own event; `DbgCmdExecDirect` is used where an immediate result is needed and the command does not put the debugger into a running state.

## State and inspection (bridgemain.h)

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

## Memory (bridgemain.h)

```c
bool DbgMemRead(duint va, void* dest, duint size);
bool DbgMemWrite(duint va, const void* src, duint size);
bool DbgMemIsValidReadPtr(duint addr);
duint DbgMemGetPageSize(duint base);
duint DbgMemFindBaseAddr(duint addr, duint* size);
bool DbgMemMap(MEMMAP* memmap);
```

Structures:

```c
typedef struct { MEMORY_BASIC_INFORMATION mbi; char info[MAX_MODULE_SIZE]; } MEMPAGE;
typedef struct { int count; MEMPAGE* page; } MEMMAP;
```

## Expressions, symbols, disassembly (bridgemain.h)

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

## Breakpoints (bridgemain.h)

```c
BPXTYPE DbgGetBpxTypeAt(duint addr);
int DbgGetBpList(BPXTYPE type, BPMAP* list);
bool DbgIsBpDisabled(duint addr);
```

`BPXTYPE` is a bitmask, so values can be combined in `DbgGetBpList`:

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

## DbgFunctions() -- extended capabilities (_dbgfunctions.h)

```c
const DBGFUNCTIONS* DbgFunctions();
```

Fields of the `DBGFUNCTIONS` struct we plan to use (function pointers):

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

The modern reference-based breakpoint API:

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

The `BP_FIELD` enum: `bpf_type`, `bpf_offset`, `bpf_address`, `bpf_enabled`, `bpf_singleshoot`, `bpf_active`, `bpf_silent`, `bpf_typeex`, `bpf_hwsize`, `bpf_hwslot`, `bpf_oldbytes`, `bpf_fastresume`, `bpf_hitcount`, `bpf_module`, `bpf_name`, `bpf_breakcondition`, `bpf_logtext`, `bpf_logcondition`, `bpf_commandtext`, `bpf_commandcondition`, `bpf_logfile`.

Structure:

```c
struct BP_REF { BPXTYPE type; duint module; duint offset; };
```

Comment from the header: the `DBGFUNCTIONS` list is append-only; nothing may be inserted in the middle, or existing plugins break.

## Script API (namespace Script)

`_scriptapi_module.h`: `Script::Module::GetList(ListOf(ModuleInfo) list)`, `InfoFromAddr`, `InfoFromName`, `SectionListFromAddr`, `SectionListFromName`, `GetExports(const ModuleInfo* mod, ListOf(ModuleExport) list)`, `GetImports(const ModuleInfo* mod, ListOf(ModuleImport) list)`, `GetMainModuleInfo`. With structures `ModuleInfo { duint base; duint size; duint entry; int sectionCount; char name[MAX_MODULE_SIZE]; char path[MAX_PATH]; }`, `ModuleSectionInfo`, `ModuleExport`, `ModuleImport`. The caller must free the list.

`_scriptapi_memory.h`: `Script::Memory::Read(duint addr, void* data, duint size, duint* sizeRead)`, `Write`, `IsValidPtr`, `GetProtect`, `SetProtect`, `GetBase`, `GetSize`, `RemoteAlloc`, `RemoteFree`.

`_scriptapi_pattern.h`: `Script::Pattern::FindMem(duint start, duint size, const char* pattern)`, `Find`, `WriteMem`, `SearchAndReplaceMem`.

`_scriptapi_register.h`: `Script::Register::Get(RegisterEnum reg)`, `Set(RegisterEnum reg, duint value)`, `Size()`, plus the named accessors `GetCIP/SetCIP`, `GetCSP/SetCSP`, `GetCFLAGS/SetCFLAGS`.

`_scriptapi_assembler.h`: `Script::Assembler::AssembleMemEx(duint addr, const char* instruction, int* size, char* error, bool fillnop)`, `AssembleEx(duint addr, unsigned char* dest, int* size, const char* instruction, char* error)`. The `dest` buffer is 16 bytes, `error` is `MAX_ERROR_SIZE`.

`_scriptapi_misc.h`: `Script::Misc::ParseExpression(const char* expression, duint* value)`, `RemoteGetProcAddress(const char* module, const char* api)`, `ResolveLabel(const char* label)`.

`_scriptapi_stack.h`: `Script::Stack::Peek(int offset)`, `Push`, `Pop`. The offset is given in multiples of `Register::Size()`.

## WARNING: Script::Debug calls Wait()

Verified fact from `src/dbg/_scriptapi_debug.cpp`: the functions `Script::Debug::Run/Pause/Stop/StepIn/StepOver/StepOut` are implemented as `DbgCmdExecDirect(command)` followed by a call to `Wait()`, and `Wait()` is `_plugin_waituntilpaused()`. As a result, they must not be used in this project for the same reason as `_plugin_waituntilpaused`: a loop driven by `GuiProcessEvents()` with no timeout. We use `DbgCmdExec` plus our own wait instead.

```c
SCRIPT_EXPORT void Script::Debug::Run()
{
    if(DbgCmdExecDirect("run"))
        Wait();
}
```

The commands these wrappers send, since we will be sending the same commands directly: `run`, `pause`, `StopDebug`, `StepInto`, `StepOver`, `StepOut`, `bp <address>`, `bc <address>`, `bd <address>`, `bphws <address>, <rw|w|x>`, `bphwc <address>`.

## GUI thread and log

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

Verified fact about log capture: in `src/gui/Src/Gui/LogView.cpp`, while redirection is active, a message is written to the file and still shows up in the log window (the `msgUtf16` variable is populated whenever logging is enabled). So `GuiLogRedirect` acts as a tee on the output rather than a replacement for it. Limitation: there is only one redirection slot, so if a plugin occupies it, the user loses access to log redirection for their own purposes; log capture must therefore be toggleable in the configuration.

## What still needs to be verified before implementation

- Whether `_gui_sendmessage`, which `GuiLogSave` and `GuiLogRedirect` are built on, is synchronous.
- Which `Dbg*` functions are actually safe to call from an arbitrary thread, and which require the debugger to be paused.
- The exact size and layout of `REGDUMP_AVX512` in the current SDK version, and how `DbgGetRegDumpEx` behaves on a size mismatch.
- How the functions listed above behave when debugging is not running.
