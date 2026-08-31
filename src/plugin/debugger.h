#pragma once

// The only place in the project allowed to call the x64dbg API (headers
// under external/sdk/cmake-sdk/pluginsdk/). These calls must not be made
// anywhere else in the project — and that must stay true.
//
// IMPORTANT: none of the functions in this file may be called from anywhere
// other than the DebuggerWorker worker thread. The x64dbg API itself is not
// designed to be called from an arbitrary thread (see
// docs/notes/x64dbg-api.md), and serializing through the single worker
// thread is the only guard against this class of races.

#include "nlohmann/json.hpp"

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace x64dbg_mcp::plugin
{

// Upper limit on the number of bytes per ReadMemory call. Bounds how much
// memory a single bridge client can request at once.
constexpr size_t kMaxReadSize = 1024ull * 1024ull; // 1 MiB

// Upper limit on the number of instructions per Disassemble call.
constexpr size_t kMaxInstructions = 256;

// Debugger state. Populated even when debugging is not active.
struct DebuggerStatus
{
    bool debugging = false;
    bool running = false;          // the process is executing (otherwise paused)
    unsigned int processId = 0;
    unsigned int threadId = 0;
    int pointerSize = 0;           // 4 or 8
    unsigned long long cip = 0;    // current instruction pointer, 0 if unavailable
    std::string module;            // module containing cip, empty if unavailable
};

// Returns the debugger state. Never throws.
DebuggerStatus GetStatus();

// Reads memory. Returns false if debugging is not active or the address is
// unreadable; error is filled with an English explanation of the reason.
bool ReadMemory(unsigned long long address, size_t size, std::vector<unsigned char>& out, std::string& error);

// A single disassembled instruction.
struct Instruction
{
    unsigned long long address = 0;
    size_t size = 0;
    std::string text;              // mnemonic with operands
    std::vector<unsigned char> bytes;
};

// Disassembles count instructions starting at address.
bool Disassemble(unsigned long long address, size_t count, std::vector<Instruction>& out, std::string& error);

// Default timeout for operations that wait for a debugger pause, and its upper limit.
constexpr int kDefaultControlTimeoutMs = 10000;
constexpr int kMaxControlTimeoutMs = 300000;

// Result of an operation that changes execution state.
struct ControlResult
{
    bool paused = false;        // whether the process stopped within the allotted time
    bool timedOut = false;      // whether the wait timed out
    DebuggerStatus status;      // state AFTER the operation
    std::string pauseReason;    // pause reason: breakpoint, step, pause, initial, exception, unknown
};

// action: run | pause | stop | restart | run_to
bool Control(const std::string& action, unsigned long long address, bool hasAddress,
             bool wait, int timeoutMs, ControlResult& out, std::string& error);

// mode: into | over | out
bool Step(const std::string& mode, int count, bool wait, int timeoutMs,
          ControlResult& out, std::string& error);

// Waits for a stop without sending a command.
bool WaitUntilPaused(int timeoutMs, ControlResult& out, std::string& error);

// Information about one existing breakpoint.
struct BreakpointInfo
{
    unsigned long long address = 0;
    std::string type;        // software | hardware | memory | dll | exception
    bool enabled = false;
    bool singleShot = false;
    unsigned int hitCount = 0;
    std::string module;
    std::string name;
};

// Sets a breakpoint from the description in params (see debugger.cpp for the
// list of accepted fields). Returns false with a clear error if any of the
// commands was rejected by x64dbg.
bool SetBreakpoint(const nlohmann::json& params, std::string& error);

// action: delete | enable | disable
bool ManageBreakpoint(const std::string& action, unsigned long long address, std::string& error);

// Lists all existing breakpoints of every type.
bool ListBreakpoints(std::vector<BreakpointInfo>& out, std::string& error);

// Upper limits on the number of exports and imports returned by a single
// GetModuleDetails call: large system modules (e.g. ntdll.dll) have counts
// in the thousands, and a full list would flood the model's context.
constexpr size_t kMaxExports = 4096;
constexpr size_t kMaxImports = 4096;

// Information about a loaded module.
struct ModuleEntry
{
    unsigned long long base = 0, size = 0, entry = 0;
    int sectionCount = 0;
    std::string name, path;
};

// Lists all loaded modules.
bool ListModules(std::vector<ModuleEntry>& out, std::string& error);

struct SectionEntry { unsigned long long address = 0, size = 0; std::string name; };
struct ExportEntry { unsigned long long ordinal = 0, rva = 0, va = 0; bool forwarded = false; std::string name, forwardName; };
struct ImportEntry { unsigned long long iatRva = 0, iatVa = 0, ordinal = 0; std::string name; };

// Detailed information about one module: sections and, optionally, exports/imports.
struct ModuleDetails
{
    ModuleEntry module;
    std::vector<SectionEntry> sections;
    std::vector<ExportEntry> exports;
    std::vector<ImportEntry> imports;
    bool exportsTruncated = false, importsTruncated = false;
};

// The module is identified EITHER by name (byAddress == false) OR by an
// address inside it (byAddress == true).
bool GetModuleDetails(const std::string& name, unsigned long long address, bool byAddress,
                      bool includeExports, bool includeImports,
                      ModuleDetails& out, std::string& error);

// A single memory page from the debuggee's memory map.
struct MemoryRegion
{
    unsigned long long base = 0, allocationBase = 0, size = 0;
    std::string state, type, protect, info;
};

// The debuggee's memory map.
bool GetMemoryMap(std::vector<MemoryRegion>& out, std::string& error);

// Information about one thread of the debuggee.
struct ThreadEntry
{
    unsigned int id = 0;
    int number = 0;
    unsigned long long entry = 0, teb = 0, cip = 0;
    unsigned int suspendCount = 0, lastError = 0;
    std::string name, priority, waitReason;
    bool current = false;
};

// Lists all threads of the debuggee.
bool ListThreads(std::vector<ThreadEntry>& out, std::string& error);

// The value of a single register.
struct RegisterValue { std::string name; unsigned long long value = 0; };

// A register snapshot of the current thread.
struct RegisterDump
{
    std::vector<RegisterValue> general;   // general-purpose, including the instruction and stack pointers
    std::vector<RegisterValue> segment;   // segment registers
    std::vector<RegisterValue> debugRegs; // debug registers
    unsigned long long eflags = 0;
    std::vector<std::pair<std::string, bool>> flags; // decoded flags
    std::vector<std::pair<std::string, std::string>> simd; // name and hex value, if requested
    unsigned int lastError = 0;
    unsigned int lastStatus = 0;
};

// Reads registers. includeSimd adds the XMM registers to the output.
// Requires active debugging and a pause: while the process is running,
// register values are not fixed, and DbgGetRegDumpEx would return an
// arbitrary/stale snapshot, same as cip in GetStatus.
bool ReadRegisters(bool includeSimd, RegisterDump& out, std::string& error);

// A single call stack frame.
struct CallStackFrame
{
    unsigned long long address = 0; // address of the stack slot holding the return address
    unsigned long long from = 0;    // where the call was made from
    unsigned long long to = 0;      // where the call went to
    std::string comment;
};

// The call stack of thread threadId. threadId == 0 means the current thread.
// Requires active debugging and a pause.
bool GetCallStack(unsigned int threadId, std::vector<CallStackFrame>& out, std::string& error);

// A single machine-word stack element (slot).
struct StackSlot
{
    unsigned long long address = 0;
    unsigned long long value = 0;
    std::string comment;
};

// Limits on the number of stack slots read by a single ReadStack call.
constexpr size_t kMinStackSlots = 1;
constexpr size_t kMaxStackSlots = 256;
constexpr size_t kDefaultStackSlots = 16;

// Reads count machine words of stack starting at the current stack pointer.
// Requires active debugging and a pause.
bool ReadStack(size_t count, std::vector<StackSlot>& out, std::string& error);

// The string at an address, as recognized by the debugger. Requires active
// debugging and a pause.
bool ReadStringAt(unsigned long long address, std::string& out, std::string& error);

// Result of evaluating an x64dbg expression.
struct EvalResult
{
    unsigned long long value = 0;
    bool pointerValid = false;   // whether the value points to readable memory
};

// Evaluates an expression. Requires active debugging.
bool EvaluateExpression(const std::string& expression, EvalResult& out, std::string& error);

// Upper limits for pattern search: bound the number of matches returned by a
// single call and the amount of memory scanned — both parameters come
// straight from the bridge client and without limits could trigger a
// multi-minute search or a huge response.
constexpr size_t kMaxPatternResults = 256;
constexpr unsigned long long kMaxPatternRangeSize = 256ull * 1024ull * 1024ull; // 256 MiB

// Searches for a byte pattern in the range [start, start + size). maxResults
// caps the output. Requires active debugging and a pause.
bool FindPattern(unsigned long long start, unsigned long long size, const std::string& pattern,
                 size_t maxResults, std::vector<unsigned long long>& out, bool& truncated, std::string& error);

// A single cross-reference to an address.
struct XrefEntry { unsigned long long address = 0; std::string type; };

// Cross-references to an address. Requires active debugging and a pause.
bool GetXrefs(unsigned long long address, std::vector<XrefEntry>& out, std::string& error);

// Boundaries of the function containing an address. Requires active debugging.
bool GetFunctionRange(unsigned long long address, unsigned long long& start, unsigned long long& end, std::string& error);

} // namespace x64dbg_mcp::plugin
