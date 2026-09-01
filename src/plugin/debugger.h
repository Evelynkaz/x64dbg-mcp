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
//
// EXCEPTION: StartLogCapture is a file and GUI-request operation, not a
// debugger-state query, and is called directly from the GUI thread (see
// McpService::EnableLogCapture) — see the comment there for why. Its shared
// state is protected by a mutex in debugger.cpp precisely because of this.

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

// Upper limit on the number of basic blocks returned by a single
// AnalyzeFunctionGraph call: a pathologically large or obfuscated function
// could otherwise produce an unbounded response.
constexpr size_t kMaxCfgBlocks = 4096;

// A single basic block of a function's control-flow graph.
struct CfgBlock
{
    unsigned long long start = 0;
    unsigned long long end = 0;          // inclusive address of the last instruction
    unsigned long long brTrue = 0;       // taken-branch target, 0 if none
    unsigned long long brFalse = 0;      // fall-through / not-taken target, 0 if none
    unsigned int instructionCount = 0;
    bool terminal = false;               // block ends in a return
    bool split = false;                  // brTrue is simply the next block
    bool indirectCall = false;           // block contains an indirect call
    std::vector<unsigned long long> exits;
};

// The control-flow graph of a function: its basic blocks and the branches
// between them.
struct FunctionGraph
{
    unsigned long long entryPoint = 0;
    std::vector<CfgBlock> blocks;
    bool truncated = false;
};

// Builds the control-flow graph of the function containing address. Requires
// active debugging. blocks is sorted by start address; truncated is set when
// kMaxCfgBlocks was reached.
bool AnalyzeFunctionGraph(unsigned long long address, FunctionGraph& out, std::string& error);

// Upper limit on the number of symbols returned by a single ListSymbols call:
// large system modules can have tens of thousands, and a full list would
// flood the model's context.
constexpr size_t kMaxSymbolResults = 4096;

// A single symbol (import, export, or debug symbol) of a module.
struct SymbolEntry
{
    unsigned long long address = 0;
    std::string name;            // undecorated when available, otherwise decorated
    std::string decoratedName;   // only when it differs from name
    std::string type;            // "import" | "export" | "symbol"
    unsigned int ordinal = 0;
};

// Enumerates symbols of the module containing moduleAddress. filter, when
// non-empty, keeps only symbols whose name contains it (case-insensitive).
// Requires active debugging; does not require a pause, since it reads the
// module's static symbol database rather than live process state.
bool ListSymbols(unsigned long long moduleAddress, const std::string& filter,
                 size_t maxResults, std::vector<SymbolEntry>& out, bool& truncated,
                 std::string& error);

// A label, comment, and bookmark at one address. Empty label/comment means
// none is set, which is a normal result, not an error.
struct Annotations
{
    std::string label;
    std::string comment;
    bool bookmark = false;
};

// Reads the label, comment, and bookmark at address. Requires active
// debugging; does not require a pause, for the same reason as ListSymbols.
bool GetAnnotations(unsigned long long address, Annotations& out, std::string& error);

// Sets the label at address. An empty text CLEARS the label — that is how
// x64dbg models removal (see LabelSet in external/x64dbg/src/dbg/label.cpp).
// Requires active debugging; does not require a pause: this only touches the
// label database, not memory or registers that could change mid-write while
// the process runs.
bool SetLabel(unsigned long long address, const std::string& text, std::string& error);

// Sets the comment at address. An empty text CLEARS the comment, same as
// SetLabel. Requires active debugging; does not require a pause, for the
// same reason as SetLabel.
bool SetComment(unsigned long long address, const std::string& text, std::string& error);

// Sets or clears the bookmark at address. Requires active debugging; does
// not require a pause, for the same reason as SetLabel.
bool SetBookmark(unsigned long long address, bool enabled, std::string& error);

// Upper limit on the number of lines returned by a single ReadLog call.
constexpr size_t kMaxLogLines = 1000;

// Result of running a command or a script.
struct CommandResult
{
    bool accepted = false;    // the debugger accepted the command
    std::string output;       // log text produced while the command ran
    bool logCaptured = false; // whether log capture is active at all
};

// Runs an arbitrary x64dbg command.
// When async is true the command is queued on the debugger's own command
// thread and the call returns immediately; otherwise it runs synchronously
// and its result is reported. Commands changing execution state (run,
// StepInto, ...) should be queued with async == true; the caller can wait
// for the resulting pause separately, e.g. via debug.wait.
bool ExecuteCommand(const std::string& command, bool async, CommandResult& out, std::string& error);

// Runs a script given as text. The text is written to a temporary file,
// loaded and executed. Script execution is asynchronous: the result reports
// that the script was started, along with whatever log output appeared
// before this call returned, not the script's full output.
bool RunScript(const std::string& scriptText, CommandResult& out, std::string& error);

// Returns the last lines of captured log output, capped at kMaxLogLines.
// truncated is set when more lines existed than were returned. Succeeds with
// an empty out even when capture is not active — that is a normal situation,
// not an error.
bool ReadLog(size_t maxLines, std::vector<std::string>& out, bool& truncated, std::string& error);

// Starts and stops log capture. Called from the service lifecycle. Starting
// determines the snapshot file path and takes one snapshot to anchor the
// starting point, so output produced before the server started is not
// returned as if it were a command's output; see IsLogCaptureActive for how
// readiness is decided afterwards. StartLogCapture is called directly on the
// GUI thread, not through DebuggerWorker::Submit — see
// McpService::EnableLogCapture.
bool StartLogCapture(std::string& error);
void StopLogCapture();

// Whether log capture is active right now: a snapshot path is known and the
// most recent snapshot attempt (from StartLogCapture, ExecuteCommand,
// RunScript, or ReadLog) succeeded.
bool IsLogCaptureActive();

// Path to the log capture file, empty if StartLogCapture has not been
// called. Exposed so callers can report where captured output is expected to
// be written, which is what makes diagnosing a stuck capture possible from
// outside.
std::string LogCaptureFilePath();

// Writes bytes into the debuggee. When recordPatch is true the change goes
// through MemPatch, which records it in the patch list so it can be undone
// later (see RestorePatches) and exported to a file (see
// ApplyPatchesToFile); when false it goes through DbgMemWrite, a plain
// write with no such bookkeeping. Requires active debugging and a pause:
// see RequirePaused in debugger.cpp for why writing while the process runs
// is refused — the bytes could be executed halfway through the write.
bool WriteMemory(unsigned long long address, const std::vector<unsigned char>& data,
                 bool recordPatch, std::string& error);

// Sets a named value: a register such as "rax"/"eax", or any other
// debugger variable, via the "mov"/"set" command (SSE registers are not
// supported through this path). Requires active debugging and a pause, for
// the same reason as WriteMemory.
bool SetNamedValue(const std::string& name, unsigned long long value, std::string& error);

// Result of assembling one instruction.
struct AssembleResult { size_t size = 0; };

// Assembles one instruction at address, overwriting whatever was there.
// fillNop pads the remainder of a replaced longer instruction with nops.
// Requires active debugging and a pause, for the same reason as WriteMemory.
bool AssembleAt(unsigned long long address, const std::string& instruction,
                bool fillNop, AssembleResult& out, std::string& error);

// A single byte patch recorded by the debugger (via WriteMemory with
// recordPatch, or elsewhere in x64dbg).
struct PatchEntry
{
    unsigned long long address = 0;
    unsigned int oldByte = 0, newByte = 0;
    std::string module;
};

// Lists all currently recorded patches. An empty list is a normal result,
// not an error. Requires active debugging.
bool ListPatches(std::vector<PatchEntry>& out, std::string& error);

// Restores a single patched address, or a whole [address, end) range when
// hasRange is true, writing the original bytes back. Requires active
// debugging and a pause, for the same reason as WriteMemory.
bool RestorePatches(unsigned long long address, unsigned long long end, bool hasRange,
                    size_t& restored, std::string& error);

// Writes all currently recorded patches into a copy of the module on disk
// at filePath; the running process itself is not touched. Requires active
// debugging.
bool ApplyPatchesToFile(const std::string& filePath, int& patched, std::string& error);

// Sets the page protection rights of the region containing address. rights
// is one of Execute, ExecuteRead, ExecuteReadWrite, ExecuteWriteCopy,
// NoAccess, ReadOnly, ReadWrite, WriteCopy, optionally prefixed with "G" for
// a guard page (the same words MemPageRightsFromString accepts) — NOT the
// compact form GetMemoryMap reports (e.g. "ERW-"), which only PageRightsToString
// produces. Requires active debugging and a pause, for the same reason as
// WriteMemory.
bool SetPageProtection(unsigned long long address, const std::string& rights, std::string& error);

// Bounds on maxSteps for TraceUntil: keeps a runaway request from tying up
// the debugger indefinitely while still allowing traces long enough to
// cross a large virtualized handler.
constexpr int kMinTraceSteps = 1;
constexpr int kMaxTraceSteps = 10000000;

// Traces until condition holds or maxSteps is reached. mode is "into" or
// "over" (stepping over calls). Requires active debugging and a pause; uses
// the same wait-for-pause mechanism as Step/Control, so the result reports
// whether tracing ended in a pause, a timeout, or the process exiting (via
// out.status).
bool TraceUntil(const std::string& mode, const std::string& condition, int maxSteps,
                int timeoutMs, ControlResult& out, std::string& error);

// Starts or stops recording executed instructions to filePath. Starting
// recording alone does not trace anything: only instructions that a trace
// command (e.g. TraceUntil) actually executes while recording is active are
// stored to the file. Requires active debugging.
bool TraceRecordToFile(bool start, const std::string& filePath, std::string& error);

// Runs until user code is reached, using temporary memory breakpoints on
// user code pages rather than single-stepping. Requires active debugging.
// Documented limitation: fails if another RunToUserCode is already running.
bool RunToUserCode(int timeoutMs, ControlResult& out, std::string& error);

// One address with a non-zero trace record hit count.
struct CoverageEntry
{
    unsigned long long address = 0;
    unsigned int hitCount = 0;
    std::string byteType;   // readable TRACERECORDBYTETYPE, e.g. "instructionBody"
};

// Upper limits for ReadCoverage: bounds the amount of memory scanned and the
// number of entries returned by a single call, for the same reason as the
// analogous limits on FindPattern.
constexpr unsigned long long kMaxCoverageRangeSize = 16ull * 1024ull * 1024ull; // 16 MiB
constexpr size_t kMaxCoverageEntries = 4096;

// Enables trace record coverage tracking for the page containing address.
// Trace record state is tracked per memory PAGE, so this affects every
// address on that page, not just the one given. granularity is one of
// "bit" (execution only), "byte", "word" (byte/word add a hit counter and
// access-type tracking). Requires active debugging.
bool EnableCoverage(unsigned long long address, const std::string& granularity, std::string& error);

// Disables trace record coverage tracking for the page containing address.
bool DisableCoverage(unsigned long long address, std::string& error);

// Reads trace record hit counts over [start, start + size). Entries with
// zero hits are omitted. truncated is set when kMaxCoverageEntries was
// reached before the whole range was scanned. Requires active debugging.
bool ReadCoverage(unsigned long long start, unsigned long long size,
                  std::vector<CoverageEntry>& out, bool& truncated, std::string& error);

// Upper limit on the number of entries returned by a single ListHandles,
// ListWindows, or ListConnections call: an open handle table or window list
// can run into the thousands, and a full dump would flood the model's context.
constexpr size_t kMaxProcessEnvEntries = 4096;

// A single open kernel object handle of the debuggee.
struct HandleEntry
{
    unsigned long long handle = 0;
    unsigned int typeNumber = 0;
    unsigned int grantedAccess = 0;
    std::string typeName;   // e.g. File, Mutant, Event — from GetHandleName
    std::string name;       // object name, may be empty
};

// Lists the debuggee's open handles. Requires active debugging; does not
// require a pause. Empty results are normal, not an error. Capped at
// kMaxProcessEnvEntries; truncated is set when the cap is reached.
// namesIncomplete is set when a wall-clock deadline cut per-handle name
// resolution short (see the comment on the deadline in debugger.cpp): the
// entries already collected are still returned in full, with an empty
// name/typeName for whichever ones were skipped — this is a partial
// success, not an error.
bool ListHandles(std::vector<HandleEntry>& out, bool& truncated, bool& namesIncomplete, std::string& error);

// A single top-level or child window owned by the debuggee.
struct WindowEntry
{
    unsigned long long handle = 0, parent = 0, wndProc = 0;
    unsigned int threadId = 0, style = 0, styleEx = 0;
    bool enabled = false;
    int left = 0, top = 0, right = 0, bottom = 0;
    std::string title, className;
};

// Lists the debuggee's windows. Requires active debugging; does not require
// a pause. Empty results are normal, not an error. Capped at
// kMaxProcessEnvEntries; truncated is set when the cap is reached.
bool ListWindows(std::vector<WindowEntry>& out, bool& truncated, std::string& error);

// A single TCP connection owned by the debuggee.
struct ConnectionEntry
{
    std::string remoteAddress, localAddress, state;
    unsigned int remotePort = 0, localPort = 0;
};

// Lists the debuggee's TCP connections. Requires active debugging; does not
// require a pause. Empty results are normal, not an error. Capped at
// kMaxProcessEnvEntries; truncated is set when the cap is reached.
bool ListConnections(std::vector<ConnectionEntry>& out, bool& truncated, std::string& error);

// A single record of the current thread's SEH exception handler chain.
struct SehEntry { unsigned long long address = 0, handler = 0; };

// The SEH chain of the current thread. Requires active debugging AND a
// pause: the chain is read from the current thread's stack, which is only
// meaningful while the process is not running, for the same reason
// registers and the call stack require a pause.
// On 64-bit builds, x64dbg's own ExHandlerGetSEH (external/x64dbg/src/dbg/exhandlerinfo.cpp)
// is a stub that unconditionally `return false;`s under `#ifdef _WIN64` —
// it does not walk a stack-based SEH chain there at all. So on x64, this
// always returns an empty chain, regardless of what the target actually
// has installed; that emptiness is NOT evidence about the debuggee.
bool GetSehChain(std::vector<SehEntry>& out, std::string& error);

// A running process visible to the debugger, as returned by ListProcesses.
struct ProcessEntry
{
    unsigned int pid = 0;
    std::string exeFile;
    std::string mainWindowTitle;
    std::string commandLine;
};

// Upper limit on the number of entries returned by a single ListProcesses call.
constexpr size_t kMaxProcessListEntries = 4096;

// Lists processes currently visible to the debugger. Does NOT require an
// active debugging session: its whole purpose is finding something to attach
// to. An empty list is a normal result, not an error. Capped at
// kMaxProcessListEntries; truncated is set when the cap is reached.
bool ListProcesses(std::vector<ProcessEntry>& out, bool& truncated, std::string& error);

// Upper limit on the size of a single AllocateMemory or DumpMemory request.
constexpr unsigned long long kMaxAllocationSize = 256ull * 1024ull * 1024ull; // 256 MiB
constexpr unsigned long long kMaxDumpSize = 256ull * 1024ull * 1024ull;      // 256 MiB

// Allocates size bytes of PAGE_EXECUTE_READWRITE memory in the debuggee.
// preferredAddress == 0 lets the system choose the address. Requires active
// debugging.
bool AllocateMemory(unsigned long long size, unsigned long long preferredAddress,
                    unsigned long long& outAddress, std::string& error);

// Frees memory previously allocated with AllocateMemory. address must be the
// base address of that allocation — the underlying VirtualFreeEx only
// accepts a region's base address. Requires active debugging.
bool FreeMemory(unsigned long long address, std::string& error);

// Saves size bytes of the debuggee's memory starting at address to a file at
// path. Requires active debugging.
bool DumpMemory(unsigned long long address, unsigned long long size,
                const std::string& path, std::string& error);

// Default timeout for waiting for the paused state after AttachProcess,
// longer than kDefaultControlTimeoutMs: reaching the system breakpoint after
// attaching can take noticeably longer than a plain run/step.
constexpr int kDefaultAttachTimeoutMs = 30000;

// Attaches to a running process by pid and waits for the resulting pause (the
// system breakpoint, per the "attach" command). Fails if a debugging session
// is already active — it must be ended first, e.g. via Control("stop") or
// DetachProcess. timeoutMs == 0 means kDefaultAttachTimeoutMs. out is filled
// the same way Control's wait path fills it: paused/timedOut/pauseReason
// reflect what the tracker actually observed, and status is the state after
// the operation — a timeout is reported as out.paused == false,
// out.timedOut == true with error left empty, NOT as a failure, since the
// attach itself was issued successfully.
bool AttachProcess(unsigned int pid, unsigned int timeoutMs, ControlResult& out, std::string& error);

// Detaches from the debuggee, leaving it running — unlike Control("stop"),
// which terminates it. Requires active debugging.
bool DetachProcess(std::string& error);

} // namespace x64dbg_mcp::plugin
