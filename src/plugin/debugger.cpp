#include "plugin/debugger.h"
#include "plugin/plugin.h"
#include "plugin/service.h"
#include "pluginsdk/_scriptapi_module.h"
#include "pluginsdk/_scriptapi_pattern.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <thread>

namespace x64dbg_mcp::plugin
{

namespace
{

// Clamps timeoutMs into the default range: <=0 means "not specified" and is
// replaced with the default value, and anything over the upper limit is
// clamped down to it.
int ClampTimeout(int timeoutMs)
{
    if (timeoutMs <= 0)
        return kDefaultControlTimeoutMs;
    if (timeoutMs > kMaxControlTimeoutMs)
        return kMaxControlTimeoutMs;
    return timeoutMs;
}

// IMPORTANT: in x64dbg commands, arguments are separated by a COMMA, not a
// space — a space only separates the command name from the first argument
// (see the comment "arguments are separated by a COMMA (not space like
// WinDbg)" in external/PluginTemplate/src/plugin.cpp and the comma-based
// argv[] parsing in external/x64dbg/src/dbg/commands/cmd-breakpoint-control.cpp).
// Commands with a single argument (StepInto, StepOut, run, DeleteBPX, etc.)
// are not affected by this — there is nothing to separate within one argument.

// Addresses in x64dbg commands are passed in hexadecimal form.
std::string FormatHexAddress(unsigned long long address)
{
    std::ostringstream out;
    out << "0x" << std::hex << address;
    return out.str();
}

std::string PauseReasonToString(PauseReason reason)
{
    switch (reason)
    {
    case PauseReason::InitialBreak: return "initial";
    case PauseReason::Breakpoint: return "breakpoint";
    case PauseReason::Step: return "step";
    case PauseReason::UserPause: return "pause";
    case PauseReason::Exception: return "exception";
    default: return "unknown";
    }
}

// Common tail for operations that sent an asynchronous command and
// optionally wait for a subsequent pause: fills in ControlResult from the
// wait outcome (or immediately, if no wait is requested).
bool FinishWithWait(DebugStateTracker& tracker, unsigned long long beforeGeneration,
                     bool wait, int timeoutMs, ControlResult& out)
{
    if (!wait)
    {
        out.paused = false;
        out.timedOut = false;
        out.pauseReason.clear();
        out.status = GetStatus();
        return true;
    }

    StateSnapshot after;
    const bool paused = tracker.WaitForPauseAfter(beforeGeneration, timeoutMs, after);
    out.paused = paused;
    out.timedOut = !paused;
    out.pauseReason = paused ? PauseReasonToString(after.reason) : std::string();
    out.status = GetStatus();
    return true;
}

bool RequireDebugging(std::string& error)
{
    if (!DbgIsDebugging())
    {
        error = "Debugging is not active: open or attach to a process in x64dbg first";
        return false;
    }
    return true;
}

// Registers, the call stack, and stack contents are only meaningful while
// the process is paused: during execution they change at arbitrary moments,
// and x64dbg would return a stale or arbitrary snapshot (see the analogous
// restriction for cip in GetStatus). Writes are refused for a different
// reason: the bytes being written could be executed halfway through the
// write, since the process keeps running concurrently with it. what
// completes the sentence "pause it before ..." (e.g. "reading registers",
// "writing memory"), so it must describe the action, not just its subject.
bool RequirePaused(const char* what, std::string& error)
{
    if (!RequireDebugging(error))
        return false;
    if (DbgIsRunning())
    {
        error = std::string("The process is currently running: pause it before ") + what;
        return false;
    }
    return true;
}

// Formats a 128-bit XMM register value as a 32-character hex string,
// high part first.
std::string FormatXmmHex(const XMMREGISTER& xmm)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0')
        << std::setw(16) << static_cast<unsigned long long>(xmm.High)
        << std::setw(16) << static_cast<unsigned long long>(xmm.Low);
    return out.str();
}

// Reads an optional string field. Returns false if the field is present
// but has the wrong type.
bool GetOptionalString(const nlohmann::json& params, const char* name, std::string& out, std::string& error)
{
    if (!params.contains(name))
        return true;
    if (!params[name].is_string())
    {
        error = std::string("Parameter \"") + name + "\" must be a string";
        return false;
    }
    out = params[name].get<std::string>();
    return true;
}

bool GetOptionalBool(const nlohmann::json& params, const char* name, bool& out, std::string& error)
{
    if (!params.contains(name))
        return true;
    if (!params[name].is_boolean())
    {
        error = std::string("Parameter \"") + name + "\" must be a boolean";
        return false;
    }
    out = params[name].get<bool>();
    return true;
}

void CollectBpFieldText(const BP_REF& ref, BP_FIELD field, std::string& out)
{
    DbgFunctions()->BpGetFieldText(&ref, field, [](const char* str, void* userdata)
    {
        *static_cast<std::string*>(userdata) = str;
    }, &out);
}

std::string BpxTypeToString(BPXTYPE type)
{
    switch (type)
    {
    case bp_normal: return "software";
    case bp_hardware: return "hardware";
    case bp_memory: return "memory";
    case bp_dll: return "dll";
    case bp_exception: return "exception";
    default: return "unknown";
    }
}

std::string MemStateToString(DWORD state)
{
    switch (state)
    {
    case MEM_COMMIT: return "commit";
    case MEM_RESERVE: return "reserve";
    case MEM_FREE: return "free";
    default: return "unknown";
    }
}

std::string MemTypeToString(DWORD type)
{
    switch (type)
    {
    case MEM_IMAGE: return "image";
    case MEM_MAPPED: return "mapped";
    case MEM_PRIVATE: return "private";
    default: return "unknown";
    }
}

// Names are taken verbatim from THREADPRIORITY (bridgemain.h) without the
// leading underscore.
std::string ThreadPriorityToString(THREADPRIORITY priority)
{
    switch (priority)
    {
    case _PriorityIdle: return "Idle";
    case _PriorityAboveNormal: return "AboveNormal";
    case _PriorityBelowNormal: return "BelowNormal";
    case _PriorityHighest: return "Highest";
    case _PriorityLowest: return "Lowest";
    case _PriorityNormal: return "Normal";
    case _PriorityTimeCritical: return "TimeCritical";
    default: return "Unknown";
    }
}

// Names are taken verbatim from THREADWAITREASON (bridgemain.h) without the
// leading underscore.
std::string ThreadWaitReasonToString(THREADWAITREASON reason)
{
    switch (reason)
    {
    case _Executive: return "Executive";
    case _FreePage: return "FreePage";
    case _PageIn: return "PageIn";
    case _PoolAllocation: return "PoolAllocation";
    case _DelayExecution: return "DelayExecution";
    case _Suspended: return "Suspended";
    case _UserRequest: return "UserRequest";
    case _WrExecutive: return "WrExecutive";
    case _WrFreePage: return "WrFreePage";
    case _WrPageIn: return "WrPageIn";
    case _WrPoolAllocation: return "WrPoolAllocation";
    case _WrDelayExecution: return "WrDelayExecution";
    case _WrSuspended: return "WrSuspended";
    case _WrUserRequest: return "WrUserRequest";
    case _WrEventPair: return "WrEventPair";
    case _WrQueue: return "WrQueue";
    case _WrLpcReceive: return "WrLpcReceive";
    case _WrLpcReply: return "WrLpcReply";
    case _WrVirtualMemory: return "WrVirtualMemory";
    case _WrPageOut: return "WrPageOut";
    case _WrRendezvous: return "WrRendezvous";
    case _Spare2: return "Spare2";
    case _Spare3: return "Spare3";
    case _Spare4: return "Spare4";
    case _Spare5: return "Spare5";
    case _WrCalloutStack: return "WrCalloutStack";
    case _WrKernel: return "WrKernel";
    case _WrResource: return "WrResource";
    case _WrPushLock: return "WrPushLock";
    case _WrMutex: return "WrMutex";
    case _WrQuantumEnd: return "WrQuantumEnd";
    case _WrDispatchInt: return "WrDispatchInt";
    case _WrPreempted: return "WrPreempted";
    case _WrYieldExecution: return "WrYieldExecution";
    case _WrFastMutex: return "WrFastMutex";
    case _WrGuardedMutex: return "WrGuardedMutex";
    case _WrRundown: return "WrRundown";
    default: return "Unknown";
    }
}

// Rejects obviously invalid patterns before calling Script::Pattern::FindMem:
// it does not distinguish "pattern is invalid" from "no matches", returning
// 0 in both cases (see external/x64dbg/src/dbg/_scriptapi_pattern.cpp and
// patterntransform in external/x64dbg/src/dbg/patternfind.cpp).
bool LooksLikeValidPattern(const std::string& pattern)
{
    bool hasHexDigit = false;
    for (char ch : pattern)
    {
        const bool isHex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
        if (ch != '?' && ch != ' ' && !isHex)
            return false;
        if (isHex)
            hasHexDigit = true;
    }
    return hasHexDigit;
}

std::string XrefTypeToString(XREFTYPE type)
{
    switch (type)
    {
    case XREF_DATA: return "data";
    case XREF_JMP: return "jmp";
    case XREF_CALL: return "call";
    default: return "none";
    }
}

std::string TraceRecordByteTypeToString(TRACERECORDBYTETYPE type)
{
    switch (type)
    {
    case InstructionBody: return "instructionBody";
    case InstructionHeading: return "instructionHeading";
    case InstructionTailing: return "instructionTailing";
    case InstructionOverlapped: return "instructionOverlapped";
    case DataByte: return "dataByte";
    case DataWord: return "dataWord";
    case DataDWord: return "dataDWord";
    case DataQWord: return "dataQWord";
    case DataFloat: return "dataFloat";
    case DataDouble: return "dataDouble";
    case DataLongDouble: return "dataLongDouble";
    case DataXMM: return "dataXMM";
    case DataYMM: return "dataYMM";
    case DataMMX: return "dataMMX";
    case DataMixed: return "dataMixed";
    case InstructionDataMixed: return "instructionDataMixed";
    default: return "unknown";
    }
}

std::string ToLowerCopy(const std::string& text)
{
    std::string result = text;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return result;
}

// Context threaded through CbSymbolEnum via DbgSymbolEnum's user pointer.
struct SymbolEnumContext
{
    std::vector<SymbolEntry>* out = nullptr;
    std::string filterLower;
    size_t cap = 0;
    bool truncated = false;
};

// Appends one symbol into *user (a SymbolEnumContext) if it passes the
// filter. Enumeration is stopped early once the cap is reached by returning
// false here: SymEnum (external/x64dbg/src/dbg/symbolinfo.cpp) checks the
// callback's return value and stops calling it as soon as it sees false.
// Must not throw: this is invoked as a raw C callback from inside the
// debugger core, where an exception crossing that boundary is undefined
// behavior.
bool CbSymbolEnum(const SYMBOLPTR_* symbol, void* user)
{
    try
    {
        auto* ctx = static_cast<SymbolEnumContext*>(user);

        // SYMBOLINFOCPP (bridgemain.h) is an RAII wrapper around SYMBOLINFO
        // whose destructor calls BridgeFree on decoratedSymbol/undecoratedSymbol
        // whenever the corresponding freeDecorated/freeUndecorated flag is
        // set, so the free cannot be skipped on any path, including the
        // early returns below.
        SYMBOLINFOCPP info;
        DbgGetSymbolInfo(symbol, &info);

        // Per the header comment on CBSYMBOLENUM, "The SYMBOLPTR* becomes
        // invalid when the module is unloaded" and must not be stored —
        // only the strings copied out of info below are kept.
        SymbolEntry entry;
        entry.address = static_cast<unsigned long long>(info.addr);
        entry.ordinal = static_cast<unsigned int>(info.ordinal);
        switch (info.type)
        {
        case sym_import: entry.type = "import"; break;
        case sym_export: entry.type = "export"; break;
        default: entry.type = "symbol"; break;
        }

        const std::string decorated = info.decoratedSymbol ? info.decoratedSymbol : "";
        const std::string undecorated = info.undecoratedSymbol ? info.undecoratedSymbol : "";
        entry.name = !undecorated.empty() ? undecorated : decorated;
        if (!decorated.empty() && decorated != entry.name)
            entry.decoratedName = decorated;

        if (!ctx->filterLower.empty() && ToLowerCopy(entry.name).find(ctx->filterLower) == std::string::npos)
            return true; // filtered out; keep enumerating

        ctx->out->push_back(std::move(entry));
        if (ctx->out->size() >= ctx->cap)
        {
            ctx->truncated = true;
            return false; // cap reached: stop enumerating
        }
        return true;
    }
    catch (...)
    {
        return false; // never let an exception escape into the debugger
    }
}

// State of log capture. Unlike everything else in this file, this is NOT
// accessed only from the DebuggerWorker worker thread: StartLogCapture runs
// directly on the GUI thread (see McpService::EnableLogCapture), while
// ReadLog and friends still run on the worker thread. g_logCaptureMutex
// protects exactly these three fields against that race; it is not held
// across file I/O.
struct LogCaptureState
{
    std::wstring filePath;       // empty until StartLogCapture has been called
    size_t deliveredBytes = 0;   // bytes of the log already delivered to a caller as a command's output
    bool lastSnapshotOk = false; // outcome of the most recent SnapshotLog call
};
LogCaptureState g_logCapture;
std::mutex g_logCaptureMutex;

std::string WideToUtf8(const std::wstring& wide)
{
    if (wide.empty())
        return {};
    const int needed = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                                            nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return {};
    std::string utf8(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), utf8.data(), needed, nullptr, nullptr);
    return utf8;
}

// Waits for GuiLogSave's write to finish: the request is delivered to the
// GUI thread asynchronously when issued, as here, from a non-GUI thread, so
// the file may not exist, or may still be mid-write, the instant GuiLogSave
// returns. Polls the file's size and last-write time; once two consecutive
// polls see the same values, the write is done. Gives up after a small total
// budget and reports whatever was last observed, so a stuck write does not
// hang the caller forever.
bool WaitForSnapshotFile(const std::wstring& path)
{
    constexpr int kBudgetMs = 1000;
    constexpr int kStepMs = 25;

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kBudgetMs);
    bool havePrevious = false;
    WIN32_FILE_ATTRIBUTE_DATA previous = {};
    for (;;)
    {
        WIN32_FILE_ATTRIBUTE_DATA current = {};
        if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &current))
        {
            if (havePrevious &&
                current.nFileSizeLow == previous.nFileSizeLow && current.nFileSizeHigh == previous.nFileSizeHigh &&
                current.ftLastWriteTime.dwLowDateTime == previous.ftLastWriteTime.dwLowDateTime &&
                current.ftLastWriteTime.dwHighDateTime == previous.ftLastWriteTime.dwHighDateTime)
                return true; // unchanged since the last poll: the write is done
            previous = current;
            havePrevious = true;
        }
        if (std::chrono::steady_clock::now() >= deadline)
            return havePrevious;
        std::this_thread::sleep_for(std::chrono::milliseconds(kStepMs));
    }
}

// Whether line mentions the snapshot file's own path. Used to recognize
// lines this mechanism added to the log itself, as opposed to lines the
// caller's command produced.
bool LineMentionsSnapshotPath(const std::string& line, const std::string& snapshotPathUtf8)
{
    return !snapshotPathUtf8.empty() && line.find(snapshotPathUtf8) != std::string::npos;
}

// Drops every line that mentions the snapshot file's path from text: taking
// a snapshot adds such lines to the log itself (GuiLogSave's handler reports
// "<message> as <path>" once it has written the file, see
// LogView::saveToFileSlot in external/x64dbg/src/gui/Src/Gui/LogView.cpp),
// and they must not be attributed to the caller's command. Matching on the
// path rather than on any particular wording is what survives a localized
// x64dbg build, where that message is translated but the path is not.
std::string StripSnapshotNoise(const std::string& text, const std::string& snapshotPathUtf8)
{
    if (snapshotPathUtf8.empty())
        return text;

    std::istringstream stream(text);
    std::ostringstream result;
    std::string line;
    bool wroteAny = false;
    while (std::getline(stream, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (LineMentionsSnapshotPath(line, snapshotPathUtf8))
            continue;
        if (wroteAny)
            result << '\n';
        result << line;
        wroteAny = true;
    }
    return result.str();
}

// Bounds on the settling retry loop in SnapshotLog: at most this many
// GuiLogSave round trips, with this pause between them, before giving up on
// waiting for the log to stop growing and returning whatever was last read.
constexpr int kMaxSnapshotAttempts = 3;
constexpr int kSnapshotSettleStepMs = 50;

// Snapshots the whole log into contents, as UTF-8 text. Also records the
// outcome into g_logCapture.lastSnapshotOk, which is how IsLogCaptureActive
// decides whether capture is working.
//
// This snapshots the log rather than tailing a stream because the alternative
// — redirecting the log to a file with GuiLogRedirect and reading its growth
// — does not work when driven from outside the GUI: x64dbg opens the
// redirect target with _wfopen_s(..., L"ab") and writes to it with fwrite,
// but external/x64dbg/src/gui/Src/Gui/LogView.cpp contains no fflush for
// that handle anywhere, and flushLogSlot only flushes the GUI's own display
// buffer — so the data sits in the CRT's buffer and the file on disk stays
// at zero bytes until the buffer fills or the file is closed. GuiLogSave,
// used here instead, writes the whole log to a file and closes it in one
// shot, so its output is actually on disk by the time the write completes.
//
// A single GuiLogSave round trip can still miss text that was logged just
// before this call, even after GuiFlushLog(): GuiLogSave's handler
// (LogView::saveToFileSlot) saves document()->toPlainText(), but newly
// logged text first lands in an internal buffer (logBuffer) and is only
// moved into the document by LogView's own flush timer — which runs only
// while the Log view happens to be the currently-visible GUI widget (see
// LogView::showEvent/hideEvent). GuiFlushLog() requests a flush but only
// performs it immediately in that same case; otherwise the flush is
// deferred until the buffer receives another message — which here is
// GuiLogSave's own "log saved" notice, added right after the file is
// written, one call too late for that same call to see it. To work around
// this without guessing a fixed delay, retry and compare consecutive
// attempts (after stripping this mechanism's own bookkeeping lines, which
// would otherwise keep the comparison from ever settling, since GuiLogSave
// adds one more such line on every attempt) until the real content stops
// growing.
bool SnapshotLog(std::string& contents, std::string& error)
{
    contents.clear();

    std::wstring path;
    {
        std::lock_guard<std::mutex> lock(g_logCaptureMutex);
        path = g_logCapture.filePath;
    }
    if (path.empty())
    {
        error = "Log capture has not been started";
        return false;
    }
    const std::string pathUtf8 = WideToUtf8(path);

    std::string previousFiltered;
    bool havePrevious = false;
    bool ok = false;
    for (int attempt = 0; attempt < kMaxSnapshotAttempts; ++attempt)
    {
        std::string current;
        bool attemptOk = false;
        do
        {
            // Log messages are queued on the GUI side; without this, text
            // produced just before this call could still be missing from the
            // snapshot.
            GuiFlushLog();

            // The GUI's save handler (LogView::saveToFileSlot) opens its target
            // with QIODevice::Append, so a stale copy from a previous snapshot
            // would end up duplicated ahead of the fresh one — delete it first
            // so every snapshot starts from a clean file.
            DeleteFileW(path.c_str());

            GuiLogSave(pathUtf8.c_str());

            if (!WaitForSnapshotFile(path))
            {
                error = "Timed out waiting for the log snapshot to be written";
                break;
            }

            // Unlike the redirect path, the save path does not consult
            // Misc/Utf16LogRedirect: LogView::saveToFileSlot always writes
            // document()->toPlainText().toUtf8() (see
            // external/x64dbg/src/gui/Src/Gui/LogView.cpp), so the file is
            // always UTF-8 and can be read directly, with no decoding step.
            std::ifstream file(path, std::ios::binary);
            if (!file)
            {
                error = "Failed to open the log snapshot file for reading";
                break;
            }
            std::ostringstream buffer;
            buffer << file.rdbuf();
            current = buffer.str();
            attemptOk = true;
        }
        while (false);

        if (!attemptOk)
            break; // keep whatever an earlier attempt in this call already produced, if any

        ok = true;
        contents = current;
        error.clear();

        const std::string filtered = StripSnapshotNoise(current, pathUtf8);
        if (havePrevious && filtered == previousFiltered)
            break; // no new (non-bookkeeping) content since the last attempt: settled
        previousFiltered = filtered;
        havePrevious = true;

        if (attempt + 1 < kMaxSnapshotAttempts)
            std::this_thread::sleep_for(std::chrono::milliseconds(kSnapshotSettleStepMs));
    }

    std::lock_guard<std::mutex> lock(g_logCaptureMutex);
    g_logCapture.lastSnapshotOk = ok;
    return ok;
}

// Fetches the current patch list into out, following the two-phase
// enumeration PatchEnum requires: call it once with a null buffer to learn
// the byte count, then again with a buffer sized for that many
// DBGPATCHINFO entries. The buffer is ordinary heap memory owned by the
// std::vector, not bridge memory, so nothing needs to be freed manually.
bool FetchPatchList(std::vector<DBGPATCHINFO>& out, std::string& error)
{
    out.clear();
    auto* functions = DbgFunctions();

    size_t byteSize = 0;
    if (!functions->PatchEnum(nullptr, &byteSize))
    {
        error = "Failed to retrieve the patch list";
        return false;
    }
    const size_t count = byteSize / sizeof(DBGPATCHINFO);
    if (count == 0)
        return true;

    out.resize(count);
    if (!functions->PatchEnum(out.data(), nullptr))
    {
        out.clear();
        error = "Failed to retrieve the patch list";
        return false;
    }
    return true;
}

} // namespace

DebuggerStatus GetStatus()
{
    DebuggerStatus status;
    try
    {
#ifdef _WIN64
        status.pointerSize = 8;
#else
        status.pointerSize = 4;
#endif
        status.debugging = DbgIsDebugging();
        if (!status.debugging)
            return status;

        status.running = DbgIsRunning();
        status.processId = static_cast<unsigned int>(DbgGetProcessId());
        status.threadId = static_cast<unsigned int>(DbgGetThreadId());

        // cip is only meaningful while the process is paused — during
        // execution DbgEval could return a stale or arbitrary value, so we
        // leave it at 0, as documented in the header.
        if (!status.running)
        {
            bool success = false;
            const duint cip = DbgEval("cip", &success);
            if (success)
            {
                status.cip = static_cast<unsigned long long>(cip);
                char moduleName[MAX_MODULE_SIZE] = {};
                if (DbgGetModuleAt(static_cast<duint>(cip), moduleName))
                    status.module = moduleName;
            }
        }
    }
    catch (...)
    {
    }
    return status;
}

bool ReadMemory(unsigned long long address, size_t size, std::vector<unsigned char>& out, std::string& error)
{
    out.clear();
    try
    {
        if (!DbgIsDebugging())
        {
            error = "Debugging is not active: start or attach to a process in x64dbg first";
            return false;
        }
        if (size == 0)
        {
            error = "Read size must be greater than zero";
            return false;
        }
        if (size > kMaxReadSize)
        {
            error = "Requested read size exceeds the maximum of 1 MiB";
            return false;
        }

        const duint addr = static_cast<duint>(address);
        if (!DbgMemIsValidReadPtr(addr))
        {
            error = "Address is not a valid readable pointer in the debuggee's memory";
            return false;
        }

        out.resize(size);
        if (!DbgMemRead(addr, out.data(), static_cast<duint>(size)))
        {
            out.clear();
            error = "Failed to read memory at the given address";
            return false;
        }
        return true;
    }
    catch (...)
    {
        out.clear();
        error = "Internal error while reading memory";
        return false;
    }
}

bool Disassemble(unsigned long long address, size_t count, std::vector<Instruction>& out, std::string& error)
{
    out.clear();
    try
    {
        if (!DbgIsDebugging())
        {
            error = "Debugging is not active: start or attach to a process in x64dbg first";
            return false;
        }
        if (count == 0)
        {
            error = "Instruction count must be greater than zero";
            return false;
        }
        if (count > kMaxInstructions)
        {
            error = "Requested instruction count exceeds the maximum of 256";
            return false;
        }

        duint addr = static_cast<duint>(address);
        for (size_t i = 0; i < count; ++i)
        {
            if (!DbgMemIsValidReadPtr(addr))
                break; // nothing further to disassemble at this address — return what we have

            BASIC_INSTRUCTION_INFO basicInfo = {};
            DbgDisasmFastAt(addr, &basicInfo);
            if (basicInfo.size <= 0)
                break; // instruction size unknown — stop disassembling

            Instruction instruction;
            instruction.address = static_cast<unsigned long long>(addr);
            instruction.size = static_cast<size_t>(basicInfo.size);

            instruction.bytes.resize(instruction.size);
            if (!DbgMemRead(addr, instruction.bytes.data(), static_cast<duint>(instruction.size)))
                instruction.bytes.clear();

            char text[GUI_MAX_DISASSEMBLY_SIZE] = {};
            if (GuiGetDisassembly(addr, text))
                instruction.text = text;

            addr += static_cast<duint>(instruction.size);
            out.push_back(std::move(instruction));
        }

        if (out.empty())
        {
            error = "Address is not a valid readable pointer in the debuggee's memory";
            return false;
        }
        return true;
    }
    catch (...)
    {
        error = "Internal error while disassembling";
        return false;
    }
}

bool Control(const std::string& action, unsigned long long address, bool hasAddress,
             bool wait, int timeoutMs, ControlResult& out, std::string& error)
{
    out = ControlResult{};
    try
    {
        const int clampedTimeout = ClampTimeout(timeoutMs);
        auto& tracker = McpService::Instance().Tracker();

        if (action == "run" || action == "run_to")
        {
            if (!RequireDebugging(error))
                return false;
            if (action == "run_to" && !hasAddress)
            {
                error = "Action \"run_to\" requires an \"address\" parameter";
                return false;
            }
            const auto before = tracker.Current().generation;
            const std::string cmd = hasAddress ? ("run " + FormatHexAddress(address)) : "run";
            DbgCmdExec(cmd.c_str());
            return FinishWithWait(tracker, before, wait, clampedTimeout, out);
        }

        if (action == "pause")
        {
            if (!RequireDebugging(error))
                return false;
            const auto before = tracker.Current().generation;
            DbgCmdExec("pause");
            return FinishWithWait(tracker, before, wait, clampedTimeout, out);
        }

        if (action == "stop")
        {
            if (!RequireDebugging(error))
                return false;
            DbgCmdExec("StopDebug");
            // "stop" does not put the process into a pause, so WaitForPauseAfter
            // does not apply here — just return the state right after sending the command.
            out.paused = false;
            out.timedOut = false;
            out.pauseReason.clear();
            out.status = GetStatus();
            return true;
        }

        if (action == "restart")
        {
            if (!RequireDebugging(error))
                return false;

            char pathBuf[MAX_PATH] = {};
            if (!Script::Module::GetMainModulePath(pathBuf))
            {
                error = "Failed to determine the path of the main module: cannot restart";
                return false;
            }
            const std::string path = pathBuf;

            const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(clampedTimeout);
            DbgCmdExec("StopDebug");

            // We wait specifically for the ABSENCE of a debugging session, not for a
            // pause: DebugStateTracker does have a notification for debugging having
            // stopped, but that alone doesn't guarantee the process has actually
            // terminated and the path is free for reloading — so we poll
            // DbgIsDebugging() directly with a small step.
            while (DbgIsDebugging())
            {
                if (std::chrono::steady_clock::now() >= deadline)
                {
                    out.timedOut = true;
                    out.paused = false;
                    out.status = GetStatus();
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }

            const auto before = tracker.Current().generation;
            const std::string cmd = "InitDebug \"" + path + "\"";
            DbgCmdExec(cmd.c_str());

            if (!wait)
            {
                out.paused = false;
                out.timedOut = false;
                out.pauseReason.clear();
                out.status = GetStatus();
                return true;
            }

            const auto now = std::chrono::steady_clock::now();
            const int remainingMs = now >= deadline ? 0 : static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            return FinishWithWait(tracker, before, true, remainingMs, out);
        }

        error = "Unknown control action \"" + action + "\": expected one of run, pause, stop, restart, run_to";
        return false;
    }
    catch (...)
    {
        error = "Internal error while controlling the debugger";
        return false;
    }
}

bool Step(const std::string& mode, int count, bool wait, int timeoutMs,
          ControlResult& out, std::string& error)
{
    out = ControlResult{};
    try
    {
        if (!RequireDebugging(error))
            return false;
        if (DbgIsRunning())
        {
            error = "The process is currently running: pause it before stepping";
            return false;
        }
        if (count < 1 || count > 1000)
        {
            error = "Step count must be between 1 and 1000";
            return false;
        }

        const int clampedTimeout = ClampTimeout(timeoutMs);
        auto& tracker = McpService::Instance().Tracker();

        if (mode == "into")
        {
            const auto before = tracker.Current().generation;
            DbgCmdExec(("StepInto " + std::to_string(count)).c_str());
            return FinishWithWait(tracker, before, wait, clampedTimeout, out);
        }

        if (mode == "out")
        {
            const auto before = tracker.Current().generation;
            DbgCmdExec(("StepOut " + std::to_string(count)).c_str());
            return FinishWithWait(tracker, before, wait, clampedTimeout, out);
        }

        if (mode == "over")
        {
            // StepOver does not accept a step count, so we repeat the command in a
            // loop, waiting for the actual stop each time before the next
            // iteration — otherwise the steps would be queued up without
            // waiting for one another, and some of them would be lost or
            // executed from the wrong place.
            for (int i = 0; i < count; ++i)
            {
                const auto before = tracker.Current().generation;
                DbgCmdExec("StepOver");
                StateSnapshot after;
                const bool paused = tracker.WaitForPauseAfter(before, clampedTimeout, after);
                out.status = GetStatus();
                if (!paused)
                {
                    out.paused = false;
                    out.timedOut = true;
                    out.pauseReason.clear();
                    return true;
                }
                out.paused = true;
                out.timedOut = false;
                out.pauseReason = PauseReasonToString(after.reason);
            }
            return true;
        }

        error = "Unknown step mode \"" + mode + "\": expected one of into, over, out";
        return false;
    }
    catch (...)
    {
        error = "Internal error while stepping";
        return false;
    }
}

bool WaitUntilPaused(int timeoutMs, ControlResult& out, std::string& error)
{
    out = ControlResult{};
    try
    {
        if (!RequireDebugging(error))
            return false;

        const int clampedTimeout = ClampTimeout(timeoutMs);
        auto& tracker = McpService::Instance().Tracker();

        // If the process is already paused, return immediately: there's no
        // need to wait for a generation "strictly greater than the current
        // one" here — the current pause is exactly the one the caller is waiting for.
        const StateSnapshot current = tracker.Current();
        if (current.state == RunState::Paused)
        {
            out.paused = true;
            out.timedOut = false;
            out.pauseReason = PauseReasonToString(current.reason);
            out.status = GetStatus();
            return true;
        }

        return FinishWithWait(tracker, current.generation, true, clampedTimeout, out);
    }
    catch (...)
    {
        error = "Internal error while waiting for a pause";
        return false;
    }
}

bool SetBreakpoint(const nlohmann::json& params, std::string& error)
{
    try
    {
        if (!RequireDebugging(error))
            return false;
        if (!params.is_object() || !params.contains("address") || !params["address"].is_number_integer())
        {
            error = "Parameter \"address\" is required and must be an integer";
            return false;
        }
        const unsigned long long address = params["address"].get<unsigned long long>();

        std::string type = "software";
        if (!GetOptionalString(params, "type", type, error))
            return false;

        std::string name;
        if (!GetOptionalString(params, "name", name, error))
            return false;

        std::string cmd;
        BPXTYPE bpType = bp_normal;
        if (type == "software")
        {
            bpType = bp_normal;
            cmd = "SetBPX " + FormatHexAddress(address);
            if (!name.empty())
                cmd += ", \"" + name + "\"";
        }
        else if (type == "hardware")
        {
            bpType = bp_hardware;
            std::string access = "x";
            if (!GetOptionalString(params, "access", access, error))
                return false;
            if (access != "r" && access != "w" && access != "x")
            {
                error = "Parameter \"access\" for a hardware breakpoint must be one of r, w, x";
                return false;
            }
            long long size = 1;
            if (params.contains("size"))
            {
                if (!params["size"].is_number_integer())
                {
                    error = "Parameter \"size\" must be an integer";
                    return false;
                }
                size = params["size"].get<long long>();
                if (size != 1 && size != 2 && size != 4 && size != 8)
                {
                    error = "Parameter \"size\" for a hardware breakpoint must be one of 1, 2, 4, 8";
                    return false;
                }
            }
            cmd = "SetHardwareBreakpoint " + FormatHexAddress(address) + ", " + access + ", " + std::to_string(size);
        }
        else if (type == "memory")
        {
            bpType = bp_memory;
            cmd = "SetMemoryBPX " + FormatHexAddress(address);
            if (params.contains("restore"))
            {
                bool restore = false;
                if (!GetOptionalBool(params, "restore", restore, error))
                    return false;
                cmd += restore ? ", 1" : ", 0";
            }
            if (params.contains("access"))
            {
                std::string access;
                if (!GetOptionalString(params, "access", access, error))
                    return false;
                if (access != "a" && access != "r" && access != "w" && access != "x")
                {
                    error = "Parameter \"access\" for a memory breakpoint must be one of a, r, w, x";
                    return false;
                }
                cmd += ", " + access;
            }
        }
        else
        {
            error = "Unknown breakpoint type \"" + type + "\": expected one of software, hardware, memory";
            return false;
        }

        if (!DbgCmdExecDirect(cmd.c_str()))
        {
            error = "Failed to set the breakpoint: the debugger rejected \"" + cmd + "\"";
            return false;
        }

        // Additional settings are applied via separate commands to the
        // breakpoint that already exists, so it must first be located by address.
        BP_REF ref{};
        if (!DbgFunctions()->BpRefVa(&ref, bpType, static_cast<duint>(address)))
        {
            error = "Breakpoint was created but could not be located afterwards to apply additional settings";
            return false;
        }

        if (type != "software" && !name.empty())
        {
            if (!ref.SetField(bpf_name, name))
            {
                error = "Failed to set the breakpoint name";
                return false;
            }
        }

        std::string condition;
        if (!GetOptionalString(params, "condition", condition, error))
            return false;
        if (params.contains("condition"))
        {
            const std::string cmd2 = "SetBreakpointCondition " + FormatHexAddress(address) + ", " + condition;
            if (!DbgCmdExecDirect(cmd2.c_str()))
            {
                error = "Failed to set the breakpoint condition";
                return false;
            }
        }

        std::string log;
        if (!GetOptionalString(params, "log", log, error))
            return false;
        if (params.contains("log"))
        {
            const std::string cmd2 = "SetBreakpointLog " + FormatHexAddress(address) + ", " + log;
            if (!DbgCmdExecDirect(cmd2.c_str()))
            {
                error = "Failed to set the breakpoint log text";
                return false;
            }
        }

        std::string logCondition;
        if (!GetOptionalString(params, "log_condition", logCondition, error))
            return false;
        if (params.contains("log_condition"))
        {
            const std::string cmd2 = "SetBreakpointLogCondition " + FormatHexAddress(address) + ", " + logCondition;
            if (!DbgCmdExecDirect(cmd2.c_str()))
            {
                error = "Failed to set the breakpoint log condition";
                return false;
            }
        }

        if (params.contains("singleshoot"))
        {
            bool singleshoot = false;
            if (!GetOptionalBool(params, "singleshoot", singleshoot, error))
                return false;
            const std::string cmd2 = "SetBreakpointSingleshoot " + FormatHexAddress(address) + ", " +
                (singleshoot ? "1" : "0");
            if (!DbgCmdExecDirect(cmd2.c_str()))
            {
                error = "Failed to set the breakpoint singleshoot flag";
                return false;
            }
        }

        if (params.contains("silent"))
        {
            bool silent = false;
            if (!GetOptionalBool(params, "silent", silent, error))
                return false;
            const std::string cmd2 = "SetBreakpointSilent " + FormatHexAddress(address) + ", " + (silent ? "1" : "0");
            if (!DbgCmdExecDirect(cmd2.c_str()))
            {
                error = "Failed to set the breakpoint silent flag";
                return false;
            }
        }

        return true;
    }
    catch (...)
    {
        error = "Internal error while setting the breakpoint";
        return false;
    }
}

bool ManageBreakpoint(const std::string& action, unsigned long long address, std::string& error)
{
    try
    {
        if (!RequireDebugging(error))
            return false;

        std::string cmdName;
        if (action == "delete")
            cmdName = "DeleteBPX";
        else if (action == "enable")
            cmdName = "EnableBPX";
        else if (action == "disable")
            cmdName = "DisableBPX";
        else
        {
            error = "Unknown breakpoint action \"" + action + "\": expected one of delete, enable, disable";
            return false;
        }

        const std::string cmd = cmdName + " " + FormatHexAddress(address);
        if (!DbgCmdExecDirect(cmd.c_str()))
        {
            error = "Failed to " + action + " the breakpoint at the given address";
            return false;
        }
        return true;
    }
    catch (...)
    {
        error = "Internal error while managing the breakpoint";
        return false;
    }
}

bool ListBreakpoints(std::vector<BreakpointInfo>& out, std::string& error)
{
    out.clear();
    try
    {
        if (!RequireDebugging(error))
            return false;

        auto* functions = DbgFunctions();
        if (!functions || !functions->BpRefList || !functions->BpGetFieldNumber || !functions->BpGetFieldText)
        {
            error = "Breakpoint listing is not supported by this x64dbg build";
            return false;
        }

        duint count = 0;
        BP_REF* refs = functions->BpRefList(&count);

        // BpRefList allocates memory via BridgeAlloc (see the implementation in
        // external/x64dbg/src/dbg/_dbgfunctions.cpp); the reference consumer of
        // this same function within x64dbg itself — src/gui/Src/Gui/BreakpointsView.cpp —
        // frees the result strictly through BridgeFree, so we do the same.
        struct RefsGuard
        {
            BP_REF* ptr;
            ~RefsGuard() { if (ptr) BridgeFree(ptr); }
        } guard{refs};

        out.reserve(count);
        for (duint i = 0; i < count; ++i)
        {
            const BP_REF& ref = refs[i];
            BreakpointInfo info;

            duint address = 0;
            if (functions->BpGetFieldNumber(&ref, bpf_address, &address))
                info.address = static_cast<unsigned long long>(address);

            info.type = BpxTypeToString(ref.type);

            duint enabled = 0;
            if (functions->BpGetFieldNumber(&ref, bpf_enabled, &enabled))
                info.enabled = enabled != 0;

            duint singleShot = 0;
            if (functions->BpGetFieldNumber(&ref, bpf_singleshoot, &singleShot))
                info.singleShot = singleShot != 0;

            duint hitCount = 0;
            if (functions->BpGetFieldNumber(&ref, bpf_hitcount, &hitCount))
                info.hitCount = static_cast<unsigned int>(hitCount);

            CollectBpFieldText(ref, bpf_module, info.module);
            CollectBpFieldText(ref, bpf_name, info.name);

            out.push_back(std::move(info));
        }
        return true;
    }
    catch (...)
    {
        out.clear();
        error = "Internal error while listing breakpoints";
        return false;
    }
}

bool ListModules(std::vector<ModuleEntry>& out, std::string& error)
{
    out.clear();
    try
    {
        if (!RequireDebugging(error))
            return false;

        // BridgeList cleans up and frees its own data in its destructor —
        // no need to manually free the module list.
        BridgeList<Script::Module::ModuleInfo> modules;
        if (!Script::Module::GetList(&modules))
        {
            error = "Failed to retrieve the module list";
            return false;
        }

        out.reserve(modules.Count());
        for (int i = 0; i < modules.Count(); ++i)
        {
            const auto& mod = modules[i];
            ModuleEntry entry;
            entry.base = static_cast<unsigned long long>(mod.base);
            entry.size = static_cast<unsigned long long>(mod.size);
            entry.entry = static_cast<unsigned long long>(mod.entry);
            entry.sectionCount = mod.sectionCount;
            entry.name = mod.name;
            entry.path = mod.path;
            out.push_back(std::move(entry));
        }
        return true;
    }
    catch (...)
    {
        out.clear();
        error = "Internal error while listing modules";
        return false;
    }
}

bool GetModuleDetails(const std::string& name, unsigned long long address, bool byAddress,
                      bool includeExports, bool includeImports,
                      ModuleDetails& out, std::string& error)
{
    out = ModuleDetails{};
    try
    {
        if (!RequireDebugging(error))
            return false;

        Script::Module::ModuleInfo info = {};
        const bool found = byAddress
            ? Script::Module::InfoFromAddr(static_cast<duint>(address), &info)
            : Script::Module::InfoFromName(name.c_str(), &info);
        if (!found)
        {
            error = byAddress
                ? "No loaded module contains the given address"
                : "Module \"" + name + "\" is not loaded";
            return false;
        }

        out.module.base = static_cast<unsigned long long>(info.base);
        out.module.size = static_cast<unsigned long long>(info.size);
        out.module.entry = static_cast<unsigned long long>(info.entry);
        out.module.sectionCount = info.sectionCount;
        out.module.name = info.name;
        out.module.path = info.path;

        // BridgeList cleans up and frees its own data in its destructor.
        BridgeList<Script::Module::ModuleSectionInfo> sections;
        if (Script::Module::SectionListFromName(info.name, &sections))
        {
            out.sections.reserve(sections.Count());
            for (int i = 0; i < sections.Count(); ++i)
            {
                SectionEntry section;
                section.address = static_cast<unsigned long long>(sections[i].addr);
                section.size = static_cast<unsigned long long>(sections[i].size);
                section.name = sections[i].name;
                out.sections.push_back(std::move(section));
            }
        }

        if (includeExports)
        {
            BridgeList<Script::Module::ModuleExport> exports;
            if (Script::Module::GetExports(&info, &exports))
            {
                const int count = exports.Count();
                const int limit = count > static_cast<int>(kMaxExports) ? static_cast<int>(kMaxExports) : count;
                out.exportsTruncated = count > static_cast<int>(kMaxExports);
                out.exports.reserve(limit);
                for (int i = 0; i < limit; ++i)
                {
                    ExportEntry item;
                    item.ordinal = static_cast<unsigned long long>(exports[i].ordinal);
                    item.rva = static_cast<unsigned long long>(exports[i].rva);
                    item.va = static_cast<unsigned long long>(exports[i].va);
                    item.forwarded = exports[i].forwarded;
                    item.name = exports[i].name;
                    item.forwardName = exports[i].forwardName;
                    out.exports.push_back(std::move(item));
                }
            }
        }

        if (includeImports)
        {
            BridgeList<Script::Module::ModuleImport> imports;
            if (Script::Module::GetImports(&info, &imports))
            {
                const int count = imports.Count();
                const int limit = count > static_cast<int>(kMaxImports) ? static_cast<int>(kMaxImports) : count;
                out.importsTruncated = count > static_cast<int>(kMaxImports);
                out.imports.reserve(limit);
                for (int i = 0; i < limit; ++i)
                {
                    ImportEntry item;
                    item.iatRva = static_cast<unsigned long long>(imports[i].iatRva);
                    item.iatVa = static_cast<unsigned long long>(imports[i].iatVa);
                    item.ordinal = static_cast<unsigned long long>(imports[i].ordinal);
                    item.name = imports[i].name;
                    out.imports.push_back(std::move(item));
                }
            }
        }

        return true;
    }
    catch (...)
    {
        error = "Internal error while retrieving module details";
        return false;
    }
}

bool GetMemoryMap(std::vector<MemoryRegion>& out, std::string& error)
{
    out.clear();
    try
    {
        if (!RequireDebugging(error))
            return false;

        MEMMAP memoryMap = {};
        if (!DbgMemMap(&memoryMap))
        {
            error = "Failed to retrieve the memory map";
            return false;
        }

        // DbgMemMap allocates memoryMap.page via BridgeAlloc, not through
        // ListInfo/BridgeList — it must be freed manually, the same way the
        // reference consumer of this function does it,
        // external/x64dbg/src/gui/Src/Gui/MemoryMapView.cpp.
        struct MapGuard
        {
            MEMMAP* map;
            ~MapGuard() { if (map->page) BridgeFree(map->page); }
        } guard{&memoryMap};

        out.reserve(memoryMap.count);
        for (int i = 0; i < memoryMap.count; ++i)
        {
            const MEMPAGE& page = memoryMap.page[i];
            MemoryRegion region;
            region.base = static_cast<unsigned long long>(reinterpret_cast<duint>(page.mbi.BaseAddress));
            region.allocationBase = static_cast<unsigned long long>(reinterpret_cast<duint>(page.mbi.AllocationBase));
            region.size = static_cast<unsigned long long>(page.mbi.RegionSize);
            region.state = MemStateToString(page.mbi.State);
            region.type = MemTypeToString(page.mbi.Type);

            char rights[RIGHTS_STRING_SIZE] = {};
            if (DbgFunctions()->PageRightsToString(page.mbi.Protect, rights))
                region.protect = rights;

            region.info = page.info;
            out.push_back(std::move(region));
        }
        return true;
    }
    catch (...)
    {
        out.clear();
        error = "Internal error while retrieving the memory map";
        return false;
    }
}

bool ListThreads(std::vector<ThreadEntry>& out, std::string& error)
{
    out.clear();
    try
    {
        if (!RequireDebugging(error))
            return false;

        THREADLIST threadList = {};
        DbgGetThreadList(&threadList);

        // DbgGetThreadList allocates threadList.list via BridgeAlloc;
        // the reference consumer — external/x64dbg/src/gui/Src/Gui/ThreadView.cpp —
        // frees the result through BridgeFree, so we do the same.
        struct ListGuard
        {
            THREADLIST* list;
            ~ListGuard() { if (list->list) BridgeFree(list->list); }
        } guard{&threadList};

        out.reserve(threadList.count);
        for (int i = 0; i < threadList.count; ++i)
        {
            const THREADALLINFO& info = threadList.list[i];
            ThreadEntry entry;
            entry.id = static_cast<unsigned int>(info.BasicInfo.ThreadId);
            entry.number = info.BasicInfo.ThreadNumber;
            entry.entry = static_cast<unsigned long long>(info.BasicInfo.ThreadStartAddress);
            entry.teb = static_cast<unsigned long long>(info.BasicInfo.ThreadLocalBase);
            entry.cip = static_cast<unsigned long long>(info.ThreadCip);
            entry.suspendCount = static_cast<unsigned int>(info.SuspendCount);
            entry.lastError = static_cast<unsigned int>(info.LastError);
            entry.name = info.BasicInfo.threadName;
            entry.priority = ThreadPriorityToString(info.Priority);
            entry.waitReason = ThreadWaitReasonToString(info.WaitReason);
            entry.current = (i == threadList.CurrentThread);
            out.push_back(std::move(entry));
        }
        return true;
    }
    catch (...)
    {
        out.clear();
        error = "Internal error while listing threads";
        return false;
    }
}

bool ReadRegisters(bool includeSimd, RegisterDump& out, std::string& error)
{
    out = RegisterDump{};
    try
    {
        if (!RequirePaused("reading registers", error))
            return false;

        REGDUMP_AVX512 dump = {};
        if (!DbgGetRegDumpEx(&dump, sizeof(dump)))
        {
            error = "Failed to read the register dump";
            return false;
        }

        const auto& ctx = dump.regcontext;
#ifdef _WIN64
        out.general = {
            {"rax", ctx.cax}, {"rbx", ctx.cbx}, {"rcx", ctx.ccx}, {"rdx", ctx.cdx},
            {"rsi", ctx.csi}, {"rdi", ctx.cdi}, {"rbp", ctx.cbp}, {"rsp", ctx.csp},
            {"r8", ctx.r8}, {"r9", ctx.r9}, {"r10", ctx.r10}, {"r11", ctx.r11},
            {"r12", ctx.r12}, {"r13", ctx.r13}, {"r14", ctx.r14}, {"r15", ctx.r15},
            {"rip", ctx.cip}
        };
#else
        out.general = {
            {"eax", ctx.cax}, {"ebx", ctx.cbx}, {"ecx", ctx.ccx}, {"edx", ctx.cdx},
            {"esi", ctx.csi}, {"edi", ctx.cdi}, {"ebp", ctx.cbp}, {"esp", ctx.csp},
            {"eip", ctx.cip}
        };
#endif
        out.segment = {
            {"gs", ctx.gs}, {"fs", ctx.fs}, {"es", ctx.es}, {"ds", ctx.ds}, {"cs", ctx.cs}, {"ss", ctx.ss}
        };
        out.debugRegs = {
            {"dr0", ctx.dr0}, {"dr1", ctx.dr1}, {"dr2", ctx.dr2}, {"dr3", ctx.dr3}, {"dr6", ctx.dr6}, {"dr7", ctx.dr7}
        };

        out.eflags = static_cast<unsigned long long>(ctx.eflags);
        // Standard x86 flags register layout: CF(0), PF(2), AF(4),
        // ZF(6), SF(7), TF(8), IF(9), DF(10), OF(11).
        auto bit = [&](int n) { return (out.eflags & (1ull << n)) != 0; };
        out.flags = {
            {"CF", bit(0)}, {"PF", bit(2)}, {"AF", bit(4)}, {"ZF", bit(6)}, {"SF", bit(7)},
            {"TF", bit(8)}, {"IF", bit(9)}, {"DF", bit(10)}, {"OF", bit(11)}
        };

        // SIMD registers are only included on request: sixteen 128-bit
        // values noticeably bloat the response, and they're rarely needed.
        if (includeSimd)
        {
#ifdef _WIN64
            constexpr int kXmmCount = 16;
#else
            constexpr int kXmmCount = 8;
#endif
            for (int i = 0; i < kXmmCount; ++i)
            {
                // The low 128 bits of a ZMM register are exactly the classic XMM.
                const XMMREGISTER& xmm = ctx.ZmmRegisters[i].Low.Low;
                out.simd.emplace_back("xmm" + std::to_string(i), FormatXmmHex(xmm));
            }
        }

        out.lastError = static_cast<unsigned int>(dump.lastError);
        out.lastStatus = static_cast<unsigned int>(dump.lastStatus);
        return true;
    }
    catch (...)
    {
        out = RegisterDump{};
        error = "Internal error while reading registers";
        return false;
    }
}

bool GetCallStack(unsigned int threadId, std::vector<CallStackFrame>& out, std::string& error)
{
    out.clear();
    try
    {
        if (!RequirePaused("reading the call stack", error))
            return false;

        DBGCALLSTACK callstack = {};
        if (threadId == 0)
        {
            DbgFunctions()->GetCallStackEx(&callstack, false);
        }
        else
        {
            THREADLIST threadList = {};
            DbgGetThreadList(&threadList);

            // See the analogous BridgeFree cleanup in ListThreads.
            struct ListGuard
            {
                THREADLIST* list;
                ~ListGuard() { if (list->list) BridgeFree(list->list); }
            } listGuard{&threadList};

            HANDLE handle = nullptr;
            for (int i = 0; i < threadList.count; ++i)
            {
                if (static_cast<unsigned int>(threadList.list[i].BasicInfo.ThreadId) == threadId)
                {
                    handle = threadList.list[i].BasicInfo.Handle;
                    break;
                }
            }
            if (!handle)
            {
                error = "No thread with id " + std::to_string(threadId) + " was found";
                return false;
            }

            DbgFunctions()->GetCallStackByThread(handle, &callstack);
        }

        // GetCallStackEx/GetCallStackByThread allocate callstack.entries via
        // BridgeAlloc; the reference consumer — external/x64dbg/src/gui/Src/Gui/CallStackView.cpp —
        // frees the result through BridgeFree, so we do the same.
        struct CallStackGuard
        {
            DBGCALLSTACK* stack;
            ~CallStackGuard() { if (stack->entries) BridgeFree(stack->entries); }
        } csGuard{&callstack};

        out.reserve(static_cast<size_t>(callstack.total));
        for (int i = 0; i < callstack.total; ++i)
        {
            const DBGCALLSTACKENTRY& entry = callstack.entries[i];
            CallStackFrame frame;
            frame.address = static_cast<unsigned long long>(entry.addr);
            frame.from = static_cast<unsigned long long>(entry.from);
            frame.to = static_cast<unsigned long long>(entry.to);
            frame.comment = entry.comment;
            out.push_back(std::move(frame));
        }
        return true;
    }
    catch (...)
    {
        out.clear();
        error = "Internal error while reading the call stack";
        return false;
    }
}

bool ReadStack(size_t count, std::vector<StackSlot>& out, std::string& error)
{
    out.clear();
    try
    {
        if (!RequirePaused("reading the stack", error))
            return false;
        if (count < kMinStackSlots || count > kMaxStackSlots)
        {
            error = "Parameter \"count\" must be between 1 and 256";
            return false;
        }

        bool success = false;
        const duint sp = DbgEval("csp", &success);
        if (!success)
        {
            error = "Failed to determine the current stack pointer";
            return false;
        }

        out.reserve(count);
        for (size_t i = 0; i < count; ++i)
        {
            const duint addr = sp + static_cast<duint>(i * sizeof(duint));
            StackSlot slot;
            slot.address = static_cast<unsigned long long>(addr);

            duint value = 0;
            if (DbgMemRead(addr, &value, sizeof(value)))
                slot.value = static_cast<unsigned long long>(value);

            STACK_COMMENT comment = {};
            if (DbgStackCommentGet(addr, &comment))
                slot.comment = comment.comment;

            out.push_back(std::move(slot));
        }
        return true;
    }
    catch (...)
    {
        out.clear();
        error = "Internal error while reading the stack";
        return false;
    }
}

bool ReadStringAt(unsigned long long address, std::string& out, std::string& error)
{
    out.clear();
    try
    {
        if (!RequirePaused("reading a string", error))
            return false;

        char text[MAX_STRING_SIZE] = {};
        if (!DbgGetStringAt(static_cast<duint>(address), text))
        {
            error = "The debugger did not recognize a string at the given address";
            return false;
        }
        out = text;
        return true;
    }
    catch (...)
    {
        out.clear();
        error = "Internal error while reading a string";
        return false;
    }
}

bool EvaluateExpression(const std::string& expression, EvalResult& out, std::string& error)
{
    out = EvalResult{};
    try
    {
        if (!RequireDebugging(error))
            return false;

        if (!DbgIsValidExpression(expression.c_str()))
        {
            error = "Expression is not syntactically valid";
            return false;
        }

        bool success = false;
        const duint value = DbgEval(expression.c_str(), &success);
        if (!success)
        {
            error = "Failed to evaluate the expression";
            return false;
        }

        out.value = static_cast<unsigned long long>(value);
        out.pointerValid = DbgMemIsValidReadPtr(static_cast<duint>(value));
        return true;
    }
    catch (...)
    {
        out = EvalResult{};
        error = "Internal error while evaluating the expression";
        return false;
    }
}

bool FindPattern(unsigned long long start, unsigned long long size, const std::string& pattern,
                 size_t maxResults, std::vector<unsigned long long>& out, bool& truncated, std::string& error)
{
    out.clear();
    truncated = false;
    try
    {
        if (!RequirePaused("reading memory for a pattern", error))
            return false;

        if (pattern.empty() || !LooksLikeValidPattern(pattern))
        {
            error = "Pattern is empty or not a valid hex/wildcard byte signature";
            return false;
        }
        if (size == 0)
        {
            error = "Search range size must be greater than zero";
            return false;
        }
        if (size > kMaxPatternRangeSize)
        {
            error = "Search range size exceeds the maximum of 256 MiB";
            return false;
        }
        if (maxResults == 0 || maxResults > kMaxPatternResults)
        {
            error = "Parameter \"max_results\" must be between 1 and 256";
            return false;
        }

        duint cursor = static_cast<duint>(start);
        const duint rangeEnd = static_cast<duint>(start + size);
        while (cursor < rangeEnd && out.size() < maxResults)
        {
            const duint remaining = rangeEnd - cursor;
            const duint found = Script::Pattern::FindMem(cursor, remaining, pattern.c_str());
            if (found == 0)
                break; // no more matches, or this part of memory is unreadable

            out.push_back(static_cast<unsigned long long>(found));
            cursor = found + 1; // continue from the byte after the one found
        }

        // If the limit was reached, separately check the remaining range for
        // one more match, so truncated reflects reality rather than just
        // the fact that the limit was hit.
        if (out.size() >= maxResults && cursor < rangeEnd)
            truncated = Script::Pattern::FindMem(cursor, rangeEnd - cursor, pattern.c_str()) != 0;

        return true;
    }
    catch (...)
    {
        out.clear();
        truncated = false;
        error = "Internal error while searching for the pattern";
        return false;
    }
}

bool GetXrefs(unsigned long long address, std::vector<XrefEntry>& out, std::string& error)
{
    out.clear();
    try
    {
        if (!RequirePaused("reading cross-references", error))
            return false;

        // DbgXrefGet's own handler treats "zero references" as failure (see
        // external/x64dbg/src/dbg/_exports.cpp:1402-1414: it computes the
        // count first, and returns false precisely when that count is
        // zero). So a false return there does not mean an error; it means
        // there are no cross-references, which is a normal, successful
        // result with an empty list. Check the count ourselves first to
        // tell that apart from a real failure.
        const size_t refCount = DbgGetXrefCountAt(static_cast<duint>(address));
        if (refCount == 0)
            return true;

        XREF_INFO xrefInfo{};
        xrefInfo.refcount = 0;
        xrefInfo.references = nullptr;

        if (!DbgXrefGet(static_cast<duint>(address), &xrefInfo))
        {
            error = "Failed to retrieve cross-references for the given address";
            return false;
        }

        // See the analogous BridgeFree cleanup in other functions in this
        // file; confirmed in
        // external/x64dbg/src/gui/Src/Gui/CPUInfoBox.cpp:490-494 and
        // external/x64dbg/src/gui/Src/BasicView/Disassembly.cpp:1625.
        struct XrefGuard
        {
            XREF_INFO* info;
            ~XrefGuard() { if (info->references) BridgeFree(info->references); }
        } guard{&xrefInfo};

        out.reserve(static_cast<size_t>(xrefInfo.refcount));
        for (duint i = 0; i < xrefInfo.refcount; ++i)
        {
            const XREF_RECORD& record = xrefInfo.references[i];
            XrefEntry entry;
            entry.address = static_cast<unsigned long long>(record.addr);
            entry.type = XrefTypeToString(record.type);
            out.push_back(std::move(entry));
        }
        return true;
    }
    catch (...)
    {
        out.clear();
        error = "Internal error while retrieving cross-references";
        return false;
    }
}

bool GetFunctionRange(unsigned long long address, unsigned long long& start, unsigned long long& end, std::string& error)
{
    start = 0;
    end = 0;
    try
    {
        if (!RequireDebugging(error))
            return false;

        duint funcStart = 0, funcEnd = 0;
        if (!DbgFunctionGet(static_cast<duint>(address), &funcStart, &funcEnd))
        {
            error = "The debugger does not know the function boundaries at the given address: "
                    "running module analysis first may help";
            return false;
        }

        start = static_cast<unsigned long long>(funcStart);
        end = static_cast<unsigned long long>(funcEnd);
        return true;
    }
    catch (...)
    {
        start = 0;
        end = 0;
        error = "Internal error while retrieving the function boundaries";
        return false;
    }
}

bool ListSymbols(unsigned long long moduleAddress, const std::string& filter,
                 size_t maxResults, std::vector<SymbolEntry>& out, bool& truncated,
                 std::string& error)
{
    out.clear();
    truncated = false;
    try
    {
        if (!RequireDebugging(error))
            return false;

        // Resolves moduleAddress to the module's base, reusing the same
        // lookup GetModuleDetails already does, rather than duplicating it.
        ModuleDetails details;
        if (!GetModuleDetails(std::string(), moduleAddress, true, false, false, details, error))
            return false;

        SymbolEnumContext ctx;
        ctx.out = &out;
        ctx.filterLower = ToLowerCopy(filter);
        ctx.cap = (maxResults == 0 || maxResults > kMaxSymbolResults) ? kMaxSymbolResults : maxResults;

        DbgSymbolEnum(static_cast<duint>(details.module.base), &CbSymbolEnum, &ctx);

        truncated = ctx.truncated;
        return true;
    }
    catch (...)
    {
        out.clear();
        truncated = false;
        error = "Internal error while listing symbols";
        return false;
    }
}

bool GetAnnotations(unsigned long long address, Annotations& out, std::string& error)
{
    out = Annotations{};
    try
    {
        if (!RequireDebugging(error))
            return false;

        const duint addr = static_cast<duint>(address);

        // A missing label or comment is not an error, it is an empty string
        // — DbgGetLabelAt/DbgGetCommentAt return false in that case.
        char label[MAX_LABEL_SIZE] = {};
        if (DbgGetLabelAt(addr, SEG_DEFAULT, label))
            out.label = label;

        char comment[MAX_COMMENT_SIZE] = {};
        if (DbgGetCommentAt(addr, comment))
            out.comment = comment;

        out.bookmark = DbgGetBookmarkAt(addr);
        return true;
    }
    catch (...)
    {
        out = Annotations{};
        error = "Internal error while reading annotations";
        return false;
    }
}

bool SetLabel(unsigned long long address, const std::string& text, std::string& error)
{
    try
    {
        if (!RequireDebugging(error))
            return false;

        // An empty text clears the label, see LabelSet in
        // external/x64dbg/src/dbg/label.cpp; DbgSetLabelAt rejects text that
        // is too long or begins with the internal delimiter '\1'.
        if (!DbgSetLabelAt(static_cast<duint>(address), text.c_str()))
        {
            error = "Failed to set the label: text may be too long, or begin with a reserved character";
            return false;
        }
        return true;
    }
    catch (...)
    {
        error = "Internal error while setting the label";
        return false;
    }
}

bool SetComment(unsigned long long address, const std::string& text, std::string& error)
{
    try
    {
        if (!RequireDebugging(error))
            return false;

        // An empty text clears the comment, same as SetLabel.
        if (!DbgSetCommentAt(static_cast<duint>(address), text.c_str()))
        {
            error = "Failed to set the comment: text may be too long, or begin with a reserved character";
            return false;
        }
        return true;
    }
    catch (...)
    {
        error = "Internal error while setting the comment";
        return false;
    }
}

bool SetBookmark(unsigned long long address, bool enabled, std::string& error)
{
    try
    {
        if (!RequireDebugging(error))
            return false;

        if (!DbgSetBookmarkAt(static_cast<duint>(address), enabled))
        {
            error = "Failed to set the bookmark";
            return false;
        }
        return true;
    }
    catch (...)
    {
        error = "Internal error while setting the bookmark";
        return false;
    }
}

bool ExecuteCommand(const std::string& command, bool async, CommandResult& out, std::string& error)
{
    out = CommandResult{};
    try
    {
        if (command.empty())
        {
            error = "Command must not be empty";
            return false;
        }

        // Deliberately no RequireDebugging check here: only some commands
        // need an active session (e.g. analysis does, ClearLog does not),
        // and the debugger itself already rejects what it cannot run —
        // that answer is passed through via out.accepted rather than
        // second-guessed here.
        std::string before, beforeError;
        const bool haveBefore = SnapshotLog(before, beforeError);

        if (async)
        {
            // Queued onto x64dbg's own command thread: DbgCmdExec's return
            // value only reports that the command was accepted into the
            // queue, not that it has run or succeeded. Commands that change
            // execution state (run, StepInto, ...) must go through this
            // path — running them directly on the worker thread could
            // deadlock with or race the debug loop. Callers that need to
            // know the outcome should wait for a pause separately.
            out.accepted = DbgCmdExec(command.c_str());
        }
        else
        {
            out.accepted = DbgCmdExecDirect(command.c_str());
        }

        std::string after, afterError;
        const bool haveAfter = SnapshotLog(after, afterError);
        out.logCaptured = haveBefore && haveAfter;
        if (haveBefore && haveAfter && after.size() > before.size())
            out.output = StripSnapshotNoise(after.substr(before.size()), LogCaptureFilePath());

        return true;
    }
    catch (...)
    {
        error = "Internal error while executing the command";
        return false;
    }
}

bool RunScript(const std::string& scriptText, CommandResult& out, std::string& error)
{
    out = CommandResult{};
    try
    {
        if (scriptText.empty())
        {
            error = "Script text must not be empty";
            return false;
        }

        char tempDir[MAX_PATH] = {};
        if (GetTempPathA(MAX_PATH, tempDir) == 0)
        {
            error = "Failed to determine a temporary directory for the script file";
            return false;
        }
        char scriptPath[MAX_PATH] = {};
        sprintf_s(scriptPath, "%smcp-script-%lu-%llu.txt", tempDir, GetCurrentProcessId(),
                  static_cast<unsigned long long>(GetTickCount64()));

        {
            std::ofstream scriptFile(scriptPath, std::ios::binary);
            if (!scriptFile)
            {
                error = "Failed to create the temporary script file";
                return false;
            }
            scriptFile.write(scriptText.data(), static_cast<std::streamsize>(scriptText.size()));
        }

        std::string before, beforeError;
        const bool haveBefore = SnapshotLog(before, beforeError);

        DbgScriptLoad(scriptPath);
        // destline == 0 runs the whole script from the beginning (same as
        // the "scriptrun" command with no argument, see cbScriptRun in
        // external/x64dbg/src/dbg/commands/cmd-script.cpp).
        DbgScriptRun(0);
        out.accepted = true; // the script was successfully handed to the debugger to run

        // DbgScriptLoad already read the whole file into memory, so it is
        // safe to delete it now even though DbgScriptRun keeps executing
        // asynchronously afterwards.
        DeleteFileA(scriptPath);

        // Script execution is asynchronous: DbgScriptRun queues the run and
        // returns immediately, so out.output only carries whatever log text
        // appeared before this call returned, not the script's full output.
        std::string after, afterError;
        const bool haveAfter = SnapshotLog(after, afterError);
        out.logCaptured = haveBefore && haveAfter;
        if (haveBefore && haveAfter && after.size() > before.size())
            out.output = StripSnapshotNoise(after.substr(before.size()), LogCaptureFilePath());

        return true;
    }
    catch (...)
    {
        error = "Internal error while running the script";
        return false;
    }
}

bool ReadLog(size_t maxLines, std::vector<std::string>& out, bool& truncated, std::string& error)
{
    out.clear();
    truncated = false;
    try
    {
        // Reading the log while capture is not active, or while a snapshot
        // cannot be taken, is not an error: it is a normal situation, and
        // the caller should get an empty result it can reason about, not a
        // failure that looks like the tool is broken.
        std::string contents;
        if (!SnapshotLog(contents, error))
        {
            error.clear();
            return true;
        }

        if (maxLines == 0 || maxLines > kMaxLogLines)
            maxLines = kMaxLogLines;

        const std::string snapshotPathUtf8 = LogCaptureFilePath();
        std::vector<std::string> lines;
        std::istringstream stream(contents);
        std::string line;
        while (std::getline(stream, line))
        {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            if (LineMentionsSnapshotPath(line, snapshotPathUtf8))
                continue; // this mechanism's own bookkeeping, not part of the captured log
            lines.push_back(std::move(line));
        }

        if (lines.size() > maxLines)
        {
            lines.erase(lines.begin(), lines.end() - static_cast<std::ptrdiff_t>(maxLines));
            truncated = true;
        }

        out = std::move(lines);
        return true;
    }
    catch (...)
    {
        out.clear();
        truncated = false;
        error = "Internal error while reading the log";
        return false;
    }
}

bool StartLogCapture(std::string& error)
{
    try
    {
        const wchar_t* userDir = BridgeUserDirectory();
        if (!userDir)
        {
            error = "Failed to determine the user directory for the log capture file";
            return false;
        }

        wchar_t path[MAX_PATH] = {};
        swprintf_s(path, L"%s\\mcp-log-%lu.txt", userDir, GetCurrentProcessId());

        {
            std::lock_guard<std::mutex> lock(g_logCaptureMutex);
            g_logCapture.filePath = path;
        }

        // Take one snapshot now and treat its length as the starting point,
        // so output produced before the server started is not returned as
        // if it were a command's own output.
        std::string contents;
        if (!SnapshotLog(contents, error))
            return false;

        std::lock_guard<std::mutex> lock(g_logCaptureMutex);
        g_logCapture.deliveredBytes = contents.size();
        return true;
    }
    catch (...)
    {
        error = "Internal error while starting log capture";
        return false;
    }
}

void StopLogCapture()
{
    std::lock_guard<std::mutex> lock(g_logCaptureMutex);
    g_logCapture = LogCaptureState{};
}

bool IsLogCaptureActive()
{
    std::lock_guard<std::mutex> lock(g_logCaptureMutex);
    return !g_logCapture.filePath.empty() && g_logCapture.lastSnapshotOk;
}

std::string LogCaptureFilePath()
{
    std::wstring path;
    {
        std::lock_guard<std::mutex> lock(g_logCaptureMutex);
        path = g_logCapture.filePath;
    }
    if (path.empty())
        return {};
    return WideToUtf8(path);
}

bool WriteMemory(unsigned long long address, const std::vector<unsigned char>& data,
                 bool recordPatch, std::string& error)
{
    try
    {
        if (!RequirePaused("writing memory", error))
            return false;
        if (data.empty())
        {
            error = "Data to write must not be empty";
            return false;
        }
        if (data.size() > kMaxReadSize)
        {
            error = "Requested write size exceeds the maximum of 1 MiB";
            return false;
        }

        const duint addr = static_cast<duint>(address);
        // MemPatch records the change in the patch list, which is what makes
        // it undoable (RestorePatches) and exportable to a file
        // (ApplyPatchesToFile); DbgMemWrite writes the bytes directly, with
        // no such bookkeeping.
        const bool ok = recordPatch
            ? DbgFunctions()->MemPatch(addr, data.data(), static_cast<duint>(data.size()))
            : DbgMemWrite(addr, data.data(), static_cast<duint>(data.size()));
        if (!ok)
        {
            error = "Failed to write memory at the given address";
            return false;
        }
        return true;
    }
    catch (...)
    {
        error = "Internal error while writing memory";
        return false;
    }
}

bool SetNamedValue(const std::string& name, unsigned long long value, std::string& error)
{
    try
    {
        if (!RequirePaused("writing a register or variable", error))
            return false;
        if (name.empty())
        {
            error = "Parameter \"name\" must not be empty";
            return false;
        }

        // Not calling DbgValSetScalar directly: the SDK header we compile
        // against is newer than the debuggers people actually run, and this
        // particular function is a case in point — it was named
        // DbgValToString in older builds and only later renamed to
        // DbgValSetScalar. Importing a symbol the host does not export
        // prevents the whole plugin from loading (Windows refuses to
        // resolve the DLL's import table), so instead we go through the
        // "mov" command (alias "set"), which x64dbg resolves at run time
        // and which therefore works across versions regardless of what the
        // installed build exports.
        const std::string cmd = "mov " + name + ", " + FormatHexAddress(value);
        if (!DbgCmdExecDirect(cmd.c_str()))
        {
            error = "The debugger rejected the assignment \"" + name + "\": expected a register name such as "
                    "\"rax\" or \"eax\", or an existing debugger variable; SSE registers are not supported "
                    "through this path";
            return false;
        }
        return true;
    }
    catch (...)
    {
        error = "Internal error while setting the value";
        return false;
    }
}

bool AssembleAt(unsigned long long address, const std::string& instruction,
                bool fillNop, AssembleResult& out, std::string& error)
{
    out = AssembleResult{};
    try
    {
        if (!RequirePaused("assembling an instruction", error))
            return false;
        if (instruction.empty())
        {
            error = "Instruction text must not be empty";
            return false;
        }

        const duint addr = static_cast<duint>(address);
        char errorBuf[MAX_ERROR_SIZE] = {};
        if (!DbgFunctions()->AssembleAtEx(addr, instruction.c_str(), errorBuf, fillNop))
        {
            // The assembler's own message explains exactly what is wrong
            // with the instruction text, so it is surfaced verbatim.
            error = errorBuf[0] ? errorBuf : "The assembler rejected the instruction";
            return false;
        }

        BASIC_INSTRUCTION_INFO basicInfo = {};
        DbgDisasmFastAt(addr, &basicInfo);
        out.size = basicInfo.size > 0 ? static_cast<size_t>(basicInfo.size) : 0;
        return true;
    }
    catch (...)
    {
        out = AssembleResult{};
        error = "Internal error while assembling the instruction";
        return false;
    }
}

bool ListPatches(std::vector<PatchEntry>& out, std::string& error)
{
    out.clear();
    try
    {
        if (!RequireDebugging(error))
            return false;

        std::vector<DBGPATCHINFO> patches;
        if (!FetchPatchList(patches, error))
            return false;

        out.reserve(patches.size());
        for (const auto& patch : patches)
        {
            if (!patch.addr)
                continue;
            PatchEntry entry;
            entry.address = static_cast<unsigned long long>(patch.addr);
            entry.oldByte = patch.oldbyte;
            entry.newByte = patch.newbyte;
            entry.module = patch.mod;
            out.push_back(std::move(entry));
        }
        return true;
    }
    catch (...)
    {
        out.clear();
        error = "Internal error while listing patches";
        return false;
    }
}

bool RestorePatches(unsigned long long address, unsigned long long end, bool hasRange,
                    size_t& restored, std::string& error)
{
    restored = 0;
    try
    {
        if (!RequirePaused("restoring a patch", error))
            return false;

        auto* functions = DbgFunctions();

        if (!hasRange)
        {
            DBGPATCHINFO info = {};
            const bool existed = functions->PatchGetEx(static_cast<duint>(address), &info);
            functions->PatchRestore(static_cast<duint>(address));
            restored = existed ? 1 : 0;
            return true;
        }

        // PatchRestoreRange returns nothing and reports no count, so the
        // number restored is derived by enumerating the patch list before
        // and after and comparing how many fell inside the range.
        std::vector<PatchEntry> before;
        if (!ListPatches(before, error))
            return false;
        size_t beforeInRange = 0;
        for (const auto& patch : before)
            if (patch.address >= address && patch.address < end)
                ++beforeInRange;

        functions->PatchRestoreRange(static_cast<duint>(address), static_cast<duint>(end));

        std::vector<PatchEntry> after;
        if (!ListPatches(after, error))
            return false;
        size_t afterInRange = 0;
        for (const auto& patch : after)
            if (patch.address >= address && patch.address < end)
                ++afterInRange;

        restored = beforeInRange > afterInRange ? beforeInRange - afterInRange : 0;
        return true;
    }
    catch (...)
    {
        restored = 0;
        error = "Internal error while restoring patches";
        return false;
    }
}

bool ApplyPatchesToFile(const std::string& filePath, int& patched, std::string& error)
{
    patched = 0;
    try
    {
        if (!RequireDebugging(error))
            return false;
        if (filePath.empty())
        {
            error = "Parameter \"path\" must not be empty";
            return false;
        }

        std::vector<DBGPATCHINFO> patches;
        if (!FetchPatchList(patches, error))
            return false;

        // Writes a patched copy of the module to filePath; the running
        // process itself is not modified by this call.
        char errorBuf[MAX_ERROR_SIZE] = {};
        const int result = DbgFunctions()->PatchFile(patches.data(), static_cast<int>(patches.size()),
            filePath.c_str(), errorBuf);
        if (result < 0)
        {
            error = errorBuf[0] ? errorBuf : "Failed to apply patches to the file";
            return false;
        }

        patched = result;
        return true;
    }
    catch (...)
    {
        patched = 0;
        error = "Internal error while applying patches to the file";
        return false;
    }
}

bool SetPageProtection(unsigned long long address, const std::string& rights, std::string& error)
{
    try
    {
        if (!RequirePaused("changing page protection", error))
            return false;
        if (rights.empty())
        {
            error = "Parameter \"rights\" must not be empty";
            return false;
        }

        if (!DbgFunctions()->SetPageRights(static_cast<duint>(address), rights.c_str()))
        {
            error = "Failed to set page rights to \"" + rights + "\": expected one of Execute, ExecuteRead, "
                    "ExecuteReadWrite, ExecuteWriteCopy, NoAccess, ReadOnly, ReadWrite, WriteCopy, optionally "
                    "prefixed with \"G\" for a guard page; the current rights of a region can be seen in the memory map";
            return false;
        }
        return true;
    }
    catch (...)
    {
        error = "Internal error while setting page protection";
        return false;
    }
}

bool TraceUntil(const std::string& mode, const std::string& condition, int maxSteps,
                int timeoutMs, ControlResult& out, std::string& error)
{
    out = ControlResult{};
    try
    {
        if (!RequirePaused("tracing", error))
            return false;
        if (mode != "into" && mode != "over")
        {
            error = "Unknown trace mode \"" + mode + "\": expected one of into, over";
            return false;
        }
        if (condition.empty())
        {
            error = "Parameter \"condition\" must not be empty";
            return false;
        }
        if (maxSteps < kMinTraceSteps || maxSteps > kMaxTraceSteps)
        {
            error = "Parameter \"max_steps\" must be between 1 and 10000000";
            return false;
        }

        const int clampedTimeout = ClampTimeout(timeoutMs);
        auto& tracker = McpService::Instance().Tracker();

        const std::string cmdName = (mode == "into") ? "TraceIntoConditional" : "TraceOverConditional";
        const std::string cmd = cmdName + " " + condition + ", " + std::to_string(maxSteps);

        const auto before = tracker.Current().generation;
        DbgCmdExec(cmd.c_str());
        return FinishWithWait(tracker, before, true, clampedTimeout, out);
    }
    catch (...)
    {
        error = "Internal error while tracing";
        return false;
    }
}

bool TraceRecordToFile(bool start, const std::string& filePath, std::string& error)
{
    try
    {
        if (!RequireDebugging(error))
            return false;

        if (start)
        {
            if (filePath.empty())
            {
                error = "Parameter \"path\" must not be empty";
                return false;
            }
            // This only opens the trace file; no instructions are stored
            // until a trace command (e.g. TraceIntoConditional/TraceOverConditional
            // via TraceUntil) actually executes while recording is active.
            const std::string cmd = "StartRunTrace \"" + filePath + "\"";
            if (!DbgCmdExecDirect(cmd.c_str()))
            {
                error = "Failed to start trace recording to \"" + filePath + "\"";
                return false;
            }
        }
        else if (!DbgCmdExecDirect("StopRunTrace"))
        {
            error = "Failed to stop trace recording";
            return false;
        }
        return true;
    }
    catch (...)
    {
        error = "Internal error while controlling trace recording";
        return false;
    }
}

bool RunToUserCode(int timeoutMs, ControlResult& out, std::string& error)
{
    out = ControlResult{};
    try
    {
        if (!RequireDebugging(error))
            return false;

        const int clampedTimeout = ClampTimeout(timeoutMs);
        auto& tracker = McpService::Instance().Tracker();

        const auto before = tracker.Current().generation;
        if (!DbgCmdExec("RunToUserCode"))
        {
            error = "The debugger rejected \"RunToUserCode\": it fails if another such command is already running";
            return false;
        }
        return FinishWithWait(tracker, before, true, clampedTimeout, out);
    }
    catch (...)
    {
        error = "Internal error while running to user code";
        return false;
    }
}

bool EnableCoverage(unsigned long long address, const std::string& granularity, std::string& error)
{
    try
    {
        if (!RequireDebugging(error))
            return false;

        auto* functions = DbgFunctions();
        if (!functions || !functions->SetTraceRecordType)
        {
            error = "Trace record coverage is not supported by this x64dbg build";
            return false;
        }

        TRACERECORDTYPE type;
        if (granularity == "bit")
            type = TraceRecordBitExec;
        else if (granularity == "byte")
            type = TraceRecordByteWithExecTypeAndCounter;
        else if (granularity == "word")
            type = TraceRecordWordWithExecTypeAndCounter;
        else
        {
            error = "Unknown coverage granularity \"" + granularity + "\": expected one of bit, byte, word";
            return false;
        }

        // Trace record state is tracked per memory PAGE: this enables
        // coverage for the whole page containing address, not just the
        // single address given.
        if (!functions->SetTraceRecordType(static_cast<duint>(address), type))
        {
            error = "Failed to enable coverage tracking for the page containing the given address";
            return false;
        }
        return true;
    }
    catch (...)
    {
        error = "Internal error while enabling coverage";
        return false;
    }
}

bool DisableCoverage(unsigned long long address, std::string& error)
{
    try
    {
        if (!RequireDebugging(error))
            return false;

        auto* functions = DbgFunctions();
        if (!functions || !functions->SetTraceRecordType)
        {
            error = "Trace record coverage is not supported by this x64dbg build";
            return false;
        }

        if (!functions->SetTraceRecordType(static_cast<duint>(address), TraceRecordNone))
        {
            error = "Failed to disable coverage tracking for the page containing the given address";
            return false;
        }
        return true;
    }
    catch (...)
    {
        error = "Internal error while disabling coverage";
        return false;
    }
}

bool ReadCoverage(unsigned long long start, unsigned long long size,
                  std::vector<CoverageEntry>& out, bool& truncated, std::string& error)
{
    out.clear();
    truncated = false;
    try
    {
        if (!RequireDebugging(error))
            return false;

        auto* functions = DbgFunctions();
        if (!functions || !functions->GetTraceRecordHitCount || !functions->GetTraceRecordByteType)
        {
            error = "Trace record coverage is not supported by this x64dbg build";
            return false;
        }

        if (size == 0)
        {
            error = "Parameter \"size\" must be greater than zero";
            return false;
        }
        if (size > kMaxCoverageRangeSize)
        {
            error = "Requested coverage range exceeds the maximum of 16 MiB";
            return false;
        }

        const duint rangeStart = static_cast<duint>(start);
        const duint rangeEnd = static_cast<duint>(start + size);
        for (duint addr = rangeStart; addr < rangeEnd; ++addr)
        {
            const unsigned int hits = functions->GetTraceRecordHitCount(addr);
            if (hits == 0)
                continue;

            if (out.size() >= kMaxCoverageEntries)
            {
                truncated = true;
                break;
            }

            CoverageEntry entry;
            entry.address = static_cast<unsigned long long>(addr);
            entry.hitCount = hits;
            entry.byteType = TraceRecordByteTypeToString(functions->GetTraceRecordByteType(addr));
            out.push_back(std::move(entry));
        }
        return true;
    }
    catch (...)
    {
        out.clear();
        truncated = false;
        error = "Internal error while reading coverage";
        return false;
    }
}

} // namespace x64dbg_mcp::plugin
