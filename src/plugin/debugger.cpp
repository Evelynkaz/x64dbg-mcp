#include "plugin/debugger.h"
#include "plugin/plugin.h"
#include "plugin/service.h"
#include "pluginsdk/_scriptapi_module.h"
#include "pluginsdk/_scriptapi_pattern.h"

#include <chrono>
#include <iomanip>
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
// restriction for cip in GetStatus).
bool RequirePaused(const char* what, std::string& error)
{
    if (!RequireDebugging(error))
        return false;
    if (DbgIsRunning())
    {
        error = std::string("The process is currently running: pause it before reading ") + what;
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
        if (!RequirePaused("registers", error))
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
        if (!RequirePaused("the call stack", error))
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
        if (!RequirePaused("the stack", error))
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
        if (!RequirePaused("a string", error))
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
        if (!RequirePaused("memory for a pattern", error))
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
        if (!RequirePaused("cross-references", error))
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

} // namespace x64dbg_mcp::plugin
