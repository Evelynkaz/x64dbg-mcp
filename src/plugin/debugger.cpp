#include "plugin/debugger.h"
#include "plugin/plugin.h"
#include "plugin/service.h"
#include "pluginsdk/_scriptapi_module.h"

#include <chrono>
#include <iomanip>
#include <sstream>
#include <thread>

namespace x64dbg_mcp::plugin
{

namespace
{

// Приводит timeoutMs к диапазону по умолчанию: <=0 значит "не задан" —
// подставляется значение по умолчанию, а всё, что превышает верхний
// предел, обрезается до него.
int ClampTimeout(int timeoutMs)
{
    if (timeoutMs <= 0)
        return kDefaultControlTimeoutMs;
    if (timeoutMs > kMaxControlTimeoutMs)
        return kMaxControlTimeoutMs;
    return timeoutMs;
}

// ВАЖНО: в командах x64dbg аргументы разделяются ЗАПЯТОЙ, а не пробелом —
// пробелом отделяется только имя команды от первого аргумента (см.
// комментарий "arguments are separated by a COMMA (not space like WinDbg)"
// в external/PluginTemplate/src/plugin.cpp и разбор argv[] по запятой в
// external/x64dbg/src/dbg/commands/cmd-breakpoint-control.cpp). Команды с
// одним аргументом (StepInto, StepOut, run, DeleteBPX и т.п.) этого не
// затрагивают — разделять внутри одного аргумента нечего.

// Адреса в командах x64dbg передаются в шестнадцатеричном виде.
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

// Общий хвост операций, отправивших асинхронную команду и опционально
// ждущих последующую паузу: заполняет ControlResult по результату ожидания
// (или немедленно, если ожидание не требуется).
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

// Регистры, стек вызовов и содержимое стека осмысленны только когда процесс
// стоит на паузе: во время выполнения они меняются в произвольный момент, и
// x64dbg вернул бы устаревший или произвольный снимок (см. аналогичное
// ограничение для cip в GetStatus).
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

// Форматирует 128-битное значение XMM-регистра как шестнадцатеричную строку
// из 32 символов, старшая часть первой.
std::string FormatXmmHex(const XMMREGISTER& xmm)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0')
        << std::setw(16) << static_cast<unsigned long long>(xmm.High)
        << std::setw(16) << static_cast<unsigned long long>(xmm.Low);
    return out.str();
}

// Читает необязательное строковое поле. Возвращает false, если поле есть,
// но имеет неверный тип.
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

// Названия элементов взяты дословно из THREADPRIORITY (bridgemain.h) без
// ведущего подчёркивания.
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

// Названия элементов взяты дословно из THREADWAITREASON (bridgemain.h) без
// ведущего подчёркивания.
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

        // cip осмысленен только когда процесс стоит на паузе — во время
        // выполнения DbgEval мог бы вернуть устаревшее или произвольное
        // значение, поэтому оставляем 0, как и задокументировано в заголовке.
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
                break; // дальше по этому адресу нечего разбирать — отдаём то, что успели

            BASIC_INSTRUCTION_INFO basicInfo = {};
            DbgDisasmFastAt(addr, &basicInfo);
            if (basicInfo.size <= 0)
                break; // размер инструкции неизвестен — прекращаем разбор

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
            // "stop" не переводит процесс в паузу, поэтому WaitForPauseAfter
            // здесь неприменим — просто отдаём состояние сразу после отправки команды.
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

            // Ждём именно ОТСУТСТВИЯ сессии отладки, а не паузы: в DebugStateTracker
            // есть уведомление о завершении отладки, но само по себе оно не гарантирует,
            // что процесс уже завершился и путь свободен для повторной загрузки —
            // поэтому опрашиваем DbgIsDebugging() напрямую с небольшим шагом.
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
            // StepOver не принимает количество шагов, поэтому повторяем команду
            // в цикле, каждый раз дожидаясь фактической остановки перед
            // следующей итерацией — иначе шаги отправятся в очередь, не
            // дожидаясь друг друга, и часть из них будет потеряна или
            // выполнена не с того места.
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

        // Если процесс уже стоит на паузе, возвращаемся немедленно: ждать
        // поколение "строго больше текущего" здесь не нужно — текущая пауза
        // и есть та, которую ожидает вызывающий.
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

        // Дополнительные настройки применяются отдельными командами к уже
        // созданной точке останова, поэтому её сперва нужно найти по адресу.
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

        // BpRefList выделяет память через BridgeAlloc (см. реализацию в
        // external/x64dbg/src/dbg/_dbgfunctions.cpp); эталонный потребитель
        // этой же функции внутри самого x64dbg — src/gui/Src/Gui/BreakpointsView.cpp —
        // освобождает результат строго через BridgeFree, поэтому делаем так же.
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

        // BridgeList сам чистит и освобождает свои данные в деструкторе —
        // вручную освобождать список модулей не нужно.
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

        // BridgeList сам чистит и освобождает свои данные в деструкторе.
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

        // DbgMemMap выделяет memoryMap.page через BridgeAlloc, а не через
        // ListInfo/BridgeList — освобождать нужно вручную, как это делает
        // эталонный потребитель этой функции,
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

        // DbgGetThreadList выделяет threadList.list через BridgeAlloc;
        // эталонный потребитель — external/x64dbg/src/gui/Src/Gui/ThreadView.cpp —
        // освобождает результат через BridgeFree, поэтому делаем так же.
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
        // Стандартная раскладка регистра флагов x86: CF(0), PF(2), AF(4),
        // ZF(6), SF(7), TF(8), IF(9), DF(10), OF(11).
        auto bit = [&](int n) { return (out.eflags & (1ull << n)) != 0; };
        out.flags = {
            {"CF", bit(0)}, {"PF", bit(2)}, {"AF", bit(4)}, {"ZF", bit(6)}, {"SF", bit(7)},
            {"TF", bit(8)}, {"IF", bit(9)}, {"DF", bit(10)}, {"OF", bit(11)}
        };

        // SIMD-регистры включаются только по запросу: шестнадцать 128-битных
        // значений заметно раздувают ответ, а нужны они редко.
        if (includeSimd)
        {
#ifdef _WIN64
            constexpr int kXmmCount = 16;
#else
            constexpr int kXmmCount = 8;
#endif
            for (int i = 0; i < kXmmCount; ++i)
            {
                // Младшие 128 бит ZMM-регистра — это и есть классический XMM.
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

            // См. аналогичное освобождение через BridgeFree в ListThreads.
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

        // GetCallStackEx/GetCallStackByThread выделяют callstack.entries через
        // BridgeAlloc; эталонный потребитель — external/x64dbg/src/gui/Src/Gui/CallStackView.cpp —
        // освобождает результат через BridgeFree, поэтому делаем так же.
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

} // namespace x64dbg_mcp::plugin
