#include "plugin/service.h"
#include "plugin/debugger.h"
#include "plugin/plugin.h"
#include "common/ipc_protocol.h"
#include "nlohmann/json.hpp"

#include <cstdio>
#include <memory>

// GetCurrentProcessId is used for the fallback pipe name; windows.h is
// already pulled in transitively via plugin.h -> bridgemain.h.

namespace x64dbg_mcp::plugin
{

namespace
{

// Default timeout for a single call into DebuggerWorker.
constexpr int kDefaultTimeoutMs = 5000;

// Extra time on top of the pause-wait timeout that DebuggerWorker::Submit is
// given for queuing the task. The pause-wait timeout (up to 300000 ms, see
// debugger.h) lives entirely INSIDE the task, so Submit must wait longer —
// otherwise it would return Timeout before the task actually finishes, even
// though the debugger is still working.
constexpr int kWaitSubmitSlackMs = 5000;

// Mirrors the timeout clamp from debugger.cpp (there it applies to the pause
// wait itself), so the timeout for queuing the task is computed correctly here.
int ClampControlTimeout(int timeoutMs)
{
    if (timeoutMs <= 0)
        return kDefaultControlTimeoutMs;
    if (timeoutMs > kMaxControlTimeoutMs)
        return kMaxControlTimeoutMs;
    return timeoutMs;
}

std::string BytesToHex(const std::vector<unsigned char>& bytes)
{
    static const char kDigits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(bytes.size() * 2);
    for (unsigned char b : bytes)
    {
        hex.push_back(kDigits[b >> 4]);
        hex.push_back(kDigits[b & 0x0F]);
    }
    return hex;
}

// Parses a hex byte string tolerant of spaces between bytes, e.g. "90 90"
// or "9090". Rejects anything left over after removing spaces that is not
// an even number of hex digits.
bool BytesFromHex(const std::string& text, std::vector<unsigned char>& out, std::string& error)
{
    out.clear();
    std::string compact;
    compact.reserve(text.size());
    for (char ch : text)
    {
        if (ch != ' ')
            compact.push_back(ch);
    }

    static const std::string kFormatError =
        "Parameter \"data\" must be a hex byte string with an even number of hex digits, "
        "spaces between bytes allowed, e.g. \"90 90\" or \"9090\"";
    if (compact.empty() || compact.size() % 2 != 0)
    {
        error = kFormatError;
        return false;
    }

    auto hexValue = [](char ch) -> int
    {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
    };

    out.reserve(compact.size() / 2);
    for (size_t i = 0; i < compact.size(); i += 2)
    {
        const int hi = hexValue(compact[i]);
        const int lo = hexValue(compact[i + 1]);
        if (hi < 0 || lo < 0)
        {
            out.clear();
            error = kFormatError;
            return false;
        }
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

std::string BuildErrorResponse(const nlohmann::json& id, ipc::ErrorCode code, const std::string& message)
{
    nlohmann::json response;
    response[ipc::kFieldId] = id;
    response[ipc::kFieldOk] = false;
    response[ipc::kFieldError] = {
        {ipc::kFieldErrorCode, static_cast<int>(code)},
        {ipc::kFieldErrorMessage, message}
    };
    return response.dump();
}

std::string BuildOkResponse(const nlohmann::json& id, const nlohmann::json& result)
{
    nlohmann::json response;
    response[ipc::kFieldId] = id;
    response[ipc::kFieldOk] = true;
    response[ipc::kFieldResult] = result;
    return response.dump();
}

// Translates a DebuggerWorker::Submit result into a protocol error code and
// message. Returns true if the task ran and the result can be used.
bool TranslateSubmitResult(DebuggerWorker::SubmitResult result, ipc::ErrorCode& code, std::string& message)
{
    switch (result)
    {
    case DebuggerWorker::SubmitResult::Completed:
        return true;
    case DebuggerWorker::SubmitResult::Timeout:
        code = ipc::ErrorCode::Timeout;
        message = "Debugger worker did not respond within the timeout";
        return false;
    default:
        // NotRunning, Rejected, SelfSubmit — all three indicate that the
        // plugin is currently unable to service the request, not that the
        // request itself is malformed.
        code = ipc::ErrorCode::Internal;
        message = "Debugger worker is not available to process the request";
        return false;
    }
}

// Extracts a non-negative integer from params. On error, fills error with an
// English message naming the parameter.
bool GetUint64Param(const nlohmann::json& params, const char* name, unsigned long long& out, std::string& error)
{
    if (!params.is_object() || !params.contains(name))
    {
        error = std::string("Missing required parameter \"") + name + "\"";
        return false;
    }
    const nlohmann::json& value = params[name];
    if (!value.is_number_integer())
    {
        error = std::string("Parameter \"") + name + "\" must be an integer";
        return false;
    }
    if (value.is_number_unsigned())
    {
        out = value.get<unsigned long long>();
        return true;
    }
    const long long signedValue = value.get<long long>();
    if (signedValue < 0)
    {
        error = std::string("Parameter \"") + name + "\" must not be negative";
        return false;
    }
    out = static_cast<unsigned long long>(signedValue);
    return true;
}

// Extracts an optional integer from params. A missing parameter is not an
// error, defaultValue is used instead.
bool GetOptionalIntParam(const nlohmann::json& params, const char* name, int defaultValue, int& out, std::string& error)
{
    if (!params.is_object() || !params.contains(name))
    {
        out = defaultValue;
        return true;
    }
    if (!params[name].is_number_integer())
    {
        error = std::string("Parameter \"") + name + "\" must be an integer";
        return false;
    }
    out = params[name].get<int>();
    return true;
}

// Extracts an optional boolean from params. A missing parameter is not an
// error, defaultValue is used instead.
bool GetOptionalBoolParam(const nlohmann::json& params, const char* name, bool defaultValue, bool& out, std::string& error)
{
    if (!params.is_object() || !params.contains(name))
    {
        out = defaultValue;
        return true;
    }
    if (!params[name].is_boolean())
    {
        error = std::string("Parameter \"") + name + "\" must be a boolean";
        return false;
    }
    out = params[name].get<bool>();
    return true;
}

// Extracts a required string from params.
bool GetRequiredStringParam(const nlohmann::json& params, const char* name, std::string& out, std::string& error)
{
    if (!params.is_object() || !params.contains(name) || !params[name].is_string())
    {
        error = std::string("Missing required string parameter \"") + name + "\"";
        return false;
    }
    out = params[name].get<std::string>();
    return true;
}

nlohmann::json StatusToJson(const DebuggerStatus& status)
{
    nlohmann::json result;
    result["debugging"] = status.debugging;
    result["running"] = status.running;
    result["processId"] = status.processId;
    result["threadId"] = status.threadId;
    result["pointerSize"] = status.pointerSize;
    result["cip"] = status.cip;
    result["module"] = status.module;
    return result;
}

nlohmann::json ControlResultToJson(const ControlResult& result)
{
    nlohmann::json out;
    out["paused"] = result.paused;
    out["timed_out"] = result.timedOut;
    out["pause_reason"] = result.pauseReason;
    out["status"] = StatusToJson(result.status);
    return out;
}

std::string HandleDebuggerStatus(DebuggerWorker& worker, const nlohmann::json& id)
{
    // The state lives behind a shared_ptr, not on this function's stack:
    // on Timeout the task MAY still be running after Submit returns control
    // (see the warning in worker.h), and it needs a safe place to write
    // its result into.
    auto status = std::make_shared<DebuggerStatus>();
    const auto submitResult = worker.Submit([status] { *status = GetStatus(); }, kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);

    return BuildOkResponse(id, StatusToJson(*status));
}

// Shared result of a memory/disassembly operation. See the comment in
// HandleDebuggerStatus for why shared_ptr is used.
struct ReadMemoryResult
{
    bool ok = false;
    std::vector<unsigned char> data;
    std::string error;
};

struct DisassembleResult
{
    bool ok = false;
    std::vector<Instruction> instructions;
    std::string error;
};

std::string HandleMemoryRead(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    unsigned long long address = 0;
    unsigned long long sizeParam = 0;
    std::string paramError;
    if (!GetUint64Param(params, "address", address, paramError) ||
        !GetUint64Param(params, "size", sizeParam, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    const size_t size = static_cast<size_t>(sizeParam);

    auto result = std::make_shared<ReadMemoryResult>();
    const auto submitResult = worker.Submit(
        [result, address, size] { result->ok = ReadMemory(address, size, result->data, result->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!result->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, result->error);

    nlohmann::json response;
    response["address"] = address;
    response["size"] = result->data.size();
    response["data"] = BytesToHex(result->data);
    return BuildOkResponse(id, response);
}

std::string HandleDisasm(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    unsigned long long address = 0;
    unsigned long long countParam = 0;
    std::string paramError;
    if (!GetUint64Param(params, "address", address, paramError) ||
        !GetUint64Param(params, "count", countParam, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    const size_t count = static_cast<size_t>(countParam);

    auto result = std::make_shared<DisassembleResult>();
    const auto submitResult = worker.Submit(
        [result, address, count] { result->ok = Disassemble(address, count, result->instructions, result->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!result->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, result->error);

    nlohmann::json response = nlohmann::json::array();
    for (const auto& instr : result->instructions)
    {
        nlohmann::json item;
        item["address"] = instr.address;
        item["size"] = instr.size;
        item["text"] = instr.text;
        item["bytes"] = BytesToHex(instr.bytes);
        response.push_back(std::move(item));
    }
    return BuildOkResponse(id, response);
}

// Shared result of an operation that changes execution state. See the
// comment in HandleDebuggerStatus for why shared_ptr is used.
struct ControlOutcome
{
    bool ok = false;
    ControlResult result;
    std::string error;
};

std::string HandleDebugControl(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    std::string paramError;
    std::string action;
    if (!GetRequiredStringParam(params, "action", action, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    const bool hasAddress = params.is_object() && params.contains("address");
    unsigned long long address = 0;
    if (hasAddress && !GetUint64Param(params, "address", address, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    bool wait = true;
    if (!GetOptionalBoolParam(params, "wait", true, wait, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    int timeoutMs = 0;
    if (!GetOptionalIntParam(params, "timeout_ms", 0, timeoutMs, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    const int submitTimeoutMs = ClampControlTimeout(timeoutMs) + kWaitSubmitSlackMs;

    auto outcome = std::make_shared<ControlOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, action, address, hasAddress, wait, timeoutMs]
        { outcome->ok = Control(action, address, hasAddress, wait, timeoutMs, outcome->result, outcome->error); },
        submitTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    return BuildOkResponse(id, ControlResultToJson(outcome->result));
}

std::string HandleDebugStep(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    std::string paramError;
    std::string mode;
    if (!GetRequiredStringParam(params, "mode", mode, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    int count = 1;
    if (!GetOptionalIntParam(params, "count", 1, count, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    bool wait = true;
    if (!GetOptionalBoolParam(params, "wait", true, wait, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    int timeoutMs = 0;
    if (!GetOptionalIntParam(params, "timeout_ms", 0, timeoutMs, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    const int submitTimeoutMs = ClampControlTimeout(timeoutMs) + kWaitSubmitSlackMs;

    auto outcome = std::make_shared<ControlOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, mode, count, wait, timeoutMs]
        { outcome->ok = Step(mode, count, wait, timeoutMs, outcome->result, outcome->error); },
        submitTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    return BuildOkResponse(id, ControlResultToJson(outcome->result));
}

std::string HandleDebugWait(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    std::string paramError;
    int timeoutMs = 0;
    if (!GetOptionalIntParam(params, "timeout_ms", 0, timeoutMs, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    const int submitTimeoutMs = ClampControlTimeout(timeoutMs) + kWaitSubmitSlackMs;

    auto outcome = std::make_shared<ControlOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, timeoutMs] { outcome->ok = WaitUntilPaused(timeoutMs, outcome->result, outcome->error); },
        submitTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    return BuildOkResponse(id, ControlResultToJson(outcome->result));
}

// Shared result of a breakpoint operation, which doesn't involve waiting
// for a pause, so the task submission timeout here is the ordinary one.
struct BreakpointOutcome
{
    bool ok = false;
    std::string error;
};

std::string HandleBreakpointSet(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    auto outcome = std::make_shared<BreakpointOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, params] { outcome->ok = SetBreakpoint(params, outcome->error); }, kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    return BuildOkResponse(id, nlohmann::json::object());
}

std::string HandleBreakpointManage(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    std::string paramError;
    std::string action;
    if (!GetRequiredStringParam(params, "action", action, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    unsigned long long address = 0;
    if (!GetUint64Param(params, "address", address, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<BreakpointOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, action, address] { outcome->ok = ManageBreakpoint(action, address, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    return BuildOkResponse(id, nlohmann::json::object());
}

struct ListBreakpointsOutcome
{
    bool ok = false;
    std::vector<BreakpointInfo> breakpoints;
    std::string error;
};

std::string HandleBreakpointList(DebuggerWorker& worker, const nlohmann::json& id)
{
    auto outcome = std::make_shared<ListBreakpointsOutcome>();
    const auto submitResult = worker.Submit(
        [outcome] { outcome->ok = ListBreakpoints(outcome->breakpoints, outcome->error); }, kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json list = nlohmann::json::array();
    for (const auto& bp : outcome->breakpoints)
    {
        nlohmann::json item;
        item["address"] = bp.address;
        item["type"] = bp.type;
        item["enabled"] = bp.enabled;
        item["singleShot"] = bp.singleShot;
        item["hitCount"] = bp.hitCount;
        item["module"] = bp.module;
        item["name"] = bp.name;
        list.push_back(std::move(item));
    }

    nlohmann::json result;
    result["breakpoints"] = list;
    return BuildOkResponse(id, result);
}

struct ListModulesOutcome
{
    bool ok = false;
    std::vector<ModuleEntry> modules;
    std::string error;
};

nlohmann::json ModuleEntryToJson(const ModuleEntry& mod)
{
    nlohmann::json item;
    item["base"] = mod.base;
    item["size"] = mod.size;
    item["entry"] = mod.entry;
    item["sectionCount"] = mod.sectionCount;
    item["name"] = mod.name;
    item["path"] = mod.path;
    return item;
}

std::string HandleModulesList(DebuggerWorker& worker, const nlohmann::json& id)
{
    auto outcome = std::make_shared<ListModulesOutcome>();
    const auto submitResult = worker.Submit(
        [outcome] { outcome->ok = ListModules(outcome->modules, outcome->error); }, kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json list = nlohmann::json::array();
    for (const auto& mod : outcome->modules)
        list.push_back(ModuleEntryToJson(mod));

    nlohmann::json result;
    result["modules"] = list;
    return BuildOkResponse(id, result);
}

struct ModuleDetailsOutcome
{
    bool ok = false;
    ModuleDetails details;
    std::string error;
};

std::string HandleModuleInfo(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    const bool hasName = params.is_object() && params.contains("name");
    const bool hasAddress = params.is_object() && params.contains("address");
    if (!hasName && !hasAddress)
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument,
            "Either parameter \"name\" or parameter \"address\" is required");

    std::string paramError;
    std::string name;
    unsigned long long address = 0;
    const bool byAddress = hasAddress;
    if (byAddress)
    {
        if (!GetUint64Param(params, "address", address, paramError))
            return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);
    }
    else if (!GetRequiredStringParam(params, "name", name, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    bool includeExports = false;
    if (!GetOptionalBoolParam(params, "include_exports", false, includeExports, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    bool includeImports = false;
    if (!GetOptionalBoolParam(params, "include_imports", false, includeImports, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<ModuleDetailsOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, name, address, byAddress, includeExports, includeImports]
        {
            outcome->ok = GetModuleDetails(name, address, byAddress, includeExports, includeImports,
                outcome->details, outcome->error);
        },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    const ModuleDetails& details = outcome->details;
    nlohmann::json sections = nlohmann::json::array();
    for (const auto& section : details.sections)
    {
        nlohmann::json item;
        item["address"] = section.address;
        item["size"] = section.size;
        item["name"] = section.name;
        sections.push_back(std::move(item));
    }

    nlohmann::json exports = nlohmann::json::array();
    for (const auto& exp : details.exports)
    {
        nlohmann::json item;
        item["ordinal"] = exp.ordinal;
        item["rva"] = exp.rva;
        item["va"] = exp.va;
        item["forwarded"] = exp.forwarded;
        item["name"] = exp.name;
        item["forwardName"] = exp.forwardName;
        exports.push_back(std::move(item));
    }

    nlohmann::json imports = nlohmann::json::array();
    for (const auto& imp : details.imports)
    {
        nlohmann::json item;
        item["iatRva"] = imp.iatRva;
        item["iatVa"] = imp.iatVa;
        item["ordinal"] = imp.ordinal;
        item["name"] = imp.name;
        imports.push_back(std::move(item));
    }

    nlohmann::json result;
    result["module"] = ModuleEntryToJson(details.module);
    result["sections"] = sections;
    result["exports"] = exports;
    result["exportsTruncated"] = details.exportsTruncated;
    result["imports"] = imports;
    result["importsTruncated"] = details.importsTruncated;
    return BuildOkResponse(id, result);
}

struct MemoryMapOutcome
{
    bool ok = false;
    std::vector<MemoryRegion> regions;
    std::string error;
};

std::string HandleMemoryMap(DebuggerWorker& worker, const nlohmann::json& id)
{
    auto outcome = std::make_shared<MemoryMapOutcome>();
    const auto submitResult = worker.Submit(
        [outcome] { outcome->ok = GetMemoryMap(outcome->regions, outcome->error); }, kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json list = nlohmann::json::array();
    for (const auto& region : outcome->regions)
    {
        nlohmann::json item;
        item["base"] = region.base;
        item["allocationBase"] = region.allocationBase;
        item["size"] = region.size;
        item["state"] = region.state;
        item["type"] = region.type;
        item["protect"] = region.protect;
        item["info"] = region.info;
        list.push_back(std::move(item));
    }

    nlohmann::json result;
    result["regions"] = list;
    return BuildOkResponse(id, result);
}

struct ListThreadsOutcome
{
    bool ok = false;
    std::vector<ThreadEntry> threads;
    std::string error;
};

std::string HandleThreadsList(DebuggerWorker& worker, const nlohmann::json& id)
{
    auto outcome = std::make_shared<ListThreadsOutcome>();
    const auto submitResult = worker.Submit(
        [outcome] { outcome->ok = ListThreads(outcome->threads, outcome->error); }, kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json list = nlohmann::json::array();
    for (const auto& thread : outcome->threads)
    {
        nlohmann::json item;
        item["id"] = thread.id;
        item["number"] = thread.number;
        item["entry"] = thread.entry;
        item["teb"] = thread.teb;
        item["cip"] = thread.cip;
        item["suspendCount"] = thread.suspendCount;
        item["lastError"] = thread.lastError;
        item["name"] = thread.name;
        item["priority"] = thread.priority;
        item["waitReason"] = thread.waitReason;
        item["current"] = thread.current;
        list.push_back(std::move(item));
    }

    nlohmann::json result;
    result["threads"] = list;
    return BuildOkResponse(id, result);
}

struct ReadRegistersOutcome
{
    bool ok = false;
    RegisterDump dump;
    std::string error;
};

nlohmann::json RegisterValuesToJson(const std::vector<RegisterValue>& values)
{
    nlohmann::json list = nlohmann::json::array();
    for (const auto& reg : values)
    {
        nlohmann::json item;
        item["name"] = reg.name;
        item["value"] = reg.value;
        list.push_back(std::move(item));
    }
    return list;
}

std::string HandleRegistersRead(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    std::string paramError;
    bool includeSimd = false;
    if (!GetOptionalBoolParam(params, "include_simd", false, includeSimd, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<ReadRegistersOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, includeSimd] { outcome->ok = ReadRegisters(includeSimd, outcome->dump, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    const RegisterDump& dump = outcome->dump;
    nlohmann::json flags;
    for (const auto& flag : dump.flags)
        flags[flag.first] = flag.second;

    nlohmann::json simd = nlohmann::json::array();
    for (const auto& reg : dump.simd)
    {
        nlohmann::json item;
        item["name"] = reg.first;
        item["value"] = reg.second;
        simd.push_back(std::move(item));
    }

    nlohmann::json result;
    result["general"] = RegisterValuesToJson(dump.general);
    result["segment"] = RegisterValuesToJson(dump.segment);
    result["debug"] = RegisterValuesToJson(dump.debugRegs);
    result["eflags"] = dump.eflags;
    result["flags"] = flags;
    result["simd"] = simd;
    result["lastError"] = dump.lastError;
    result["lastStatus"] = dump.lastStatus;
    return BuildOkResponse(id, result);
}

struct GetCallStackOutcome
{
    bool ok = false;
    std::vector<CallStackFrame> frames;
    std::string error;
};

std::string HandleCallStack(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    std::string paramError;
    int threadId = 0;
    if (!GetOptionalIntParam(params, "thread_id", 0, threadId, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);
    if (threadId < 0)
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, "Parameter \"thread_id\" must not be negative");

    auto outcome = std::make_shared<GetCallStackOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, threadId]
        { outcome->ok = GetCallStack(static_cast<unsigned int>(threadId), outcome->frames, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json frames = nlohmann::json::array();
    for (const auto& frame : outcome->frames)
    {
        nlohmann::json item;
        item["address"] = frame.address;
        item["from"] = frame.from;
        item["to"] = frame.to;
        item["comment"] = frame.comment;
        frames.push_back(std::move(item));
    }

    nlohmann::json result;
    result["frames"] = frames;
    return BuildOkResponse(id, result);
}

struct ReadStackOutcome
{
    bool ok = false;
    std::vector<StackSlot> slots;
    std::string error;
};

std::string HandleStackRead(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    std::string paramError;
    int count = static_cast<int>(kDefaultStackSlots);
    if (!GetOptionalIntParam(params, "count", static_cast<int>(kDefaultStackSlots), count, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);
    if (count < 1)
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, "Parameter \"count\" must be greater than zero");

    auto outcome = std::make_shared<ReadStackOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, count]
        { outcome->ok = ReadStack(static_cast<size_t>(count), outcome->slots, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json slots = nlohmann::json::array();
    for (const auto& slot : outcome->slots)
    {
        nlohmann::json item;
        item["address"] = slot.address;
        item["value"] = slot.value;
        item["comment"] = slot.comment;
        slots.push_back(std::move(item));
    }

    nlohmann::json result;
    result["slots"] = slots;
    return BuildOkResponse(id, result);
}

struct StringReadOutcome
{
    bool ok = false;
    std::string value;
    std::string error;
};

std::string HandleStringRead(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    unsigned long long address = 0;
    std::string paramError;
    if (!GetUint64Param(params, "address", address, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<StringReadOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, address] { outcome->ok = ReadStringAt(address, outcome->value, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json result;
    result["address"] = address;
    result["string"] = outcome->value;
    return BuildOkResponse(id, result);
}

struct ExpressionEvalOutcome
{
    bool ok = false;
    EvalResult value;
    std::string error;
};

std::string HandleExpressionEval(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    std::string expression;
    std::string paramError;
    if (!GetRequiredStringParam(params, "expression", expression, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<ExpressionEvalOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, expression] { outcome->ok = EvaluateExpression(expression, outcome->value, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json result;
    result["expression"] = expression;
    result["value"] = outcome->value.value;
    result["pointerValid"] = outcome->value.pointerValid;
    return BuildOkResponse(id, result);
}

struct PatternFindOutcome
{
    bool ok = false;
    std::vector<unsigned long long> matches;
    bool truncated = false;
    std::string error;
};

std::string HandlePatternFind(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    std::string paramError;
    std::string pattern;
    if (!GetRequiredStringParam(params, "pattern", pattern, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    const bool hasModule = params.is_object() && params.contains("module");
    const bool hasRange = params.is_object() && params.contains("start") && params.contains("size");
    if (hasModule == hasRange)
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument,
            "Provide either parameter \"module\" or both \"start\" and \"size\", but not both");

    std::string moduleName;
    unsigned long long start = 0, size = 0;
    if (hasModule)
    {
        if (!GetRequiredStringParam(params, "module", moduleName, paramError))
            return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);
    }
    else if (!GetUint64Param(params, "start", start, paramError) ||
             !GetUint64Param(params, "size", size, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    int maxResults = 32;
    if (!GetOptionalIntParam(params, "max_results", 32, maxResults, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);
    if (maxResults < 1)
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, "Parameter \"max_results\" must be greater than zero");

    auto outcome = std::make_shared<PatternFindOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, pattern, hasModule, moduleName, start, size, maxResults]
        {
            unsigned long long rangeStart = start;
            unsigned long long rangeSize = size;
            if (hasModule)
            {
                ModuleDetails details;
                std::string moduleError;
                if (!GetModuleDetails(moduleName, 0, false, false, false, details, moduleError))
                {
                    outcome->ok = false;
                    outcome->error = moduleError;
                    return;
                }
                rangeStart = details.module.base;
                rangeSize = details.module.size;
            }
            outcome->ok = FindPattern(rangeStart, rangeSize, pattern, static_cast<size_t>(maxResults),
                outcome->matches, outcome->truncated, outcome->error);
        },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json result;
    result["matches"] = outcome->matches;
    result["truncated"] = outcome->truncated;
    return BuildOkResponse(id, result);
}

struct XrefsOutcome
{
    bool ok = false;
    std::vector<XrefEntry> xrefs;
    std::string error;
};

std::string HandleXrefsGet(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    unsigned long long address = 0;
    std::string paramError;
    if (!GetUint64Param(params, "address", address, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<XrefsOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, address] { outcome->ok = GetXrefs(address, outcome->xrefs, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json xrefs = nlohmann::json::array();
    for (const auto& xref : outcome->xrefs)
    {
        nlohmann::json item;
        item["address"] = xref.address;
        item["type"] = xref.type;
        xrefs.push_back(std::move(item));
    }

    nlohmann::json result;
    result["address"] = address;
    result["xrefs"] = xrefs;
    return BuildOkResponse(id, result);
}

struct FunctionDisasmOutcome
{
    bool ok = false;
    unsigned long long start = 0, end = 0;
    std::vector<Instruction> instructions;
    bool truncated = false;
    std::string error;
};

std::string HandleFunctionDisasm(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    unsigned long long address = 0;
    std::string paramError;
    if (!GetUint64Param(params, "address", address, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<FunctionDisasmOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, address]
        {
            if (!GetFunctionRange(address, outcome->start, outcome->end, outcome->error))
                return;

            std::vector<Instruction> all;
            if (!Disassemble(outcome->start, kMaxInstructions, all, outcome->error))
                return;

            for (const auto& instr : all)
            {
                if (instr.address >= outcome->end)
                    break;
                outcome->instructions.push_back(instr);
            }
            // The instruction limit was hit before the end of the function —
            // the whole disassembled set made it into the result, but fell short of end.
            if (outcome->instructions.size() == all.size() && !all.empty() &&
                all.back().address + all.back().size < outcome->end)
                outcome->truncated = true;

            outcome->ok = true;
        },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json instructions = nlohmann::json::array();
    for (const auto& instr : outcome->instructions)
    {
        nlohmann::json item;
        item["address"] = instr.address;
        item["size"] = instr.size;
        item["text"] = instr.text;
        item["bytes"] = BytesToHex(instr.bytes);
        instructions.push_back(std::move(item));
    }

    nlohmann::json result;
    result["start"] = outcome->start;
    result["end"] = outcome->end;
    result["instructions"] = instructions;
    result["truncated"] = outcome->truncated;
    return BuildOkResponse(id, result);
}

nlohmann::json CommandResultToJson(const CommandResult& result)
{
    nlohmann::json out;
    out["accepted"] = result.accepted;
    out["output"] = result.output;
    out["logCaptured"] = result.logCaptured;
    return out;
}

struct CommandResultOutcome
{
    bool ok = false;
    CommandResult result;
    std::string error;
};

std::string HandleCommandExec(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    std::string command;
    std::string paramError;
    if (!GetRequiredStringParam(params, "command", command, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    bool async = false;
    if (!GetOptionalBoolParam(params, "async", false, async, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<CommandResultOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, command, async] { outcome->ok = ExecuteCommand(command, async, outcome->result, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    return BuildOkResponse(id, CommandResultToJson(outcome->result));
}

std::string HandleScriptRun(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    std::string script;
    std::string paramError;
    if (!GetRequiredStringParam(params, "script", script, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<CommandResultOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, script] { outcome->ok = RunScript(script, outcome->result, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    return BuildOkResponse(id, CommandResultToJson(outcome->result));
}

struct LogReadOutcome
{
    bool ok = false;
    std::vector<std::string> lines;
    bool truncated = false;
    bool captured = false;
    std::string captureFile;
    std::string error;
};

std::string HandleLogRead(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    std::string paramError;
    int maxLines = 200;
    if (!GetOptionalIntParam(params, "max_lines", 200, maxLines, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);
    if (maxLines < 1)
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, "Parameter \"max_lines\" must be greater than zero");

    auto outcome = std::make_shared<LogReadOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, maxLines]
        {
            outcome->ok = ReadLog(static_cast<size_t>(maxLines), outcome->lines, outcome->truncated, outcome->error);
            outcome->captured = IsLogCaptureActive();
            outcome->captureFile = LogCaptureFilePath();
        },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json result;
    result["lines"] = outcome->lines;
    result["truncated"] = outcome->truncated;
    result["logCaptured"] = outcome->captured;
    result["captureFile"] = outcome->captureFile;
    if (!outcome->captured)
        result["note"] = "Log capture is not active, so no output is available.";
    return BuildOkResponse(id, result);
}

// Shared result of a write/patch operation that carries no data of its own,
// just success or failure.
struct WriteOutcome
{
    bool ok = false;
    std::string error;
};

std::string HandleMemoryWrite(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    unsigned long long address = 0;
    std::string paramError;
    if (!GetUint64Param(params, "address", address, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    std::string dataHex;
    if (!GetRequiredStringParam(params, "data", dataHex, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    std::vector<unsigned char> data;
    if (!BytesFromHex(dataHex, data, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    bool recordPatch = true;
    if (!GetOptionalBoolParam(params, "record_patch", true, recordPatch, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<WriteOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, address, data, recordPatch]
        { outcome->ok = WriteMemory(address, data, recordPatch, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json result;
    result["address"] = address;
    result["size"] = data.size();
    result["recordedAsPatch"] = recordPatch;
    return BuildOkResponse(id, result);
}

std::string HandleRegisterSet(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    std::string name;
    std::string paramError;
    if (!GetRequiredStringParam(params, "name", name, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    unsigned long long value = 0;
    if (!GetUint64Param(params, "value", value, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<WriteOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, name, value] { outcome->ok = SetNamedValue(name, value, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json result;
    result["name"] = name;
    result["value"] = value;
    return BuildOkResponse(id, result);
}

struct AssembleOutcome
{
    bool ok = false;
    AssembleResult result;
    std::string error;
};

std::string HandleAssemble(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    unsigned long long address = 0;
    std::string paramError;
    if (!GetUint64Param(params, "address", address, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    std::string instruction;
    if (!GetRequiredStringParam(params, "instruction", instruction, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    bool fillNop = true;
    if (!GetOptionalBoolParam(params, "fill_nop", true, fillNop, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<AssembleOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, address, instruction, fillNop]
        { outcome->ok = AssembleAt(address, instruction, fillNop, outcome->result, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json result;
    result["address"] = address;
    result["size"] = outcome->result.size;
    return BuildOkResponse(id, result);
}

struct ListPatchesOutcome
{
    bool ok = false;
    std::vector<PatchEntry> patches;
    std::string error;
};

std::string HandlePatchesList(DebuggerWorker& worker, const nlohmann::json& id)
{
    auto outcome = std::make_shared<ListPatchesOutcome>();
    const auto submitResult = worker.Submit(
        [outcome] { outcome->ok = ListPatches(outcome->patches, outcome->error); }, kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json list = nlohmann::json::array();
    for (const auto& patch : outcome->patches)
    {
        nlohmann::json item;
        item["address"] = patch.address;
        item["oldByte"] = patch.oldByte;
        item["newByte"] = patch.newByte;
        item["module"] = patch.module;
        list.push_back(std::move(item));
    }

    nlohmann::json result;
    result["patches"] = list;
    return BuildOkResponse(id, result);
}

struct RestorePatchesOutcome
{
    bool ok = false;
    size_t restored = 0;
    std::string error;
};

std::string HandlePatchesRestore(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    const bool hasAddress = params.is_object() && params.contains("address");
    const bool hasRange = params.is_object() && params.contains("start") && params.contains("end");
    if (hasAddress == hasRange)
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument,
            "Provide either parameter \"address\" or both \"start\" and \"end\", but not both");

    std::string paramError;
    unsigned long long address = 0, end = 0;
    if (hasAddress)
    {
        if (!GetUint64Param(params, "address", address, paramError))
            return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);
    }
    else if (!GetUint64Param(params, "start", address, paramError) ||
             !GetUint64Param(params, "end", end, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<RestorePatchesOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, address, end, hasRange]
        { outcome->ok = RestorePatches(address, end, hasRange, outcome->restored, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json result;
    result["restored"] = outcome->restored;
    return BuildOkResponse(id, result);
}

struct ApplyPatchesOutcome
{
    bool ok = false;
    int patched = 0;
    std::string error;
};

std::string HandlePatchesApplyToFile(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    std::string path;
    std::string paramError;
    if (!GetRequiredStringParam(params, "path", path, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<ApplyPatchesOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, path] { outcome->ok = ApplyPatchesToFile(path, outcome->patched, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json result;
    result["patched"] = outcome->patched;
    result["path"] = path;
    return BuildOkResponse(id, result);
}

std::string HandleMemorySetRights(DebuggerWorker& worker, const nlohmann::json& id, const nlohmann::json& params)
{
    unsigned long long address = 0;
    std::string paramError;
    if (!GetUint64Param(params, "address", address, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    std::string rights;
    if (!GetRequiredStringParam(params, "rights", rights, paramError))
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidArgument, paramError);

    auto outcome = std::make_shared<WriteOutcome>();
    const auto submitResult = worker.Submit(
        [outcome, address, rights] { outcome->ok = SetPageProtection(address, rights, outcome->error); },
        kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);
    if (!outcome->ok)
        return BuildErrorResponse(id, ipc::ErrorCode::OperationFailed, outcome->error);

    nlohmann::json result;
    result["address"] = address;
    result["rights"] = rights;
    return BuildOkResponse(id, result);
}

// Debug state callbacks. Run on x64dbg's own debugger threads, so they must
// be as short as possible and never throw: DebugStateTracker itself never throws.
void CbInitDebug(CBTYPE, void*) { McpService::Instance().Tracker().NotifyDebugStarted(); }
void CbCreateProcess(CBTYPE, void*) { McpService::Instance().Tracker().NotifyDebugStarted(); }
void CbStopDebug(CBTYPE, void*) { McpService::Instance().Tracker().NotifyDebugStopped(); }
void CbExitProcess(CBTYPE, void*) { McpService::Instance().Tracker().NotifyDebugStopped(); }
void CbPauseDebug(CBTYPE, void*) { McpService::Instance().Tracker().NotifyPaused(PauseReason::UserPause); }
void CbBreakpoint(CBTYPE, void*) { McpService::Instance().Tracker().NotifyPaused(PauseReason::Breakpoint); }
void CbStepped(CBTYPE, void*) { McpService::Instance().Tracker().NotifyPaused(PauseReason::Step); }
void CbSystemBreakpoint(CBTYPE, void*) { McpService::Instance().Tracker().NotifyPaused(PauseReason::InitialBreak); }
void CbResumeDebug(CBTYPE, void*) { McpService::Instance().Tracker().NotifyResumed(); }

} // namespace

McpService& McpService::Instance()
{
    static McpService instance;
    return instance;
}

bool McpService::Start()
{
    if (!worker_.Start())
    {
        dputs("failed to start the debugger worker thread");
        return false;
    }

    auto handler = [this](const std::string& request) { return HandleRequest(request); };

    if (pipeServer_.Start(ipc::kDefaultPipeName, handler))
        return true;

    // The default pipe name may be taken by another already-running instance
    // of this same plugin (e.g. a second x64dbg instance). Instead of
    // failing, try a fallback name with this process's PID — the second
    // instance can then run at the same time, the bridge just needs to be
    // told this name explicitly.
    const std::string fallbackName =
        std::string(ipc::kDefaultPipeName) + "-" + std::to_string(GetCurrentProcessId());
    if (pipeServer_.Start(fallbackName, handler))
    {
        dprintf("default pipe name is busy, listening on \"%s\" instead\n", fallbackName.c_str());
        return true;
    }

    dputs("failed to start the IPC pipe server");
    worker_.Submit([] { StopLogCapture(); }, kDefaultTimeoutMs);
    worker_.Stop();
    return false;
}

void McpService::EnableLogCapture()
{
    // This is best-effort: if it cannot be enabled, log a warning and keep
    // going — the server, and command execution itself, remain fully usable
    // without it, just without captured output.
    //
    // Unlike everything else in debugger.h, StartLogCapture must NOT be
    // submitted to the worker thread. It issues GUI-side requests
    // (GuiLogSave, GuiFlushLog) delivered to Qt slots that run on the GUI
    // thread. This function is called from pluginSetup, which x64dbg runs ON
    // the GUI thread and which blocks waiting for this call to return — so
    // if those requests were issued from the worker thread instead, the GUI
    // thread could never service its own queue to process them while it sits
    // here waiting, and the requests would never run. (An earlier version of
    // this code appeared to work only by accident: a 2-second poll inside
    // the worker task delayed things long enough for the GUI queue to drain
    // afterwards; removing that poll exposed this.) Calling StartLogCapture
    // directly, here, on the GUI thread is correct precisely because it is a
    // file and GUI-request operation, not a query into debugger state, so
    // the usual "worker thread only" rule for debugger.h does not apply to it.
    std::string captureError;
    const bool started = StartLogCapture(captureError);

    if (!started)
    {
        dprintf("failed to start log capture: %s; commands will still run but their output will not be captured\n",
                captureError.c_str());
        return;
    }

    dprintf("log capture started, snapshotting to \"%s\"\n", LogCaptureFilePath().c_str());
}

void McpService::Stop()
{
    // The shutdown order is strictly this:
    // 1) Tracker().Shutdown() — wakes up everyone waiting for a pause via
    //    WaitForPauseAfter; otherwise they would hang until their own
    //    timeout, even though the plugin is already unloading.
    // 2) PipeServer::Stop() — stops accepting new requests and wakes up the
    //    connection threads, so no new tasks are submitted to the worker
    //    queue anymore.
    // 3) StopLogCapture(), submitted to the worker — must run while the
    //    worker thread is still alive, since log capture state may only be
    //    touched from that thread.
    // 4) DebuggerWorker::Stop() — stops the executor last.
    // The reverse order would mean the worker's Stop() waits for the current
    // task, which may itself be waiting for a debugger pause — hanging until
    // its own timeout and delaying the plugin unload for that whole time.
    tracker_.Shutdown();
    pipeServer_.Stop();
    worker_.Submit([] { StopLogCapture(); }, kDefaultTimeoutMs);
    worker_.Stop();
}

DebugStateTracker& McpService::Tracker()
{
    return tracker_;
}

std::string McpService::PipeName() const
{
    return pipeServer_.PipeName();
}

std::string McpService::HandleRequest(const std::string& request)
{
    const nlohmann::json parsed = nlohmann::json::parse(request, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object())
        return BuildErrorResponse(nullptr, ipc::ErrorCode::InvalidRequest, "Request is not a valid JSON object");

    const nlohmann::json id = parsed.value(ipc::kFieldId, nlohmann::json());

    if (!parsed.contains(ipc::kFieldMethod) || !parsed[ipc::kFieldMethod].is_string())
        return BuildErrorResponse(id, ipc::ErrorCode::InvalidRequest, "Request is missing a string \"method\" field");

    const std::string method = parsed[ipc::kFieldMethod].get<std::string>();
    const nlohmann::json params = parsed.value(ipc::kFieldParams, nlohmann::json::object());

    if (method == "debugger.status")
        return HandleDebuggerStatus(worker_, id);
    if (method == "memory.read")
        return HandleMemoryRead(worker_, id, params);
    if (method == "disasm")
        return HandleDisasm(worker_, id, params);
    if (method == "debug.control")
        return HandleDebugControl(worker_, id, params);
    if (method == "debug.step")
        return HandleDebugStep(worker_, id, params);
    if (method == "debug.wait")
        return HandleDebugWait(worker_, id, params);
    if (method == "breakpoint.set")
        return HandleBreakpointSet(worker_, id, params);
    if (method == "breakpoint.manage")
        return HandleBreakpointManage(worker_, id, params);
    if (method == "breakpoint.list")
        return HandleBreakpointList(worker_, id);
    if (method == "modules.list")
        return HandleModulesList(worker_, id);
    if (method == "module.info")
        return HandleModuleInfo(worker_, id, params);
    if (method == "memory.map")
        return HandleMemoryMap(worker_, id);
    if (method == "threads.list")
        return HandleThreadsList(worker_, id);
    if (method == "registers.read")
        return HandleRegistersRead(worker_, id, params);
    if (method == "callstack")
        return HandleCallStack(worker_, id, params);
    if (method == "stack.read")
        return HandleStackRead(worker_, id, params);
    if (method == "string.read")
        return HandleStringRead(worker_, id, params);
    if (method == "expression.eval")
        return HandleExpressionEval(worker_, id, params);
    if (method == "pattern.find")
        return HandlePatternFind(worker_, id, params);
    if (method == "xrefs.get")
        return HandleXrefsGet(worker_, id, params);
    if (method == "function.disasm")
        return HandleFunctionDisasm(worker_, id, params);
    if (method == "command.exec")
        return HandleCommandExec(worker_, id, params);
    if (method == "script.run")
        return HandleScriptRun(worker_, id, params);
    if (method == "log.read")
        return HandleLogRead(worker_, id, params);
    if (method == "memory.write")
        return HandleMemoryWrite(worker_, id, params);
    if (method == "register.set")
        return HandleRegisterSet(worker_, id, params);
    if (method == "assemble")
        return HandleAssemble(worker_, id, params);
    if (method == "patches.list")
        return HandlePatchesList(worker_, id);
    if (method == "patches.restore")
        return HandlePatchesRestore(worker_, id, params);
    if (method == "patches.apply_to_file")
        return HandlePatchesApplyToFile(worker_, id, params);
    if (method == "memory.set_rights")
        return HandleMemorySetRights(worker_, id, params);

    return BuildErrorResponse(id, ipc::ErrorCode::UnknownMethod, "Unknown method: " + method);
}

void RegisterDebugCallbacks(int pluginHandle)
{
    _plugin_registercallback(pluginHandle, CB_INITDEBUG, CbInitDebug);
    _plugin_registercallback(pluginHandle, CB_CREATEPROCESS, CbCreateProcess);
    _plugin_registercallback(pluginHandle, CB_STOPDEBUG, CbStopDebug);
    _plugin_registercallback(pluginHandle, CB_EXITPROCESS, CbExitProcess);
    _plugin_registercallback(pluginHandle, CB_PAUSEDEBUG, CbPauseDebug);
    _plugin_registercallback(pluginHandle, CB_BREAKPOINT, CbBreakpoint);
    _plugin_registercallback(pluginHandle, CB_STEPPED, CbStepped);
    _plugin_registercallback(pluginHandle, CB_SYSTEMBREAKPOINT, CbSystemBreakpoint);
    _plugin_registercallback(pluginHandle, CB_RESUMEDEBUG, CbResumeDebug);
}

void UnregisterDebugCallbacks(int pluginHandle)
{
    _plugin_unregistercallback(pluginHandle, CB_INITDEBUG);
    _plugin_unregistercallback(pluginHandle, CB_CREATEPROCESS);
    _plugin_unregistercallback(pluginHandle, CB_STOPDEBUG);
    _plugin_unregistercallback(pluginHandle, CB_EXITPROCESS);
    _plugin_unregistercallback(pluginHandle, CB_PAUSEDEBUG);
    _plugin_unregistercallback(pluginHandle, CB_BREAKPOINT);
    _plugin_unregistercallback(pluginHandle, CB_STEPPED);
    _plugin_unregistercallback(pluginHandle, CB_SYSTEMBREAKPOINT);
    _plugin_unregistercallback(pluginHandle, CB_RESUMEDEBUG);
}

} // namespace x64dbg_mcp::plugin
