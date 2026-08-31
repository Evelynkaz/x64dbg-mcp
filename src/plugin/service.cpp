#include "plugin/service.h"
#include "plugin/debugger.h"
#include "plugin/plugin.h"
#include "common/ipc_protocol.h"
#include "nlohmann/json.hpp"

#include <memory>

// GetCurrentProcessId используется для запасного имени канала; windows.h уже
// подключён транзитивно через plugin.h -> bridgemain.h.

namespace x64dbg_mcp::plugin
{

namespace
{

// Таймаут по умолчанию для одного обращения к DebuggerWorker.
constexpr int kDefaultTimeoutMs = 5000;

// Дополнительное время сверх таймаута ожидания паузы, которое даётся
// DebuggerWorker::Submit на постановку задачи в очередь. Таймаут ожидания
// паузы (до 300000 мс, см. debugger.h) целиком проживает ВНУТРИ задачи,
// поэтому Submit обязан ждать дольше — иначе он вернёт Timeout раньше, чем
// задача успеет фактически завершиться, хотя отладчик всё ещё работает.
constexpr int kWaitSubmitSlackMs = 5000;

// Зеркалит ограничение таймаута из debugger.cpp (там оно применяется к
// самому ожиданию паузы), чтобы здесь верно рассчитать таймаут постановки
// задачи в очередь.
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

// Переводит результат DebuggerWorker::Submit в код и текст ошибки протокола.
// Возвращает true, если задача выполнена и результат можно использовать.
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
        // NotRunning, Rejected, SelfSubmit — все три указывают на то, что
        // плагин сейчас не в состоянии обслужить запрос, а не на ошибку
        // самого запроса.
        code = ipc::ErrorCode::Internal;
        message = "Debugger worker is not available to process the request";
        return false;
    }
}

// Достаёт из params неотрицательное целое число. При ошибке заполняет error
// английским текстом с именем параметра.
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

// Достаёт из params необязательное целое число. Отсутствие параметра —
// не ошибка, подставляется defaultValue.
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

// Достаёт из params необязательное булево значение. Отсутствие параметра —
// не ошибка, подставляется defaultValue.
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

// Достаёт из params обязательную строку.
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
    // Состояние живёт под shared_ptr, а не на стеке этой функции: при
    // Timeout задача МОЖЕТ ещё выполняться после того, как Submit вернёт
    // управление (см. предупреждение в worker.h), и обязана иметь куда
    // безопасно дописать результат.
    auto status = std::make_shared<DebuggerStatus>();
    const auto submitResult = worker.Submit([status] { *status = GetStatus(); }, kDefaultTimeoutMs);

    ipc::ErrorCode code;
    std::string message;
    if (!TranslateSubmitResult(submitResult, code, message))
        return BuildErrorResponse(id, code, message);

    return BuildOkResponse(id, StatusToJson(*status));
}

// Разделяемый результат операции с памятью/дизассемблированием. См.
// комментарий в HandleDebuggerStatus о причине использования shared_ptr.
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

// Разделяемый результат операции, меняющей состояние выполнения. См.
// комментарий в HandleDebuggerStatus о причине использования shared_ptr.
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

// Разделяемый результат операции с точками останова, не связанной с
// ожиданием паузы, поэтому таймаут постановки задачи здесь обычный.
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

// Коллбэки состояния отладки. Исполняются в потоках отладчика x64dbg, поэтому
// обязаны быть максимально короткими и не бросать исключений: DebugStateTracker
// сам по себе исключений не бросает.
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

    // Основное имя канала может быть занято другим уже работающим экземпляром
    // этого же плагина (например, второй запущенный x64dbg). Вместо отказа
    // пробуем запасное имя с PID этого процесса — второй экземпляр сможет
    // работать одновременно, просто мосту нужно будет явно указать это имя.
    const std::string fallbackName =
        std::string(ipc::kDefaultPipeName) + "-" + std::to_string(GetCurrentProcessId());
    if (pipeServer_.Start(fallbackName, handler))
    {
        dprintf("default pipe name is busy, listening on \"%s\" instead\n", fallbackName.c_str());
        return true;
    }

    dputs("failed to start the IPC pipe server");
    worker_.Stop();
    return false;
}

void McpService::Stop()
{
    // Порядок остановки строго такой:
    // 1) Tracker().Shutdown() — будит всех, кто ждёт паузу через
    //    WaitForPauseAfter; иначе они провисят до собственного таймаута,
    //    хотя плагин уже выгружается.
    // 2) PipeServer::Stop() — прекращает приём новых запросов и будит потоки
    //    соединений, поэтому новые задачи в очередь воркера больше не
    //    поступают.
    // 3) DebuggerWorker::Stop() — останавливает исполнителя последним.
    // Обратный порядок означает, что Stop() воркера дождётся текущей задачи,
    // а та может ждать паузы отладчика — и провисит до собственного
    // таймаута, задержав тем самым выгрузку плагина на всё это время.
    tracker_.Shutdown();
    pipeServer_.Stop();
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
