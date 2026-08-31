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

    nlohmann::json result;
    result["debugging"] = status->debugging;
    result["running"] = status->running;
    result["processId"] = status->processId;
    result["threadId"] = status->threadId;
    result["pointerSize"] = status->pointerSize;
    result["cip"] = status->cip;
    result["module"] = status->module;
    return BuildOkResponse(id, result);
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
