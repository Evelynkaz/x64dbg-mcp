#include "bridge/mcp_server.h"
#include "bridge/logging.h"

namespace x64dbg_mcp::bridge
{

namespace
{

// Ключи _meta современной модели — константы, чтобы длинные строки не
// расходились в написании между местами использования.
constexpr const char* kMetaProtocolVersion = "io.modelcontextprotocol/protocolVersion";
constexpr const char* kMetaClientCapabilities = "io.modelcontextprotocol/clientCapabilities";
constexpr const char* kMetaServerInfo = "io.modelcontextprotocol/serverInfo";

// Защита от раздувания памяти на входных данных, приходящих извне (stdin —
// внешний, потенциально враждебный источник): отбраковываем слишком большие
// сообщения до попытки их разобрать.
constexpr size_t kMaxMessageBytes = 8u * 1024u * 1024u;

// Защита от переполнения стека: рекурсивный обходчик nlohmann::json при
// большой вложенности структуры переполняет стек вызовов и убивает процесс
// аварийно, минуя любые catch. Ограничиваем глубину до разбора.
constexpr int kMaxNestingDepth = 64;

// Ошибка протокола JSON-RPC (malformed request, unknown tool и т.п.),
// которую нужно вернуть клиенту как стандартную ошибку JSON-RPC, а не как
// результат с isError — по классификации спецификации MCP это Protocol
// Error, а не Tool Execution Error.
struct ProtocolError
{
    int code;
    std::string message;
};

// Считает максимальную глубину вложенности { } [ ] в сыром тексте сообщения
// БЕЗ его разбора. Нужна отдельная дешёвая проверка ДО парсинга: полагаться
// на сам разбор нельзя — рекурсивный парсер nlohmann::json переполняет стек
// раньше, чем успевает сообщить об ошибке через исключение или discarded.
int ComputeMaxNestingDepth(const std::string& line)
{
    int depth = 0;
    int maxDepth = 0;
    bool inString = false;
    bool escaped = false;

    for (char c : line)
    {
        if (inString)
        {
            if (escaped)
                escaped = false;
            else if (c == '\\')
                escaped = true;
            else if (c == '"')
                inString = false;
            continue;
        }

        if (c == '"')
            inString = true;
        else if (c == '{' || c == '[')
        {
            ++depth;
            if (depth > maxDepth)
                maxDepth = depth;
        }
        else if (c == '}' || c == ']')
            --depth;
    }

    return maxDepth;
}

nlohmann::json MakeErrorResponse(const nlohmann::json& id, int code, const std::string& message,
                                  const nlohmann::json& data = nullptr)
{
    nlohmann::json error = { {"code", code}, {"message", message} };
    if (!data.is_null())
        error["data"] = data;

    return nlohmann::json{
        {"jsonrpc", "2.0"},
        {"id", id},
        {"error", std::move(error)}
    };
}

nlohmann::json MakeResultResponse(const nlohmann::json& id, nlohmann::json result)
{
    return nlohmann::json{
        {"jsonrpc", "2.0"},
        {"id", id},
        {"result", std::move(result)}
    };
}

nlohmann::json BuildServerInfo()
{
    return nlohmann::json{ {"name", "x64dbg-mcp"}, {"version", SERVER_VERSION_STR} };
}

// Достаёт объект _meta из params, если он есть и действительно объект;
// иначе — пустой объект. Отдельная функция, чтобы не повторять одну и ту же
// проверку типов в нескольких местах.
nlohmann::json ExtractMeta(const nlohmann::json& params)
{
    if (params.is_object() && params.contains("_meta") && params["_meta"].is_object())
        return params["_meta"];
    return nlohmann::json::object();
}

// Дописывает в результат современной модели обязательные поля: признак
// завершённости запроса и информацию о сервере в _meta.
void ApplyModernEnvelope(nlohmann::json& result)
{
    result["resultType"] = "complete";
    result["_meta"][kMetaServerInfo] = BuildServerInfo();
}

// Определяет, относится ли сообщение к современной модели протокола.
//
// ВАЖНО: признаком современной модели НЕЛЬЗЯ считать сам факт наличия
// объекта _meta в params — _meta является штатной частью MCP, и клиент
// вправе класть туда собственные ключи в ЛЮБОЙ модели протокола. Так,
// Claude Code 2.1.251, работающий по устаревшему рукопожатию initialize
// (версия 2025-11-25), кладёт в _meta свои ключи "progressToken" и
// "claudecode/toolUseId". Прежняя реализация принимала за современную
// модель любое сообщение с непустым _meta, из-за чего сервер требовал от
// такого клиента поле _meta["io.modelcontextprotocol/protocolVersion"],
// не находил его и отвечал ошибкой -32602 на КАЖДЫЙ вызов инструмента —
// продукт был неработоспособен. Дефект обнаружен подключением реального
// клиента, поэтому эту проверку нельзя «упрощать» обратно к простому
// params.contains("_meta").
//
// Правильный признак — наличие в _meta хотя бы одного ключа,
// ЗАРЕЗЕРВИРОВАННОГО спецификацией MCP, то есть начинающегося с префикса
// "io.modelcontextprotocol/". Клиентские ключи этого префикса не имеют.
bool IsModernProtocol(const std::string& method, const nlohmann::json& params)
{
    if (method == "server/discover")
        return true;

    const nlohmann::json meta = ExtractMeta(params);
    if (!meta.is_object())
        return false;

    constexpr const char* kReservedPrefix = "io.modelcontextprotocol/";
    for (const auto& item : meta.items())
    {
        if (item.key().rfind(kReservedPrefix, 0) == 0)
            return true;
    }
    return false;
}

} // namespace

McpServer::McpServer(ToolRegistry registry) : registry_(std::move(registry))
{
}

nlohmann::json McpServer::HandleToolsList() const
{
    return nlohmann::json{ {"tools", registry_.ListJson()} };
}

nlohmann::json McpServer::HandleToolsCall(const nlohmann::json& params) const
{
    // Malformed request по классификации спецификации MCP — ошибка протокола,
    // а не результат вызова инструмента.
    if (!params.is_object() || !params.contains("name") || !params["name"].is_string())
        throw ProtocolError{ -32602, "params.name must be present and must be a string containing the tool name" };

    const std::string name = params["name"].get<std::string>();

    nlohmann::json arguments = nlohmann::json::object();
    if (params.contains("arguments"))
    {
        if (!params["arguments"].is_object())
            throw ProtocolError{ -32602, "params.arguments must be an object" };
        arguments = params["arguments"];
    }

    const Tool* tool = registry_.Find(name);
    if (tool == nullptr)
        throw ProtocolError{ -32602, "Unknown tool: " + name };

    // Ошибка инструмента (ToolError) по правилам MCP возвращается как обычный
    // результат с isError, а не как ошибка JSON-RPC — иначе модель не увидит
    // текст ошибки и не сможет на него отреагировать. Любое другое исключение
    // прячем за общим сообщением, чтобы не раскрывать внутренности реализации.
    try
    {
        nlohmann::json structured = tool->handler(arguments);
        return nlohmann::json{
            {"content", nlohmann::json::array({
                { {"type", "text"}, {"text", structured.dump()} }
            })},
            {"structuredContent", structured},
            {"isError", false}
        };
    }
    catch (const ToolError& e)
    {
        return nlohmann::json{
            {"isError", true},
            {"content", nlohmann::json::array({
                { {"type", "text"}, {"text", std::string(e.what())} }
            })}
        };
    }
    catch (...)
    {
        return nlohmann::json{
            {"isError", true},
            {"content", nlohmann::json::array({
                { {"type", "text"}, {"text", "Internal error while executing the tool"} }
            })}
        };
    }
}

nlohmann::json McpServer::HandleDiscover() const
{
    nlohmann::json result = {
        {"supportedVersions", nlohmann::json::array({ kModernVersion })},
        {"capabilities", {{"tools", nlohmann::json::object()}}},
        {"instructions",
            "This server provides access to the x64dbg debugger for reverse "
            "engineering: process inspection, breakpoints, disassembly, and "
            "memory of the debugged program."}
    };
    ApplyModernEnvelope(result);
    return result;
}

std::optional<std::string> McpServer::HandleMessage(const std::string& line)
{
    // Отбраковка входа ДО разбора JSON: рекурсивный разбор глубоко вложенной
    // или чрезмерно большой структуры может переполнить стек или память
    // раньше, чем разбор сообщит об ошибке — это нужно проверять на сыром
    // тексте, полагаться на сам парсер здесь нельзя.
    if (line.size() > kMaxMessageBytes)
        return MakeErrorResponse(nullptr, -32600, "Invalid Request: message too large").dump();

    if (ComputeMaxNestingDepth(line) > kMaxNestingDepth)
        return MakeErrorResponse(nullptr, -32600, "Invalid Request: message nesting too deep").dump();

    // Идентификатор запроса объявлен до try и используется в внешнем catch —
    // иначе ошибка -32603 при уже разобранном id уйдёт с id: null, и клиент
    // не сможет сопоставить ответ со своим запросом.
    nlohmann::json id = nullptr;

    // Последний рубеж: контракт запрещает исключениям покидать HandleMessage.
    // nlohmann::json бросает при доступе к отсутствующим или несовместимым по
    // типу полям, поэтому ловим всё, что могло проскочить мимо явных проверок
    // ниже — так метод гарантированно не пробросит исключение наружу.
    try
    {
        const nlohmann::json msg = nlohmann::json::parse(line, nullptr, false);
        if (msg.is_discarded())
            return MakeErrorResponse(nullptr, -32700, "Parse error").dump();

        if (!msg.is_object())
            return MakeErrorResponse(nullptr, -32600, "Invalid Request").dump();

        id = msg.contains("id") ? msg["id"] : nlohmann::json(nullptr);
        const bool isNotification = !msg.contains("id");

        // JSON-RPC 2.0 допускает для id только строку, число или null. Любой
        // другой тип строгий клиент не сможет сопоставить с запросом.
        if (!id.is_null() && !id.is_string() && !id.is_number())
            return MakeErrorResponse(nullptr, -32600, "Invalid Request: id must be a string, number, or null").dump();

        if (!msg.contains("method") || !msg["method"].is_string())
            return MakeErrorResponse(id, -32600, "Invalid Request").dump();

        const std::string method = msg["method"].get<std::string>();
        const nlohmann::json params = msg.value("params", nlohmann::json::object());

        if (method == "notifications/cancelled")
        {
            Log(LogLevel::Info, "notifications/cancelled: " + params.dump());
            return std::nullopt;
        }

        // Любое уведомление (сообщение без id) ответа не требует — это общее
        // правило JSON-RPC, а не особенность конкретного метода.
        if (isNotification)
            return std::nullopt;

        // Определение модели по самому сообщению: initialize — всегда
        // устаревшее рукопожатие; иначе — см. IsModernProtocol. Если модель
        // определена как современная, но внутри чего-то не хватает, это
        // выясняется ниже и превращается в корректную ошибку -32602, а не в
        // "метод не найден".
        const bool isModern = (method != "initialize") && IsModernProtocol(method, params);

        if (isModern)
        {
            const nlohmann::json meta = ExtractMeta(params);

            if (!meta.contains(kMetaProtocolVersion) || !meta[kMetaProtocolVersion].is_string())
            {
                return MakeErrorResponse(id, -32602,
                    std::string("Missing required field params._meta[\"") +
                    kMetaProtocolVersion + "\"]").dump();
            }

            if (!meta.contains(kMetaClientCapabilities) || !meta[kMetaClientCapabilities].is_object())
            {
                return MakeErrorResponse(id, -32602,
                    std::string("params._meta[\"") + kMetaClientCapabilities +
                    "\"] must be present and must be an object").dump();
            }

            const std::string requestedVersion = meta[kMetaProtocolVersion].get<std::string>();
            if (requestedVersion != kModernVersion)
            {
                // Клиенту нужно перечислить все версии, на которых сервер
                // может согласовать соединение, а не только современную —
                // иначе он не поймёт, что может откатиться на рукопожатие
                // initialize.
                nlohmann::json supported = nlohmann::json::array({ kModernVersion });
                for (const char* legacy : kLegacyVersions)
                    supported.push_back(legacy);

                const nlohmann::json data = {
                    {"supported", supported},
                    {"requested", requestedVersion}
                };
                return MakeErrorResponse(id, -32022, "Unsupported protocol version", data).dump();
            }

            nlohmann::json result;
            if (method == "server/discover")
                result = HandleDiscover();
            else if (method == "tools/list")
                result = HandleToolsList();
            else if (method == "ping")
                result = nlohmann::json::object();
            else if (method == "tools/call")
            {
                try
                {
                    result = HandleToolsCall(params);
                }
                catch (const ProtocolError& e)
                {
                    return MakeErrorResponse(id, e.code, e.message).dump();
                }
            }
            else
                return MakeErrorResponse(id, -32601, "Method not found: " + method).dump();

            ApplyModernEnvelope(result);
            return MakeResultResponse(id, result).dump();
        }

        // Устаревшая модель.
        if (method == "initialize")
        {
            std::string clientVersion;
            if (params.is_object() && params.contains("protocolVersion") && params["protocolVersion"].is_string())
                clientVersion = params["protocolVersion"].get<std::string>();

            // По умолчанию — наша самая новая устаревшая версия: если клиент
            // прислал версию, которую мы не знаем, соединение не рвём, а
            // называем свою версию, а не повторяем чужую как есть.
            std::string negotiated = kLegacyVersions[0];
            for (const char* known : kLegacyVersions)
            {
                if (clientVersion == known)
                {
                    negotiated = known;
                    break;
                }
            }

            const nlohmann::json result = {
                {"protocolVersion", negotiated},
                {"capabilities", {{"tools", nlohmann::json::object()}}},
                {"serverInfo", BuildServerInfo()}
            };
            return MakeResultResponse(id, result).dump();
        }

        if (method == "tools/list")
            return MakeResultResponse(id, HandleToolsList()).dump();

        if (method == "ping")
            return MakeResultResponse(id, nlohmann::json::object()).dump();

        if (method == "tools/call")
        {
            try
            {
                return MakeResultResponse(id, HandleToolsCall(params)).dump();
            }
            catch (const ProtocolError& e)
            {
                return MakeErrorResponse(id, e.code, e.message).dump();
            }
        }

        return MakeErrorResponse(id, -32601, "Method not found: " + method).dump();
    }
    catch (...)
    {
        return MakeErrorResponse(id, -32603, "Internal error").dump();
    }
}

} // namespace x64dbg_mcp::bridge
