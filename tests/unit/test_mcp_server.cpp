#include "bridge/mcp_server.h"
#include "bridge/plugin_link.h"
#include "bridge/tool_registry.h"
#include "common/pipe_server.h"
#include "doctest/doctest.h"
#include "nlohmann/json.hpp"

#include <atomic>
#include <memory>
#include <string>
#include <vector>

using x64dbg_mcp::PipeServer;
using x64dbg_mcp::bridge::CreateDefaultRegistry;
using x64dbg_mcp::bridge::kLegacyVersions;
using x64dbg_mcp::bridge::kModernVersion;
using x64dbg_mcp::bridge::McpServer;
using x64dbg_mcp::bridge::PluginLink;
using x64dbg_mcp::bridge::Tool;
using x64dbg_mcp::bridge::ToolRegistry;
using x64dbg_mcp::bridge::ToolResult;
using nlohmann::json;

namespace
{

// Уникальное имя канала на каждый тест, чтобы прогоны с фиктивным плагином
// не мешали друг другу (в том числе повторные прогоны набора тестов подряд).
std::string MakeMcpTestPipeName()
{
    static std::atomic<int> counter{0};
    return R"(\\.\pipe\x64dbg-mcp-mcp-server-test-)" + std::to_string(GetCurrentProcessId()) +
           "-" + std::to_string(++counter);
}

// Свежий сервер на каждый тест: HandleMessage не хранит состояния между
// вызовами, но так проще читать сценарии по отдельности.
McpServer MakeServer()
{
    return McpServer(CreateDefaultRegistry());
}

json Parse(const std::string& response)
{
    return json::parse(response);
}

// Проверяет, что json-массив version-строк содержит указанное значение.
bool Contains(const json& array, const std::string& value)
{
    for (const auto& item : array)
    {
        if (item == value)
            return true;
    }
    return false;
}

} // namespace

// ---- Устаревшая модель (рукопожатие initialize) ----

TEST_CASE("mcp: initialize с известной версией возвращает её эхом") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-11-25","capabilities":{}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["result"]["protocolVersion"] == "2025-11-25");
    CHECK(msg["result"]["capabilities"].contains("tools"));
    CHECK(msg["result"]["serverInfo"].contains("name"));
}

TEST_CASE("mcp: initialize с неизвестной версией не рвёт рукопожатие, отвечает своей версией") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"1900-01-01","capabilities":{}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    REQUIRE(msg.contains("result"));
    // Сервер не должен вернуть присланную клиентом версию как есть.
    CHECK(msg["result"]["protocolVersion"] != "1900-01-01");
}

TEST_CASE("mcp: notifications/initialized не требует ответа") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","method":"notifications/initialized"})";

    CHECK_FALSE(server.HandleMessage(request).has_value());
}

TEST_CASE("mcp: tools/list в устаревшей модели возвращает непустой список инструментов") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    REQUIRE(msg["result"]["tools"].is_array());
    REQUIRE_FALSE(msg["result"]["tools"].empty());

    const json& first = msg["result"]["tools"][0];
    CHECK(first.contains("name"));
    CHECK(first.contains("description"));
    CHECK(first.contains("inputSchema"));
}

TEST_CASE("mcp: tools/call для server_status возвращает content и structuredContent") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"server_status","arguments":{}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    REQUIRE(msg["result"]["content"].is_array());
    CHECK(msg["result"]["structuredContent"].contains("server_version"));
    // Спецификация MCP показывает isError: false в примерах успешного результата.
    CHECK(msg["result"]["isError"] == false);
}

// server_status задаёт человекочитаемый text, поэтому content[0].text должен
// быть читаемой строкой, а не сериализованным structuredContent.
TEST_CASE("mcp: content[0].text инструмента с заданным text не является JSON") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":30,"method":"tools/call",
        "params":{"name":"server_status","arguments":{}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    const std::string text = msg["result"]["content"][0]["text"].get<std::string>();
    REQUIRE_FALSE(text.empty());
    CHECK(text[0] != '{');
}

TEST_CASE("mcp: structuredContent read_memory и disassemble не содержит поле text верхнего уровня") {
    const std::string pipeName = MakeMcpTestPipeName();

    PipeServer pipeServer;
    REQUIRE(pipeServer.Start(pipeName, [](const std::string& request) -> std::string {
        const json parsed = json::parse(request);
        const std::string method = parsed.at("method").get<std::string>();

        json result;
        if (method == "memory.read")
            result = { {"address", 0}, {"size", 4}, {"data", "deadbeef"} };
        else if (method == "disasm")
            result = json::array({ {{"address", 0}, {"size", 1}, {"text", "nop"}, {"bytes", "90"}} });

        return json{ {"id", parsed.at("id")}, {"ok", true}, {"result", result} }.dump();
    }));

    auto link = std::make_shared<PluginLink>(pipeName, 1000, 3000);
    McpServer server(CreateDefaultRegistry(link));

    const std::string readRequest = R"({"jsonrpc":"2.0","id":31,"method":"tools/call",
        "params":{"name":"read_memory","arguments":{"address":0,"size":4}}})";
    auto readResponse = server.HandleMessage(readRequest);
    REQUIRE(readResponse.has_value());
    const json readMsg = Parse(*readResponse);
    CHECK_FALSE(readMsg["result"]["structuredContent"].contains("text"));
    CHECK(readMsg["result"]["content"][0]["text"].get<std::string>()[0] != '{');

    const std::string disasmRequest = R"({"jsonrpc":"2.0","id":32,"method":"tools/call",
        "params":{"name":"disassemble","arguments":{"address":0,"count":1}}})";
    auto disasmResponse = server.HandleMessage(disasmRequest);
    REQUIRE(disasmResponse.has_value());
    const json disasmMsg = Parse(*disasmResponse);
    CHECK_FALSE(disasmMsg["result"]["structuredContent"].contains("text"));
    CHECK(disasmMsg["result"]["content"][0]["text"].get<std::string>()[0] != '{');

    pipeServer.Stop();
}

TEST_CASE("mcp: инструмент без заданного text получает сериализацию structuredContent с отступами") {
    ToolRegistry registry;
    Tool tool;
    tool.name = "fake_tool";
    tool.description = "test tool";
    tool.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", json::object()},
        {"additionalProperties", false}
    };
    tool.handler = [](const json& /*arguments*/) -> ToolResult {
        ToolResult result;
        result.structuredContent = { {"a", 1}, {"b", {{"c", 2}}} };
        return result;
    };
    registry.Add(std::move(tool));

    McpServer server(std::move(registry));
    const std::string request = R"({"jsonrpc":"2.0","id":33,"method":"tools/call",
        "params":{"name":"fake_tool","arguments":{}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    const std::string text = msg["result"]["content"][0]["text"].get<std::string>();
    CHECK(text == msg["result"]["structuredContent"].dump(2));
    CHECK(text.find('\n') != std::string::npos);
}

// Спецификация MCP (раздел Error Handling) относит неизвестное имя
// инструмента к Protocol Errors: "Unknown tool, Malformed requests, Server
// errors ... returned as standard JSON-RPC errors". Ранее сервер возвращал
// это как результат с isError: true, что противоречит спецификации.
TEST_CASE("mcp: tools/call для несуществующего инструмента даёт ошибку JSON-RPC -32602") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":4,"method":"tools/call",
        "params":{"name":"no_such_tool","arguments":{}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK_FALSE(msg.contains("result"));
    CHECK(msg["error"]["code"] == -32602);
}

// ---- Современная (stateless) модель ----

TEST_CASE("mcp: server/discover с корректным _meta возвращает полное описание сервера") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":"d1","method":"server/discover",
        "params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["result"]["resultType"] == "complete");
    CHECK(Contains(msg["result"]["supportedVersions"], kModernVersion));
    CHECK(msg["result"]["_meta"].contains("io.modelcontextprotocol/serverInfo"));
}

TEST_CASE("mcp: запрос современной модели без protocolVersion в _meta -> ошибка -32602") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":5,"method":"server/discover",
        "params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{}}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32602);
}

TEST_CASE("mcp: запрос современной модели без clientCapabilities в _meta -> ошибка -32602") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":6,"method":"server/discover",
        "params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32602);
}

TEST_CASE("mcp: неподдерживаемая версия современного протокола -> ошибка -32022") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":7,"method":"server/discover",
        "params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion":"1900-01-01",
            "io.modelcontextprotocol/clientCapabilities":{}}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32022);
    CHECK(Contains(msg["error"]["data"]["supported"], kModernVersion));
    // data.supported должен содержать не только современную версию, но и все
    // устаревшие: иначе клиент не поймёт, что может откатиться на initialize.
    for (const char* legacy : kLegacyVersions)
        CHECK(Contains(msg["error"]["data"]["supported"], legacy));
    CHECK(msg["error"]["data"]["requested"] == "1900-01-01");
}

TEST_CASE("mcp: tools/list в современной модели содержит resultType complete") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":8,"method":"tools/list",
        "params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["result"]["resultType"] == "complete");
    REQUIRE_FALSE(msg["result"]["tools"].empty());
}

// ---- Регрессия: _meta с клиентскими ключами не должен переключать модель ----

TEST_CASE("mcp: реальный tools/call от Claude Code 2.1.251 с _meta без зарезервированных ключей проходит") {
    // Дословное сообщение, перехваченное от Claude Code 2.1.251 (устаревшее
    // рукопожатие initialize, версия 2025-11-25). Прежняя реализация видела
    // непустой _meta, считала это заявкой на современную модель, требовала
    // io.modelcontextprotocol/protocolVersion, не находила его и отвечала
    // -32602 на КАЖДЫЙ вызов инструмента — сервер был неработоспособен с
    // этим клиентом.
    McpServer server = MakeServer();
    const std::string request =
        R"({"method":"tools/call","params":{"name":"server_status","arguments":{},)"
        R"("_meta":{"claudecode/toolUseId":"toolu_01H5MWZpag2yLEKD9wemGFSu","progressToken":2}},)"
        R"("jsonrpc":"2.0","id":2})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK_FALSE(msg.contains("error"));
    CHECK(msg["result"]["structuredContent"].contains("server_version"));
}

TEST_CASE("mcp: tools/list с клиентским progressToken в _meta обрабатывается по устаревшей модели") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":10,"method":"tools/list",
        "params":{"_meta":{"progressToken":5}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK_FALSE(msg.contains("error"));
    REQUIRE(msg["result"]["tools"].is_array());
    REQUIRE_FALSE(msg["result"]["tools"].empty());
    // Устаревшая модель не оборачивает результат в конверт современной.
    CHECK_FALSE(msg["result"].contains("resultType"));
}

TEST_CASE("mcp: зарезервированный clientCapabilities без protocolVersion распознаётся как современная модель") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":11,"method":"tools/list",
        "params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{}}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32602);
}

TEST_CASE("mcp: _meta с клиентскими и зарезервированными ключами одновременно обрабатывается по современной модели") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":12,"method":"tools/list",
        "params":{"_meta":{
            "progressToken":7,
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK_FALSE(msg.contains("error"));
    CHECK(msg["result"]["resultType"] == "complete");
}

TEST_CASE("mcp: server/discover без _meta всё равно современная модель, ошибка -32602, а не -32601") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":13,"method":"server/discover","params":{}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    REQUIRE(msg.contains("error"));
    CHECK(msg["error"]["code"] == -32602);
}

// ---- Общее ----

TEST_CASE("mcp: битый JSON -> ошибка -32700, id равен null") {
    McpServer server = MakeServer();
    auto response = server.HandleMessage("{не json");
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32700);
    CHECK(msg["id"].is_null());
}

TEST_CASE("mcp: сообщение-массив вместо объекта -> ошибка -32600") {
    McpServer server = MakeServer();
    auto response = server.HandleMessage("[1,2,3]");
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32600);
}

TEST_CASE("mcp: неизвестный метод в устаревшей модели -> ошибка -32601") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":9,"method":"no/such/method","params":{}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32601);
}

TEST_CASE("mcp: notifications/cancelled не требует ответа") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}})";

    CHECK_FALSE(server.HandleMessage(request).has_value());
}

TEST_CASE("mcp: ни один ответ не содержит перевода строки") {
    // Реальный риск: если json::dump() когда-нибудь начнёт печатать
    // сообщение с отступами (или в код закрадётся ручная конкатенация с
    // '\n'), одно сообщение MCP разорвётся на две строки и сломает
    // построчный транспорт stdio.
    McpServer server = MakeServer();

    const std::vector<std::string> requests = {
        R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}})",
        R"({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})",
        R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"server_status","arguments":{}}})",
        R"({"jsonrpc":"2.0","id":"d1","method":"server/discover",
            "params":{"_meta":{
                "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientCapabilities":{}}}})",
        "{не json"
    };

    for (const auto& request : requests)
    {
        auto response = server.HandleMessage(request);
        REQUIRE(response.has_value());
        CHECK(response->find('\n') == std::string::npos);
    }
}

// ---- Защита от переполнения стека и раздувания памяти на входе ----

TEST_CASE("mcp: сообщение с 20000 уровней вложенности отбраковывается -32600, процесс не падает") {
    // Сам факт, что этот тест дошёл до CHECK, уже доказывает отсутствие
    // падения процесса: рекурсивный разбор такой глубины переполняет стек.
    McpServer server = MakeServer();
    const std::string request =
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":)" +
        std::string(20000, '[') + std::string(20000, ']') + "}}";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32600);
}

TEST_CASE("mcp: сообщение с допустимой вложенностью (10 уровней) обрабатывается нормально") {
    McpServer server = MakeServer();
    const std::string request =
        R"({"jsonrpc":"2.0","id":21,"method":"tools/list","params":{"nested":)" +
        std::string(10, '[') + "1" + std::string(10, ']') + "}}";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK_FALSE(msg.contains("error"));
    REQUIRE(msg["result"]["tools"].is_array());
}

TEST_CASE("mcp: сообщение размером больше предела -> ошибка -32600") {
    McpServer server = MakeServer();
    // Значение заведомо больше лимита в 8 МиБ, заданного в mcp_server.cpp.
    const std::string request =
        R"({"jsonrpc":"2.0","id":22,"method":"tools/list","params":{"pad":")" +
        std::string(9u * 1024u * 1024u, 'a') + "\"}}";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32600);
}

// ---- Разбор некорректных tools/call как ошибок протокола ----

TEST_CASE("mcp: tools/call без params.name -> ошибка -32602") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":23,"method":"tools/call","params":{"arguments":{}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32602);
}

TEST_CASE("mcp: tools/call с arguments в виде строки -> ошибка -32602") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":24,"method":"tools/call",
        "params":{"name":"server_status","arguments":"строка"}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32602);
}

// ---- Тип id запроса ----

TEST_CASE("mcp: id в виде объекта -> ошибка -32600 с id: null") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":{"a":1},"method":"tools/list","params":{}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32600);
    CHECK(msg["id"].is_null());
}

TEST_CASE("mcp: id в виде строки обрабатывается нормально и возвращается строкой") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":"req-1","method":"tools/list","params":{}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK_FALSE(msg.contains("error"));
    CHECK(msg["id"] == "req-1");
}

// ---- ping ----

TEST_CASE("mcp: ping возвращает успешный результат, а не -32601") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":25,"method":"ping","params":{}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK_FALSE(msg.contains("error"));
    REQUIRE(msg.contains("result"));
}

// ---- clientCapabilities должен быть объектом ----

TEST_CASE("mcp: clientCapabilities не объект -> ошибка -32602") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":26,"method":"server/discover",
        "params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":"не-объект"}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32602);
}
