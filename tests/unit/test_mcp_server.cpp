#include "bridge/mcp_server.h"
#include "bridge/plugin_link.h"
#include "bridge/resource_registry.h"
#include "bridge/tool_registry.h"
#include "common/pipe_server.h"
#include "doctest/doctest.h"
#include "nlohmann/json.hpp"

#include <atomic>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using x64dbg_mcp::PipeServer;
using x64dbg_mcp::bridge::CreateDefaultRegistry;
using x64dbg_mcp::bridge::CreateDefaultResourceRegistry;
using x64dbg_mcp::bridge::kLegacyVersions;
using x64dbg_mcp::bridge::kModernVersion;
using x64dbg_mcp::bridge::McpServer;
using x64dbg_mcp::bridge::PluginLink;
using x64dbg_mcp::bridge::Resource;
using x64dbg_mcp::bridge::ResourceRegistry;
using x64dbg_mcp::bridge::Tool;
using x64dbg_mcp::bridge::ToolRegistry;
using x64dbg_mcp::bridge::ToolResult;
using nlohmann::json;

namespace
{

// A unique pipe name per test so runs with the fake plugin don't interfere
// with each other (including repeated back-to-back runs of the test suite).
std::string MakeMcpTestPipeName()
{
    static std::atomic<int> counter{0};
    return R"(\\.\pipe\x64dbg-mcp-mcp-server-test-)" + std::to_string(GetCurrentProcessId()) +
           "-" + std::to_string(++counter);
}

// A fresh server per test: HandleMessage keeps no state between calls,
// but it's easier to read scenarios in isolation this way. Includes the
// default resources (no link, so reads explain there is no connection
// rather than failing) so resources/list and resources/read tests have
// real, known uris to exercise.
McpServer MakeServer()
{
    return McpServer(CreateDefaultRegistry(), CreateDefaultResourceRegistry());
}

json Parse(const std::string& response)
{
    return json::parse(response);
}

// Checks that the json array of version strings contains the given value.
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

// ---- Legacy model (initialize handshake) ----

TEST_CASE("mcp: initialize with a known version echoes it back") {
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

TEST_CASE("mcp: initialize with an unknown version does not break the handshake, replies with its own version") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"1900-01-01","capabilities":{}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    REQUIRE(msg.contains("result"));
    // The server must not echo back the client-supplied version as is.
    CHECK(msg["result"]["protocolVersion"] != "1900-01-01");
}

TEST_CASE("mcp: notifications/initialized requires no response") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","method":"notifications/initialized"})";

    CHECK_FALSE(server.HandleMessage(request).has_value());
}

TEST_CASE("mcp: tools/list in the legacy model returns a non-empty tool list") {
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

TEST_CASE("mcp: tools/call for server_status returns content and structuredContent") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"server_status","arguments":{}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    REQUIRE(msg["result"]["content"].is_array());
    CHECK(msg["result"]["structuredContent"].contains("server_version"));
    // The MCP spec shows isError: false in examples of a successful result.
    CHECK(msg["result"]["isError"] == false);
}

// server_status sets a human-readable text, so content[0].text must be a
// readable string, not a serialized structuredContent.
TEST_CASE("mcp: content[0].text of a tool with an explicit text is not JSON") {
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

TEST_CASE("mcp: structuredContent of read_memory and disassemble has no top-level text field") {
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

TEST_CASE("mcp: a tool without explicit text gets an indented structuredContent serialization") {
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

// The MCP spec (Error Handling section) classifies an unknown tool name as
// a Protocol Error: "Unknown tool, Malformed requests, Server errors ...
// returned as standard JSON-RPC errors". Previously the server returned this
// as a result with isError: true, which contradicts the spec.
TEST_CASE("mcp: tools/call for a nonexistent tool gives JSON-RPC error -32602") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":4,"method":"tools/call",
        "params":{"name":"no_such_tool","arguments":{}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK_FALSE(msg.contains("result"));
    CHECK(msg["error"]["code"] == -32602);
}

// ---- Modern (stateless) model ----

TEST_CASE("mcp: server/discover with valid _meta returns the full server description") {
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

TEST_CASE("mcp: a modern-model request without protocolVersion in _meta -> error -32602") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":5,"method":"server/discover",
        "params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{}}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32602);
}

TEST_CASE("mcp: a modern-model request without clientCapabilities in _meta -> error -32602") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":6,"method":"server/discover",
        "params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32602);
}

TEST_CASE("mcp: unsupported modern protocol version -> error -32022") {
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
    // data.supported must contain not only the modern version but all the
    // legacy ones too: otherwise the client won't know it can fall back to initialize.
    for (const char* legacy : kLegacyVersions)
        CHECK(Contains(msg["error"]["data"]["supported"], legacy));
    CHECK(msg["error"]["data"]["requested"] == "1900-01-01");
}

TEST_CASE("mcp: tools/list in the modern model contains resultType complete") {
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

// ---- Regression: _meta with client-side keys must not switch the model ----

TEST_CASE("mcp: a real tools/call from Claude Code 2.1.251 with _meta lacking reserved keys succeeds") {
    // The verbatim message captured from Claude Code 2.1.251 (legacy
    // initialize handshake, version 2025-11-25). The previous implementation
    // saw a non-empty _meta, treated it as opting into the modern model,
    // required io.modelcontextprotocol/protocolVersion, didn't find it, and
    // responded -32602 on EVERY tool call — the server was unusable with
    // this client.
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

TEST_CASE("mcp: tools/list with a client progressToken in _meta is handled by the legacy model") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":10,"method":"tools/list",
        "params":{"_meta":{"progressToken":5}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK_FALSE(msg.contains("error"));
    REQUIRE(msg["result"]["tools"].is_array());
    REQUIRE_FALSE(msg["result"]["tools"].empty());
    // The legacy model does not wrap the result in the modern envelope.
    CHECK_FALSE(msg["result"].contains("resultType"));
}

TEST_CASE("mcp: a reserved clientCapabilities without protocolVersion is recognized as the modern model") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":11,"method":"tools/list",
        "params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{}}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32602);
}

TEST_CASE("mcp: _meta with both client and reserved keys together is handled by the modern model") {
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

TEST_CASE("mcp: server/discover without _meta is still the modern model, error -32602, not -32601") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":13,"method":"server/discover","params":{}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    REQUIRE(msg.contains("error"));
    CHECK(msg["error"]["code"] == -32602);
}

// ---- General ----

TEST_CASE("mcp: malformed JSON -> error -32700, id is null") {
    McpServer server = MakeServer();
    auto response = server.HandleMessage("{not json");
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32700);
    CHECK(msg["id"].is_null());
}

TEST_CASE("mcp: a message that is an array instead of an object -> error -32600") {
    McpServer server = MakeServer();
    auto response = server.HandleMessage("[1,2,3]");
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32600);
}

TEST_CASE("mcp: an unknown method in the legacy model -> error -32601") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":9,"method":"no/such/method","params":{}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32601);
}

TEST_CASE("mcp: notifications/cancelled requires no response") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}})";

    CHECK_FALSE(server.HandleMessage(request).has_value());
}

TEST_CASE("mcp: no response contains a newline") {
    // A real risk: if json::dump() ever starts printing the message with
    // indentation (or manual concatenation with '\n' creeps into the code),
    // a single MCP message would split into two lines and break the
    // line-oriented stdio transport.
    McpServer server = MakeServer();

    const std::vector<std::string> requests = {
        R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}})",
        R"({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})",
        R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"server_status","arguments":{}}})",
        R"({"jsonrpc":"2.0","id":"d1","method":"server/discover",
            "params":{"_meta":{
                "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientCapabilities":{}}}})",
        "{not json"
    };

    for (const auto& request : requests)
    {
        auto response = server.HandleMessage(request);
        REQUIRE(response.has_value());
        CHECK(response->find('\n') == std::string::npos);
    }
}

// ---- Protection against stack overflow and memory blowup on input ----

TEST_CASE("mcp: a message with 20000 levels of nesting is rejected with -32600, the process does not crash") {
    // The mere fact that this test reaches CHECK already proves the process
    // didn't crash: recursive parsing of this depth overflows the stack.
    McpServer server = MakeServer();
    const std::string request =
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":)" +
        std::string(20000, '[') + std::string(20000, ']') + "}}";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32600);
}

TEST_CASE("mcp: a message with acceptable nesting (10 levels) is handled normally") {
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

TEST_CASE("mcp: a message larger than the size limit -> error -32600") {
    McpServer server = MakeServer();
    // A value knowingly larger than the 8 MiB limit set in mcp_server.cpp.
    const std::string request =
        R"({"jsonrpc":"2.0","id":22,"method":"tools/list","params":{"pad":")" +
        std::string(9u * 1024u * 1024u, 'a') + "\"}}";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32600);
}

// ---- Parsing malformed tools/call as protocol errors ----

TEST_CASE("mcp: tools/call without params.name -> error -32602") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":23,"method":"tools/call","params":{"arguments":{}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32602);
}

TEST_CASE("mcp: tools/call with arguments as a string -> error -32602") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":24,"method":"tools/call",
        "params":{"name":"server_status","arguments":"a string"}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32602);
}

// ---- Request id type ----

TEST_CASE("mcp: id as an object -> error -32600 with id: null") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":{"a":1},"method":"tools/list","params":{}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32600);
    CHECK(msg["id"].is_null());
}

TEST_CASE("mcp: id as a string is handled normally and returned as a string") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":"req-1","method":"tools/list","params":{}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK_FALSE(msg.contains("error"));
    CHECK(msg["id"] == "req-1");
}

// ---- ping ----

TEST_CASE("mcp: ping returns a successful result, not -32601") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":25,"method":"ping","params":{}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK_FALSE(msg.contains("error"));
    REQUIRE(msg.contains("result"));
}

// ---- Regression: non-ASCII window titles must not corrupt the response ----

// TruncateForTable (debugger_tools.cpp) has internal linkage inside an
// anonymous namespace, so it is not reachable from a unit test directly.
// This test instead exercises the bug through the public tool interface it
// broke: list_windows on a window whose title contains multi-byte UTF-8
// (CJK) text. Before the fix, a byte-wise cut inside TruncateForTable could
// split a character and produce invalid UTF-8, which nlohmann::json::dump()
// then rejected with type_error.316 inside HandleToolsCall, and the
// exception was swallowed by HandleMessage's outermost catch into a bare
// "Internal error". The three paddings below shift a fixed 3-byte CJK
// character across the fixed cut offset used by FormatWindowList (28 - 3 =
// 25), covering all three byte-offsets a cut can land on within a
// character.
TEST_CASE("mcp: list_windows with a non-ASCII (CJK) title does not corrupt the response") {
    for (int pad = 0; pad < 3; ++pad)
    {
        const std::string pipeName = MakeMcpTestPipeName();

        // Build a genuinely valid, long, non-ASCII title: 20 repetitions of
        // a real 3-byte CJK character (U+4E2D, "中"), preceded by `pad`
        // ASCII bytes so the character boundaries shift relative to the
        // fixed cut offset used by TruncateForTable.
        std::string title(static_cast<std::size_t>(pad), 'A');
        for (int i = 0; i < 20; ++i)
            title += "\xE4\xB8\xAD";

        PipeServer pipeServer;
        REQUIRE(pipeServer.Start(pipeName, [&title](const std::string& request) -> std::string {
            const json parsed = json::parse(request);
            const std::string method = parsed.at("method").get<std::string>();

            json result;
            if (method == "process.windows")
            {
                result = { {"windows", json::array({
                    { {"handle", 1}, {"wndProc", 2}, {"threadId", 3},
                      {"title", title}, {"className", title} }
                })}, {"truncated", false} };
            }

            return json{ {"id", parsed.at("id")}, {"ok", true}, {"result", result} }.dump();
        }));

        auto link = std::make_shared<PluginLink>(pipeName, 1000, 3000);
        McpServer server(CreateDefaultRegistry(link));

        const std::string request = R"({"jsonrpc":"2.0","id":40,"method":"tools/call",
            "params":{"name":"list_windows","arguments":{}}})";
        auto response = server.HandleMessage(request);
        REQUIRE(response.has_value());

        // Before the fix, HandleMessage's own .dump() would throw on the
        // invalid UTF-8 and the whole response degraded to a bare -32603
        // "Internal error"; here the call must succeed instead.
        const json msg = Parse(*response);
        CHECK_FALSE(msg.contains("error"));
        REQUIRE(msg.contains("result"));
        CHECK(msg["result"]["isError"] == false);

        // Truncation is for the human-readable table only: the structured
        // result keeps the title untouched.
        CHECK(msg["result"]["structuredContent"]["windows"][0]["title"] == title);

        pipeServer.Stop();
    }
}

// ---- clientCapabilities must be an object ----

TEST_CASE("mcp: clientCapabilities not an object -> error -32602") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":26,"method":"server/discover",
        "params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":"not-an-object"}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32602);
}

// ---- Resources ----

TEST_CASE("mcp: resources/list in the legacy model returns the registered resources with all fields") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":50,"method":"resources/list","params":{}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    REQUIRE(msg["result"]["resources"].is_array());
    REQUIRE_FALSE(msg["result"]["resources"].empty());
    // The legacy model does not wrap the result in the modern envelope.
    CHECK_FALSE(msg["result"].contains("resultType"));

    const json& first = msg["result"]["resources"][0];
    CHECK(first.contains("uri"));
    CHECK(first.contains("name"));
    CHECK(first.contains("title"));
    CHECK(first.contains("description"));
    CHECK(first.contains("mimeType"));
}

TEST_CASE("mcp: resources/list in the modern model contains resultType complete") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":51,"method":"resources/list",
        "params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["result"]["resultType"] == "complete");
    REQUIRE(msg["result"]["resources"].is_array());
    REQUIRE_FALSE(msg["result"]["resources"].empty());
}

TEST_CASE("mcp: resources/read returns content for a known uri in the legacy model") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":52,"method":"resources/read",
        "params":{"uri":"x64dbg://memory-map"}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    REQUIRE(msg["result"]["contents"].is_array());
    REQUIRE(msg["result"]["contents"].size() == 1);
    CHECK(msg["result"]["contents"][0]["uri"] == "x64dbg://memory-map");
    CHECK(msg["result"]["contents"][0]["mimeType"] == "text/plain");
    CHECK_FALSE(msg["result"]["contents"][0]["text"].get<std::string>().empty());
}

TEST_CASE("mcp: resources/read returns content for a known uri in the modern model") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":53,"method":"resources/read",
        "params":{"uri":"x64dbg://disassembly/current",
        "_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["result"]["resultType"] == "complete");
    REQUIRE(msg["result"]["contents"].is_array());
    CHECK(msg["result"]["contents"][0]["uri"] == "x64dbg://disassembly/current");
    CHECK_FALSE(msg["result"]["contents"][0]["text"].get<std::string>().empty());
}

TEST_CASE("mcp: resources/read for an unknown uri -> error -32002") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":54,"method":"resources/read",
        "params":{"uri":"x64dbg://no-such-resource"}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK_FALSE(msg.contains("result"));
    CHECK(msg["error"]["code"] == -32002);
}

TEST_CASE("mcp: resources/read without params.uri -> error -32602") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":55,"method":"resources/read","params":{}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32602);
}

TEST_CASE("mcp: resources/read with a non-string uri -> error -32602") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":56,"method":"resources/read","params":{"uri":42}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK(msg["error"]["code"] == -32602);
}

// A resource read failure is content, not a protocol error: the model must
// see a clear explanation instead of a broken server, and no exception may
// escape HandleMessage.
TEST_CASE("mcp: resources/read for a resource whose read function throws returns a successful, explanatory result") {
    ResourceRegistry resources;
    Resource resource;
    resource.uri = "x64dbg://broken";
    resource.name = "broken";
    resource.title = "Broken resource";
    resource.description = "test resource";
    resource.mimeType = "text/plain";
    resource.read = []() -> std::string { throw std::runtime_error("boom"); };
    resources.Add(std::move(resource));

    McpServer server(ToolRegistry(), std::move(resources));
    const std::string request = R"({"jsonrpc":"2.0","id":57,"method":"resources/read",
        "params":{"uri":"x64dbg://broken"}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    CHECK_FALSE(msg.contains("error"));
    REQUIRE(msg.contains("result"));
    const std::string text = msg["result"]["contents"][0]["text"].get<std::string>();
    CHECK(text.find("boom") != std::string::npos);
}

// The regression test for the running server having advertised the
// 'resources' capability while main.cpp passed an empty registry to
// McpServer: CreateDefaultResourceRegistry must actually register all
// three resources, not just be reachable from tests that build their own
// registry.
TEST_CASE("mcp: CreateDefaultResourceRegistry registers all three resources") {
    ResourceRegistry resources = CreateDefaultResourceRegistry();

    CHECK(resources.Find("x64dbg://commands") != nullptr);
    CHECK(resources.Find("x64dbg://memory-map") != nullptr);
    CHECK(resources.Find("x64dbg://disassembly/current") != nullptr);

    const Resource* commands = resources.Find("x64dbg://commands");
    REQUIRE(commands != nullptr);
    const std::string text = commands->read();
    CHECK_FALSE(text.empty());
    CHECK(text.find("run") != std::string::npos);
    CHECK(text.find("HEX by default") != std::string::npos);
}

TEST_CASE("mcp: initialize capabilities include resources") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":58,"method":"initialize",
        "params":{"protocolVersion":"2025-11-25","capabilities":{}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    REQUIRE(msg["result"]["capabilities"].contains("resources"));
}

TEST_CASE("mcp: server/discover capabilities include resources") {
    McpServer server = MakeServer();
    const std::string request = R"({"jsonrpc":"2.0","id":"d2","method":"server/discover",
        "params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}}}})";

    auto response = server.HandleMessage(request);
    REQUIRE(response.has_value());

    const json msg = Parse(*response);
    REQUIRE(msg["result"]["capabilities"].contains("resources"));
}
