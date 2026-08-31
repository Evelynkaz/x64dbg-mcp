#include "bridge/plugin_link.h"
#include "bridge/tool_registry.h"
#include "common/pipe_server.h"
#include "nlohmann/json.hpp"
#include "doctest/doctest.h"

#include <atomic>
#include <string>

using x64dbg_mcp::PipeServer;
using x64dbg_mcp::bridge::PluginLink;
using x64dbg_mcp::bridge::ToolError;

namespace
{

// A unique pipe name per test so runs don't interfere with each other
// (including repeated back-to-back runs of the whole test suite).
std::string MakePipeName()
{
    static std::atomic<int> counter{0};
    return R"(\\.\pipe\x64dbg-mcp-link-test-)" + std::to_string(GetCurrentProcessId()) +
           "-" + std::to_string(++counter);
}

// A fake plugin handler: parses the {id,method,params} request and
// responds with {id,ok:true,result}.
PipeServer::RequestHandler MakeOkHandler(const nlohmann::json& result)
{
    return [result](const std::string& request) -> std::string
    {
        const nlohmann::json parsed = nlohmann::json::parse(request);
        return nlohmann::json{
            {"id", parsed.at("id")},
            {"ok", true},
            {"result", result}
        }.dump();
    };
}

} // namespace

TEST_CASE("plugin_link: a successful call returns the content of result") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, MakeOkHandler({{"debugging", true}, {"processId", 1234}})));

    PluginLink link(pipeName, 1000, 3000);
    const nlohmann::json result = link.Call("debugger.status", nlohmann::json::object());
    CHECK(result["debugging"] == true);
    CHECK(result["processId"] == 1234);

    server.Stop();
}

TEST_CASE("plugin_link: an error from the plugin becomes a ToolError with the same text") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) -> std::string {
        const nlohmann::json parsed = nlohmann::json::parse(request);
        return nlohmann::json{
            {"id", parsed.at("id")},
            {"ok", false},
            {"error", {{"code", 3}, {"message", "Not debugging: start a session first"}}}
        }.dump();
    }));

    PluginLink link(pipeName, 1000, 3000);

    bool threw = false;
    try
    {
        link.Call("debugger.status", nlohmann::json::object());
    }
    catch (const ToolError& e)
    {
        threw = true;
        CHECK(std::string(e.what()).find("Not debugging: start a session first") != std::string::npos);
    }
    CHECK(threw);

    server.Stop();
}

TEST_CASE("plugin_link: pipe unavailable -> ToolError mentions x64dbg and the plugin, IsAvailable does not throw") {
    const std::string pipeName = MakePipeName(); // no server was started on this name

    PluginLink link(pipeName, 500, 2000);

    CHECK_FALSE(link.IsAvailable());

    bool threw = false;
    try
    {
        link.Call("debugger.status", nlohmann::json::object());
    }
    catch (const ToolError& e)
    {
        threw = true;
        const std::string message = e.what();
        CHECK(message.find("x64dbg") != std::string::npos);
        CHECK(message.find("plugin") != std::string::npos);
    }
    CHECK(threw);
}

TEST_CASE("plugin_link: reconnects after the server restarts on the same name") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, MakeOkHandler({{"ping", 1}})));

    PluginLink link(pipeName, 1000, 3000);
    const nlohmann::json first = link.Call("debugger.status", nlohmann::json::object());
    CHECK(first["ping"] == 1);

    server.Stop();

    PipeServer server2;
    REQUIRE(server2.Start(pipeName, MakeOkHandler({{"ping", 2}})));

    // The user restarted x64dbg without restarting the MCP client: the second
    // call through the same PluginLink must succeed.
    const nlohmann::json second = link.Call("debugger.status", nlohmann::json::object());
    CHECK(second["ping"] == 2);

    server2.Stop();
}

TEST_CASE("plugin_link: an invalid (non-JSON) plugin response -> ToolError, not a crash") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& /*request*/) -> std::string {
        return "not-json-at-all";
    }));

    PluginLink link(pipeName, 1000, 3000);
    CHECK_THROWS_AS(link.Call("debugger.status", nlohmann::json::object()), ToolError);

    server.Stop();
}

TEST_CASE("plugin_link: a response missing required fields -> ToolError with a clear message") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) -> std::string {
        const nlohmann::json parsed = nlohmann::json::parse(request);
        // No "ok" field — the response doesn't conform to the protocol.
        return nlohmann::json{{"id", parsed.at("id")}}.dump();
    }));

    PluginLink link(pipeName, 1000, 3000);

    bool threw = false;
    try
    {
        link.Call("debugger.status", nlohmann::json::object());
    }
    catch (const ToolError& e)
    {
        threw = true;
        CHECK_FALSE(std::string(e.what()).empty());
    }
    CHECK(threw);

    server.Stop();
}

TEST_CASE("plugin_link: IsAvailable returns true while the server is up") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, MakeOkHandler(nlohmann::json::object())));

    PluginLink link(pipeName, 1000, 3000);
    CHECK(link.IsAvailable());

    server.Stop();
}
