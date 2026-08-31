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

// Уникальное имя канала на каждый тест, чтобы прогоны не мешали друг другу
// (в том числе повторные прогоны всего набора тестов подряд).
std::string MakePipeName()
{
    static std::atomic<int> counter{0};
    return R"(\\.\pipe\x64dbg-mcp-link-test-)" + std::to_string(GetCurrentProcessId()) +
           "-" + std::to_string(++counter);
}

// Фиктивный обработчик плагина: разбирает запрос {id,method,params} и
// отвечает {id,ok:true,result}.
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

TEST_CASE("plugin_link: успешный вызов возвращает содержимое result") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, MakeOkHandler({{"debugging", true}, {"processId", 1234}})));

    PluginLink link(pipeName, 1000, 3000);
    const nlohmann::json result = link.Call("debugger.status", nlohmann::json::object());
    CHECK(result["debugging"] == true);
    CHECK(result["processId"] == 1234);

    server.Stop();
}

TEST_CASE("plugin_link: ошибка от плагина превращается в ToolError с тем же текстом") {
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

TEST_CASE("plugin_link: канал недоступен -> ToolError упоминает x64dbg и плагин, IsAvailable не бросает") {
    const std::string pipeName = MakePipeName(); // сервер на этом имени не запускался

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

TEST_CASE("plugin_link: переподключение после перезапуска сервера на том же имени") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, MakeOkHandler({{"ping", 1}})));

    PluginLink link(pipeName, 1000, 3000);
    const nlohmann::json first = link.Call("debugger.status", nlohmann::json::object());
    CHECK(first["ping"] == 1);

    server.Stop();

    PipeServer server2;
    REQUIRE(server2.Start(pipeName, MakeOkHandler({{"ping", 2}})));

    // Пользователь перезапустил x64dbg, не перезапуская MCP-клиент: второй
    // вызов через тот же PluginLink обязан пройти.
    const nlohmann::json second = link.Call("debugger.status", nlohmann::json::object());
    CHECK(second["ping"] == 2);

    server2.Stop();
}

TEST_CASE("plugin_link: некорректный (не JSON) ответ плагина -> ToolError, а не падение") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& /*request*/) -> std::string {
        return "not-json-at-all";
    }));

    PluginLink link(pipeName, 1000, 3000);
    CHECK_THROWS_AS(link.Call("debugger.status", nlohmann::json::object()), ToolError);

    server.Stop();
}

TEST_CASE("plugin_link: ответ без обязательных полей -> ToolError с внятным текстом") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) -> std::string {
        const nlohmann::json parsed = nlohmann::json::parse(request);
        // Нет поля "ok" — ответ не соответствует протоколу.
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

TEST_CASE("plugin_link: IsAvailable возвращает true при поднятом сервере") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, MakeOkHandler(nlohmann::json::object())));

    PluginLink link(pipeName, 1000, 3000);
    CHECK(link.IsAvailable());

    server.Stop();
}
