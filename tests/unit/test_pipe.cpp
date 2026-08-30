#include "common/pipe_server.h"
#include "common/pipe_client.h"
#include "common/ipc_protocol.h"
#include "nlohmann/json.hpp"
#include "doctest/doctest.h"

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>

using x64dbg_mcp::PipeServer;
using x64dbg_mcp::PipeClient;

namespace
{

// Уникальное имя канала на каждый тест, чтобы прогоны не мешали друг другу
// (в том числе повторные прогоны всего набора тестов подряд).
std::string MakePipeName()
{
    static std::atomic<int> counter{0};
    return R"(\\.\pipe\x64dbg-mcp-test-)" + std::to_string(GetCurrentProcessId()) +
           "-" + std::to_string(++counter);
}

} // namespace

TEST_CASE("pipe: запрос-ответ") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) {
        return request + "-pong";
    }));

    PipeClient client;
    REQUIRE(client.Connect(pipeName, 2000));

    std::string response;
    REQUIRE(client.SendRequest("ping", response, 2000));
    CHECK(response == "ping-pong");

    server.Stop();
}

TEST_CASE("pipe: несколько запросов подряд по одному соединению") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) {
        return "resp:" + request;
    }));

    PipeClient client;
    REQUIRE(client.Connect(pipeName, 2000));

    for (int i = 0; i < 20; ++i)
    {
        const std::string request = "req:" + std::to_string(i);
        std::string response;
        REQUIRE(client.SendRequest(request, response, 2000));
        CHECK(response == "resp:" + request);
    }

    server.Stop();
}

TEST_CASE("pipe: крупное сообщение проходит целиком и без искажений") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) {
        return request; // эхо, чтобы проверить целостность передачи
    }));

    PipeClient client;
    REQUIRE(client.Connect(pipeName, 5000));

    // Не менее 1 МиБ, содержимое меняется по периоду, не кратному степени
    // двойки — чтобы сдвиг данных был заметен.
    const size_t size = 1024 * 1024 + 37;
    std::string payload(size, '\0');
    for (size_t i = 0; i < size; ++i)
        payload[i] = static_cast<char>((i * 7 + 3) % 251);

    std::string response;
    REQUIRE(client.SendRequest(payload, response, 5000));
    REQUIRE(response.size() == payload.size());
    CHECK(response == payload);

    server.Stop();
}

TEST_CASE("pipe: двоичные данные с нулевыми байтами переживают передачу") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) {
        return request;
    }));

    PipeClient client;
    REQUIRE(client.Connect(pipeName, 2000));

    std::string payload(1000, '\0');
    for (size_t i = 0; i < payload.size(); ++i)
        payload[i] = (i % 13 == 0) ? '\0' : static_cast<char>(i & 0xFF);

    std::string response;
    REQUIRE(client.SendRequest(payload, response, 2000));
    REQUIRE(response.size() == payload.size());
    CHECK(response == payload);

    server.Stop();
}

TEST_CASE("pipe: подключение к несуществующему каналу завершается неудачей быстро") {
    const std::string pipeName = MakePipeName(); // сервер на этом имени не запускался

    PipeClient client;
    const auto start = std::chrono::steady_clock::now();
    const bool connected = client.Connect(pipeName, 1000);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK_FALSE(connected);
    CHECK_FALSE(client.LastError().empty());
    CHECK(elapsed < std::chrono::milliseconds(1500));
}

TEST_CASE("pipe: исключение в обработчике не роняет сервер") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) -> std::string {
        if (request == "boom")
            throw std::runtime_error("handler failure");
        return "ok:" + request;
    }));

    PipeClient client;
    REQUIRE(client.Connect(pipeName, 2000));

    std::string response;
    REQUIRE(client.SendRequest("boom", response, 2000));

    const nlohmann::json parsed = nlohmann::json::parse(response, nullptr, false);
    REQUIRE_FALSE(parsed.is_discarded());
    CHECK(parsed[x64dbg_mcp::ipc::kFieldOk] == false);
    CHECK(parsed[x64dbg_mcp::ipc::kFieldError][x64dbg_mcp::ipc::kFieldErrorCode] ==
          static_cast<int>(x64dbg_mcp::ipc::ErrorCode::Internal));
    CHECK_FALSE(parsed[x64dbg_mcp::ipc::kFieldError][x64dbg_mcp::ipc::kFieldErrorMessage]
                    .get<std::string>()
                    .empty());

    // Соединение должно и дальше обслуживаться штатно.
    REQUIRE(client.SendRequest("still alive", response, 2000));
    CHECK(response == "ok:still alive");

    server.Stop();
}

TEST_CASE("pipe: остановка сервера при подключённом клиенте не виснет") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) {
        return request;
    }));

    PipeClient client;
    REQUIRE(client.Connect(pipeName, 2000));

    const auto start = std::chrono::steady_clock::now();
    server.Stop();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(elapsed < std::chrono::seconds(2));
    CHECK_FALSE(server.IsRunning());
}

TEST_CASE("pipe: повторный Stop и Stop без Start безопасны") {
    PipeServer neverStarted;
    neverStarted.Stop();
    neverStarted.Stop();

    const std::string pipeName = MakePipeName();
    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) { return request; }));

    server.Stop();
    server.Stop();
    CHECK_FALSE(server.IsRunning());
}

TEST_CASE("pipe: занятое имя канала — второй Start возвращает false") {
    const std::string pipeName = MakePipeName();

    PipeServer serverA;
    REQUIRE(serverA.Start(pipeName, [](const std::string& request) { return request; }));

    PipeServer serverB;
    CHECK_FALSE(serverB.Start(pipeName, [](const std::string& request) { return request; }));

    serverA.Stop();
    serverB.Stop();
}

TEST_CASE("pipe: подключение и отключение без единого запроса не убивают сервер (дефект 1)") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) {
        return request + "-pong";
    }));

    // Мост подключился и вышел, не отправив ни одного запроса (Ctrl-C,
    // перезапуск клиента, проверка живости) — это штатная ситуация, а не
    // повод остановить приём соединений навсегда. Повторяем цикл несколько
    // раз: далеко не каждая попытка обязана попасть точно в узкое окно гонки
    // ERROR_NO_DATA, но сервер обязан пережить их все.
    for (int cycle = 0; cycle < 5; ++cycle)
    {
        {
            PipeClient idle;
            REQUIRE(idle.Connect(pipeName, 2000));
            idle.Disconnect();
        }

        PipeClient client;
        REQUIRE(client.Connect(pipeName, 2000));
        std::string response;
        REQUIRE(client.SendRequest("ping", response, 2000));
        CHECK(response == "ping-pong");
    }

    server.Stop();
}

TEST_CASE("pipe: остановка при долгом обработчике не приводит к утечке дескрипторов (дефект 2)") {
    auto getHandleCount = []() -> DWORD {
        DWORD count = 0;
        GetProcessHandleCount(GetCurrentProcess(), &count);
        return count;
    };

    // Обработчик спит дольше предела ожидания присоединения потока в Stop()
    // (5 секунд) — Stop() обязан отсоединить поток, а не дождаться его или
    // закрыть дескрипторы у него из-под ног. Несколько циклов запуска и
    // остановки не должны наращивать число дескрипторов процесса.
    constexpr int kCycles = 3;
    constexpr int kHandlerSleepMs = 5500;
    DWORD baseline = 0;

    for (int cycle = 0; cycle < kCycles; ++cycle)
    {
        const std::string pipeName = MakePipeName();

        PipeServer server;
        std::atomic<bool> handlerEntered{false};
        REQUIRE(server.Start(pipeName, [&](const std::string& request) -> std::string {
            handlerEntered = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(kHandlerSleepMs));
            return request;
        }));

        PipeClient client;
        REQUIRE(client.Connect(pipeName, 2000));

        std::thread requester([&client]() {
            std::string response;
            client.SendRequest("slow", response, 8000);
        });

        while (!handlerEntered.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(10));

        const auto start = std::chrono::steady_clock::now();
        server.Stop();
        const auto elapsed = std::chrono::steady_clock::now() - start;
        CHECK(elapsed < std::chrono::seconds(7)); // не ждём все kHandlerSleepMs обработчика

        requester.join();

        // Даём отсоединённому потоку время фактически завершиться и закрыть
        // свои дескрипторы, прежде чем измерять их число.
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        const DWORD current = getHandleCount();
        if (cycle == 0)
            baseline = current;
        else
            CHECK(current <= baseline + 5); // допуск на служебный шум ОС/CRT
    }
}

TEST_CASE("pipe: несовпадение мажорной версии протокола отклоняет подключение (дефект 3)") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) { return request; }));

    PipeClient client(x64dbg_mcp::ipc::kProtocolVersionMajor + 1, 0);
    CHECK_FALSE(client.Connect(pipeName, 2000));
    CHECK_FALSE(client.LastError().empty());
    CHECK_FALSE(client.IsConnected());

    server.Stop();
}

TEST_CASE("pipe: отклонённое соединение не мешает следующему клиенту (дефект 1 и 3)") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) {
        return request + "-pong";
    }));

    PipeClient badClient(x64dbg_mcp::ipc::kProtocolVersionMajor + 1, 0);
    CHECK_FALSE(badClient.Connect(pipeName, 2000));

    PipeClient goodClient;
    REQUIRE(goodClient.Connect(pipeName, 2000));
    std::string response;
    REQUIRE(goodClient.SendRequest("ping", response, 2000));
    CHECK(response == "ping-pong");

    server.Stop();
}
