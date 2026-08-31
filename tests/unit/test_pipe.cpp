#include "common/pipe_server.h"
#include "common/pipe_client.h"
#include "common/ipc_protocol.h"
#include "nlohmann/json.hpp"
#include "doctest/doctest.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using x64dbg_mcp::PipeServer;
using x64dbg_mcp::PipeClient;

namespace
{

// A unique pipe name per test so runs don't interfere with each other
// (including repeated back-to-back runs of the whole test suite).
std::string MakePipeName()
{
    static std::atomic<int> counter{0};
    return R"(\\.\pipe\x64dbg-mcp-test-)" + std::to_string(GetCurrentProcessId()) +
           "-" + std::to_string(++counter);
}

} // namespace

TEST_CASE("pipe: request-response") {
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

TEST_CASE("pipe: several requests in a row on one connection") {
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

TEST_CASE("pipe: a large message passes through whole and undamaged") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) {
        return request; // echo, to verify transfer integrity
    }));

    PipeClient client;
    REQUIRE(client.Connect(pipeName, 5000));

    // At least 1 MiB, content varies with a period not a power of two —
    // so any data shift would be noticeable.
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

TEST_CASE("pipe: binary data with null bytes survives transfer") {
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

TEST_CASE("pipe: connecting to a nonexistent pipe fails quickly") {
    const std::string pipeName = MakePipeName(); // no server was started on this name

    PipeClient client;
    const auto start = std::chrono::steady_clock::now();
    const bool connected = client.Connect(pipeName, 1000);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK_FALSE(connected);
    CHECK_FALSE(client.LastError().empty());
    CHECK(elapsed < std::chrono::milliseconds(1500));
}

TEST_CASE("pipe: an exception in the handler does not crash the server") {
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

    // The connection must continue to be served normally.
    REQUIRE(client.SendRequest("still alive", response, 2000));
    CHECK(response == "ok:still alive");

    server.Stop();
}

TEST_CASE("pipe: stopping the server while a client is connected does not hang") {
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

TEST_CASE("pipe: repeated Stop and Stop without Start are safe") {
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

TEST_CASE("pipe: pipe name already in use — a second Start returns false") {
    const std::string pipeName = MakePipeName();

    PipeServer serverA;
    REQUIRE(serverA.Start(pipeName, [](const std::string& request) { return request; }));

    PipeServer serverB;
    CHECK_FALSE(serverB.Start(pipeName, [](const std::string& request) { return request; }));

    serverA.Stop();
    serverB.Stop();
}

TEST_CASE("pipe: connecting and disconnecting without a single request does not kill the server (defect 1)") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) {
        return request + "-pong";
    }));

    // The bridge connected and exited without sending a single request
    // (Ctrl-C, client restart, liveness check) — this is a normal situation,
    // not a reason to stop accepting connections forever. We repeat the cycle
    // several times: not every attempt is guaranteed to land exactly in the
    // narrow ERROR_NO_DATA race window, but the server must survive them all.
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

TEST_CASE("pipe: stopping during a long-running handler does not leak handles (defect 2)") {
    auto getHandleCount = []() -> DWORD {
        DWORD count = 0;
        GetProcessHandleCount(GetCurrentProcess(), &count);
        return count;
    };

    // The handler sleeps longer than the thread-join wait limit in Stop()
    // (5 seconds) — Stop() must detach the thread instead of waiting for it
    // or closing handles out from under it. Several start/stop cycles must
    // not grow the process handle count.
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
        CHECK(elapsed < std::chrono::seconds(7)); // we don't wait for the handler's full kHandlerSleepMs

        requester.join();

        // Give the detached thread time to actually finish and close its
        // handles before we measure their count.
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        const DWORD current = getHandleCount();
        if (cycle == 0)
            baseline = current;
        else
            CHECK(current <= baseline + 5); // allowance for OS/CRT background noise
    }
}

TEST_CASE("pipe: protocol major version mismatch rejects the connection (defect 3)") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) { return request; }));

    PipeClient client(x64dbg_mcp::ipc::kProtocolVersionMajor + 1, 0);
    CHECK_FALSE(client.Connect(pipeName, 2000));
    CHECK_FALSE(client.LastError().empty());
    CHECK_FALSE(client.IsConnected());

    server.Stop();
}

TEST_CASE("pipe: a vanished client does not block a second connection (defect: single-instance pipe)") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) {
        return request + "-pong";
    }));

    {
        // The PipeClient API has no rawer teardown than this: its destructor
        // closes the handle (CancelIoEx + CloseHandle) without sending any
        // application-level goodbye — the protocol has none. This is the
        // closest thing to the client process just vanishing mid-conversation
        // while it is still connected.
        PipeClient client;
        REQUIRE(client.Connect(pipeName, 2000));
        std::string response;
        REQUIRE(client.SendRequest("ping", response, 2000));
        CHECK(response == "ping-pong");
    } // client destroyed here, with no further request pending

    PipeClient second;
    REQUIRE(second.Connect(pipeName, 2000));
    std::string response;
    REQUIRE(second.SendRequest("ping", response, 2000));
    CHECK(response == "ping-pong");

    server.Stop();
}

TEST_CASE("pipe: two clients connected at the same time are served correctly and not swapped") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) {
        return "resp:" + request;
    }));

    PipeClient clientA;
    REQUIRE(clientA.Connect(pipeName, 2000));
    PipeClient clientB;
    REQUIRE(clientB.Connect(pipeName, 2000));

    std::atomic<bool> aOk{true};
    std::atomic<bool> bOk{true};

    std::thread threadA([&]() {
        for (int i = 0; i < 30; ++i)
        {
            const std::string request = "A:" + std::to_string(i);
            std::string response;
            if (!clientA.SendRequest(request, response, 2000) || response != "resp:" + request)
                aOk = false;
        }
    });

    std::thread threadB([&]() {
        for (int i = 0; i < 30; ++i)
        {
            const std::string request = "B:" + std::to_string(i);
            std::string response;
            if (!clientB.SendRequest(request, response, 2000) || response != "resp:" + request)
                bOk = false;
        }
    });

    threadA.join();
    threadB.join();

    CHECK(aOk.load());
    CHECK(bOk.load());

    server.Stop();
}

TEST_CASE("pipe: stopping with several connections open completes promptly") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) {
        return request;
    }));

    constexpr int kClients = 5;
    std::vector<std::unique_ptr<PipeClient>> clients;
    for (int i = 0; i < kClients; ++i)
    {
        auto client = std::make_unique<PipeClient>();
        REQUIRE(client->Connect(pipeName, 2000));
        std::string response;
        REQUIRE(client->SendRequest("hello", response, 2000));
        clients.push_back(std::move(client));
    }

    const auto start = std::chrono::steady_clock::now();
    server.Stop();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(elapsed < std::chrono::seconds(2));
    CHECK_FALSE(server.IsRunning());
}

TEST_CASE("pipe: exceeding the connection limit does not crash the server, which keeps serving") {
    const std::string pipeName = MakePipeName();

    PipeServer server;
    REQUIRE(server.Start(pipeName, [](const std::string& request) {
        return request + "-pong";
    }));

    // More clients than the server's concurrent-connection bound. Some of
    // these connect attempts may themselves fail (ERROR_PIPE_BUSY, or the
    // connection being closed right after being accepted) — that is fine and
    // expected; what matters is that the server does not crash and keeps
    // serving afterward.
    constexpr int kClients = 12;
    std::vector<std::unique_ptr<PipeClient>> clients;
    for (int i = 0; i < kClients; ++i)
    {
        auto client = std::make_unique<PipeClient>();
        client->Connect(pipeName, 500);
        clients.push_back(std::move(client));
    }
    clients.clear(); // drop the excess connections

    // The server notices each dropped connection asynchronously (a
    // connection thread has to wake up and see the broken pipe before it
    // decrements the connection count), so a fresh connection right after
    // clients.clear() can still land in the narrow window where the count
    // has not caught up yet and gets bound-rejected — that is correct
    // behavior, not a bug, so retry for a bit rather than a single attempt.
    bool ok = false;
    std::string response;
    for (int attempt = 0; attempt < 30 && !ok; ++attempt)
    {
        PipeClient client;
        if (client.Connect(pipeName, 500) && client.SendRequest("ping", response, 2000))
            ok = true;
        else
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    REQUIRE(ok);
    CHECK(response == "ping-pong");

    server.Stop();
}

TEST_CASE("pipe: a rejected connection does not block the next client (defects 1 and 3)") {
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
