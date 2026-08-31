#include "plugin/worker.h"
#include "doctest/doctest.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

using x64dbg_mcp::plugin::DebuggerWorker;

TEST_CASE("worker: task runs and Submit returns Completed") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    std::atomic<bool> ran{false};
    const auto result = worker.Submit([&] { ran = true; }, 2000);

    CHECK(result == DebuggerWorker::SubmitResult::Completed);
    CHECK(ran.load());

    worker.Stop();
}

TEST_CASE("worker: tasks run in the order they were submitted") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    std::mutex mutex;
    std::vector<int> order;

    // A gate task holds the worker thread while we enqueue the other tasks
    // from separate threads — otherwise, calling Submit sequentially from a
    // single thread would only check that the previous task finished before
    // the next one was submitted, not the order the queue is processed in.
    std::atomic<bool> release{false};
    std::thread gateThread([&] {
        worker.Submit([&] {
            while (!release.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }, 5000);
    });

    // Wait until the gate has definitely taken over the worker thread.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // A small pause between submitting each task makes the order they land
    // in the queue deterministic for the test.
    std::vector<std::thread> submitters;
    for (int i = 0; i < 4; ++i)
    {
        submitters.emplace_back([&, i] {
            worker.Submit([&, i] {
                std::lock_guard<std::mutex> lock(mutex);
                order.push_back(i);
            }, 5000);
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    release = true;
    gateThread.join();
    for (auto& t : submitters)
        t.join();

    REQUIRE(order.size() == 4);
    CHECK(order == std::vector<int>({0, 1, 2, 3}));

    worker.Stop();
}

TEST_CASE("worker: all tasks run on the same thread") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    std::mutex mutex;
    std::vector<std::thread::id> ids;

    for (int i = 0; i < 5; ++i)
    {
        worker.Submit([&] {
            std::lock_guard<std::mutex> lock(mutex);
            ids.push_back(std::this_thread::get_id());
        }, 2000);
    }

    REQUIRE(ids.size() == 5);
    for (const auto& id : ids)
    {
        CHECK(id == ids.front());
        CHECK(id != std::this_thread::get_id());
    }

    worker.Stop();
}

TEST_CASE("worker: a task that exceeds its time gives Timeout, and later tasks run normally") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    std::atomic<bool> slowTaskFinished{false};
    const auto slowResult = worker.Submit([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
        slowTaskFinished = true;
    }, 100);

    CHECK(slowResult == DebuggerWorker::SubmitResult::Timeout);
    // The slow task wasn't interrupted and keeps running — Submit just
    // stopped waiting for it. This checks ref-counted ownership:
    // TaskCompletion outlived the caller leaving on timeout.
    CHECK_FALSE(slowTaskFinished.load());

    std::atomic<bool> nextRan{false};
    const auto nextResult = worker.Submit([&] { nextRan = true; }, 3000);

    CHECK(nextResult == DebuggerWorker::SubmitResult::Completed);
    CHECK(nextRan.load());
    CHECK(slowTaskFinished.load()); // by now the slow task has already finished

    worker.Stop();
}

TEST_CASE("worker: an exception from a task does not crash the thread") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    const auto throwingResult = worker.Submit([] {
        throw std::runtime_error("boom");
    }, 2000);
    CHECK(throwingResult == DebuggerWorker::SubmitResult::Completed);

    std::atomic<bool> nextRan{false};
    const auto nextResult = worker.Submit([&] { nextRan = true; }, 2000);
    CHECK(nextResult == DebuggerWorker::SubmitResult::Completed);
    CHECK(nextRan.load());

    worker.Stop();
}

TEST_CASE("worker: Submit without Start gives NotRunning") {
    DebuggerWorker worker;
    const auto result = worker.Submit([] {}, 1000);
    CHECK(result == DebuggerWorker::SubmitResult::NotRunning);
}

TEST_CASE("worker: Stop with queued tasks completes quickly and does not hang") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    // The first task actually runs and occupies the worker thread for a
    // limited time — Stop() must wait specifically for it, not for all the
    // tasks waiting behind it in the queue.
    std::thread runningThread([&] {
        worker.Submit([] { std::this_thread::sleep_for(std::chrono::milliseconds(500)); }, 5000);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Tasks that must never run — if Stop() waited for all of them, that
    // would take more than 5 seconds in total. The submit timeout is
    // deliberately large (5000 ms): we're verifying that cancellation in
    // Stop() actually wakes these threads, not that they timed out on their
    // own submit timeout.
    constexpr int kQueued = 5;
    std::atomic<int> queuedRan{0};
    std::vector<DebuggerWorker::SubmitResult> results(kQueued);
    std::vector<std::chrono::milliseconds> submitElapsed(kQueued);
    std::vector<std::thread> queuedThreads;
    for (int i = 0; i < kQueued; ++i)
    {
        queuedThreads.emplace_back([&, i] {
            const auto submitStart = std::chrono::steady_clock::now();
            results[i] = worker.Submit([&] {
                std::this_thread::sleep_for(std::chrono::milliseconds(2000));
                ++queuedRan;
            }, 5000);
            submitElapsed[i] = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - submitStart);
        });
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    const auto start = std::chrono::steady_clock::now();
    worker.Stop();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(elapsed < std::chrono::milliseconds(2000));
    CHECK(queuedRan.load() == 0);

    runningThread.join();
    for (auto& t : queuedThreads)
        t.join();

    // We check the cancellation path itself, not just its consequence: each
    // thread that submitted a task must get NotRunning and finish well
    // within its five-second submit timeout. Replacing the cancellation
    // loop with a simple queue clear would leave these threads hanging
    // until the Timeout expires — this check catches exactly that mutation.
    for (int i = 0; i < kQueued; ++i)
    {
        CHECK(results[i] == DebuggerWorker::SubmitResult::NotRunning);
        CHECK(submitElapsed[i] < std::chrono::milliseconds(1000));
    }
}

TEST_CASE("worker: submitting a task from within a task gives SelfSubmit, from outside gives Completed") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    DebuggerWorker::SubmitResult innerResult = DebuggerWorker::SubmitResult::Completed;
    const auto outerResult = worker.Submit([&] {
        innerResult = worker.Submit([] {}, 2000);
    }, 3000);

    CHECK(outerResult == DebuggerWorker::SubmitResult::Completed);
    CHECK(innerResult == DebuggerWorker::SubmitResult::SelfSubmit);

    worker.Stop();
}

TEST_CASE("worker: a task dropped due to queue timeout does not run") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    // The gate occupies the worker thread while the second task waits in the queue.
    std::atomic<bool> release{false};
    std::thread gateThread([&] {
        worker.Submit([&] {
            while (!release.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }, 10000);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    std::atomic<bool> abandonedTaskRan{false};
    const auto abandonedResult = worker.Submit([&] { abandonedTaskRan = true; }, 200);
    CHECK(abandonedResult == DebuggerWorker::SubmitResult::Timeout);

    // We release the worker thread only AFTER the caller has received
    // Timeout — this exact order reproduces the defect: without the
    // "abandoned" marker, the worker thread would still go on to run
    // the task afterward.
    release = true;
    gateThread.join();

    std::atomic<bool> nextRan{false};
    const auto nextResult = worker.Submit([&] { nextRan = true; }, 2000);
    CHECK(nextResult == DebuggerWorker::SubmitResult::Completed);
    CHECK(nextRan.load());

    CHECK_FALSE(abandonedTaskRan.load());

    worker.Stop();
}

TEST_CASE("worker: repeated Start/Stop and Stop without Start are safe") {
    DebuggerWorker worker;
    worker.Stop(); // without a preceding Start

    REQUIRE(worker.Start());
    REQUIRE(worker.Start()); // repeated Start is safe
    CHECK(worker.IsRunning());

    worker.Stop();
    worker.Stop(); // repeated Stop is safe
    CHECK_FALSE(worker.IsRunning());

    REQUIRE(worker.Start()); // the worker thread can be restarted
    std::atomic<bool> ran{false};
    CHECK(worker.Submit([&] { ran = true; }, 2000) == DebuggerWorker::SubmitResult::Completed);
    CHECK(ran.load());
    worker.Stop();
}

TEST_CASE("worker: queue overflow gives Rejected") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    // Occupy the worker thread with a task that waits for a signal — all
    // other tasks will just pile up in the queue without running.
    std::atomic<bool> release{false};
    std::thread gateThread([&] {
        worker.Submit([&] {
            while (!release.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }, 10000);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    constexpr int kAttempts = 200; // knowingly larger than the queue limit (64)
    std::vector<std::thread> submitters;
    std::vector<DebuggerWorker::SubmitResult> results(kAttempts);
    for (int i = 0; i < kAttempts; ++i)
    {
        submitters.emplace_back([&, i] {
            results[i] = worker.Submit([] {}, 10000);
        });
    }

    // Give all the threads time to try to enqueue a task before releasing the gate.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    release = true;

    gateThread.join();
    for (auto& t : submitters)
        t.join();

    int rejected = 0;
    int completed = 0;
    for (const auto& r : results)
    {
        if (r == DebuggerWorker::SubmitResult::Rejected)
            ++rejected;
        else if (r == DebuggerWorker::SubmitResult::Completed)
            ++completed;
    }

    CHECK(rejected > 0);
    CHECK(rejected + completed == kAttempts);

    worker.Stop();
}
