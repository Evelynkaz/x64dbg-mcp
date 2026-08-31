#include "plugin/worker.h"
#include "doctest/doctest.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

using x64dbg_mcp::plugin::DebuggerWorker;

TEST_CASE("worker: задача выполняется, Submit возвращает Completed") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    std::atomic<bool> ran{false};
    const auto result = worker.Submit([&] { ran = true; }, 2000);

    CHECK(result == DebuggerWorker::SubmitResult::Completed);
    CHECK(ran.load());

    worker.Stop();
}

TEST_CASE("worker: задачи выполняются в порядке постановки") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    std::mutex mutex;
    std::vector<int> order;

    // Задача-шлагбаум занимает рабочий поток, пока мы ставим в очередь
    // остальные задачи из отдельных потоков — иначе, вызывая Submit
    // последовательно из одного потока, мы бы просто проверяли, что
    // предыдущая задача успела выполниться до постановки следующей, а не
    // порядок обработки очереди.
    std::atomic<bool> release{false};
    std::thread gateThread([&] {
        worker.Submit([&] {
            while (!release.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }, 5000);
    });

    // Ждём, пока шлагбаум точно займёт рабочий поток.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Небольшая пауза между постановкой каждой задачи делает порядок их
    // попадания в очередь детерминированным для теста.
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

TEST_CASE("worker: все задачи исполняются в одном и том же потоке") {
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

TEST_CASE("worker: задача, превысившая время, даёт Timeout, а следующие выполняются нормально") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    std::atomic<bool> slowTaskFinished{false};
    const auto slowResult = worker.Submit([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
        slowTaskFinished = true;
    }, 100);

    CHECK(slowResult == DebuggerWorker::SubmitResult::Timeout);
    // Медленная задача не была прервана и продолжает исполняться — Submit
    // о ней просто перестал ждать. Проверка владения с подсчётом ссылок:
    // TaskCompletion пережил уход вызывающего по таймауту.
    CHECK_FALSE(slowTaskFinished.load());

    std::atomic<bool> nextRan{false};
    const auto nextResult = worker.Submit([&] { nextRan = true; }, 3000);

    CHECK(nextResult == DebuggerWorker::SubmitResult::Completed);
    CHECK(nextRan.load());
    CHECK(slowTaskFinished.load()); // к этому моменту медленная задача уже доработала

    worker.Stop();
}

TEST_CASE("worker: исключение из задачи не роняет поток") {
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

TEST_CASE("worker: Submit без Start даёт NotRunning") {
    DebuggerWorker worker;
    const auto result = worker.Submit([] {}, 1000);
    CHECK(result == DebuggerWorker::SubmitResult::NotRunning);
}

TEST_CASE("worker: Stop с задачами в очереди завершается быстро и не виснет") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    // Первая задача реально исполняется и занимает рабочий поток на
    // ограниченное время — Stop() обязан дождаться именно её, а не всех
    // задач, ожидающих в очереди позади неё.
    std::thread runningThread([&] {
        worker.Submit([] { std::this_thread::sleep_for(std::chrono::milliseconds(500)); }, 5000);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Задачи, которые никогда не должны выполниться — если бы Stop() ждал
    // их всех, суммарно это заняло бы больше 5 секунд. Таймаут постановки
    // намеренно большой (5000 мс): мы проверяем, что отмена в Stop() реально
    // будит эти потоки, а не что они сами истекли по таймауту постановки.
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

    // Проверяем сам путь отмены, а не только его следствие: каждый
    // поставивший задачу поток обязан получить NotRunning и уложиться
    // существенно меньше своего пятисекундного таймаута постановки. Замена
    // цикла отмены на простую очистку очереди оставила бы эти потоки висеть
    // до истечения Timeout — эта проверка ловит именно такую мутацию.
    for (int i = 0; i < kQueued; ++i)
    {
        CHECK(results[i] == DebuggerWorker::SubmitResult::NotRunning);
        CHECK(submitElapsed[i] < std::chrono::milliseconds(1000));
    }
}

TEST_CASE("worker: постановка задачи изнутри задачи даёт SelfSubmit, снаружи — Completed") {
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

TEST_CASE("worker: задача, брошенная по таймауту в очереди, не выполняется") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    // Шлагбаум занимает рабочий поток, пока вторая задача ждёт в очереди.
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

    // Освобождаем рабочий поток уже ПОСЛЕ того, как вызывающий получил
    // Timeout, — именно этот порядок воспроизводит дефект: без пометки
    // "брошена" рабочий поток впоследствии всё равно исполнил бы задачу.
    release = true;
    gateThread.join();

    std::atomic<bool> nextRan{false};
    const auto nextResult = worker.Submit([&] { nextRan = true; }, 2000);
    CHECK(nextResult == DebuggerWorker::SubmitResult::Completed);
    CHECK(nextRan.load());

    CHECK_FALSE(abandonedTaskRan.load());

    worker.Stop();
}

TEST_CASE("worker: повторные Start/Stop и Stop без Start безопасны") {
    DebuggerWorker worker;
    worker.Stop(); // без предшествующего Start

    REQUIRE(worker.Start());
    REQUIRE(worker.Start()); // повторный Start безопасен
    CHECK(worker.IsRunning());

    worker.Stop();
    worker.Stop(); // повторный Stop безопасен
    CHECK_FALSE(worker.IsRunning());

    REQUIRE(worker.Start()); // рабочий поток можно перезапустить
    std::atomic<bool> ran{false};
    CHECK(worker.Submit([&] { ran = true; }, 2000) == DebuggerWorker::SubmitResult::Completed);
    CHECK(ran.load());
    worker.Stop();
}

TEST_CASE("worker: переполнение очереди даёт Rejected") {
    DebuggerWorker worker;
    REQUIRE(worker.Start());

    // Занимаем рабочий поток задачей, которая ждёт сигнала — все остальные
    // задачи будут только накапливаться в очереди, не выполняясь.
    std::atomic<bool> release{false};
    std::thread gateThread([&] {
        worker.Submit([&] {
            while (!release.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }, 10000);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    constexpr int kAttempts = 200; // заведомо больше предела очереди (64)
    std::vector<std::thread> submitters;
    std::vector<DebuggerWorker::SubmitResult> results(kAttempts);
    for (int i = 0; i < kAttempts; ++i)
    {
        submitters.emplace_back([&, i] {
            results[i] = worker.Submit([] {}, 10000);
        });
    }

    // Даём всем потокам время попытаться поставить задачу в очередь,
    // прежде чем освободить шлагбаум.
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
