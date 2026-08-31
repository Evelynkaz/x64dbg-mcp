#include "plugin/debug_state.h"
#include "doctest/doctest.h"

#include <atomic>
#include <chrono>
#include <thread>

using x64dbg_mcp::plugin::DebugStateTracker;
using x64dbg_mcp::plugin::PauseReason;
using x64dbg_mcp::plugin::RunState;
using x64dbg_mcp::plugin::StateSnapshot;

TEST_CASE("debug_state: начальное состояние — NotDebugging, поколение 0") {
    DebugStateTracker tracker;
    const StateSnapshot snapshot = tracker.Current();
    CHECK(snapshot.state == RunState::NotDebugging);
    CHECK(snapshot.reason == PauseReason::None);
    CHECK(snapshot.generation == 0);
}

TEST_CASE("debug_state: обычная последовательность переходов") {
    DebugStateTracker tracker;

    tracker.NotifyDebugStarted();
    CHECK(tracker.Current().state == RunState::Running);

    tracker.NotifyPaused(PauseReason::Breakpoint);
    StateSnapshot afterPause = tracker.Current();
    CHECK(afterPause.state == RunState::Paused);
    CHECK(afterPause.reason == PauseReason::Breakpoint);

    tracker.NotifyResumed();
    CHECK(tracker.Current().state == RunState::Running);

    tracker.NotifyDebugStopped();
    CHECK(tracker.Current().state == RunState::NotDebugging);
}

TEST_CASE("debug_state: поколение растёт только при переходе в паузу") {
    DebugStateTracker tracker;

    tracker.NotifyDebugStarted();
    CHECK(tracker.Current().generation == 0);

    tracker.NotifyPaused(PauseReason::Step);
    CHECK(tracker.Current().generation == 1);

    // Возобновление не меняет поколение.
    tracker.NotifyResumed();
    CHECK(tracker.Current().generation == 1);

    tracker.NotifyPaused(PauseReason::Breakpoint);
    CHECK(tracker.Current().generation == 2);

    // Остановка отладки тоже не меняет поколение.
    tracker.NotifyDebugStopped();
    CHECK(tracker.Current().generation == 2);
}

// Главная проверка отсутствия гонки: пауза наступила ДО того, как её начали
// ждать. Если бы ожидание строилось на текущем состоянии, а не на счётчике
// поколений, этот сценарий провисел бы до таймаута.
TEST_CASE("debug_state: ожидание не проспало событие, случившееся раньше вызова") {
    DebugStateTracker tracker;
    tracker.NotifyDebugStarted();
    const unsigned long long before = tracker.Current().generation;

    tracker.NotifyPaused(PauseReason::Breakpoint);

    StateSnapshot out;
    const auto start = std::chrono::steady_clock::now();
    const bool result = tracker.WaitForPauseAfter(before, 5000, out);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(result);
    CHECK(out.state == RunState::Paused);
    CHECK(out.generation > before);
    // Возврат должен быть немедленным, а не после ожидания.
    CHECK(elapsed < std::chrono::milliseconds(500));
}

TEST_CASE("debug_state: ожидание без паузы завершается по таймауту за отведённое время") {
    DebugStateTracker tracker;
    tracker.NotifyDebugStarted();
    const unsigned long long before = tracker.Current().generation;

    StateSnapshot out;
    const auto start = std::chrono::steady_clock::now();
    const bool result = tracker.WaitForPauseAfter(before, 300, out);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK_FALSE(result);
    CHECK(elapsed >= std::chrono::milliseconds(250));
    CHECK(elapsed < std::chrono::milliseconds(2000));
}

TEST_CASE("debug_state: ожидание из другого потока просыпается при уведомлении о паузе") {
    DebugStateTracker tracker;
    tracker.NotifyDebugStarted();
    const unsigned long long before = tracker.Current().generation;

    std::atomic<bool> result{false};
    std::atomic<bool> finished{false};

    std::thread waiter([&] {
        StateSnapshot out;
        result = tracker.WaitForPauseAfter(before, 5000, out);
        finished = true;
    });

    // Даём потоку время дойти до фактического ожидания.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    tracker.NotifyPaused(PauseReason::UserPause);

    waiter.join();
    CHECK(finished);
    CHECK(result);
}

TEST_CASE("debug_state: завершение отладки будит ожидающего без ожидания полного таймаута") {
    DebugStateTracker tracker;
    tracker.NotifyDebugStarted();
    const unsigned long long before = tracker.Current().generation;

    std::atomic<bool> result{true};

    std::thread waiter([&] {
        StateSnapshot out;
        result = tracker.WaitForPauseAfter(before, 5000, out);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    const auto stopStart = std::chrono::steady_clock::now();
    tracker.NotifyDebugStopped();

    waiter.join();
    const auto elapsed = std::chrono::steady_clock::now() - stopStart;

    CHECK_FALSE(result.load());
    // Разбужен уведомлением, а не пятисекундным таймаутом.
    CHECK(elapsed < std::chrono::milliseconds(2000));
}

TEST_CASE("debug_state: после Shutdown ожидание возвращает false немедленно") {
    DebugStateTracker tracker;
    tracker.Shutdown();
    CHECK(tracker.IsShutdown());

    StateSnapshot out;
    const auto start = std::chrono::steady_clock::now();
    const bool result = tracker.WaitForPauseAfter(0, 5000, out);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK_FALSE(result);
    CHECK(elapsed < std::chrono::milliseconds(500));
}

TEST_CASE("debug_state: Shutdown будит ожидающего в другом потоке") {
    DebugStateTracker tracker;
    tracker.NotifyDebugStarted();
    const unsigned long long before = tracker.Current().generation;

    std::atomic<bool> result{true};

    std::thread waiter([&] {
        StateSnapshot out;
        result = tracker.WaitForPauseAfter(before, 5000, out);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    const auto shutdownStart = std::chrono::steady_clock::now();
    tracker.Shutdown();

    waiter.join();
    const auto elapsed = std::chrono::steady_clock::now() - shutdownStart;

    CHECK_FALSE(result.load());
    CHECK(elapsed < std::chrono::milliseconds(2000));
}

// Дефект 1: пауза наступила, но к моменту, когда WaitForPauseAfter снова
// захватывает мьютекс после пробуждения, состояние уже перезаписано
// возобновлением. Решение обязано опираться на поколение, а не на текущее
// snapshot_.state — иначе этот тест ловил бы false вместо true.
TEST_CASE("debug_state: пауза, затем возобновление — ожидание всё равно видит состоявшуюся паузу") {
    DebugStateTracker tracker;
    tracker.NotifyDebugStarted();
    const unsigned long long before = tracker.Current().generation;

    tracker.NotifyPaused(PauseReason::Breakpoint);
    tracker.NotifyResumed();

    StateSnapshot out;
    const auto start = std::chrono::steady_clock::now();
    const bool result = tracker.WaitForPauseAfter(before, 3000, out);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(result);
    CHECK(out.state == RunState::Paused);
    CHECK(out.reason == PauseReason::Breakpoint);
    CHECK(out.generation == before + 1);
    CHECK(elapsed < std::chrono::milliseconds(500));
}

// Тот же дефект 1, но пауза "перекрывается" завершением отладки (процесс
// завершился, стоя на точке останова), а не возобновлением.
TEST_CASE("debug_state: пауза, затем завершение отладки — ожидание всё равно видит состоявшуюся паузу") {
    DebugStateTracker tracker;
    tracker.NotifyDebugStarted();
    const unsigned long long before = tracker.Current().generation;

    tracker.NotifyPaused(PauseReason::Breakpoint);
    tracker.NotifyDebugStopped();

    StateSnapshot out;
    const auto start = std::chrono::steady_clock::now();
    const bool result = tracker.WaitForPauseAfter(before, 3000, out);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(result);
    CHECK(out.state == RunState::Paused);
    CHECK(out.reason == PauseReason::Breakpoint);
    CHECK(out.generation == before + 1);
    CHECK(elapsed < std::chrono::milliseconds(500));
}

// Дефект 2: сессия ещё не начиналась, поэтому условие "state == NotDebugging"
// не должно расцениваться как "сессия завершилась". Ожидание обязано
// достоять до реального старта и последующей начальной точки останова.
TEST_CASE("debug_state: ожидание начальной точки останова на ещё не начатой сессии не возвращает false мгновенно") {
    DebugStateTracker tracker;

    std::atomic<bool> result{false};
    std::atomic<bool> finished{false};

    std::thread waiter([&] {
        StateSnapshot out;
        result = tracker.WaitForPauseAfter(0, 5000, out);
        finished = true;
    });

    // Даём ожидающему потоку время дойти до фактического ожидания и убеждаемся,
    // что он не проснулся преждевременно на "сессия ещё не начиналась".
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK_FALSE(finished.load());

    tracker.NotifyDebugStarted();
    tracker.NotifyPaused(PauseReason::InitialBreak);

    waiter.join();
    CHECK(finished.load());
    CHECK(result.load());
}

// Ответ на вопрос ревью (дефект 3): одна физическая остановка — одно
// поколение. Повторное уведомление о паузе без промежуточного возобновления
// не должно увеличивать поколение, но должно уточнить причину, если раньше
// она была неопределённой.
TEST_CASE("debug_state: повторное уведомление о паузе без возобновления не увеличивает поколение") {
    DebugStateTracker tracker;
    tracker.NotifyDebugStarted();

    tracker.NotifyPaused(PauseReason::Unknown);
    const StateSnapshot first = tracker.Current();
    CHECK(first.state == RunState::Paused);
    CHECK(first.reason == PauseReason::Unknown);

    tracker.NotifyPaused(PauseReason::Breakpoint);
    const StateSnapshot second = tracker.Current();
    CHECK(second.generation == first.generation);
    CHECK(second.reason == PauseReason::Breakpoint);

    // Причина уже определена — следующее уведомление её не портит.
    tracker.NotifyPaused(PauseReason::Step);
    const StateSnapshot third = tracker.Current();
    CHECK(third.generation == first.generation);
    CHECK(third.reason == PauseReason::Breakpoint);
}

// Ловит мутацию "предикат ожидания заменён на голое ожидание": при одной
// паузе просыпаться с true должен только ожидающий, чьё запрошенное
// поколение меньше нового; ожидающий "впереди" обязан продолжить ожидание
// и завершиться по собственному таймауту.
TEST_CASE("debug_state: при одной паузе с true просыпается только ожидающий меньшего поколения") {
    DebugStateTracker tracker;
    tracker.NotifyDebugStarted();
    const unsigned long long gen0 = tracker.Current().generation;

    std::atomic<bool> lowResult{false};
    std::atomic<bool> highResult{true};
    std::atomic<bool> lowFinished{false};
    std::atomic<bool> highFinished{false};

    const auto overallStart = std::chrono::steady_clock::now();

    std::thread lowWaiter([&] {
        StateSnapshot out;
        lowResult = tracker.WaitForPauseAfter(gen0, 5000, out);
        lowFinished = true;
    });
    std::thread highWaiter([&] {
        StateSnapshot out;
        highResult = tracker.WaitForPauseAfter(gen0 + 5, 700, out);
        highFinished = true;
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK_FALSE(lowFinished.load());
    CHECK_FALSE(highFinished.load());

    tracker.NotifyPaused(PauseReason::Breakpoint); // новое поколение gen0 + 1

    lowWaiter.join();
    const auto lowElapsed = std::chrono::steady_clock::now() - overallStart;
    CHECK(lowFinished.load());
    CHECK(lowResult.load());
    CHECK(lowElapsed < std::chrono::milliseconds(1000)); // разбужен уведомлением, не таймаутом

    highWaiter.join();
    const auto highElapsed = std::chrono::steady_clock::now() - overallStart;
    CHECK(highFinished.load());
    CHECK_FALSE(highResult.load()); // не дождался поколения gen0 + 5
    CHECK(highElapsed >= std::chrono::milliseconds(600)); // действительно достоял до своего таймаута
    CHECK(highElapsed < std::chrono::milliseconds(2000));
}
