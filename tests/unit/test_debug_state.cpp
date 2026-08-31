#include "plugin/debug_state.h"
#include "doctest/doctest.h"

#include <atomic>
#include <chrono>
#include <thread>

using x64dbg_mcp::plugin::DebugStateTracker;
using x64dbg_mcp::plugin::PauseReason;
using x64dbg_mcp::plugin::RunState;
using x64dbg_mcp::plugin::StateSnapshot;

TEST_CASE("debug_state: initial state is NotDebugging with generation 0") {
    DebugStateTracker tracker;
    const StateSnapshot snapshot = tracker.Current();
    CHECK(snapshot.state == RunState::NotDebugging);
    CHECK(snapshot.reason == PauseReason::None);
    CHECK(snapshot.generation == 0);
}

TEST_CASE("debug_state: a normal sequence of transitions") {
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

TEST_CASE("debug_state: generation increases only on transition to paused") {
    DebugStateTracker tracker;

    tracker.NotifyDebugStarted();
    CHECK(tracker.Current().generation == 0);

    tracker.NotifyPaused(PauseReason::Step);
    CHECK(tracker.Current().generation == 1);

    // Resuming does not change the generation.
    tracker.NotifyResumed();
    CHECK(tracker.Current().generation == 1);

    tracker.NotifyPaused(PauseReason::Breakpoint);
    CHECK(tracker.Current().generation == 2);

    // Stopping the debug session doesn't change the generation either.
    tracker.NotifyDebugStopped();
    CHECK(tracker.Current().generation == 2);
}

// The main check for the absence of a race: the pause happened BEFORE
// anyone started waiting for it. If the wait were built on the current
// state rather than the generation counter, this scenario would hang
// until the timeout.
TEST_CASE("debug_state: wait does not miss an event that already happened before the call") {
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
    // The return must be immediate, not after waiting.
    CHECK(elapsed < std::chrono::milliseconds(500));
}

TEST_CASE("debug_state: wait without a pause times out within the allotted time") {
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

TEST_CASE("debug_state: wait from another thread wakes up when notified of a pause") {
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

    // Give the thread time to reach the actual wait.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    tracker.NotifyPaused(PauseReason::UserPause);

    waiter.join();
    CHECK(finished);
    CHECK(result);
}

TEST_CASE("debug_state: ending the debug session wakes the waiter without waiting the full timeout") {
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
    // Woken by the notification, not by the five-second timeout.
    CHECK(elapsed < std::chrono::milliseconds(2000));
}

TEST_CASE("debug_state: after Shutdown, wait returns false immediately") {
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

TEST_CASE("debug_state: Shutdown wakes a waiter on another thread") {
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

// Defect 1: the pause happened, but by the time WaitForPauseAfter reacquires
// the mutex after waking up, the state has already been overwritten by a
// resume. The solution must rely on the generation, not on the current
// snapshot_.state — otherwise this test would get false instead of true.
TEST_CASE("debug_state: pause then resume — wait still observes the pause that happened") {
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

// The same defect 1, but the pause is "overridden" by the debug session
// stopping (the process terminated while sitting on a breakpoint) rather
// than by a resume.
TEST_CASE("debug_state: pause then end debugging — wait still observes the pause that happened") {
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

// Defect 2: the session hasn't started yet, so the condition
// "state == NotDebugging" must not be interpreted as "the session ended".
// The wait must hold out until the actual start and the subsequent
// initial breakpoint.
TEST_CASE("debug_state: waiting for the initial breakpoint on a not-yet-started session does not return false instantly") {
    DebugStateTracker tracker;

    std::atomic<bool> result{false};
    std::atomic<bool> finished{false};

    std::thread waiter([&] {
        StateSnapshot out;
        result = tracker.WaitForPauseAfter(0, 5000, out);
        finished = true;
    });

    // Give the waiting thread time to reach the actual wait and make sure
    // it didn't wake up prematurely on "the session hasn't started yet".
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK_FALSE(finished.load());

    tracker.NotifyDebugStarted();
    tracker.NotifyPaused(PauseReason::InitialBreak);

    waiter.join();
    CHECK(finished.load());
    CHECK(result.load());
}

// Answering a review question (defect 3, which later grew into defect 2 of
// the live check): one physical stop — one generation. A repeated pause
// notification without an intervening resume must not increase the
// generation, but must refine the reason by priority (see PauseReason in
// debug_state.h), not just replace Unknown.
TEST_CASE("debug_state: repeated pause notification without resuming does not increase the generation") {
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

    // The reason is already higher priority than Step — the next notification doesn't spoil it.
    tracker.NotifyPaused(PauseReason::Step);
    const StateSnapshot third = tracker.Current();
    CHECK(third.generation == first.generation);
    CHECK(third.reason == PauseReason::Breakpoint);
}

// Defect 2 of the live check: x64dbg sends several notifications for one
// physical stop in an unpredictable order. If a less specific reason
// (UserPause) arrives BEFORE a more specific one (Step), it must not
// survive the subsequent, more precise notification.
TEST_CASE("debug_state: a less specific reason yields to a more specific one within the same pause") {
    DebugStateTracker tracker;
    tracker.NotifyDebugStarted();
    const unsigned long long before = tracker.Current().generation;

    tracker.NotifyPaused(PauseReason::UserPause);
    tracker.NotifyPaused(PauseReason::Step);
    const StateSnapshot snapshot = tracker.Current();

    CHECK(snapshot.reason == PauseReason::Step);
    CHECK(snapshot.generation == before + 1);
}

// Reverse order: a more specific reason (Breakpoint) that arrives first
// must not be displaced by a less specific UserPause.
TEST_CASE("debug_state: a more specific reason does not yield to a less specific one") {
    DebugStateTracker tracker;
    tracker.NotifyDebugStarted();
    const unsigned long long before = tracker.Current().generation;

    tracker.NotifyPaused(PauseReason::Breakpoint);
    tracker.NotifyPaused(PauseReason::UserPause);
    const StateSnapshot snapshot = tracker.Current();

    CHECK(snapshot.reason == PauseReason::Breakpoint);
    CHECK(snapshot.generation == before + 1);
}

// Catches the mutation "wait predicate replaced with a bare wait": for a
// single pause, only the waiter whose requested generation is less than
// the new one must wake up with true; a waiter that's "ahead" must keep
// waiting and finish on its own timeout.
TEST_CASE("debug_state: a single pause with true wakes only the waiter with the smaller generation") {
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

    tracker.NotifyPaused(PauseReason::Breakpoint); // new generation gen0 + 1

    lowWaiter.join();
    const auto lowElapsed = std::chrono::steady_clock::now() - overallStart;
    CHECK(lowFinished.load());
    CHECK(lowResult.load());
    CHECK(lowElapsed < std::chrono::milliseconds(1000)); // woken by the notification, not the timeout

    highWaiter.join();
    const auto highElapsed = std::chrono::steady_clock::now() - overallStart;
    CHECK(highFinished.load());
    CHECK_FALSE(highResult.load()); // did not wait out generation gen0 + 5
    CHECK(highElapsed >= std::chrono::milliseconds(600)); // actually held out until its own timeout
    CHECK(highElapsed < std::chrono::milliseconds(2000));
}
