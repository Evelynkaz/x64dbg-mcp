#pragma once

#include <condition_variable>
#include <mutex>

namespace x64dbg_mcp::plugin
{

enum class RunState
{
    NotDebugging,   // debugging is not active
    Running,        // the process is executing
    Paused,         // the process is stopped
};

// The order of the values MATTERS: it defines the priority of the pause
// reason within a single physical pause (see NotifyPaused) — from less
// specific to more specific: Unknown < UserPause < InitialBreak < Step <
// Breakpoint < Exception. Do not reorder without updating NotifyPaused
// accordingly.
enum class PauseReason
{
    None,
    Unknown,
    UserPause,
    InitialBreak,   // system breakpoint hit on process start
    Step,
    Breakpoint,
    Exception,
};

struct StateSnapshot
{
    RunState state = RunState::NotDebugging;
    PauseReason reason = PauseReason::None;
    // Incremented by one on EVERY transition into the paused state.
    // Used for race-free waiting: see WaitForPauseAfter.
    unsigned long long generation = 0;
};

// Tracks debugging state from notifications delivered externally (from
// x64dbg callbacks). Does not depend on the x64dbg SDK, so it is testable
// with a plain unit test without a running debugger.
class DebugStateTracker
{
public:
    // Notifications are called from x64dbg callbacks. They do not block.
    void NotifyDebugStarted();
    void NotifyDebugStopped();
    void NotifyPaused(PauseReason reason);
    void NotifyResumed();

    StateSnapshot Current() const;

    // Waits for a transition into pause with a generation STRICTLY GREATER
    // than afterGeneration. If that generation has already been reached,
    // returns immediately — this is exactly what eliminates the race where
    // the pause happens before the caller starts waiting for it.
    // Returns false on timeout or after Shutdown.
    bool WaitForPauseAfter(unsigned long long afterGeneration, int timeoutMs, StateSnapshot& out);

    // Wakes up everyone waiting and forbids further waits.
    // Called on plugin unload so that nobody is left hanging.
    void Shutdown();

    bool IsShutdown() const;

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    StateSnapshot snapshot_;
    // The state snapshot captured at the moment of the last pause. Needed
    // because by the time a waiting thread wakes up and re-acquires the
    // mutex, snapshot_ may already have been overwritten by a later
    // notification (NotifyResumed, NotifyDebugStopped) — the pause itself
    // already happened, but it is no longer visible in the current state.
    StateSnapshot lastPause_;
    bool shutdown_ = false;
    // Incremented on every NotifyDebugStarted. Lets WaitForPauseAfter tell
    // "the debugging session ended" apart from "the session hasn't started
    // yet" — both cases would otherwise look identical as
    // RunState::NotDebugging.
    unsigned long long sessionGeneration_ = 0;
};

} // namespace x64dbg_mcp::plugin
