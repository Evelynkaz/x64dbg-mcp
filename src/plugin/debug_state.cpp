#include "plugin/debug_state.h"

#include <chrono>

namespace x64dbg_mcp::plugin
{

void DebugStateTracker::NotifyDebugStarted()
{
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot_.state = RunState::Running;
    snapshot_.reason = PauseReason::None;
    // New debugging session: bump the session number so WaitForPauseAfter
    // can tell the end of THIS session apart from the end of the previous one.
    ++sessionGeneration_;
    // The generation does not change: starting debugging is not a pause transition.
    cv_.notify_all();
}

void DebugStateTracker::NotifyDebugStopped()
{
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot_.state = RunState::NotDebugging;
    snapshot_.reason = PauseReason::None;
    // Wake up everyone waiting for a pause: without this, whoever called
    // WaitForPauseAfter before debugging ended would hang until their own
    // timeout, even though the pause they are waiting for will now never
    // happen — debugging has ended. The generation does not change: this is not a pause.
    cv_.notify_all();
}

void DebugStateTracker::NotifyPaused(PauseReason reason)
{
    std::lock_guard<std::mutex> lock(mutex_);

    // A single physical debugger stop can produce several notification
    // callbacks (e.g. both a breakpoint one and a pause one). Rule: one
    // physical stop is one generation. So the generation is incremented
    // ONLY on a transition into pause from a state other than Paused; a
    // repeated notification about an already-established pause does not
    // change the generation — otherwise it would grow twice and release an
    // unrelated waiter ahead of time.
    if (snapshot_.state != RunState::Paused)
    {
        snapshot_.state = RunState::Paused;
        snapshot_.reason = reason;
        ++snapshot_.generation;

        // Remember the snapshot of this pause separately from snapshot_: by
        // the time a waiter in WaitForPauseAfter re-acquires the mutex after
        // waking up, snapshot_ may already have been overwritten by a
        // subsequent notification (Resumed, DebugStopped). So the decision
        // of whether the expected pause happened is made from the
        // generation number, while this saved snapshot is what gets
        // returned to the caller.
        lastPause_ = snapshot_;
    }
    else if (reason > snapshot_.reason)
    {
        // We are already paused (second callback for the same stop). x64dbg
        // can send several notifications for one physical stop, and their
        // arrival order is not guaranteed (e.g. CB_PAUSEDEBUG with UserPause
        // can arrive before the more precise CB_STEPPED with Step). So a
        // higher-priority (more specific) reason overrides a lower-priority
        // one, not the other way around — otherwise the precise reason
        // would be lost to a coarse pause notification that happened to
        // arrive first. The generation is left untouched: this is still the
        // same physical pause.
        snapshot_.reason = reason;
        lastPause_.reason = reason;
    }

    cv_.notify_all();
}

void DebugStateTracker::NotifyResumed()
{
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot_.state = RunState::Running;
    snapshot_.reason = PauseReason::None;
    // The generation does not change: resuming is not a pause transition.
    cv_.notify_all();
}

StateSnapshot DebugStateTracker::Current() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return snapshot_;
}

bool DebugStateTracker::WaitForPauseAfter(unsigned long long afterGeneration, int timeoutMs, StateSnapshot& out)
{
    std::unique_lock<std::mutex> lock(mutex_);

    // Distinguish "the debugging session hasn't started yet" from "the
    // debugging session has already ended" — both cases would otherwise
    // look identical as RunState::NotDebugging, and a caller waiting for the
    // initial system breakpoint (PauseReason::InitialBreak) before debugging
    // even starts would get a false immediate wakeup. A session is
    // considered ended only if it WAS active on entry to this function and
    // it is still the same session.
    const bool entryDebugging = snapshot_.state != RunState::NotDebugging;
    const unsigned long long entrySession = sessionGeneration_;

    // The predicate is checked BEFORE the first actual wait (that's how
    // wait_for with a predicate behaves), so if a pause with the required
    // generation already happened before this call, the function returns
    // true immediately — the race of "the pause happened before anyone
    // started waiting for it" simply cannot occur.
    auto woken = [&] {
        return shutdown_ ||
               snapshot_.generation > afterGeneration ||
               (entryDebugging && snapshot_.state == RunState::NotDebugging && sessionGeneration_ == entrySession);
    };

    cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs < 0 ? 0 : timeoutMs), woken);

    // The decision is made ONLY from the generation number, not from the
    // current snapshot_.state: by the time this thread re-acquired the
    // mutex after waking up, the state could already have been overwritten
    // by a subsequent notification (Resumed, DebugStopped), even though the
    // expected pause actually happened. What gets returned is the
    // previously saved snapshot of that pause, not whatever snapshot_ shows
    // right now.
    if (shutdown_)
    {
        out = snapshot_;
        return false;
    }
    if (snapshot_.generation > afterGeneration)
    {
        out = lastPause_;
        return true;
    }
    out = snapshot_;
    return false;
}

void DebugStateTracker::Shutdown()
{
    std::lock_guard<std::mutex> lock(mutex_);
    shutdown_ = true;
    cv_.notify_all();
}

bool DebugStateTracker::IsShutdown() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return shutdown_;
}

} // namespace x64dbg_mcp::plugin
