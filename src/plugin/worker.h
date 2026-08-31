#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace x64dbg_mcp::plugin
{

// A task queue with a single worker thread. The point: all calls to the
// x64dbg API must come from one thread, to rule out an entire class of races.
// Does not depend on the x64dbg SDK, so it is testable with a plain unit test.
class DebuggerWorker
{
public:
    using Task = std::function<void()>;

    enum class SubmitResult
    {
        Completed,   // the task ran to completion
        Timeout,     // did not finish within the allotted time
        NotRunning,  // the worker thread is not running
        Rejected,    // the queue is full — this is a transient condition, worth retrying later
        SelfSubmit,  // Submit was called from the worker thread itself — a caller bug
    };

    DebuggerWorker();
    ~DebuggerWorker();

    DebuggerWorker(const DebuggerWorker&) = delete;
    DebuggerWorker& operator=(const DebuggerWorker&) = delete;

    bool Start();

    // WARNING: on plugin unload, DebugStateTracker::Shutdown() MUST be
    // called before Stop(). Stop() joins the worker thread with no time
    // limit, and if the task it is currently running is waiting for a
    // debugger pause with a long timeout, Stop() will be delayed for that
    // whole time — hanging the x64dbg thread that triggered the plugin
    // unload. Tasks run by this worker must not block on unbounded waits.
    void Stop();
    bool IsRunning() const;

    // Queues a task and waits for it to finish.
    // On Timeout the task MAY still be running — so anything it uses
    // must outlive its completion.
    SubmitResult Submit(Task task, int timeoutMs);

    size_t QueueSize() const;

private:
    // Completion state for a single task, shared between Submit() and the
    // worker thread. It lives behind a shared_ptr rather than as a local
    // variable on Submit()'s stack: a running task cannot be interrupted (it
    // may be in the middle of a debugger API call), so if Submit times out
    // before the task actually finishes, the worker thread must still be
    // allowed to write the result into this state even after Submit's stack
    // has already unwound. The same class of bug and the same fix as in
    // PipeServerState (see src/common/pipe_server.h).
    struct TaskCompletion
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        bool cancelled = false; // the task was dropped by Stop() before it ran
        bool abandoned = false; // Submit timed out while the task had not started yet
    };

    struct QueueItem
    {
        Task task;
        std::shared_ptr<TaskCompletion> completion;
    };

    void Run();

    static constexpr size_t kMaxQueueSize = 64;

    std::mutex lifecycleMutex_; // serializes Start()/Stop() against each other
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::atomic<std::thread::id> workerThreadId_{};

    mutable std::mutex queueMutex_;
    std::condition_variable queueCv_;
    std::deque<QueueItem> queue_;
};

} // namespace x64dbg_mcp::plugin
