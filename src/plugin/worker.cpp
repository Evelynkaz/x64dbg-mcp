#include "plugin/worker.h"

#include <chrono>

namespace x64dbg_mcp::plugin
{

DebuggerWorker::DebuggerWorker() = default;

DebuggerWorker::~DebuggerWorker()
{
    Stop();
}

bool DebuggerWorker::Start()
{
    std::lock_guard<std::mutex> lifecycle(lifecycleMutex_);
    if (running_.load())
        return true; // already running — calling Start again is safe

    // In case a previous Stop() was never called — bring the queue back to
    // a clean state before starting again.
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        queue_.clear();
    }
    stopRequested_ = false;

    try
    {
        thread_ = std::thread(&DebuggerWorker::Run, this);
    }
    catch (...)
    {
        return false;
    }

    workerThreadId_ = thread_.get_id();
    running_ = true;
    return true;
}

void DebuggerWorker::Stop()
{
    std::lock_guard<std::mutex> lifecycle(lifecycleMutex_);

    if (std::this_thread::get_id() == workerThreadId_.load())
        return;  // Stop() from the worker thread: joining itself is impossible

    if (!running_.load())
        return; // not running or already stopped — safe to no-op

    std::deque<QueueItem> pending;
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        stopRequested_ = true;
        pending.swap(queue_);
    }
    queueCv_.notify_all();

    // Wait for the thread without force-terminating it: TerminateThread
    // could stop it in the middle of a debugger API call, leaving the
    // process in an unpredictable state. Whatever task is currently running
    // (if any) is allowed to finish — it must not be interrupted.
    if (thread_.joinable())
        thread_.join();

    running_ = false;
    workerThreadId_ = std::thread::id{};

    // Tasks left in the queue will never run — their waiters get NotRunning
    // instead of hanging until their own timeout.
    for (auto& item : pending)
    {
        {
            std::lock_guard<std::mutex> lock(item.completion->mutex);
            item.completion->cancelled = true;
        }
        item.completion->cv.notify_all();
    }
}

bool DebuggerWorker::IsRunning() const
{
    return running_.load();
}

DebuggerWorker::SubmitResult DebuggerWorker::Submit(Task task, int timeoutMs)
{
    if (!running_.load())
        return SubmitResult::NotRunning;

    // Calling Submit from the worker thread itself would deadlock: the
    // thread would wait for a task to finish that it itself must run. This
    // is a caller bug, not a normal condition — reject it without queuing,
    // using a distinct code so the caller can tell it apart from a
    // transient queue overload (Rejected).
    if (std::this_thread::get_id() == workerThreadId_.load())
        return SubmitResult::SelfSubmit;

    auto completion = std::make_shared<TaskCompletion>();

    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        if (!running_.load() || stopRequested_.load())
            return SubmitResult::NotRunning;
        if (queue_.size() >= kMaxQueueSize)
            return SubmitResult::Rejected;
        queue_.push_back(QueueItem{std::move(task), completion});
    }
    queueCv_.notify_one();

    std::unique_lock<std::mutex> lock(completion->mutex);
    const bool signalled = completion->cv.wait_for(
        lock, std::chrono::milliseconds(timeoutMs < 0 ? 0 : timeoutMs),
        [&] { return completion->done || completion->cancelled; });

    if (!signalled)
    {
        // The task may not have started yet — mark it abandoned so the
        // worker thread skips it instead of running it after the caller has
        // already been told the wait timed out. If the task is already
        // running, this flag has no effect: a running task cannot be
        // interrupted, it may be in the middle of a debugger API call.
        completion->abandoned = true;
        return SubmitResult::Timeout;
    }

    return completion->cancelled ? SubmitResult::NotRunning : SubmitResult::Completed;
}

size_t DebuggerWorker::QueueSize() const
{
    std::lock_guard<std::mutex> lock(queueMutex_);
    return queue_.size();
}

void DebuggerWorker::Run()
{
    for (;;)
    {
        QueueItem item;
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCv_.wait(lock, [&] { return stopRequested_.load() || !queue_.empty(); });
            if (queue_.empty())
            {
                if (stopRequested_.load())
                    break;
                continue; // spurious wakeup
            }
            item = std::move(queue_.front());
            queue_.pop_front();
        }

        // Only skip tasks that have NOT started yet and were abandoned by
        // the caller on timeout (Submit() returned Timeout before the task
        // left the queue). An already-started task cannot be interrupted —
        // it may be in the middle of a debugger API call.
        {
            std::lock_guard<std::mutex> lock(item.completion->mutex);
            if (item.completion->abandoned)
                continue;
        }

        // An exception from a task must not bring down the worker thread —
        // otherwise one broken task would stop all subsequent ones from
        // being served. catch (...) only catches C++ exceptions
        // (std::bad_alloc, std::runtime_error, etc.). Structured exceptions
        // (SEH), such as an invalid memory access inside the debugger API,
        // are not caught by this and will pass right through it — as in
        // src/common/pipe_server.cpp, guarding against those has to happen
        // in the wrapper layer over the API itself, not here.
        try
        {
            item.task();
        }
        catch (...)
        {
        }

        {
            std::lock_guard<std::mutex> lock(item.completion->mutex);
            item.completion->done = true;
        }
        item.completion->cv.notify_all();
    }
}

} // namespace x64dbg_mcp::plugin
