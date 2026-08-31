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

// Очередь задач с единственным рабочим потоком. Смысл: все обращения к API
// x64dbg должны идти из одного потока, чтобы исключить целый класс гонок.
// Не зависит от SDK x64dbg, поэтому тестируется обычным юнит-тестом.
class DebuggerWorker
{
public:
    using Task = std::function<void()>;

    enum class SubmitResult
    {
        Completed,   // задача выполнена
        Timeout,     // не уложилась в отведённое время
        NotRunning,  // рабочий поток не запущен
        Rejected,    // очередь переполнена — состояние временное, стоит повторить позже
        SelfSubmit,  // Submit вызван из самого рабочего потока — ошибка вызывающего кода
    };

    DebuggerWorker();
    ~DebuggerWorker();

    DebuggerWorker(const DebuggerWorker&) = delete;
    DebuggerWorker& operator=(const DebuggerWorker&) = delete;

    bool Start();

    // ПРЕДУПРЕЖДЕНИЕ: при выгрузке плагина перед вызовом Stop() ОБЯЗАТЕЛЬНО
    // сначала вызвать DebugStateTracker::Shutdown(). Stop() присоединяет
    // рабочий поток без ограничения по времени, и если задача, которую он
    // сейчас исполняет, ждёт паузы отладчика с большим таймаутом, Stop()
    // задержится на всё это время — подвесив тем самым поток x64dbg,
    // вызвавший выгрузку плагина. Задачи, исполняемые этим воркером, не
    // должны блокироваться на неограниченных по времени ожиданиях.
    void Stop();
    bool IsRunning() const;

    // Ставит задачу в очередь и ждёт её завершения.
    // При Timeout задача МОЖЕТ продолжать выполняться — поэтому всё,
    // что она использует, обязано пережить её завершение.
    SubmitResult Submit(Task task, int timeoutMs);

    size_t QueueSize() const;

private:
    // Состояние завершения одной задачи, разделяемое между Submit() и
    // рабочим потоком. Живёт под shared_ptr, а не как локальная переменная
    // в стеке Submit(): прервать выполняющуюся задачу нельзя (она может быть
    // в середине вызова API отладчика), поэтому если Submit уходит по
    // таймауту раньше, чем задача фактически завершится, рабочий поток
    // обязан иметь право дописать в это состояние результат даже после того,
    // как стек вызывающего Submit уже размотан. Тот же класс ошибки и то же
    // решение, что и в PipeServerState (см. src/common/pipe_server.h).
    struct TaskCompletion
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        bool cancelled = false; // задача отброшена Stop() до исполнения
        bool abandoned = false; // Submit ушёл по таймауту, задача ещё не начата
    };

    struct QueueItem
    {
        Task task;
        std::shared_ptr<TaskCompletion> completion;
    };

    void Run();

    static constexpr size_t kMaxQueueSize = 64;

    std::mutex lifecycleMutex_; // сериализует Start()/Stop() между собой
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::atomic<std::thread::id> workerThreadId_{};

    mutable std::mutex queueMutex_;
    std::condition_variable queueCv_;
    std::deque<QueueItem> queue_;
};

} // namespace x64dbg_mcp::plugin
