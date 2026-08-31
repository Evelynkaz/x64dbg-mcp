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
        return true; // уже запущен — повторный Start безопасен

    // На случай, если предыдущий Stop() не был вызван — приводим очередь
    // к чистому состоянию перед новым запуском.
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
        return;  // Stop() из рабочего потока: присоединиться к самому себе невозможно

    if (!running_.load())
        return; // не запущен либо уже остановлен — безопасно

    std::deque<QueueItem> pending;
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        stopRequested_ = true;
        pending.swap(queue_);
    }
    queueCv_.notify_all();

    // Дожидаемся потока без принудительного завершения: TerminateThread мог
    // бы остановить его посреди вызова API отладчика, оставив процесс в
    // непредсказуемом состоянии. Задача, которая сейчас исполняется (если
    // есть), доработает — прерывать её нельзя.
    if (thread_.joinable())
        thread_.join();

    running_ = false;
    workerThreadId_ = std::thread::id{};

    // Задачи, оставшиеся в очереди, никогда не будут исполнены — их
    // ожидающие получают NotRunning, а не зависают до собственного таймаута.
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

    // Вызов Submit из самого рабочего потока привёл бы к взаимной
    // блокировке: поток ждал бы завершения задачи, которую должен исполнить
    // он же сам. Это ошибка использования вызывающего кода, а не штатная
    // ситуация — отклоняем без постановки в очередь отдельным кодом, чтобы
    // вызывающий мог отличить её от временной перегрузки очереди (Rejected).
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
        // Задача, возможно, ещё не начала выполняться — помечаем её
        // брошенной, чтобы рабочий поток пропустил её и не выполнил уже
        // после того, как вызывающему был отдан ответ об истечении
        // времени. Если задача уже исполняется, это поле ни на что не
        // повлияет: прервать выполняющуюся задачу нельзя, она может быть
        // в середине вызова API отладчика.
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
                continue; // ложное пробуждение
            }
            item = std::move(queue_.front());
            queue_.pop_front();
        }

        // Пропускаем только ещё НЕ начатые задачи, брошенные вызывающим по
        // таймауту (Submit() успел вернуть Timeout раньше, чем задача
        // покинула очередь). Уже начатую задачу прерывать нельзя — она
        // может быть в середине вызова API отладчика.
        {
            std::lock_guard<std::mutex> lock(item.completion->mutex);
            if (item.completion->abandoned)
                continue;
        }

        // Исключение из задачи не должно ронять рабочий поток — иначе одна
        // сломанная задача обрывает обслуживание всех последующих.
        // catch (...) перехватывает только исключения C++ (std::bad_alloc,
        // std::runtime_error и т. п.). Структурные исключения (SEH),
        // например обращение по недопустимому адресу внутри API отладчика,
        // этим не сдерживаются и пройдут мимо этого catch — как и в
        // src/common/pipe_server.cpp, защита от них должна быть в слое
        // обёртки над самим API, а не здесь.
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
