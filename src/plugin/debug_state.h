#pragma once

#include <condition_variable>
#include <mutex>

namespace x64dbg_mcp::plugin
{

enum class RunState
{
    NotDebugging,   // отладка не запущена
    Running,        // процесс выполняется
    Paused,         // процесс остановлен
};

enum class PauseReason
{
    None,
    Unknown,
    InitialBreak,   // системная точка останова при запуске
    Breakpoint,
    Step,
    UserPause,
    Exception,
};

struct StateSnapshot
{
    RunState state = RunState::NotDebugging;
    PauseReason reason = PauseReason::None;
    // Увеличивается на единицу при КАЖДОМ переходе в состояние паузы.
    // Служит для ожидания без гонок: см. WaitForPauseAfter.
    unsigned long long generation = 0;
};

// Отслеживает состояние отладки на основе уведомлений, поступающих извне
// (из коллбэков x64dbg). Не зависит от SDK x64dbg, поэтому тестируется
// обычным юнит-тестом без запущенного отладчика.
class DebugStateTracker
{
public:
    // Уведомления вызываются из коллбэков x64dbg. Не блокируют.
    void NotifyDebugStarted();
    void NotifyDebugStopped();
    void NotifyPaused(PauseReason reason);
    void NotifyResumed();

    StateSnapshot Current() const;

    // Ждёт перехода в паузу с поколением СТРОГО БОЛЬШЕ afterGeneration.
    // Если такое поколение уже достигнуто, возвращает немедленно —
    // именно это устраняет гонку "пауза наступила раньше ожидания".
    // Возвращает false по таймауту или после Shutdown.
    bool WaitForPauseAfter(unsigned long long afterGeneration, int timeoutMs, StateSnapshot& out);

    // Будит всех ожидающих и запрещает дальнейшие ожидания.
    // Вызывается при выгрузке плагина, чтобы никто не остался висеть.
    void Shutdown();

    bool IsShutdown() const;

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    StateSnapshot snapshot_;
    // Снимок состояния, зафиксированный в момент последней паузы. Нужен
    // потому что к тому моменту, когда ожидающий поток пробуждается и
    // заново захватывает мьютекс, snapshot_ уже может быть перезаписан
    // следующим уведомлением (NotifyResumed, NotifyDebugStopped) — сама
    // пауза уже состоялась, но её больше не видно в текущем состоянии.
    StateSnapshot lastPause_;
    bool shutdown_ = false;
    // Увеличивается при каждом NotifyDebugStarted. Позволяет в
    // WaitForPauseAfter отличить "сессия отладки завершилась" от "сессия
    // ещё не начиналась" — оба случая иначе выглядели бы одинаково как
    // RunState::NotDebugging.
    unsigned long long sessionGeneration_ = 0;
};

} // namespace x64dbg_mcp::plugin
