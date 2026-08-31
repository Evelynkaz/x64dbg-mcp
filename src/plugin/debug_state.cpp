#include "plugin/debug_state.h"

#include <chrono>

namespace x64dbg_mcp::plugin
{

void DebugStateTracker::NotifyDebugStarted()
{
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot_.state = RunState::Running;
    snapshot_.reason = PauseReason::None;
    // Новая сессия отладки: увеличиваем номер сессии, чтобы WaitForPauseAfter
    // мог отличить завершение ЭТОЙ сессии от завершения предыдущей.
    ++sessionGeneration_;
    // Поколение не меняется: старт отладки — не переход в паузу.
    cv_.notify_all();
}

void DebugStateTracker::NotifyDebugStopped()
{
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot_.state = RunState::NotDebugging;
    snapshot_.reason = PauseReason::None;
    // Будим всех ожидающих паузы: без этого тот, кто вызвал
    // WaitForPauseAfter до завершения отладки, провисит до собственного
    // таймаута, хотя паузы, которую он ждёт, уже никогда не будет —
    // отладка закончилась. Поколение не меняется: это не пауза.
    cv_.notify_all();
}

void DebugStateTracker::NotifyPaused(PauseReason reason)
{
    std::lock_guard<std::mutex> lock(mutex_);

    // Одна физическая остановка отладчика может породить несколько
    // коллбэков-уведомлений (например, и о точке останова, и о паузе).
    // Правило: одна физическая остановка — одно поколение. Поэтому
    // поколение увеличивается ТОЛЬКО при переходе в паузу из состояния,
    // отличного от Paused; повторное уведомление о уже наступившей паузе
    // поколение не меняет — иначе оно выросло бы дважды и освободило
    // постороннего ожидающего раньше времени.
    if (snapshot_.state != RunState::Paused)
    {
        snapshot_.state = RunState::Paused;
        snapshot_.reason = reason;
        ++snapshot_.generation;

        // Запоминаем снимок момента паузы отдельно от snapshot_: к моменту,
        // когда ожидающий в WaitForPauseAfter снова захватит мьютекс после
        // пробуждения, snapshot_ уже может быть перезаписан последующим
        // уведомлением (Resumed, DebugStopped). Поэтому решение о том,
        // состоялась ли ожидаемая пауза, принимается по номеру поколения, а
        // возвращается вызывающему именно этот сохранённый снимок.
        lastPause_ = snapshot_;
    }
    else if (snapshot_.reason == PauseReason::Unknown)
    {
        // Уже стоим на паузе (второй коллбэк той же остановки) — уточняем
        // причину, если раньше она была неопределённой, но поколение не
        // трогаем: это по-прежнему та же самая физическая пауза.
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
    // Поколение не меняется: возобновление — не переход в паузу.
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

    // Различаем "сессия отладки ещё не начиналась" и "сессия отладки уже
    // завершилась" — оба случая иначе выглядели бы одинаково как
    // RunState::NotDebugging и вызывающий, ждущий начальную системную точку
    // останова (PauseReason::InitialBreak) ещё до старта отладки, получил бы
    // ложное немедленное пробуждение. Сессией считается завершившейся только
    // если она БЫЛА активна на входе в функцию и это та же самая сессия.
    const bool entryDebugging = snapshot_.state != RunState::NotDebugging;
    const unsigned long long entrySession = sessionGeneration_;

    // Условие проверяется ДО первого фактического ожидания (таково поведение
    // wait_for с предикатом), поэтому если пауза с нужным поколением уже
    // наступила раньше вызова, функция вернёт true немедленно — гонка
    // "пауза наступила раньше, чем её начали ждать" не возникает в принципе.
    auto woken = [&] {
        return shutdown_ ||
               snapshot_.generation > afterGeneration ||
               (entryDebugging && snapshot_.state == RunState::NotDebugging && sessionGeneration_ == entrySession);
    };

    cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs < 0 ? 0 : timeoutMs), woken);

    // Решение принимается ТОЛЬКО по номеру поколения, а не по текущему
    // snapshot_.state: к моменту, когда этот поток снова захватил мьютекс
    // после пробуждения, состояние уже могло быть перезаписано следующим
    // уведомлением (Resumed, DebugStopped), хотя ожидаемая пауза фактически
    // состоялась. Наружу отдаётся заранее сохранённый снимок этой паузы,
    // а не то, что видно в snapshot_ прямо сейчас.
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
