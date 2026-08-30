#include "bridge/logging.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>

namespace x64dbg_mcp::bridge
{

namespace
{

// Журнал пишут разные потоки (в будущем — как минимум поток stdio-цикла
// и поток канала к плагину), поэтому доступ к состоянию и к самому stderr
// защищён одним мьютексом.
std::mutex g_mutex;
LogLevel g_minLevel = LogLevel::Info;

const char* LevelName(LogLevel level)
{
    switch (level)
    {
    case LogLevel::Error: return "ERROR";
    case LogLevel::Warn:  return "WARN";
    case LogLevel::Info:  return "INFO";
    case LogLevel::Debug: return "DEBUG";
    }
    return "?";
}

} // namespace

void SetLogLevel(LogLevel level)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_minLevel = level;
}

void Log(LogLevel level, const std::string& message)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    // Уровни объявлены по убыванию важности (Error=0 .. Debug=3), поэтому
    // "менее важный, чем порог" означает "числовое значение больше".
    if (static_cast<int>(level) > static_cast<int>(g_minLevel))
        return;

    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif

    std::ostringstream line;
    line << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << " [" << LevelName(level) << "] " << message << "\n";

    std::cerr << line.str();
    std::cerr.flush();
}

} // namespace x64dbg_mcp::bridge
