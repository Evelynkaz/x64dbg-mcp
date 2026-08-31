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

// The log is written from multiple threads (eventually at least the stdio
// loop thread and the pipe-to-plugin thread), so access to the state and to
// stderr itself is protected by a single mutex.
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

    // Levels are declared in decreasing order of importance (Error=0 .. Debug=3),
    // so "less important than the threshold" means "numerically greater".
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
