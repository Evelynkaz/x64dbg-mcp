#pragma once

// Единственное место в проекте, откуда допускается вызывать API x64dbg
// (заголовки external/sdk/cmake-sdk/pluginsdk/). Больше нигде в проекте эти
// вызовы делать нельзя — так и должно оставаться.
//
// ВАЖНО: все функции этого файла ЗАПРЕЩЕНО вызывать откуда-либо, кроме
// рабочего потока DebuggerWorker. Само API x64dbg не рассчитано на вызов из
// произвольного потока (см. docs/notes/x64dbg-api.md), а сериализация через
// единственный рабочий поток — единственная защита от этого класса гонок.

#include "nlohmann/json.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace x64dbg_mcp::plugin
{

// Верхний предел на количество байт за один вызов ReadMemory. Ограничивает
// объём памяти, который может запросить один клиент моста за раз.
constexpr size_t kMaxReadSize = 1024ull * 1024ull; // 1 MiB

// Верхний предел на количество инструкций за один вызов Disassemble.
constexpr size_t kMaxInstructions = 256;

// Состояние отладчика. Заполняется даже когда отладка не запущена.
struct DebuggerStatus
{
    bool debugging = false;
    bool running = false;          // процесс выполняется (иначе на паузе)
    unsigned int processId = 0;
    unsigned int threadId = 0;
    int pointerSize = 0;           // 4 или 8
    unsigned long long cip = 0;    // текущая точка выполнения, 0 если недоступна
    std::string module;            // модуль по адресу cip, пусто если недоступен
};

// Возвращает состояние отладчика. Никогда не бросает.
DebuggerStatus GetStatus();

// Чтение памяти. Возвращает false, если отладка не запущена или адрес недоступен;
// error заполняется английским текстом с объяснением причины.
bool ReadMemory(unsigned long long address, size_t size, std::vector<unsigned char>& out, std::string& error);

// Одна дизассемблированная инструкция.
struct Instruction
{
    unsigned long long address = 0;
    size_t size = 0;
    std::string text;              // мнемоника с операндами
    std::vector<unsigned char> bytes;
};

// Дизассемблирование count инструкций начиная с address.
bool Disassemble(unsigned long long address, size_t count, std::vector<Instruction>& out, std::string& error);

// Таймаут по умолчанию для операций, ожидающих паузу отладчика, и его верхний предел.
constexpr int kDefaultControlTimeoutMs = 10000;
constexpr int kMaxControlTimeoutMs = 300000;

// Результат операции, меняющей состояние выполнения.
struct ControlResult
{
    bool paused = false;        // остановился ли процесс в отведённое время
    bool timedOut = false;      // истекло ожидание
    DebuggerStatus status;      // состояние ПОСЛЕ операции
    std::string pauseReason;    // причина остановки: breakpoint, step, pause, initial, exception, unknown
};

// action: run | pause | stop | restart | run_to
bool Control(const std::string& action, unsigned long long address, bool hasAddress,
             bool wait, int timeoutMs, ControlResult& out, std::string& error);

// mode: into | over | out
bool Step(const std::string& mode, int count, bool wait, int timeoutMs,
          ControlResult& out, std::string& error);

// Ожидание остановки без отправки команды.
bool WaitUntilPaused(int timeoutMs, ControlResult& out, std::string& error);

// Сведения об одной установленной точке останова.
struct BreakpointInfo
{
    unsigned long long address = 0;
    std::string type;        // software | hardware | memory | dll | exception
    bool enabled = false;
    bool singleShot = false;
    unsigned int hitCount = 0;
    std::string module;
    std::string name;
};

// Устанавливает точку останова по описанию из params (см. debugger.cpp за
// перечнем допустимых полей). Возвращает false и понятную ошибку, если
// какая-либо из команд не была принята x64dbg.
bool SetBreakpoint(const nlohmann::json& params, std::string& error);

// action: delete | enable | disable
bool ManageBreakpoint(const std::string& action, unsigned long long address, std::string& error);

// Список всех установленных точек останова всех типов.
bool ListBreakpoints(std::vector<BreakpointInfo>& out, std::string& error);

// Верхние пределы на количество экспортов и импортов, возвращаемых за один
// вызов GetModuleDetails: у крупных системных модулей (например, ntdll.dll)
// счёт идёт на тысячи записей, а полный список забьёт контекст модели.
constexpr size_t kMaxExports = 4096;
constexpr size_t kMaxImports = 4096;

// Сведения о загруженном модуле.
struct ModuleEntry
{
    unsigned long long base = 0, size = 0, entry = 0;
    int sectionCount = 0;
    std::string name, path;
};

// Список всех загруженных модулей.
bool ListModules(std::vector<ModuleEntry>& out, std::string& error);

struct SectionEntry { unsigned long long address = 0, size = 0; std::string name; };
struct ExportEntry { unsigned long long ordinal = 0, rva = 0, va = 0; bool forwarded = false; std::string name, forwardName; };
struct ImportEntry { unsigned long long iatRva = 0, iatVa = 0, ordinal = 0; std::string name; };

// Подробные сведения об одном модуле: секции и, опционально, экспорты/импорты.
struct ModuleDetails
{
    ModuleEntry module;
    std::vector<SectionEntry> sections;
    std::vector<ExportEntry> exports;
    std::vector<ImportEntry> imports;
    bool exportsTruncated = false, importsTruncated = false;
};

// Модуль задаётся ЛИБО именем (byAddress == false), ЛИБО адресом внутри него
// (byAddress == true).
bool GetModuleDetails(const std::string& name, unsigned long long address, bool byAddress,
                      bool includeExports, bool includeImports,
                      ModuleDetails& out, std::string& error);

// Одна страница памяти из карты памяти отлаживаемого процесса.
struct MemoryRegion
{
    unsigned long long base = 0, allocationBase = 0, size = 0;
    std::string state, type, protect, info;
};

// Карта памяти отлаживаемого процесса.
bool GetMemoryMap(std::vector<MemoryRegion>& out, std::string& error);

// Сведения об одном потоке отлаживаемого процесса.
struct ThreadEntry
{
    unsigned int id = 0;
    int number = 0;
    unsigned long long entry = 0, teb = 0, cip = 0;
    unsigned int suspendCount = 0, lastError = 0;
    std::string name, priority, waitReason;
    bool current = false;
};

// Список всех потоков отлаживаемого процесса.
bool ListThreads(std::vector<ThreadEntry>& out, std::string& error);

} // namespace x64dbg_mcp::plugin
