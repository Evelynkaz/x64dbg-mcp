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

} // namespace x64dbg_mcp::plugin
