#pragma once

// Единственное место в проекте, откуда допускается вызывать API x64dbg
// (заголовки external/sdk/cmake-sdk/pluginsdk/). Больше нигде в проекте эти
// вызовы делать нельзя — так и должно оставаться.
//
// ВАЖНО: все функции этого файла ЗАПРЕЩЕНО вызывать откуда-либо, кроме
// рабочего потока DebuggerWorker. Само API x64dbg не рассчитано на вызов из
// произвольного потока (см. docs/notes/x64dbg-api.md), а сериализация через
// единственный рабочий поток — единственная защита от этого класса гонок.

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

} // namespace x64dbg_mcp::plugin
