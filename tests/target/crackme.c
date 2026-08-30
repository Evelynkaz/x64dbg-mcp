// crackme.c
// Подопытная программа для ручной проверки инструментов MCP-сервера x64dbg.
// У каждой "мишени" ниже заранее известный правильный ответ -
// сверять с ним нужно в tests/target/README.md.

// Сознательное подавление предупреждений CRT о "небезопасных" функциях:
// strcmp тут безопасен по построению (обе строки завершены нулём),
// а sprintf/strcpy в этом файле вообще не используются.
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <string.h>

// --- 1. Строки для проверки чтения памяти и поиска ссылок на строки ---
static const char g_ascii_string[] = "X64DBG_MCP_TEST_ASCII_STRING";
static const wchar_t g_wide_string[] = L"X64DBG_MCP_TEST_WIDE_STRING";

// --- 2. Байтовый маркер для проверки поиска по сигнатуре ---
// Значение заведомо не встречается в обычном коде компилятора.
volatile unsigned char g_pattern_marker[16] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
};

// --- 4. Глобальные переменные с известными значениями для проверки памяти ---
volatile int g_magic = 0x1337;
volatile int g_counter = 0;

// Счётчик рабочего потока растёт независимо от g_counter - поток легко узнать.
volatile int g_thread_counter = 0;

static const char PASSWORD[] = "s3cr3t";

// --- 3. Именованные экспортируемые функции ---
// dllexport кладёт имя в таблицу экспорта, чтобы x64dbg видел его без PDB.
// noinline не даёт компилятору растворить функцию в месте вызова.

// Сравнивает вход с паролем. Условный переход внутри - мишень для патча.
__declspec(dllexport) __declspec(noinline) int check_password(const char* input)
{
    if (strcmp(input, PASSWORD) == 0)
    {
        return 1;
    }
    return 0;
}

// Простая контрольная сумма по байтам буфера - мишень для разбора цикла.
__declspec(dllexport) __declspec(noinline) unsigned int compute_checksum(const unsigned char* data, int len)
{
    unsigned int sum = 0;
    int i;
    for (i = 0; i < len; i++)
    {
        sum += data[i];
    }
    return sum;
}

// Циклический XOR - мишень для разбора простого преобразования данных.
__declspec(dllexport) __declspec(noinline) void xor_decrypt(unsigned char* buf, int len, unsigned char key)
{
    int i;
    for (i = 0; i < len; i++)
    {
        buf[i] ^= key;
    }
}

// Простое сложение - мишень для проверки изменения регистров/аргументов.
__declspec(dllexport) __declspec(noinline) int target_function(int a, int b)
{
    return a + b;
}

// --- 6. Рабочий поток для проверки списка потоков и регистров чужого потока ---
static DWORD WINAPI worker_thread(LPVOID param)
{
    (void)param;
    for (;;)
    {
        g_thread_counter++;
        // Период отличается от главного потока (500 мс), поток легко узнать.
        Sleep(750);
    }
}

int main(void)
{
    DWORD pid;
    HMODULE base;
    DWORD tick_count;
    WCHAR module_path[MAX_PATH];
    HANDLE self_file;
    unsigned int marker_sum;
    int i;
    HANDLE thread_handle;
    int iteration = 0;

    // --- 5. Однократные вызовы WinAPI, чтобы их имена попали в таблицу импорта ---
    tick_count = GetTickCount();
    GetModuleFileNameW(NULL, module_path, MAX_PATH);
    self_file = CreateFileW(module_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (self_file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(self_file);
    }

    // --- 1. Печать строк, чтобы компоновщик их не выбросил ---
    printf("ASCII string: %s\n", g_ascii_string);
    printf("Wide string: %ls\n", g_wide_string);

    // --- 2. Использование байтового маркера, чтобы не был выброшен ---
    marker_sum = 0;
    for (i = 0; i < 16; i++)
    {
        marker_sum += g_pattern_marker[i];
    }
    printf("Pattern marker checksum: %u\n", marker_sum);

    // --- 8. Опорные сведения при старте: сверяются с ответами инструментов MCP ---
    pid = GetCurrentProcessId();
    base = GetModuleHandle(NULL);
    printf("PID: %lu\n", pid);
    printf("Module base: %p\n", (void*)base);
    printf("Tick count at start: %lu\n", tick_count);
    printf("Address of g_magic: %p\n", (void*)&g_magic);
    printf("Address of g_pattern_marker: %p\n", (void*)g_pattern_marker);
    printf("Address of check_password: %p\n", (void*)check_password);
    printf("Address of target_function: %p\n", (void*)target_function);
    fflush(stdout);

    // --- 6. Запуск рабочего потока ---
    thread_handle = CreateThread(NULL, 0, worker_thread, NULL, 0, NULL);
    if (thread_handle != NULL)
    {
        CloseHandle(thread_handle);
    }

    // --- Основной цикл: демонстрация памяти, пароля и потока ---
    for (;;)
    {
        int password_ok;

        iteration++;
        g_counter++;

        // --- 7. Мишень для патча: заведомо неверный пароль ---
        password_ok = check_password("wrongpass");

        printf("iter=%d g_magic=0x%X counter=%d access=%s\n",
               iteration, g_magic, g_counter, password_ok ? "GRANTED" : "DENIED");
        fflush(stdout);

        Sleep(500);
    }
}
