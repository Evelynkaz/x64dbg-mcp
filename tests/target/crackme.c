// crackme.c
// A test subject program for manually verifying the x64dbg MCP server tools.
// Each "target" below has a known correct answer in advance -
// compare against it using tests/target/README.md.

// Deliberate suppression of CRT warnings about "unsafe" functions:
// strcmp is safe here by construction (both strings are null-terminated),
// and sprintf/strcpy aren't used in this file at all.
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <string.h>

// --- 1. Strings for testing memory reads and string reference searches ---
static const char g_ascii_string[] = "X64DBG_MCP_TEST_ASCII_STRING";
static const wchar_t g_wide_string[] = L"X64DBG_MCP_TEST_WIDE_STRING";

// --- 2. Byte marker for testing signature (byte pattern) search ---
// The value is deliberately not something that appears in ordinary compiler-generated code.
volatile unsigned char g_pattern_marker[16] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
};

// --- 4. Global variables with known values for testing memory access ---
volatile int g_magic = 0x1337;
volatile int g_counter = 0;

// The worker thread's counter grows independently of g_counter - the thread is easy to identify.
volatile int g_thread_counter = 0;

static const char PASSWORD[] = "s3cr3t";

// --- 3. Named exported functions ---
// dllexport puts the name in the export table so x64dbg can see it without a PDB.
// noinline stops the compiler from inlining the function at the call site.

// Compares the input against the password. The conditional jump inside is a patch target.
__declspec(dllexport) __declspec(noinline) int check_password(const char* input)
{
    if (strcmp(input, PASSWORD) == 0)
    {
        return 1;
    }
    return 0;
}

// A simple byte-wise checksum over a buffer - a target for loop analysis.
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

// A repeating XOR - a target for analyzing a simple data transformation.
__declspec(dllexport) __declspec(noinline) void xor_decrypt(unsigned char* buf, int len, unsigned char key)
{
    int i;
    for (i = 0; i < len; i++)
    {
        buf[i] ^= key;
    }
}

// A simple addition - a target for testing register/argument modification.
__declspec(dllexport) __declspec(noinline) int target_function(int a, int b)
{
    return a + b;
}

// --- 6. Worker thread for testing the thread list and another thread's registers ---
static DWORD WINAPI worker_thread(LPVOID param)
{
    (void)param;
    for (;;)
    {
        g_thread_counter++;
        // The period differs from the main thread's (500 ms), making the thread easy to identify.
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

    // --- 5. One-time WinAPI calls so their names land in the import table ---
    tick_count = GetTickCount();
    GetModuleFileNameW(NULL, module_path, MAX_PATH);
    self_file = CreateFileW(module_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (self_file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(self_file);
    }

    // --- 1. Print the strings so the linker doesn't discard them ---
    printf("ASCII string: %s\n", g_ascii_string);
    printf("Wide string: %ls\n", g_wide_string);

    // --- 2. Use the byte marker so it isn't discarded ---
    marker_sum = 0;
    for (i = 0; i < 16; i++)
    {
        marker_sum += g_pattern_marker[i];
    }
    printf("Pattern marker checksum: %u\n", marker_sum);

    // --- 8. Reference values at startup: compared against MCP tool responses ---
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

    // --- 6. Start the worker thread ---
    thread_handle = CreateThread(NULL, 0, worker_thread, NULL, 0, NULL);
    if (thread_handle != NULL)
    {
        CloseHandle(thread_handle);
    }

    // --- Main loop: demonstrates memory, the password, and the thread ---
    for (;;)
    {
        int password_ok;

        iteration++;
        g_counter++;

        // --- 7. Patch target: deliberately wrong password ---
        password_ok = check_password("wrongpass");

        printf("iter=%d g_magic=0x%X counter=%d access=%s\n",
               iteration, g_magic, g_counter, password_ok ? "GRANTED" : "DENIED");
        fflush(stdout);

        Sleep(500);
    }
}
