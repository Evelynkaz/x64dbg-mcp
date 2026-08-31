// envtarget.c
// A test subject program for manually verifying the process-environment MCP
// tools (list_handles, list_windows, list_connections). Each object it
// creates has a known correct answer in advance - compare against it using
// tests/target/README.md.
//
// It also reproduces the exact condition of a heap out-of-bounds read that
// was fixed in ListWindows(): the debugger fills WINDOW_INFO::windowTitle
// with a plain memcpy (external/x64dbg/src/dbg/handles.cpp) and gives no
// guarantee of a trailing null terminator when the UTF-8 title is long
// enough to fill the 512-byte buffer exactly. The window created below has
// a title whose UTF-8 form exceeds 512 bytes on purpose.

// Deliberate suppression of CRT warnings about "unsafe" functions:
// wcscpy/wcscat here operate on buffers sized for their fixed-length inputs.
#define _CRT_SECURE_NO_WARNINGS

// This file uses the *W (wide) Win32 APIs exclusively, so resource macros
// like IDC_ARROW must resolve to their wide-char form as well.
#define UNICODE
#define _UNICODE

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

// --- 1. Window with a deliberately long title and class name ---
// Two CJK characters (U+6F22 U+5B57), repeated to 200 characters. Each
// encodes to 3 bytes in UTF-8, so the UTF-8 form is ~600 bytes - larger
// than the debugger's 512-byte WINDOW_INFO::windowTitle buffer.
#define WINDOW_TITLE_CHAR_COUNT 200
#define WINDOW_CLASS_CHAR_COUNT 200

static wchar_t g_window_title[WINDOW_TITLE_CHAR_COUNT + 1];
static wchar_t g_window_class[WINDOW_CLASS_CHAR_COUNT + 1];

static void build_window_title(void)
{
    int i;
    for (i = 0; i < WINDOW_TITLE_CHAR_COUNT; i += 2)
    {
        g_window_title[i] = 0x6F22;
        g_window_title[i + 1] = 0x5B57;
    }
    g_window_title[WINDOW_TITLE_CHAR_COUNT] = L'\0';
}

static void build_window_class(void)
{
    static const wchar_t prefix[] = L"X64DBG_MCP_ENVTARGET_WINDOW_CLASS_";
    size_t prefix_len = wcslen(prefix);
    size_t i;
    wcscpy(g_window_class, prefix);
    for (i = prefix_len; i < WINDOW_CLASS_CHAR_COUNT; i++)
    {
        g_window_class[i] = L'X';
    }
    g_window_class[WINDOW_CLASS_CHAR_COUNT] = L'\0';
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

// Creates the window and prints its reference values. Returns the window
// handle, or NULL if creation failed (the program continues regardless).
static HWND create_window(void)
{
    WNDCLASSEXW wc;
    HWND hwnd;
    int utf8_len;
    char utf8_buffer[4096];

    build_window_title();
    build_window_class();

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = g_window_class;

    if (!RegisterClassExW(&wc))
    {
        printf("RegisterClassExW failed: %lu\n", GetLastError());
        return NULL;
    }

    hwnd = CreateWindowExW(0, g_window_class, L"envtarget", WS_OVERLAPPEDWINDOW,
                            CW_USEDEFAULT, CW_USEDEFAULT, 400, 200,
                            NULL, NULL, wc.hInstance, NULL);
    if (hwnd == NULL)
    {
        printf("CreateWindowExW failed: %lu\n", GetLastError());
        return NULL;
    }

    if (!SetWindowTextW(hwnd, g_window_title))
    {
        printf("SetWindowTextW failed: %lu\n", GetLastError());
    }

    ShowWindow(hwnd, SW_SHOWNORMAL);
    UpdateWindow(hwnd);

    utf8_len = WideCharToMultiByte(CP_UTF8, 0, g_window_title, -1,
                                    utf8_buffer, (int)sizeof(utf8_buffer), NULL, NULL);
    if (utf8_len > 0)
    {
        utf8_len -= 1; // exclude the null terminator WideCharToMultiByte counted
    }
    else
    {
        printf("WideCharToMultiByte failed: %lu\n", GetLastError());
    }

    printf("Window handle: %p\n", (void*)hwnd);
    printf("Window class name: %ls\n", g_window_class);
    printf("Window title character count: %d\n", (int)wcslen(g_window_title));
    printf("Window title UTF-8 byte length: %d\n", utf8_len);

    return hwnd;
}

// --- 2. Named mutex ---
static void create_named_mutex(void)
{
    const wchar_t* name = L"X64DBG_MCP_ENVTARGET_MUTEX";
    HANDLE mutex = CreateMutexW(NULL, FALSE, name);
    if (mutex == NULL)
    {
        printf("CreateMutexW failed: %lu\n", GetLastError());
        return;
    }
    printf("Mutex name: %ls, handle: %p\n", name, (void*)mutex);
}

// --- 3. Open file handle in the temp directory ---
static void create_open_file(void)
{
    wchar_t temp_path[MAX_PATH];
    wchar_t file_path[MAX_PATH];
    HANDLE file;

    if (GetTempPathW(MAX_PATH, temp_path) == 0)
    {
        printf("GetTempPathW failed: %lu\n", GetLastError());
        return;
    }
    wsprintfW(file_path, L"%sX64DBG_MCP_ENVTARGET_FILE.tmp", temp_path);

    file = CreateFileW(file_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        printf("CreateFileW failed: %lu\n", GetLastError());
        return;
    }
    printf("File path: %ls, handle: %p\n", file_path, (void*)file);
}

// --- 4. Named event ---
static void create_named_event(void)
{
    const wchar_t* name = L"X64DBG_MCP_ENVTARGET_EVENT";
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, name);
    if (event == NULL)
    {
        printf("CreateEventW failed: %lu\n", GetLastError());
        return;
    }
    printf("Event name: %ls, handle: %p\n", name, (void*)event);
}

// --- 5. Established TCP connection on loopback only ---
// A listening socket bound to 127.0.0.1 on an ephemeral port, connected to
// from a second socket in the same process. No traffic leaves the machine.
static void create_loopback_connection(void)
{
    SOCKET listen_sock, client_sock, accepted_sock;
    struct sockaddr_in addr, bound_addr;
    int addr_len;
    unsigned short port;

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET)
    {
        printf("socket(listen) failed: %d\n", WSAGetLastError());
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = 0; // ephemeral port

    if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        printf("bind failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        return;
    }
    if (listen(listen_sock, 1) == SOCKET_ERROR)
    {
        printf("listen failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        return;
    }

    addr_len = sizeof(bound_addr);
    memset(&bound_addr, 0, sizeof(bound_addr));
    if (getsockname(listen_sock, (struct sockaddr*)&bound_addr, &addr_len) == SOCKET_ERROR)
    {
        printf("getsockname failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        return;
    }
    port = ntohs(bound_addr.sin_port);

    client_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client_sock == INVALID_SOCKET)
    {
        printf("socket(client) failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        return;
    }

    addr.sin_port = htons(port);
    if (connect(client_sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        printf("connect failed: %d\n", WSAGetLastError());
        closesocket(client_sock);
        closesocket(listen_sock);
        return;
    }

    accepted_sock = accept(listen_sock, NULL, NULL);
    if (accepted_sock == INVALID_SOCKET)
    {
        printf("accept failed: %d\n", WSAGetLastError());
        closesocket(client_sock);
        closesocket(listen_sock);
        return;
    }

    printf("TCP loopback port: %u (127.0.0.1, established, loopback only - no external traffic)\n",
           (unsigned int)port);
}

int main(void)
{
    DWORD pid;
    WSADATA wsa_data;
    int wsa_result;
    MSG msg;

    // --- 6. Print the process ID first, clearly labelled ---
    pid = GetCurrentProcessId();
    printf("PID: %lu\n", pid);
    fflush(stdout);

    wsa_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_result != 0)
    {
        printf("WSAStartup failed: %d\n", wsa_result);
    }

    create_named_mutex();
    create_open_file();
    create_named_event();
    if (wsa_result == 0)
    {
        create_loopback_connection();
    }
    create_window();
    fflush(stdout);

    // --- 7. Message loop: keeps the window alive so a debugger can attach ---
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (wsa_result == 0)
    {
        WSACleanup();
    }

    return 0;
}
