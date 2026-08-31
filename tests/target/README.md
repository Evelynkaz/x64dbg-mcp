# crackme — a test subject program for manually verifying MCP tools

## Why this exists

`crackme.exe` is a small console target program. It does not automatically
test the x64dbg-mcp plugin itself — it provides **known correct answers in
advance**, so that when manually testing an MCP tool (memory reads, string
search, byte pattern search, thread listing, disassembly, patching, etc.)
you can immediately tell whether the tool answered correctly or lied.

On startup, the program prints reference values (PID, module base address,
addresses of key targets) — these are what you compare the tools' answers
against.

## Build

The `crackme` target is not built during a normal plugin build — only with
an explicit flag:

```
cmake -B build64 -A x64 -DX64DBG_MCP_BUILD_TARGET=ON
cmake --build build64 --config Release --target crackme
```

The resulting file will be at `build64\Release\crackme.exe`.

## Target table

| Target | How to verify | Correct answer |
| --- | --- | --- |
| ASCII string `X64DBG_MCP_TEST_ASCII_STRING` | String search / memory read at the address from the output | The string reads exactly as `X64DBG_MCP_TEST_ASCII_STRING` |
| Wide string `X64DBG_MCP_TEST_WIDE_STRING` | Wide-string search / memory read as UTF-16 | The string reads exactly as `X64DBG_MCP_TEST_WIDE_STRING` |
| Marker `g_pattern_marker` = `DE AD BE EF CA FE BA BE 12 34 56 78 9A BC DE F0` | Byte pattern search | The found address matches the `g_pattern_marker` address printed at startup |
| `check_password` | Export list / find symbol by name, disassemble the function | The function address matches the one printed at startup; a conditional jump after `strcmp` is visible inside |
| `compute_checksum` | Disassemble the function, analyze the loop | A loop summing the bytes of the buffer is visible |
| `xor_decrypt` | Disassemble the function | An `XOR` loop over the buffer is visible |
| `target_function(a, b)` | Set a breakpoint, read/write registers and arguments, change the result | Returns `a + b`; changing the argument value or the result register visibly changes the return value |
| `g_magic` (starting value `0x1337`) | Read memory at the address; write memory | The value in the program's output (`g_magic=0x...`) changes immediately after the tool writes a new value |
| `g_counter` | Read memory in a loop | The value increases by 1 every iteration (~500 ms) |
| `Sleep` import | Breakpoint on an API function | The breakpoint hits every main loop iteration (~500 ms) and every ~750 ms in the worker thread |
| `GetTickCount`, `CreateFileW` imports | Import list / cross-references to the API | Both functions are present in the import table, called once at startup |
| Worker thread (`CreateThread`) | Thread list, reading another thread's registers | A second thread is visible in the thread list; its counter (`g_thread_counter`, not printed to the console, but growing in memory) increases with a period of ~750 ms — different from the main thread |
| PID, module base | Attaching the debugger to the process | The PID and base in the debugger match the values printed at startup |

## Patch: DENIED → GRANTED

The main loop always calls `check_password("wrongpass")` — a deliberately
wrong password, so the output constantly shows `access=DENIED`.

To get `access=GRANTED`, find the conditional jump in `check_password` that
follows the `strcmp` call (`je`/`jne` after comparing the result to zero),
and invert it (for example, `jne` → `je`, or replace the jump with an
unconditional `jmp`, or NOP out the jump itself so the `return 1;` branch
always executes).

How to confirm the patch worked: after changing the byte(s) in the
process's memory, without stopping the program, wait for the next output
line — it should show `access=GRANTED` instead of `access=DENIED`.

## Important

The built `crackme.exe` is deliberately not stored in the repository — it
is built locally with the command above and is a working (disposable)
artifact for manual testing.

# envtarget — a test subject program for the process-environment tools

## Why this exists

`envtarget.exe` provides known correct answers for `list_handles`,
`list_windows` and `list_connections`. Like `crackme.exe`, it prints
reference values on startup and does not exit on its own — it runs a real
message loop so a debugger can attach or run it.

**Critically, its window title is a regression check for a heap
out-of-bounds read that was fixed in `ListWindows()`.** The debugger fills
`WINDOW_INFO::windowTitle` (a 512-byte buffer, see
`external/x64dbg/src/dbg/handles.cpp`) with a plain `memcpy` and gives no
guarantee of a trailing null terminator when the UTF-8 title is long enough
to fill the buffer exactly. Before the fix, constructing a `std::string`
directly from that buffer ran past the end of the debugger's allocation —
an access violation that MSVC's `catch (...)` does not intercept, which
therefore crashes and terminates x64dbg entirely. `envtarget.exe`'s window
title is ~200 CJK characters, whose UTF-8 form is printed at startup and
must be greater than 512 bytes for this check to be meaningful.

## Build

```
cmake -B build64 -A x64 -DX64DBG_MCP_BUILD_TARGET=ON
cmake --build build64 --config Release --target envtarget
```

The resulting file will be at `build64\Release\envtarget.exe`.

## Target table

| Target | How to verify | Correct answer |
| --- | --- | --- |
| Long window title (~200 CJK characters, UTF-8 form > 512 bytes) | `list_windows`, read the `title` field for `envtarget`'s window | The tool must not crash x64dbg and must return the title without reading past the unterminated 512-byte buffer — this is the regression check for the fixed heap out-of-bounds read |
| Long window class name (200 ASCII characters) | `list_windows`, read the `className` field | The class name matches the value printed at startup |
| Named mutex `X64DBG_MCP_ENVTARGET_MUTEX` | `list_handles`, filter for mutex objects | A mutex named `X64DBG_MCP_ENVTARGET_MUTEX` is present; its handle value matches the one printed at startup |
| Open file handle in the temp directory | `list_handles`, filter for file objects | A file handle whose path matches `File path:` printed at startup is present |
| Named event `X64DBG_MCP_ENVTARGET_EVENT` | `list_handles`, filter for event objects | An event named `X64DBG_MCP_ENVTARGET_EVENT` is present; its handle value matches the one printed at startup |
| Loopback TCP connection | `list_connections` | An established TCP connection with local and remote address `127.0.0.1` on the port printed at startup (`TCP loopback port:`) is present |
| PID | Attaching the debugger to the process | The PID matches the value printed at startup |

## Important

The built `envtarget.exe` is deliberately not stored in the repository —
it is built locally with the command above and is a working (disposable)
artifact for manual testing. It does not exit on its own: close its window
or kill the process when you are done testing.
