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
