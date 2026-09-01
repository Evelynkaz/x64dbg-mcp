# x64dbg-mcp

An MCP server for the [x64dbg](https://x64dbg.com/) debugger. It gives an AI agent access to live debugging and reverse engineering: inspecting process state, reading memory, disassembling code, controlling execution, and managing breakpoints.

![x64dbg with the x64dbg-mcp plugin loaded](docs/images/screenshot.png)

## What it can do

- Inspect the debugger state: whether a session exists, running or paused, process and thread IDs, pointer size, current instruction pointer.
- Read raw memory, disassemble code, and read strings, all with human-readable formatting alongside the structured data, dump a memory region straight to a file for offline analysis, and build a function's control-flow graph to untangle obfuscated and virtualized code.
- List running processes and attach the debugger to one already running, then detach again leaving it untouched.
- Control execution: run, pause, stop, restart, run to an address, step into/over/out, and run until the program's own code is reached again.
- Set, manage, and list breakpoints, software, hardware, and memory, with conditions and logging.
- Trace execution, record code coverage, and log a chosen expression at each traced instruction, so analyzing packed or obfuscated code does not need one round trip per instruction.
- Search memory for byte patterns and list cross-references to an address.
- List loaded modules, the memory map, threads, open handles, windows, and network connections.
- Write to the debuggee: patch memory, assemble instructions in place, change registers, allocate and free memory, and run arbitrary x64dbg commands and scripts.
- Read and write the debugger's own labels, comments, and bookmarks, so a finding persists across sessions.

## Example

A real exchange between an agent and x64dbg-mcp while looking at a crackme.

`debugger_status`:

```
Debugging: process is paused (PID 21788, TID 31068, 64-bit) at 0x7ff6a7ac17a0 in crackme.
```

`disassemble`:

```
00007ff6a7ac17a0  4883ec28                  sub rsp,28
00007ff6a7ac17a4  e853020000                call crackme.7FF6A7AC19FC
00007ff6a7ac17a9  4883c428                  add rsp,28
00007ff6a7ac17ad  e972feffff                jmp crackme.7FF6A7AC1624
00007ff6a7ac17b2  cc                        int3
```

`read_memory`:

```
00007ff6a7ac17a0  48 83 ec 28 e8 53 02 00  00 48 83 c4 28 e9 72 fe  H..(.S...H..(.r.
00007ff6a7ac17b0  ff ff cc cc b9 02 00 00  00 cd 29 c3 48 83 ec 28  ..........).H..(
```

`set_breakpoint` followed by `debug_control` with action `run`:

```
Breakpoint set at 0x7ff6a7ac17a9 (software).
Paused (breakpoint) at 0x7ff6a7ac17a9 in crackme.
```

`module_info`:

```
crackme.exe  base=0x7ff6a7ac0000  size=0x28000  entry=0x7ff6a7ac17a0

Sections:
Address           Size        Name
0x7ff6a7ac1000    0x14b70     .text
0x7ff6a7ad6000    0xa7c4      .rdata
0x7ff6a7ae1000    0x1780      .data
```

From this listing alone, the model recognized the C runtime function prologue, the stack space reserved for the Win64 calling convention argument shadow space, a tail jump used instead of a return, and the `int3` filler bytes marking the end of the function, all without being told any of it.

## How it works

x64dbg-mcp is two processes talking over a named pipe:

```
MCP client (Claude Code / Claude Desktop)
        |  stdio, JSON-RPC 2.0
        v
x64dbg-mcp.exe            MCP server: schemas, limits, formatting
        |  named pipe (owner-only ACL)
        v
x64dbg-mcp.dp64           plugin inside x64dbg.exe
        |  queue -> single worker thread
        v
x64dbg SDK
```

Two processes instead of one because the MCP stdio transport requires the client to launch the server as its own child process, while x64dbg is opened directly by the user, not by the MCP client. Splitting the server out also means that parsing data coming from the model happens outside the debugger process, so a bug there cannot bring the debugging session down with it. See `docs/adr/0001-architecture.md` for the full rationale.

## Installation

1. Download a build, or build it from source (see below).
2. Copy `x64dbg-mcp.dp64` into the `plugins` folder next to `x64dbg.exe` (for the 32-bit debugger, copy `x64dbg-mcp.dp32` into the `plugins` folder next to `x32dbg.exe`).
3. Put `x64dbg-mcp.exe` anywhere.
4. Add the server to the MCP client configuration.

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "C:\\path\\to\\x64dbg-mcp.exe"
    }
  }
}
```

Claude Code:

```
claude mcp add x64dbg -- C:\path\to\x64dbg-mcp.exe
```

The server can be started before x64dbg: the connection to the plugin is established on the first tool call, and if the debugger is restarted, the server reconnects on its own.

## Tools

### Session and state

Whether the server and the debugger are reachable, and what the debuggee is currently doing.

| Tool | What it does |
|---|---|
| `server_status` | Reports whether the server is connected to the x64dbg plugin. |
| `debugger_status` | Reports whether a debugging session exists, running or paused, PID/TID, pointer size, current instruction pointer, and module. |
| `wait_until_paused` | Waits for the debuggee to reach a paused state. |

### Reading memory and code

Inspecting data, instructions, and the current call context without changing anything.

| Tool | What it does |
|---|---|
| `read_memory` | Reads raw bytes from the debuggee memory, up to 1 MiB per call, with a hex dump. |
| `disassemble` | Disassembles up to 256 instructions starting at an address, with symbols already resolved. |
| `disassemble_function` | Disassembles an entire function, using the debugger's own analysis of its boundaries. |
| `function_graph` | The control-flow graph of a function: its basic blocks and the branches between them, for untangling obfuscated and virtualized control flow. |
| `read_string` | Reads the string at a memory address, ASCII or UTF-16, decoded the way the debugger would show it. |
| `read_stack` | Reads machine words from the top of the stack together with the debugger's annotations for them. |
| `call_stack` | Reconstructs the chain of calls that led to the current instruction, with return addresses and resolved symbols. |
| `read_registers` | Reads the CPU registers of the paused debuggee: general purpose, segment, debug, and the flags register with individual flags decoded. |
| `evaluate_expression` | Evaluates an expression in x64dbg's expression language and reports its value. |
| `find_pattern` | Searches the debuggee memory for a byte signature, with masks. |
| `find_references` | Lists the places that reference a given address. |

### Execution control

Running, stopping, and stepping the debuggee.

| Tool | What it does |
|---|---|
| `debug_control` | Runs, pauses, stops, restarts the debuggee, or runs to a chosen address. |
| `step` | Steps into, over, or out of the current instruction, one or many steps per call. |
| `run_to_user_code` | Resumes execution until control returns to the program's own code, skipping system library code. |

### Processes

Finding a process to attach to, and attaching to or detaching from it.

| Tool | What it does |
|---|---|
| `list_processes` | Lists processes running on the system, with PID, executable name, and window title, for picking an attach target. |
| `attach_process` | Attaches the debugger to an already-running process and waits for it to pause. |
| `detach_process` | Detaches from the debuggee, leaving it running, unlike stopping it. |

### Breakpoints

Setting and managing software, hardware, and memory breakpoints.

| Tool | What it does |
|---|---|
| `set_breakpoint` | Sets a software, hardware, or memory breakpoint, optionally conditional or logging. |
| `manage_breakpoint` | Deletes, enables, or disables an existing breakpoint. |
| `list_breakpoints` | Lists every breakpoint with its type, state, hit count, and name. |

### Process and module layout

The shape of the debuggee: its modules, memory, and threads.

| Tool | What it does |
|---|---|
| `list_modules` | Lists loaded modules with base address, size, entry point, and path. |
| `module_info` | Reports a module's sections and, on request, its export and import tables. |
| `memory_map` | Reports the process memory map: regions, state, type, and access protection. |
| `list_threads` | Lists the debuggee threads with their state and which one is current. |

### Symbols and annotations

Naming things, and finding things that are already named.

| Tool | What it does |
|---|---|
| `list_symbols` | Lists a module's symbols — imports, exports, and debug information — with an optional name filter. |
| `annotate` | Reads or writes the debugger's own labels, comments, and bookmarks at an address. |

### Writing and patching

Changing the debuggee's memory, registers, and page protection.

| Tool | What it does |
|---|---|
| `write_memory` | Writes raw bytes into the debuggee memory, recorded as an undoable patch by default. |
| `set_register` | Sets a register, or any debugger variable, to a given value. |
| `assemble_at` | Assembles one instruction and writes it at the given address. |
| `patches` | Lists recorded patches, restores them, or writes them into a copy of the file on disk. |
| `set_page_rights` | Changes the memory protection of the region containing an address. |
| `allocate_memory` | Allocates a block of readable, writable, executable memory inside the debuggee. |
| `free_memory` | Frees memory previously allocated with `allocate_memory`. |
| `dump_memory` | Writes a region of the debuggee's memory to a file on disk. |

### Tracing and coverage

Running long stretches of the debuggee inside x64dbg itself instead of one MCP call per instruction.

| Tool | What it does |
|---|---|
| `trace_until` | Steps the debuggee one instruction at a time inside the debugger until a condition is met or a step limit is reached. |
| `trace_record` | Starts or stops recording every instruction the debuggee executes to a trace file. |
| `set_trace_log` | Configures the log line written for each traced instruction: a format string, an optional condition, and an optional output file. |
| `code_coverage` | Records which addresses were executed and how many times, then reads the counts back. |

### Commands and scripting

A fallback for anything not covered by a dedicated tool.

| Tool | What it does |
|---|---|
| `execute_command` | Runs any x64dbg command and returns whatever the debugger printed. |
| `run_script` | Runs an x64dbg script given as text. |
| `read_log` | Returns the most recent lines of the x64dbg log. |

### Process environment

What the debuggee has opened outside its own memory: kernel objects, windows, and network connections.

| Tool | What it does |
|---|---|
| `list_handles` | Lists the kernel objects the debuggee currently has open: files, registry keys, mutexes, events, and more. |
| `list_windows` | Lists the windows belonging to the debuggee, with their window procedure address. |
| `list_connections` | Lists the debuggee's active TCP connections. |
| `seh_chain` | Shows the chain of structured exception handlers registered for the current thread. |

## Resources

Beyond tools, the server exposes MCP resources: static or read-only data a client can pin into its context once, instead of spending a tool call to fetch it on every request.

| URI | What it contains |
|---|---|
| `x64dbg://commands` | Every command the debugger accepts, with aliases and whether each requires an active debugging session. |
| `x64dbg://memory-map` | The debuggee's memory regions. |
| `x64dbg://disassembly/current` | Disassembly at the current instruction. |

## Prompts

The server also exposes MCP prompts: reusable starting procedures for the reverse-engineering workflows it exists to support. A prompt does not act on the debugger by itself — it returns a block of instructions naming the real tools to call and in what order, for the model to follow.

| Name | What it starts |
|---|---|
| `analyze_function` | Understanding what a single function does: its boundaries, callers, called APIs, and strings, ending with the finding recorded in the debugger's own database. |
| `trace_to_api_call` | Stopping execution exactly when the debuggee calls a chosen API function, then inspecting the call's arguments and caller. |
| `defeat_anti_debugging` | Finding and neutralizing anti-debugging checks: the common API-based checks, exception-based tricks, and timing-based tricks. |
| `analyze_virtualized_code` | Reverse-engineering a code virtualization protector's VM: locating the dispatcher, tracing virtual instructions one at a time inside the debugger, and building a map of handler addresses to their effect. |

## Security and risks

This server gives the model full access to the debugger: reading memory, controlling execution, setting breakpoints, and, just as much, writing to the debuggee — patching memory, assembling instructions, changing registers, and running arbitrary x64dbg commands and scripts in the debuggee's own context. It can also attach to a process the user did not start from x64dbg, allocate executable memory inside a process, and write regions of process memory to files on disk. Please read this before pointing it at anything important:

- Only debug code you are prepared to lose, and preferably do it in an isolated environment: the debuggee actually runs, it is not simulated.
- The named pipe is restricted to the owner of the session and the system; remote connections are rejected.
- The model can make mistakes. It can pause, modify, or terminate the debugged process.
- Responsibility for what is being debugged rests with the user, not the tool.

## Compatibility

The plugin is built against the x64dbg plugin SDK and loads into recent x64dbg releases.

- The plugin links only against SDK functions that the debugger's `x64bridge.dll` exports directly. If a build of x64dbg is missing a function the plugin references, the whole plugin fails to load — Windows refuses to resolve the DLL's import table, x64dbg shows an entry-point error dialog, and none of the tools are available, not just the one that used the missing function. This is why the project deliberately restricts itself to long-established SDK exports.
- Some features are reached instead through the SDK's `DbgFunctions()` function-pointer table, which is resolved at run time rather than imported. Those are checked for availability before use and report a plain "not supported by this x64dbg build" error instead of crashing or failing to load.
- The plugin's imports were checked against the export table of x64dbg 2025.08.19, and it is built against the 2026.05.27 plugin SDK. If the plugin fails to load with an entry-point error, the fix is to update x64dbg.

## Building from source

Requires Visual Studio 2022 or newer and CMake 3.19+. The x64dbg SDK is downloaded automatically at configure time and verified against a checksum; there is nothing to install by hand.

```
cmake -B build64 -A x64
cmake --build build64 --config Release
```

For a 32-bit build, use `-A Win32` instead. The build produces `build64\Release\x64dbg-mcp.dp64` and `build64\Release\x64dbg-mcp.exe`.

Tests:

```
ctest --test-dir build64 -C Release --output-on-failure
```

The C runtime is linked statically, so there is nothing extra to redistribute alongside the built binaries.

## Development and verification

`tests/target/crackme.c` is a small target program used for manual verification of the MCP tools. It is built with `-DX64DBG_MCP_BUILD_TARGET=ON` and prints its own reference addresses (PID, module base, key target addresses) on startup, so a tool answer can be checked against known-correct values instead of just looking plausible. See `tests/target/README.md` for the full list of targets and how to check each one.

## Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| Tools report that x64dbg is not running | The plugin is not loaded, or the debugger is closed | Check `server_status`, confirm the plugin file is in `plugins`, and look for a load message in the x64dbg log |
| Multiple x64dbg instances running | The pipe name is taken; the second plugin picks a name that includes its process ID and logs it | Pass that name to the server with `--pipe <name>` |
| The client sees no tools | The server did not start | Run `x64dbg-mcp.exe --help` by hand and check its stderr output |
| Need a detailed log | | Pass `--log-level debug`; the log is written to stderr |
| `attach_process` reports that no debugging session started, or attaching appears to hang | Another x64dbg plugin is showing a modal dialog. ScyllaHide, commonly installed for anti-anti-debugging work, shows an error dialog during attach (for example "NtSetInformationThread is already hooked!"), and x64dbg does not finish attaching until it is dismissed | Switch to the x64dbg window and dismiss the dialog, then retry. The plugin cannot dismiss another plugin's dialog on your behalf |

## Limitations

Not implemented yet: a handful of convenience tools that would bundle several existing calls into one — a post-halt snapshot, a one-call function breakdown, searching for immediate values, and a registers diff. Deliberately out of scope for now: working with types and structures, graphical interaction, managing x64dbg windows, and source-level debugging. See `docs/tools.md` for the full roadmap.

## License

MIT, see `LICENSE`. Third-party licenses are listed in `THIRD_PARTY_LICENSES.md`. The x64dbg SDK is not bundled in this repository; it is downloaded during the build.
