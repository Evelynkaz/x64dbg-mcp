# MCP server tools

Below is the list of version-1 MCP server tools, grouped by purpose. The project's end goal is to bring the server to a level where the agent can reverse-engineer VMProtect-protected crackmes, so the tool set covers both full debugger access and a dedicated tracing group, without which analyzing virtualized code is impossible.

Tool descriptions are written as documentation for the model agent: what the tool does, when to use it, what it returns, and what its limits are. The quality of reverse-engineering depends directly on the quality of these descriptions — the agent picks a tool and interprets its result based solely on what is written here.

## Principles

- Every tool returns both a structured result and human-readable text.
- Every debug-control operation accepts `wait` (enabled by default) and `timeout_ms`, and returns the debugger's state AFTER the operation: state, CIP value, stop reason. The agent should never have to guess how an asynchronous operation ended.
- Every blocking operation has a timeout. A stuck request must return an error, not freeze the debugger.
- Limits apply: a maximum number of bytes to read, a maximum number of instructions to disassemble, a cap on response size.
- **Heavy work runs inside the debugger, not as a loop of MCP calls.** The agent must not make one call per instruction: that's what conditional tracing, trace recording, and code coverage exist for. This is critical for goals like analyzing virtualized code, where the instruction count runs into the hundreds of thousands.
- The "Write" and "Commands" groups can be disabled in the configuration; all groups are enabled by default.
- **An arbitrary command does not replace a dedicated tool.** The `execute_command` tool gives full access to the debugger, but x64dbg commands are actions, not a data source: out of 308 documented commands, 266 expose no result variables at all, and the rest return at best a single number. Anything the agent needs to read is exposed through the API and returned in structured form; commands remain a fallback path for actions that have no dedicated tool.

## Tool groups

### State and inspection (read-only)

| Tool | Purpose | Backed by |
|---|---|---|
| `debugger_status` | Whether debugging is active, state (running/paused), PID, bitness, current CIP, module | `DbgIsDebugging`, `DbgIsRunning`, `DbgGetProcessId`, `DbgGetThreadId`, `DbgGetDebugEngine` |
| `list_modules` | Modules: base, size, entry point, path | `Script::Module::GetList` |
| `module_info` | Module sections, exports, imports | `Script::Module::InfoFromName`, `SectionListFromName`, `GetExports`, `GetImports` |
| `memory_map` | Memory regions, rights, state | `DbgMemMap`, `DbgFunctions()->GetPageRights` |
| `list_threads` | Threads, identifiers, names | `DbgGetThreadList`, `DbgFunctions()->ThreadGetName` |
| `read_registers` | Registers of the selected thread: general-purpose, flags, segment, SIMD | `DbgGetRegDumpEx` |
| `call_stack` | Call stack | `DbgFunctions()->GetCallStackEx`, `GetCallStackByThread` |
| `read_stack` | Stack contents with comments | `DbgStackCommentGet`, `DbgMemRead` |
| `list_breakpoints` | All breakpoints with all fields | `DbgFunctions()->BpRefList`, `BpGetFieldNumber`, `BpGetFieldText` |
| `list_symbols` | Symbols, labels, comments | `DbgSymbolEnum`, `DbgGetLabelAt`, `DbgGetCommentAt` |

### Reading and analysis

| Tool | Purpose | Backed by |
|---|---|---|
| `read_memory` | Read with a limit, output as hex with ASCII or base64 | `DbgMemRead`, `DbgMemIsValidReadPtr` |
| `disassemble` | N instructions from an address | `DbgDisasmFastAt`, `GuiGetDisassembly` |
| `disassemble_function` | An entire function based on analysis boundaries | `DbgFunctionGet` |
| `function_graph` | A function's control-flow graph; helps untangle obfuscated and virtualized code | `DbgAnalyzeFunction` |
| `read_string` | ASCII and UTF-16 with auto-detection | `DbgGetStringAt` |
| `evaluate_expression` | Evaluate x64dbg expressions, including API names and dereferencing | `DbgEval`, `Script::Misc::ParseExpression` |
| `find_pattern` | Byte signature search with masks | `Script::Pattern::FindMem` |
| `find_references` | Cross-references to an address or string | `DbgXrefGet`, `DbgGetXrefCountAt` |
| `dump_memory` | Dump a region to a file | — |

### Debug control

| Tool | Purpose | Backed by |
|---|---|---|
| `debug_control` | `run`, `pause`, `stop`, `restart`, `run_to_address` | the `run`, `pause`, `StopDebug` commands, queued via `DbgCmdExec` followed by waiting for the pause event |
| `step` | `into`, `over`, `out`, with a step count | the `StepInto`, `StepOver`, `StepOut` commands |
| `wait_until_paused` | Explicit wait for a halt with a timeout | — |
| `set_breakpoint` | Software, hardware, and memory breakpoints; with condition, logging, an on-hit command, one-shot | the `bp`, `bphws` commands, `SetBreakpointCondition`, `SetBreakpointLog`, `SetBreakpointLogCondition`, `SetBreakpointCommand`, `SetBreakpointSingleshoot`, `SetBreakpointFastResume`, `SetBreakpointSilent` |
| `manage_breakpoint` | Delete, enable, disable, reset hit count | the `bc`, `bd`, `be` commands, `ResetBreakpointHitCount`, `GetBreakpointHitCount` |

### Tracing and code coverage

This group exists for tasks where the instruction count runs into the hundreds of thousands: analyzing virtualized and packed code. Tracing runs entirely inside x64dbg; only the result is handed back.

| Tool | Purpose | Backed by |
|---|---|---|
| `trace_until` | Step trace, into or over, until a condition is met or the step limit is exhausted. The key tool in this group | the `TraceIntoConditional` (short form `ticnd`) and `TraceOverConditional` (short form `tocnd`) commands; both take a condition as the first argument and an optional step maximum as the second |
| `trace_record` | Record a trace to a file: start and stop. Recording alone does not trace — a trace command is still needed | the `StartRunTrace` command (aliases `StartTraceRecording`, `opentrace`; argument is a file name) and `StopRunTrace` |
| `trace_log` | Configure the log text and condition used during tracing | the `TraceSetLog`, `TraceSetLogFile`, `TraceSetCommand` commands |
| `code_coverage` | Which addresses were executed and how many times | `DbgFunctions()->SetTraceRecordType`, `GetTraceRecordType`, `GetTraceRecordHitCount`, `GetTraceRecordByteType` |
| `run_to_user_code` | Leave system code and return to user code; sets temporary breakpoints on user-code pages rather than single-stepping. Useful for unpacking. Documented limitation: the command fails if a previous call of the same kind is still running | the `RunToUserCode` command (short form `rtu`) |

### Write (this group can be disabled)

| Tool | Purpose | Backed by |
|---|---|---|
| `write_memory` | Write bytes | `DbgMemWrite`, `DbgFunctions()->MemPatch` |
| `set_register` | Change a register | `Script::Register::Set` |
| `assemble_at` | Assemble an instruction at an address, padding with nops | `DbgFunctions()->AssembleAtEx`, `Script::Assembler::AssembleMemEx` |
| `set_page_rights` | Change a memory page's rights | `DbgFunctions()->SetPageRights` |
| `patches` | List patches, revert them, apply to a file | `DbgFunctions()->PatchEnum`, `PatchRestore`, `PatchRestoreRange`, `PatchFile` |

### Commands and scripts (this group can be disabled)

| Tool | Purpose | Backed by |
|---|---|---|
| `execute_command` | An arbitrary x64dbg command, returning its result and captured log output. A universal fallback: anything not covered by a dedicated tool is available through this one | — |
| `run_script` | Run an x64dbg script | — |
| `read_log` | Read log output | — |

### Agent-level tools

This group does not exist to add new debugger capabilities, but to save the model's calls and context. Every MCP call costs the agent time and context space, so where the agent almost always requests several things in a row, it's cheaper to hand them back in one call. None of the tools in this group provides anything unattainable by combining the others — it just makes it cheaper.

| Tool | Purpose | Backed by |
|---|---|---|
| `context_snapshot` | The full picture right after a halt, in one call: stop reason, registers with changed ones flagged, top of the stack, disassembly around CIP with symbols, current module and function. Replaces the four or five separate calls the agent would otherwise make after every pause | `DbgGetRegDumpEx`, `DbgDisasmFastAt`, `DbgFunctions()->GetCallStackEx`, `DbgGetModuleAt` |
| `analyze_function` | Break down a function in one call: boundaries, disassembly, incoming cross-references, called API functions, strings and constants used | `DbgFunctionGet`, `DbgDisasmFastAt`, `DbgXrefGet`, `DbgGetStringAt` |
| `search_immediate` | Search for immediate values in a module's code: magic numbers, encryption keys, buffer sizes. Complements byte-signature search when the target is baked into an instruction rather than sitting in data | `DbgDisasmFastAt`, `Script::Module::InfoFromName` |
| `registers_diff` | What changed in registers and flags between two halt points | `DbgGetRegDumpEx` |

The `step` and `trace_until` tools return register and flag changes alongside the new state, not just the state itself. The reason is that when analyzing virtualized code, the meaning of a VM handler shows up precisely in what it changed. Making the model compare two full register dumps means burning its context and getting comparison errors in a place where the debugger can just hand over a ready answer.

Disassembly always comes back with symbols, labels, and comments already resolved: the agent should never have to guess what lives at an address. Large responses support paged retrieval, so one big chunk doesn't push everything else out of the model's context.

## Resources and prompts

MCP resources are the current disassembled fragment and the memory map. Prompts cover typical scenarios: analyzing a function, tracing to an API call, defeating anti-debugging, and analyzing virtualized code.

A separate resource is the x64dbg command reference. There are over three hundred commands, and the model doesn't remember their syntax by heart, which makes it prone to inventing commands and arguments that don't exist. The reference is exposed as an MCP resource, so it only enters the context when it's actually needed. The official x64dbg documentation is distributed under the MIT license, which is compatible with the project's license, so the reference can be built from it with attribution given in THIRD_PARTY_LICENSES.

## Deliberately out of scope for version 1

- Working with types and structures — get the solid foundation first, extend later.
- Graphical interaction — get the solid foundation first, extend later.
- Managing x64dbg windows — get the solid foundation first, extend later.
- Working with source code and line-level debug information — get the solid foundation first, extend later.
