# ADR 0001. Architecture: plugin + separate stdio process

- Status: Accepted
- Date: 2026-08-30

## Context

The project's goal is an MCP server for the x64dbg debugger that gives an AI agent
full access to reverse-engineering and debugging capabilities.

The product is installed by third-party users, so what matters most is runtime
stability and the absence of runtime dependencies the user would have to install
separately.

The user explicitly prefers the stdio transport.

Verified environment: x64dbg installed at `D:\Reverse\x64dbg` (build 2025.08.19);
compiler — MSVC 19.x from Visual Studio 18.2.1; the current SDK is taken from
x64dbg release `2026.05.27`, asset `x64dbg-pluginsdk-cmake.zip`.

## Options considered

### Option A — all-in-one

A C++ plugin (`.dp64`/`.dp32`) that brings up its own MCP server over Streamable
HTTP on 127.0.0.1.

### Option B — bridge

A C++ plugin inside x64dbg plus a separate MCP server process; the two talk over
a named pipe.

## Criteria

- Compliance with the stdio transport requirement.
- Debugger resilience to server failures.
- Amount of external dependencies.
- Testability.
- Latency.
- Complexity (number of moving parts).
- Ease of installation for the end user.

## Decision

**Option B** is adopted: a `x64dbg-mcp.dp64`/`.dp32` plugin plus a separate
`x64dbg-mcp.exe` executable (the stdio MCP server). Both parts are implemented in
C++17, in a single repository, with a single CMake build.

Rationale:

1. **stdio is incompatible with option A.** In the stdio transport, the MCP
   client launches the server as a child process and talks to it over its
   standard input/output streams. x64dbg is a GUI application; its standard
   streams don't belong to the MCP client. To get stdio, the client would have
   to launch x64dbg itself as its own subprocess and manage its lifecycle,
   which is unacceptable. Option A forces a move to HTTP, i.e. abandoning the
   user's requirement.

2. **The MCP specification requires the server to be restartable.** The spec
   revision from 2026-07-28 mandates that the client restart a crashed stdio
   server, and the protocol is declared stateless. Restarting a standalone
   bridge is harmless. Restarting x64dbg would mean losing the debugging
   session — option A conflicts with the protocol's model.

3. **Failure isolation.** Parsing JSON from the model, schema validation,
   response formatting — this is the most likely source of bugs, and in option
   B that code runs outside x64dbg. Inside the debugger, only a minimal,
   auditable layer remains: receive a frame, call the SDK, send a response.

4. **Fewer dependencies, not more.** Option A would require vendoring an HTTP
   server. Option B needs no HTTP at all: only a header-only JSON library
   remains. This reduces the amount of third-party code running inside the
   debugger process.

5. **Testability.** The MCP layer, parameter validation, and serialization are
   unit-tested without a running x64dbg.

## Consequences

Positive:

- Compliance with the stdio transport requirement.
- A server crash does not bring down the debugger.
- The MCP layer is tested in isolation from x64dbg.
- No runtime dependencies for the user: static CRT, a self-contained `.exe`.

Negative, and how we mitigate them:

- An IPC protocol appears — its own source of bugs and a versioning concern.
  Mitigation: a minimal frame (4-byte little-endian length prefix + UTF-8
  JSON), the protocol version is sent in the first message, and the connection
  is rejected on a major-version mismatch; the protocol is documented in a
  separate file, `docs/protocol.md`.
- Two deliverables instead of one (`.dp64`/`.dp32` and `.exe`). Mitigation:
  both are built by a single command and shipped in a single release archive.
- Extra IPC latency. Estimate: fractions of a millisecond on a local named
  pipe, negligible compared to the debugging operations themselves.

## Implementation language

C++17 for both parts. Rationale: the plugin must be native; a single language
gives one repository, one build system, and shared code (JSON, IPC framing,
formatting). A self-contained `.exe` with a statically linked CRT requires
neither an interpreter nor redistributable packages from the user.
Alternatives (Python, C#) were rejected precisely because of the runtime
dependency they'd impose on the end user.

## External dependencies

Header-only libraries only, vendored under `third_party/` with version and
license noted:

- nlohmann/json — JSON, MIT license.
- doctest — unit tests, MIT license.

Both licenses are compatible with the project's license. No HTTP library is
needed — a direct consequence of choosing option B.

The x64dbg SDK is not vendored: it is downloaded during CMake configuration
from the official release, so the repository contains no third-party code.

## Diagram

```
MCP client (Claude Desktop / Claude Code)
        |  stdio, JSON-RPC 2.0
        v
x64dbg-mcp.exe (bridge)
        |  named pipe
        v
x64dbg-mcp.dp64 (plugin inside the x64dbg.exe process)
        |  queue
        v
dedicated worker thread
        |
        v
x64dbg SDK
```
