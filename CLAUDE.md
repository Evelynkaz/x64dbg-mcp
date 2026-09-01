# Working on x64dbg-mcp

This plugin runs **inside the x64dbg process**. A crash, a hang, or a heap corruption
here takes down the user's debugger and whatever hostile binary they were analyzing.
Every rule below exists because breaking it already broke something. Each one names
the failure so it is clear what is being prevented.

## The x64dbg API

**Never use an x64dbg function, struct, constant, or command you have not found in the
sources.** They are cloned into `external/` (gitignored). Read the actual declaration
and, where behaviour matters, the actual implementation in `external/x64dbg/src/dbg/`.
An invented API name is not a compile error you catch later — it is a debugger crash.

**Imported symbols and function-pointer members fail differently, and the difference
decides whether the plugin loads at all.**

- Members of the `DbgFunctions()` table are pointers resolved at run time. A missing one
  is `nullptr`. Null-check every one before calling and report the feature as unsupported
  by this x64dbg build. These cannot break loading.
- Anything else from the SDK (`Script::*`, bridge functions) is a **static import**. If
  the installed debugger's `x64bridge.dll` / `x64dbg.dll` does not export it, Windows
  refuses to resolve the import table and **the entire plugin fails to load** — an
  entry-point error dialog and not a single tool, not a partial failure.

**Therefore: any change touching the SDK surface requires an import check before commit.**
Run `dumpbin /imports` on the built `.dp64` and `.dp32`, diff the imported name list
against the previous build, and confirm every name appears in `dumpbin /exports` of the
installed `x64dbg.dll` / `x32dbg.dll`. This is not optional; it caught a total load
failure caused by `DbgValSetScalar`, which is present in the SDK headers but absent from
the installed build's exports.

## Building command strings

x64dbg's own documentation warns in bold: **all numbers in expressions are hex by
default.** Arguments are separated by **commas**, not spaces.

- Format every number with an explicit `0x` prefix. A bare decimal is silently
  reinterpreted: `attach 18308` attached to nothing because it was read as `0x18308`,
  `step 10` executed sixteen steps, and a trace limit of 1000 became 4096. None of these
  reported an error — they succeeded at doing the wrong thing.
- Separate arguments with commas.
- Quote any path: a space or comma in an unquoted path becomes extra arguments.
- Verify the specific argument's parsing in `external/x64dbg/docs/commands/` or the
  command's implementation. Do not infer it from a neighbouring call site.

## Data coming back from the debugger

**Fixed-size `char` arrays are not guaranteed to be null-terminated.** Read every one with
an explicit length bound (`strnlen(arr, sizeof(arr))`), regardless of what the current
upstream implementation does. `WINDOW_INFO::windowTitle` is `char[512]` filled by a plain
`memcpy`; a title whose UTF-8 form exceeds the buffer left no terminator, and constructing
a `std::string` from it read past the end of the debugger's heap allocation. That is an
access violation, which MSVC's `catch (...)` does **not** intercept.

**Serialize JSON with `error_handler_t::replace`, never the strict default.** Strings from
a debuggee can be cut mid-multi-byte-character by the debugger's fixed buffers, and
nlohmann's strict handler throws on the resulting invalid UTF-8 — losing the entire
response because of one bad field. Both the plugin and the bridge must use the replacing
handler.

**Truncate strings on character boundaries, never on byte offsets.** A byte-wise cut
splits a multi-byte character and produces invalid UTF-8. Use the boundary-safe helper in
`debugger_tools.cpp`; a raw `substr` on text that may be non-ASCII is a bug.

**An empty result is usually a success — but prove it is not a failure.** A console
program has no windows; an offline one has no connections; many kernel objects are
unnamed. Reporting these as errors teaches the model the tool is broken. The opposite
mistake is just as bad: `GetProcessList` returns `false` both for a real failure and for
an empty snapshot, writing the count only in the latter case, so a sentinel distinguishes
them. A machine always has running processes — reporting a failure as "none found" states
something impossible and the model will reason from it.

## Staying alive inside the debugger

- **No exception may escape into x64dbg.** Wrap every entry point.
- **All x64dbg API calls go through the single worker thread**, and `src/plugin/debugger.cpp`
  is the only file that calls the SDK. That thread serializes everything, so **any
  unbounded operation blocks every other tool, including pause.** Bound anything that can
  take arbitrary time with a deadline: `GetHandleName` spawns a thread and waits 200 ms per
  handle, which at a 4096-entry cap is over ten minutes of a wedged debugger.
- Cap every list, report truncation in both the structured result and the text, and give
  every blocking operation a timeout.

## Verifying a change

**Unit tests are not sufficient and have never been.** Every serious defect in this project
passed a green test suite on both architectures: the 512-byte out-of-bounds read, the
UTF-8 truncation that made `list_windows` fail on any non-ASCII title, and the hex/decimal
bugs that silently did the wrong thing.

Verify against a live debugger using the targets in `tests/target/`, which print their own
reference values at startup so an answer can be checked against known-correct data instead
of being judged plausible:

- `crackme.c` — known addresses, a byte-pattern marker, ASCII and wide strings.
- `envtarget.c` — named mutex, event and file, a loopback TCP pair, and a window titled
  with 200 CJK characters (600 UTF-8 bytes) that reproduces the out-of-bounds read.

Prefer checks that close a loop: write memory then read it back; allocate, use, free, then
confirm the read now fails; dump a region and validate the PE header from the file format
itself; cross-check one tool against another (`registers.rsp` against `read_stack`, a call
stack's return address against the value in memory).

When measuring tool output with Python on a Russian-locale Windows machine, pass `-X utf8`.
Without it stdin is decoded as windows-1251 and correct UTF-8 output looks like mojibake —
which will be mistaken for a product defect.

## Conventions

- **English only**, everywhere in this repository, including comments and commit messages.
- Conventional Commits. Explain *why* in the body, and state what was verified and how.
- `LICENSE` is not to be modified.
- Both architectures must build and all tests pass before a commit.
- Third-party dependencies are header-only and vendored with their licenses recorded in
  `THIRD_PARTY_LICENSES.md`. **No third-party code is committed to this repository** — the
  x64dbg SDK is downloaded at build time and `external/` is gitignored.
- Do not push without the user's explicit permission.
