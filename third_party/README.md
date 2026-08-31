# Vendored dependencies

This directory contains third-party header-only libraries included in the
repository as source (vendored), so the build doesn't depend on external
package managers.

| Library          | Version | License | Source | Why it's needed |
|------------------|--------|----------|--------------|-------------|
| nlohmann/json    | v3.12.0 | MIT | https://github.com/nlohmann/json/releases/download/v3.12.0/json.hpp | Parsing and building JSON for the MCP protocol and inter-process communication |
| doctest          | v2.5.3  | MIT | https://raw.githubusercontent.com/doctest/doctest/v2.5.3/doctest/doctest.h | Unit tests |

Both libraries are header-only and therefore need no separate build step — just
include the header. The x64dbg SDK is deliberately absent here: it is
downloaded by CMake during project configuration (see
`cmake/x64dbg-sdk.cmake`) and is not vendored.

Full license texts are provided in `THIRD_PARTY_LICENSES.md`.

## How to update a version

1. Replace the header file (and the license file, if it changed) in the
   corresponding subdirectory, without hand-editing it.
2. Update the version number in the table above.
3. Update the version number and license text in `THIRD_PARTY_LICENSES.md`.
