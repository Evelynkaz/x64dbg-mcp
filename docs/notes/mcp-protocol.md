# Note: MCP specification and server requirements

Source: `https://modelcontextprotocol.io/specification/2026-07-28`, checked 2026-08-30.

## Two protocol eras

- **Modern**: revision `2026-07-28` and newer. The protocol is declared stateless, there is no handshake, and version/capabilities are sent with every request.
- **Legacy**: `2025-11-25` and older. A session is established with an `initialize` request.
- **Dual-era** implementation supports both. Our server must be dual-era: modern clients work against the new model, existing ones against `initialize`.

## Required fields of a modern request

The fields live under `params._meta`:

| Key | Type | Required |
|---|---|---|
| `io.modelcontextprotocol/protocolVersion` | string | yes |
| `io.modelcontextprotocol/clientCapabilities` | ClientCapabilities | yes |
| `io.modelcontextprotocol/clientInfo` | Implementation | no |
| `io.modelcontextprotocol/logLevel` | LoggingLevel | no |

A request missing a required field is invalid; the server must respond with error `-32602`.
Responses from the server must include `_meta["io.modelcontextprotocol/serverInfo"]`.

## resultType

Every result must contain a `resultType` field. `"complete"` means the request finished and the result is final. `"input_required"` means additional input is needed. If the field is absent, the client treats it as `"complete"` (for compatibility with older servers).

## server/discover

The server must implement the `server/discover` method. Example request:

```json
{ "jsonrpc": "2.0", "id": "discover-1", "method": "server/discover",
  "params": { "_meta": {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": { "name": "ExampleClient", "version": "1.0.0" },
    "io.modelcontextprotocol/clientCapabilities": {} } } }
```

Example response:

```json
{ "jsonrpc": "2.0", "id": "discover-1", "result": {
    "resultType": "complete",
    "supportedVersions": ["2026-07-28"],
    "capabilities": { "tools": {}, "resources": {} },
    "_meta": { "io.modelcontextprotocol/serverInfo": { "name": "ExampleServer", "version": "1.0.0" } },
    "instructions": "...",
    "ttlMs": 3600000,
    "cacheScope": "public" } }
```

`server/discover` also serves as a probe the client uses on stdio to determine which era the server implements.

## Version errors

If the server does not support the requested version, it must return code `-32022` with the list of supported versions:

```json
{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32022, "message": "Unsupported protocol version",
  "data": { "supported": ["2026-07-28", "2025-11-25"], "requested": "1900-01-01" } } }
```

Other codes defined by the spec: `-32020` HeaderMismatch, `-32021` MissingRequiredClientCapability.
The range `-32020`..`-32099` is reserved by the specification; custom codes must not be placed there. The range `-32000`..`-32019` is declared legacy, and new implementations should not use it. Custom codes should be placed outside the reserved range `-32768`..`-32000`.

Separately: a server that supports only modern versions must list the supported versions in the error text returned for `initialize`, since legacy clients have no mechanism for negotiating forward.

## stdio rules

- The client launches the server as a child process.
- One message per line; newlines inside a message are forbidden; encoding is UTF-8.
- Nothing but valid MCP messages may appear on `stdout`. This is a hard requirement: any debug print to stdout breaks the transport.
- Arbitrary journal messages can be written to `stderr`; the client is not required to treat them as an error indicator.
- The server does not send JSON-RPC requests to the client.
- Cancelling a request is done via the `notifications/cancelled` notification referencing the request id; the server must stop working on it and send no further messages for that request.
- Termination: the client closes stdin; the server must exit immediately on receiving EOF on stdin. This is the primary and only portable signal for graceful shutdown.
- If the server crashes unexpectedly, the client restarts the process; any in-flight requests are simply lost.

## JSON Schemas

Schemas are treated as JSON Schema 2020-12 by default when `$schema` is not specified. Using 2020-12 explicitly is recommended.

## What the client actually sends: verified by experiment

Verified on 2026-08-30 against Claude Code version 2.1.251 (newer than 2.1.232, the version starting from which the runtime supporting the 2026-07-28 revision is enabled).

Method: a local stdio stub server was registered, capable of responding under both the modern and legacy models; all messages received from the client were logged.

The first message received was:

```json
{"method":"initialize",
 "params":{"protocolVersion":"2025-11-25",
 "capabilities":{"roots":{"listChanged":true},"elicitation":{}},
 "clientInfo":{"name":"claude-code","title":"Claude Code","version":"2.1.251"}},
 "jsonrpc":"2.0","id":0}
```

Next came the `notifications/initialized` notification, followed by a `tools/list` request.

No `server/discover` request was ever received.

Conclusion: as of this check, Claude Code uses the legacy model with an `initialize` handshake and version `2025-11-25` for local stdio servers. It negotiates the modern revision with servers over HTTP and with connectors, but not with local stdio servers.

Practical consequence: supporting the legacy model is mandatory, or the server won't connect at all. Support for the modern model is added at the same time, so the project won't need rework once clients are updated. This check should be repeated whenever new client versions are released.

## Conclusions for our implementation

- The server is dual-era: it handles both `initialize` and modern requests carrying `_meta`.
- Implement `server/discover`.
- Put `resultType: "complete"` and `serverInfo` in `_meta` on every result.
- No diagnostics are ever written to stdout; all logging goes to stderr and to a file.
- Handle `notifications/cancelled`.
- Exit on EOF on stdin.
- Pick error codes outside the reserved range, except for the codes defined by the spec.
