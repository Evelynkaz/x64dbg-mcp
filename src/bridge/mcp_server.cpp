#include "bridge/mcp_server.h"
#include "bridge/logging.h"

namespace x64dbg_mcp::bridge
{

namespace
{

// _meta keys of the modern model — constants so the long strings don't
// drift apart between the places that use them.
constexpr const char* kMetaProtocolVersion = "io.modelcontextprotocol/protocolVersion";
constexpr const char* kMetaClientCapabilities = "io.modelcontextprotocol/clientCapabilities";
constexpr const char* kMetaServerInfo = "io.modelcontextprotocol/serverInfo";

// Protection against memory blow-up from input coming from the outside
// (stdin is an external, potentially hostile source): reject messages that
// are too large before even attempting to parse them.
constexpr size_t kMaxMessageBytes = 8u * 1024u * 1024u;

// Protection against stack overflow: nlohmann::json's recursive walker
// overflows the call stack and kills the process on deeply nested input,
// bypassing any catch. Limit the depth before parsing.
constexpr int kMaxNestingDepth = 64;

// A JSON-RPC protocol error (malformed request, unknown tool, etc.) that
// must be returned to the client as a standard JSON-RPC error rather than as
// a result with isError — per the MCP specification's classification, this
// is a Protocol Error, not a Tool Execution Error.
struct ProtocolError
{
    int code;
    std::string message;
};

// Computes the maximum nesting depth of { } [ ] in the raw message text
// WITHOUT parsing it. A separate, cheap check is needed BEFORE parsing: you
// cannot rely on the parse itself — nlohmann::json's recursive parser
// overflows the stack before it manages to report an error via exception or
// discarded.
int ComputeMaxNestingDepth(const std::string& line)
{
    int depth = 0;
    int maxDepth = 0;
    bool inString = false;
    bool escaped = false;

    for (char c : line)
    {
        if (inString)
        {
            if (escaped)
                escaped = false;
            else if (c == '\\')
                escaped = true;
            else if (c == '"')
                inString = false;
            continue;
        }

        if (c == '"')
            inString = true;
        else if (c == '{' || c == '[')
        {
            ++depth;
            if (depth > maxDepth)
                maxDepth = depth;
        }
        else if (c == '}' || c == ']')
            --depth;
    }

    return maxDepth;
}

// Every response serialized below with .dump() passes
// error_handler_t::replace instead of the strict default. Data crossing
// this boundary (tool results, table text) originates in a debugged,
// possibly hostile process, so a single malformed UTF-8 string must
// degrade to U+FFFD in that one field, never throw and destroy the whole
// response — the strict default previously turned a window with a
// non-ASCII title into a bare, undiagnosable "Internal error" for the
// entire list_windows call.
nlohmann::json MakeErrorResponse(const nlohmann::json& id, int code, const std::string& message,
                                  const nlohmann::json& data = nullptr)
{
    nlohmann::json error = { {"code", code}, {"message", message} };
    if (!data.is_null())
        error["data"] = data;

    return nlohmann::json{
        {"jsonrpc", "2.0"},
        {"id", id},
        {"error", std::move(error)}
    };
}

nlohmann::json MakeResultResponse(const nlohmann::json& id, nlohmann::json result)
{
    return nlohmann::json{
        {"jsonrpc", "2.0"},
        {"id", id},
        {"result", std::move(result)}
    };
}

nlohmann::json BuildServerInfo()
{
    return nlohmann::json{ {"name", "x64dbg-mcp"}, {"version", SERVER_VERSION_STR} };
}

// Capabilities advertised both by the legacy initialize handshake and by
// the modern server/discover — kept in one place so the two can't drift apart.
nlohmann::json BuildCapabilities()
{
    return nlohmann::json{
        {"tools", nlohmann::json::object()},
        {"resources", {{"subscribe", false}, {"listChanged", false}}}
    };
}

// Extracts the _meta object from params if it is present and is actually an
// object; otherwise returns an empty object. Kept as a separate function so
// the same type check isn't repeated in several places.
nlohmann::json ExtractMeta(const nlohmann::json& params)
{
    if (params.is_object() && params.contains("_meta") && params["_meta"].is_object())
        return params["_meta"];
    return nlohmann::json::object();
}

// Adds the required fields to a modern-model result: a marker that the
// request is complete and server info in _meta.
void ApplyModernEnvelope(nlohmann::json& result)
{
    result["resultType"] = "complete";
    result["_meta"][kMetaServerInfo] = BuildServerInfo();
}

// Determines whether a message belongs to the modern protocol model.
//
// IMPORTANT: the mere presence of a _meta object in params must NOT be
// treated as a sign of the modern model — _meta is a regular part of MCP,
// and the client is free to put its own keys there under ANY protocol
// model. For instance, Claude Code 2.1.251, which speaks the legacy
// initialize handshake (version 2025-11-25), puts its own "progressToken"
// and "claudecode/toolUseId" keys into _meta. The previous implementation
// treated any message with a non-empty _meta as modern, which made the
// server demand the field _meta["io.modelcontextprotocol/protocolVersion"]
// from such a client, fail to find it, and answer with error -32602 on
// EVERY tool call — the product was unusable. The defect was found by
// connecting a real client, so this check must not be "simplified" back to
// a plain params.contains("_meta").
//
// The correct signal is the presence in _meta of at least one key
// RESERVED by the MCP specification, i.e. starting with the prefix
// "io.modelcontextprotocol/". Client keys never have this prefix.
bool IsModernProtocol(const std::string& method, const nlohmann::json& params)
{
    if (method == "server/discover")
        return true;

    const nlohmann::json meta = ExtractMeta(params);
    if (!meta.is_object())
        return false;

    constexpr const char* kReservedPrefix = "io.modelcontextprotocol/";
    for (const auto& item : meta.items())
    {
        if (item.key().rfind(kReservedPrefix, 0) == 0)
            return true;
    }
    return false;
}

} // namespace

McpServer::McpServer(ToolRegistry registry, ResourceRegistry resources)
    : registry_(std::move(registry)), resources_(std::move(resources))
{
}

nlohmann::json McpServer::HandleToolsList() const
{
    return nlohmann::json{ {"tools", registry_.ListJson()} };
}

nlohmann::json McpServer::HandleToolsCall(const nlohmann::json& params) const
{
    // A malformed request per the MCP specification's classification is a
    // protocol error, not a tool call result.
    if (!params.is_object() || !params.contains("name") || !params["name"].is_string())
        throw ProtocolError{ -32602, "params.name must be present and must be a string containing the tool name" };

    const std::string name = params["name"].get<std::string>();

    nlohmann::json arguments = nlohmann::json::object();
    if (params.contains("arguments"))
    {
        if (!params["arguments"].is_object())
            throw ProtocolError{ -32602, "params.arguments must be an object" };
        arguments = params["arguments"];
    }

    const Tool* tool = registry_.Find(name);
    if (tool == nullptr)
        throw ProtocolError{ -32602, "Unknown tool: " + name };

    // Per the MCP rules, a tool error (ToolError) is returned as a regular
    // result with isError, not as a JSON-RPC error — otherwise the model
    // wouldn't see the error text and couldn't react to it. Any other
    // exception is hidden behind a generic message so implementation
    // internals aren't exposed.
    try
    {
        const ToolResult result = tool->handler(arguments);
        const std::string text = result.text.empty()
            ? result.structuredContent.dump(2, ' ', false, nlohmann::json::error_handler_t::replace)
            : result.text;
        return nlohmann::json{
            {"content", nlohmann::json::array({
                { {"type", "text"}, {"text", text} }
            })},
            {"structuredContent", result.structuredContent},
            {"isError", false}
        };
    }
    catch (const ToolError& e)
    {
        return nlohmann::json{
            {"isError", true},
            {"content", nlohmann::json::array({
                { {"type", "text"}, {"text", std::string(e.what())} }
            })}
        };
    }
    catch (...)
    {
        return nlohmann::json{
            {"isError", true},
            {"content", nlohmann::json::array({
                { {"type", "text"}, {"text", "Internal error while executing the tool"} }
            })}
        };
    }
}

nlohmann::json McpServer::HandleResourcesList() const
{
    return nlohmann::json{ {"resources", resources_.ListJson()} };
}

nlohmann::json McpServer::HandleResourcesRead(const nlohmann::json& params) const
{
    // A malformed request per the MCP specification's classification is a
    // protocol error, not a resource read result.
    if (!params.is_object() || !params.contains("uri") || !params["uri"].is_string())
        throw ProtocolError{ -32602, "params.uri must be present and must be a string containing the resource uri" };

    const std::string uri = params["uri"].get<std::string>();

    const Resource* resource = resources_.Find(uri);
    if (resource == nullptr)
        throw ProtocolError{ -32002, "Resource not found: " + uri };

    // A resource whose read fails at runtime (e.g. no debugging session) is
    // not a protocol error: the client still gets a successful read whose
    // text explains what is unavailable and why, rather than a broken
    // server. No exception may escape from here.
    std::string text;
    try
    {
        text = resource->read();
    }
    catch (const std::exception& e)
    {
        text = std::string("Failed to read resource ") + uri + ": " + e.what();
    }
    catch (...)
    {
        text = "Failed to read resource " + uri + ": internal error";
    }

    return nlohmann::json{
        {"contents", nlohmann::json::array({
            { {"uri", uri}, {"mimeType", resource->mimeType}, {"text", text} }
        })}
    };
}

nlohmann::json McpServer::HandleDiscover() const
{
    nlohmann::json result = {
        {"supportedVersions", nlohmann::json::array({ kModernVersion })},
        {"capabilities", BuildCapabilities()},
        {"instructions",
            "This server provides access to the x64dbg debugger for reverse "
            "engineering: process inspection, breakpoints, disassembly, and "
            "memory of the debugged program."}
    };
    ApplyModernEnvelope(result);
    return result;
}

std::optional<std::string> McpServer::HandleMessage(const std::string& line)
{
    // Reject the input BEFORE parsing JSON: recursively parsing a deeply
    // nested or excessively large structure can overflow the stack or
    // memory before parsing reports an error — this has to be checked on
    // the raw text, we cannot rely on the parser itself here.
    if (line.size() > kMaxMessageBytes)
        return MakeErrorResponse(nullptr, -32600, "Invalid Request: message too large").dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);

    if (ComputeMaxNestingDepth(line) > kMaxNestingDepth)
        return MakeErrorResponse(nullptr, -32600, "Invalid Request: message nesting too deep").dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);

    // The request id is declared before the try block and used in the outer
    // catch — otherwise a -32603 error with an already-parsed id would go
    // out with id: null, and the client wouldn't be able to match the
    // response to its request.
    nlohmann::json id = nullptr;

    // Last line of defense: the contract forbids exceptions from escaping
    // HandleMessage. nlohmann::json throws when accessing missing or
    // type-mismatched fields, so we catch anything that might have slipped
    // past the explicit checks below — this way the method is guaranteed
    // not to propagate an exception outward.
    try
    {
        const nlohmann::json msg = nlohmann::json::parse(line, nullptr, false);
        if (msg.is_discarded())
            return MakeErrorResponse(nullptr, -32700, "Parse error").dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);

        if (!msg.is_object())
            return MakeErrorResponse(nullptr, -32600, "Invalid Request").dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);

        id = msg.contains("id") ? msg["id"] : nlohmann::json(nullptr);
        const bool isNotification = !msg.contains("id");

        // JSON-RPC 2.0 only allows a string, a number, or null for id. A
        // strict client would be unable to match any other type to its request.
        if (!id.is_null() && !id.is_string() && !id.is_number())
            return MakeErrorResponse(nullptr, -32600, "Invalid Request: id must be a string, number, or null").dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);

        if (!msg.contains("method") || !msg["method"].is_string())
            return MakeErrorResponse(id, -32600, "Invalid Request").dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);

        const std::string method = msg["method"].get<std::string>();
        const nlohmann::json params = msg.value("params", nlohmann::json::object());

        if (method == "notifications/cancelled")
        {
            Log(LogLevel::Info, "notifications/cancelled: " + params.dump());
            return std::nullopt;
        }

        // Any notification (a message without an id) requires no response —
        // this is a general JSON-RPC rule, not a quirk of a specific method.
        if (isNotification)
            return std::nullopt;

        // Determine the model from the message itself: initialize is always
        // the legacy handshake; otherwise see IsModernProtocol. If the model
        // is determined to be modern but something is missing inside, that
        // is discovered below and turned into a proper -32602 error rather
        // than "method not found".
        const bool isModern = (method != "initialize") && IsModernProtocol(method, params);

        if (isModern)
        {
            const nlohmann::json meta = ExtractMeta(params);

            if (!meta.contains(kMetaProtocolVersion) || !meta[kMetaProtocolVersion].is_string())
            {
                return MakeErrorResponse(id, -32602,
                    std::string("Missing required field params._meta[\"") +
                    kMetaProtocolVersion + "\"]").dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
            }

            if (!meta.contains(kMetaClientCapabilities) || !meta[kMetaClientCapabilities].is_object())
            {
                return MakeErrorResponse(id, -32602,
                    std::string("params._meta[\"") + kMetaClientCapabilities +
                    "\"] must be present and must be an object").dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
            }

            const std::string requestedVersion = meta[kMetaProtocolVersion].get<std::string>();
            if (requestedVersion != kModernVersion)
            {
                // The client needs to see all versions the server can
                // negotiate, not just the modern one — otherwise it won't
                // realize it can fall back to the initialize handshake.
                nlohmann::json supported = nlohmann::json::array({ kModernVersion });
                for (const char* legacy : kLegacyVersions)
                    supported.push_back(legacy);

                const nlohmann::json data = {
                    {"supported", supported},
                    {"requested", requestedVersion}
                };
                return MakeErrorResponse(id, -32022, "Unsupported protocol version", data).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
            }

            nlohmann::json result;
            if (method == "server/discover")
                result = HandleDiscover();
            else if (method == "tools/list")
                result = HandleToolsList();
            else if (method == "resources/list")
                result = HandleResourcesList();
            else if (method == "ping")
                result = nlohmann::json::object();
            else if (method == "tools/call")
            {
                try
                {
                    result = HandleToolsCall(params);
                }
                catch (const ProtocolError& e)
                {
                    return MakeErrorResponse(id, e.code, e.message).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
                }
            }
            else if (method == "resources/read")
            {
                try
                {
                    result = HandleResourcesRead(params);
                }
                catch (const ProtocolError& e)
                {
                    return MakeErrorResponse(id, e.code, e.message).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
                }
            }
            else
                return MakeErrorResponse(id, -32601, "Method not found: " + method).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);

            ApplyModernEnvelope(result);
            return MakeResultResponse(id, result).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
        }

        // Legacy model.
        if (method == "initialize")
        {
            std::string clientVersion;
            if (params.is_object() && params.contains("protocolVersion") && params["protocolVersion"].is_string())
                clientVersion = params["protocolVersion"].get<std::string>();

            // Default to our newest legacy version: if the client sent a
            // version we don't know, we don't break the connection — we
            // state our own version rather than echoing the unknown one back.
            std::string negotiated = kLegacyVersions[0];
            for (const char* known : kLegacyVersions)
            {
                if (clientVersion == known)
                {
                    negotiated = known;
                    break;
                }
            }

            const nlohmann::json result = {
                {"protocolVersion", negotiated},
                {"capabilities", BuildCapabilities()},
                {"serverInfo", BuildServerInfo()}
            };
            return MakeResultResponse(id, result).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
        }

        if (method == "tools/list")
            return MakeResultResponse(id, HandleToolsList()).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);

        if (method == "resources/list")
            return MakeResultResponse(id, HandleResourcesList()).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);

        if (method == "ping")
            return MakeResultResponse(id, nlohmann::json::object()).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);

        if (method == "tools/call")
        {
            try
            {
                return MakeResultResponse(id, HandleToolsCall(params)).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
            }
            catch (const ProtocolError& e)
            {
                return MakeErrorResponse(id, e.code, e.message).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
            }
        }

        if (method == "resources/read")
        {
            try
            {
                return MakeResultResponse(id, HandleResourcesRead(params)).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
            }
            catch (const ProtocolError& e)
            {
                return MakeErrorResponse(id, e.code, e.message).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
            }
        }

        return MakeErrorResponse(id, -32601, "Method not found: " + method).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    }
    catch (const std::exception& e)
    {
        return MakeErrorResponse(id, -32603, std::string("Internal error: ") + e.what())
            .dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    }
    catch (...)
    {
        return MakeErrorResponse(id, -32603, "Internal error").dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    }
}

} // namespace x64dbg_mcp::bridge
