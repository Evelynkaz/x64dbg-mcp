#pragma once

// Message format between the bridge and the plugin.
//
// Request — an object with fields id, method, params.
// Response — an object with fields id, ok, and either result (on success) or error (on failure).

namespace x64dbg_mcp::ipc
{

// Protocol version. The major version changes on incompatible changes;
// a side with a different major version must refuse the connection
// rather than try to work with it.
constexpr int kProtocolVersionMajor = 1;
constexpr int kProtocolVersionMinor = 0;

// Default named pipe name.
constexpr const char* kDefaultPipeName = R"(\\.\pipe\x64dbg-mcp)";

// Request field names.
constexpr const char* kFieldId = "id";
constexpr const char* kFieldMethod = "method";
constexpr const char* kFieldParams = "params";

// Response field names.
constexpr const char* kFieldOk = "ok";
constexpr const char* kFieldResult = "result";
constexpr const char* kFieldError = "error";

// Error object field names.
constexpr const char* kFieldErrorCode = "code";
constexpr const char* kFieldErrorMessage = "message";

// Protocol error codes.
enum class ErrorCode : int
{
    None = 0,
    InvalidRequest = 1,      // the message failed to parse or is missing required fields
    UnknownMethod = 2,       // the method isn't registered
    NotDebugging = 3,        // debugging isn't running
    DebuggerBusy = 4,        // the process is currently running, the operation requires a pause
    InvalidArgument = 5,     // an argument failed validation
    Timeout = 6,             // the operation didn't finish within the allotted time
    OperationFailed = 7,     // the debugger refused to perform the operation
    Internal = 8,            // an unexpected failure inside the plugin
};

} // namespace x64dbg_mcp::ipc
