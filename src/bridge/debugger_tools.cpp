#include "bridge/debugger_tools.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <initializer_list>
#include <sstream>
#include <vector>

namespace x64dbg_mcp::bridge
{

namespace
{

// Разбирает шестнадцатеричную строку (как её присылает memory.read) в байты.
// Молча останавливается на первом некорректном символе — плагину доверяем,
// но падать из-за одного плохого символа в дампе не стоит.
std::vector<std::uint8_t> HexToBytes(const std::string& hex)
{
    auto nibble = [](char c) -> int
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    std::vector<std::uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            break;
        bytes.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return bytes;
}

// Привычный дамп памяти: смещение, 16 байт в шестнадцатеричном виде в
// строке, затем колонка печатных символов (непечатные заменены точкой).
std::string FormatHexDump(std::uint64_t baseAddress, const std::vector<std::uint8_t>& bytes)
{
    std::ostringstream out;
    for (size_t offset = 0; offset < bytes.size(); offset += 16)
    {
        out << std::hex << std::setw(16) << std::setfill('0') << (baseAddress + offset) << "  ";

        const size_t lineLen = (std::min)(bytes.size() - offset, static_cast<size_t>(16));
        for (size_t i = 0; i < 16; ++i)
        {
            if (i < lineLen)
                out << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<unsigned int>(bytes[offset + i]) << ' ';
            else
                out << "   ";
            if (i == 7)
                out << ' ';
        }

        out << ' ';
        for (size_t i = 0; i < lineLen; ++i)
        {
            const std::uint8_t b = bytes[offset + i];
            out << (std::isprint(b) ? static_cast<char>(b) : '.');
        }
        out << '\n';
    }
    return out.str();
}

// Листинг дизассемблера: одна строка на инструкцию — адрес, байты, мнемоника.
std::string FormatDisasmListing(const nlohmann::json& instructions)
{
    std::ostringstream out;
    for (const auto& insn : instructions)
    {
        const std::uint64_t address = insn.value("address", 0ULL);
        const std::string bytesHex = insn.value("bytes", std::string());
        const std::string text = insn.value("text", std::string());

        out << std::hex << std::setw(16) << std::setfill('0') << address << std::dec
            << "  " << std::left << std::setw(24) << std::setfill(' ') << bytesHex
            << std::right << "  " << text << '\n';
    }
    return out.str();
}

void RequireNonNegativeInteger(const nlohmann::json& arguments, const char* field, const char* toolName)
{
    if (!arguments.contains(field) || !arguments[field].is_number_integer() ||
        arguments[field].get<long long>() < 0)
    {
        throw ToolError(std::string(toolName) + ": '" + field + "' must be a non-negative integer");
    }
}

// Проверяет, что поле — строка из заданного набора допустимых значений, и
// возвращает её. Список допустимых значений печатается в сообщении об
// ошибке, чтобы модель сразу увидела, что можно было передать.
std::string RequireEnumString(const nlohmann::json& arguments, const char* field,
                               std::initializer_list<const char*> allowed, const char* toolName)
{
    if (!arguments.contains(field) || !arguments[field].is_string())
        throw ToolError(std::string(toolName) + ": '" + field + "' is required and must be a string");

    const std::string value = arguments[field].get<std::string>();
    for (const char* option : allowed)
    {
        if (value == option)
            return value;
    }

    std::ostringstream options;
    bool first = true;
    for (const char* option : allowed)
    {
        if (!first)
            options << ", ";
        options << "'" << option << "'";
        first = false;
    }
    throw ToolError(std::string(toolName) + ": '" + field + "' must be one of: " + options.str());
}

// Человекочитаемая сводка результата debug.control/debug.step/debug.wait:
// остановился ли процесс, по какой причине, по какому адресу и в каком
// модуле. Если ожидание истекло, прямо сообщает, что процесс всё ещё бежит.
std::string FormatPauseResult(const nlohmann::json& result)
{
    if (result.value("timed_out", false))
        return "Timed out waiting for the process to pause; it is still running.";

    const nlohmann::json status = result.value("status", nlohmann::json::object());
    if (!status.value("debugging", false))
        return "Not debugging. Open or attach to a process in x64dbg to start a debugging session.";

    if (!result.value("paused", false))
        return "Process is still running.";

    const std::uint64_t cip = status.value("cip", 0ULL);
    const std::string module = status.value("module", std::string());
    const std::string reason = result.value("pause_reason", std::string());

    std::ostringstream out;
    out << "Paused";
    if (!reason.empty())
        out << " (" << reason << ")";
    out << " at 0x" << std::hex << cip;
    if (!module.empty())
        out << " in " << module;
    out << ".";
    return out.str();
}

// Выровненная таблица точек останова: адрес, тип, состояние, число
// срабатываний, имя.
std::string FormatBreakpointList(const nlohmann::json& breakpoints)
{
    std::ostringstream out;
    out << std::left
        << std::setw(18) << "Address"
        << std::setw(10) << "Type"
        << std::setw(10) << "State"
        << std::setw(6) << "Hits"
        << "Name" << '\n';

    for (const auto& bp : breakpoints)
    {
        const std::uint64_t address = bp.value("address", 0ULL);
        const std::string type = bp.value("type", std::string());
        const bool enabled = bp.value("enabled", true);
        const unsigned long long hitCount = bp.value("hitCount", 0ULL);
        const std::string name = bp.value("name", std::string());

        std::ostringstream addressText;
        addressText << "0x" << std::hex << address;

        out << std::left
            << std::setw(18) << addressText.str()
            << std::setw(10) << type
            << std::setw(10) << (enabled ? "enabled" : "disabled")
            << std::setw(6) << hitCount
            << name << '\n';
    }
    return out.str();
}

// Краткая читаемая сводка debugger.status для модели: адреса — в
// шестнадцатеричном виде, десятичные адреса в реверсе бесполезны.
std::string FormatDebuggerStatus(const nlohmann::json& status)
{
    if (!status.value("debugging", false))
        return "Not debugging. Open or attach to a process in x64dbg to start a debugging session.";

    const unsigned int processId = status.value("processId", 0u);
    const unsigned int threadId = status.value("threadId", 0u);
    const int pointerSize = status.value("pointerSize", 0);
    const int bits = pointerSize == 8 ? 64 : 32;

    std::ostringstream out;
    if (status.value("running", false))
    {
        out << "Debugging: process is running (PID " << processId << ", TID " << threadId
            << ", " << bits << "-bit). Pause execution to inspect memory or disassemble.";
        return out.str();
    }

    const std::uint64_t cip = status.value("cip", 0ULL);
    const std::string module = status.value("module", std::string());

    out << "Debugging: process is paused (PID " << processId << ", TID " << threadId
        << ", " << bits << "-bit) at 0x" << std::hex << cip;
    if (!module.empty())
        out << " in " << module;
    out << ".";
    return out.str();
}

} // namespace

void RegisterDebuggerTools(ToolRegistry& registry, std::shared_ptr<PluginLink> link)
{
    Tool status;
    status.name = "debugger_status";
    status.description =
        "Report the current state of the debugger: whether a debugging session "
        "exists, whether the debuggee is running or paused, its process and "
        "thread identifiers, pointer size (32 or 64 bit), the current "
        "instruction pointer, and the module that owns it. Call this tool "
        "FIRST in every reverse-engineering session, and call it again "
        "whenever it is unclear whether the target process is still alive or "
        "where execution is currently paused: most other tools require an "
        "active session that is paused, and will fail otherwise. The "
        "instruction pointer value is only meaningful while the process is "
        "paused; while the process is running it is reported as zero. Takes "
        "no parameters.";
    status.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", nlohmann::json::object()},
        {"additionalProperties", false}
    };
    status.handler = [link](const nlohmann::json& /*arguments*/) -> ToolResult
    {
        if (!link)
            throw ToolError("debugger_status: plugin link is not configured");

        ToolResult result;
        result.structuredContent = link->Call("debugger.status", nlohmann::json::object());
        result.text = FormatDebuggerStatus(result.structuredContent);
        return result;
    };
    registry.Add(std::move(status));

    Tool readMemory;
    readMemory.name = "read_memory";
    readMemory.description =
        "Read raw bytes from the memory of the debugged process. Use it to "
        "inspect data structures, buffers, and tables, to verify the outcome "
        "of a write, or to read the data referenced by an instruction "
        "operand. Returns the requested address, the number of bytes "
        "actually read, and the bytes themselves encoded as a hex string, "
        "together with a human-readable hex dump (16 bytes per line, offset, "
        "hex byte values, and a column of printable characters with "
        "non-printable bytes shown as a dot) so the content can be read at a "
        "glance. Reads at most 1 MiB (1048576 bytes) per call. Requires an "
        "active debugging session; the address must be mapped and readable, "
        "otherwise the tool fails with an explanation. Parameters: 'address' "
        "— a non-negative integer giving the memory address to read from (a "
        "number, not a hex string); 'size' — a positive integer giving the "
        "number of bytes to read.";
    readMemory.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description", "Address to read from, given as a number (not a hex string)."}
            }},
            {"size", {
                {"type", "integer"},
                {"minimum", 1},
                {"maximum", 1048576},
                {"description", "Number of bytes to read, from 1 up to 1048576 (1 MiB) per call."}
            }}
        }},
        {"required", nlohmann::json::array({"address", "size"})},
        {"additionalProperties", false}
    };
    readMemory.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("read_memory: plugin link is not configured");

        RequireNonNegativeInteger(arguments, "address", "read_memory");
        if (!arguments.contains("size") || !arguments["size"].is_number_integer())
            throw ToolError("read_memory: 'size' must be a positive integer");
        const long long size = arguments["size"].get<long long>();
        if (size < 1 || size > 1048576)
            throw ToolError("read_memory: 'size' must be between 1 and 1048576 bytes (1 MiB)");

        const std::uint64_t address = arguments["address"].get<std::uint64_t>();

        nlohmann::json result = link->Call("memory.read", {
            {"address", address},
            {"size", size}
        });

        std::vector<std::uint8_t> bytes;
        if (result.contains("data") && result["data"].is_string())
            bytes = HexToBytes(result["data"].get<std::string>());

        ToolResult toolResult;
        toolResult.structuredContent = std::move(result);
        toolResult.text = FormatHexDump(address, bytes);
        return toolResult;
    };
    registry.Add(std::move(readMemory));

    Tool disasm;
    disasm.name = "disassemble";
    disasm.description =
        "Disassemble a sequence of instructions starting at the given "
        "address. Use it to read a function, follow control flow, find a "
        "good place for a breakpoint, or verify the result of a patch. "
        "Returns, for each instruction, its address, size in bytes, "
        "disassembled text with symbols already resolved, and raw bytes, "
        "together with a human-readable listing (one line per instruction: "
        "address, bytes, mnemonic) for quick reading. Disassembles at most "
        "256 instructions per call. Requires an active debugging session; "
        "disassembly stops early if an instruction cannot be decoded at some "
        "address. Parameters: 'address' — a non-negative integer giving the "
        "starting address (a number, not a hex string); 'count' — an integer "
        "from 1 to 256 giving the number of instructions to disassemble.";
    disasm.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description", "Address to start disassembling from, given as a number (not a hex string)."}
            }},
            {"count", {
                {"type", "integer"},
                {"minimum", 1},
                {"maximum", 256},
                {"description", "Number of instructions to disassemble, from 1 to 256."}
            }}
        }},
        {"required", nlohmann::json::array({"address", "count"})},
        {"additionalProperties", false}
    };
    disasm.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("disassemble: plugin link is not configured");

        RequireNonNegativeInteger(arguments, "address", "disassemble");
        if (!arguments.contains("count") || !arguments["count"].is_number_integer())
            throw ToolError("disassemble: 'count' must be an integer between 1 and 256");
        const long long count = arguments["count"].get<long long>();
        if (count < 1 || count > 256)
            throw ToolError("disassemble: 'count' must be between 1 and 256");

        const std::uint64_t address = arguments["address"].get<std::uint64_t>();

        const nlohmann::json instructions = link->Call("disasm", {
            {"address", address},
            {"count", count}
        });

        ToolResult result;
        result.structuredContent["instructions"] = instructions;
        result.text = FormatDisasmListing(instructions);
        return result;
    };
    registry.Add(std::move(disasm));

    Tool control;
    control.name = "debug_control";
    control.description =
        "Control the execution of the debugged process: resume it, pause "
        "it, stop the debugging session, restart the target from scratch, "
        "or run until a chosen address. 'run' resumes a paused process. "
        "'pause' suspends a running process. 'stop' ends the debugging "
        "session entirely. 'restart' terminates the current instance of "
        "the debuggee and launches the same executable again from its "
        "entry point. 'run_to' sets a temporary one-shot breakpoint at "
        "'address' and resumes execution until that breakpoint is hit (or "
        "the process stops for any other reason); use it to skip over "
        "known, uninteresting code instead of single-stepping through it. "
        "By default this tool WAITS for the process to reach a paused "
        "state and returns the state after the operation completes, so "
        "there is no need to call wait_until_paused separately after "
        "using it. If the wait times out, the returned 'timed_out' field "
        "is true and the process keeps running — this is not an error, it "
        "just means the process did not pause within the given time; call "
        "wait_until_paused or debug_control again to keep waiting. Set "
        "'wait' to false to return immediately after issuing the command. "
        "Returns 'paused' (whether the process ended up paused), "
        "'timed_out', 'pause_reason' (why it stopped, e.g. a breakpoint), "
        "and 'status' (the same structure as debugger_status). Requires "
        "an active debugging session, except for the trivial case where "
        "there is none at all. 'run_to' requires 'address'; other actions "
        "ignore it.";
    control.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"action", {
                {"type", "string"},
                {"enum", nlohmann::json::array({"run", "pause", "stop", "restart", "run_to"})},
                {"description",
                 "Execution control action to perform: 'run' resumes, 'pause' suspends, "
                 "'stop' ends the debugging session, 'restart' relaunches the same "
                 "executable, 'run_to' resumes until 'address' is reached."}
            }},
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Address to run to, given as a number (not a hex string). Required "
                 "when action is 'run_to', ignored otherwise."}
            }},
            {"wait", {
                {"type", "boolean"},
                {"default", true},
                {"description",
                 "Whether to wait for the process to pause before returning. Defaults "
                 "to true; set to false to return immediately after issuing the command."}
            }},
            {"timeout_ms", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Maximum time to wait for the process to pause, in milliseconds. Only "
                 "used when 'wait' is true. If omitted, the plugin's default timeout is used."}
            }}
        }},
        {"required", nlohmann::json::array({"action"})},
        {"allOf", nlohmann::json::array({
            {
                {"if", {
                    {"properties", {{"action", {{"const", "run_to"}}}}},
                    {"required", nlohmann::json::array({"action"})}
                }},
                {"then", {{"required", nlohmann::json::array({"action", "address"})}}}
            }
        })},
        {"additionalProperties", false}
    };
    control.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("debug_control: plugin link is not configured");

        const std::string action = RequireEnumString(
            arguments, "action", {"run", "pause", "stop", "restart", "run_to"}, "debug_control");

        nlohmann::json params = {{"action", action}};

        if (action == "run_to")
        {
            RequireNonNegativeInteger(arguments, "address", "debug_control");
            params["address"] = arguments["address"].get<std::uint64_t>();
        }
        else if (arguments.contains("address"))
        {
            RequireNonNegativeInteger(arguments, "address", "debug_control");
            params["address"] = arguments["address"].get<std::uint64_t>();
        }

        params["wait"] = arguments.value("wait", true);
        if (arguments.contains("timeout_ms"))
        {
            RequireNonNegativeInteger(arguments, "timeout_ms", "debug_control");
            params["timeout_ms"] = arguments["timeout_ms"].get<long long>();
        }

        ToolResult result;
        result.structuredContent = link->Call("debug.control", params);
        result.text = FormatPauseResult(result.structuredContent);
        return result;
    };
    registry.Add(std::move(control));

    Tool step;
    step.name = "step";
    step.description =
        "Execute one or more instructions in the paused debuggee, one step "
        "at a time. 'into' steps into any call encountered (entering the "
        "called function). 'over' steps over a call, executing the entire "
        "called function and stopping right after it returns, without "
        "entering it. 'out' runs until the current instruction IS a return "
        "from the current function, and stops THERE, without executing it "
        "yet — execution is still inside the current function, one more "
        "step ('into' or 'over') is needed to actually return to the "
        "caller. Use 'count' to perform several steps in a SINGLE "
        "call instead of calling this tool repeatedly: each tool call "
        "costs time and context, so when the intent is 'step over 20 "
        "instructions', pass count=20 rather than invoking step twenty "
        "times. 'count' accepts values from 1 to 1000. Requires the "
        "process to be paused; if it is currently running, the tool fails "
        "and reports that the process must be paused first (with "
        "debug_control action 'pause'). Returns the state after the "
        "requested steps have been executed, in the same shape as "
        "debug_control: 'paused', 'timed_out', 'pause_reason', and "
        "'status' (including the address where execution stopped). "
        "Stepping stops early, before 'count' is reached, if the process "
        "hits another breakpoint, exits, or crashes.";
    step.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"mode", {
                {"type", "string"},
                {"enum", nlohmann::json::array({"into", "over", "out"})},
                {"description",
                 "'into' steps into calls, 'over' steps over calls, 'out' stops ON the "
                 "current function's return instruction, before executing it."}
            }},
            {"count", {
                {"type", "integer"},
                {"minimum", 1},
                {"maximum", 1000},
                {"default", 1},
                {"description",
                 "Number of steps to perform in this single call, from 1 to 1000. "
                 "Prefer a larger count over calling this tool repeatedly."}
            }},
            {"wait", {
                {"type", "boolean"},
                {"default", true},
                {"description", "Whether to wait for the steps to complete before returning. Defaults to true."}
            }},
            {"timeout_ms", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Maximum time to wait for the steps to complete, in milliseconds. Only "
                 "used when 'wait' is true. If omitted, the plugin's default timeout is used."}
            }}
        }},
        {"required", nlohmann::json::array({"mode"})},
        {"additionalProperties", false}
    };
    step.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("step: plugin link is not configured");

        const std::string mode = RequireEnumString(arguments, "mode", {"into", "over", "out"}, "step");

        long long count = 1;
        if (arguments.contains("count"))
        {
            if (!arguments["count"].is_number_integer())
                throw ToolError("step: 'count' must be an integer between 1 and 1000");
            count = arguments["count"].get<long long>();
            if (count < 1 || count > 1000)
                throw ToolError("step: 'count' must be between 1 and 1000");
        }

        nlohmann::json params = {
            {"mode", mode},
            {"count", count},
            {"wait", arguments.value("wait", true)}
        };
        if (arguments.contains("timeout_ms"))
        {
            RequireNonNegativeInteger(arguments, "timeout_ms", "step");
            params["timeout_ms"] = arguments["timeout_ms"].get<long long>();
        }

        ToolResult result;
        result.structuredContent = link->Call("debug.step", params);
        result.text = FormatPauseResult(result.structuredContent);
        return result;
    };
    registry.Add(std::move(step));

    Tool wait;
    wait.name = "wait_until_paused";
    wait.description =
        "Wait for the debugged process to reach a paused state. Use it "
        "after resuming execution without waiting (debug_control or step "
        "with wait=false), or when expecting a breakpoint to be hit as a "
        "result of an action taken in the target program from outside the "
        "debugger (for example, interacting with its UI). If the process "
        "is already paused when this tool is called, it returns "
        "immediately. Returns the same state shape as debug_control: "
        "'paused', 'timed_out' (true if the timeout elapsed while the "
        "process was still running — not an error, just keep waiting or "
        "check back later), 'pause_reason', and 'status'.";
    wait.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"timeout_ms", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Maximum time to wait for the process to pause, in milliseconds. If "
                 "omitted, the plugin's default timeout is used."}
            }}
        }},
        {"additionalProperties", false}
    };
    wait.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("wait_until_paused: plugin link is not configured");

        nlohmann::json params = nlohmann::json::object();
        if (arguments.contains("timeout_ms"))
        {
            RequireNonNegativeInteger(arguments, "timeout_ms", "wait_until_paused");
            params["timeout_ms"] = arguments["timeout_ms"].get<long long>();
        }

        ToolResult result;
        result.structuredContent = link->Call("debug.wait", params);
        result.text = FormatPauseResult(result.structuredContent);
        return result;
    };
    registry.Add(std::move(wait));

    Tool setBreakpoint;
    setBreakpoint.name = "set_breakpoint";
    setBreakpoint.description =
        "Set a breakpoint at an address. Three kinds are available. A "
        "'software' breakpoint (the default) patches the target "
        "instruction's first byte with INT3; it works anywhere executable "
        "but is detectable by code that checksums itself. A 'hardware' "
        "breakpoint uses one of the CPU's four debug registers; it does "
        "not modify memory at all, so it is invisible to code-integrity "
        "checks, but at most four hardware breakpoints can exist at once "
        "across the whole process. A 'memory' breakpoint triggers on "
        "access to a range of memory rather than on executing an "
        "instruction. Use 'condition' to make the breakpoint conditional: "
        "it is an expression in x64dbg's expression syntax, evaluated "
        "every time the breakpoint fires, and execution actually stops "
        "only when it evaluates to a non-zero value — for example "
        "'rcx == 0x10' stops only when RCX holds 0x10, letting the "
        "process run past every other hit. Use 'log' together with "
        "'log_condition' to record data every time the breakpoint fires "
        "WITHOUT stopping the process: 'log' is the text written to the "
        "log (may reference registers and memory), and 'log_condition' is "
        "a separate expression that gates whether logging happens on a "
        "given hit, independent of 'condition'. For a 'hardware' "
        "breakpoint, 'access' must be 'r' (triggers on both reads and "
        "writes), 'w' (writes only), or 'x' (execution only), 'size' must "
        "be 1, 2, 4, or 8 bytes, and 'address' must be aligned to 'size'. "
        "For a 'memory' breakpoint, 'access' must be 'a' (any access), "
        "'r', 'w', or 'x'. 'singleshoot' removes the breakpoint "
        "automatically after it fires once; 'name' attaches a label for "
        "use with manage_breakpoint and list_breakpoints; 'silent' "
        "suppresses the message x64dbg would otherwise print when the "
        "breakpoint hits; 'restore' controls whether the breakpoint's "
        "original memory protection or byte is restored once it has done "
        "its job. Requires an active debugging session. Returns a short "
        "confirmation together with the plugin's breakpoint description.";
    setBreakpoint.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Address to break at, given as a number (not a hex string). For "
                 "'hardware' breakpoints it must be aligned to 'size'."}
            }},
            {"type", {
                {"type", "string"},
                {"enum", nlohmann::json::array({"software", "hardware", "memory"})},
                {"default", "software"},
                {"description",
                 "Kind of breakpoint: 'software' (INT3 patch), 'hardware' (debug "
                 "register, at most four at a time, does not modify memory), or "
                 "'memory' (triggers on memory access)."}
            }},
            {"name", {
                {"type", "string"},
                {"description", "Optional label for the breakpoint, used to identify it in list_breakpoints and other tools."}
            }},
            {"singleshoot", {
                {"type", "boolean"},
                {"default", false},
                {"description", "If true, the breakpoint removes itself automatically the first time it fires."}
            }},
            {"condition", {
                {"type", "string"},
                {"description",
                 "x64dbg expression evaluated on every hit; execution stops only when "
                 "it is non-zero. Example: 'rcx == 0x10'."}
            }},
            {"log", {
                {"type", "string"},
                {"description",
                 "Text logged every time the breakpoint fires, instead of or in "
                 "addition to stopping the process. May reference registers and memory."}
            }},
            {"log_condition", {
                {"type", "string"},
                {"description",
                 "x64dbg expression evaluated on every hit to decide whether to write "
                 "the 'log' text; independent of 'condition'."}
            }},
            {"silent", {
                {"type", "boolean"},
                {"description", "If true, suppresses the message x64dbg would normally print when the breakpoint hits."}
            }},
            {"access", {
                {"type", "string"},
                {"enum", nlohmann::json::array({"r", "w", "x", "a"})},
                {"description",
                 "Access type that triggers the breakpoint. For 'hardware': 'r' (read "
                 "and write), 'w' (write), or 'x' (execute). For 'memory': 'a' (any "
                 "access), 'r', 'w', or 'x'."}
            }},
            {"size", {
                {"type", "integer"},
                {"enum", nlohmann::json::array({1, 2, 4, 8})},
                {"description",
                 "Size in bytes watched by a 'hardware' breakpoint: 1, 2, 4, or 8. "
                 "'address' must be aligned to this size."}
            }},
            {"restore", {
                {"type", "boolean"},
                {"description",
                 "Whether to restore the original memory protection or byte after the "
                 "breakpoint has done its job (relevant to 'memory' and one-shot breakpoints)."}
            }}
        }},
        {"required", nlohmann::json::array({"address"})},
        {"additionalProperties", false}
    };
    setBreakpoint.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("set_breakpoint: plugin link is not configured");

        RequireNonNegativeInteger(arguments, "address", "set_breakpoint");
        const std::uint64_t address = arguments["address"].get<std::uint64_t>();

        std::string type = "software";
        if (arguments.contains("type"))
            type = RequireEnumString(arguments, "type", {"software", "hardware", "memory"}, "set_breakpoint");

        if (type == "hardware")
        {
            if (!arguments.contains("access") || !arguments["access"].is_string() ||
                (arguments["access"] != "r" && arguments["access"] != "w" && arguments["access"] != "x"))
                throw ToolError("set_breakpoint: hardware breakpoints require 'access' to be 'r', 'w', or 'x'");
            if (!arguments.contains("size") || !arguments["size"].is_number_integer())
                throw ToolError("set_breakpoint: hardware breakpoints require 'size' to be 1, 2, 4, or 8");
            const long long size = arguments["size"].get<long long>();
            if (size != 1 && size != 2 && size != 4 && size != 8)
                throw ToolError("set_breakpoint: hardware breakpoints require 'size' to be 1, 2, 4, or 8");
            if (address % static_cast<std::uint64_t>(size) != 0)
                throw ToolError("set_breakpoint: 'address' must be aligned to 'size' for a hardware breakpoint");
        }
        else if (type == "memory")
        {
            if (!arguments.contains("access") || !arguments["access"].is_string() ||
                (arguments["access"] != "a" && arguments["access"] != "r" &&
                 arguments["access"] != "w" && arguments["access"] != "x"))
                throw ToolError("set_breakpoint: memory breakpoints require 'access' to be 'a', 'r', 'w', or 'x'");
        }

        nlohmann::json params = {{"address", address}, {"type", type}};
        for (const char* field : {"name", "condition", "log", "log_condition", "access"})
        {
            if (arguments.contains(field))
                params[field] = arguments[field];
        }
        for (const char* field : {"singleshoot", "silent", "restore"})
        {
            if (arguments.contains(field))
                params[field] = arguments[field];
        }
        if (arguments.contains("size"))
            params["size"] = arguments["size"];

        ToolResult result;
        result.structuredContent = link->Call("breakpoint.set", params);

        std::ostringstream text;
        text << "Breakpoint set at 0x" << std::hex << address << " (" << type << ").";
        result.text = text.str();
        return result;
    };
    registry.Add(std::move(setBreakpoint));

    Tool manageBreakpoint;
    manageBreakpoint.name = "manage_breakpoint";
    manageBreakpoint.description =
        "Delete, enable, or disable an existing breakpoint at the given "
        "address. 'disable' keeps the breakpoint's settings and condition "
        "intact so it can be re-enabled later with the same behavior; "
        "'delete' removes it permanently. Use list_breakpoints first if "
        "the exact address is not known. Requires an active debugging "
        "session and a breakpoint already present at 'address'. Returns a "
        "short confirmation with the address and the action performed.";
    manageBreakpoint.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"action", {
                {"type", "string"},
                {"enum", nlohmann::json::array({"delete", "enable", "disable"})},
                {"description",
                 "'delete' removes the breakpoint permanently; 'enable' / 'disable' "
                 "toggle it while keeping its settings."}
            }},
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description", "Address of the breakpoint to manage, given as a number (not a hex string)."}
            }}
        }},
        {"required", nlohmann::json::array({"action", "address"})},
        {"additionalProperties", false}
    };
    manageBreakpoint.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("manage_breakpoint: plugin link is not configured");

        const std::string action =
            RequireEnumString(arguments, "action", {"delete", "enable", "disable"}, "manage_breakpoint");
        RequireNonNegativeInteger(arguments, "address", "manage_breakpoint");
        const std::uint64_t address = arguments["address"].get<std::uint64_t>();

        ToolResult result;
        result.structuredContent = link->Call("breakpoint.manage", {
            {"action", action},
            {"address", address}
        });

        std::ostringstream text;
        text << "Breakpoint at 0x" << std::hex << address << " "
             << (action == "delete" ? "deleted" : action == "enable" ? "enabled" : "disabled") << ".";
        result.text = text.str();
        return result;
    };
    registry.Add(std::move(manageBreakpoint));

    Tool listBreakpoints;
    listBreakpoints.name = "list_breakpoints";
    listBreakpoints.description =
        "List every breakpoint currently set in the debuggee, along with "
        "its type ('software', 'hardware', or 'memory'), whether it is "
        "enabled, whether it is single-shot, how many times it has fired, "
        "which module it belongs to, and its name. Use it to see what is "
        "already set before adding more breakpoints, to find the address "
        "of a named breakpoint for manage_breakpoint, or to check which "
        "breakpoint was hit after a pause. Takes no parameters.";
    listBreakpoints.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", nlohmann::json::object()},
        {"additionalProperties", false}
    };
    listBreakpoints.handler = [link](const nlohmann::json& /*arguments*/) -> ToolResult
    {
        if (!link)
            throw ToolError("list_breakpoints: plugin link is not configured");

        ToolResult result;
        result.structuredContent = link->Call("breakpoint.list", nlohmann::json::object());

        const nlohmann::json breakpoints = result.structuredContent.value("breakpoints", nlohmann::json::array());
        result.text = FormatBreakpointList(breakpoints);
        return result;
    };
    registry.Add(std::move(listBreakpoints));
}

} // namespace x64dbg_mcp::bridge
