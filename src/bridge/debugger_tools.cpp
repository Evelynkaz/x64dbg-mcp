#include "bridge/debugger_tools.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
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
}

} // namespace x64dbg_mcp::bridge
