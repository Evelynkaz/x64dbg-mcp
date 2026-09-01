#include "bridge/debugger_tools.h"
#include "bridge/x64dbg_commands.inc"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <initializer_list>
#include <limits>
#include <sstream>
#include <vector>

namespace x64dbg_mcp::bridge
{

namespace
{

// The plugin waits this long for a pause/completion when a tool omits
// 'timeout_ms' (mirrors kDefaultControlTimeoutMs in plugin/debugger.h,
// which lives in the plugin's own binary and is not visible from here;
// kept in sync by hand — if the plugin's default ever changes, this
// constant must change with it).
constexpr long long kDefaultOperationTimeoutMs = 10000;

// Extra time given to the transport on top of the operation's own
// timeout. The wait for a pause/completion happens on the plugin side and
// is bounded by the operation's own timeout_ms; the plugin still needs
// time after that to build and send its response back, so the transport
// timeout must outlive it — otherwise the bridge would give up on a
// legitimate long-running operation before the plugin itself does.
constexpr long long kRequestTimeoutMarginMs = 15000;

// A generous fixed request timeout for tools that can run long without
// taking a 'timeout_ms' of their own: code_coverage's 'read' scans a
// range, find_pattern scans up to 256 MiB, execute_command may run an
// arbitrary (possibly slow) command, and run_script runs a script.
constexpr int kSlowToolRequestTimeoutMs = 120000;

// Request timeout for a call whose 'params' may carry a 'timeout_ms' the
// tool is about to forward to the plugin: the operation's own timeout (or
// the plugin's default, if none was given) plus a margin for the plugin
// to answer after that wait ends.
int RequestTimeoutMs(const nlohmann::json& params)
{
    const long long operationTimeoutMs = params.contains("timeout_ms")
        ? params["timeout_ms"].get<long long>()
        : kDefaultOperationTimeoutMs;
    const long long requestTimeoutMs = operationTimeoutMs + kRequestTimeoutMarginMs;
    return requestTimeoutMs > (std::numeric_limits<int>::max)()
        ? (std::numeric_limits<int>::max)()
        : static_cast<int>(requestTimeoutMs);
}

// Parses a hex string (as sent by memory.read) into bytes. Silently stops
// at the first invalid character — we trust the plugin, but it's not worth
// failing over one bad character in a dump.
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

// A familiar memory dump: offset, 16 bytes in hex on the line, then a
// column of printable characters (non-printable ones replaced with a dot).
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

// Disassembler listing: one line per instruction — address, bytes, mnemonic.
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

// Verifies that a field is a string from a given set of allowed values, and
// returns it. The list of allowed values is printed in the error message so
// the model immediately sees what it could have passed.
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

// Human-readable summary of a debug.control/debug.step/debug.wait result:
// whether the process stopped, for what reason, at what address, and in
// what module. If the wait timed out, says outright that the process is
// still running.
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

// Aligned table of breakpoints: address, type, state, hit count, name.
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

// Short readable summary of debugger.status for the model: addresses in
// hex — decimal addresses are useless in reverse engineering.
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

// Aligned table of modules: base, size, entry point, name.
std::string FormatModuleList(const nlohmann::json& modules)
{
    std::ostringstream out;
    out << std::left
        << std::setw(18) << "Base"
        << std::setw(12) << "Size"
        << std::setw(18) << "Entry"
        << "Name" << '\n';

    for (const auto& module : modules)
    {
        const std::uint64_t base = module.value("base", 0ULL);
        const std::uint64_t size = module.value("size", 0ULL);
        const std::uint64_t entry = module.value("entry", 0ULL);
        const std::string name = module.value("name", std::string());

        std::ostringstream baseText, sizeText, entryText;
        baseText << "0x" << std::hex << base;
        sizeText << "0x" << std::hex << size;
        entryText << "0x" << std::hex << entry;

        out << std::left
            << std::setw(18) << baseText.str()
            << std::setw(12) << sizeText.str()
            << std::setw(18) << entryText.str()
            << name << '\n';
    }
    out << modules.size() << " module" << (modules.size() == 1 ? "" : "s") << ".\n";
    return out.str();
}

// Module header, table of its sections, and, if requested, export and
// import tables; if a list is truncated, separately reports the 4096-entry limit.
std::string FormatModuleInfo(const nlohmann::json& result, bool includeExports, bool includeImports)
{
    std::ostringstream out;
    const nlohmann::json module = result.value("module", nlohmann::json::object());
    const std::string name = module.value("name", std::string());
    const std::string path = module.value("path", std::string());

    // Numeric module fields are printed as "unavailable" if absent from the
    // plugin's response, instead of silently defaulting to zero — otherwise
    // a format mismatch between the plugin and the bridge (as happened with
    // flat vs. nested JSON) would again get masked by zeros in the text
    // without anyone noticing.
    auto formatHexField = [&module](const char* field) -> std::string
    {
        if (!module.contains(field) || !module[field].is_number_integer())
            return "unavailable";
        std::ostringstream text;
        text << "0x" << std::hex << module[field].get<std::uint64_t>();
        return text.str();
    };

    out << (name.empty() ? "(unknown module)" : name)
        << "  base=" << formatHexField("base")
        << "  size=" << formatHexField("size")
        << "  entry=" << formatHexField("entry");
    if (!path.empty())
        out << "  " << path;
    out << "\n\n";

    const nlohmann::json sections = result.value("sections", nlohmann::json::array());
    out << "Sections:\n"
        << std::left
        << std::setw(18) << "Address"
        << std::setw(12) << "Size"
        << "Name" << '\n';
    for (const auto& section : sections)
    {
        const std::uint64_t address = section.value("address", 0ULL);
        const std::uint64_t sectionSize = section.value("size", 0ULL);
        const std::string sectionName = section.value("name", std::string());

        std::ostringstream addressText, sizeText;
        addressText << "0x" << std::hex << address;
        sizeText << "0x" << std::hex << sectionSize;

        out << std::left
            << std::setw(18) << addressText.str()
            << std::setw(12) << sizeText.str()
            << sectionName << '\n';
    }

    if (includeExports)
    {
        const nlohmann::json exports = result.value("exports", nlohmann::json::array());
        out << "\nExports:\n"
            << std::left
            << std::setw(8) << "Ordinal"
            << std::setw(18) << "RVA"
            << std::setw(18) << "VA"
            << "Name" << '\n';
        for (const auto& exp : exports)
        {
            const unsigned int ordinal = exp.value("ordinal", 0u);
            const std::uint64_t rva = exp.value("rva", 0ULL);
            const std::uint64_t va = exp.value("va", 0ULL);
            const bool forwarded = exp.value("forwarded", false);
            const std::string exportName = exp.value("name", std::string());
            const std::string forwardName = exp.value("forwardName", std::string());

            std::ostringstream rvaText, vaText;
            rvaText << "0x" << std::hex << rva;
            vaText << "0x" << std::hex << va;

            out << std::left
                << std::setw(8) << ordinal
                << std::setw(18) << rvaText.str()
                << std::setw(18) << vaText.str()
                << (forwarded ? (exportName + " -> " + forwardName) : exportName) << '\n';
        }
        if (result.value("exportsTruncated", false))
            out << "Export list truncated at 4096 entries.\n";
    }

    if (includeImports)
    {
        const nlohmann::json imports = result.value("imports", nlohmann::json::array());
        out << "\nImports:\n"
            << std::left
            << std::setw(18) << "IAT RVA"
            << std::setw(18) << "IAT VA"
            << std::setw(8) << "Ordinal"
            << "Name" << '\n';
        for (const auto& imp : imports)
        {
            const std::uint64_t iatRva = imp.value("iatRva", 0ULL);
            const std::uint64_t iatVa = imp.value("iatVa", 0ULL);
            const unsigned int ordinal = imp.value("ordinal", 0u);
            const std::string importName = imp.value("name", std::string());

            std::ostringstream rvaText, vaText;
            rvaText << "0x" << std::hex << iatRva;
            vaText << "0x" << std::hex << iatVa;

            out << std::left
                << std::setw(18) << rvaText.str()
                << std::setw(18) << vaText.str()
                << std::setw(8) << ordinal
                << importName << '\n';
        }
        if (result.value("importsTruncated", false))
            out << "Import list truncated at 4096 entries.\n";
    }

    return out.str();
}

// Aligned table of memory regions: base, size, state, type, protection,
// info. At the end — the number of regions and the total committed memory size.
std::string FormatMemoryMap(const nlohmann::json& regions)
{
    std::ostringstream out;
    out << std::left
        << std::setw(18) << "Base"
        << std::setw(12) << "Size"
        << std::setw(10) << "State"
        << std::setw(10) << "Type"
        << std::setw(8) << "Protect"
        << "Info" << '\n';

    std::uint64_t committedTotal = 0;
    for (const auto& region : regions)
    {
        const std::uint64_t base = region.value("base", 0ULL);
        const std::uint64_t size = region.value("size", 0ULL);
        const std::string state = region.value("state", std::string());
        const std::string type = region.value("type", std::string());
        const std::string protect = region.value("protect", std::string());
        const std::string info = region.value("info", std::string());

        if (state == "commit")
            committedTotal += size;

        std::ostringstream baseText, sizeText;
        baseText << "0x" << std::hex << base;
        sizeText << "0x" << std::hex << size;

        out << std::left
            << std::setw(18) << baseText.str()
            << std::setw(12) << sizeText.str()
            << std::setw(10) << state
            << std::setw(10) << type
            << std::setw(8) << protect
            << info << '\n';
    }

    out << regions.size() << " region" << (regions.size() == 1 ? "" : "s")
        << ", 0x" << std::hex << committedTotal << " bytes committed.\n";
    return out.str();
}

// Aligned table of threads: id, current address, entry point, priority,
// wait reason, name; the current thread is marked with an asterisk.
std::string FormatThreadList(const nlohmann::json& threads)
{
    std::ostringstream out;
    out << std::left
        << std::setw(3) << ' '
        << std::setw(10) << "ID"
        << std::setw(18) << "CIP"
        << std::setw(18) << "Entry"
        << std::setw(10) << "Priority"
        << std::setw(16) << "Wait reason"
        << "Name" << '\n';

    for (const auto& thread : threads)
    {
        const unsigned int id = thread.value("id", 0u);
        const std::uint64_t cip = thread.value("cip", 0ULL);
        const std::uint64_t entry = thread.value("entry", 0ULL);
        const std::string priority = thread.value("priority", std::string());
        const std::string waitReason = thread.value("waitReason", std::string());
        const std::string name = thread.value("name", std::string());
        const bool current = thread.value("current", false);

        std::ostringstream cipText, entryText;
        cipText << "0x" << std::hex << cip;
        entryText << "0x" << std::hex << entry;

        out << std::left
            << std::setw(3) << (current ? "*" : " ")
            << std::setw(10) << id
            << std::setw(18) << cipText.str()
            << std::setw(18) << entryText.str()
            << std::setw(10) << priority
            << std::setw(16) << waitReason
            << name << '\n';
    }
    return out.str();
}

// Prints a register value in hex regardless of whether it arrived as a
// number (regular registers) or as a string (wide SIMD registers, which
// don't fit into a 64-bit JSON integer).
std::string FormatRegisterValue(const nlohmann::json& value)
{
    if (value.is_number_integer())
    {
        std::ostringstream text;
        text << "0x" << std::hex << value.get<std::uint64_t>();
        return text.str();
    }
    if (value.is_string())
    {
        const std::string text = value.get<std::string>();
        if (text.rfind("0x", 0) == 0 || text.rfind("0X", 0) == 0)
            return text;
        return "0x" + text;
    }
    return "0x0";
}

// A list of registers ({"name","value"}) in several columns, so a group of
// registers fits on the screen as a whole instead of stretching over many lines.
std::string FormatRegisterColumns(const nlohmann::json& registers, int columns)
{
    std::ostringstream out;
    int inRow = 0;
    for (const auto& reg : registers)
    {
        const std::string name = reg.value("name", std::string());
        std::ostringstream cell;
        cell << std::left << std::setw(4) << name << FormatRegisterValue(reg.value("value", nlohmann::json()));

        out << std::left << std::setw(22) << cell.str();
        ++inRow;
        if (inRow == columns)
        {
            out << '\n';
            inRow = 0;
        }
    }
    if (inRow != 0)
        out << '\n';
    return out.str();
}

// Human-readable summary of registers.read: general-purpose registers in
// columns, EFLAGS with a list of set flags, segment registers, debug
// registers (only if at least one is non-zero), and, if requested, SIMD
// registers one per line.
std::string FormatRegisters(const nlohmann::json& result, bool includeSimd)
{
    std::ostringstream out;
    out << "General purpose registers:\n"
        << FormatRegisterColumns(result.value("general", nlohmann::json::array()), 3);

    const std::uint64_t eflags = result.value("eflags", 0ULL);
    const nlohmann::json flags = result.value("flags", nlohmann::json::object());
    std::ostringstream setFlags;
    bool firstFlag = true;
    for (const char* flag : {"CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF"})
    {
        if (flags.value(flag, false))
        {
            if (!firstFlag)
                setFlags << ' ';
            setFlags << flag;
            firstFlag = false;
        }
    }
    out << "\nEFLAGS: 0x" << std::hex << eflags
        << "  [" << (setFlags.str().empty() ? "none set" : setFlags.str()) << "]\n";

    out << "\nSegment registers:\n"
        << FormatRegisterColumns(result.value("segment", nlohmann::json::array()), 6);

    const nlohmann::json debugRegisters = result.value("debug", nlohmann::json::array());
    bool anyDebugRegisterSet = false;
    for (const auto& reg : debugRegisters)
    {
        const nlohmann::json value = reg.value("value", nlohmann::json());
        if ((value.is_number_integer() && value.get<std::uint64_t>() != 0) ||
            (value.is_string() && !value.get<std::string>().empty() &&
             value.get<std::string>().find_first_not_of('0') != std::string::npos))
        {
            anyDebugRegisterSet = true;
            break;
        }
    }
    if (anyDebugRegisterSet)
    {
        out << "\nDebug registers:\n"
            << FormatRegisterColumns(debugRegisters, 4);
    }

    if (includeSimd)
    {
        const nlohmann::json simd = result.value("simd", nlohmann::json::array());
        out << "\nSIMD registers:\n";
        for (const auto& reg : simd)
        {
            const std::string name = reg.value("name", std::string());
            out << std::left << std::setw(8) << name
                << FormatRegisterValue(reg.value("value", nlohmann::json())) << '\n';
        }
    }

    const unsigned long long lastError = result.value("lastError", 0ULL);
    const unsigned long long lastStatus = result.value("lastStatus", 0ULL);
    out << "\nLastError: 0x" << std::hex << lastError
        << "  LastStatus: 0x" << std::hex << lastStatus << '\n';
    return out.str();
}

// Table of call stack frames: frame number, return address on the stack,
// where the call was made from, where it led, and the debugger's comment.
std::string FormatCallStack(const nlohmann::json& frames)
{
    std::ostringstream out;
    out << std::left
        << std::setw(6) << "Frame"
        << std::setw(18) << "Address"
        << std::setw(18) << "From"
        << std::setw(18) << "To"
        << "Comment" << '\n';

    std::size_t index = 0;
    for (const auto& frame : frames)
    {
        const std::uint64_t address = frame.value("address", 0ULL);
        const std::uint64_t from = frame.value("from", 0ULL);
        const std::uint64_t to = frame.value("to", 0ULL);
        const std::string comment = frame.value("comment", std::string());

        std::ostringstream addressText, fromText, toText;
        addressText << "0x" << std::hex << address;
        fromText << "0x" << std::hex << from;
        toText << "0x" << std::hex << to;

        out << std::left
            << std::setw(6) << index
            << std::setw(18) << addressText.str()
            << std::setw(18) << fromText.str()
            << std::setw(18) << toText.str()
            << comment << '\n';
        ++index;
    }
    if (frames.empty())
        out << "(empty call stack)\n";
    return out.str();
}

// Table of words at the top of the stack: slot address, value, the
// debugger's comment on that value (e.g. if it is a return address).
std::string FormatStackSlots(const nlohmann::json& slots)
{
    std::ostringstream out;
    out << std::left
        << std::setw(18) << "Address"
        << std::setw(18) << "Value"
        << "Comment" << '\n';

    for (const auto& slot : slots)
    {
        const std::uint64_t address = slot.value("address", 0ULL);
        const std::uint64_t value = slot.value("value", 0ULL);
        const std::string comment = slot.value("comment", std::string());

        std::ostringstream addressText, valueText;
        addressText << "0x" << std::hex << address;
        valueText << "0x" << std::hex << value;

        out << std::left
            << std::setw(18) << addressText.str()
            << std::setw(18) << valueText.str()
            << comment << '\n';
    }
    return out.str();
}

// Human-readable summary of string.read: the address and the string itself.
std::string FormatReadString(const nlohmann::json& result)
{
    const std::uint64_t address = result.value("address", 0ULL);
    const std::string text = result.value("string", std::string());

    std::ostringstream out;
    out << "0x" << std::hex << address << ": " << text;
    return out.str();
}

// Human-readable summary of expression.eval: the expression, its value in
// hex and decimal, and whether it points to readable memory.
std::string FormatEvaluateExpression(const nlohmann::json& result)
{
    const std::string expression = result.value("expression", std::string());
    const std::uint64_t value = result.value("value", 0ULL);
    const bool pointerValid = result.value("pointerValid", false);

    std::ostringstream out;
    out << expression << " = 0x" << std::hex << value << std::dec << " (" << value << ")"
        << (pointerValid ? "  [points to readable memory]" : "  [not a readable pointer]");
    return out.str();
}

// Human-readable summary of pattern.find: a list of found addresses, one
// per line, and the total number of matches; if the result was truncated
// at the limit, a separate line about it.
std::string FormatPatternMatches(const nlohmann::json& result)
{
    const nlohmann::json matches = result.value("matches", nlohmann::json::array());

    std::ostringstream out;
    for (const auto& match : matches)
        out << "0x" << std::hex << match.get<std::uint64_t>() << '\n';
    out << std::dec << matches.size() << " match" << (matches.size() == 1 ? "" : "es") << ".\n";
    if (result.value("truncated", false))
        out << "Result truncated at the requested limit; more matches may exist.\n";
    return out.str();
}

// "Address, reference kind" table for xrefs.get; if there are no
// references, says so directly and mentions the debugger analysis limitation.
std::string FormatXrefs(const nlohmann::json& result)
{
    const std::uint64_t address = result.value("address", 0ULL);
    const nlohmann::json xrefs = result.value("xrefs", nlohmann::json::array());

    std::ostringstream out;
    if (xrefs.empty())
    {
        out << "No references found to 0x" << std::hex << address
            << ". Cross-references come from xref analysis already performed by "
               "the debugger, so an unanalyzed module may report none even "
               "though references exist in the code; running the 'analxrefs' "
               "command with the execute_command tool first may help — note "
               "that 'analyse' alone does not build cross-references.\n";
        return out.str();
    }

    out << std::left
        << std::setw(18) << "Address"
        << "Type" << '\n';
    for (const auto& xref : xrefs)
    {
        const std::uint64_t xrefAddress = xref.value("address", 0ULL);
        const std::string type = xref.value("type", std::string());

        std::ostringstream addressText;
        addressText << "0x" << std::hex << xrefAddress;

        out << std::left
            << std::setw(18) << addressText.str()
            << type << '\n';
    }
    return out.str();
}

// A header with the function's bounds and size, then a listing like a
// regular disassembly; if the function was truncated at the instruction
// limit, a line about it.
std::string FormatDisassembleFunction(const nlohmann::json& result)
{
    const std::uint64_t start = result.value("start", 0ULL);
    const std::uint64_t end = result.value("end", 0ULL);
    const nlohmann::json instructions = result.value("instructions", nlohmann::json::array());

    std::ostringstream out;
    out << "Function 0x" << std::hex << start << " - 0x" << end
        << " (0x" << (end - start) << " bytes), " << std::dec << instructions.size()
        << " instruction" << (instructions.size() == 1 ? "" : "s") << ".\n\n"
        << FormatDisasmListing(instructions);
    if (result.value("truncated", false))
        out << "Instruction listing truncated at the tool's limit.\n";
    return out.str();
}

// Human-readable summary of command.exec: whether the command was
// accepted, a note if log capture is inactive, then its output verbatim.
std::string FormatCommandResult(const nlohmann::json& result)
{
    std::ostringstream out;
    out << (result.value("accepted", false) ? "Command accepted." : "Command rejected by the debugger.") << '\n';
    if (!result.value("logCaptured", false))
        out << "Log capture is inactive; the command still ran, but its output could not be captured.\n";
    out << result.value("output", std::string());
    return out.str();
}

// Human-readable summary of script.run: confirms the script started, then
// whatever output the log held at that moment.
std::string FormatScriptResult(const nlohmann::json& result)
{
    std::ostringstream out;
    out << "Script started.\n" << result.value("output", std::string());
    return out.str();
}

// The requested tail of the x64dbg log, followed by a line count and, if
// the result was truncated at the requested limit, a note about it.
std::string FormatLogLines(const nlohmann::json& result)
{
    const nlohmann::json lines = result.value("lines", nlohmann::json::array());

    std::ostringstream out;
    for (const auto& line : lines)
        out << line.get<std::string>() << '\n';
    out << lines.size() << " line" << (lines.size() == 1 ? "" : "s") << ".\n";
    if (result.value("truncated", false))
        out << "Log truncated; more lines exist beyond the requested limit.\n";
    return out.str();
}

// Human-readable summary of memory.write: how many bytes were written,
// where, and whether the write was recorded as an undoable patch.
std::string FormatWriteMemoryResult(const nlohmann::json& result)
{
    const std::uint64_t address = result.value("address", 0ULL);
    const std::uint64_t size = result.value("size", 0ULL);
    const bool recordedAsPatch = result.value("recordedAsPatch", false);

    std::ostringstream out;
    out << "Wrote " << std::dec << size << " byte" << (size == 1 ? "" : "s")
        << " at 0x" << std::hex << address << ". "
        << (recordedAsPatch ? "Recorded as a patch." : "Not recorded as a patch.");
    return out.str();
}

// Human-readable summary of register.set: the register name and its new
// value in hex and decimal.
std::string FormatSetRegisterResult(const nlohmann::json& result)
{
    const std::string name = result.value("name", std::string());
    const std::uint64_t value = result.value("value", 0ULL);

    std::ostringstream out;
    out << name << " = 0x" << std::hex << value << std::dec << " (" << value << ")";
    return out.str();
}

// Human-readable summary of assemble: the address, the instruction as
// given, and the resulting size in bytes.
std::string FormatAssembleResult(const nlohmann::json& result, const std::string& instruction)
{
    const std::uint64_t address = result.value("address", 0ULL);
    const std::uint64_t size = result.value("size", 0ULL);

    std::ostringstream out;
    out << "Assembled '" << instruction << "' at 0x" << std::hex << address << std::dec
        << " (" << size << " byte" << (size == 1 ? "" : "s") << ").";
    return out.str();
}

// Table of recorded patches: address, original byte, current byte,
// module; says plainly if there are none, rather than showing an empty table.
std::string FormatPatchesList(const nlohmann::json& patches)
{
    if (patches.empty())
        return "No patches are currently recorded.\n";

    std::ostringstream out;
    out << std::left
        << std::setw(18) << "Address"
        << std::setw(8) << "Old"
        << std::setw(8) << "New"
        << "Module" << '\n';

    for (const auto& patch : patches)
    {
        const std::uint64_t address = patch.value("address", 0ULL);
        const unsigned int oldByte = patch.value("oldByte", 0u);
        const unsigned int newByte = patch.value("newByte", 0u);
        const std::string module = patch.value("module", std::string());

        std::ostringstream addressText, oldText, newText;
        addressText << "0x" << std::hex << address;
        oldText << "0x" << std::hex << std::setw(2) << std::setfill('0') << oldByte;
        newText << "0x" << std::hex << std::setw(2) << std::setfill('0') << newByte;

        out << std::left
            << std::setw(18) << addressText.str()
            << std::setw(8) << oldText.str()
            << std::setw(8) << newText.str()
            << module << '\n';
    }
    out << patches.size() << " patch" << (patches.size() == 1 ? "" : "es") << ".\n";
    return out.str();
}

// Human-readable summary of patches.restore: how many patches were restored.
std::string FormatPatchesRestore(const nlohmann::json& result)
{
    const long long restored = result.value("restored", 0LL);

    std::ostringstream out;
    out << restored << " patch" << (restored == 1 ? "" : "es") << " restored.";
    return out.str();
}

// Human-readable summary of patches.apply_to_file: how many patches were
// written, and to which file. Does not change the running process.
std::string FormatPatchesApplyToFile(const nlohmann::json& result)
{
    const long long patched = result.value("patched", 0LL);
    const std::string path = result.value("path", std::string());

    std::ostringstream out;
    out << patched << " patch" << (patched == 1 ? "" : "es") << " written to " << path << ".";
    return out.str();
}

// Human-readable summary of memory.set_rights: the address and the
// rights that were applied.
std::string FormatSetPageRightsResult(const nlohmann::json& result)
{
    const std::uint64_t address = result.value("address", 0ULL);
    const std::string rights = result.value("rights", std::string());

    std::ostringstream out;
    out << "Set rights of 0x" << std::hex << address << std::dec << " to '" << rights << "'.";
    return out.str();
}

// Human-readable summary of trace.record: confirms that recording either
// started (with the destination path) or stopped. Recording itself does
// not execute anything, so there is nothing else to report here.
std::string FormatTraceRecordResult(const std::string& action, const std::string& path)
{
    std::ostringstream out;
    if (action == "start")
        out << "Trace recording started, writing to " << path << ".";
    else
        out << "Trace recording stopped.";
    return out.str();
}

// Human-readable summary of coverage.enable / coverage.disable: confirms
// the address and, for 'enable', the granularity that was applied.
// Coverage is tracked per memory page, so this always covers the whole
// page containing the given address.
std::string FormatCoverageToggleResult(const std::string& action, std::uint64_t address,
                                        const std::string& granularity)
{
    std::ostringstream out;
    if (action == "enable")
        out << "Coverage enabled for the page containing 0x" << std::hex << address
            << " (granularity: '" << granularity << "').";
    else
        out << "Coverage disabled for the page containing 0x" << std::hex << address << ".";
    return out.str();
}

// Table of coverage.read entries — address, hit count, byte type — sorted
// by hit count descending, so the busiest address (typically a virtual
// machine's dispatcher) is first. Followed by a count line and, if the
// result was truncated, a line about it. Sorting is for the text only;
// the structured entries are passed through in the order the plugin sent them.
std::string FormatCoverageRead(const nlohmann::json& result)
{
    const nlohmann::json entries = result.value("entries", nlohmann::json::array());
    std::vector<nlohmann::json> sorted(entries.begin(), entries.end());
    std::sort(sorted.begin(), sorted.end(), [](const nlohmann::json& a, const nlohmann::json& b)
    {
        return a.value("hitCount", 0ULL) > b.value("hitCount", 0ULL);
    });

    std::ostringstream out;
    out << std::left
        << std::setw(18) << "Address"
        << std::setw(10) << "Hits"
        << "Type" << '\n';
    for (const auto& entry : sorted)
    {
        const std::uint64_t address = entry.value("address", 0ULL);
        const unsigned long long hitCount = entry.value("hitCount", 0ULL);
        const std::string byteType = entry.value("byteType", std::string());

        std::ostringstream addressText;
        addressText << "0x" << std::hex << address;

        out << std::left
            << std::setw(18) << addressText.str()
            << std::setw(10) << hitCount
            << byteType << '\n';
    }
    out << std::dec << sorted.size() << " entr" << (sorted.size() == 1 ? "y" : "ies") << ".\n";
    if (result.value("truncated", false))
        out << "Result truncated; more coverage entries may exist.\n";
    return out.str();
}

// Aligned table of symbols: address, type, name — in the order the plugin
// returned them (imports and exports are not re-sorted). Followed by a
// count line and, if the result was truncated at the requested limit, a
// line about it.
std::string FormatSymbolList(const nlohmann::json& symbols, bool truncated)
{
    std::ostringstream out;
    out << std::left
        << std::setw(18) << "Address"
        << std::setw(10) << "Type"
        << "Name" << '\n';

    for (const auto& symbol : symbols)
    {
        const std::uint64_t address = symbol.value("address", 0ULL);
        const std::string type = symbol.value("type", std::string());
        const std::string name = symbol.value("name", std::string());

        std::ostringstream addressText;
        addressText << "0x" << std::hex << address;

        out << std::left
            << std::setw(18) << addressText.str()
            << std::setw(10) << type
            << name << '\n';
    }
    out << std::dec << symbols.size() << " symbol" << (symbols.size() == 1 ? "" : "s") << ".\n";
    if (truncated)
        out << "Result truncated at the requested limit; more symbols may exist.\n";
    return out.str();
}

// Human-readable summary of annotations.get: the address and each
// annotation present at it (label, comment, bookmark); says plainly when
// there are none.
std::string FormatAnnotationsGet(const nlohmann::json& result)
{
    const std::uint64_t address = result.value("address", 0ULL);
    const std::string label = result.value("label", std::string());
    const std::string comment = result.value("comment", std::string());
    const bool bookmark = result.value("bookmark", false);

    std::ostringstream out;
    out << "0x" << std::hex << address << ":\n";
    if (label.empty() && comment.empty() && !bookmark)
    {
        out << "No annotations at this address.\n";
        return out.str();
    }
    if (!label.empty())
        out << "  Label: " << label << '\n';
    if (!comment.empty())
        out << "  Comment: " << comment << '\n';
    if (bookmark)
        out << "  Bookmark: set\n";
    return out.str();
}

// Human-readable confirmation of annotations.set: exactly what was applied
// at the address, distinguishing a value that was set from one that was
// cleared (an empty label/comment, or a bookmark passed as false).
std::string FormatAnnotationsSet(std::uint64_t address, bool hasLabel, const std::string& label,
                                  bool hasComment, const std::string& comment,
                                  bool hasBookmark, bool bookmark)
{
    std::ostringstream out;
    out << "Applied at 0x" << std::hex << address << ":\n";
    if (hasLabel)
        out << "  Label " << (label.empty() ? "cleared." : ("set to '" + label + "'.")) << '\n';
    if (hasComment)
        out << "  Comment " << (comment.empty() ? "cleared." : ("set to '" + comment + "'.")) << '\n';
    if (hasBookmark)
        out << "  Bookmark " << (bookmark ? "set." : "cleared.") << '\n';
    return out.str();
}

// Truncates a string to at most maxLen bytes for display in a fixed-width
// table column, appending '...' if it was cut; the structured result keeps
// the string in full regardless of what the table shows.
//
// maxLen is a byte budget (it drives the width of fixed-width table
// columns), but a plain byte-wise cut can land in the middle of a
// multi-byte UTF-8 character — e.g. a CJK character is 3 bytes, so cutting
// at an arbitrary offset splits it and produces invalid UTF-8. That invalid
// text then reaches nlohmann::json::dump() in mcp_server.cpp, which throws
// on invalid UTF-8 by default; the throw used to be swallowed by the
// outermost catch and turned list_windows on a window with a non-ASCII
// title into a bare "Internal error" for the whole call. So after picking
// the byte budget, back up over trailing UTF-8 continuation bytes
// (10xxxxxx) to land the cut on a character boundary.
std::string TruncateForTable(const std::string& text, std::size_t maxLen)
{
    if (text.size() <= maxLen)
        return text;

    auto backUpToCharBoundary = [&text](std::size_t pos) {
        while (pos > 0 && (static_cast<unsigned char>(text[pos]) & 0xC0) == 0x80)
            --pos;
        return pos;
    };

    if (maxLen <= 3)
        return text.substr(0, backUpToCharBoundary(maxLen));
    return text.substr(0, backUpToCharBoundary(maxLen - 3)) + "...";
}

// Aligned table of open handles: handle value, type, name. Followed by a
// count line and, if the plugin reported truncation, a line about it. An
// empty name is normal — many kernel objects (anonymous events, unnamed
// sections and mutexes) simply have no name, and this is not a failure to
// resolve it.
std::string FormatHandleList(const nlohmann::json& handles, bool truncated)
{
    std::ostringstream out;
    out << std::left
        << std::setw(18) << "Handle"
        << std::setw(16) << "Type"
        << "Name" << '\n';

    for (const auto& handle : handles)
    {
        const std::uint64_t value = handle.value("handle", 0ULL);
        const std::string typeName = handle.value("typeName", std::string());
        const std::string name = handle.value("name", std::string());

        std::ostringstream handleText;
        handleText << "0x" << std::hex << value;

        out << std::left
            << std::setw(18) << handleText.str()
            << std::setw(16) << (typeName.empty() ? "(unknown)" : typeName)
            << (name.empty() ? "(unnamed)" : name) << '\n';
    }
    out << handles.size() << " handle" << (handles.size() == 1 ? "" : "s") << ".\n";
    if (truncated)
        out << "Handle list truncated at the tool's limit.\n";
    return out.str();
}

// Aligned table of windows: handle, title, class, window procedure address,
// owning thread. Title and class are truncated to a sensible width for the
// table only; the structured result keeps them in full. Followed by a
// count line and, if the plugin reported truncation, a line about it.
std::string FormatWindowList(const nlohmann::json& windows, bool truncated)
{
    std::ostringstream out;
    out << std::left
        << std::setw(18) << "Handle"
        << std::setw(30) << "Title"
        << std::setw(20) << "Class"
        << std::setw(18) << "WndProc"
        << "Thread" << '\n';

    for (const auto& window : windows)
    {
        const std::uint64_t handle = window.value("handle", 0ULL);
        const std::uint64_t wndProc = window.value("wndProc", 0ULL);
        const unsigned int threadId = window.value("threadId", 0u);
        const std::string title = window.value("title", std::string());
        const std::string className = window.value("className", std::string());

        std::ostringstream handleText, wndProcText;
        handleText << "0x" << std::hex << handle;
        wndProcText << "0x" << std::hex << wndProc;

        out << std::left
            << std::setw(18) << handleText.str()
            << std::setw(30) << TruncateForTable(title, 28)
            << std::setw(20) << TruncateForTable(className, 18)
            << std::setw(18) << wndProcText.str()
            << threadId << '\n';
    }
    out << windows.size() << " window" << (windows.size() == 1 ? "" : "s") << ".\n";
    if (truncated)
        out << "Window list truncated at the tool's limit.\n";
    return out.str();
}

// Aligned table of TCP connections: local address:port, remote
// address:port, state. Followed by a count line and, if the plugin
// reported truncation, a line about it.
std::string FormatConnectionList(const nlohmann::json& connections, bool truncated)
{
    std::ostringstream out;
    out << std::left
        << std::setw(24) << "Local"
        << std::setw(24) << "Remote"
        << "State" << '\n';

    for (const auto& connection : connections)
    {
        const std::string localAddress = connection.value("localAddress", std::string());
        const unsigned int localPort = connection.value("localPort", 0u);
        const std::string remoteAddress = connection.value("remoteAddress", std::string());
        const unsigned int remotePort = connection.value("remotePort", 0u);
        const std::string state = connection.value("state", std::string());

        std::ostringstream localText, remoteText;
        localText << localAddress << ":" << localPort;
        remoteText << remoteAddress << ":" << remotePort;

        out << std::left
            << std::setw(24) << localText.str()
            << std::setw(24) << remoteText.str()
            << state << '\n';
    }
    out << connections.size() << " connection" << (connections.size() == 1 ? "" : "s") << ".\n";
    if (truncated)
        out << "Connection list truncated at the tool's limit.\n";
    return out.str();
}

// Table of SEH chain entries for the current thread: index, exception
// registration record address, handler address. If the chain is empty,
// says so and notes that 64-bit Windows uses table-based exception
// handling instead of the classic FS:[0] linked list this walks, so an
// empty chain there is expected rather than a sign the process has no
// exception handlers — and, on top of that, x64dbg's own 64-bit build
// does not even implement a stack-walked chain (ExHandlerGetSEH in
// external/x64dbg/src/dbg/exhandlerinfo.cpp is `return false;` under
// `#ifdef _WIN64`), so this tool always returns empty on x64 regardless
// of the target.
std::string FormatSehChain(const nlohmann::json& entries)
{
    std::ostringstream out;
    if (entries.empty())
    {
        out << "No SEH chain entries on the current thread. 64-bit Windows "
               "uses table-based exception handling instead of the classic "
               "FS:[0] linked list, so an empty chain there is expected and "
               "does not mean the process has no exception handlers; this "
               "result is mainly meaningful for 32-bit targets. On top of "
               "that, x64dbg's own 64-bit build does not implement a "
               "stack-walked SEH chain at all, so this tool ALWAYS returns "
               "empty on a 64-bit x64dbg, regardless of what the target "
               "actually has installed — do not read this emptiness as "
               "evidence about the program.\n";
        return out.str();
    }

    out << std::left
        << std::setw(6) << "Index"
        << std::setw(18) << "Record"
        << "Handler" << '\n';

    std::size_t index = 0;
    for (const auto& entry : entries)
    {
        const std::uint64_t address = entry.value("address", 0ULL);
        const std::uint64_t handler = entry.value("handler", 0ULL);

        std::ostringstream addressText, handlerText;
        addressText << "0x" << std::hex << address;
        handlerText << "0x" << std::hex << handler;

        out << std::left
            << std::setw(6) << index
            << std::setw(18) << addressText.str()
            << handlerText.str() << '\n';
        ++index;
    }
    return out.str();
}

// Aligned table of running processes: PID, executable file name, window
// title, command line. Title and command line are truncated for the table
// only, using TruncateForTable so a multi-byte character is never split;
// the structured result keeps both strings in full. Followed by a count
// line and, if the plugin reported truncation, a line about it.
std::string FormatProcessList(const nlohmann::json& processes, bool truncated)
{
    std::ostringstream out;
    out << std::left
        << std::setw(8) << "PID"
        << std::setw(24) << "Executable"
        << std::setw(30) << "Title"
        << "Command line" << '\n';

    for (const auto& process : processes)
    {
        const unsigned int pid = process.value("pid", 0u);
        const std::string exeFile = process.value("exeFile", std::string());
        const std::string title = process.value("mainWindowTitle", std::string());
        const std::string commandLine = process.value("commandLine", std::string());

        out << std::left
            << std::setw(8) << pid
            << std::setw(24) << exeFile
            << std::setw(30) << TruncateForTable(title, 28)
            << TruncateForTable(commandLine, 80) << '\n';
    }
    out << processes.size() << " process" << (processes.size() == 1 ? "" : "es") << ".\n";
    if (truncated)
        out << "Process list truncated at the tool's limit.\n";
    return out.str();
}

// Human-readable confirmation of debug.detach: the debuggee is left running.
std::string FormatDetachResult()
{
    return "Detached from the debuggee. Its breakpoints were removed; the process keeps running.";
}

// Human-readable summary of memory.allocate: the resulting address and size in hex.
std::string FormatAllocateMemoryResult(const nlohmann::json& result)
{
    const std::uint64_t address = result.value("address", 0ULL);
    const std::uint64_t size = result.value("size", 0ULL);

    std::ostringstream out;
    out << "Allocated 0x" << std::hex << size << " bytes at 0x" << address << ".";
    return out.str();
}

// Human-readable confirmation of memory.free: the address that was freed.
std::string FormatFreeMemoryResult(std::uint64_t address)
{
    std::ostringstream out;
    out << "Freed memory at 0x" << std::hex << address << ".";
    return out.str();
}

// Human-readable summary of memory.dump: the address range, its size, and
// the file it was written to.
std::string FormatDumpMemoryResult(const nlohmann::json& result, std::uint64_t address)
{
    const std::uint64_t size = result.value("size", 0ULL);
    const std::string path = result.value("path", std::string());

    std::ostringstream out;
    out << "Dumped 0x" << std::hex << size << " bytes (0x" << address << " - 0x" << (address + size)
        << ") to " << path << ".";
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
        "session entirely, TERMINATING the process — including one this "
        "tool only attached to and did not start; if the process should "
        "keep running instead, use detach_process. 'restart' terminates "
        "the current instance of the debuggee and launches the same "
        "executable again from its entry point. 'run_to' sets a "
        "temporary one-shot breakpoint at 'address' and resumes execution "
        "until that breakpoint is hit (or the process stops for any "
        "other reason); use it to skip over known, uninteresting code "
        "instead of single-stepping through it. "
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
        result.structuredContent = link->Call("debug.control", params, RequestTimeoutMs(params));
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
        result.structuredContent = link->Call("debug.step", params, RequestTimeoutMs(params));
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
        result.structuredContent = link->Call("debug.wait", params, RequestTimeoutMs(params));
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

    Tool listModules;
    listModules.name = "list_modules";
    listModules.description =
        "List the modules loaded into the debugged process, each with its "
        "base address, size, entry point, section count, and full path. "
        "Call this tool EARLY in a reverse-engineering session to see what "
        "the process is made of and to find the base address of a library "
        "of interest: addresses reported by other tools (disassemble, "
        "read_memory, breakpoints, call stacks) are matched against the "
        "modules returned here to tell which module they belong to. "
        "Returns every loaded module, including system libraries such as "
        "ntdll.dll and kernel32.dll. Requires an active debugging session. "
        "Takes no parameters.";
    listModules.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", nlohmann::json::object()},
        {"additionalProperties", false}
    };
    listModules.handler = [link](const nlohmann::json& /*arguments*/) -> ToolResult
    {
        if (!link)
            throw ToolError("list_modules: plugin link is not configured");

        ToolResult result;
        result.structuredContent = link->Call("modules.list", nlohmann::json::object());
        const nlohmann::json modules = result.structuredContent.value("modules", nlohmann::json::array());
        result.text = FormatModuleList(modules);
        return result;
    };
    registry.Add(std::move(listModules));

    Tool moduleInfo;
    moduleInfo.name = "module_info";
    moduleInfo.description =
        "Report details about a single module: its sections with their "
        "addresses and sizes, and, on request, its export and import "
        "tables. Identify the module either by 'name' (its file name, e.g. "
        "'ntdll.dll') or by 'address' (any address that falls inside it); "
        "exactly one of the two must be given. Use this tool to find the "
        "address of an exported function, to see the section layout before "
        "a signature scan, or to see which system functions a module "
        "imports. Exports and imports are NOT included by default, because "
        "system libraries can have thousands of each; set "
        "'include_exports' and/or 'include_imports' to true only when "
        "those tables are actually needed. Each of the export and import "
        "lists is truncated at 4096 entries; when that happens the "
        "corresponding 'exportsTruncated' or 'importsTruncated' field in "
        "the result is true and the human-readable output says so "
        "explicitly. Requires an active debugging session; fails if no "
        "module matches 'name' or 'address'.";
    moduleInfo.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"name", {
                {"type", "string"},
                {"description",
                 "File name of the module to inspect, e.g. 'ntdll.dll'. Accepted "
                 "either with or without the file extension: the name reported by "
                 "debugger_status has no extension (e.g. 'crackme'), while the name "
                 "reported by list_modules has one (e.g. 'crackme.exe'); either form "
                 "works here. Mutually exclusive with 'address'."}
            }},
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Any address inside the module, given as a number (not a hex "
                 "string). Mutually exclusive with 'name'."}
            }},
            {"include_exports", {
                {"type", "boolean"},
                {"default", false},
                {"description", "Include the module's export table. Defaults to false; system libraries can export thousands of symbols."}
            }},
            {"include_imports", {
                {"type", "boolean"},
                {"default", false},
                {"description", "Include the module's import table. Defaults to false; system libraries can import thousands of symbols."}
            }}
        }},
        {"anyOf", nlohmann::json::array({
            { {"required", nlohmann::json::array({"name"})} },
            { {"required", nlohmann::json::array({"address"})} }
        })},
        {"additionalProperties", false}
    };
    moduleInfo.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("module_info: plugin link is not configured");

        if (!arguments.contains("name") && !arguments.contains("address"))
            throw ToolError("module_info: either 'name' or 'address' must be provided");

        nlohmann::json params = nlohmann::json::object();
        if (arguments.contains("name"))
        {
            if (!arguments["name"].is_string())
                throw ToolError("module_info: 'name' must be a string");
            params["name"] = arguments["name"].get<std::string>();
        }
        if (arguments.contains("address"))
        {
            RequireNonNegativeInteger(arguments, "address", "module_info");
            params["address"] = arguments["address"].get<std::uint64_t>();
        }
        const bool includeExports = arguments.value("include_exports", false);
        const bool includeImports = arguments.value("include_imports", false);
        params["include_exports"] = includeExports;
        params["include_imports"] = includeImports;

        ToolResult result;
        result.structuredContent = link->Call("module.info", params);
        result.text = FormatModuleInfo(result.structuredContent, includeExports, includeImports);
        return result;
    };
    registry.Add(std::move(moduleInfo));

    Tool memoryMap;
    memoryMap.name = "memory_map";
    memoryMap.description =
        "Report the memory map of the debugged process: every region with "
        "its base address, size, state, type, and access protection. Use "
        "it to find regions suitable for a signature scan, to spot "
        "unpacked or dynamically generated code, or to find out why a "
        "given address is not readable or writable. State 'commit' means "
        "the range is allocated and backed by physical storage; 'reserve' "
        "means the address range is reserved but has no physical memory "
        "behind it yet; 'free' means the range is available for future "
        "allocation. Type 'image' is memory belonging to a loaded module "
        "image, 'mapped' is a memory-mapped file, and 'private' is "
        "ordinary allocated memory not backed by any file. Private, "
        "committed, and executable memory that is NOT part of any module "
        "is a strong sign of unpacked or dynamically generated code — look "
        "there first when the code of interest is not found in a loaded "
        "module. Note: the 'info' field of each region is a free-text "
        "description produced by x64dbg itself and follows the language of "
        "its UI (for example, a Russian-language x64dbg build reports "
        "Russian text there); do not rely on its exact wording when parsing "
        "results. Requires an active debugging session. Takes no parameters.";
    memoryMap.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", nlohmann::json::object()},
        {"additionalProperties", false}
    };
    memoryMap.handler = [link](const nlohmann::json& /*arguments*/) -> ToolResult
    {
        if (!link)
            throw ToolError("memory_map: plugin link is not configured");

        ToolResult result;
        result.structuredContent = link->Call("memory.map", nlohmann::json::object());
        const nlohmann::json regions = result.structuredContent.value("regions", nlohmann::json::array());
        result.text = FormatMemoryMap(regions);
        return result;
    };
    registry.Add(std::move(memoryMap));

    Tool listThreads;
    listThreads.name = "list_threads";
    listThreads.description =
        "List the threads of the debugged process, each with its "
        "identifier, entry point, current instruction pointer, suspend "
        "count, last error code, priority, and wait reason. The 'current' "
        "field marks the thread whose context other tools (debugger_status, "
        "read_memory, disassemble at the instruction pointer, step) "
        "currently operate on. Use this tool when analyzing multi-threaded "
        "programs and whenever it matters which thread is doing what, for "
        "example to find a worker thread stuck waiting on a handle, or to "
        "tell threads created by the target apart from threads injected by "
        "protection code. Note: the 'name' field is a free-text description "
        "produced by x64dbg itself and follows the language of its UI (for "
        "example, a Russian-language x64dbg build reports Russian text "
        "there); do not rely on its exact wording when parsing results. "
        "Requires an active debugging session. Takes no parameters.";
    listThreads.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", nlohmann::json::object()},
        {"additionalProperties", false}
    };
    listThreads.handler = [link](const nlohmann::json& /*arguments*/) -> ToolResult
    {
        if (!link)
            throw ToolError("list_threads: plugin link is not configured");

        ToolResult result;
        result.structuredContent = link->Call("threads.list", nlohmann::json::object());
        const nlohmann::json threads = result.structuredContent.value("threads", nlohmann::json::array());
        result.text = FormatThreadList(threads);
        return result;
    };
    registry.Add(std::move(listThreads));

    Tool readRegisters;
    readRegisters.name = "read_registers";
    readRegisters.description =
        "Read the CPU registers of the paused debuggee: general-purpose "
        "registers, the instruction and stack pointers, segment registers, "
        "debug registers, the EFLAGS register with its individual flags "
        "already decoded, and the last-error code. Call this tool after "
        "every pause to understand the current state, to read a function's "
        "arguments as delivered by the calling convention (in registers "
        "for x64, or after locating the stack frame for x86), or to check "
        "the outcome of a comparison right before a conditional jump. The "
        "decoded flags matter for predicting where a conditional jump "
        "goes: ZF is set when the result of the previous operation was "
        "zero (drives JZ/JE and JNZ/JNE), CF is set on an unsigned carry "
        "or borrow (drives JB/JC and JAE/JNC), SF mirrors the sign bit of "
        "the result (drives JS/JNS), and OF is set on signed overflow "
        "(drives JO/JNO and, together with SF, the signed comparisons "
        "JL/JGE/JG/JLE). Requires an active debugging session with the "
        "process paused; the registers reported belong to the current "
        "thread. SIMD registers (XMM/YMM) are NOT included by default "
        "because they take up a lot of space; set 'include_simd' to true "
        "only when they are actually needed.";
    readRegisters.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"include_simd", {
                {"type", "boolean"},
                {"default", false},
                {"description", "Include SIMD (XMM/YMM) registers. Defaults to false; they take up a lot of space."}
            }}
        }},
        {"additionalProperties", false}
    };
    readRegisters.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("read_registers: plugin link is not configured");

        const bool includeSimd = arguments.value("include_simd", false);

        ToolResult result;
        result.structuredContent = link->Call("registers.read", {
            {"include_simd", includeSimd}
        });
        result.text = FormatRegisters(result.structuredContent, includeSimd);
        return result;
    };
    registry.Add(std::move(readRegisters));

    Tool callStack;
    callStack.name = "call_stack";
    callStack.description =
        "Reconstruct the chain of calls that led to the current point of "
        "execution: for each frame, the address of the stack slot holding "
        "the return address, where the call was made from, where it led "
        "to, and the debugger's comment for that frame. Use it to "
        "understand how the program reached the current location, to find "
        "the caller of the current function, or to trace a path from a "
        "known entry point down to the code of interest. Requires an "
        "active debugging session with the process paused; by default the "
        "call stack of the current thread is returned, use 'thread_id' "
        "(from list_threads) to inspect another thread. In optimized code "
        "built without frame pointers, unwinding can be incomplete or "
        "inaccurate — treat the result as a best effort, not a guarantee.";
    callStack.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"thread_id", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Identifier of the thread whose call stack to reconstruct, from "
                 "list_threads. Omit, or pass 0, to use the current thread."}
            }}
        }},
        {"additionalProperties", false}
    };
    callStack.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("call_stack: plugin link is not configured");

        nlohmann::json params = nlohmann::json::object();
        if (arguments.contains("thread_id"))
        {
            RequireNonNegativeInteger(arguments, "thread_id", "call_stack");
            params["thread_id"] = arguments["thread_id"].get<long long>();
        }

        ToolResult result;
        result.structuredContent = link->Call("callstack", params);
        const nlohmann::json frames = result.structuredContent.value("frames", nlohmann::json::array());
        result.text = FormatCallStack(frames);
        return result;
    };
    registry.Add(std::move(callStack));

    Tool readStack;
    readStack.name = "read_stack";
    readStack.description =
        "Read the machine words sitting on top of the stack, starting at "
        "the current stack pointer, together with the debugger's comment "
        "for each one (for example, identifying a value as a return "
        "address or a pointer into a module). Use it to inspect a "
        "function's arguments and local variables, to look for return "
        "addresses and pointers to data, or to make sense of a stack "
        "frame. Requires an active debugging session with the process "
        "paused. Reads from 1 to 256 words per call, 16 by default; the "
        "size of a word matches the bitness of the debugged process (4 "
        "bytes for a 32-bit process, 8 bytes for a 64-bit process).";
    readStack.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"count", {
                {"type", "integer"},
                {"minimum", 1},
                {"maximum", 256},
                {"default", 16},
                {"description", "Number of stack words to read, from 1 to 256. Defaults to 16."}
            }}
        }},
        {"additionalProperties", false}
    };
    readStack.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("read_stack: plugin link is not configured");

        long long count = 16;
        if (arguments.contains("count"))
        {
            if (!arguments["count"].is_number_integer())
                throw ToolError("read_stack: 'count' must be an integer between 1 and 256");
            count = arguments["count"].get<long long>();
            if (count < 1 || count > 256)
                throw ToolError("read_stack: 'count' must be between 1 and 256");
        }

        ToolResult result;
        result.structuredContent = link->Call("stack.read", {
            {"count", count}
        });
        const nlohmann::json slots = result.structuredContent.value("slots", nlohmann::json::array());
        result.text = FormatStackSlots(slots);
        return result;
    };
    registry.Add(std::move(readStack));

    Tool readString;
    readString.name = "read_string";
    readString.description =
        "Read the string located at a memory address, decoded the way the "
        "debugger itself recognizes it — the debugger determines the "
        "encoding on its own (for example plain ASCII or UTF-16). Use it to "
        "read messages, paths, names, and other text data referenced by "
        "code; it is especially useful on the operand of an instruction "
        "that loads the address of a string. Limitation: if the debugger "
        "does not recognize a string at the given address, the tool fails "
        "with an error — that does not mean there is no data there, only "
        "that it does not look like a string. Parameters: 'address' — a "
        "non-negative integer giving the address to read from (a number, "
        "not a hex string).";
    readString.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description", "Address to read the string from, given as a number (not a hex string)."}
            }}
        }},
        {"required", nlohmann::json::array({"address"})},
        {"additionalProperties", false}
    };
    readString.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("read_string: plugin link is not configured");

        RequireNonNegativeInteger(arguments, "address", "read_string");
        const std::uint64_t address = arguments["address"].get<std::uint64_t>();

        ToolResult result;
        result.structuredContent = link->Call("string.read", {
            {"address", address}
        });
        result.text = FormatReadString(result.structuredContent);
        return result;
    };
    registry.Add(std::move(readString));

    Tool evaluateExpression;
    evaluateExpression.name = "evaluate_expression";
    evaluateExpression.description =
        "Evaluate an expression written in x64dbg's expression language. "
        "This is the most flexible inspection tool: it understands API "
        "function names, registers, memory dereferences, and arithmetic. "
        "Examples: 'kernel32.CreateFileW' — the address of an API "
        "function; '[rsp+8]' — the value stored at that address; "
        "'rax+0x10' — arithmetic on a register; 'crackme.exe:$0' — an "
        "address given as an offset into a file. Returns the resulting "
        "value together with a flag telling whether it points into memory "
        "that is currently readable, so it is immediately clear whether "
        "the value can be read with read_memory. Requires an active "
        "debugging session; registers are only available while the "
        "process is paused. Parameters: 'expression' — the expression to "
        "evaluate, as a string.";
    evaluateExpression.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"expression", {
                {"type", "string"},
                {"description",
                 "x64dbg expression to evaluate, e.g. 'kernel32.CreateFileW', "
                 "'[rsp+8]', 'rax+0x10', or 'crackme.exe:$0'."}
            }}
        }},
        {"required", nlohmann::json::array({"expression"})},
        {"additionalProperties", false}
    };
    evaluateExpression.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("evaluate_expression: plugin link is not configured");

        if (!arguments.contains("expression") || !arguments["expression"].is_string())
            throw ToolError("evaluate_expression: 'expression' is required and must be a string");
        const std::string expression = arguments["expression"].get<std::string>();

        ToolResult result;
        result.structuredContent = link->Call("expression.eval", {
            {"expression", expression}
        });
        result.text = FormatEvaluateExpression(result.structuredContent);
        return result;
    };
    registry.Add(std::move(evaluateExpression));

    Tool findPattern;
    findPattern.name = "find_pattern";
    findPattern.description =
        "Search for a byte signature in the debuggee's memory. The search "
        "range is given either as 'start' and 'size' together, or as "
        "'module' alone, in which case the whole module is searched. "
        "Signature format: hex bytes separated by spaces, with '??' "
        "standing in for an unknown byte, for example "
        "'48 8B ?? 24 ?? 48 89'. Unknown bytes matter because addresses "
        "and offsets change between builds while the surrounding reference "
        "instructions stay the same. Use this tool to find known code "
        "sequences, magic constants, or structure headers again after a "
        "rebuild. Limits: at most 256 matches and at most 256 MiB of range "
        "are scanned per call; if there are more matches than the limit "
        "allows, the corresponding flag in the result is true. Parameters: "
        "'pattern' — the signature to search for; 'start' and 'size' — the "
        "address range to search (used together); 'module' — the name of "
        "a module to search entirely (mutually exclusive with 'start'/"
        "'size'); 'max_results' — maximum number of matches to return, 1 "
        "to 256, defaults to 32.";
    findPattern.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"pattern", {
                {"type", "string"},
                {"description",
                 "Byte signature to search for: hex bytes separated by spaces, with "
                 "'??' for an unknown byte, e.g. '48 8B ?? 24 ?? 48 89'."}
            }},
            {"start", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Start address of the range to search, given as a number (not a hex "
                 "string). Used together with 'size'."}
            }},
            {"size", {
                {"type", "integer"},
                {"minimum", 1},
                {"maximum", 268435456},
                {"description",
                 "Size in bytes of the range to search, at most 268435456 (256 MiB). "
                 "Used together with 'start'."}
            }},
            {"module", {
                {"type", "string"},
                {"description", "Name of the module to search entirely. Mutually exclusive with 'start'/'size'."}
            }},
            {"max_results", {
                {"type", "integer"},
                {"minimum", 1},
                {"maximum", 256},
                {"default", 32},
                {"description", "Maximum number of matches to return, from 1 to 256. Defaults to 32."}
            }}
        }},
        {"required", nlohmann::json::array({"pattern"})},
        {"anyOf", nlohmann::json::array({
            { {"required", nlohmann::json::array({"start", "size"})} },
            { {"required", nlohmann::json::array({"module"})} }
        })},
        {"additionalProperties", false}
    };
    findPattern.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("find_pattern: plugin link is not configured");

        if (!arguments.contains("pattern") || !arguments["pattern"].is_string())
            throw ToolError("find_pattern: 'pattern' is required and must be a string");
        const std::string pattern = arguments["pattern"].get<std::string>();

        const bool hasModule = arguments.contains("module");
        const bool hasStart = arguments.contains("start");
        const bool hasSize = arguments.contains("size");
        if (hasModule && (hasStart || hasSize))
            throw ToolError("find_pattern: 'module' cannot be combined with 'start'/'size'");
        if (!hasModule && !(hasStart && hasSize))
            throw ToolError("find_pattern: provide either 'start' and 'size', or 'module'");

        nlohmann::json params = {{"pattern", pattern}};
        if (hasModule)
        {
            if (!arguments["module"].is_string())
                throw ToolError("find_pattern: 'module' must be a string");
            params["module"] = arguments["module"].get<std::string>();
        }
        else
        {
            RequireNonNegativeInteger(arguments, "start", "find_pattern");
            if (!arguments["size"].is_number_integer())
                throw ToolError("find_pattern: 'size' must be a positive integer");
            const long long size = arguments["size"].get<long long>();
            if (size < 1 || size > 268435456)
                throw ToolError("find_pattern: 'size' must be between 1 and 268435456 bytes (256 MiB)");
            params["start"] = arguments["start"].get<std::uint64_t>();
            params["size"] = size;
        }

        long long maxResults = 32;
        if (arguments.contains("max_results"))
        {
            if (!arguments["max_results"].is_number_integer())
                throw ToolError("find_pattern: 'max_results' must be an integer between 1 and 256");
            maxResults = arguments["max_results"].get<long long>();
            if (maxResults < 1 || maxResults > 256)
                throw ToolError("find_pattern: 'max_results' must be between 1 and 256");
        }
        params["max_results"] = maxResults;

        ToolResult result;
        result.structuredContent = link->Call("pattern.find", params, kSlowToolRequestTimeoutMs);
        result.text = FormatPatternMatches(result.structuredContent);
        return result;
    };
    registry.Add(std::move(findPattern));

    Tool findReferences;
    findReferences.name = "find_references";
    findReferences.description =
        "List the places that reference a given address, together with "
        "the kind of reference: a call, a jump, or a data access. Use it "
        "to find every caller of a function, to find code that reads a "
        "variable of interest, or to gauge how heavily a function is "
        "used. Limitation: references come from xref analysis already "
        "performed by the debugger, so unanalyzed regions may hold "
        "references that are not listed here; an empty result does not "
        "prove that no references exist. If a module has not been "
        "xref-analyzed yet, run it directly with the execute_command "
        "tool using the 'analxrefs' command; note that 'analyse' alone "
        "does not build cross-references. Parameters: 'address' — a "
        "non-negative integer giving the address to find references to (a "
        "number, not a hex string).";
    findReferences.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description", "Address to find references to, given as a number (not a hex string)."}
            }}
        }},
        {"required", nlohmann::json::array({"address"})},
        {"additionalProperties", false}
    };
    findReferences.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("find_references: plugin link is not configured");

        RequireNonNegativeInteger(arguments, "address", "find_references");
        const std::uint64_t address = arguments["address"].get<std::uint64_t>();

        ToolResult result;
        result.structuredContent = link->Call("xrefs.get", {
            {"address", address}
        });
        result.text = FormatXrefs(result.structuredContent);
        return result;
    };
    registry.Add(std::move(findReferences));

    Tool disassembleFunction;
    disassembleFunction.name = "disassemble_function";
    disassembleFunction.description =
        "Disassemble an entire function, using the debugger's analysis to "
        "determine its boundaries. Use it as the first step of analyzing "
        "a function — it is more convenient than guessing the function's "
        "length and calling disassemble several times. Returns the "
        "function's start and end address together with its instructions, "
        "in the same shape as disassemble. Limitations: the boundaries "
        "come from the debugger's analysis, so the tool fails if no "
        "function is defined at 'address'; if a module has not been "
        "analyzed yet, run analysis directly with the execute_command "
        "tool using the 'analyse' command, which builds function "
        "boundaries for the current module; very long functions are cut "
        "off at the tool's instruction limit, which is reported by a "
        "truncation flag in the result. Parameters: 'address' — a "
        "non-negative integer giving an address inside the function to "
        "disassemble (a number, not a hex string).";
    disassembleFunction.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description", "Address inside the function to disassemble, given as a number (not a hex string)."}
            }}
        }},
        {"required", nlohmann::json::array({"address"})},
        {"additionalProperties", false}
    };
    disassembleFunction.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("disassemble_function: plugin link is not configured");

        RequireNonNegativeInteger(arguments, "address", "disassemble_function");
        const std::uint64_t address = arguments["address"].get<std::uint64_t>();

        ToolResult result;
        result.structuredContent = link->Call("function.disasm", {
            {"address", address}
        });
        result.text = FormatDisassembleFunction(result.structuredContent);
        return result;
    };
    registry.Add(std::move(disassembleFunction));

    Tool executeCommand;
    executeCommand.name = "execute_command";
    executeCommand.description =
        "Run any x64dbg command and return whatever the debugger printed "
        "to its log as a result. This is the escape hatch: x64dbg has "
        "over three hundred commands, and anything not covered by a "
        "dedicated tool in this server is reachable here. Examples: "
        "'analyse' builds function boundaries for the current module, "
        "which disassemble_function depends on; 'analxrefs' builds "
        "cross-references for the current module, which find_references "
        "depends on — 'analyse' alone does not build cross-references; "
        "'bpgoto' and "
        "other breakpoint commands not exposed by set_breakpoint; "
        "'memset' and other memory commands; 'var' to declare or inspect "
        "a debugger variable. IMPORTANT: the arguments of an x64dbg "
        "command are separated by COMMAS, not spaces, e.g. "
        "'bp kernel32.CreateFileW,\"my label\"' — passing space-separated "
        "arguments is a very common mistake and usually makes the "
        "command fail silently or do something unintended. By default "
        "the command runs synchronously and its result is reported "
        "directly in this call. Set 'async' to true for a command that "
        "resumes execution (e.g. 'run', or a breakpoint command expected "
        "to hit); after an asynchronous call, use wait_until_paused to "
        "wait for the next pause. Whether output was actually captured "
        "depends on the debugger's log capture being active; the "
        "result's 'logCaptured' field says whether it was. A command the "
        "debugger rejects returns 'accepted' as false, together with "
        "whatever it printed. SAFETY: this tool can change the state of "
        "the debuggee and of the debugger itself, including writing "
        "memory and resuming execution — use it deliberately, not "
        "experimentally.";
    executeCommand.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"command", {
                {"type", "string"},
                {"description",
                 "x64dbg command to run, e.g. 'analyse', 'analxrefs', 'bpgoto 0x401000', "
                 "'memset 0x401000,0x90,0x10', or 'var x = 1'. Arguments are "
                 "separated by commas, not spaces."}
            }},
            {"async", {
                {"type", "boolean"},
                {"default", false},
                {"description",
                 "If true, the command runs asynchronously: use this for a command "
                 "that resumes execution, then call wait_until_paused to wait for "
                 "the next pause. Defaults to false (synchronous)."}
            }}
        }},
        {"required", nlohmann::json::array({"command"})},
        {"additionalProperties", false}
    };
    executeCommand.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("execute_command: plugin link is not configured");

        if (!arguments.contains("command") || !arguments["command"].is_string())
            throw ToolError("execute_command: 'command' is required and must be a string");
        const std::string command = arguments["command"].get<std::string>();
        const bool async = arguments.value("async", false);

        ToolResult result;
        result.structuredContent = link->Call("command.exec", {
            {"command", command},
            {"async", async}
        }, kSlowToolRequestTimeoutMs);
        result.text = FormatCommandResult(result.structuredContent);
        return result;
    };
    registry.Add(std::move(executeCommand));

    Tool runScript;
    runScript.name = "run_script";
    runScript.description =
        "Run an x64dbg script given as text. Useful for sequences that "
        "would otherwise take many round trips through execute_command — "
        "setting up a group of breakpoints, walking a structure field by "
        "field, or repeating an action. Execution is asynchronous: this "
        "tool reports that the script started and returns whatever log "
        "output was available at that moment, without waiting for the "
        "script to finish; use wait_until_paused afterward to wait for "
        "the script to reach a pause. Limitations: the script language is "
        "x64dbg's own scripting language, not the same syntax as a single "
        "command; a syntax error in the script surfaces in the log "
        "output rather than as a tool error. Parameters: 'script' — the "
        "full text of the script to run.";
    runScript.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"script", {
                {"type", "string"},
                {"description", "Full text of the x64dbg script to run."}
            }}
        }},
        {"required", nlohmann::json::array({"script"})},
        {"additionalProperties", false}
    };
    runScript.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("run_script: plugin link is not configured");

        if (!arguments.contains("script") || !arguments["script"].is_string())
            throw ToolError("run_script: 'script' is required and must be a string");
        const std::string script = arguments["script"].get<std::string>();

        ToolResult result;
        result.structuredContent = link->Call("script.run", {
            {"script", script}
        }, kSlowToolRequestTimeoutMs);
        result.text = FormatScriptResult(result.structuredContent);
        return result;
    };
    registry.Add(std::move(runScript));

    Tool readLog;
    readLog.name = "read_log";
    readLog.description =
        "Return the most recent lines of the x64dbg log, including output "
        "from commands run with execute_command or run_script, "
        "breakpoint hits, and messages printed by the debugger itself. "
        "Use it after an asynchronous execute_command or run_script call "
        "to see what happened, or to inspect the output recorded by a "
        "logging breakpoint (set_breakpoint's 'log' parameter), which "
        "writes data to the log without stopping the process. Returns at "
        "most 1000 lines per call, the most recent ones. Limitations: "
        "capture must be active for there to be anything to read; the "
        "result's 'logCaptured' field says whether it is. Parameters: "
        "'max_lines' — maximum number of lines to return, from 1 to "
        "1000, defaulting to 200.";
    readLog.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"max_lines", {
                {"type", "integer"},
                {"minimum", 1},
                {"maximum", 1000},
                {"default", 200},
                {"description", "Maximum number of most recent log lines to return, from 1 to 1000."}
            }}
        }},
        {"additionalProperties", false}
    };
    readLog.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("read_log: plugin link is not configured");

        long long maxLines = 200;
        if (arguments.contains("max_lines"))
        {
            if (!arguments["max_lines"].is_number_integer())
                throw ToolError("read_log: 'max_lines' must be an integer between 1 and 1000");
            maxLines = arguments["max_lines"].get<long long>();
            if (maxLines < 1 || maxLines > 1000)
                throw ToolError("read_log: 'max_lines' must be between 1 and 1000");
        }

        ToolResult result;
        result.structuredContent = link->Call("log.read", {
            {"max_lines", maxLines}
        });
        result.text = FormatLogLines(result.structuredContent);
        return result;
    };
    registry.Add(std::move(readLog));

    Tool writeMemory;
    writeMemory.name = "write_memory";
    writeMemory.description =
        "Write raw bytes into the memory of the debugged process. SAFETY: "
        "this modifies the running program directly and can crash it, "
        "corrupt its data structures, or make it behave unpredictably — "
        "use it deliberately, not experimentally. Give the bytes to write "
        "as a hex string in 'data', e.g. '90 90' or '9090' (spaces are "
        "optional). By default the write is recorded as a patch (see the "
        "'patches' tool), which makes it undoable and lets it later be "
        "saved into a copy of the file on disk; set 'record_patch' to "
        "false to write without recording. Use this tool to change a "
        "value a program is about to read, to disable a check, or to "
        "fill code with NOPs. Requires the process to be paused: writing "
        "while it runs is refused, because the target could be executing "
        "the very bytes being overwritten halfway through the write. "
        "Parameters: 'address' — a non-negative integer giving the "
        "address to write to (a number, not a hex string); 'data' — the "
        "bytes to write, as a hex string; 'record_patch' — whether to "
        "record the write as a patch, true by default.";
    writeMemory.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description", "Address to write to, given as a number (not a hex string)."}
            }},
            {"data", {
                {"type", "string"},
                {"description", "Bytes to write, as a hex string, e.g. '90 90' or '9090'. Spaces are optional."}
            }},
            {"record_patch", {
                {"type", "boolean"},
                {"default", true},
                {"description",
                 "Whether to record the write as an undoable patch, manageable with "
                 "the 'patches' tool. Defaults to true."}
            }}
        }},
        {"required", nlohmann::json::array({"address", "data"})},
        {"additionalProperties", false}
    };
    writeMemory.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("write_memory: plugin link is not configured");

        RequireNonNegativeInteger(arguments, "address", "write_memory");
        if (!arguments.contains("data") || !arguments["data"].is_string())
            throw ToolError("write_memory: 'data' is required and must be a hex string");
        const std::uint64_t address = arguments["address"].get<std::uint64_t>();
        const std::string data = arguments["data"].get<std::string>();
        const bool recordPatch = arguments.value("record_patch", true);

        ToolResult result;
        result.structuredContent = link->Call("memory.write", {
            {"address", address},
            {"data", data},
            {"record_patch", recordPatch}
        });
        result.text = FormatWriteMemoryResult(result.structuredContent);
        return result;
    };
    registry.Add(std::move(writeMemory));

    Tool setRegister;
    setRegister.name = "set_register";
    setRegister.description =
        "Set a register, or any debugger variable, by name to a given "
        "value. SAFETY: setting the instruction pointer (rip/eip) to an "
        "arbitrary address usually crashes the process — use this tool "
        "deliberately, not experimentally. Names are the usual ones for "
        "the debuggee's architecture: 'rax', 'rip', 'rsp', and similar on "
        "64-bit; 'eax', 'eip', 'esp', and similar on 32-bit. Use it to "
        "force a branch by changing a flag or a compared value, to "
        "redirect execution by setting the instruction pointer, or to "
        "fix an argument before a call. Requires the process to be "
        "paused; the change applies to the current thread. Parameters: "
        "'name' — the register or variable name; 'value' — the value to "
        "set it to, as a number.";
    setRegister.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"name", {
                {"type", "string"},
                {"description", "Register or debugger variable name, e.g. 'rax', 'rip', 'rsp', 'eax'."}
            }},
            {"value", {
                {"type", "integer"},
                {"description", "Value to set the register or variable to."}
            }}
        }},
        {"required", nlohmann::json::array({"name", "value"})},
        {"additionalProperties", false}
    };
    setRegister.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("set_register: plugin link is not configured");

        if (!arguments.contains("name") || !arguments["name"].is_string())
            throw ToolError("set_register: 'name' is required and must be a string");
        if (!arguments.contains("value") || !arguments["value"].is_number_integer())
            throw ToolError("set_register: 'value' is required and must be an integer");
        const std::string name = arguments["name"].get<std::string>();
        const long long value = arguments["value"].get<long long>();

        ToolResult result;
        result.structuredContent = link->Call("register.set", {
            {"name", name},
            {"value", value}
        });
        result.text = FormatSetRegisterResult(result.structuredContent);
        return result;
    };
    registry.Add(std::move(setRegister));

    Tool assembleAt;
    assembleAt.name = "assemble_at";
    assembleAt.description =
        "Assemble one instruction and write it at the given address. "
        "SAFETY: this changes code that is about to run, the same as "
        "writing memory directly — use it deliberately, not "
        "experimentally. Give the instruction in the debugger's assembly "
        "syntax, for example 'nop', 'jmp 0x140001000', or 'mov eax, 1'. A "
        "shorter instruction leaves behind leftover bytes of the one it "
        "replaced, which would otherwise be decoded as garbage; "
        "'fill_nop', true by default, pads those leftover bytes with "
        "NOPs so the surrounding code stream stays valid — it should "
        "normally stay on. Use this tool to turn a conditional jump into "
        "its opposite or into NOPs, to redirect a call, or to insert a "
        "breakpoint-like instruction. Requires the process to be paused. "
        "If the given text cannot be assembled, the tool fails with the "
        "assembler's own message, which says exactly what is wrong. "
        "Parameters: 'address' — a non-negative integer giving the "
        "address to assemble at (a number, not a hex string); "
        "'instruction' — the instruction text; 'fill_nop' — whether to "
        "pad leftover bytes with NOPs, true by default.";
    assembleAt.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description", "Address to assemble the instruction at, given as a number (not a hex string)."}
            }},
            {"instruction", {
                {"type", "string"},
                {"description", "Instruction text in the debugger's assembly syntax, e.g. 'jmp 0x140001000'."}
            }},
            {"fill_nop", {
                {"type", "boolean"},
                {"default", true},
                {"description",
                 "Whether to pad leftover bytes of a shorter replacement instruction "
                 "with NOPs, keeping the code stream valid. Defaults to true; should "
                 "normally stay on."}
            }}
        }},
        {"required", nlohmann::json::array({"address", "instruction"})},
        {"additionalProperties", false}
    };
    assembleAt.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("assemble_at: plugin link is not configured");

        RequireNonNegativeInteger(arguments, "address", "assemble_at");
        if (!arguments.contains("instruction") || !arguments["instruction"].is_string())
            throw ToolError("assemble_at: 'instruction' is required and must be a string");
        const std::uint64_t address = arguments["address"].get<std::uint64_t>();
        const std::string instruction = arguments["instruction"].get<std::string>();
        const bool fillNop = arguments.value("fill_nop", true);

        ToolResult result;
        result.structuredContent = link->Call("assemble", {
            {"address", address},
            {"instruction", instruction},
            {"fill_nop", fillNop}
        });
        result.text = FormatAssembleResult(result.structuredContent, instruction);
        return result;
    };
    registry.Add(std::move(assembleAt));

    Tool patches;
    patches.name = "patches";
    patches.description =
        "Manage recorded patches — writes made with write_memory or "
        "assemble_at while recording was enabled (the default). 'list' "
        "shows every patch with its address, original byte, and current "
        "byte. 'restore' puts the original bytes back, either at a "
        "single 'address' or across a range given by 'start' and 'end' "
        "together. 'apply_to_file' writes every current patch into a "
        "copy of the module on disk at 'path'; it does NOT change the "
        "running process, it produces a patched file — this is how a fix "
        "is made permanent. Use this tool to review what has been "
        "changed, to undo an experiment, or to save a working patch. "
        "Limitation: only writes recorded as patches appear here; a "
        "write made with 'record_patch' set to false is invisible to it. "
        "Parameters: 'action' — 'list', 'restore', or 'apply_to_file'; "
        "'address' — single address to restore (for 'restore', mutually "
        "exclusive with 'start'/'end'); 'start' and 'end' — range of "
        "addresses to restore (for 'restore', used together); 'path' — "
        "destination file path (required for 'apply_to_file').";
    patches.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"action", {
                {"type", "string"},
                {"enum", nlohmann::json::array({"list", "restore", "apply_to_file"})},
                {"description",
                 "'list' shows recorded patches, 'restore' reverts them, "
                 "'apply_to_file' writes them into a copy of the module on disk."}
            }},
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Address of a single patch to restore, given as a number (not a "
                 "hex string). Used with 'restore'; mutually exclusive with "
                 "'start'/'end'."}
            }},
            {"start", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Start address of a range of patches to restore. Used together "
                 "with 'end', for 'restore'."}
            }},
            {"end", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "End address of a range of patches to restore. Used together "
                 "with 'start', for 'restore'."}
            }},
            {"path", {
                {"type", "string"},
                {"description",
                 "Destination path for the patched copy of the module. Required "
                 "for 'apply_to_file'."}
            }}
        }},
        {"required", nlohmann::json::array({"action"})},
        {"allOf", nlohmann::json::array({
            {
                {"if", {
                    {"properties", {{"action", {{"const", "apply_to_file"}}}}},
                    {"required", nlohmann::json::array({"action"})}
                }},
                {"then", {{"required", nlohmann::json::array({"action", "path"})}}}
            }
        })},
        {"additionalProperties", false}
    };
    patches.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("patches: plugin link is not configured");

        const std::string action =
            RequireEnumString(arguments, "action", {"list", "restore", "apply_to_file"}, "patches");

        ToolResult result;
        if (action == "list")
        {
            result.structuredContent = link->Call("patches.list", nlohmann::json::object());
            const nlohmann::json list = result.structuredContent.value("patches", nlohmann::json::array());
            result.text = FormatPatchesList(list);
        }
        else if (action == "restore")
        {
            const bool hasAddress = arguments.contains("address");
            const bool hasStart = arguments.contains("start");
            const bool hasEnd = arguments.contains("end");
            if (hasAddress && (hasStart || hasEnd))
                throw ToolError("patches: 'address' cannot be combined with 'start'/'end'");
            if (!hasAddress && !(hasStart && hasEnd))
                throw ToolError("patches: 'restore' requires either 'address', or 'start' and 'end' together");

            nlohmann::json params = nlohmann::json::object();
            if (hasAddress)
            {
                RequireNonNegativeInteger(arguments, "address", "patches");
                params["address"] = arguments["address"].get<std::uint64_t>();
            }
            else
            {
                RequireNonNegativeInteger(arguments, "start", "patches");
                RequireNonNegativeInteger(arguments, "end", "patches");
                params["start"] = arguments["start"].get<std::uint64_t>();
                params["end"] = arguments["end"].get<std::uint64_t>();
            }

            result.structuredContent = link->Call("patches.restore", params);
            result.text = FormatPatchesRestore(result.structuredContent);
        }
        else
        {
            if (!arguments.contains("path") || !arguments["path"].is_string())
                throw ToolError("patches: 'apply_to_file' requires 'path' to be a string");
            const std::string path = arguments["path"].get<std::string>();

            result.structuredContent = link->Call("patches.apply_to_file", {
                {"path", path}
            });
            result.text = FormatPatchesApplyToFile(result.structuredContent);
        }
        return result;
    };
    registry.Add(std::move(patches));

    Tool setPageRights;
    setPageRights.name = "set_page_rights";
    setPageRights.description =
        "Change the memory protection of the region containing an "
        "address. SAFETY: relaxing protection can mask bugs in the "
        "debuggee and change its behaviour — use it deliberately, not "
        "experimentally. The 'rights' string uses full-word names: "
        "'Execute', 'ExecuteRead', 'ExecuteReadWrite', "
        "'ExecuteWriteCopy', 'NoAccess', 'ReadOnly', 'ReadWrite', "
        "'WriteCopy' — optionally prefixed with 'G' for a guard page "
        "(e.g. 'GExecuteRead'). This is NOT the compact form (e.g. "
        "'ERWC') that the memory_map tool displays; that form is "
        "display-only and will be rejected here. Use it to make a "
        "read-only region writable before patching it, or to make data "
        "executable when analysing generated code. Requires the process "
        "to be paused; the change applies to the whole memory region, "
        "not a single byte. Parameters: 'address' — a non-negative "
        "integer giving an address inside the region (a number, not a "
        "hex string); 'rights' — the protection to apply, as a string.";
    setPageRights.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description", "Address inside the region to change, given as a number (not a hex string)."}
            }},
            {"rights", {
                {"type", "string"},
                {"description",
                 "Protection to apply, as a full-word name: 'Execute', "
                 "'ExecuteRead', 'ExecuteReadWrite', 'ExecuteWriteCopy', "
                 "'NoAccess', 'ReadOnly', 'ReadWrite', 'WriteCopy' — optionally "
                 "prefixed with 'G' for a guard page. NOT the compact form "
                 "(e.g. 'ERWC') shown by memory_map; that display form is "
                 "rejected here."}
            }}
        }},
        {"required", nlohmann::json::array({"address", "rights"})},
        {"additionalProperties", false}
    };
    setPageRights.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("set_page_rights: plugin link is not configured");

        RequireNonNegativeInteger(arguments, "address", "set_page_rights");
        if (!arguments.contains("rights") || !arguments["rights"].is_string())
            throw ToolError("set_page_rights: 'rights' is required and must be a string");
        const std::uint64_t address = arguments["address"].get<std::uint64_t>();
        const std::string rights = arguments["rights"].get<std::string>();

        ToolResult result;
        result.structuredContent = link->Call("memory.set_rights", {
            {"address", address},
            {"rights", rights}
        });
        result.text = FormatSetPageRightsResult(result.structuredContent);
        return result;
    };
    registry.Add(std::move(setPageRights));

    Tool traceUntil;
    traceUntil.name = "trace_until";
    traceUntil.description =
        "Run the debuggee one instruction at a time INSIDE the debugger, "
        "without returning to the model after each step, until a chosen "
        "condition becomes true or a step budget is exhausted — then stop "
        "and report where execution ended up. 'into' follows calls into "
        "the called function; 'over' executes each call as a single unit "
        "without entering it. WHY THIS MATTERS: the whole trace runs "
        "inside x64dbg, so a trace of a million instructions costs one "
        "tool call, not a million. Stepping through obfuscated or "
        "virtualised code with the step tool, one instruction and one "
        "round trip at a time, is not practical — this is the tool built "
        "for that. 'condition' is an x64dbg expression, the same "
        "language evaluate_expression uses; if unsure what an expression "
        "evaluates to, try it there first. Examples: 'rip == "
        "0x140001000' stops when execution reaches that address; 'rax == "
        "0' stops when a register takes a given value; '[rsp] == "
        "0x1234' stops when a memory location holds a given value; "
        "expressions like 'dis.iscall(rip)' stop on a given kind of "
        "instruction, here the next call. Requires the process to be "
        "paused when the call starts. 'max_steps' bounds how many "
        "instructions run even if the condition never becomes true, from "
        "1 to 10000000; it defaults to 100000. Returns the same shape as "
        "the step tools: 'paused', 'timed_out', 'pause_reason', and "
        "'status'. If neither the condition nor the step budget is "
        "reached before 'timeout_ms' elapses, 'timed_out' is true and "
        "the process is still running — this is not an error, just a "
        "sign the trace needs a tighter condition or more time.";
    traceUntil.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"mode", {
                {"type", "string"},
                {"enum", nlohmann::json::array({"into", "over"})},
                {"description",
                 "'into' follows calls into the called function, 'over' executes "
                 "each call as a single unit without entering it."}
            }},
            {"condition", {
                {"type", "string"},
                {"description",
                 "x64dbg expression evaluated after every instruction; the trace "
                 "stops once it is non-zero. Same language as evaluate_expression. "
                 "Examples: 'rip == 0x140001000', 'rax == 0', '[rsp] == 0x1234', "
                 "'dis.iscall(rip)'."}
            }},
            {"max_steps", {
                {"type", "integer"},
                {"minimum", 1},
                {"maximum", 10000000},
                {"default", 100000},
                {"description",
                 "Maximum number of instructions to execute even if 'condition' "
                 "never becomes true, from 1 to 10000000."}
            }},
            {"timeout_ms", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Maximum time to wait for the trace to finish, in milliseconds. "
                 "If omitted, the plugin's default timeout is used."}
            }}
        }},
        {"required", nlohmann::json::array({"mode", "condition"})},
        {"additionalProperties", false}
    };
    traceUntil.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("trace_until: plugin link is not configured");

        const std::string mode = RequireEnumString(arguments, "mode", {"into", "over"}, "trace_until");
        if (!arguments.contains("condition") || !arguments["condition"].is_string())
            throw ToolError("trace_until: 'condition' is required and must be a string");
        const std::string condition = arguments["condition"].get<std::string>();

        long long maxSteps = 100000;
        if (arguments.contains("max_steps"))
        {
            if (!arguments["max_steps"].is_number_integer())
                throw ToolError("trace_until: 'max_steps' must be an integer between 1 and 10000000");
            maxSteps = arguments["max_steps"].get<long long>();
            if (maxSteps < 1 || maxSteps > 10000000)
                throw ToolError("trace_until: 'max_steps' must be between 1 and 10000000");
        }

        nlohmann::json params = {
            {"mode", mode},
            {"condition", condition},
            {"max_steps", maxSteps}
        };
        if (arguments.contains("timeout_ms"))
        {
            RequireNonNegativeInteger(arguments, "timeout_ms", "trace_until");
            params["timeout_ms"] = arguments["timeout_ms"].get<long long>();
        }

        ToolResult result;
        result.structuredContent = link->Call("trace.until", params, RequestTimeoutMs(params));
        result.text = FormatPauseResult(result.structuredContent);
        return result;
    };
    registry.Add(std::move(traceUntil));

    Tool traceRecord;
    traceRecord.name = "trace_record";
    traceRecord.description =
        "Start or stop recording every instruction the debuggee executes "
        "into a trace file that x64dbg can open and browse afterwards. "
        "Recording by itself does not execute anything: call this tool "
        "with action 'start', then run or trace the process "
        "(debug_control, step, or trace_until), then call this tool "
        "again with action 'stop' — the file ends up holding exactly the "
        "instructions that were actually executed while recording was "
        "on. Use it to capture a full execution path for later study, to "
        "compare two runs of the same code, or to recover the real "
        "control flow of obfuscated code that a static disassembly "
        "cannot show. Requires an active debugging session. Parameters: "
        "'action' — 'start' or 'stop'; 'path' — destination file path "
        "for the trace, required when 'action' is 'start' and ignored "
        "otherwise.";
    traceRecord.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"action", {
                {"type", "string"},
                {"enum", nlohmann::json::array({"start", "stop"})},
                {"description", "'start' begins recording to 'path', 'stop' ends recording."}
            }},
            {"path", {
                {"type", "string"},
                {"description",
                 "Destination file path for the trace. Required when 'action' is "
                 "'start', ignored otherwise."}
            }}
        }},
        {"required", nlohmann::json::array({"action"})},
        {"allOf", nlohmann::json::array({
            {
                {"if", {
                    {"properties", {{"action", {{"const", "start"}}}}},
                    {"required", nlohmann::json::array({"action"})}
                }},
                {"then", {{"required", nlohmann::json::array({"action", "path"})}}}
            }
        })},
        {"additionalProperties", false}
    };
    traceRecord.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("trace_record: plugin link is not configured");

        const std::string action = RequireEnumString(arguments, "action", {"start", "stop"}, "trace_record");

        nlohmann::json params = {{"action", action}};
        std::string path;
        if (action == "start")
        {
            if (!arguments.contains("path") || !arguments["path"].is_string())
                throw ToolError("trace_record: 'start' requires 'path' to be a string");
            path = arguments["path"].get<std::string>();
            params["path"] = path;
        }

        ToolResult result;
        result.structuredContent = link->Call("trace.record", params);
        result.text = FormatTraceRecordResult(action, path);
        return result;
    };
    registry.Add(std::move(traceRecord));

    Tool runToUserCode;
    runToUserCode.name = "run_to_user_code";
    runToUserCode.description =
        "Resume execution until control reaches code belonging to the "
        "debugged program itself, rather than a system library. WHY "
        "THIS MATTERS: after a call into a system function, or while a "
        "packer's unpacking stub runs library code, this returns to the "
        "interesting part in one step instead of stepping through the "
        "library by hand. It works by setting temporary memory "
        "breakpoints on the pages that hold user code, rather than "
        "single-stepping instruction by instruction, so it is fast even "
        "across long stretches of system code. Requires a debugging "
        "session that is running or paused inside system code for the "
        "call to be meaningful; x64dbg refuses to start a second such "
        "run while one is already in progress. Returns the same shape "
        "as the step tools: 'paused', 'timed_out', 'pause_reason', and "
        "'status'. If it times out, 'timed_out' is true and the process "
        "is still running. Parameters: 'timeout_ms' — maximum time to "
        "wait, in milliseconds; if omitted, the plugin's default timeout "
        "is used.";
    runToUserCode.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"timeout_ms", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Maximum time to wait for user code to be reached, in "
                 "milliseconds. If omitted, the plugin's default timeout is used."}
            }}
        }},
        {"additionalProperties", false}
    };
    runToUserCode.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("run_to_user_code: plugin link is not configured");

        nlohmann::json params = nlohmann::json::object();
        if (arguments.contains("timeout_ms"))
        {
            RequireNonNegativeInteger(arguments, "timeout_ms", "run_to_user_code");
            params["timeout_ms"] = arguments["timeout_ms"].get<long long>();
        }

        ToolResult result;
        result.structuredContent = link->Call("trace.run_to_user_code", params, RequestTimeoutMs(params));
        result.text = FormatPauseResult(result.structuredContent);
        return result;
    };
    registry.Add(std::move(runToUserCode));

    Tool codeCoverage;
    codeCoverage.name = "code_coverage";
    codeCoverage.description =
        "Record which addresses in the debuggee were executed and how "
        "many times, then read the counts back. 'enable' turns on "
        "recording for the memory page containing 'address'; 'disable' "
        "turns it off for that page; 'read' returns the recorded hit "
        "counts for the range ['start', 'start' + 'size']. Usage: "
        "enable coverage for a region, run or trace the program, then "
        "read it. WHY THIS MATTERS for unpacking and virtualised code: "
        "addresses that turn out to have been executed but are not "
        "recognized as code reveal where the real code lives after "
        "unpacking, and hit counts expose the dispatch loop of a "
        "virtual machine — the handler dispatcher is the address with "
        "by far the most hits, since it runs once per virtual "
        "instruction. 'granularity' controls what is recorded per byte: "
        "'bit' only records whether a byte was executed at all; 'byte' "
        "and 'word' also keep a hit counter, which is what makes a "
        "dispatch loop visible — 'byte' is the default and the right "
        "choice unless memory for the coverage map is a concern. LIMIT: "
        "coverage is tracked per memory PAGE, so enabling it for one "
        "address enables it for the whole page that contains it. "
        "'read' is limited in range and in the number of entries it "
        "returns; the result says when it was truncated, and addresses "
        "that were never executed are omitted entirely. Parameters: "
        "'action' — 'enable', 'disable', or 'read'; 'address' — address "
        "inside the page to toggle, required for 'enable' and "
        "'disable'; 'granularity' — 'bit', 'byte', or 'word', used only "
        "by 'enable', defaults to 'byte'; 'start' and 'size' — range to "
        "read, both required for 'read'.";
    codeCoverage.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"action", {
                {"type", "string"},
                {"enum", nlohmann::json::array({"enable", "disable", "read"})},
                {"description",
                 "'enable' turns coverage on for a page, 'disable' turns it off, "
                 "'read' returns recorded hit counts for a range."}
            }},
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Address inside the page to toggle coverage for, given as a "
                 "number (not a hex string). Required for 'enable' and 'disable'."}
            }},
            {"granularity", {
                {"type", "string"},
                {"enum", nlohmann::json::array({"bit", "byte", "word"})},
                {"default", "byte"},
                {"description",
                 "'bit' only records whether a byte was executed; 'byte' and "
                 "'word' also keep a hit counter, which is what reveals a virtual "
                 "machine's dispatch loop. Used only by 'enable', defaults to 'byte'."}
            }},
            {"start", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Start address of the range to read coverage for. Required for 'read'."}
            }},
            {"size", {
                {"type", "integer"},
                {"minimum", 1},
                {"description", "Size in bytes of the range to read coverage for. Required for 'read'."}
            }}
        }},
        {"required", nlohmann::json::array({"action"})},
        {"allOf", nlohmann::json::array({
            {
                {"if", {
                    {"properties", {{"action", {{"const", "enable"}}}}},
                    {"required", nlohmann::json::array({"action"})}
                }},
                {"then", {{"required", nlohmann::json::array({"action", "address"})}}}
            },
            {
                {"if", {
                    {"properties", {{"action", {{"const", "disable"}}}}},
                    {"required", nlohmann::json::array({"action"})}
                }},
                {"then", {{"required", nlohmann::json::array({"action", "address"})}}}
            },
            {
                {"if", {
                    {"properties", {{"action", {{"const", "read"}}}}},
                    {"required", nlohmann::json::array({"action"})}
                }},
                {"then", {{"required", nlohmann::json::array({"action", "start", "size"})}}}
            }
        })},
        {"additionalProperties", false}
    };
    codeCoverage.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("code_coverage: plugin link is not configured");

        const std::string action =
            RequireEnumString(arguments, "action", {"enable", "disable", "read"}, "code_coverage");

        ToolResult result;
        if (action == "enable" || action == "disable")
        {
            RequireNonNegativeInteger(arguments, "address", "code_coverage");
            const std::uint64_t address = arguments["address"].get<std::uint64_t>();

            nlohmann::json params = {{"address", address}};
            std::string granularity = "byte";
            if (action == "enable")
            {
                if (arguments.contains("granularity"))
                    granularity = RequireEnumString(arguments, "granularity", {"bit", "byte", "word"}, "code_coverage");
                params["granularity"] = granularity;
            }

            result.structuredContent = link->Call(action == "enable" ? "coverage.enable" : "coverage.disable", params);
            result.text = FormatCoverageToggleResult(action, address, granularity);
        }
        else
        {
            RequireNonNegativeInteger(arguments, "start", "code_coverage");
            if (!arguments.contains("size") || !arguments["size"].is_number_integer() ||
                arguments["size"].get<long long>() < 1)
                throw ToolError("code_coverage: 'size' must be a positive integer");
            const std::uint64_t start = arguments["start"].get<std::uint64_t>();
            const long long size = arguments["size"].get<long long>();

            result.structuredContent = link->Call("coverage.read", {
                {"start", start},
                {"size", size}
            }, kSlowToolRequestTimeoutMs);
            result.text = FormatCoverageRead(result.structuredContent);
        }
        return result;
    };
    registry.Add(std::move(codeCoverage));

    Tool listSymbols;
    listSymbols.name = "list_symbols";
    listSymbols.description =
        "List the symbols of a module — imports, exports, and any symbols "
        "loaded from debug information — together with their addresses. "
        "Identify the module either by 'module' (its name) or by 'address' "
        "(any address that falls inside it); exactly one of the two must be "
        "given. Use this tool to find the address of a function by name, to "
        "discover which API a module imports, or to get an overview of what "
        "a module offers. 'filter' matches part of a symbol's name "
        "case-insensitively, which is the practical way to search a large "
        "system library instead of scanning its whole symbol table. "
        "'max_results' caps the number of symbols returned, defaulting to "
        "1000; the result's 'truncated' field, and the human-readable text, "
        "say plainly when the list was truncated. Symbols come from what "
        "the debugger has already loaded: a module without debug "
        "information shows only its imports and exports. Requires an "
        "active debugging session; fails if no module matches 'module' or "
        "'address'.";
    listSymbols.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Any address inside the module, given as a number (not a hex "
                 "string). Mutually exclusive with 'module'."}
            }},
            {"module", {
                {"type", "string"},
                {"description", "Name of the module to list symbols of, e.g. 'ntdll.dll'. Mutually exclusive with 'address'."}
            }},
            {"filter", {
                {"type", "string"},
                {"description",
                 "Case-insensitive substring to match against symbol names; only "
                 "matching symbols are returned. Omit to list every symbol."}
            }},
            {"max_results", {
                {"type", "integer"},
                {"minimum", 1},
                {"default", 1000},
                {"description", "Maximum number of symbols to return. Defaults to 1000."}
            }}
        }},
        {"anyOf", nlohmann::json::array({
            { {"required", nlohmann::json::array({"address"})} },
            { {"required", nlohmann::json::array({"module"})} }
        })},
        {"additionalProperties", false}
    };
    listSymbols.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("list_symbols: plugin link is not configured");

        if (!arguments.contains("address") && !arguments.contains("module"))
            throw ToolError("list_symbols: either 'address' or 'module' must be provided");

        nlohmann::json params = nlohmann::json::object();
        if (arguments.contains("address"))
        {
            RequireNonNegativeInteger(arguments, "address", "list_symbols");
            params["address"] = arguments["address"].get<std::uint64_t>();
        }
        if (arguments.contains("module"))
        {
            if (!arguments["module"].is_string())
                throw ToolError("list_symbols: 'module' must be a string");
            params["module"] = arguments["module"].get<std::string>();
        }
        if (arguments.contains("filter"))
        {
            if (!arguments["filter"].is_string())
                throw ToolError("list_symbols: 'filter' must be a string");
            params["filter"] = arguments["filter"].get<std::string>();
        }
        long long maxResults = 1000;
        if (arguments.contains("max_results"))
        {
            if (!arguments["max_results"].is_number_integer() || arguments["max_results"].get<long long>() < 1)
                throw ToolError("list_symbols: 'max_results' must be a positive integer");
            maxResults = arguments["max_results"].get<long long>();
        }
        params["max_results"] = maxResults;

        ToolResult result;
        result.structuredContent = link->Call("symbols.list", params);
        const nlohmann::json symbols = result.structuredContent.value("symbols", nlohmann::json::array());
        result.text = FormatSymbolList(symbols, result.structuredContent.value("truncated", false));
        return result;
    };
    registry.Add(std::move(listSymbols));

    Tool annotate;
    annotate.name = "annotate";
    annotate.description =
        "Read or write the debugger's own annotations at an address: a "
        "label (a name shown in place of the address), a comment (free "
        "text shown beside the instruction), and a bookmark (a marked "
        "position). WHY THIS MATTERS: these are stored in x64dbg's "
        "database for the analysed program and persist across sessions, "
        "so naming a function once its purpose is understood, or writing "
        "down a conclusion as a comment, makes that finding part of the "
        "project rather than something only visible in the current "
        "conversation. Use action 'get' to read the annotations currently "
        "at 'address'; use action 'set' to write them — at least one of "
        "'label', 'comment', or 'bookmark' must be given for 'set'. An "
        "empty string for 'label' or 'comment' CLEARS that annotation "
        "instead of setting it. Recommended practice: label a function as "
        "soon as its purpose is understood, and comment the instruction "
        "that made it clear. LIMITS: requires an active debugging "
        "session; a label replaces the name displayed for that address "
        "everywhere in the debugger (disassembly, call stacks, breakpoint "
        "lists, and so on), so choose names that will still make sense "
        "later.";
    annotate.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"action", {
                {"type", "string"},
                {"enum", nlohmann::json::array({"get", "set"})},
                {"description", "'get' reads the annotations at 'address', 'set' writes them."}
            }},
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description", "Address to read or write annotations for, given as a number (not a hex string)."}
            }},
            {"label", {
                {"type", "string"},
                {"description",
                 "New label for the address. An empty string clears the existing "
                 "label. Only used, and optional, with action 'set'."}
            }},
            {"comment", {
                {"type", "string"},
                {"description",
                 "New comment for the address. An empty string clears the existing "
                 "comment. Only used, and optional, with action 'set'."}
            }},
            {"bookmark", {
                {"type", "boolean"},
                {"description",
                 "Whether a bookmark should be set (true) or cleared (false) at the "
                 "address. Only used, and optional, with action 'set'."}
            }}
        }},
        {"required", nlohmann::json::array({"action", "address"})},
        {"additionalProperties", false}
    };
    annotate.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("annotate: plugin link is not configured");

        const std::string action = RequireEnumString(arguments, "action", {"get", "set"}, "annotate");
        RequireNonNegativeInteger(arguments, "address", "annotate");
        const std::uint64_t address = arguments["address"].get<std::uint64_t>();

        ToolResult result;
        if (action == "get")
        {
            result.structuredContent = link->Call("annotations.get", {{"address", address}});
            result.text = FormatAnnotationsGet(result.structuredContent);
        }
        else
        {
            const bool hasLabel = arguments.contains("label");
            const bool hasComment = arguments.contains("comment");
            const bool hasBookmark = arguments.contains("bookmark");
            if (!hasLabel && !hasComment && !hasBookmark)
                throw ToolError("annotate: 'set' requires at least one of 'label', 'comment', 'bookmark'");

            std::string label, comment;
            bool bookmark = false;

            nlohmann::json params = {{"address", address}};
            if (hasLabel)
            {
                if (!arguments["label"].is_string())
                    throw ToolError("annotate: 'label' must be a string");
                label = arguments["label"].get<std::string>();
                params["label"] = label;
            }
            if (hasComment)
            {
                if (!arguments["comment"].is_string())
                    throw ToolError("annotate: 'comment' must be a string");
                comment = arguments["comment"].get<std::string>();
                params["comment"] = comment;
            }
            if (hasBookmark)
            {
                if (!arguments["bookmark"].is_boolean())
                    throw ToolError("annotate: 'bookmark' must be a boolean");
                bookmark = arguments["bookmark"].get<bool>();
                params["bookmark"] = bookmark;
            }

            result.structuredContent = link->Call("annotations.set", params);
            result.text = FormatAnnotationsSet(address, hasLabel, label, hasComment, comment, hasBookmark, bookmark);
        }
        return result;
    };
    registry.Add(std::move(annotate));

    Tool listHandles;
    listHandles.name = "list_handles";
    listHandles.description =
        "List the kernel objects the debugged process currently has open: "
        "files, registry keys, mutexes, events, semaphores, and other "
        "processes, each with its handle value, type, and, where the "
        "debugger can resolve it, its name. Use it to see which files a "
        "program touched, to spot a single-instance mutex that gates a "
        "second launch, or to notice that it opened another process — a "
        "sign of injection or interprocess control. An empty name is "
        "normal, NOT an error: many kernel objects (anonymous events, "
        "unnamed sections and mutexes) simply have no name, and the "
        "debugger could not have resolved one that does not exist. "
        "Requires an active debugging session. The list is capped at the "
        "plugin's limit; when the cap is hit, 'truncated' is true and the "
        "human-readable text says so. Takes no parameters.";
    listHandles.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", nlohmann::json::object()},
        {"additionalProperties", false}
    };
    listHandles.handler = [link](const nlohmann::json& /*arguments*/) -> ToolResult
    {
        if (!link)
            throw ToolError("list_handles: plugin link is not configured");

        ToolResult result;
        result.structuredContent = link->Call("process.handles", nlohmann::json::object());
        const nlohmann::json handles = result.structuredContent.value("handles", nlohmann::json::array());
        result.text = FormatHandleList(handles, result.structuredContent.value("truncated", false));
        return result;
    };
    registry.Add(std::move(listHandles));

    Tool listWindows;
    listWindows.name = "list_windows";
    listWindows.description =
        "List the windows belonging to the debugged process, each with its "
        "handle, title, class name, owning thread identifier, window "
        "procedure address, style flags, and position on screen. Use it to "
        "connect a visible dialog or control to the code behind it: the "
        "window procedure address is the entry point for that window's "
        "message handling, and is exactly where a breakpoint goes when "
        "investigating what happens when a button is clicked or a message "
        "is received. A console application or a background service "
        "legitimately has no windows at all; an empty result is normal, "
        "not an error. Requires an active debugging session. The list is "
        "capped at the plugin's limit; when the cap is hit, 'truncated' is "
        "true and the human-readable text says so. Takes no parameters.";
    listWindows.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", nlohmann::json::object()},
        {"additionalProperties", false}
    };
    listWindows.handler = [link](const nlohmann::json& /*arguments*/) -> ToolResult
    {
        if (!link)
            throw ToolError("list_windows: plugin link is not configured");

        ToolResult result;
        result.structuredContent = link->Call("process.windows", nlohmann::json::object());
        const nlohmann::json windows = result.structuredContent.value("windows", nlohmann::json::array());
        result.text = FormatWindowList(windows, result.structuredContent.value("truncated", false));
        return result;
    };
    registry.Add(std::move(listWindows));

    Tool listConnections;
    listConnections.name = "list_connections";
    listConnections.description =
        "List the debugged process's active TCP connections, each with the "
        "local address and port, the remote address and port, and the "
        "connection state. Use it to find out where a program connects "
        "over the network; combined with a breakpoint on a networking API "
        "(for example connect or send), this identifies the exact code "
        "responsible for a given connection. Reports TCP connections only, "
        "not UDP. A program that does not use the network legitimately has "
        "none; an empty result is normal, not an error. Requires an "
        "active debugging session. The list is capped at the plugin's "
        "limit; when the cap is hit, 'truncated' is true and the "
        "human-readable text says so. Takes no parameters.";
    listConnections.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", nlohmann::json::object()},
        {"additionalProperties", false}
    };
    listConnections.handler = [link](const nlohmann::json& /*arguments*/) -> ToolResult
    {
        if (!link)
            throw ToolError("list_connections: plugin link is not configured");

        ToolResult result;
        result.structuredContent = link->Call("process.connections", nlohmann::json::object());
        const nlohmann::json connections = result.structuredContent.value("connections", nlohmann::json::array());
        result.text = FormatConnectionList(connections, result.structuredContent.value("truncated", false));
        return result;
    };
    registry.Add(std::move(listConnections));

    Tool sehChain;
    sehChain.name = "seh_chain";
    sehChain.description =
        "Show the chain of structured exception handlers (SEH) registered "
        "for the current thread, each with the exception registration "
        "record's address on the stack and the address of its handler "
        "function. Exception-based control flow and anti-debugging both "
        "lean on handlers: code that installs a handler and then "
        "deliberately triggers a fault hides its real logic inside that "
        "handler, invisible to a straightforward disassembly of the "
        "surrounding code. This tool shows where that handler lives so it "
        "can be disassembled or broken on directly. Requires the process "
        "to be paused, since the chain is read off the current thread's "
        "stack; it reflects the current thread only, not every thread in "
        "the process. 64-bit Windows uses table-based exception handling "
        "instead of the classic FS:[0] linked list this tool walks, so "
        "this result is mainly meaningful for 32-bit (x86) targets — an "
        "empty chain on a 64-bit target does not mean the process has no "
        "exception handlers, and the human-readable text says so "
        "explicitly rather than leaving the model to draw that conclusion "
        "from an empty list. On top of that, x64dbg itself does not "
        "implement a stack-walked SEH chain in its 64-bit build at all, so "
        "on x64 this tool ALWAYS returns an empty chain regardless of the "
        "target — an empty result there is not evidence of anything. Takes "
        "no parameters.";
    sehChain.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", nlohmann::json::object()},
        {"additionalProperties", false}
    };
    sehChain.handler = [link](const nlohmann::json& /*arguments*/) -> ToolResult
    {
        if (!link)
            throw ToolError("seh_chain: plugin link is not configured");

        ToolResult result;
        result.structuredContent = link->Call("process.seh_chain", nlohmann::json::object());
        const nlohmann::json entries = result.structuredContent.value("entries", nlohmann::json::array());
        result.text = FormatSehChain(entries);
        return result;
    };
    registry.Add(std::move(sehChain));

    Tool listProcesses;
    listProcesses.name = "list_processes";
    listProcesses.description =
        "List the processes currently running on the system, each with its "
        "process identifier (PID), executable file name, main window "
        "title, and full command line. Its purpose is finding a target "
        "process to attach to: use it before attach_process to look up "
        "the PID of the process to attach to. Unlike most tools in this "
        "server, it does NOT require an active debugging session — it "
        "reports on every process on the system, not just the one being "
        "debugged. A console application or background service "
        "legitimately has no main window; an empty title is normal, not "
        "an error. The list is capped at the plugin's limit; when the cap "
        "is hit, 'truncated' is true and the human-readable text says so. "
        "Takes no parameters.";
    listProcesses.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", nlohmann::json::object()},
        {"additionalProperties", false}
    };
    listProcesses.handler = [link](const nlohmann::json& /*arguments*/) -> ToolResult
    {
        if (!link)
            throw ToolError("list_processes: plugin link is not configured");

        ToolResult result;
        result.structuredContent = link->Call("process.list", nlohmann::json::object());
        const nlohmann::json processes = result.structuredContent.value("processes", nlohmann::json::array());
        result.text = FormatProcessList(processes, result.structuredContent.value("truncated", false));
        return result;
    };
    registry.Add(std::move(listProcesses));

    Tool attachProcess;
    attachProcess.name = "attach_process";
    attachProcess.description =
        "Attach the debugger to an already-running process and wait for "
        "it to stop, so it can be inspected the same way as a process "
        "launched from x64dbg. Use list_processes first to find the PID "
        "of the process to attach to. Returns the same paused-state shape "
        "as debug_control and wait_until_paused: 'paused', 'timed_out', "
        "'pause_reason', and 'status'. If the wait times out, 'timed_out' "
        "is true and the process keeps running under the debugger; call "
        "wait_until_paused to keep waiting. Constraints: fails if a "
        "debugging session is already active — detach or stop it first; "
        "the target must be attachable, meaning it matches this debugger "
        "build's architecture (32-bit vs 64-bit) and this process has "
        "sufficient privileges to attach to it; attaching freezes the "
        "target for as long as it stays paused, so anything relying on it "
        "(its UI, its network connections) stalls while the debugger "
        "holds it. SAFETY: once attached, debug_control with action "
        "'stop' TERMINATES the process — including this one, which the "
        "tool did not start and which was already running beforehand. To "
        "inspect a process and leave it running afterwards, use "
        "detach_process instead of debug_control's 'stop'. Parameters: "
        "'pid' — the process identifier to attach to, as reported by "
        "list_processes; 'timeout_ms' — maximum time to wait for the "
        "process to pause, in milliseconds; if omitted, the plugin's "
        "default timeout is used.";
    attachProcess.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"pid", {
                {"type", "integer"},
                {"minimum", 1},
                {"description", "Process identifier (PID) to attach to, as reported by list_processes."}
            }},
            {"timeout_ms", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Maximum time to wait for the process to pause, in milliseconds. If "
                 "omitted, the plugin's default timeout is used."}
            }}
        }},
        {"required", nlohmann::json::array({"pid"})},
        {"additionalProperties", false}
    };
    attachProcess.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("attach_process: plugin link is not configured");

        if (!arguments.contains("pid") || !arguments["pid"].is_number_integer() ||
            arguments["pid"].get<long long>() < 1)
            throw ToolError("attach_process: 'pid' is required and must be a positive integer");
        const long long pid = arguments["pid"].get<long long>();

        nlohmann::json params = {{"pid", pid}};
        if (arguments.contains("timeout_ms"))
        {
            RequireNonNegativeInteger(arguments, "timeout_ms", "attach_process");
            params["timeoutMs"] = arguments["timeout_ms"].get<long long>();
        }

        ToolResult result;
        result.structuredContent = link->Call("debug.attach", params, RequestTimeoutMs(arguments));
        result.text = FormatPauseResult(result.structuredContent);
        return result;
    };
    registry.Add(std::move(attachProcess));

    Tool detachProcess;
    detachProcess.name = "detach_process";
    detachProcess.description =
        "Detach the debugger from the debuggee, leaving it running "
        "exactly as it would without a debugger attached — unlike "
        "debug_control's 'stop' action, which TERMINATES the process. "
        "Detaching removes all breakpoints first, since a software "
        "breakpoint left behind would crash the target the next time "
        "execution reached that address with no debugger there to catch "
        "it. Use this after attach_process when the goal was only to "
        "inspect a running process and it should keep running "
        "afterwards. Requires an active debugging session. Takes no "
        "parameters.";
    detachProcess.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", nlohmann::json::object()},
        {"additionalProperties", false}
    };
    detachProcess.handler = [link](const nlohmann::json& /*arguments*/) -> ToolResult
    {
        if (!link)
            throw ToolError("detach_process: plugin link is not configured");

        ToolResult result;
        result.structuredContent = link->Call("debug.detach", nlohmann::json::object());
        result.text = FormatDetachResult();
        return result;
    };
    registry.Add(std::move(detachProcess));

    Tool allocateMemory;
    allocateMemory.name = "allocate_memory";
    allocateMemory.description =
        "Allocate a block of memory inside the debugged process and "
        "return its address. The memory is readable, writable, and "
        "executable, so it can hold injected code as well as data — for "
        "example a buffer to redirect a pointer at, scratch space for a "
        "script, or a small stub to jump to. Requires an active debugging "
        "session. The allocation belongs to the debuggee: it lives only "
        "as long as the process does, and disappears (like all its other "
        "memory) when the process exits. 'address', if given, is only a "
        "preferred base — the allocation may still land elsewhere if that "
        "address is unavailable; always use the address this tool "
        "returns, not the one requested. Allocates at most 268435456 bytes "
        "(256 MiB) per call. Parameters: 'size' — the number of bytes to "
        "allocate, from 1 up to 268435456; 'address' — an optional "
        "non-negative integer giving a preferred base address (0 or "
        "omitted means let the debugger choose).";
    allocateMemory.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"size", {
                {"type", "integer"},
                {"minimum", 1},
                {"maximum", 268435456},
                {"description", "Number of bytes to allocate, from 1 up to 268435456 (256 MiB) per call."}
            }},
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Preferred base address, given as a number (not a hex string). 0 "
                 "or omitted means let the debugger choose an address."}
            }}
        }},
        {"required", nlohmann::json::array({"size"})},
        {"additionalProperties", false}
    };
    allocateMemory.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("allocate_memory: plugin link is not configured");

        if (!arguments.contains("size") || !arguments["size"].is_number_integer() ||
            arguments["size"].get<long long>() < 1)
            throw ToolError("allocate_memory: 'size' is required and must be a positive integer");
        const long long size = arguments["size"].get<long long>();

        nlohmann::json params = {{"size", size}};
        if (arguments.contains("address"))
        {
            RequireNonNegativeInteger(arguments, "address", "allocate_memory");
            params["address"] = arguments["address"].get<std::uint64_t>();
        }

        ToolResult result;
        result.structuredContent = link->Call("memory.allocate", params);
        result.text = FormatAllocateMemoryResult(result.structuredContent);
        return result;
    };
    registry.Add(std::move(allocateMemory));

    Tool freeMemory;
    freeMemory.name = "free_memory";
    freeMemory.description =
        "Free memory previously allocated with allocate_memory. 'address' "
        "must be exactly the base address returned by that allocation, "
        "not an arbitrary address inside the allocated region — freeing "
        "anything else, including memory the debuggee itself allocated, "
        "corrupts the process's heap and will likely crash it. Requires "
        "an active debugging session. Parameters: 'address' — the base "
        "address of the allocation to free, as returned by "
        "allocate_memory.";
    freeMemory.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description",
                 "Base address of the allocation to free, given as a number (not a "
                 "hex string), as returned by allocate_memory."}
            }}
        }},
        {"required", nlohmann::json::array({"address"})},
        {"additionalProperties", false}
    };
    freeMemory.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("free_memory: plugin link is not configured");

        RequireNonNegativeInteger(arguments, "address", "free_memory");
        const std::uint64_t address = arguments["address"].get<std::uint64_t>();

        ToolResult result;
        result.structuredContent = link->Call("memory.free", {{"address", address}});
        result.text = FormatFreeMemoryResult(address);
        return result;
    };
    registry.Add(std::move(freeMemory));

    Tool dumpMemory;
    dumpMemory.name = "dump_memory";
    dumpMemory.description =
        "Write a region of the debuggee's memory to a file on disk, byte "
        "for byte. Use it to carve out an unpacked image, a decrypted "
        "buffer, or an embedded resource for offline analysis with tools "
        "outside the debugger. For anything small enough to inspect "
        "directly, read_memory is the better choice — it returns the "
        "bytes straight to the model instead of round-tripping through a "
        "file; dump_memory is for large regions and for handing data to "
        "external tools. Requires an active debugging session; the "
        "address range must be mapped and readable. Dumps at most "
        "268435456 bytes (256 MiB) per call. 'path' is a path on the "
        "machine running x64dbg, not inside the debuggee, and an existing "
        "file at that path is overwritten without warning. Parameters: "
        "'address' — a non-negative integer giving the starting address "
        "to dump (a number, not a hex string); 'size' — the number of "
        "bytes to dump, from 1 up to 268435456; 'path' — the destination "
        "file path.";
    dumpMemory.inputSchema = {
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"type", "object"},
        {"properties", {
            {"address", {
                {"type", "integer"},
                {"minimum", 0},
                {"description", "Starting address to dump, given as a number (not a hex string)."}
            }},
            {"size", {
                {"type", "integer"},
                {"minimum", 1},
                {"maximum", 268435456},
                {"description", "Number of bytes to dump, from 1 up to 268435456 (256 MiB) per call."}
            }},
            {"path", {
                {"type", "string"},
                {"description", "Destination file path on the machine running x64dbg. An existing file is overwritten."}
            }}
        }},
        {"required", nlohmann::json::array({"address", "size", "path"})},
        {"additionalProperties", false}
    };
    dumpMemory.handler = [link](const nlohmann::json& arguments) -> ToolResult
    {
        if (!link)
            throw ToolError("dump_memory: plugin link is not configured");

        RequireNonNegativeInteger(arguments, "address", "dump_memory");
        if (!arguments.contains("size") || !arguments["size"].is_number_integer())
            throw ToolError("dump_memory: 'size' must be a positive integer");
        const long long size = arguments["size"].get<long long>();
        if (size < 1 || size > 268435456)
            throw ToolError("dump_memory: 'size' must be between 1 and 268435456 bytes (256 MiB)");
        if (!arguments.contains("path") || !arguments["path"].is_string())
            throw ToolError("dump_memory: 'path' is required and must be a string");

        const std::uint64_t address = arguments["address"].get<std::uint64_t>();
        const std::string path = arguments["path"].get<std::string>();

        ToolResult result;
        result.structuredContent = link->Call("memory.dump", {
            {"address", address},
            {"size", size},
            {"path", path}
        });
        result.text = FormatDumpMemoryResult(result.structuredContent, address);
        return result;
    };
    registry.Add(std::move(dumpMemory));
}

void RegisterDebuggerResources(ResourceRegistry& registry, std::shared_ptr<PluginLink> link)
{
    Resource memoryMap;
    memoryMap.uri = "x64dbg://memory-map";
    memoryMap.name = "memory_map";
    memoryMap.title = "Memory map";
    memoryMap.description =
        "The debuggee's memory regions with their base address, size, "
        "state, type, and access protection, formatted the same way as "
        "the memory_map tool. Empty when nothing is currently being "
        "debugged.";
    memoryMap.mimeType = "text/plain";
    memoryMap.read = [link]() -> std::string
    {
        if (!link)
            return "No connection to the x64dbg-mcp plugin. Start x64dbg with the "
                   "x64dbg-mcp plugin installed to see the memory map.";

        const nlohmann::json result = link->Call("memory.map", nlohmann::json::object());
        const nlohmann::json regions = result.value("regions", nlohmann::json::array());
        return FormatMemoryMap(regions);
    };
    registry.Add(std::move(memoryMap));

    Resource currentDisassembly;
    currentDisassembly.uri = "x64dbg://disassembly/current";
    currentDisassembly.name = "current_disassembly";
    currentDisassembly.title = "Disassembly at the current instruction";
    currentDisassembly.description =
        "Disassembly of the 32 instructions starting at the current "
        "instruction pointer, formatted the same way as the disassemble "
        "tool. Explains instead of failing when there is no debugging "
        "session or the process is currently running.";
    currentDisassembly.mimeType = "text/plain";
    currentDisassembly.read = [link]() -> std::string
    {
        if (!link)
            return "No connection to the x64dbg-mcp plugin. Start x64dbg with the "
                   "x64dbg-mcp plugin installed to see the current disassembly.";

        const nlohmann::json status = link->Call("debugger.status", nlohmann::json::object());
        if (!status.value("debugging", false))
            return "Not debugging. Open or attach to a process in x64dbg to see the current disassembly.";
        if (status.value("running", false))
            return "The process is running. Pause it to disassemble at the current instruction pointer.";

        const std::uint64_t cip = status.value("cip", 0ULL);
        const nlohmann::json instructions = link->Call("disasm", {
            {"address", cip},
            {"count", 32}
        });
        return FormatDisasmListing(instructions);
    };
    registry.Add(std::move(currentDisassembly));

    Resource commandReference;
    commandReference.uri = "x64dbg://commands";
    commandReference.name = "x64dbg_commands";
    commandReference.title = "x64dbg command reference";
    commandReference.description =
        "Every command the debugger accepts, generated from x64dbg's own "
        "command registrations: primary name, aliases, and whether it "
        "requires an active debugging session. Look up a command and its "
        "argument syntax here instead of guessing it. Static and compiled "
        "into the server, so it is available even when nothing is being "
        "debugged.";
    commandReference.mimeType = "text/plain";
    commandReference.read = []() -> std::string
    {
        return kX64dbgCommandReference;
    };
    registry.Add(std::move(commandReference));
}

} // namespace x64dbg_mcp::bridge
