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

// Выровненная таблица модулей: база, размер, точка входа, имя.
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

// Заголовок модуля, таблица его секций и, если запрошены, таблицы экспорта
// и импорта; при усечении списка отдельно сообщает о пределе в 4096 записей.
std::string FormatModuleInfo(const nlohmann::json& result, bool includeExports, bool includeImports)
{
    std::ostringstream out;
    const nlohmann::json module = result.value("module", nlohmann::json::object());
    const std::string name = module.value("name", std::string());
    const std::string path = module.value("path", std::string());

    // Числовые поля модуля печатаются как "unavailable", если их нет в
    // ответе плагина, вместо молчаливого нуля — иначе расхождение формата
    // между плагином и мостом (как было с плоским/вложенным JSON) снова
    // будет незаметно маскироваться нулями в тексте.
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

// Выровненная таблица регионов памяти: база, размер, состояние, тип, права,
// описание. В конце — число регионов и суммарный объём закреплённой (commit) памяти.
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

// Выровненная таблица потоков: идентификатор, текущий адрес, точка входа,
// приоритет, причина ожидания, имя; текущий поток отмечен звёздочкой.
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

// Печатает значение регистра в шестнадцатеричном виде независимо от того,
// пришло ли оно числом (обычные регистры) или строкой (широкие регистры
// SIMD, которые не помещаются в 64-битное целое JSON).
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

// Список регистров ({"name","value"}) в несколько колонок, чтобы группа
// регистров помещалась на экран целиком, а не растягивалась на много строк.
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

// Человекочитаемая сводка registers.read: регистры общего назначения в
// колонках, EFLAGS с перечнем установленных флагов, сегментные регистры,
// отладочные регистры (только если хотя бы один ненулевой), и, если
// запрошены, регистры SIMD по одному на строку.
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

// Таблица кадров стека вызовов: номер кадра, адрес возврата на стеке,
// откуда сделан вызов, куда он вёл, и комментарий отладчика.
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

// Таблица слов на вершине стека: адрес слота, значение, комментарий
// отладчика к этому значению (например, если это адрес возврата).
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
}

} // namespace x64dbg_mcp::bridge
