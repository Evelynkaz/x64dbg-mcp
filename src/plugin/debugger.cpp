#include "plugin/debugger.h"
#include "plugin/plugin.h"

namespace x64dbg_mcp::plugin
{

DebuggerStatus GetStatus()
{
    DebuggerStatus status;
    try
    {
#ifdef _WIN64
        status.pointerSize = 8;
#else
        status.pointerSize = 4;
#endif
        status.debugging = DbgIsDebugging();
        if (!status.debugging)
            return status;

        status.running = DbgIsRunning();
        status.processId = static_cast<unsigned int>(DbgGetProcessId());
        status.threadId = static_cast<unsigned int>(DbgGetThreadId());

        // cip осмысленен только когда процесс стоит на паузе — во время
        // выполнения DbgEval мог бы вернуть устаревшее или произвольное
        // значение, поэтому оставляем 0, как и задокументировано в заголовке.
        if (!status.running)
        {
            bool success = false;
            const duint cip = DbgEval("cip", &success);
            if (success)
            {
                status.cip = static_cast<unsigned long long>(cip);
                char moduleName[MAX_MODULE_SIZE] = {};
                if (DbgGetModuleAt(static_cast<duint>(cip), moduleName))
                    status.module = moduleName;
            }
        }
    }
    catch (...)
    {
    }
    return status;
}

bool ReadMemory(unsigned long long address, size_t size, std::vector<unsigned char>& out, std::string& error)
{
    out.clear();
    try
    {
        if (!DbgIsDebugging())
        {
            error = "Debugging is not active: start or attach to a process in x64dbg first";
            return false;
        }
        if (size == 0)
        {
            error = "Read size must be greater than zero";
            return false;
        }
        if (size > kMaxReadSize)
        {
            error = "Requested read size exceeds the maximum of 1 MiB";
            return false;
        }

        const duint addr = static_cast<duint>(address);
        if (!DbgMemIsValidReadPtr(addr))
        {
            error = "Address is not a valid readable pointer in the debuggee's memory";
            return false;
        }

        out.resize(size);
        if (!DbgMemRead(addr, out.data(), static_cast<duint>(size)))
        {
            out.clear();
            error = "Failed to read memory at the given address";
            return false;
        }
        return true;
    }
    catch (...)
    {
        out.clear();
        error = "Internal error while reading memory";
        return false;
    }
}

bool Disassemble(unsigned long long address, size_t count, std::vector<Instruction>& out, std::string& error)
{
    out.clear();
    try
    {
        if (!DbgIsDebugging())
        {
            error = "Debugging is not active: start or attach to a process in x64dbg first";
            return false;
        }
        if (count == 0)
        {
            error = "Instruction count must be greater than zero";
            return false;
        }
        if (count > kMaxInstructions)
        {
            error = "Requested instruction count exceeds the maximum of 256";
            return false;
        }

        duint addr = static_cast<duint>(address);
        for (size_t i = 0; i < count; ++i)
        {
            if (!DbgMemIsValidReadPtr(addr))
                break; // дальше по этому адресу нечего разбирать — отдаём то, что успели

            BASIC_INSTRUCTION_INFO basicInfo = {};
            DbgDisasmFastAt(addr, &basicInfo);
            if (basicInfo.size <= 0)
                break; // размер инструкции неизвестен — прекращаем разбор

            Instruction instruction;
            instruction.address = static_cast<unsigned long long>(addr);
            instruction.size = static_cast<size_t>(basicInfo.size);

            instruction.bytes.resize(instruction.size);
            if (!DbgMemRead(addr, instruction.bytes.data(), static_cast<duint>(instruction.size)))
                instruction.bytes.clear();

            char text[GUI_MAX_DISASSEMBLY_SIZE] = {};
            if (GuiGetDisassembly(addr, text))
                instruction.text = text;

            addr += static_cast<duint>(instruction.size);
            out.push_back(std::move(instruction));
        }

        if (out.empty())
        {
            error = "Address is not a valid readable pointer in the debuggee's memory";
            return false;
        }
        return true;
    }
    catch (...)
    {
        error = "Internal error while disassembling";
        return false;
    }
}

} // namespace x64dbg_mcp::plugin
