#include "bridge/debugger_prompts.h"

namespace x64dbg_mcp::bridge
{

namespace
{

// Returns the named argument as a string if it was actually supplied
// (present, a string, and non-empty); otherwise an empty string, so callers
// can fall back to text that still reads correctly rather than
// interpolating an empty placeholder.
std::string GetArgument(const nlohmann::json& arguments, const std::string& name)
{
    if (arguments.is_object() && arguments.contains(name) && arguments[name].is_string())
        return arguments[name].get<std::string>();
    return {};
}

std::string RenderAnalyzeFunction(const nlohmann::json& arguments)
{
    const std::string address = GetArgument(arguments, "address");
    const std::string target = address.empty()
        ? "the function containing the current instruction pointer"
        : ("the function at " + address);

    return
        "Analyze " + target + ".\n\n"
        "1. Call debugger_status to confirm a debugging session exists and is "
        "paused; if it is running, call debug_control with action \"pause\" "
        "first. If \"address\" is not already a plain integer, resolve it "
        "with evaluate_expression (it accepts hex, decimal, registers, and "
        "module.symbol names such as an API name) and use the numeric value "
        "it returns for every tool below that takes an address — "
        "those tools take addresses as numbers, not hex strings.\n"
        "2. Call disassemble_function with that address to get the "
        "function's boundaries and full instruction listing in one call, "
        "instead of guessing its length and calling disassemble repeatedly. "
        "If it fails because the module has not been analyzed yet, run the "
        "\"analyse\" command with execute_command first.\n"
        "3. Call find_references on the function's start address to see "
        "every caller. If the result is empty because the module has not "
        "been xref-analyzed yet, run the \"analxrefs\" command with "
        "execute_command and retry.\n"
        "4. Read the disassembly for calls to imported functions. Use "
        "list_symbols on the owning module, or evaluate_expression on an "
        "API name, to resolve any address the disassembly does not already "
        "show a symbol for.\n"
        "5. Use read_string on any address the function references that "
        "could hold text, to recover embedded strings and error messages "
        "that hint at the function's purpose.\n"
        "6. Once the function's purpose is understood, record it with "
        "annotate: set a label naming the function and a comment at its "
        "entry point summarizing what it does, so the finding persists in "
        "the debugger's database across sessions.";
}

std::string RenderTraceToApiCall(const nlohmann::json& arguments)
{
    const std::string apiName = GetArgument(arguments, "api_name");
    const std::string target = apiName.empty() ? "the target API function" : apiName;

    return
        "Trace execution until it reaches " + target + ".\n\n"
        "1. Call debugger_status to confirm a debugging session exists and "
        "is paused; if it is running, call debug_control with action "
        "\"pause\" first.\n"
        "2. Call evaluate_expression with expression \"" + target + "\" to "
        "resolve its address. If it fails because the module exporting it "
        "is not loaded yet, use list_symbols on the owning module once it "
        "is loaded, or set a breakpoint on the module's entry point first "
        "with set_breakpoint and continue with step 3 once it is reached.\n"
        "3. Call set_breakpoint with the resolved numeric address (tool "
        "arguments take addresses as numbers, not hex strings), type "
        "\"software\", and a \"name\" identifying it (for example the API "
        "name), so it can be found again with list_breakpoints or removed "
        "with manage_breakpoint.\n"
        "4. Call debug_control with action \"run\" to resume the debuggee; "
        "it waits for a pause by default, so there is no need to call "
        "wait_until_paused separately unless \"wait\" was set to false.\n"
        "5. Once paused at the breakpoint, confirm it stopped at the "
        "intended call with debugger_status, then inspect the context with "
        "call_stack (who called it and from where), read_registers or "
        "read_stack (its arguments, per the target's calling convention), "
        "and evaluate_expression for any value that needs dereferencing.\n"
        "6. If the breakpoint is no longer needed, remove it with "
        "manage_breakpoint so it does not interfere with later execution.";
}

std::string RenderDefeatAntiDebugging(const nlohmann::json& arguments)
{
    const std::string technique = GetArgument(arguments, "technique");
    const std::string focus = technique.empty()
        ? "Check the common techniques below in order."
        : ("Focus first on " + technique + ", then check the other common techniques below.");

    return
        "Find and defeat the anti-debugging checks in the debuggee. " + focus + "\n\n"
        "1. Call debugger_status to confirm a debugging session exists and "
        "is paused.\n"
        "2. Check for the common user-mode checks by resolving each with "
        "evaluate_expression: \"kernel32.IsDebuggerPresent\", "
        "\"kernel32.CheckRemoteDebuggerPresent\", "
        "\"ntdll.NtQueryInformationProcess\", and "
        "\"kernel32.OutputDebugStringA\" (a debugger's presence changes its "
        "behavior). For each one that resolves, call find_references on "
        "its address to see whether and where the debuggee actually calls "
        "it; an import that is never referenced is not being used as a "
        "check.\n"
        "3. For each call site found, call set_breakpoint there, then "
        "debug_control with action \"run\" to reach it, and inspect the "
        "surrounding code with disassemble to see how the result is used "
        "(commonly a comparison and a conditional jump right after the "
        "call returns).\n"
        "4. To neutralize a check without touching code: step over the "
        "call with the step tool (mode \"over\"), then use set_register to "
        "force the return value the check's caller expects (for example "
        "clearing eax/rax so the process looks not-debugged). To "
        "neutralize it permanently: use assemble_at or write_memory to "
        "patch the comparison or the call itself; patches keeps a record "
        "you can list and revert later.\n"
        "5. For exception-based tricks (an installed handler that the "
        "program deliberately triggers a fault to reach): call seh_chain "
        "to list the registered handlers for the current thread, then "
        "disassemble each handler's code to see what it actually does.\n"
        "6. For timing-based tricks (measuring elapsed time around a "
        "region with rdtsc or GetTickCount and comparing against a "
        "threshold): find_references to the timing call, then apply the "
        "same technique as step 4 to the comparison that follows it.\n"
        "7. Record each check found and how it was defeated with annotate, "
        "so the same crackme does not need to be re-analyzed from scratch "
        "later.";
}

std::string RenderAnalyzeVirtualizedCode(const nlohmann::json& arguments)
{
    const std::string handlerAddress = GetArgument(arguments, "handler_address");
    const std::string entry = handlerAddress.empty()
        ? "First locate the VM's entry point: look for a function that reads "
          "a large flat structure and then loops, dispatching through a "
          "table indexed by a byte or word it just read — "
          "find_pattern and find_references around suspicious loops in "
          "disassemble_function output are the way to spot one."
        : ("Start from the known VM entry point at " + handlerAddress + ": if "
           "it is not already a plain integer, resolve it with "
           "evaluate_expression, then reach it with debug_control action "
           "\"run_to\" using that numeric address.");

    return
        "Analyze virtualized code. This workload runs into hundreds of "
        "thousands of instructions, so every step below relies on tracing "
        "that runs inside the debugger rather than one step per model "
        "call.\n\n"
        "1. Call debugger_status to confirm a debugging session exists and "
        "is paused. " + entry + "\n"
        "2. Call code_coverage with action \"enable\" on the region "
        "containing the dispatcher to record which addresses execute and "
        "how often. Then run or trace the program for a while (see step 3) "
        "and call code_coverage with action \"read\" over that range: the "
        "dispatcher itself is the address with by far the most hits, since "
        "it runs once per virtual instruction, and this is the fastest way "
        "to confirm you found it.\n"
        "3. Call trace_record with action \"start\" and a destination file "
        "path to capture the real, deobfuscated control flow for later "
        "study, then use debug_control or trace_until to actually run the "
        "code, then trace_record with action \"stop\" when done.\n"
        "4. Use trace_until with mode \"over\" and a condition such as "
        "\"rip == <dispatcher_address>\" (resolved as a numeric address, "
        "evaluated with evaluate_expression first if needed) to advance "
        "one virtual instruction at a time instead of single-stepping "
        "through every native instruction of a handler. It reports "
        "register and flag changes alongside the new state after each "
        "stop — read those diffs first, since a VM handler's "
        "meaning shows up in exactly what it changed.\n"
        "5. Use read_stack and evaluate_expression to inspect the VM's own "
        "context structure (its virtual registers, virtual instruction "
        "pointer, and virtual stack), and call_stack to see the native call "
        "chain that reached the dispatcher.\n"
        "6. As handlers are identified (for example one that adds two "
        "virtual registers), name them with annotate — a label "
        "on the handler's address and a comment describing its effect "
        "— so the growing map of the VM's instruction set "
        "persists across sessions instead of being re-derived every time.\n"
        "7. Once code_coverage shows which handler addresses actually ran, "
        "call disassemble_function on each one still unidentified to work "
        "out what it does, and repeat from step 4 to keep tracing.";
}

} // namespace

void RegisterDebuggerPrompts(PromptRegistry& registry)
{
    Prompt analyzeFunction;
    analyzeFunction.name = "analyze_function";
    analyzeFunction.title = "Analyze a function";
    analyzeFunction.description =
        "Starting procedure for understanding what a single function does: "
        "its boundaries, its callers, the APIs it calls, and any strings it "
        "references, ending with the finding recorded in the debugger's own "
        "database so it persists across sessions.";
    analyzeFunction.arguments = {
        { "address",
          "Address of the function to analyze, as x64dbg's expression "
          "evaluator would accept it (a hex number, a decimal number, or an "
          "expression such as an API name). If omitted, the function "
          "containing the current instruction pointer is analyzed instead.",
          false }
    };
    analyzeFunction.render = RenderAnalyzeFunction;
    registry.Add(std::move(analyzeFunction));

    Prompt traceToApiCall;
    traceToApiCall.name = "trace_to_api_call";
    traceToApiCall.title = "Trace execution to an API call";
    traceToApiCall.description =
        "Starting procedure for stopping execution exactly when the "
        "debuggee calls a chosen API function, then inspecting the call's "
        "arguments and caller.";
    traceToApiCall.arguments = {
        { "api_name",
          "Name of the API function to stop at, exactly as x64dbg's "
          "expression evaluator would resolve it, for example "
          "\"kernel32.CreateFileW\".",
          true }
    };
    traceToApiCall.render = RenderTraceToApiCall;
    registry.Add(std::move(traceToApiCall));

    Prompt defeatAntiDebugging;
    defeatAntiDebugging.name = "defeat_anti_debugging";
    defeatAntiDebugging.title = "Defeat anti-debugging checks";
    defeatAntiDebugging.description =
        "Starting procedure for finding and neutralizing anti-debugging "
        "checks: the common API-based checks, exception-based tricks, and "
        "timing-based tricks.";
    defeatAntiDebugging.arguments = {
        { "technique",
          "Optional hint about the suspected technique (for example "
          "\"IsDebuggerPresent\", \"timing check\", or \"SEH\"). If "
          "omitted, the common techniques are checked in order.",
          false }
    };
    defeatAntiDebugging.render = RenderDefeatAntiDebugging;
    registry.Add(std::move(defeatAntiDebugging));

    Prompt analyzeVirtualizedCode;
    analyzeVirtualizedCode.name = "analyze_virtualized_code";
    analyzeVirtualizedCode.title = "Analyze virtualized code";
    analyzeVirtualizedCode.description =
        "Starting procedure for reverse-engineering a code virtualization "
        "protector's VM: locating the dispatcher, tracing virtual "
        "instructions one at a time inside the debugger, and building a "
        "map of handler addresses to their effect.";
    analyzeVirtualizedCode.arguments = {
        { "handler_address",
          "Address of the VM's entry point or dispatch loop, if already "
          "known. If omitted, it is located first before proceeding.",
          false }
    };
    analyzeVirtualizedCode.render = RenderAnalyzeVirtualizedCode;
    registry.Add(std::move(analyzeVirtualizedCode));
}

} // namespace x64dbg_mcp::bridge
