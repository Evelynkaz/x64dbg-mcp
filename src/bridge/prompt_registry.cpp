#include "bridge/prompt_registry.h"
#include "bridge/debugger_prompts.h"

namespace x64dbg_mcp::bridge
{

void PromptRegistry::Add(Prompt prompt)
{
    prompts_.push_back(std::move(prompt));
}

const Prompt* PromptRegistry::Find(const std::string& name) const
{
    for (const auto& prompt : prompts_)
    {
        if (prompt.name == name)
            return &prompt;
    }
    return nullptr;
}

nlohmann::json PromptRegistry::ListJson() const
{
    nlohmann::json list = nlohmann::json::array();
    for (const auto& prompt : prompts_)
    {
        nlohmann::json arguments = nlohmann::json::array();
        for (const auto& argument : prompt.arguments)
        {
            arguments.push_back({
                {"name", argument.name},
                {"description", argument.description},
                {"required", argument.required}
            });
        }
        list.push_back({
            {"name", prompt.name},
            {"title", prompt.title},
            {"description", prompt.description},
            {"arguments", arguments}
        });
    }
    return list;
}

size_t PromptRegistry::Size() const
{
    return prompts_.size();
}

PromptRegistry CreateDefaultPromptRegistry()
{
    PromptRegistry registry;
    RegisterDebuggerPrompts(registry);
    return registry;
}

} // namespace x64dbg_mcp::bridge
