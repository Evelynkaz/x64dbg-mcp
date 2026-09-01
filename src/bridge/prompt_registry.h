#pragma once

#include "nlohmann/json.hpp"

#include <functional>
#include <string>
#include <vector>

namespace x64dbg_mcp::bridge
{

// Description of one argument a prompt accepts, advertised via prompts/list
// and validated by prompts/get.
struct PromptArgument
{
    std::string name;
    std::string description;
    bool required = false;
};

// Description of a single prompt exposed to the model via prompts/list and
// prompts/get. Unlike a tool, a prompt does not act on the debugger — it
// renders a block of instructions for the model to follow, with the
// caller's arguments interpolated into it.
struct Prompt
{
    std::string name;
    std::string title;
    std::string description;
    std::vector<PromptArgument> arguments;
    std::function<std::string(const nlohmann::json& arguments)> render; // returns the message text
};

class PromptRegistry
{
public:
    void Add(Prompt prompt);
    const Prompt* Find(const std::string& name) const;
    nlohmann::json ListJson() const; // array of descriptions for the prompts/list response
    size_t Size() const;

private:
    std::vector<Prompt> prompts_;
};

// Creates a registry with the server's default set of prompts: reusable
// starting procedures for the reverse-engineering workflows this server
// exists to support.
PromptRegistry CreateDefaultPromptRegistry();

} // namespace x64dbg_mcp::bridge
