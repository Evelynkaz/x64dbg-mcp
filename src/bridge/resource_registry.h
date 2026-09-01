#pragma once

#include "nlohmann/json.hpp"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace x64dbg_mcp::bridge
{

class PluginLink;

// Description of a single resource exposed to the model via resources/list
// and resources/read. Unlike a tool, a resource takes no arguments — it is
// meant to be pinned as context by the client rather than invoked.
struct Resource
{
    std::string uri;
    std::string name;         // programmatic name
    std::string title;        // human-readable
    std::string description;
    std::string mimeType;
    std::function<std::string()> read;   // returns the text content
};

class ResourceRegistry
{
public:
    void Add(Resource resource);
    const Resource* Find(const std::string& uri) const;
    nlohmann::json ListJson() const; // array of descriptions for the resources/list response
    size_t Size() const;

private:
    std::vector<Resource> resources_;
};

// Creates a registry with the server's default set of resources, including
// debugger resources that talk to the plugin through link. link may be
// empty (nullptr) — in that case a resource read explains that no plugin
// is connected, rather than throwing.
ResourceRegistry CreateDefaultResourceRegistry(std::shared_ptr<PluginLink> link = nullptr);

} // namespace x64dbg_mcp::bridge
