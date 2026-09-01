#include "bridge/resource_registry.h"
#include "bridge/debugger_tools.h"

namespace x64dbg_mcp::bridge
{

void ResourceRegistry::Add(Resource resource)
{
    resources_.push_back(std::move(resource));
}

const Resource* ResourceRegistry::Find(const std::string& uri) const
{
    for (const auto& resource : resources_)
    {
        if (resource.uri == uri)
            return &resource;
    }
    return nullptr;
}

nlohmann::json ResourceRegistry::ListJson() const
{
    nlohmann::json list = nlohmann::json::array();
    for (const auto& resource : resources_)
    {
        list.push_back({
            {"uri", resource.uri},
            {"name", resource.name},
            {"title", resource.title},
            {"description", resource.description},
            {"mimeType", resource.mimeType}
        });
    }
    return list;
}

size_t ResourceRegistry::Size() const
{
    return resources_.size();
}

ResourceRegistry CreateDefaultResourceRegistry(std::shared_ptr<PluginLink> link)
{
    ResourceRegistry registry;
    RegisterDebuggerResources(registry, link);
    return registry;
}

} // namespace x64dbg_mcp::bridge
