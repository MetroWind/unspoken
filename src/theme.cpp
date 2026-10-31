#include "theme.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <set>

#include <mw/utils.hpp>
#include <ryml.hpp>
#include <ryml_std.hpp>

namespace unspoken
{
namespace
{
bool validIdCharacter(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

bool validId(const std::string& id)
{
    return !id.empty()
        && std::all_of(id.begin(), id.end(), validIdCharacter);
}

mw::E<std::string> field(ryml::ConstNodeRef root, const char* key)
{
    auto node = root.find_child(ryml::to_csubstr(key));
    if(!node.readable()) return std::string{};
    if(!node.has_val() || node.val_is_null())
    {
        return std::unexpected(mw::runtimeError(
            "Theme fields must be strings"));
    }
    auto value = node.val();
    return std::string(value.str, value.len);
}
}

mw::E<void> ThemeManager::loadDir(const std::filesystem::path& dir)
{
    std::map<std::string, Theme> loaded;
    try
    {
        for(const auto& entry : std::filesystem::directory_iterator(dir))
        {
            if(!entry.is_directory()) continue;
            auto manifest = entry.path() / "info.yaml";
            if(!std::filesystem::exists(manifest)) continue;
            std::string id = entry.path().filename().string();
            if(!validId(id))
                return std::unexpected(mw::runtimeError("Invalid theme ID: " + id));
            std::ifstream file(manifest);
            if(!file) return std::unexpected(mw::runtimeError(
                "Cannot read theme manifest: " + manifest.string()));
            std::string content(std::istreambuf_iterator<char>{file}, {});
            auto tree = ryml::parse_in_arena(ryml::to_csubstr(content));
            auto root = tree.crootref();
            if(!root.is_map()) return std::unexpected(mw::runtimeError(
                "Theme manifest must be a mapping: " + manifest.string()));
            std::set<std::string> keys;
            for(auto node : root.children())
            {
                auto key = node.key();
                if(!keys.insert(std::string(key.str, key.len)).second)
                    return std::unexpected(mw::runtimeError(
                        "Duplicate theme manifest field in: " + id));
            }
            Theme theme;
            ASSIGN_OR_RETURN(theme.name, field(root, "name"));
            if(theme.name.empty()) theme.name = id;
            ASSIGN_OR_RETURN(theme.parent, field(root, "parent"));
            for(const auto& asset : std::filesystem::directory_iterator(entry.path()))
            {
                if(asset.is_regular_file() && asset.path().extension() == ".css")
                {
                    auto filename = asset.path().filename().string();
                    // Keep stylesheet URLs safe without URL encoding.
                    if(!validId(asset.path().stem().string()))
                        return std::unexpected(mw::runtimeError(
                            "Invalid theme stylesheet filename: " + filename));
                    theme.stylesheets.push_back(id + "/" + filename);
                }
            }
            std::sort(theme.stylesheets.begin(), theme.stylesheets.end());
            loaded.emplace(id, std::move(theme));
        }
        for(const auto& [id, theme] : loaded)
        {
            std::set<std::string> visited;
            std::string current = id;
            while(!current.empty())
            {
                if(!visited.insert(current).second)
                    return std::unexpected(mw::runtimeError(
                        "Theme inheritance cycle at: " + current));
                auto it = loaded.find(current);
                if(it == loaded.end())
                    return std::unexpected(mw::runtimeError(
                        "Missing theme parent: " + current));
                current = it->second.parent;
            }
        }
    }
    catch(const std::exception& error)
    {
        return std::unexpected(mw::runtimeError(error.what()));
    }
    themes = std::move(loaded);
    return {};
}

std::vector<std::string> ThemeManager::stylesheets(const std::string& id) const
{
    std::vector<const Theme*> chain;
    auto it = themes.find(id);
    while(it != themes.end())
    {
        chain.push_back(&it->second);
        it = themes.find(it->second.parent);
    }
    std::vector<std::string> result;
    for(auto item = chain.rbegin(); item != chain.rend(); ++item)
        result.insert(result.end(), (*item)->stylesheets.begin(),
                      (*item)->stylesheets.end());
    return result;
}
}
