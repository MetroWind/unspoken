#include "emoji.hpp"

#include <algorithm>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>

#include <mw/error.hpp>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace unspoken
{

bool isValidShortcode(std::string_view stem)
{
    if(stem.empty()) return false;
    for(char c : stem)
    {
        bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
            || c == '_';
        if(!ok) return false;
    }
    return true;
}

std::string imageMediaTypeForExt(std::string_view ext_lower)
{
    if(ext_lower == "png")  return "image/png";
    if(ext_lower == "jpg" || ext_lower == "jpeg") return "image/jpeg";
    if(ext_lower == "gif")  return "image/gif";
    if(ext_lower == "webp") return "image/webp";
    if(ext_lower == "svg")  return "image/svg+xml";
    if(ext_lower == "avif") return "image/avif";
    return "";
}

EmojiRegistry EmojiRegistry::scan(const std::string& emoji_dir,
                                  const std::string& url_root)
{
    EmojiRegistry reg;
    namespace fs = std::filesystem;
    std::error_code ec;
    if(!fs::is_directory(emoji_dir, ec))
    {
        spdlog::info("Emoji dir {} does not exist; no custom emoji loaded.",
                     emoji_dir);
        return reg;
    }

    for(const auto& entry : fs::directory_iterator(emoji_dir, ec))
    {
        if(!entry.is_regular_file()) continue;
        const fs::path& p = entry.path();
        std::string stem = p.stem().string();
        std::string ext = p.extension().string();
        if(!ext.empty() && ext.front() == '.') ext.erase(ext.begin());
        std::transform(ext.begin(), ext.end(), ext.begin(),
                       [](unsigned char c){ return std::tolower(c); });

        std::string media_type = imageMediaTypeForExt(ext);
        if(media_type.empty()) continue; // not an image; ignore.

        if(!isValidShortcode(stem))
        {
            spdlog::warn("Skipping emoji file {}: invalid shortcode '{}' "
                         "(allowed charset [a-z0-9_]).",
                         p.filename().string(), stem);
            continue;
        }
        if(reg.by_shortcode.contains(stem))
        {
            spdlog::warn("Emoji shortcode ':{}:' collision; keeping the "
                         "first file, ignoring {}.", stem,
                         p.filename().string());
            continue;
        }

        EmojiInfo info;
        info.shortcode = stem;
        info.image_url = url_root + "emoji/" + p.filename().string();
        info.media_type = media_type;
        reg.by_shortcode.emplace(stem, std::move(info));
    }
    spdlog::info("Loaded {} custom emoji from {}.", reg.by_shortcode.size(),
                 emoji_dir);
    return reg;
}

std::optional<EmojiInfo>
EmojiRegistry::lookup(std::string_view shortcode) const
{
    auto it = by_shortcode.find(std::string(shortcode));
    if(it == by_shortcode.end()) return std::nullopt;
    return it->second;
}

std::vector<EmojiInfo> EmojiRegistry::all() const
{
    std::vector<EmojiInfo> out;
    out.reserve(by_shortcode.size());
    for(const auto& [_, info] : by_shortcode) out.push_back(info);
    return out;
}

mw::E<std::vector<UnicodeEmojiCategory>>
loadUnicodeEmojiCategories(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    if(!file)
    {
        return std::unexpected(mw::runtimeError(
            std::format("Failed to open emoji data file {}", path)));
    }

    std::string text;
    text.assign(std::istreambuf_iterator<char>(file),
                std::istreambuf_iterator<char>());
    if(file.bad())
    {
        return std::unexpected(mw::runtimeError(
            std::format("Failed to read emoji data file {}", path)));
    }

    try
    {
        nlohmann::json root = nlohmann::json::parse(text);
        if(!root.contains("categories") || !root["categories"].is_array())
        {
            return std::unexpected(mw::runtimeError(
                "Emoji data is missing categories array"));
        }

        std::vector<UnicodeEmojiCategory> categories;
        for(const auto& c : root["categories"])
        {
            if(!c.contains("id") || !c["id"].is_string()
               || !c.contains("label") || !c["label"].is_string()
               || !c.contains("subgroups") || !c["subgroups"].is_array())
            {
                return std::unexpected(mw::runtimeError(
                    "Emoji category has invalid shape"));
            }

            UnicodeEmojiCategory category;
            category.id = c["id"].get<std::string>();
            category.label = c["label"].get<std::string>();
            for(const auto& s : c["subgroups"])
            {
                if(!s.contains("id") || !s["id"].is_string()
                   || !s.contains("label") || !s["label"].is_string()
                   || !s.contains("emoji") || !s["emoji"].is_array())
                {
                    return std::unexpected(mw::runtimeError(
                        "Emoji subgroup has invalid shape"));
                }

                UnicodeEmojiSubgroup subgroup;
                subgroup.id = s["id"].get<std::string>();
                subgroup.label = s["label"].get<std::string>();
                for(const auto& e : s["emoji"])
                {
                    if(!e.contains("emoji") || !e["emoji"].is_string()
                       || !e.contains("name") || !e["name"].is_string()
                       || !e.contains("version")
                       || !e["version"].is_string())
                    {
                        return std::unexpected(mw::runtimeError(
                            "Emoji entry has invalid shape"));
                    }
                    subgroup.emoji.push_back({
                        e["emoji"].get<std::string>(),
                        e["name"].get<std::string>(),
                        e["version"].get<std::string>(),
                    });
                }
                category.subgroups.push_back(std::move(subgroup));
            }
            categories.push_back(std::move(category));
        }

        return categories;
    }
    catch(const std::exception& e)
    {
        return std::unexpected(mw::runtimeError(
            std::format("Failed to parse emoji data file {}: {}",
                        path, e.what())));
    }
}

} // namespace unspoken
