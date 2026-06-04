#include "emoji.hpp"

#include <algorithm>
#include <filesystem>
#include <string>
#include <string_view>

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

} // namespace unspoken
