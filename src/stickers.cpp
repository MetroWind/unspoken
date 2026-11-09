#include "stickers.hpp"

#include <algorithm>
#include <cstdint>

#include <mw/url.hpp>
#include <mw/utils.hpp>
#include <spdlog/spdlog.h>

#include "attachments.hpp"

namespace unspoken
{
namespace
{

mw::Error missing()
{
    return mw::HTTPError(404, "No such sticker");
}

std::string stickerMediaType(std::string_view filename)
{
    auto ext = extensionOf(filename);
    if(ext != "png" && ext != "jpg" && ext != "jpeg" && ext != "gif"
       && ext != "webp" && ext != "avif") return "";
    return mediaTypeForExtension(ext);
}

bool byteLess(const std::filesystem::path& a,
              const std::filesystem::path& b)
{
    const auto x = a.filename().string();
    const auto y = b.filename().string();
    return std::lexicographical_compare(x.begin(), x.end(), y.begin(), y.end(),
        [](unsigned char l, unsigned char r) { return l < r; });
}

mw::E<std::vector<std::filesystem::path>> entries(
    const std::filesystem::path& path)
{
    std::error_code ec;
    std::vector<std::filesystem::path> result;
    auto it = std::filesystem::directory_iterator(path, ec);
    if(ec) return std::unexpected(mw::runtimeError(ec.message()));
    for(; it != std::filesystem::directory_iterator(); it.increment(ec))
    {
        if(ec) return std::unexpected(mw::runtimeError(ec.message()));
        result.push_back(it->path());
    }
    if(ec) return std::unexpected(mw::runtimeError(ec.message()));
    std::sort(result.begin(), result.end(), byteLess);
    return result;
}

} // namespace

bool validStickerName(std::string_view name)
{
    if(name.empty() || name.front() == '.' || name == "..") return false;
    for(size_t i = 0; i < name.size();)
    {
        auto c = static_cast<unsigned char>(name[i++]);
        if(c < 32 || c == 127 || c == '/' || c == '\\') return false;
        if(c < 128) continue;
        int count = c >= 0xc2 && c <= 0xdf ? 1
            : c >= 0xe0 && c <= 0xef ? 2
            : c >= 0xf0 && c <= 0xf4 ? 3 : -1;
        if(count < 0 || i + count > name.size()) return false;
        uint32_t value = c & ((1 << (6 - count)) - 1);
        for(int j = 0; j < count; ++j)
        {
            auto next = static_cast<unsigned char>(name[i++]);
            if((next & 0xc0) != 0x80) return false;
            value = (value << 6) | (next & 0x3f);
        }
        if((count == 1 && value < 0x80)
           || (count == 2 && value < 0x800)
           || (count == 3 && value < 0x10000)
           || (value >= 0xd800 && value <= 0xdfff)
           || value > 0x10ffff) return false;
    }
    return true;
}

mw::E<std::filesystem::path> stickerPath(const std::string& root,
    std::string_view pack, std::string_view filename)
{
    namespace fs = std::filesystem;
    if(!validStickerName(pack) || !validStickerName(filename)
       || fs::path(filename).stem().empty()
       || stickerMediaType(filename).empty())
        return std::unexpected(missing());
    std::error_code ec;
    auto canonical_root = fs::canonical(root, ec);
    if(ec) return std::unexpected(missing());
    auto dir = canonical_root / pack;
    auto status = fs::symlink_status(dir, ec);
    if(ec || !fs::is_directory(status)) return std::unexpected(missing());
    auto path = dir / filename;
    status = fs::symlink_status(path, ec);
    if(ec || !fs::is_regular_file(status)) return std::unexpected(missing());
    auto size = fs::file_size(path, ec);
    if(ec) return std::unexpected(mw::runtimeError(ec.message()));
    if(size == 0) return std::unexpected(missing());
    auto resolved = fs::canonical(path, ec);
    if(ec) return std::unexpected(missing());
    // Compare components, never a textual prefix such as root vs root-old.
    auto relative = resolved.lexically_relative(canonical_root);
    if(relative != fs::path(pack) / filename)
        return std::unexpected(missing());
    return resolved;
}

mw::E<StickerRegistry> StickerRegistry::scan(const std::string& root,
                                             const std::string& url_root)
{
    namespace fs = std::filesystem;
    StickerRegistry result;
    result.root = root;
    std::error_code ec;
    bool exists = fs::exists(root, ec);
    if(ec) return std::unexpected(mw::runtimeError(ec.message()));
    if(!exists)
    {
        spdlog::info("Sticker root missing; no stickers loaded");
        return result;
    }
    ASSIGN_OR_RETURN(auto dirs, entries(root));
    size_t count = 0;
    auto prefix = url_root;
    if(!prefix.ends_with('/')) prefix += '/';
    for(const auto& dir : dirs)
    {
        auto name = dir.filename().string();
        auto status = fs::symlink_status(dir, ec);
        if(ec) return std::unexpected(mw::runtimeError(ec.message()));
        if(!validStickerName(name) || !fs::is_directory(status))
        {
            spdlog::warn("Skipping ineligible sticker pack entry");
            continue;
        }
        StickerPack pack{name, {}};
        ASSIGN_OR_RETURN(auto files, entries(dir));
        for(const auto& file : files)
        {
            auto filename = file.filename().string();
            auto path = stickerPath(root, name, filename);
            if(!path)
            {
                if(!path.error().as<mw::HTTPError>())
                    return std::unexpected(path.error());
                spdlog::warn("Skipping ineligible sticker file entry");
                continue;
            }
            auto url = prefix + "stickers/" + mw::URL::encode(name)
                + "/" + mw::URL::encode(filename);
            pack.stickers.push_back({url, file.stem().string(), url,
                stickerMediaType(filename), name, filename});
            ++count;
        }
        if(!pack.stickers.empty()) result.packs.push_back(std::move(pack));
    }
    spdlog::info("Loaded {} packs and {} stickers", result.packs.size(), count);
    return result;
}

std::optional<StickerInfo> StickerRegistry::lookup(std::string_view key) const
{
    for(const auto& pack : packs)
        for(const auto& sticker : pack.stickers)
            if(sticker.key == key) return sticker;
    return std::nullopt;
}

mw::E<void> StickerRegistry::available(const StickerInfo& info) const
{
    auto path = stickerPath(root, info.pack, info.filename);
    if(!path) return std::unexpected(mw::HTTPError(400,
        "Sticker unavailable. Refresh the picker."));
    return {};
}

nlohmann::json StickerRegistry::catalog() const
{
    auto result = nlohmann::json::array();
    for(const auto& pack : packs)
    {
        auto images = nlohmann::json::array();
        for(const auto& sticker : pack.stickers)
            images.push_back({{"key", sticker.key}, {"name", sticker.name},
                {"url", sticker.url}, {"media_type", sticker.media_type}});
        result.push_back({{"name", pack.name}, {"stickers", images}});
    }
    return result;
}

} // namespace unspoken
