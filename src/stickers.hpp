#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <mw/error.hpp>
#include <nlohmann/json.hpp>

namespace unspoken
{

// A selectable static image; keys are canonical URLs, never client paths.
struct StickerInfo
{
    // Canonical selection identifier supplied by discovery.
    std::string key;
    // Exact filename stem or pack directory label.
    std::string name;
    // Public original image location, with encoded components.
    std::string url;
    // Image MIME type derived from the supported extension.
    std::string media_type;
    // Decoded immediate directory name used to recheck eligibility.
    std::string pack;
    // Exact decoded filename including its extension.
    std::string filename;
};

// An ordered pack named by its immediate directory.
struct StickerPack
{
    // Exact filename stem or pack directory label.
    std::string name;
    // Eligible images in unsigned UTF-8 filename order.
    std::vector<StickerInfo> stickers;
};

// Validate a decoded single path component, including UTF-8 validity.
bool validStickerName(std::string_view name);

// Resolve an eligible current file beneath root; invalid paths return 404.
mw::E<std::filesystem::path> stickerPath(const std::string& root,
    std::string_view pack, std::string_view filename);

// Startup snapshot of operator-managed images. No image bytes are read.
class StickerRegistry
{
public:
    // Discover sorted packs without creating directories or database rows.
    static mw::E<StickerRegistry> scan(const std::string& root,
                                      const std::string& url_root);
    // Resolve an exact key from this snapshot.
    std::optional<StickerInfo> lookup(std::string_view key) const;
    // Ordered packs for native forms and the enhanced picker.
    const std::vector<StickerPack>& all() const { return packs; }
    // Whether there are no selectable images.
    bool empty() const { return packs.empty(); }
    // Serialize raw catalog values; callers must escape native HTML labels.
    nlohmann::json catalog() const;
    // Verify that a selected image remains available and eligible.
    mw::E<void> available(const StickerInfo& info) const;
private:
    std::string root;
    std::vector<StickerPack> packs;
};

} // namespace unspoken
