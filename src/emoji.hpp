#pragma once

// Server-wide custom emoji (design §13.4). The emoji directory is the
// single source of truth: it is scanned once at startup into an in-memory
// registry (no DB table). The map is built once and shared read-only
// across all threads, so no locking is needed after construction.

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <mw/error.hpp>

namespace unspoken
{

struct EmojiInfo
{
    std::string shortcode;   // the :name: without colons
    std::string image_url;   // <url_root>emoji/<filename>
    std::string media_type;  // derived from the file extension
};

class EmojiRegistry
{
public:
    EmojiRegistry() = default;

    // Scan `emoji_dir` for image files and build the registry. The
    // shortcode is the filename stem; invalid stems (charset [a-z0-9_]+)
    // are skipped with a logged warning, and shortcode collisions keep
    // the first file encountered (first wins) with a logged warning.
    // `url_root` is the configured root (already ending in '/').
    static EmojiRegistry scan(const std::string& emoji_dir,
                              const std::string& url_root);

    std::optional<EmojiInfo> lookup(std::string_view shortcode) const;

    // All emoji, sorted by shortcode — for the authoring picker.
    std::vector<EmojiInfo> all() const;

    bool empty() const { return by_shortcode.empty(); }

private:
    std::map<std::string, EmojiInfo> by_shortcode;
};

// A Unicode emoji entry loaded from generated picker data.
struct UnicodeEmoji
{
    // Rendered emoji sequence inserted or submitted by the picker.
    std::string emoji;
    // CLDR short name used for labels and tooltips.
    std::string name;
    // Emoji version from Unicode emoji-test.txt.
    std::string version;
};

// A Unicode emoji subgroup loaded from generated picker data.
struct UnicodeEmojiSubgroup
{
    // Stable ASCII identifier for HTML tab state.
    std::string id;
    // Human-readable subgroup label from Unicode emoji-test.txt.
    std::string label;
    // Ordered emoji entries in this subgroup.
    std::vector<UnicodeEmoji> emoji;
};

// A Unicode emoji category loaded from generated picker data.
struct UnicodeEmojiCategory
{
    // Stable ASCII identifier for HTML tab state.
    std::string id;
    // Human-readable category label from Unicode emoji-test.txt.
    std::string label;
    // First fully-qualified emoji in the category, used as the tab icon.
    std::string representative_emoji;
    // Ordered emoji subgroups in this category.
    std::vector<UnicodeEmojiSubgroup> subgroups;
};

// Load generated Unicode emoji picker data from JSON.
mw::E<std::vector<UnicodeEmojiCategory>>
loadUnicodeEmojiCategories(const std::string& path);

// True if `stem` is a valid emoji shortcode ([a-z0-9_]+, non-empty).
bool isValidShortcode(std::string_view stem);

// MIME type for a lowercased file extension (without the dot), or "" if
// the extension is not a recognized image type.
std::string imageMediaTypeForExt(std::string_view ext_lower);

} // namespace unspoken
