#pragma once

// Markdown rendering for local posts (design §13.1), custom-emoji
// shortcode substitution (§13.4), and MacroDown prefix markup extraction
// for mentions/hashtags (§13.2). Local posts are authored in Markdown
// and rendered to HTML once, at compose time; both the source and the
// rendered HTML are stored.

#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json.hpp>

#include "emoji.hpp"

namespace unspoken
{

// A mention parsed from local Markdown source.
struct ParsedMention
{
    std::string name; // original ActivityStreams name, including '@'
    std::string username;
    std::string domain; // empty means local shorthand, e.g. @alice
};

// A hashtag parsed from local Markdown source.
struct ParsedHashtag
{
    std::string name; // original ActivityStreams name, including '#'
    std::string tag;
};

// Rendered Markdown plus extracted entities from the same syntax tree.
struct RenderedPostContent
{
    std::string html;
    std::vector<ParsedMention> mentions;
    std::vector<ParsedHashtag> hashtags;
};

// Render Markdown source to HTML using MacroDown.
std::string renderMarkdown(const std::string& source);

// Replace each known :shortcode: token in `html` with an <img class=
// "emoji"> tag from the registry. Unknown shortcodes are left verbatim.
std::string substituteEmoji(std::string_view html,
                            const EmojiRegistry& emoji);

// Render explicitly advertised remote emoji in text nodes, preserving exact
// valid shortcode names without rewriting attributes.
std::string substituteRemoteEmoji(std::string_view html,
    const std::map<std::string, EmojiInfo>& emoji);

// The full local compose pipeline: render Markdown, then substitute
// emoji into the rendered HTML (the stored content_html).
std::string renderPostContent(const std::string& source,
                              const EmojiRegistry& emoji);

// The full local compose pipeline with mention/hashtag extraction from
// the MacroDown syntax tree.
RenderedPostContent parsePostContent(const std::string& source,
                                     const EmojiRegistry& emoji);

// Turn marked mention spans into profile links using resolved Mention tags.
// Preserve visible text and existing anchors; perform no network resolution.
std::string linkMentions(std::string_view html, const nlohmann::json& tags);

// Display marked mention links as @username, keeping the full handle in
// title and accessibility labels. When site_root is set, link remote
// mentions to internal profiles. Preserve stored and federated content.
std::string shortenMentionLabels(std::string_view html,
                                 std::string_view site_root = "");

// Restore generated custom emoji images to :shortcode: text for remote
// clients, which render emoji using the accompanying ActivityPub tags.
std::string emojiShortcodesForFederation(std::string_view html);

// Extract a bounded UTF-8 excerpt, decoding entities and separating blocks.
// Omit scripts/styles and use image alt text for inline emoji.
std::string plainTextExcerpt(std::string_view html, size_t max_chars = 300);

// Find the language of an existing content/summary string from its matching
// language map or inline JSON-LD default. Missing/ambiguous metadata is unknown.
std::optional<std::string> languageForText(const nlohmann::json& object,
                                          std::string_view property);

// Parse remote ActivityPub HTML as UTF-8 and rebuild it using an allowlist,
// escaping decoded text and attributes once before storage or display.
std::string sanitizeRemoteHtml(std::string_view html);

} // namespace unspoken
