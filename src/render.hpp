#pragma once

// Markdown rendering for local posts (design §13.1), custom-emoji
// shortcode substitution (§13.4), and MacroDown prefix markup extraction
// for mentions/hashtags (§13.2). Local posts are authored in Markdown
// and rendered to HTML once, at compose time; both the source and the
// rendered HTML are stored.

#include <string>
#include <string_view>
#include <vector>

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

// The full local compose pipeline: render Markdown, then substitute
// emoji into the rendered HTML (the stored content_html).
std::string renderPostContent(const std::string& source,
                              const EmojiRegistry& emoji);

// The full local compose pipeline with mention/hashtag extraction from
// the MacroDown syntax tree.
RenderedPostContent parsePostContent(const std::string& source,
                                     const EmojiRegistry& emoji);

// Sanitize untrusted HTML from remote ActivityPub objects before it is
// stored or displayed.
std::string sanitizeRemoteHtml(std::string_view html);

} // namespace unspoken
