#pragma once

// Markdown rendering for local posts (design §13.1) plus custom-emoji
// shortcode substitution (§13.4). Local posts are authored in Markdown
// and rendered to HTML once, at compose time; both the source and the
// rendered HTML are stored. Mentions/hashtags via custom MacroDown markup
// are Phase 6 — this module only does plain rendering + emoji for now.

#include <string>
#include <string_view>

#include "emoji.hpp"

namespace unspoken
{

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

} // namespace unspoken
