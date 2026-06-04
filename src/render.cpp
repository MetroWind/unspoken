#include "render.hpp"

#include <string>
#include <string_view>

#include <mw/utils.hpp>
#include <macrodown.h>

#include "emoji.hpp"

namespace unspoken
{

std::string renderMarkdown(const std::string& source)
{
    macrodown::MacroDown md;
    auto root = md.parse(source);
    if(!root) return "";
    return md.render(*root);
}

std::string substituteEmoji(std::string_view html, const EmojiRegistry& emoji)
{
    std::string out;
    out.reserve(html.size());
    size_t i = 0;
    while(i < html.size())
    {
        if(html[i] != ':')
        {
            out.push_back(html[i]);
            ++i;
            continue;
        }
        // Find the closing colon, allowing only shortcode chars between.
        size_t j = i + 1;
        while(j < html.size())
        {
            char c = html[j];
            bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '_';
            if(!ok) break;
            ++j;
        }
        if(j < html.size() && html[j] == ':' && j > i + 1)
        {
            std::string_view code = html.substr(i + 1, j - i - 1);
            if(auto info = emoji.lookup(code); info.has_value())
            {
                out += std::format(
                    "<img class=\"emoji\" src=\"{}\" alt=\":{}:\" "
                    "title=\":{}:\">",
                    mw::escapeHTML(info->image_url), code, code);
                i = j + 1;
                continue;
            }
        }
        // No emoji match: emit the literal ':' and continue past it.
        out.push_back(':');
        ++i;
    }
    return out;
}

std::string renderPostContent(const std::string& source,
                              const EmojiRegistry& emoji)
{
    return substituteEmoji(renderMarkdown(source), emoji);
}

} // namespace unspoken
