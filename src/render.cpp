#include "render.hpp"

#include <cctype>
#include <format>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <mw/utils.hpp>
#include <macrodown.h>

#include "emoji.hpp"

namespace unspoken
{

namespace
{

std::string lowerAscii(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    for(char c : s)
    {
        out.push_back(static_cast<char>(std::tolower(
            static_cast<unsigned char>(c))));
    }
    return out;
}

bool isNameChar(char c)
{
    return std::isalnum(static_cast<unsigned char>(c)) || c == '-'
        || c == '_';
}

bool isSpace(char c)
{
    return std::isspace(static_cast<unsigned char>(c));
}

std::string trimAscii(std::string_view s)
{
    while(!s.empty() && isSpace(s.front())) s.remove_prefix(1);
    while(!s.empty() && isSpace(s.back())) s.remove_suffix(1);
    return std::string(s);
}

bool isAllowedTag(std::string_view tag)
{
    static const std::set<std::string_view> TAGS = {
        "a", "b", "blockquote", "br", "code", "em", "i", "img", "p", "pre",
        "span", "strong", "u",
    };
    return TAGS.contains(tag);
}

std::string readAttrValue(std::string_view tag, size_t& pos)
{
    while(pos < tag.size() && isSpace(tag[pos])) ++pos;
    if(pos >= tag.size()) return "";
    char quote = tag[pos];
    if(quote == '"' || quote == '\'')
    {
        ++pos;
        size_t start = pos;
        while(pos < tag.size() && tag[pos] != quote) ++pos;
        std::string out(tag.substr(start, pos - start));
        if(pos < tag.size()) ++pos;
        return out;
    }

    size_t start = pos;
    while(pos < tag.size() && !isSpace(tag[pos]) && tag[pos] != '>')
        ++pos;
    return std::string(tag.substr(start, pos - start));
}

std::optional<std::string> attrValue(std::string_view tag,
                                     std::string_view wanted)
{
    size_t pos = 0;
    while(pos < tag.size() && !isSpace(tag[pos])) ++pos;
    while(pos < tag.size())
    {
        while(pos < tag.size() && isSpace(tag[pos])) ++pos;
        size_t name_start = pos;
        while(pos < tag.size() && isNameChar(tag[pos])) ++pos;
        if(pos == name_start) break;
        std::string name = lowerAscii(tag.substr(name_start,
                                                 pos - name_start));
        while(pos < tag.size() && isSpace(tag[pos])) ++pos;
        if(pos >= tag.size() || tag[pos] != '=') continue;
        ++pos;
        std::string value = readAttrValue(tag, pos);
        if(name == wanted) return value;
    }
    return std::nullopt;
}

bool safeHref(std::string_view href)
{
    std::string h = lowerAscii(trimAscii(href));
    return h.starts_with("https://") || h.starts_with("http://")
        || h.starts_with("mailto:") || h.starts_with("/");
}

bool safeImageSrc(std::string_view src)
{
    std::string s = lowerAscii(trimAscii(src));
    return s.starts_with("https://") || s.starts_with("/");
}

bool safeSpanClass(std::string_view cls)
{
    return cls == "mention" || cls == "hashtag";
}

std::optional<std::string> sanitizeTag(std::string_view raw_tag)
{
    std::string tag = trimAscii(raw_tag);
    if(tag.empty()) return std::nullopt;

    bool closing = false;
    if(tag.front() == '/')
    {
        closing = true;
        tag.erase(tag.begin());
        tag = trimAscii(tag);
    }
    if(tag.empty()) return std::nullopt;

    bool self_closing = false;
    if(tag.back() == '/')
    {
        self_closing = true;
        tag.pop_back();
        tag = trimAscii(tag);
    }

    size_t name_end = 0;
    while(name_end < tag.size() && isNameChar(tag[name_end])) ++name_end;
    if(name_end == 0) return std::nullopt;
    std::string name = lowerAscii(std::string_view(tag).substr(0, name_end));
    if(!isAllowedTag(name)) return std::nullopt;

    if(closing) return "</" + name + ">";
    if(name == "br") return "<br>";

    std::string out = "<" + name;
    if(name == "a")
    {
        auto href = attrValue(tag, "href");
        if(!href.has_value() || !safeHref(*href)) return std::nullopt;
        out += " href=\"" + mw::escapeHTML(*href) + "\"";
        out += " rel=\"nofollow noopener noreferrer\"";
    }
    else if(name == "span")
    {
        auto cls = attrValue(tag, "class");
        if(cls.has_value() && safeSpanClass(*cls))
            out += " class=\"" + *cls + "\"";
    }
    else if(name == "img")
    {
        auto src = attrValue(tag, "src");
        auto cls = attrValue(tag, "class");
        if(!src.has_value() || !safeImageSrc(*src)
           || !cls.has_value() || *cls != "emoji")
        {
            return std::nullopt;
        }
        out += " class=\"emoji\"";
        out += " src=\"" + mw::escapeHTML(*src) + "\"";
        if(auto alt = attrValue(tag, "alt"); alt.has_value())
            out += " alt=\"" + mw::escapeHTML(*alt) + "\"";
        if(auto title = attrValue(tag, "title"); title.has_value())
            out += " title=\"" + mw::escapeHTML(*title) + "\"";
    }
    out += self_closing ? "/>" : ">";
    return out;
}

std::optional<std::string> tagName(std::string_view raw_tag)
{
    std::string tag = trimAscii(raw_tag);
    if(tag.empty()) return std::nullopt;
    if(tag.front() == '/')
    {
        tag.erase(tag.begin());
        tag = trimAscii(tag);
    }
    if(tag.empty()) return std::nullopt;
    size_t name_end = 0;
    while(name_end < tag.size() && isNameChar(tag[name_end])) ++name_end;
    if(name_end == 0) return std::nullopt;
    return lowerAscii(tag.substr(0, name_end));
}

bool isClosingTag(std::string_view raw_tag)
{
    std::string tag = trimAscii(raw_tag);
    return !tag.empty() && tag.front() == '/';
}

bool isSelfClosingTag(std::string_view raw_tag)
{
    std::string tag = trimAscii(raw_tag);
    return !tag.empty() && tag.back() == '/';
}

std::string nodePlainText(const macrodown::Node& node)
{
    return std::visit([](const auto& item) -> std::string
    {
        using T = std::decay_t<decltype(item)>;
        if constexpr(std::is_same_v<T, macrodown::Text>)
        {
            return item.content;
        }
        else if constexpr(std::is_same_v<T, macrodown::Group>)
        {
            std::string out;
            for(const auto& child : item.children)
                if(child) out += nodePlainText(*child);
            return out;
        }
        else
        {
            std::string out;
            for(const auto& arg : item.arguments)
                if(arg) out += nodePlainText(*arg);
            return out;
        }
    }, node.data);
}

std::optional<ParsedMention> parseMentionToken(std::string_view token)
{
    if(token.empty()) return std::nullopt;
    if(token.front() == '@') token.remove_prefix(1);
    if(token.empty()) return std::nullopt;

    size_t at = token.find('@');
    std::string_view username = at == std::string_view::npos
        ? token : token.substr(0, at);
    std::string_view domain = at == std::string_view::npos
        ? std::string_view() : token.substr(at + 1);
    if(username.empty() || username.find('@') != std::string_view::npos
       || domain.find('@') != std::string_view::npos)
    {
        return std::nullopt;
    }

    ParsedMention out;
    out.username = std::string(username);
    out.domain = std::string(domain);
    out.name = "@" + out.username;
    if(!out.domain.empty()) out.name += "@" + out.domain;
    return out;
}

std::optional<ParsedHashtag> parseHashtagToken(std::string_view token)
{
    if(token.empty()) return std::nullopt;
    if(token.front() == '#') token.remove_prefix(1);
    if(token.empty()) return std::nullopt;

    ParsedHashtag out;
    out.tag = std::string(token);
    out.name = "#" + out.tag;
    return out;
}

macrodown::MacroDown markupParser()
{
    macrodown::MacroDown md;
    md.definePrefixMarkup({"@", "mention", ""});
    md.definePrefixMarkup({"#", "hashtag", ""});
    md.evaluator().defineIntrinsic("mention",
        [](const std::vector<std::string>& args) -> std::string
        {
            std::string token = args.empty() ? "" : args[0];
            return std::format("<span class=\"mention\">@{}</span>",
                               mw::escapeHTML(token));
        });
    md.evaluator().defineIntrinsic("hashtag",
        [](const std::vector<std::string>& args) -> std::string
        {
            std::string token = args.empty() ? "" : args[0];
            return std::format("<span class=\"hashtag\">#{}</span>",
                               mw::escapeHTML(token));
        });
    return md;
}

} // namespace

std::string renderMarkdown(const std::string& source)
{
    macrodown::MacroDown md = markupParser();
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

RenderedPostContent parsePostContent(const std::string& source,
                                     const EmojiRegistry& emoji)
{
    macrodown::MacroDown md = markupParser();
    auto root = md.parse(source);
    if(!root) return {};

    RenderedPostContent out;
    std::set<std::string> seen_mentions;
    std::set<std::string> seen_hashtags;
    root->forEach([&](const macrodown::Node& node)
    {
        if(!std::holds_alternative<macrodown::Macro>(node.data)) return;
        const auto& macro = std::get<macrodown::Macro>(node.data);
        if(macro.arguments.empty() || !macro.arguments[0]) return;
        std::string token = nodePlainText(*macro.arguments[0]);

        if(macro.name == "mention")
        {
            auto mention = parseMentionToken(token);
            if(!mention.has_value()) return;
            std::string key = lowerAscii(mention->name);
            if(seen_mentions.insert(key).second)
                out.mentions.push_back(std::move(*mention));
        }
        else if(macro.name == "hashtag")
        {
            auto hashtag = parseHashtagToken(token);
            if(!hashtag.has_value()) return;
            std::string key = lowerAscii(hashtag->name);
            if(seen_hashtags.insert(key).second)
                out.hashtags.push_back(std::move(*hashtag));
        }
    });
    out.html = substituteEmoji(md.render(*root), emoji);
    return out;
}

std::string sanitizeRemoteHtml(std::string_view html)
{
    std::string out;
    out.reserve(html.size());
    std::vector<std::string> open_tags;
    size_t pos = 0;
    while(pos < html.size())
    {
        size_t lt = html.find('<', pos);
        if(lt == std::string_view::npos)
        {
            out += mw::escapeHTML(html.substr(pos));
            break;
        }
        out += mw::escapeHTML(html.substr(pos, lt - pos));

        size_t gt = html.find('>', lt + 1);
        if(gt == std::string_view::npos)
        {
            out += "&lt;";
            pos = lt + 1;
            continue;
        }

        std::string raw = trimAscii(html.substr(lt + 1, gt - lt - 1));
        std::string lowered = lowerAscii(raw);
        if(lowered.starts_with("script")
           || lowered.starts_with("style"))
        {
            std::string close = lowered.starts_with("script")
                ? "</script>" : "</style>";
            std::string rest = lowerAscii(html.substr(gt + 1));
            size_t end = rest.find(close);
            pos = end == std::string::npos
                ? html.size()
                : gt + 1 + end + close.size();
            continue;
        }

        auto name = tagName(raw);
        if(auto safe = sanitizeTag(raw); safe.has_value())
        {
            if(isClosingTag(raw))
            {
                if(name.has_value() && !open_tags.empty()
                   && open_tags.back() == *name)
                {
                    open_tags.pop_back();
                    out += *safe;
                }
            }
            else
            {
                out += *safe;
                if(name.has_value() && *name != "br" && *name != "img"
                   && !isSelfClosingTag(raw))
                {
                    open_tags.push_back(*name);
                }
            }
        }
        pos = gt + 1;
    }
    return out;
}

} // namespace unspoken
