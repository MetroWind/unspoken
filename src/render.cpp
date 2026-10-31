#include "render.hpp"

#include <cctype>
#include <algorithm>
#include <format>
#include <limits>
#include <memory>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/tree.h>

#include <mw/utils.hpp>
#include <mw/url.hpp>
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

// Read decoded attribute text; ownership stays within this translation unit.
std::optional<std::string> attrValue(const xmlNode* node, const char* name)
{
    std::unique_ptr<xmlChar, decltype(xmlFree)> value(
        xmlGetNoNsProp(node, reinterpret_cast<const xmlChar*>(name)), xmlFree);
    if(!value) return std::nullopt;
    return std::string(reinterpret_cast<const char*>(value.get()));
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

// Emit only allowed attributes, escaping the parser's decoded values once.
std::optional<std::string> sanitizedStartTag(
    const xmlNode* node, std::string_view name)
{
    if(!isAllowedTag(name)) return std::nullopt;
    if(name == "br") return "<br>";

    std::string out = "<" + std::string(name);
    if(name == "a")
    {
        auto href = attrValue(node, "href");
        if(!href.has_value() || !safeHref(*href)) return std::nullopt;
        out += " href=\"" + mw::escapeHTML(*href) + "\"";
        out += " rel=\"nofollow noopener noreferrer\"";
    }
    else if(name == "span")
    {
        auto cls = attrValue(node, "class");
        if(cls.has_value() && safeSpanClass(*cls))
            out += " class=\"" + *cls + "\"";
    }
    else if(name == "img")
    {
        auto src = attrValue(node, "src");
        auto cls = attrValue(node, "class");
        if(!src.has_value() || !safeImageSrc(*src)
           || !cls.has_value() || *cls != "emoji")
        {
            return std::nullopt;
        }
        out += " class=\"emoji\"";
        out += " src=\"" + mw::escapeHTML(*src) + "\"";
        if(auto alt = attrValue(node, "alt"); alt.has_value())
            out += " alt=\"" + mw::escapeHTML(*alt) + "\"";
        if(auto title = attrValue(node, "title"); title.has_value())
            out += " title=\"" + mw::escapeHTML(*title) + "\"";
    }
    out += ">";
    return out;
}

// Rebuild the tree without copying untrusted markup or serializer options.
void appendSanitizedNodes(const xmlNode* node, std::string& out)
{
    for(; node != nullptr; node = node->next)
    {
        if(node->type == XML_TEXT_NODE || node->type == XML_CDATA_SECTION_NODE)
        {
            if(node->content != nullptr)
                out += mw::escapeHTML(
                    reinterpret_cast<const char*>(node->content));
            continue;
        }
        if(node->type != XML_ELEMENT_NODE) continue;
        std::string name = lowerAscii(
            reinterpret_cast<const char*>(node->name));
        if(name == "script" || name == "style") continue;

        auto start_tag = sanitizedStartTag(node, name);
        if(start_tag.has_value()) out += *start_tag;
        appendSanitizedNodes(node->children, out);
        if(start_tag.has_value() && name != "br" && name != "img")
            out += "</" + name + ">";
    }
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

xmlNode* findBody(xmlNode* node)
{
    for(; node; node = node->next)
    {
        if(node->type == XML_ELEMENT_NODE &&
           xmlStrEqual(node->name,BAD_CAST "body")) return node;
        if(auto* found = findBody(node->children)) return found;
    }
    return nullptr;
}

bool linkMentionNodes(xmlNode* node,
    const std::map<std::string,std::string>& links, bool inside_anchor)
{
    bool changed = false;
    for(; node; node = node->next)
    {
        if(node->type != XML_ELEMENT_NODE) continue;
        bool anchor = xmlStrEqual(node->name,BAD_CAST "a");
        if(!inside_anchor && !anchor &&
           xmlStrEqual(node->name,BAD_CAST "span"))
        {
            auto classes = attrValue(node,"class");
            if(classes && *classes == "mention")
            {
                std::unique_ptr<xmlChar,decltype(xmlFree)> text(
                    xmlNodeGetContent(node),xmlFree);
                auto match = links.find(text ?
                    reinterpret_cast<const char*>(text.get()) : "");
                if(match != links.end())
                {
                    xmlNodeSetName(node,BAD_CAST "a");
                    xmlSetProp(node,BAD_CAST "href",BAD_CAST match->second.c_str());
                    xmlSetProp(node,BAD_CAST "rel",
                               BAD_CAST "mention noopener noreferrer");
                    anchor = true;
                    changed = true;
                }
            }
        }
        changed = linkMentionNodes(node->children,links,
                                    inside_anchor || anchor) || changed;
    }
    return changed;
}

bool shortenMentionNodes(xmlNode* node)
{
    bool changed = false;
    for(; node; node = node->next)
    {
        if(node->type != XML_ELEMENT_NODE) continue;
        auto classes = attrValue(node,"class");
        if(xmlStrEqual(node->name,BAD_CAST "a") && classes &&
           *classes == "mention")
        {
            std::unique_ptr<xmlChar,decltype(xmlFree)> text(
                xmlNodeGetContent(node),xmlFree);
            std::string full = text ?
                reinterpret_cast<const char*>(text.get()) : "";
            auto separator = full.find('@',1);
            if(full.starts_with('@') && separator > 1 &&
               separator != std::string::npos && separator+1 < full.size() &&
               full.find('@',separator+1) == std::string::npos &&
               std::none_of(full.begin(),full.end(),[](unsigned char c)
                            { return std::isspace(c); }))
            {
                auto local = full.substr(0,separator);
                xmlSetProp(node,BAD_CAST "title",BAD_CAST full.c_str());
                xmlSetProp(node,BAD_CAST "aria-label",BAD_CAST full.c_str());
                xmlNodeSetContent(node,BAD_CAST "");
                xmlAddChild(node,xmlNewText(BAD_CAST local.c_str()));
                changed = true;
            }
        }
        changed = shortenMentionNodes(node->children) || changed;
    }
    return changed;
}

std::string transformMentionHtml(std::string_view html,
    const std::map<std::string,std::string>& links, bool shorten_labels)
{
    if(html.empty() || (!shorten_labels && links.empty()) ||
       html.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
        return std::string(html);
    std::unique_ptr<xmlDoc,decltype(&xmlFreeDoc)> doc(
        htmlReadMemory(html.data(),static_cast<int>(html.size()),nullptr,
            "UTF-8",HTML_PARSE_NONET | HTML_PARSE_NODEFDTD |
            HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING),&xmlFreeDoc);
    if(!doc) return std::string(html);
    auto* body = findBody(doc->children);
    if(!body) return std::string(html);
    bool changed = !links.empty() && linkMentionNodes(body->children,links,false);
    if(shorten_labels) changed = shortenMentionNodes(body->children) || changed;
    if(!changed) return std::string(html);
    std::unique_ptr<xmlBuffer,decltype(&xmlBufferFree)> buffer(
        xmlBufferCreate(),&xmlBufferFree);
    if(!buffer) return std::string(html);
    for(auto* node = body->children; node; node = node->next)
        if(htmlNodeDump(buffer.get(),doc.get(),node) < 0)
            return std::string(html);
    return std::string(reinterpret_cast<const char*>(xmlBufferContent(buffer.get())),
                        xmlBufferLength(buffer.get()));
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

std::string linkMentions(std::string_view html, const nlohmann::json& tags)
{
    if(!tags.is_array() || html.empty() ||
       html.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
        return std::string(html);
    std::map<std::string,std::string> links;
    for(const auto& tag : tags)
    {
        if(!tag.is_object()) continue;
        auto type = tag.find("type");
        auto name = tag.find("name");
        auto href = tag.find("href");
        if(type == tag.end() || *type != "Mention" || name == tag.end() ||
           !name->is_string() || href == tag.end() || !href->is_string())
            continue;
        auto url = mw::URL::fromStr(href->get<std::string>());
        if(!url || (url->scheme() != "https" && url->scheme() != "http") ||
           url->host().empty() || !url->user().empty() ||
           !url->password().empty()) continue;
        links.emplace(name->get<std::string>(),href->get<std::string>());
    }
    return transformMentionHtml(html,links,false);
}

std::string shortenMentionLabels(std::string_view html)
{
    if(html.find("mention") == std::string::npos) return std::string(html);
    return transformMentionHtml(html,{},true);
}

std::string sanitizeRemoteHtml(std::string_view html)
{
    if(html.empty()) return "";
    // The container keeps leading text and sibling elements in a fragment.
    // All document/container tags are unwrapped by the allowlist traversal.
    constexpr std::string_view PREFIX = "<html><body><div>";
    constexpr std::string_view SUFFIX = "</div></body></html>";
    if(html.size() > static_cast<size_t>(std::numeric_limits<int>::max())
                     - PREFIX.size() - SUFFIX.size())
    {
        return mw::escapeHTML(html);
    }
    std::string input = std::string(PREFIX) + std::string(html)
        + std::string(SUFFIX);
    std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)> doc(
        htmlReadMemory(input.data(), static_cast<int>(input.size()), nullptr,
                       "UTF-8", HTML_PARSE_NODEFDTD | HTML_PARSE_NOERROR
                       | HTML_PARSE_NOWARNING),
        &xmlFreeDoc);
    if(!doc) return mw::escapeHTML(html);

    std::string out;
    out.reserve(html.size());
    appendSanitizedNodes(doc->children, out);
    return out;
}

} // namespace unspoken
