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

bool hasToken(std::string_view tokens, std::string_view wanted)
{
    while(!tokens.empty())
    {
        while(!tokens.empty() && isSpace(tokens.front()))
            tokens.remove_prefix(1);
        auto end = tokens.find_first_of(" \t\r\n\f");
        auto token = tokens.substr(0,end);
        if(token == wanted) return true;
        if(end == std::string_view::npos) break;
        tokens.remove_prefix(end + 1);
    }
    return false;
}

bool isMention(const xmlNode* node)
{
    auto classes = attrValue(node,"class");
    auto rel = attrValue(node,"rel");
    return (classes && hasToken(*classes,"mention"))
        || (rel && hasToken(*rel,"mention"));
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

void contextLanguage(const nlohmann::json& context,
                     std::optional<std::string>& language)
{
    if(context.is_array())
    {
        for(const auto& entry : context) contextLanguage(entry, language);
    }
    else if(context.is_object())
    {
        auto value = context.find("@language");
        if(value == context.end()) return;
        language.reset();
        if(value->is_string())
            language = value->get<std::string>();
    }
    else if(context.is_null()) language.reset();
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
        if(isMention(node)) out += " class=\"mention\"";
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

void appendPlainText(const xmlNode* node, std::string& out)
{
    for(; node; node = node->next)
    {
        if(node->type == XML_TEXT_NODE && node->content)
        {
            out += reinterpret_cast<const char*>(node->content);
            continue;
        }
        if(node->type != XML_ELEMENT_NODE) continue;
        const std::string name = lowerAscii(
            reinterpret_cast<const char*>(node->name));
        if(name == "script" || name == "style" || name == "head" ||
           name == "template") continue;
        const bool block = name == "p" || name == "div" || name == "br" ||
            name == "li" || name == "blockquote" || name == "pre" ||
            name == "tr" || name == "td" || name == "hr" ||
            (name.size() == 2 && name[0] == 'h' &&
             name[1] >= '1' && name[1] <= '6');
        if(block) out += ' ';
        if(name == "img")
        {
            if(auto alt = attrValue(node, "alt")) out += *alt;
        }
        else appendPlainText(node->children, out);
        if(block) out += ' ';
    }
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

bool shortenMentionNodes(xmlNode* node, std::string_view site_root)
{
    bool changed = false;
    for(; node; node = node->next)
    {
        if(node->type != XML_ELEMENT_NODE) continue;
        if(xmlStrEqual(node->name,BAD_CAST "a") && isMention(node))
        {
            auto href = attrValue(node,"href");
            if(href && !site_root.empty() &&
               !href->starts_with(std::string(site_root) + "u/") &&
               !href->starts_with(std::string(site_root) + "remote?uri="))
            {
                auto url = mw::URL::fromStr(*href);
                if(url && (url->scheme() == "https" ||
                           url->scheme() == "http") && !url->host().empty()
                   && url->user().empty() && url->password().empty())
                {
                    auto internal = std::string(site_root) + "remote?uri="
                        + mw::URL::encode(*href);
                    xmlSetProp(node,BAD_CAST "href",BAD_CAST internal.c_str());
                    changed = true;
                }
            }
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
        changed = shortenMentionNodes(node->children,site_root) || changed;
    }
    return changed;
}

bool replaceRemoteEmojiNodes(xmlNode* node,
    const std::map<std::string, EmojiInfo>& emoji)
{
    bool changed = false;
    while(node)
    {
        auto* next = node->next;
        if(node->type != XML_TEXT_NODE)
        {
            changed = replaceRemoteEmojiNodes(node->children, emoji) || changed;
            node = next;
            continue;
        }
        const std::string text(reinterpret_cast<const char*>(node->content));
        size_t pos = 0;
        size_t copied = 0;
        while(pos < text.size())
        {
            auto start = text.find(':', pos);
            if(start == std::string::npos) break;
            auto end = text.find(':', start + 1);
            if(end == std::string::npos) break;
            auto shortcode = text.substr(start + 1, end - start - 1);
            auto it = isValidShortcode(shortcode)
                ? emoji.find(shortcode) : emoji.end();
            if(it == emoji.end()
               || (!it->second.image_url.starts_with("https://")
                   && !it->second.image_url.starts_with("http://")))
            {
                // An unrelated colon must not consume a following shortcode.
                pos = start + 1;
                continue;
            }
            auto* image = xmlNewNode(nullptr, BAD_CAST "img");
            if(!image) break;
            auto label = text.substr(start, end - start + 1);
            xmlNewProp(image, BAD_CAST "class", BAD_CAST "emoji");
            xmlNewProp(image, BAD_CAST "src",
                       BAD_CAST it->second.image_url.c_str());
            xmlNewProp(image, BAD_CAST "alt", BAD_CAST label.c_str());
            xmlNewProp(image, BAD_CAST "title", BAD_CAST label.c_str());
            xmlAddPrevSibling(node, image);
            if(start > copied)
                xmlAddPrevSibling(image, xmlNewTextLen(
                    BAD_CAST(text.data() + copied),
                    static_cast<int>(start - copied)));
            copied = end + 1;
            pos = copied;
            changed = true;
        }
        if(copied)
            xmlNodeSetContent(node, BAD_CAST(text.c_str() + copied));
        node = next;
    }
    return changed;
}

bool restoreEmojiNodes(xmlNode* node)
{
    bool changed = false;
    while(node)
    {
        auto* next = node->next;
        auto classes = attrValue(node,"class");
        auto alt = attrValue(node,"alt");
        if(node->type == XML_ELEMENT_NODE &&
           xmlStrEqual(node->name,BAD_CAST "img") && classes &&
           *classes == "emoji" && alt && alt->size() > 2 &&
           alt->front() == ':' && alt->back() == ':' &&
           isValidShortcode(std::string_view(*alt).substr(1, alt->size()-2)))
        {
            auto* text = xmlNewText(BAD_CAST alt->c_str());
            if(text)
            {
                xmlReplaceNode(node,text);
                xmlFreeNode(node);
                changed = true;
            }
        }
        else changed = restoreEmojiNodes(node->children) || changed;
        node = next;
    }
    return changed;
}

std::string transformPostHtml(std::string_view html,
    const std::map<std::string,std::string>& links, bool shorten_labels,
    bool restore_emoji = false, std::string_view site_root = "",
    const std::map<std::string, EmojiInfo>& remote_emoji = {})
{
    if(html.empty() || (!shorten_labels && !restore_emoji && links.empty()
                        && remote_emoji.empty()) ||
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
    if(shorten_labels)
        changed = shortenMentionNodes(body->children,site_root) || changed;
    if(restore_emoji) changed = restoreEmojiNodes(body->children) || changed;
    if(!remote_emoji.empty())
        changed = replaceRemoteEmojiNodes(body->children, remote_emoji) || changed;
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
        while(j < html.size() && isValidShortcode(html.substr(j, 1))) ++j;
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

std::string substituteRemoteEmoji(std::string_view html,
    const std::map<std::string, EmojiInfo>& emoji)
{
    return transformPostHtml(html, {}, false, false, "", emoji);
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
    return transformPostHtml(html,links,false);
}

std::string shortenMentionLabels(std::string_view html,
                                 std::string_view site_root)
{
    if(html.find("mention") == std::string::npos) return std::string(html);
    return transformPostHtml(html,{},true,false,site_root);
}

std::string emojiShortcodesForFederation(std::string_view html)
{
    if(html.find("emoji") == std::string_view::npos) return std::string(html);
    return transformPostHtml(html,{},false,true);
}

std::string plainTextExcerpt(std::string_view html, size_t max_chars)
{
    if(html.empty() || max_chars == 0 ||
       html.size() > static_cast<size_t>(std::numeric_limits<int>::max()) - 64)
        return "";
    const auto input = "<html><body><div>" + std::string(html) +
        "</div></body></html>";
    std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)> doc(
        htmlReadMemory(input.data(), static_cast<int>(input.size()), nullptr,
            "UTF-8", HTML_PARSE_NONET | HTML_PARSE_NODEFDTD |
            HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING), &xmlFreeDoc);
    if(!doc) return "";
    auto* body = findBody(doc->children);
    if(!body) return "";
    std::string text;
    appendPlainText(body->children, text);
    std::string result;
    bool space = false;
    size_t count = 0;
    for(size_t i = 0; i < text.size();)
    {
        auto c = static_cast<unsigned char>(text[i]);
        if(std::isspace(c) || text.compare(i, 2, "\xc2\xa0") == 0)
        {
            space = !result.empty();
            i += c == 0xc2 ? 2 : 1;
            continue;
        }
        if(count + (space ? 1 : 0) >= max_chars) return result + "…";
        if(space)
        {
            result += ' ';
            ++count;
            space = false;
        }
        size_t end = i + 1;
        while(end < text.size() &&
              (static_cast<unsigned char>(text[end]) & 0xc0) == 0x80) ++end;
        result.append(text, i, end - i);
        i = end;
        ++count;
    }
    return result;
}

std::optional<std::string> languageForText(const nlohmann::json& object,
                                          std::string_view property)
{
    if(!object.is_object()) return std::nullopt;
    auto text = object.find(std::string(property));
    if(text == object.end() || !text->is_string()) return std::nullopt;
    std::optional<std::string> fallback;
    auto context = object.find("@context");
    if(context != object.end()) contextLanguage(*context, fallback);
    auto map = object.find(std::string(property) + "Map");
    if(map == object.end() || !map->is_object()) return fallback;
    std::optional<std::string> matching;
    bool ambiguous = false;
    for(auto entry = map->begin(); entry != map->end(); ++entry)
    {
        if(!entry->is_string() || *entry != *text) continue;
        if(fallback && lowerAscii(*fallback) == lowerAscii(entry.key()))
            return fallback;
        if(matching && lowerAscii(*matching) != lowerAscii(entry.key()))
            ambiguous = true;
        else matching = entry.key();
    }
    if(ambiguous) return std::nullopt;
    return matching ? matching : fallback;
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
