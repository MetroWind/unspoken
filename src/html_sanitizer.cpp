#include "html_sanitizer.hpp"
#include <gumbo.h>
#include <vector>
#include <unordered_set>
#include <sstream>
#include <algorithm>
#include <iostream>

namespace
{

const std::unordered_set<std::string> ALLOWED_TAGS = {
    "a", "abbr", "acronym", "b", "blockquote", "code", "em", "i", 
    "li", "ol", "ul", "p", "pre", "strong", "br", "div", "span", 
    "img", "h1", "h2", "h3", "h4", "h5", "h6", "hr",
    "table", "thead", "tbody", "tr", "th", "td", "caption"
};

const std::unordered_set<std::string> ALLOWED_ATTRIBUTES = {
    "href", "title", "class", "src", "alt", "width", "height", "rel", "target"
};

const std::unordered_set<std::string> URL_ATTRIBUTES = {
    "href", "src"
};

const std::unordered_set<std::string> SAFE_SCHEMES = {
    "http", "https", "mailto", "xmpp", "magnet"
};

const std::unordered_set<std::string> VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", 
    "link", "meta", "param", "source", "track", "wbr"
};

bool isAllowedTag(const std::string& tag)
{
    return ALLOWED_TAGS.count(tag);
}

bool isAllowedAttribute(const std::string& attr)
{
    return ALLOWED_ATTRIBUTES.count(attr);
}

bool isVoidTag(const std::string& tag)
{
    return VOID_TAGS.count(tag);
}

bool isSafeUrl(const std::string& url)
{
    if(url.empty())
    {
        return true;
    }
    if(url.find(":") == std::string::npos)
    {
        return true; // Relative URL
    }
    
    // Check scheme
    std::string scheme;
    for(char c : url)
    {
        if(c == ':')
        {
            break;
        }
        scheme += std::tolower(c);
    }
    return SAFE_SCHEMES.count(scheme);
}

std::string escapeHtml(const std::string& data)
{
    std::string buffer;
    buffer.reserve(data.size());
    for(size_t pos = 0; pos != data.size(); ++pos)
    {
        switch(data[pos])
        {
            case '&':  buffer.append("&amp;");       break;
            case '"': buffer.append("&quot;");      break;
            case '\'': buffer.append("&apos;");      break;
            case '<':  buffer.append("&lt;");        break;
            case '>':  buffer.append("&gt;");        break;
            default:   buffer.append(&data[pos], 1); break;
        }
    }
    return buffer;
}

void traverse(GumboNode* node, std::stringstream& ss)
{
    if(node->type == GUMBO_NODE_TEXT)
    {
        ss << escapeHtml(std::string(node->v.text.text));
        return;
    }
    else if(node->type == GUMBO_NODE_WHITESPACE)
    {
        ss << node->v.text.text;
        return;
    }
    else if(node->type != GUMBO_NODE_ELEMENT)
    {
        return;
    }

    std::string tag = gumbo_normalized_tagname(node->v.element.tag);
    if(tag.empty())
    {
        GumboTag tag_enum = node->v.element.tag;
        if(tag_enum == GUMBO_TAG_UNKNOWN)
        {
            GumboStringPiece original = node->v.element.original_tag;
            gumbo_tag_from_original_text(&original);
        }
    }

    // Special handling for style/script to drop content
    if(tag == "script" || tag == "style" || tag == "iframe" || tag == "object" || 
        tag == "embed" || tag == "applet" || tag == "meta" || tag == "link" || tag == "title")
    {
        return; 
    }

    bool allowed = isAllowedTag(tag);

    if(allowed)
    {
        ss << "<" << tag;
        GumboVector* attributes = &node->v.element.attributes;
        for(unsigned int i = 0; i < attributes->length; ++i)
        {
            GumboAttribute* attr = static_cast<GumboAttribute*>(attributes->data[i]);
            std::string attr_name = attr->name;
            std::string attr_val = attr->value;

            if(isAllowedAttribute(attr_name))
            {
                if(URL_ATTRIBUTES.count(attr_name))
                {
                    if(!isSafeUrl(attr_val))
                    {
                        continue;
                    }
                }
                ss << " " << attr_name << "=\"" << escapeHtml(attr_val) << "\"";
            }
        }
        
        if(isVoidTag(tag))
        {
            ss << " />";
            return; // No children for void tags
        }
        else
        {
            ss << ">";
        }
    }

    GumboVector* children = &node->v.element.children;
    for(unsigned int i = 0; i < children->length; ++i)
    {
        traverse(static_cast<GumboNode*>(children->data[i]), ss);
    }

    if(allowed && !isVoidTag(tag))
    {
        ss << "</" << tag << ">";
    }
}

} // namespace

std::string HtmlSanitizer::sanitize(const std::string& input)
{
    GumboOutput* output = gumbo_parse(input.c_str());
    
    std::stringstream ss;
    
    // Gumbo wraps in <html><head>...</head><body>...</body></html>
    // We want to extract content of body.
    
    GumboNode* root = output->root;
    GumboNode* body = nullptr;
    
    if(root->type == GUMBO_NODE_ELEMENT)
    {
        // Find body
        if(root->v.element.children.length >= 2)
        {
            // usually head is 0, body is 1
            // But verify
            for(unsigned int i=0; i<root->v.element.children.length; ++i)
            {
                GumboNode* child = static_cast<GumboNode*>(root->v.element.children.data[i]);
                if(child->type == GUMBO_NODE_ELEMENT && child->v.element.tag == GUMBO_TAG_BODY)
                {
                    body = child;
                    break;
                }
            }
        }
    }
    
    if(body)
    {
        GumboVector* children = &body->v.element.children;
        for(unsigned int i = 0; i < children->length; ++i)
        {
            traverse(static_cast<GumboNode*>(children->data[i]), ss);
        }
    }
    else
    {
        // Fallback: just traverse root?
        traverse(root, ss);
    }

    gumbo_destroy_output(&kGumboDefaultOptions, output);
    return ss.str();
}