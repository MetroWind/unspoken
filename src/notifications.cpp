#include "service.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <libxml/HTMLparser.h>
#include <libxml/tree.h>
#include <mw/url.hpp>
#include <mw/utils.hpp>

namespace unspoken
{
namespace
{

void appendText(const xmlNode* node, std::string& result)
{
    for(; node; node = node->next)
    {
        if(node->type == XML_TEXT_NODE && node->content)
            result += reinterpret_cast<const char*>(node->content);
        else if(node->type == XML_ELEMENT_NODE)
        {
            if(xmlStrEqual(node->name, BAD_CAST "img"))
            {
                std::unique_ptr<xmlChar, decltype(xmlFree)> alt(
                    xmlGetProp(node, BAD_CAST "alt"), xmlFree);
                if(alt) result += reinterpret_cast<const char*>(alt.get());
            }
            else
            {
                bool block = xmlStrEqual(node->name, BAD_CAST "p")
                    || xmlStrEqual(node->name, BAD_CAST "div")
                    || xmlStrEqual(node->name, BAD_CAST "li")
                    || xmlStrEqual(node->name, BAD_CAST "br");
                if(block) result += ' ';
                appendText(node->children, result);
                if(block) result += ' ';
            }
        }
    }
}

std::string excerpt(const Post& post, std::string_view fallback)
{
    if(post.sensitive && (!post.summary || post.summary->empty()))
        return "sensitive post";
    std::string html = post.summary && !post.summary->empty()
        ? *post.summary : post.content_html;
    if(post.summary && !post.summary->empty() && post.local_author_id)
        html = mw::escapeHTML(*post.summary);
    if(html.size() > static_cast<size_t>(std::numeric_limits<int>::max()) - 64)
        return std::string(fallback);
    html = "<html><body><div>" + html + "</div></body></html>";
    std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)> doc(
        htmlReadMemory(html.data(), static_cast<int>(html.size()), nullptr,
            "UTF-8", HTML_PARSE_NONET | HTML_PARSE_NOERROR
            | HTML_PARSE_NOWARNING | HTML_PARSE_NODEFDTD), &xmlFreeDoc);
    if(!doc) return std::string(fallback);
    std::string text;
    appendText(xmlDocGetRootElement(doc.get()), text);
    std::string result;
    size_t count = 0;
    bool space = false;
    for(size_t i = 0; i < text.size();)
    {
        unsigned char first = text[i];
        size_t size = first < 0x80 ? 1 : first < 0xe0 ? 2
            : first < 0xf0 ? 3 : 4;
        if(i + size > text.size()) break;
        uint32_t code = first & (size == 1 ? 0x7f : size == 2 ? 0x1f
            : size == 3 ? 0x0f : 0x07);
        for(size_t j = 1; j < size; ++j)
            code = (code << 6) | (static_cast<unsigned char>(text[i+j]) & 63);
        bool whitespace = code <= 32 || code == 0xa0 || code == 0x1680
            || (code >= 0x2000 && code <= 0x200a) || code == 0x2028
            || code == 0x2029 || code == 0x202f || code == 0x205f
            || code == 0x3000;
        if(whitespace)
            space = !result.empty();
        else
        {
            if(count + (space ? 1 : 0) >= 80)
            {
                result += "…";
                break;
            }
            if(space)
            {
                result += ' ';
                ++count;
            }
            result.append(text, i, size);
            ++count;
            space = false;
        }
        i += size;
    }
    return mw::escapeHTML(result.empty() ? std::string(fallback) : result);
}

nlohmann::json postLink(const Config& config, const Post& post,
                         std::string_view fallback)
{
    return {{"url", mw::escapeHTML(config.url_root + "p/"
                + std::to_string(post.id))},
            {"excerpt", excerpt(post, fallback)}};
}

} // namespace

mw::E<void> Service::notifyInteraction(NotificationKind kind,
    std::string_view actor_uri, std::string_view target_uri,
    int64_t now_seconds, std::string_view reaction) const
{
    Notification entry;
    entry.kind = kind;
    entry.actor_uri = actor_uri;
    entry.created_at = now_seconds;
    std::optional<User> recipient;
    if(kind == NotificationKind::FOLLOW)
    {
        const std::string prefix = config.url_root + "u/";
        if(!target_uri.starts_with(prefix)) return {};
        ASSIGN_OR_RETURN(recipient, data.getUserByUsername(
            target_uri.substr(prefix.size())));
        if(!recipient || actor_uri == actorUri(recipient->username)) return {};
        ASSIGN_OR_RETURN(auto follow, data.getFollow(actor_uri, target_uri));
        if(!follow || follow->state != FollowState::ACCEPTED) return {};
        entry.follow_id = follow->id;
    }
    else
    {
        ASSIGN_OR_RETURN(auto post, data.getPostByUri(target_uri));
        if(!post || !post->local_author_id) return {};
        ASSIGN_OR_RETURN(recipient, data.getUserById(*post->local_author_id));
        if(!recipient || actor_uri == actorUri(recipient->username)) return {};
        entry.post_id = post->id;
        switch(kind)
        {
        case NotificationKind::LIKE:
        {
            ASSIGN_OR_RETURN(auto likes, data.likesForPost(post->uri));
            for(const auto& like : likes)
                if(like.actor_uri == actor_uri) entry.like_id = like.id;
            if(!entry.like_id) return {};
            break;
        }
        case NotificationKind::BOOST:
        {
            ASSIGN_OR_RETURN(auto boosts, data.boostsForPost(post->uri));
            for(const auto& boost : boosts)
                if(boost.actor_uri == actor_uri) entry.boost_id = boost.id;
            if(!entry.boost_id) return {};
            break;
        }
        case NotificationKind::REACTION:
        {
            ASSIGN_OR_RETURN(auto reactions, data.reactionsForPost(post->uri));
            for(const auto& saved : reactions)
                if(saved.actor_uri == actor_uri && saved.emoji == reaction)
                    entry.reaction_id = saved.id;
            if(!entry.reaction_id) return {};
            break;
        }
        default:
            return std::unexpected(mw::runtimeError(
                "Unsupported interaction notification kind"));
        }
    }
    entry.recipient_user_id = recipient->id;
    return data.recordNotification(entry);
}

mw::E<void> Service::notifyReply(const Post& reply,
    std::string_view actor_uri, int64_t now_seconds) const
{
    if(!reply.in_reply_to_uri) return {};
    ASSIGN_OR_RETURN(auto parent, data.getPostByUri(*reply.in_reply_to_uri));
    if(!parent || !parent->local_author_id) return {};
    ASSIGN_OR_RETURN(auto recipient, data.getUserById(*parent->local_author_id));
    if(!recipient || actor_uri == actorUri(recipient->username)) return {};
    ASSIGN_OR_RETURN(bool visible, canViewPost(reply, recipient));
    if(!visible) return {};
    Notification entry;
    entry.kind = NotificationKind::REPLY;
    entry.actor_uri = actor_uri;
    entry.recipient_user_id = recipient->id;
    entry.post_id = parent->id;
    entry.reply_post_id = reply.id;
    entry.created_at = now_seconds;
    return data.recordNotification(entry);
}

mw::E<nlohmann::json> Service::notificationPage(const User& viewer,
    const Cursor& cursor, int64_t now_seconds) const
{
    if(cursor.max_id && cursor.min_id)
        return std::unexpected(mw::httpError(400, "Conflicting cursors"));
    ASSIGN_OR_RETURN(auto entries, data.notificationsFor(viewer.id, now_seconds));
    std::vector<Notification> visible;
    std::vector<std::optional<Post>> posts;
    std::vector<std::optional<Post>> replies;
    for(const auto& entry : entries)
    {
        std::optional<Post> post;
        std::optional<Post> reply;
        if(entry.post_id)
        {
            ASSIGN_OR_RETURN(post, data.getPostById(*entry.post_id));
            if(!post) continue;
            ASSIGN_OR_RETURN(bool allowed, canViewPost(*post, viewer));
            if(!allowed) continue;
        }
        if(entry.reply_post_id)
        {
            ASSIGN_OR_RETURN(reply, data.getPostById(*entry.reply_post_id));
            if(!reply) continue;
            ASSIGN_OR_RETURN(bool allowed, canViewPost(*reply, viewer));
            if(!allowed) continue;
        }
        visible.push_back(entry);
        posts.push_back(std::move(post));
        replies.push_back(std::move(reply));
    }
    std::vector<size_t> selected;
    for(size_t i = 0; i < visible.size(); ++i)
    {
        if(cursor.max_id && visible[i].id >= *cursor.max_id) continue;
        if(cursor.min_id && visible[i].id <= *cursor.min_id) continue;
        selected.push_back(i);
    }
    if(selected.size() > NOTIFICATIONS_PER_PAGE)
    {
        if(cursor.min_id)
            selected.erase(selected.begin(), selected.end()
                           - NOTIFICATIONS_PER_PAGE);
        else
            selected.resize(NOTIFICATIONS_PER_PAGE);
    }
    std::vector<ActorCollectionItem> actors;
    std::map<std::string, size_t> actor_indexes;
    for(size_t i : selected)
    {
        const auto& entry = visible[i];
        if(actor_indexes.contains(entry.actor_uri)) continue;
        actor_indexes.emplace(entry.actor_uri, actors.size());
        actors.push_back({entry.id, entry.actor_uri});
    }
    ASSIGN_OR_RETURN(auto actor_views, followViews(actors));
    nlohmann::json result = {{"entries", nlohmann::json::array()},
        {"has_older", false}, {"has_newer", false}, {"older_id", 0},
        {"newer_id", 0}, {"paged", cursor.max_id || cursor.min_id}};
    for(size_t j = 0; j < selected.size(); ++j)
    {
        size_t i = selected[j];
        const auto& entry = visible[i];
        auto actor_view = actor_views[actor_indexes.find(entry.actor_uri)->second];
        auto actor_url = mw::URL::fromStr(entry.actor_uri);
        if(!actor_url || actor_url->host().empty()
           || (actor_url->scheme() != "https" && actor_url->scheme() != "http"))
        {
            actor_view["profile_url"] = "";
        }
        nlohmann::json view = {{"id", entry.id},
            {"kind", static_cast<int>(entry.kind)}, {"actor", actor_view},
            {"created_at", entry.created_at},
            {"timestamp", formatTimestamp(entry.created_at)},
            {"datetime", formatTimestamp(entry.created_at)}};
        std::string datetime = view["datetime"];
        datetime[10] = 'T';
        view["datetime"] = datetime + ":00Z";
        if(posts[i]) view["post"] = postLink(config, *posts[i], "your post");
        if(replies[i]) view["reply"] = postLink(config, *replies[i], "reply");
        if(entry.reaction_id && posts[i])
        {
            ASSIGN_OR_RETURN(auto reactions,
                             data.reactionsForPost(posts[i]->uri));
            bool found = false;
            for(const auto& saved : reactions)
            {
                if(saved.id != *entry.reaction_id) continue;
                view["emoji"] = mw::escapeHTML(saved.emoji);
                found = true;
                break;
            }
            if(!found) continue;
        }
        result["entries"].push_back(std::move(view));
    }
    if(!selected.empty())
    {
        int64_t first = visible[selected.front()].id;
        int64_t last = visible[selected.back()].id;
        result["newer_id"] = first;
        result["older_id"] = last;
        result["has_newer"] = visible.front().id > first;
        result["has_older"] = visible.back().id < last;
    }
    return result;
}

} // namespace unspoken
