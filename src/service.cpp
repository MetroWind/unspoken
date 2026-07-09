#include "service.hpp"

#include <ctime>
#include <format>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>
#include <mw/error.hpp>
#include <mw/utils.hpp>

#include "attachments.hpp"
#include "config.hpp"
#include "data.hpp"
#include "render.hpp"
#include "structs.hpp"

namespace unspoken
{

namespace
{
int64_t nowSeconds()
{
    return static_cast<int64_t>(std::time(nullptr));
}

struct ReactionGroup
{
    int count = 0;
    bool viewer_reacted = false;
    std::string html;
};

std::string remoteEmojiHtml(const Reaction& reaction)
{
    if(!reaction.remote_emoji_url.has_value()) return "";
    return std::format(
        "<img class=\"emoji\" src=\"{}\" alt=\"{}\" title=\"{}\">",
        mw::escapeHTML(*reaction.remote_emoji_url),
        mw::escapeHTML(reaction.emoji),
        mw::escapeHTML(reaction.emoji));
}

mw::E<std::vector<std::string>> localMentionActorUris(
    const Config& config, const DataSourceInterface& data,
    const std::vector<ParsedMention>& mentions)
{
    std::vector<std::string> out;
    std::set<std::string> seen;
    for(const auto& mention : mentions)
    {
        if(!mention.domain.empty() && mention.domain != config.public_domain)
            continue;
        ASSIGN_OR_RETURN(auto user,
                         data.getUserByUsername(mention.username));
        if(!user.has_value()) continue;
        std::string uri = config.url_root + "u/" + user->username;
        if(seen.insert(uri).second) out.push_back(std::move(uri));
    }
    return out;
}

std::string localActorUri(const Config& config, std::string_view username)
{
    return config.url_root + "u/" + std::string(username);
}

std::string localAttachmentUrl(const Config& config, const Attachment& a)
{
    std::string ext = a.extension.empty()
        ? extensionOf(a.original_name) : a.extension;
    std::string filename = ext.empty() ? a.sha256 : (a.sha256 + "." + ext);
    return std::format("{}media/{}/{}", config.url_root,
                       a.sha256.substr(0, 1), filename);
}

mw::E<bool> canNonPublicActorViewPost(
    const Config& config, const DataSourceInterface& data, const Post& post,
    std::string_view actor_uri)
{
    if(post.visibility == Visibility::FOLLOWERS
       && post.local_author_id.has_value())
    {
        ASSIGN_OR_RETURN(auto author, data.getUserById(
            *post.local_author_id));
        if(author.has_value())
        {
            ASSIGN_OR_RETURN(auto f, data.getFollow(
                actor_uri, localActorUri(config, author->username)));
            if(f.has_value() && f->state == FollowState::ACCEPTED)
                return true;
        }
    }

    ASSIGN_OR_RETURN(auto recipients, data.getPostRecipients(post.id));
    for(const auto& r : recipients)
    {
        if(r.recipient_uri == actor_uri) return true;
    }
    return false;
}
} // namespace

std::string formatTimestamp(int64_t unix_seconds)
{
    std::time_t t = static_cast<std::time_t>(unix_seconds);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tm);
    return std::string(buf);
}

// ─── URI construction ──────────────────────────────────────────────────

std::string Service::actorUri(std::string_view username) const
{
    return std::format("{}u/{}", config.url_root, username);
}

std::string Service::followersUri(std::string_view username) const
{
    return std::format("{}u/{}/followers", config.url_root, username);
}

std::string Service::handleFor(std::string_view username) const
{
    return std::format("@{}@{}", username, config.public_domain);
}

// ─── Addressing (design §12.5) ─────────────────────────────────────────

std::vector<PostRecipient>
Service::recipientsFor(Visibility vis, std::string_view author_username,
                       const std::vector<std::string>& mentioned) const
{
    std::vector<PostRecipient> out;
    auto add = [&](const std::string& uri, const char* field) {
        out.push_back(PostRecipient{0, uri, field});
    };
    const std::string followers = followersUri(author_username);
    const std::string public_iri(AS_PUBLIC);

    switch(vis)
    {
    case Visibility::PUBLIC:
        add(public_iri, "to");
        add(followers, "cc");
        break;
    case Visibility::UNLISTED:
        add(followers, "to");
        add(public_iri, "cc");
        break;
    case Visibility::FOLLOWERS:
        add(followers, "to");
        break;
    case Visibility::DIRECT:
        // Recipients are exactly the mentioned actors (Phase 6 wires
        // mention extraction; for now the caller supplies them).
        for(const auto& m : mentioned) add(m, "to");
        break;
    }
    // Mentioned actors are always added to addressing so they receive the
    // post (design §13.2). For Direct they are already the `to` set above.
    if(vis != Visibility::DIRECT)
    {
        for(const auto& m : mentioned) add(m, "to");
    }
    return out;
}

// ─── Posting ───────────────────────────────────────────────────────────

mw::E<Post> Service::createPost(const User& author,
                                const ComposeParams& p) const
{
    RenderedPostContent rendered = parsePostContent(p.source, emoji);
    ASSIGN_OR_RETURN(auto mentioned_actors,
                     localMentionActorUris(config, data, rendered.mentions));
    std::set<std::string> seen_mentions(mentioned_actors.begin(),
                                        mentioned_actors.end());
    for(const auto& uri : p.mentioned_actor_uris)
    {
        if(seen_mentions.insert(uri).second)
            mentioned_actors.push_back(uri);
    }

    NewPost np;
    np.local_author_id = author.id;
    np.content_html = rendered.html;
    np.content_source = p.source;
    np.summary = p.summary;
    np.sensitive = p.sensitive;
    np.visibility = p.visibility;
    np.in_reply_to_uri = p.in_reply_to_uri;

    std::vector<PostRecipient> recipients =
        recipientsFor(p.visibility, author.username, mentioned_actors);
    std::string prefix = config.url_root + "p/";
    ASSIGN_OR_RETURN(Post post, data.insertPost(np, recipients, prefix));

    for(int64_t aid : p.attachment_ids)
    {
        DO_OR_RETURN(data.attachToPost(aid, post.id));
    }
    return post;
}

mw::E<bool> Service::canViewPost(const Post& post,
                                 const std::optional<User>& viewer) const
{
    if(post.visibility == Visibility::PUBLIC
       || post.visibility == Visibility::UNLISTED)
    {
        return true;
    }
    if(!viewer.has_value()) return false;
    // The author can always see their own post.
    if(post.local_author_id.has_value()
       && *post.local_author_id == viewer->id)
    {
        return true;
    }
    const std::string viewer_actor = actorUri(viewer->username);
    return canNonPublicActorViewPost(config, data, post, viewer_actor);
}

mw::E<bool> Service::canActorViewPost(const Post& post,
                                      std::string_view actor_uri) const
{
    if(post.visibility == Visibility::PUBLIC
       || post.visibility == Visibility::UNLISTED)
    {
        return true;
    }

    if(post.local_author_id.has_value())
    {
        ASSIGN_OR_RETURN(auto author, data.getUserById(*post.local_author_id));
        if(author.has_value() && actor_uri == actorUri(author->username))
        {
            return true;
        }
    }

    return canNonPublicActorViewPost(config, data, post, actor_uri);
}

// ─── Timelines ─────────────────────────────────────────────────────────

mw::E<std::vector<Post>>
Service::homeTimeline(const User& viewer, const Cursor& c) const
{
    const std::string viewer_actor = actorUri(viewer.username);
    ASSIGN_OR_RETURN(auto following, data.followingUris(viewer_actor));

    std::vector<int64_t> author_ids;
    std::vector<int64_t> remote_author_ids;
    author_ids.push_back(viewer.id);
    const std::string local_prefix = config.url_root + "u/";
    for(const auto& uri : following)
    {
        if(uri.starts_with(local_prefix))
        {
            std::string_view username = std::string_view(uri).substr(
                local_prefix.size());
            // Strip any trailing path (defensive; actor URIs have none).
            if(size_t slash = username.find('/');
               slash != std::string_view::npos)
            {
                username = username.substr(0, slash);
            }
            ASSIGN_OR_RETURN(auto u, data.getUserByUsername(username));
            if(u.has_value()) author_ids.push_back(u->id);
            continue;
        }

        ASSIGN_OR_RETURN(auto actor, data.getRemoteActorByUri(uri));
        if(actor.has_value()) remote_author_ids.push_back(actor->id);
    }
    return data.homeTimelinePosts(author_ids, remote_author_ids, viewer.id, c,
                                  config.posts_per_page, viewer_actor);
}

// ─── Interactions ──────────────────────────────────────────────────────

mw::E<void> Service::setLike(const User& viewer, const Post& p, bool on) const
{
    const std::string actor = actorUri(viewer.username);
    if(on)
    {
        Like l;
        l.actor_uri = actor;
        l.post_uri = p.uri;
        l.activity_uri = std::format("{}activities/like/{}/{}",
                                     config.url_root, viewer.id, p.id);
        l.created_at = nowSeconds();
        return data.addLike(l);
    }
    return data.removeLike(actor, p.uri);
}

mw::E<void> Service::setBoost(const User& viewer, const Post& p, bool on) const
{
    // Only Public and Unlisted posts can be boosted (PRD line 25).
    if(on && p.visibility != Visibility::PUBLIC
       && p.visibility != Visibility::UNLISTED)
    {
        return std::unexpected(mw::httpError(
            403, "Only public or unlisted posts can be boosted"));
    }
    const std::string actor = actorUri(viewer.username);
    if(on)
    {
        Boost b;
        b.actor_uri = actor;
        b.post_uri = p.uri;
        b.activity_uri = std::format("{}activities/boost/{}/{}",
                                     config.url_root, viewer.id, p.id);
        b.created_at = nowSeconds();
        return data.addBoost(b);
    }
    return data.removeBoost(actor, p.uri);
}

mw::E<void> Service::setReaction(const User& viewer, const Post& p,
                                 std::string_view emoji_str, bool on) const
{
    const std::string actor = actorUri(viewer.username);
    if(on)
    {
        Reaction r;
        r.actor_uri = actor;
        r.post_uri = p.uri;
        r.emoji = std::string(emoji_str);
        r.activity_uri = std::format("{}activities/react/{}/{}/{:x}",
                                     config.url_root, viewer.id, p.id,
                                     std::hash<std::string>{}(r.emoji));
        r.created_at = nowSeconds();
        return data.addReaction(r);
    }
    return data.removeReaction(actor, p.uri, emoji_str);
}

mw::E<void> Service::setBookmark(const User& viewer, const Post& p,
                                 bool on) const
{
    if(on) return data.addBookmark(viewer.id, p.id);
    return data.removeBookmark(viewer.id, p.id);
}

mw::E<void> Service::setFollowActor(
    const User& viewer, std::string_view target_actor_uri, bool on,
    FollowState state, std::optional<std::string> follow_activity_uri) const
{
    const std::string follower = actorUri(viewer.username);
    const std::string followee(target_actor_uri);
    if(follower == followee)
    {
        return std::unexpected(mw::httpError(400, "Cannot follow yourself"));
    }
    if(on)
    {
        Follow f;
        f.follower_uri = follower;
        f.followee_uri = followee;
        f.state = state;
        f.follow_activity_uri = std::move(follow_activity_uri);
        f.created_at = nowSeconds();
        return data.addFollow(f);
    }
    return data.removeFollow(follower, followee);
}

mw::E<void> Service::setFollow(const User& viewer,
                               std::string_view target_username,
                               bool on) const
{
    // Local follows auto-accept immediately (no federation needed).
    return setFollowActor(viewer, actorUri(target_username), on);
}

// ─── View models ───────────────────────────────────────────────────────

mw::E<void> Service::updateProfile(const User& user,
                                   const UserProfileUpdate& update) const
{
    if(update.display_name.size() > 120)
    {
        return std::unexpected(mw::httpError(
            400, "Display name is too long."));
    }
    if(update.bio.size() > 5000)
    {
        return std::unexpected(mw::httpError(400, "Bio is too long."));
    }

    auto check_profile_media = [&](std::optional<int64_t> id,
                                   std::string_view name) -> mw::E<void> {
        if(!id.has_value()) return {};
        ASSIGN_OR_RETURN(auto attachment, data.getAttachmentById(*id));
        if(!attachment.has_value())
        {
            return std::unexpected(mw::httpError(
                400, std::format("{} attachment does not exist.", name)));
        }
        if(attachment->remote_url.has_value() || !attachment->is_image)
        {
            return std::unexpected(mw::httpError(
                400, std::format("{} must be a local image.", name)));
        }
        return {};
    };
    DO_OR_RETURN(check_profile_media(update.avatar_attachment_id, "Avatar"));
    DO_OR_RETURN(check_profile_media(update.banner_attachment_id, "Banner"));

    std::vector<UserProfileField> fields;
    fields.reserve(update.fields.size());
    for(const auto& field : update.fields)
    {
        std::string label(mw::strip(field.label));
        std::string value(mw::strip(field.value));
        if(label.empty() && value.empty()) continue;
        if(label.empty())
        {
            return std::unexpected(mw::httpError(
                400, "Profile field label is required when value is set."));
        }
        if(value.empty())
        {
            return std::unexpected(mw::httpError(
                400, "Profile field value is required when label is set."));
        }
        if(label.size() > 40)
        {
            return std::unexpected(mw::httpError(
                400, "Profile field label is too long."));
        }
        if(value.size() > 250)
        {
            return std::unexpected(mw::httpError(
                400, "Profile field value is too long."));
        }
        if(fields.size() >= static_cast<size_t>(MAX_PROFILE_FIELDS))
        {
            return std::unexpected(mw::httpError(
                400, "Too many profile fields."));
        }
        fields.push_back(UserProfileField{
            0, user.id, std::move(label), std::move(value),
            static_cast<int>(fields.size()),
        });
    }

    UserProfileUpdate normalized;
    normalized.display_name = update.display_name;
    normalized.bio = update.bio;
    normalized.avatar_attachment_id = update.avatar_attachment_id;
    normalized.banner_attachment_id = update.banner_attachment_id;
    normalized.fields = std::move(fields);
    return data.replaceUserProfile(normalized, user.id);
}

mw::E<std::vector<RenderedProfileField>>
Service::renderedProfileFields(const User& user) const
{
    ASSIGN_OR_RETURN(auto fields, data.profileFieldsForUser(user.id));
    std::vector<RenderedProfileField> out;
    out.reserve(fields.size());
    for(const auto& field : fields)
    {
        std::string label(mw::strip(field.label));
        std::string value(mw::strip(field.value));
        if(label.empty() || value.empty()) continue;
        out.push_back(RenderedProfileField{
            label,
            renderPostContent(value, emoji),
        });
    }
    return out;
}

mw::E<nlohmann::json> Service::userView(const User& u) const
{
    // Plain-text fields are HTML-escaped here because Inja does not
    // auto-escape; rendered HTML fields are emitted raw after generation.
    auto esc = [](std::string_view s) { return mw::escapeHTML(s); };
    nlohmann::json j;
    j["id"] = u.id;
    j["username"] = esc(u.username);
    j["display_name"] =
        esc(u.display_name.empty() ? u.username : u.display_name);
    j["handle"] = esc(handleFor(u.username));
    j["profile_url"] = esc(actorUri(u.username));
    j["bio_source"] = esc(u.bio);          // shown in the edit textarea
    j["bio_html"] = renderPostContent(u.bio, emoji);
    j["avatar_url"] = "";
    j["avatar_alt"] = esc(std::format("{} avatar",
                                      u.display_name.empty()
                                      ? u.username : u.display_name));
    j["banner_url"] = "";
    j["banner_alt"] = esc(std::format("{} banner",
                                      u.display_name.empty()
                                      ? u.username : u.display_name));

    if(u.avatar_attachment_id.has_value())
    {
        ASSIGN_OR_RETURN(auto avatar,
                         data.getAttachmentById(*u.avatar_attachment_id));
        if(avatar.has_value() && !avatar->remote_url.has_value()
           && avatar->is_image)
        {
            j["avatar_url"] = esc(localAttachmentUrl(config, *avatar));
        }
    }
    if(u.banner_attachment_id.has_value())
    {
        ASSIGN_OR_RETURN(auto banner,
                         data.getAttachmentById(*u.banner_attachment_id));
        if(banner.has_value() && !banner->remote_url.has_value()
           && banner->is_image)
        {
            j["banner_url"] = esc(localAttachmentUrl(config, *banner));
        }
    }

    ASSIGN_OR_RETURN(auto source_fields, data.profileFieldsForUser(u.id));
    ASSIGN_OR_RETURN(auto rendered_fields, renderedProfileFields(u));
    nlohmann::json fields = nlohmann::json::array();
    for(size_t i = 0; i < rendered_fields.size(); ++i)
    {
        const auto& field = rendered_fields[i];
        std::string source_value;
        if(i < source_fields.size()) source_value = source_fields[i].value;
        fields.push_back({
            {"label", esc(field.label)},
            {"value_source", esc(source_value)},
            {"value_html", field.value_html},
        });
    }
    j["fields"] = std::move(fields);
    j["is_local"] = true;
    return j;
}

mw::E<nlohmann::json>
Service::postView(const Post& p, const std::optional<User>& viewer) const
{
    auto esc = [](std::string_view s) { return mw::escapeHTML(s); };
    nlohmann::json j;
    j["id"] = p.id;
    j["uri"] = esc(p.uri);
    j["url"] = esc(p.uri); // local posts: the uri is the canonical URL
    j["content_html"] = p.content_html; // already rendered/sanitized HTML
    j["summary"] = esc(p.summary.value_or(""));
    j["has_summary"] = p.summary.has_value() && !p.summary->empty();
    j["sensitive"] = p.sensitive;
    j["visibility"] = std::string(visibilityToStr(p.visibility));
    j["created_at"] = formatTimestamp(p.created_at);
    j["in_reply_to_uri"] = esc(p.in_reply_to_uri.value_or(""));
    j["is_reply"] = p.in_reply_to_uri.has_value();

    // ── Author ──
    nlohmann::json author;
    if(p.local_author_id.has_value())
    {
        ASSIGN_OR_RETURN(auto u, data.getUserById(*p.local_author_id));
        if(u.has_value())
        {
            author["username"] = esc(u->username);
            author["display_name"] =
                esc(u->display_name.empty() ? u->username : u->display_name);
            author["handle"] = esc(handleFor(u->username));
            author["profile_url"] = esc(actorUri(u->username));
            author["is_local"] = true;
        }
    }
    if(author.is_null())
    {
        if(p.remote_author_id.has_value())
        {
            ASSIGN_OR_RETURN(auto a, data.getRemoteActorById(
                *p.remote_author_id));
            if(a.has_value())
            {
                std::string display = a->display_name.empty()
                    ? a->username : a->display_name;
                author["username"] = esc(a->username);
                author["display_name"] = esc(display);
                author["handle"] =
                    esc(std::format("@{}@{}", a->username, a->domain));
                author["profile_url"] = esc(a->uri);
                author["is_local"] = false;
            }
        }
    }
    if(author.is_null())
    {
        author["username"] = "unknown";
        author["display_name"] = "unknown";
        author["handle"] = "";
        author["profile_url"] = "";
        author["is_local"] = false;
    }
    j["author"] = author;

    // ── Attachments ──
    ASSIGN_OR_RETURN(auto atts, data.attachmentsForPost(p.id));
    nlohmann::json att_arr = nlohmann::json::array();
    for(const auto& a : atts)
    {
        nlohmann::json aj;
        if(a.remote_url.has_value())
        {
            aj["url"] = esc(*a.remote_url);
        }
        else
        {
            aj["url"] = esc(localAttachmentUrl(config, a));
        }
        aj["media_type"] = esc(a.media_type);
        aj["is_image"] = a.is_image;
        aj["original_name"] = esc(a.original_name);
        aj["sensitive"] = a.sensitive;
        att_arr.push_back(std::move(aj));
    }
    j["attachments"] = att_arr;

    // ── Likes / reactions ──
    ASSIGN_OR_RETURN(auto likes, data.likesForPost(p.uri));
    j["like_count"] = likes.size();
    const std::string viewer_actor =
        viewer.has_value() ? actorUri(viewer->username) : "";
    bool liked = false;
    for(const auto& l : likes)
        if(l.actor_uri == viewer_actor) { liked = true; break; }
    j["liked"] = liked;

    ASSIGN_OR_RETURN(auto boosts, data.boostsForPost(p.uri));
    j["boost_count"] = boosts.size();
    bool boosted = false;
    for(const auto& b : boosts)
        if(b.actor_uri == viewer_actor) { boosted = true; break; }
    j["boosted"] = boosted;

    ASSIGN_OR_RETURN(auto reactions, data.reactionsForPost(p.uri));
    // Group reactions by emoji, count, and whether the viewer reacted.
    std::vector<std::string> order;
    std::map<std::string, ReactionGroup> grouped;
    for(const auto& r : reactions)
    {
        auto it = grouped.find(r.emoji);
        if(it == grouped.end())
        {
            order.push_back(r.emoji);
            ReactionGroup g;
            g.count = 1;
            g.html = remoteEmojiHtml(r);
            if(g.html.empty())
                g.html = substituteEmoji(mw::escapeHTML(r.emoji), emoji);
            grouped.emplace(r.emoji, std::move(g));
            it = grouped.find(r.emoji);
        }
        else
        {
            it->second.count += 1;
        }
        if(r.actor_uri == viewer_actor) it->second.viewer_reacted = true;
    }
    nlohmann::json react_arr = nlohmann::json::array();
    for(const auto& e : order)
    {
        nlohmann::json rj;
        rj["emoji"] = e;
        rj["emoji_html"] = grouped[e].html;
        rj["count"] = grouped[e].count;
        rj["reacted"] = grouped[e].viewer_reacted;
        react_arr.push_back(std::move(rj));
    }
    j["reactions"] = react_arr;

    // ── Viewer-relative flags ──
    bool is_author = viewer.has_value() && p.local_author_id.has_value()
        && *p.local_author_id == viewer->id;
    j["is_author"] = is_author;
    j["can_delete"] = is_author;
    j["can_boost"] = (p.visibility == Visibility::PUBLIC
                      || p.visibility == Visibility::UNLISTED);
    bool bookmarked = false;
    if(viewer.has_value())
    {
        ASSIGN_OR_RETURN(bookmarked, data.isBookmarked(viewer->id, p.id));
    }
    j["bookmarked"] = bookmarked;
    j["logged_in"] = viewer.has_value();
    return j;
}

mw::E<nlohmann::json>
Service::postViews(const std::vector<Post>& posts,
                   const std::optional<User>& viewer) const
{
    nlohmann::json arr = nlohmann::json::array();
    for(const auto& p : posts)
    {
        ASSIGN_OR_RETURN(auto v, postView(p, viewer));
        arr.push_back(std::move(v));
    }
    return arr;
}

} // namespace unspoken
