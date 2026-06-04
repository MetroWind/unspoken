#include "federation.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <ctime>
#include <format>
#include <iomanip>
#include <locale>
#include <sstream>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>
#include <mw/crypto.hpp>
#include <mw/error.hpp>
#include <mw/http_client.hpp>
#include <mw/url.hpp>
#include <mw/utils.hpp>

#include "attachments.hpp"
#include "data.hpp"
#include "structs.hpp"

namespace unspoken
{

namespace
{

nlohmann::json activityContext()
{
    return nlohmann::json::array({
        "https://www.w3.org/ns/activitystreams",
        "https://w3id.org/security/v1",
    });
}

std::string isoTimestamp(int64_t unix_seconds)
{
    std::time_t t = static_cast<std::time_t>(unix_seconds);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

std::string httpDate()
{
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[40];
    std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    return std::string(buf);
}

std::string requestTarget(const mw::URL& url)
{
    std::string path = url.path();
    if(path.empty()) path = "/";
    std::string query = url.query();
    if(!query.empty()) path += "?" + query;
    return path;
}

std::string requestAuthority(const mw::URL& url)
{
    std::string host = url.host();
    std::string port = url.port();
    if(port.empty()) return host;
    if((url.scheme() == "https" && port == "443")
       || (url.scheme() == "http" && port == "80"))
    {
        return host;
    }
    return host + ":" + port;
}

bool ipv4In(const std::vector<uint8_t>& a, uint8_t b0)
{
    return a.size() == 4 && a[0] == b0;
}

bool ipv4In(const std::vector<uint8_t>& a, uint8_t b0, uint8_t b1)
{
    return a.size() == 4 && a[0] == b0 && a[1] == b1;
}

bool ipv6AllZeroUntilLast(const std::vector<uint8_t>& a, uint8_t last)
{
    if(a.size() != 16 || a[15] != last) return false;
    for(size_t i = 0; i < 15; ++i) if(a[i] != 0) return false;
    return true;
}

std::string lower(std::string_view s)
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

std::unordered_map<std::string, std::string>
lowerHeaders(const std::unordered_map<std::string, std::string>& headers)
{
    std::unordered_map<std::string, std::string> out;
    for(const auto& [k, v] : headers) out[lower(k)] = v;
    return out;
}

std::optional<std::string> header(
    const std::unordered_map<std::string, std::string>& headers,
    std::string_view name)
{
    auto it = headers.find(std::string(name));
    if(it == headers.end()) return std::nullopt;
    return it->second;
}

std::vector<std::string> splitWords(std::string_view s)
{
    std::istringstream in{std::string(s)};
    std::vector<std::string> out;
    std::string item;
    while(in >> item) out.push_back(item);
    return out;
}

std::unordered_map<std::string, std::string>
parseSignatureParams(std::string_view sig)
{
    std::unordered_map<std::string, std::string> out;
    size_t pos = 0;
    while(pos < sig.size())
    {
        while(pos < sig.size() && (sig[pos] == ' ' || sig[pos] == ','))
            ++pos;
        size_t eq = sig.find('=', pos);
        if(eq == std::string_view::npos) break;
        std::string key = lower(sig.substr(pos, eq - pos));
        pos = eq + 1;
        std::string value;
        if(pos < sig.size() && sig[pos] == '"')
        {
            ++pos;
            while(pos < sig.size())
            {
                if(sig[pos] == '\\' && pos + 1 < sig.size())
                {
                    value.push_back(sig[pos + 1]);
                    pos += 2;
                    continue;
                }
                if(sig[pos] == '"')
                {
                    ++pos;
                    break;
                }
                value.push_back(sig[pos++]);
            }
        }
        else
        {
            size_t comma = sig.find(',', pos);
            value = std::string(sig.substr(
                pos, comma == std::string_view::npos ? comma : comma - pos));
            pos = comma == std::string_view::npos ? sig.size() : comma + 1;
        }
        out[key] = value;
    }
    return out;
}

std::optional<int64_t> parseHttpDate(std::string_view date)
{
    std::tm tm{};
    std::istringstream in{std::string(date)};
    in.imbue(std::locale::classic());
    in >> std::get_time(&tm, "%a, %d %b %Y %H:%M:%S GMT");
    if(in.fail()) return std::nullopt;
#if defined(_WIN32)
    return static_cast<int64_t>(_mkgmtime(&tm));
#else
    return static_cast<int64_t>(timegm(&tm));
#endif
}

mw::E<std::string> digestHeaderFor(std::string_view body)
{
    mw::SHA256Hasher hasher;
    ASSIGN_OR_RETURN(auto digest, hasher.hashToBytes(std::string(body)));
    return "SHA-256=" + mw::base64Encode(
        std::span<unsigned char>(digest.data(), digest.size()), false, true);
}

bool containsHeader(const std::vector<std::string>& headers,
                    std::string_view name)
{
    for(const auto& h : headers) if(lower(h) == name) return true;
    return false;
}

mw::E<std::string> signingString(
    const IncomingHttpRequest& req,
    const std::unordered_map<std::string, std::string>& headers,
    const std::vector<std::string>& signed_headers)
{
    std::vector<std::string> lines;
    for(const auto& raw_name : signed_headers)
    {
        std::string name = lower(raw_name);
        if(name == "(request-target)")
        {
            lines.push_back(std::format("(request-target): {} {}",
                                        lower(req.method), req.target));
            continue;
        }
        auto value = header(headers, name);
        if(!value.has_value())
        {
            return std::unexpected(mw::runtimeError(
                std::format("Signed header missing: {}", name)));
        }
        lines.push_back(std::format("{}: {}", name, *value));
    }

    std::string out;
    for(size_t i = 0; i < lines.size(); ++i)
    {
        if(i > 0) out.push_back('\n');
        out += lines[i];
    }
    return out;
}

void appendAll(std::vector<std::string>& out,
               const std::vector<std::string>& in)
{
    out.insert(out.end(), in.begin(), in.end());
}

mw::E<SigningActor> signingActorForUri(const Config& config,
                                       const DataSourceInterface& data,
                                       std::string_view actor_uri)
{
    const std::string system_uri = config.url_root + "actor";
    if(actor_uri == system_uri)
    {
        ASSIGN_OR_RETURN(auto system, data.getSystemActor());
        if(!system.has_value())
        {
            return std::unexpected(mw::runtimeError(
                "Delivery signer is missing system actor"));
        }
        return signingActorForSystem(config, *system);
    }

    const std::string local_prefix = config.url_root + "u/";
    if(!actor_uri.starts_with(local_prefix))
    {
        return std::unexpected(mw::runtimeError(
            "Delivery signer must be a local actor"));
    }
    std::string_view username = actor_uri.substr(local_prefix.size());
    if(username.empty() || username.find('/') != std::string_view::npos)
    {
        return std::unexpected(mw::runtimeError(
            "Delivery signer actor URI is invalid"));
    }
    ASSIGN_OR_RETURN(auto user, data.getUserByUsername(username));
    if(!user.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Delivery signer local user not found"));
    }
    return signingActorFor(config, *user);
}

mw::E<void> performDeliveryJob(const Config& config,
                               const DataSourceInterface& data,
                               mw::CryptoInterface& crypto,
                               mw::HTTPSessionInterface& http,
                               const nlohmann::json& payload)
{
    if(!payload.is_object() || !payload.contains("target_inbox")
       || !payload["target_inbox"].is_string()
       || !payload.contains("signer_actor")
       || !payload["signer_actor"].is_string()
       || !payload.contains("activity"))
    {
        return std::unexpected(mw::runtimeError(
            "Delivery job payload is malformed"));
    }

    std::string inbox = payload["target_inbox"].get<std::string>();
    std::string signer_uri = payload["signer_actor"].get<std::string>();
    ASSIGN_OR_RETURN(auto signer, signingActorForUri(config, data,
                                                     signer_uri));
    std::string body = payload["activity"].dump();

    DO_OR_RETURN(hardenOutboundSession(http));
    ASSIGN_OR_RETURN(auto req, signedHttpRequest(
        crypto, signer, "POST", inbox, body, "application/activity+json"));
    ASSIGN_OR_RETURN(const mw::HTTPResponse* res, http.post(req));
    if(res->status < 200 || res->status >= 300)
    {
        return std::unexpected(mw::httpError(
            res->status, "Activity delivery failed"));
    }
    return {};
}

bool isLocalActorUri(const Config& config, std::string_view uri)
{
    return uri.starts_with(config.url_root + "u/")
        || uri == config.url_root + "actor";
}

std::optional<std::string> localUsernameForActor(const Config& config,
                                                 std::string_view uri)
{
    const std::string prefix = config.url_root + "u/";
    if(!uri.starts_with(prefix)) return std::nullopt;
    std::string_view username = uri.substr(prefix.size());
    if(username.empty() || username.find('/') != std::string_view::npos)
        return std::nullopt;
    return std::string(username);
}

std::optional<std::string> followersCollectionOwner(const Config& config,
                                                    std::string_view uri)
{
    constexpr std::string_view SUFFIX = "/followers";
    if(!uri.starts_with(config.url_root + "u/")
       || !uri.ends_with(SUFFIX))
    {
        return std::nullopt;
    }
    return std::string(uri.substr(0, uri.size() - SUFFIX.size()));
}

bool addressesContainPublic(const std::vector<std::string>& addresses)
{
    for(const auto& uri : addresses)
        if(isPublicAddress(uri)) return true;
    return false;
}

Visibility visibilityForActivityObject(const nlohmann::json& object)
{
    std::vector<std::string> to = normalizeAddressing(
        object.value("to", nlohmann::json()));
    std::vector<std::string> cc = normalizeAddressing(
        object.value("cc", nlohmann::json()));
    if(addressesContainPublic(to)) return Visibility::PUBLIC;
    if(addressesContainPublic(cc)) return Visibility::UNLISTED;
    return Visibility::FOLLOWERS;
}

std::vector<PostRecipient> recipientsForObject(const nlohmann::json& object)
{
    std::vector<PostRecipient> out;
    for(const auto& uri : normalizeAddressing(
            object.value("to", nlohmann::json())))
    {
        out.push_back(PostRecipient{0, uri, "to"});
    }
    for(const auto& uri : normalizeAddressing(
            object.value("cc", nlohmann::json())))
    {
        out.push_back(PostRecipient{0, uri, "cc"});
    }
    return out;
}

mw::E<void> storeRemoteAttachments(const DataSourceInterface& data,
                                   const nlohmann::json& object,
                                   int64_t post_id)
{
    nlohmann::json attachments = object.value("attachment",
                                              nlohmann::json::array());
    if(attachments.is_object()) attachments = nlohmann::json::array(
        {attachments});
    if(!attachments.is_array()) return {};

    for(const auto& item : attachments)
    {
        if(!item.is_object()) continue;
        auto url = normalizeRef(item.contains("url") ? item["url"]
                                                     : nlohmann::json());
        if(!url.has_value()) continue;
        Attachment a;
        a.post_id = post_id;
        a.sha256 = "";
        a.media_type = item.value("mediaType", std::string());
        a.original_name = item.value("name", *url);
        a.sensitive = item.value("sensitive", false);
        a.remote_url = *url;
        std::string type = item.value("type", std::string());
        a.is_image = type == "Image" || a.media_type.starts_with("image/");
        DO_OR_RETURN(data.insertAttachment(a));
    }
    return {};
}

mw::E<void> handleCreateActivity(const Config& config,
                                 const DataSourceInterface& data,
                                 const Activity& activity)
{
    if(!activity.object.is_object()
       || activity.object.value("type", std::string()) != "Note")
    {
        return {};
    }
    auto uri = normalizeRef(activity.object);
    if(!uri.has_value()) return {};
    ASSIGN_OR_RETURN(auto existing, data.getPostByUri(*uri));
    if(existing.has_value()) return {};

    auto attributed_to = normalizeRef(
        activity.object.contains("attributedTo")
            ? activity.object["attributedTo"] : nlohmann::json());
    std::string author_uri = attributed_to.value_or(activity.actor);
    std::optional<int64_t> remote_author_id;
    ASSIGN_OR_RETURN(auto remote_author, data.getRemoteActorByUri(author_uri));
    if(remote_author.has_value()) remote_author_id = remote_author->id;

    NewPost np;
    np.uri = *uri;
    np.remote_author_id = remote_author_id;
    // Temporary conservative sanitizer until the planned HTML sanitizer
    // layer lands: render remote HTML as text, not executable markup.
    np.content_html = mw::escapeHTML(
        activity.object.value("content", std::string()));
    np.summary = activity.object.contains("summary")
        && activity.object["summary"].is_string()
        ? std::optional<std::string>(mw::escapeHTML(
              activity.object["summary"].get<std::string>()))
        : std::nullopt;
    np.sensitive = activity.object.value("sensitive", false);
    np.visibility = visibilityForActivityObject(activity.object);
    np.in_reply_to_uri = normalizeRef(
        activity.object.contains("inReplyTo")
            ? activity.object["inReplyTo"] : nlohmann::json());
    if(activity.object.contains("published")
       && activity.object["published"].is_string())
    {
        np.published = activity.object["published"].get<std::string>();
    }
    ASSIGN_OR_RETURN(auto post, data.insertPost(
        np, recipientsForObject(activity.object), config.url_root + "p/"));
    return storeRemoteAttachments(data, activity.object, post.id);
}

mw::E<void> handleFollowActivity(const Config& config,
                                 const DataSourceInterface& data,
                                 const Activity& activity,
                                 int64_t now_seconds)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return {};
    auto username = localUsernameForActor(config, *object_uri);
    if(!username.has_value()) return {};
    ASSIGN_OR_RETURN(auto local_user, data.getUserByUsername(*username));
    if(!local_user.has_value()) return {};

    Follow follow;
    follow.follower_uri = activity.actor;
    follow.followee_uri = *object_uri;
    follow.state = FollowState::ACCEPTED;
    follow.follow_activity_uri = activity.id;
    follow.created_at = now_seconds;
    DO_OR_RETURN(data.addFollow(follow));

    nlohmann::json accept = {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", std::format("{}activities/accept/{}", config.url_root,
                           now_seconds)},
        {"type", "Accept"},
        {"actor", *object_uri},
        {"object", activity.raw},
        {"to", nlohmann::json::array({activity.actor})},
    };
    std::vector<PostRecipient> recipients = {
        {0, activity.actor, "to"},
    };
    ASSIGN_OR_RETURN(auto jobs, enqueueOutboundDelivery(
        config, data, *object_uri, accept, recipients, now_seconds));
    (void)jobs;
    return {};
}

mw::E<void> handleAcceptActivity(const DataSourceInterface& data,
                                 const Activity& activity)
{
    if(!activity.object.is_object()) return {};
    auto follower = normalizeRef(
        activity.object.contains("actor") ? activity.object["actor"]
                                          : nlohmann::json());
    auto followee = normalizeRef(
        activity.object.contains("object") ? activity.object["object"]
                                           : nlohmann::json());
    if(!follower.has_value() || !followee.has_value()) return {};
    return data.setFollowState(*follower, *followee, FollowState::ACCEPTED);
}

mw::E<void> handleLikeActivity(const DataSourceInterface& data,
                               const Activity& activity,
                               int64_t now_seconds)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return {};
    ASSIGN_OR_RETURN(auto post, data.getPostByUri(*object_uri));
    if(!post.has_value()) return {};
    Like like;
    like.actor_uri = activity.actor;
    like.post_uri = *object_uri;
    like.activity_uri = activity.id;
    like.created_at = now_seconds;
    return data.addLike(like);
}

mw::E<void> handleAnnounceActivity(const DataSourceInterface& data,
                                   const Activity& activity,
                                   int64_t now_seconds)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return {};
    ASSIGN_OR_RETURN(auto post, data.getPostByUri(*object_uri));
    if(!post.has_value()) return {};
    if(post->visibility != Visibility::PUBLIC
       && post->visibility != Visibility::UNLISTED)
    {
        return {};
    }
    Boost boost;
    boost.actor_uri = activity.actor;
    boost.post_uri = *object_uri;
    boost.activity_uri = activity.id;
    boost.created_at = now_seconds;
    return data.addBoost(boost);
}

mw::E<void> handleEmojiReactActivity(const DataSourceInterface& data,
                                     const Activity& activity,
                                     int64_t now_seconds)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return {};
    ASSIGN_OR_RETURN(auto post, data.getPostByUri(*object_uri));
    if(!post.has_value()) return {};
    std::string emoji = activity.raw.value("content", std::string());
    if(emoji.empty()) emoji = activity.raw.value("name", std::string());
    if(emoji.empty()) return {};
    Reaction reaction;
    reaction.actor_uri = activity.actor;
    reaction.post_uri = *object_uri;
    reaction.emoji = emoji;
    reaction.activity_uri = activity.id;
    reaction.created_at = now_seconds;
    return data.addReaction(reaction);
}

mw::E<void> handleDeleteActivity(const DataSourceInterface& data,
                                 const Activity& activity)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return {};
    ASSIGN_OR_RETURN(auto post, data.getPostByUri(*object_uri));
    if(!post.has_value()) return {};
    return data.deletePost(post->id);
}

mw::E<void> handleUpdateActivity(const Config& config,
                                 const DataSourceInterface& data,
                                 const Activity& activity)
{
    if(!activity.object.is_object()
       || activity.object.value("type", std::string()) != "Note")
    {
        return {};
    }
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return {};
    ASSIGN_OR_RETURN(auto existing, data.getPostByUri(*object_uri));
    if(!existing.has_value()) return {};
    DO_OR_RETURN(data.deletePost(existing->id));
    return handleCreateActivity(config, data, activity);
}

mw::E<void> handleUndoActivity(const DataSourceInterface& data,
                               const Activity& activity)
{
    if(!activity.object.is_object()) return {};
    Activity wrapped;
    ASSIGN_OR_RETURN(wrapped, parseActivity(activity.object));
    auto object_uri = normalizeRef(wrapped.object);
    if(wrapped.type == "Follow" && object_uri.has_value())
    {
        return data.removeFollow(wrapped.actor, *object_uri);
    }
    if(wrapped.type == "Like" && object_uri.has_value())
    {
        return data.removeLike(wrapped.actor, *object_uri);
    }
    if(wrapped.type == "Announce" && object_uri.has_value())
    {
        return data.removeBoost(wrapped.actor, *object_uri);
    }
    if(wrapped.type == "EmojiReact" && object_uri.has_value())
    {
        std::string emoji = wrapped.raw.value("content", std::string());
        if(emoji.empty()) emoji = wrapped.raw.value("name", std::string());
        if(!emoji.empty())
            return data.removeReaction(wrapped.actor, *object_uri, emoji);
    }
    return {};
}

} // namespace

std::vector<std::string> normalizeAddressing(const nlohmann::json& field)
{
    std::vector<std::string> out;
    if(field.is_null()) return out;
    if(field.is_array())
    {
        for(const auto& item : field)
        {
            if(auto ref = normalizeRef(item); ref.has_value())
                out.push_back(*ref);
        }
        return out;
    }
    if(auto ref = normalizeRef(field); ref.has_value()) out.push_back(*ref);
    return out;
}

std::optional<std::string> normalizeRef(const nlohmann::json& field)
{
    if(field.is_string()) return field.get<std::string>();
    if(field.is_object() && field.contains("id") && field["id"].is_string())
    {
        return field["id"].get<std::string>();
    }
    return std::nullopt;
}

mw::E<Activity> parseActivity(const nlohmann::json& raw)
{
    if(!raw.is_object())
    {
        return std::unexpected(mw::runtimeError("Activity must be an object"));
    }
    auto id = normalizeRef(raw.contains("id") ? raw["id"] : nlohmann::json());
    auto actor = normalizeRef(raw.contains("actor") ? raw["actor"]
                                                    : nlohmann::json());
    if(!id.has_value() || !raw.contains("type") || !raw["type"].is_string()
       || !actor.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Activity is missing id, type, or actor"));
    }

    Activity activity;
    activity.id = *id;
    activity.type = raw["type"].get<std::string>();
    activity.actor = *actor;
    activity.object = raw.contains("object") ? raw["object"] : nlohmann::json();
    appendAll(activity.to,
              normalizeAddressing(raw.value("to", nlohmann::json())));
    appendAll(activity.to,
              normalizeAddressing(raw.value("bto", nlohmann::json())));
    appendAll(activity.to,
              normalizeAddressing(raw.value("audience", nlohmann::json())));
    appendAll(activity.cc,
              normalizeAddressing(raw.value("cc", nlohmann::json())));
    appendAll(activity.cc,
              normalizeAddressing(raw.value("bcc", nlohmann::json())));
    activity.raw = raw;
    return activity;
}

bool isPublicAddress(std::string_view uri)
{
    return uri == AS_PUBLIC || uri == "as:Public" || uri == "Public";
}

bool wantsActivityJson(std::string_view accept)
{
    return accept.find("application/activity+json") != std::string_view::npos
        || accept.find("application/ld+json") != std::string_view::npos;
}

nlohmann::json actorJson(const Config& config, const User& user,
                         std::string_view summary_html)
{
    std::string actor = config.url_root + "u/" + user.username;
    nlohmann::json j;
    j["@context"] = activityContext();
    j["type"] = "Person";
    j["id"] = actor;
    j["preferredUsername"] = user.username;
    j["name"] = user.display_name.empty() ? user.username : user.display_name;
    j["summary"] = std::string(summary_html);
    j["inbox"] = actor + "/inbox";
    j["outbox"] = actor + "/outbox";
    j["followers"] = actor + "/followers";
    j["following"] = actor + "/following";
    j["endpoints"] = {{"sharedInbox", config.url_root + "inbox"}};
    j["publicKey"] = {
        {"id", actor + "#main-key"},
        {"owner", actor},
        {"publicKeyPem", user.public_key_pem},
    };
    return j;
}

nlohmann::json systemActorJson(const Config& config,
                               std::string_view public_key_pem)
{
    std::string actor = config.url_root + "actor";
    nlohmann::json j;
    j["@context"] = activityContext();
    j["type"] = "Application";
    j["id"] = actor;
    j["preferredUsername"] = "unspoken";
    j["name"] = "unspoken";
    j["inbox"] = config.url_root + "inbox";
    j["endpoints"] = {{"sharedInbox", config.url_root + "inbox"}};
    j["publicKey"] = {
        {"id", actor + "#main-key"},
        {"owner", actor},
        {"publicKeyPem", std::string(public_key_pem)},
    };
    return j;
}

nlohmann::json noteJson(const Config& config, const Post& post,
                        const User& author,
                        const std::vector<PostRecipient>& recipients,
                        const std::vector<Attachment>& attachments)
{
    nlohmann::json to = nlohmann::json::array();
    nlohmann::json cc = nlohmann::json::array();
    for(const auto& r : recipients)
    {
        if(r.field == "to") to.push_back(r.recipient_uri);
        if(r.field == "cc") cc.push_back(r.recipient_uri);
    }

    nlohmann::json attachment_arr = nlohmann::json::array();
    for(const auto& a : attachments)
    {
        std::string url;
        if(a.remote_url.has_value())
        {
            url = *a.remote_url;
        }
        else
        {
            std::string ext = extensionOf(a.original_name);
            std::string filename = ext.empty() ? a.sha256
                : (a.sha256 + "." + ext);
            url = std::format("{}media/{}/{}", config.url_root,
                              a.sha256.substr(0, 1), filename);
        }
        attachment_arr.push_back({
            {"type", a.is_image ? "Image" : "Document"},
            {"mediaType", a.media_type},
            {"url", url},
            {"name", a.original_name},
        });
    }

    nlohmann::json j;
    j["@context"] = "https://www.w3.org/ns/activitystreams";
    j["type"] = "Note";
    j["id"] = post.uri;
    j["url"] = post.uri;
    j["attributedTo"] = config.url_root + "u/" + author.username;
    j["content"] = post.content_html;
    j["to"] = to;
    j["cc"] = cc;
    j["sensitive"] = post.sensitive;
    j["published"] = post.published.value_or(isoTimestamp(post.created_at));
    if(post.summary.has_value()) j["summary"] = *post.summary;
    if(post.in_reply_to_uri.has_value()) j["inReplyTo"] = *post.in_reply_to_uri;
    if(!attachment_arr.empty()) j["attachment"] = attachment_arr;
    return j;
}

nlohmann::json deleteActivityJson(
    std::string_view activity_id, std::string_view actor_uri,
    std::string_view object_uri, const std::vector<PostRecipient>& recipients)
{
    nlohmann::json to = nlohmann::json::array();
    nlohmann::json cc = nlohmann::json::array();
    for(const auto& r : recipients)
    {
        if(r.field == "to") to.push_back(r.recipient_uri);
        if(r.field == "cc") cc.push_back(r.recipient_uri);
    }
    return {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", std::string(activity_id)},
        {"type", "Delete"},
        {"actor", std::string(actor_uri)},
        {"object", std::string(object_uri)},
        {"to", to},
        {"cc", cc},
    };
}

nlohmann::json actorUpdateActivityJson(
    const Config& config, std::string_view activity_id, const User& user,
    std::string_view summary_html,
    const std::vector<PostRecipient>& recipients)
{
    nlohmann::json to = nlohmann::json::array();
    nlohmann::json cc = nlohmann::json::array();
    for(const auto& r : recipients)
    {
        if(r.field == "to") to.push_back(r.recipient_uri);
        if(r.field == "cc") cc.push_back(r.recipient_uri);
    }
    std::string actor_uri = config.url_root + "u/" + user.username;
    return {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", std::string(activity_id)},
        {"type", "Update"},
        {"actor", actor_uri},
        {"object", actorJson(config, user, summary_html)},
        {"to", to},
        {"cc", cc},
    };
}

nlohmann::json webFingerJson(const Config& config, const User& user)
{
    std::string actor = config.url_root + "u/" + user.username;
    return {
        {"subject", std::format("acct:{}@{}", user.username,
                                config.public_domain)},
        {"aliases", nlohmann::json::array({actor})},
        {"links", nlohmann::json::array({
            {
                {"rel", "self"},
                {"type", "application/activity+json"},
                {"href", actor},
            },
        })},
    };
}

nlohmann::json nodeInfoDiscoveryJson(const Config& config)
{
    return {
        {"links", nlohmann::json::array({
            {
                {"rel", "http://nodeinfo.diaspora.software/ns/schema/2.1"},
                {"href", config.url_root + "nodeinfo/2.1"},
            },
        })},
    };
}

nlohmann::json nodeInfoJson(const Config& config)
{
    return {
        {"version", "2.1"},
        {"software", {
            {"name", config.nodeinfo.software_name},
            {"version", "0.1.0"},
        }},
        {"protocols", nlohmann::json::array({"activitypub"})},
        {"services", {
            {"inbound", nlohmann::json::array()},
            {"outbound", nlohmann::json::array()},
        }},
        {"openRegistrations", config.nodeinfo.open_registrations},
        {"usage", {
            {"users", {
                {"total", 0},
                {"activeHalfyear", 0},
                {"activeMonth", 0},
            }},
            {"localPosts", 0},
        }},
        {"metadata", {
            {"nodeDescription", config.nodeinfo.description},
        }},
    };
}

bool isAllowedOutboundAddress(const mw::SockAddr& addr)
{
    const auto& a = addr.address;
    if(addr.family == mw::AddressFamily::IPV4)
    {
        if(a.size() != 4) return false;
        if(ipv4In(a, 10) || ipv4In(a, 127) || ipv4In(a, 169, 254)
           || ipv4In(a, 192, 168))
        {
            return false;
        }
        if(a[0] == 172 && a[1] >= 16 && a[1] <= 31) return false;
        // Carrier-grade NAT, localhost-ish zero net, multicast/reserved.
        if(a[0] == 100 && a[1] >= 64 && a[1] <= 127) return false;
        if(a[0] == 0 || a[0] >= 224) return false;
        return true;
    }

    if(addr.family == mw::AddressFamily::IPV6)
    {
        if(a.size() != 16) return false;
        if(ipv6AllZeroUntilLast(a, 1)) return false; // ::1
        if((a[0] & 0xfe) == 0xfc) return false;      // fc00::/7 ULA
        if(a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return false; // fe80::/10
        if(a[0] == 0xff) return false;               // multicast
        return true;
    }
    return false;
}

mw::E<void> hardenOutboundSession(mw::HTTPSessionInterface& http)
{
    DO_OR_RETURN(http.allowedProtocols("https"));
    DO_OR_RETURN(http.allowedRedirectProtocols("https"));
    DO_OR_RETURN(http.maxRedirections(5));
    http.followRedirects(true);
    http.addressFilter([](const mw::SockAddr& addr)
    {
        return isAllowedOutboundAddress(addr);
    });
    return {};
}

mw::E<mw::HTTPRequest> signedGetRequest(const Config& config,
                                        const SystemActor& system_actor,
                                        mw::CryptoInterface& crypto,
                                        std::string_view uri)
{
    return signedHttpRequest(crypto, signingActorForSystem(config,
                                                           system_actor),
                             "GET", uri);
}

SigningActor signingActorFor(const Config& config, const User& user)
{
    std::string actor = config.url_root + "u/" + user.username;
    return SigningActor{
        actor,
        actor + "#main-key",
        user.private_key_pem,
    };
}

SigningActor signingActorForSystem(const Config& config,
                                   const SystemActor& system_actor)
{
    return SigningActor{
        config.url_root + "actor",
        config.url_root + "actor#main-key",
        system_actor.private_key_pem,
    };
}

mw::E<mw::HTTPRequest> signedHttpRequest(
    mw::CryptoInterface& crypto, const SigningActor& actor,
    std::string_view method, std::string_view uri, std::string_view body,
    std::string_view content_type)
{
    auto parsed = mw::URL::fromStr(std::string(uri));
    if(!parsed.has_value() || parsed->scheme() != "https"
       || parsed->host().empty())
    {
        return std::unexpected(mw::runtimeError(
            "Outbound federation fetch URL must be absolute https"));
    }

    std::string date = httpDate();
    std::string target = requestTarget(*parsed);
    std::string host = requestAuthority(*parsed);
    std::string method_lower = lower(method);
    std::string signed_headers = "(request-target) host date";
    std::string signing_input = std::format(
        "(request-target): {} {}\nhost: {}\ndate: {}",
        method_lower, target, host, date);

    std::optional<std::string> digest;
    if(method_lower == "post" || method_lower == "put")
    {
        ASSIGN_OR_RETURN(auto d, digestHeaderFor(body));
        digest = d;
        signed_headers += " digest";
        signing_input += "\ndigest: " + *digest;
    }

    ASSIGN_OR_RETURN(auto sig, crypto.sign(
        mw::SignatureAlgorithm::RSA_V1_5_SHA256,
        actor.private_key_pem, signing_input));
    std::string sig64 = mw::base64Encode(
        std::span<unsigned char>(sig.data(), sig.size()), false, true);

    mw::HTTPRequest req{std::string(uri)};
    if(!body.empty()) req.setPayload(body);
    if(!content_type.empty()) req.setContentType(content_type);
    req.addHeader("Accept", "application/activity+json");
    req.addHeader("Host", host);
    req.addHeader("Date", date);
    if(digest.has_value()) req.addHeader("Digest", *digest);
    req.addHeader("Signature", std::format(
        R"(keyId="{}",algorithm="rsa-sha256",headers="{}",signature="{}")",
        actor.key_id, signed_headers, sig64));
    return req;
}

mw::E<RemoteActor> resolveRemoteActor(const Config& config,
                                      const DataSourceInterface& data,
                                      mw::CryptoInterface& crypto,
                                      mw::HTTPSessionInterface& http,
                                      const SystemActor& system_actor,
                                      std::string_view actor_uri,
                                      bool force_refresh)
{
    ASSIGN_OR_RETURN(auto cached, data.getRemoteActorByUri(actor_uri));
    if(cached.has_value() && !force_refresh) return *cached;

    DO_OR_RETURN(hardenOutboundSession(http));
    ASSIGN_OR_RETURN(auto req, signedGetRequest(config, system_actor, crypto,
                                                actor_uri));
    ASSIGN_OR_RETURN(const mw::HTTPResponse* res, http.get(req));
    if(res->status < 200 || res->status >= 300)
    {
        return std::unexpected(mw::httpError(res->status,
                                             "Remote actor fetch failed"));
    }

    nlohmann::json doc = nlohmann::json::parse(res->payloadAsStr(),
                                               nullptr, false);
    if(!doc.is_object())
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor response is not JSON"));
    }
    std::string id = doc.value("id", std::string(actor_uri));
    auto parsed_id = mw::URL::fromStr(id);
    if(!parsed_id.has_value() || parsed_id->host().empty())
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor has invalid id"));
    }
    if(!doc.contains("inbox") || !doc["inbox"].is_string()
       || !doc.contains("publicKey") || !doc["publicKey"].is_object())
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor is missing inbox or publicKey"));
    }
    const auto& public_key = doc["publicKey"];
    if(!public_key.contains("id") || !public_key["id"].is_string()
       || !public_key.contains("publicKeyPem")
       || !public_key["publicKeyPem"].is_string())
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor has incomplete publicKey"));
    }

    RemoteActor actor;
    actor.uri = id;
    actor.username = doc.value("preferredUsername", std::string());
    if(actor.username.empty()) actor.username = parsed_id->host();
    actor.domain = parsed_id->host();
    actor.display_name = doc.value("name", std::string());
    actor.inbox = doc["inbox"].get<std::string>();
    if(doc.contains("endpoints") && doc["endpoints"].is_object()
       && doc["endpoints"].contains("sharedInbox")
       && doc["endpoints"]["sharedInbox"].is_string())
    {
        actor.shared_inbox = doc["endpoints"]["sharedInbox"].get<std::string>();
    }
    actor.public_key_id = public_key["id"].get<std::string>();
    actor.public_key_pem = public_key["publicKeyPem"].get<std::string>();
    actor.actor_json = doc.dump();
    actor.fetched_at = mw::timeToSeconds(mw::Clock::now());
    return data.upsertRemoteActor(actor);
}

mw::E<VerifiedSignature> verifyHttpSignature(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, const IncomingHttpRequest& req,
    int64_t now_seconds)
{
    auto headers = lowerHeaders(req.headers);
    auto sig_header = header(headers, "signature");
    if(!sig_header.has_value())
    {
        return std::unexpected(mw::httpError(401, "Missing Signature"));
    }
    auto params = parseSignatureParams(*sig_header);
    if(!params.contains("keyid") || !params.contains("signature"))
    {
        return std::unexpected(mw::httpError(401, "Bad Signature header"));
    }
    std::string algorithm = lower(params.contains("algorithm")
        ? params["algorithm"] : "rsa-sha256");
    if(algorithm != "rsa-sha256" && algorithm != "hs2019")
    {
        return std::unexpected(mw::httpError(
            401, "Unsupported signature algorithm"));
    }

    std::vector<std::string> signed_headers = params.contains("headers")
        ? splitWords(params["headers"])
        : std::vector<std::string>{"date"};
    if(!containsHeader(signed_headers, "date"))
    {
        return std::unexpected(mw::httpError(401, "Date is not signed"));
    }
    if(!containsHeader(signed_headers, "(request-target)"))
    {
        return std::unexpected(mw::httpError(
            401, "Request target is not signed"));
    }
    auto date = header(headers, "date");
    if(!date.has_value())
    {
        return std::unexpected(mw::httpError(401, "Missing Date"));
    }
    auto request_time = parseHttpDate(*date);
    if(!request_time.has_value()
       || std::llabs(now_seconds - *request_time)
              > config.http_signature_skew_seconds)
    {
        return std::unexpected(mw::httpError(401, "Date skew too large"));
    }

    std::string method = lower(req.method);
    if(method == "post" || method == "put")
    {
        if(!containsHeader(signed_headers, "digest"))
        {
            return std::unexpected(mw::httpError(
                401, "Digest is not signed"));
        }
        auto digest = header(headers, "digest");
        if(!digest.has_value())
        {
            return std::unexpected(mw::httpError(401, "Missing Digest"));
        }
        ASSIGN_OR_RETURN(auto expected_digest, digestHeaderFor(req.body));
        if(*digest != expected_digest)
        {
            return std::unexpected(mw::httpError(401, "Digest mismatch"));
        }
    }

    ASSIGN_OR_RETURN(auto signature_bytes, mw::base64Decode(
        params["signature"]));
    ASSIGN_OR_RETURN(auto input, signingString(req, headers, signed_headers));

    std::string key_id = params["keyid"];
    std::string actor_uri = key_id;
    if(size_t hash = actor_uri.find('#'); hash != std::string::npos)
        actor_uri = actor_uri.substr(0, hash);
    ASSIGN_OR_RETURN(auto actor, data.getRemoteActorByUri(actor_uri));
    if(!actor.has_value() || actor->public_key_id != key_id)
    {
        return std::unexpected(mw::httpError(401, "Unknown signature key"));
    }

    ASSIGN_OR_RETURN(bool ok, crypto.verifySignature(
        mw::SignatureAlgorithm::RSA_V1_5_SHA256, actor->public_key_pem,
        signature_bytes, input));
    if(!ok)
    {
        return std::unexpected(mw::httpError(401, "Bad signature"));
    }
    return VerifiedSignature{actor_uri, key_id};
}

mw::E<VerifiedSignature> verifyHttpSignatureWithKeyRefresh(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, const IncomingHttpRequest& req,
    int64_t now_seconds)
{
    auto first = verifyHttpSignature(config, data, crypto, req, now_seconds);
    if(first.has_value()) return *first;

    auto headers = lowerHeaders(req.headers);
    auto sig_header = header(headers, "signature");
    if(!sig_header.has_value()) return std::unexpected(first.error());
    auto params = parseSignatureParams(*sig_header);
    if(!params.contains("keyid")) return std::unexpected(first.error());

    std::string actor_uri = params["keyid"];
    if(size_t hash = actor_uri.find('#'); hash != std::string::npos)
        actor_uri = actor_uri.substr(0, hash);
    auto refreshed = resolveRemoteActor(config, data, crypto, http,
                                        system_actor, actor_uri, true);
    if(!refreshed.has_value()) return std::unexpected(first.error());

    return verifyHttpSignature(config, data, crypto, req, now_seconds);
}

mw::E<int64_t> enqueueDeliveryJob(const DataSourceInterface& data,
                                  std::string_view target_inbox,
                                  std::string_view signer_actor_uri,
                                  const nlohmann::json& activity,
                                  int64_t now_seconds)
{
    if(target_inbox.empty() || signer_actor_uri.empty()
       || !activity.is_object())
    {
        return std::unexpected(mw::runtimeError(
            "Delivery job requires inbox, signer, and activity object"));
    }
    nlohmann::json payload = {
        {"target_inbox", std::string(target_inbox)},
        {"signer_actor", std::string(signer_actor_uri)},
        {"activity", activity},
    };
    return data.enqueueJob("deliver", payload.dump(), now_seconds,
                           now_seconds);
}

mw::E<std::vector<std::string>> deliveryInboxesForRecipients(
    const Config& config, const DataSourceInterface& data,
    const std::vector<PostRecipient>& recipients)
{
    std::set<std::string> inboxes;

    auto add_actor = [&](std::string_view actor_uri) -> mw::E<void> {
        if(actor_uri.empty() || isPublicAddress(actor_uri)
           || isLocalActorUri(config, actor_uri))
        {
            return {};
        }
        ASSIGN_OR_RETURN(auto actor, data.getRemoteActorByUri(actor_uri));
        if(!actor.has_value())
        {
            return std::unexpected(mw::runtimeError(std::format(
                "Remote delivery actor is not cached: {}", actor_uri)));
        }
        inboxes.insert(actor->shared_inbox.value_or(actor->inbox));
        return {};
    };

    for(const auto& r : recipients)
    {
        if(isPublicAddress(r.recipient_uri)) continue;
        if(auto owner = followersCollectionOwner(config, r.recipient_uri);
           owner.has_value())
        {
            ASSIGN_OR_RETURN(auto followers, data.followerUris(*owner));
            for(const auto& follower : followers)
            {
                DO_OR_RETURN(add_actor(follower));
            }
            continue;
        }
        DO_OR_RETURN(add_actor(r.recipient_uri));
    }

    return std::vector<std::string>(inboxes.begin(), inboxes.end());
}

mw::E<std::vector<int64_t>> enqueueOutboundDelivery(
    const Config& config, const DataSourceInterface& data,
    std::string_view signer_actor_uri, const nlohmann::json& activity,
    const std::vector<PostRecipient>& recipients, int64_t now_seconds)
{
    ASSIGN_OR_RETURN(auto inboxes, deliveryInboxesForRecipients(
        config, data, recipients));
    std::vector<int64_t> job_ids;
    job_ids.reserve(inboxes.size());
    for(const auto& inbox : inboxes)
    {
        ASSIGN_OR_RETURN(auto id, enqueueDeliveryJob(
            data, inbox, signer_actor_uri, activity, now_seconds));
        job_ids.push_back(id);
    }
    return job_ids;
}

mw::E<InboxDispatchResult> dispatchIncomingActivity(
    const Config& config, const DataSourceInterface& data,
    std::string_view verified_actor_uri, const Activity& activity,
    int64_t now_seconds)
{
    if(activity.actor != verified_actor_uri)
    {
        return std::unexpected(mw::httpError(
            401, "Activity actor does not match signature actor"));
    }

    ASSIGN_OR_RETURN(bool first_seen, data.markActivitySeen(
        activity.id, now_seconds));
    if(!first_seen) return InboxDispatchResult{true};

    if(activity.type == "Create")
    {
        DO_OR_RETURN(handleCreateActivity(config, data, activity));
    }
    else if(activity.type == "Follow")
    {
        DO_OR_RETURN(handleFollowActivity(config, data, activity,
                                          now_seconds));
    }
    else if(activity.type == "Accept")
    {
        DO_OR_RETURN(handleAcceptActivity(data, activity));
    }
    else if(activity.type == "Like")
    {
        DO_OR_RETURN(handleLikeActivity(data, activity, now_seconds));
    }
    else if(activity.type == "Announce")
    {
        DO_OR_RETURN(handleAnnounceActivity(data, activity, now_seconds));
    }
    else if(activity.type == "EmojiReact")
    {
        DO_OR_RETURN(handleEmojiReactActivity(data, activity, now_seconds));
    }
    else if(activity.type == "Delete")
    {
        DO_OR_RETURN(handleDeleteActivity(data, activity));
    }
    else if(activity.type == "Undo")
    {
        DO_OR_RETURN(handleUndoActivity(data, activity));
    }
    else if(activity.type == "Update")
    {
        DO_OR_RETURN(handleUpdateActivity(config, data, activity));
    }

    return InboxDispatchResult{false};
}

mw::E<bool> runFederationJobOnce(const Config& config,
                                 const DataSourceInterface& data,
                                 mw::CryptoInterface& crypto,
                                 mw::HTTPSessionInterface& http,
                                 int64_t now_seconds)
{
    ASSIGN_OR_RETURN(auto claimed, data.claimJob(now_seconds));
    if(!claimed.has_value()) return false;

    mw::E<void> result;
    if(claimed->kind == "deliver")
    {
        nlohmann::json payload = nlohmann::json::parse(
            claimed->payload_json, nullptr, false);
        result = performDeliveryJob(config, data, crypto, http, payload);
    }
    else
    {
        result = std::unexpected(mw::runtimeError(
            std::format("Unknown job kind: {}", claimed->kind)));
    }

    if(result.has_value())
    {
        DO_OR_RETURN(data.completeJob(claimed->id));
    }
    else
    {
        DO_OR_RETURN(data.failJob(
            claimed->id, mw::errorMsg(result.error()), now_seconds,
            config.job_retry_base_delay_seconds, config.job_max_retries));
    }
    return true;
}

} // namespace unspoken
