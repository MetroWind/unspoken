#include "federation.hpp"
#include <actpub/engine.hpp>
#include <actpub/identity.hpp>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <ctime>
#include <format>
#include <iomanip>
#include <locale>
#include <map>
#include <sstream>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>
#include <mw/crypto.hpp>
#include <mw/error.hpp>
#include <mw/http_client.hpp>
#include <mw/url.hpp>
#include <mw/utils.hpp>
#include <spdlog/spdlog.h>

#include "attachments.hpp"
#include "data.hpp"
#include "emoji.hpp"
#include "render.hpp"
#include "service.hpp"
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

std::string localAttachmentUrl(const Config& config, const Attachment& a)
{
    std::string ext = a.extension.empty()
        ? extensionOf(a.original_name) : a.extension;
    std::string filename = ext.empty() ? a.sha256 : (a.sha256 + "." + ext);
    return std::format("{}media/{}/{}", config.url_root,
                       a.sha256.substr(0, 1), filename);
}

std::optional<nlohmann::json> actorImageJson(
    const Config& config, const std::optional<Attachment>& attachment)
{
    if(!attachment.has_value() || attachment->remote_url.has_value()
       || !attachment->is_image)
    {
        return std::nullopt;
    }
    return nlohmann::json{
        {"type", "Image"},
        {"mediaType", attachment->media_type},
        {"url", localAttachmentUrl(config, *attachment)},
        {"name", attachment->original_name},
    };
}

nlohmann::json headersJson(
    const std::unordered_map<std::string, std::string>& headers)
{
    nlohmann::json out = nlohmann::json::object();
    for(const auto& [key, value] : headers) out[key] = value;
    return out;
}

void logOutgoingFederationRequest(std::string_view method,
                                  const mw::HTTPRequest& req)
{
    spdlog::info("Outgoing federation request: {} {} bytes={}",
                 method, req.url, req.request_data.size());
    spdlog::debug("Outgoing federation request headers: {}",
                  headersJson(req.header).dump());
    spdlog::debug("Outgoing federation request body: {}",
                  req.request_data);
}

void logOutgoingFederationResponse(std::string_view method,
                                   const mw::HTTPRequest& req,
                                   const mw::HTTPResponse& res)
{
    spdlog::info("Outgoing federation response: {} {} status={} bytes={}",
                 method, req.url, res.status, res.payload.size());
    spdlog::debug("Outgoing federation response headers: {}",
                  headersJson(res.header).dump());
    spdlog::debug("Outgoing federation response body: {}",
                  res.payloadAsStr());
}

ap::TransportConfig transportConfig(const Config& config)
{
    return {config.dev, config.http_signature_skew_seconds};
}

std::optional<std::pair<std::string, std::string>>
parseHandle(std::string_view handle)
{
    handle = mw::strip(handle);
    if(handle.starts_with('@')) handle.remove_prefix(1);
    size_t at = handle.find('@');
    if(at == std::string_view::npos || at == 0 || at + 1 >= handle.size())
        return std::nullopt;
    if(handle.find('@', at + 1) != std::string_view::npos)
        return std::nullopt;
    std::string username(handle.substr(0, at));
    std::string domain(handle.substr(at + 1));
    if(domain.find('/') != std::string::npos
       || domain.find(':') != std::string::npos)
    {
        return std::nullopt;
    }
    return std::make_pair(username, domain);
}

void appendAll(std::vector<std::string>& out,
               const std::vector<std::string>& in)
{
    out.insert(out.end(), in.begin(), in.end());
}

std::string jsonString(const nlohmann::json& object, const char* key,
                       std::string_view fallback = "")
{
    auto field = object.find(key);
    if(field == object.end() || !field->is_string())
        return std::string(fallback);
    return field->get<std::string>();
}

bool boolField(const nlohmann::json& object, std::string_view key)
{
    if(!object.is_object()) return false;
    auto it = object.find(std::string(key));
    return it != object.end() && it->is_boolean() && it->get<bool>();
}

mw::E<bool> handleCreateActivity(const Config& config,
                                 const DataSourceInterface& data,
                                 const Activity& activity,
                                 const VerifiedSignature* signature = nullptr);
bool isLocalActorUri(const Config& config, std::string_view uri);

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

    DO_OR_RETURN(hardenOutboundSession(config, http, inbox));
    ASSIGN_OR_RETURN(auto req, signedHttpRequest(
        config, crypto, signer, "POST", inbox, body,
        "application/activity+json"));
    logOutgoingFederationRequest("POST", req);
    auto res_e = http.post(req);
    if(!res_e.has_value())
    {
        spdlog::warn("Outgoing federation response: POST {} failed: {}",
                     req.url, mw::errorMsg(res_e.error()));
        return std::unexpected(res_e.error());
    }
    const mw::HTTPResponse* res = *res_e;
    logOutgoingFederationResponse("POST", req, *res);
    if(res->status < 200 || res->status >= 300)
    {
        return std::unexpected(mw::httpError(
            res->status, "Activity delivery failed"));
    }
    return {};
}

std::vector<std::string> objectRefsFromCollection(const nlohmann::json& doc)
{
    std::vector<std::string> out;
    auto add_refs = [&](const nlohmann::json& items)
    {
        if(items.is_array())
        {
            for(const auto& item : items)
                if(auto ref = normalizeRef(item); ref.has_value())
                    out.push_back(*ref);
        }
        else if(auto ref = normalizeRef(items); ref.has_value())
        {
            out.push_back(*ref);
        }
    };

    if(doc.is_array())
    {
        add_refs(doc);
        return out;
    }
    if(!doc.is_object()) return out;
    if(doc.contains("orderedItems")) add_refs(doc["orderedItems"]);
    if(doc.contains("items")) add_refs(doc["items"]);
    return out;
}

mw::E<nlohmann::json> signedGetJson(
    const Config& config, mw::CryptoInterface& crypto,
    mw::HTTPSessionInterface& http, const SystemActor& system_actor,
    std::string_view uri)
{
    DO_OR_RETURN(hardenOutboundSession(config, http, uri));
    ASSIGN_OR_RETURN(auto req, signedGetRequest(config, system_actor, crypto,
                                                uri));
    ASSIGN_OR_RETURN(const mw::HTTPResponse* res, http.get(req));
    if(res->status < 200 || res->status >= 300)
    {
        return std::unexpected(mw::httpError(res->status,
                                             "Remote object fetch failed"));
    }
    nlohmann::json doc = nlohmann::json::parse(res->payloadAsStr(),
                                               nullptr, false);
    if(!doc.is_object() && !doc.is_array())
    {
        return std::unexpected(mw::runtimeError(
            "Remote object response is not JSON"));
    }
    return doc;
}

mw::E<void> ensureRemoteActorForObject(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, const nlohmann::json& object,
    std::string_view fallback_actor)
{
    auto actor_uri = normalizeRef(object.contains("attributedTo")
        ? object["attributedTo"] : nlohmann::json());
    std::string uri = actor_uri.value_or(std::string(fallback_actor));
    if(uri.empty() || isLocalActorUri(config, uri)) return {};

    ASSIGN_OR_RETURN(auto actor, ensureRemoteActorRetained(
        config, data, crypto, http, system_actor, uri,
        mw::timeToSeconds(mw::Clock::now())));
    (void)actor;
    return {};
}

mw::E<void> fetchThreadObject(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view uri, int depth_left,
    std::set<std::string>& seen)
{
    if(depth_left <= 0 || uri.empty()) return {};
    std::string key(uri);
    if(!seen.insert(key).second) return {};

    ASSIGN_OR_RETURN(auto doc, signedGetJson(config, crypto, http,
                                             system_actor, uri));
    if(doc.is_array())
    {
        for(const auto& ref : objectRefsFromCollection(doc))
        {
            DO_OR_RETURN(fetchThreadObject(config, data, crypto, http,
                                           system_actor, ref, depth_left - 1,
                                           seen));
        }
        return {};
    }

    if(jsonString(doc, "type") == "Note")
    {
        auto object_uri = normalizeRef(doc);
        if(!object_uri.has_value()) return {};
        auto actor = normalizeRef(doc.contains("attributedTo")
            ? doc["attributedTo"] : nlohmann::json());
        Activity synthetic;
        synthetic.id = *object_uri + "#fetch";
        synthetic.type = "Create";
        synthetic.actor = actor.value_or(std::string());
        synthetic.object = doc;
        synthetic.raw = {
            {"id", synthetic.id},
            {"type", "Create"},
            {"actor", synthetic.actor},
            {"object", doc},
        };
        if(!synthetic.actor.empty())
            DO_OR_RETURN(handleCreateActivity(config, data, synthetic));

        auto parent = normalizeRef(doc.contains("inReplyTo")
            ? doc["inReplyTo"] : nlohmann::json());
        if(parent.has_value())
        {
            ASSIGN_OR_RETURN(auto existing_parent,
                             data.getPostByUri(*parent));
            if(!existing_parent.has_value())
            {
                DO_OR_RETURN(fetchThreadObject(config, data, crypto, http,
                                               system_actor, *parent,
                                               depth_left - 1, seen));
            }
        }

        if(doc.contains("replies"))
        {
            std::vector<std::string> replies =
                objectRefsFromCollection(doc["replies"]);
            if(replies.empty())
            {
                auto first = normalizeRef(
                    doc["replies"].contains("first")
                        ? doc["replies"]["first"] : nlohmann::json());
                if(first.has_value())
                {
                    ASSIGN_OR_RETURN(auto page, signedGetJson(
                        config, crypto, http, system_actor, *first));
                    replies = objectRefsFromCollection(page);
                }
            }
            for(const auto& reply : replies)
            {
                ASSIGN_OR_RETURN(auto existing_reply,
                                 data.getPostByUri(reply));
                if(!existing_reply.has_value())
                {
                    DO_OR_RETURN(fetchThreadObject(config, data, crypto, http,
                                                   system_actor, reply,
                                                   depth_left - 1, seen));
                }
            }
        }
    }
    else
    {
        for(const auto& ref : objectRefsFromCollection(doc))
        {
            DO_OR_RETURN(fetchThreadObject(config, data, crypto, http,
                                           system_actor, ref, depth_left - 1,
                                           seen));
        }
    }
    return {};
}

mw::E<void> performFetchThreadJob(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const nlohmann::json& payload)
{
    if(!payload.is_object() || !payload.contains("root_uri")
       || !payload["root_uri"].is_string())
    {
        return std::unexpected(mw::runtimeError(
            "Fetch-thread job payload is malformed"));
    }
    ASSIGN_OR_RETURN(auto system_actor, data.getSystemActor());
    if(!system_actor.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Fetch-thread job requires a system actor"));
    }
    int depth = payload.value("depth", config.thread_fetch_max_depth);
    if(depth > config.thread_fetch_max_depth)
        depth = config.thread_fetch_max_depth;
    std::set<std::string> seen;
    return fetchThreadObject(config, data, crypto, http, *system_actor,
                             payload["root_uri"].get<std::string>(),
                             depth, seen);
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

bool isLocalPostUri(const Config& config, std::string_view uri)
{
    return uri.starts_with(config.url_root + "p/");
}

mw::E<bool> referencesKnownOwnedObject(
    const Config& config, const DataSourceInterface& data,
    std::string_view uri, int depth_left)
{
    if(depth_left <= 0 || uri.empty()) return false;
    if(isLocalPostUri(config, uri)) return true;

    ASSIGN_OR_RETURN(auto post, data.getPostByUri(uri));
    if(!post.has_value()) return false;
    if(post->local_author_id.has_value()) return true;
    if(post->in_reply_to_uri.has_value())
    {
        return referencesKnownOwnedObject(config, data,
                                          *post->in_reply_to_uri,
                                          depth_left - 1);
    }
    return false;
}

struct ForwardingPlan
{
    nlohmann::json activity;
    std::vector<std::pair<std::string, std::string>> destinations;
};

mw::E<std::optional<nlohmann::json>> fetchForwardedObject(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view object_uri)
{
    if(isLocalPostUri(config, object_uri))
        return std::optional<nlohmann::json>{};
    ASSIGN_OR_RETURN(auto doc, signedGetJson(config, crypto, http,
                                             system_actor, object_uri));
    if(!doc.is_object()) return std::optional<nlohmann::json>{};
    auto fetched_id = normalizeRef(doc);
    if(!fetched_id.has_value() || *fetched_id != object_uri)
        return std::optional<nlohmann::json>{};
    if(auto parent = normalizeRef(doc.contains("inReplyTo")
            ? doc["inReplyTo"] : nlohmann::json());
       parent.has_value())
    {
        ASSIGN_OR_RETURN(bool references_owned, referencesKnownOwnedObject(
            config, data, *parent, config.thread_fetch_max_depth));
        if(references_owned) return std::optional<nlohmann::json>{doc};
    }
    return std::optional<nlohmann::json>{};
}

mw::E<std::optional<ForwardingPlan>> prepareIncomingForwarding(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface* crypto, mw::HTTPSessionInterface* http,
    const SystemActor* system_actor, const Activity& activity)
{
    if(crypto == nullptr || http == nullptr || system_actor == nullptr)
        return std::optional<ForwardingPlan>{};
    if(activity.type != "Create") return std::optional<ForwardingPlan>{};
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return std::optional<ForwardingPlan>{};

    std::vector<std::string> claimed_addresses;
    claimed_addresses.insert(claimed_addresses.end(), activity.to.begin(),
                             activity.to.end());
    claimed_addresses.insert(claimed_addresses.end(), activity.cc.begin(),
                             activity.cc.end());
    std::set<std::string> claimed_collections;
    for(const auto& address : claimed_addresses)
    {
        auto owner = followersCollectionOwner(config, address);
        if(owner.has_value() && isLocalActorUri(config, *owner))
            claimed_collections.insert(address);
    }
    if(claimed_collections.empty()) return std::optional<ForwardingPlan>{};

    ASSIGN_OR_RETURN(auto object, fetchForwardedObject(
        config, data, *crypto, *http, *system_actor, *object_uri));
    if(!object.has_value()) return std::optional<ForwardingPlan>{};
    auto attributed_to = normalizeRef(object->contains("attributedTo")
        ? (*object)["attributedTo"] : nlohmann::json());
    if(!attributed_to.has_value() || *attributed_to != activity.actor)
        return std::optional<ForwardingPlan>{};

    std::vector<std::string> addressed;
    appendAll(addressed, normalizeAddressing(
        object->value("to", nlohmann::json())));
    appendAll(addressed, normalizeAddressing(
        object->value("cc", nlohmann::json())));

    ForwardingPlan plan;
    plan.activity = {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", activity.id},
        {"type", "Create"},
        {"actor", activity.actor},
        {"object", *object},
    };
    if(object->contains("to")) plan.activity["to"] = (*object)["to"];
    if(object->contains("cc")) plan.activity["cc"] = (*object)["cc"];

    std::set<std::string> forwarded_collections;
    for(const auto& address : addressed)
    {
        auto owner = followersCollectionOwner(config, address);
        if(!owner.has_value() || !isLocalActorUri(config, *owner)) continue;
        if(!claimed_collections.contains(address)) continue;
        if(!forwarded_collections.insert(address).second) continue;
        plan.destinations.emplace_back(*owner, address);
    }
    if(plan.destinations.empty()) return std::optional<ForwardingPlan>{};
    return std::optional<ForwardingPlan>{std::move(plan)};
}

mw::E<bool> executeIncomingForwarding(
    const Config& config, const DataSourceInterface& data,
    const ForwardingPlan& plan, int64_t now_seconds)
{
    for(const auto& [owner, address] : plan.destinations)
    {
        std::vector<PostRecipient> recipients = {
            {0, address, "to"},
        };
        ASSIGN_OR_RETURN(auto jobs, enqueueOutboundDelivery(
            config, data, owner, plan.activity, recipients, now_seconds));
        (void)jobs;
    }
    return !plan.destinations.empty();
}

bool addressesContainPublic(const std::vector<std::string>& addresses)
{
    for(const auto& uri : addresses)
        if(isPublicAddress(uri)) return true;
    return false;
}

bool addressesContainFollowersCollection(
    const std::vector<std::string>& addresses)
{
    for(const auto& uri : addresses)
    {
        if(uri.ends_with("/followers")) return true;
    }
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
    if(!addressesContainFollowersCollection(to)
       && !addressesContainFollowersCollection(cc))
    {
        return Visibility::DIRECT;
    }
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

std::map<std::string, EmojiInfo> emojiTagsForObject(
    const nlohmann::json& object)
{
    std::map<std::string, EmojiInfo> out;
    nlohmann::json tags = object.value("tag", nlohmann::json::array());
    if(tags.is_object()) tags = nlohmann::json::array({tags});
    if(!tags.is_array()) return out;

    for(const auto& tag : tags)
    {
        if(!tag.is_object() || jsonString(tag, "type") != "Emoji")
            continue;
        std::string shortcode = jsonString(tag, "name");
        if(shortcode.size() >= 3 && shortcode.front() == ':'
           && shortcode.back() == ':')
        {
            shortcode = shortcode.substr(1, shortcode.size() - 2);
        }
        if(!isValidShortcode(shortcode)) continue;
        if(!tag.contains("icon") || !tag["icon"].is_object()) continue;
        const auto& icon = tag["icon"];
        if(!icon.contains("url") || !icon["url"].is_string()) continue;
        std::string url = icon["url"].get<std::string>();
        if(!url.starts_with("https://") && !url.starts_with("http://"))
            continue;

        EmojiInfo info;
        info.shortcode = shortcode;
        info.image_url = url;
        info.media_type = jsonString(icon, "mediaType", "image/png");
        out.emplace(shortcode, std::move(info));
    }
    return out;
}

std::string substituteRemoteEmoji(std::string_view html,
                                  const std::map<std::string, EmojiInfo>& emoji)
{
    std::string out;
    out.reserve(html.size());
    size_t pos = 0;
    while(pos < html.size())
    {
        size_t start = html.find(':', pos);
        if(start == std::string_view::npos)
        {
            out += html.substr(pos);
            break;
        }
        out += html.substr(pos, start - pos);
        size_t end = html.find(':', start + 1);
        if(end == std::string_view::npos)
        {
            out += html.substr(start);
            break;
        }
        std::string shortcode(html.substr(start + 1, end - start - 1));
        auto it = emoji.find(shortcode);
        if(isValidShortcode(shortcode) && it != emoji.end())
        {
            out += std::format(
                "<img class=\"emoji\" src=\"{}\" alt=\":{}:\" "
                "title=\":{}:\">",
                mw::escapeHTML(it->second.image_url), shortcode, shortcode);
        }
        else
        {
            out += html.substr(start, end - start + 1);
        }
        pos = end + 1;
    }
    return out;
}

std::string tagPageUrl(const Config& config, std::string_view tag)
{
    std::string out;
    out.reserve(tag.size());
    for(char c : tag)
    {
        out.push_back(static_cast<char>(std::tolower(
            static_cast<unsigned char>(c))));
    }
    return config.url_root + "tags/" + out;
}

nlohmann::json tagsForPostSource(const Config& config,
                                 const std::vector<PostRecipient>& recipients,
                                 std::string_view source,
                                 const EmojiRegistry* emoji)
{
    if(source.empty()) return nlohmann::json::array();

    std::set<std::string> addressed;
    for(const auto& recipient : recipients)
        addressed.insert(recipient.recipient_uri);

    EmojiRegistry empty_emoji;
    RenderedPostContent parsed = parsePostContent(std::string(source),
                                                  empty_emoji);
    nlohmann::json tags = nlohmann::json::array();
    for(const auto& mention : parsed.mentions)
    {
        std::string href;
        if(mention.domain.empty() || mention.domain == config.public_domain)
        {
            href = config.url_root + "u/" + mention.username;
        }
        else
        {
            std::optional<std::string> alias_href;
            bool alias_ambiguous = false;
            for(const auto& recipient : addressed)
            {
                auto url_e = mw::URL::fromStr(recipient);
                if(!url_e.has_value()) continue;
                const mw::URL& url = *url_e;
                std::string path = url.path();
                bool username_match = path.ends_with(
                    "/" + mention.username)
                    || path.ends_with("/@" + mention.username);
                if(!username_match) continue;
                if(url.host() == mention.domain)
                {
                    href = recipient;
                    break;
                }
                if(alias_href.has_value())
                {
                    alias_ambiguous = true;
                }
                else
                {
                    alias_href = recipient;
                }
            }
            if(href.empty() && alias_href.has_value() && !alias_ambiguous)
                href = *alias_href;
        }
        if(href.empty()) continue;
        if(!addressed.contains(href)) continue;
        tags.push_back({
            {"type", "Mention"},
            {"href", href},
            {"name", mention.name},
        });
    }
    for(const auto& hashtag : parsed.hashtags)
    {
        tags.push_back({
            {"type", "Hashtag"},
            {"href", tagPageUrl(config, hashtag.tag)},
            {"name", hashtag.name},
        });
    }
    if(emoji != nullptr)
    {
        size_t pos = 0;
        std::set<std::string> seen_emoji;
        while(pos < source.size())
        {
            size_t start = source.find(':', pos);
            if(start == std::string_view::npos) break;
            size_t end = source.find(':', start + 1);
            if(end == std::string_view::npos) break;
            std::string shortcode(source.substr(start + 1,
                                                end - start - 1));
            pos = end + 1;
            if(!isValidShortcode(shortcode)) continue;
            auto info = emoji->lookup(shortcode);
            if(!info.has_value()) continue;
            if(!seen_emoji.insert(shortcode).second) continue;
            tags.push_back({
                {"type", "Emoji"},
                {"id", config.url_root + "emoji/" + shortcode},
                {"name", ":" + shortcode + ":"},
                {"icon", {
                    {"type", "Image"},
                    {"mediaType", info->media_type},
                    {"url", info->image_url},
                }},
            });
        }
    }
    return tags;
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
        a.media_type = jsonString(item, "mediaType");
        a.original_name = jsonString(item, "name", *url);
        a.sensitive = boolField(object, "sensitive")
            || boolField(item, "sensitive");
        a.remote_url = *url;
        std::string type = jsonString(item, "type");
        a.is_image = type == "Image" || a.media_type.starts_with("image/");
        DO_OR_RETURN(data.insertAttachment(a));
    }
    return {};
}

mw::E<NewPost> remoteNotePostFromActivity(
    const Config& config, const DataSourceInterface& data,
    const Activity& activity)
{
    auto uri = normalizeRef(activity.object);
    if(!uri.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Remote Note is missing id"));
    }

    auto attributed_to = normalizeRef(
        activity.object.contains("attributedTo")
            ? activity.object["attributedTo"] : nlohmann::json());
    std::string author_uri = attributed_to.value_or(activity.actor);
    std::optional<int64_t> remote_author_id;
    ASSIGN_OR_RETURN(auto remote_author, data.getRemoteActorByUri(author_uri));
    if(remote_author.has_value()) remote_author_id = remote_author->id;

    NewPost np;
    np.preview_origin = config.url_root;
    np.previews_enabled = config.link_previews_enabled;
    np.preview_excluded_urls = previewExcludedUrlsForObject(activity.object);
    np.uri = *uri;
    np.remote_author_id = remote_author_id;
    auto remote_emoji = emojiTagsForObject(activity.object);
    np.content_html = substituteRemoteEmoji(
        sanitizeRemoteHtml(jsonString(activity.object, "content")),
        remote_emoji);
    np.summary = activity.object.contains("summary")
        && activity.object["summary"].is_string()
        ? std::optional<std::string>(sanitizeRemoteHtml(
              activity.object["summary"].get<std::string>()))
        : std::nullopt;
    np.sensitive = boolField(activity.object, "sensitive");
    np.visibility = visibilityForActivityObject(activity.object);
    np.in_reply_to_uri = normalizeRef(
        activity.object.contains("inReplyTo")
            ? activity.object["inReplyTo"] : nlohmann::json());
    if(activity.object.contains("published")
       && activity.object["published"].is_string())
    {
        np.published = activity.object["published"].get<std::string>();
    }
    return np;
}

mw::E<bool> handleCreateActivity(const Config& config,
                                 const DataSourceInterface& data,
                                 const Activity& activity,
                                 const VerifiedSignature* signature)
{
    if(!activity.object.is_object() ||
       jsonString(activity.object, "type") != "Note")
    {
        return false;
    }
    auto uri = normalizeRef(activity.object);
    if(!uri.has_value() || isLocalPostUri(config, *uri)) return false;
    auto attributed_to = normalizeRef(activity.object.contains("attributedTo")
        ? activity.object["attributedTo"] : nlohmann::json());
    if(attributed_to.has_value() && *attributed_to != activity.actor)
        return false;
    ASSIGN_OR_RETURN(auto existing, data.getPostByUri(*uri));
    if(existing.has_value()) return false;
    ASSIGN_OR_RETURN(auto np, remoteNotePostFromActivity(config, data, activity));
    if(signature != nullptr && signature->actor_uri != activity.actor)
        return false;
    if(signature != nullptr && !signature->actor_was_retained)
    {
        ASSIGN_OR_RETURN(auto post, data.insertRemoteActorAndPost(
            signature->actor, np, recipientsForObject(activity.object)));
        DO_OR_RETURN(storeRemoteAttachments(data, activity.object, post.id));
        return true;
    }
    if(signature != nullptr) np.remote_author_id = signature->actor.id;
    ASSIGN_OR_RETURN(auto post, data.insertPost(
        np, recipientsForObject(activity.object), config.url_root + "p/"));
    DO_OR_RETURN(storeRemoteAttachments(data, activity.object, post.id));
    return true;
}

mw::E<bool> handleFollowActivity(const Config& config,
                                 const DataSourceInterface& data,
                                 const Activity& activity,
                                 const VerifiedSignature& signature,
                                 int64_t now_seconds, bool& actor_retained)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return false;
    auto username = localUsernameForActor(config, *object_uri);
    if(!username.has_value()) return false;
    ASSIGN_OR_RETURN(auto local_user, data.getUserByUsername(*username));
    if(!local_user.has_value()) return false;

    Follow follow;
    follow.follower_uri = activity.actor;
    follow.followee_uri = *object_uri;
    follow.state = FollowState::ACCEPTED;
    follow.follow_activity_uri = activity.id;
    follow.created_at = now_seconds;
    DO_OR_RETURN(data.addFollow(follow));
    if(!signature.actor_was_retained)
    {
        ASSIGN_OR_RETURN(auto retained, data.upsertRemoteActor(
            signature.actor));
        (void)retained;
        actor_retained = true;
    }
    ASSIGN_OR_RETURN(auto stored_follow, data.getFollow(
        activity.actor, *object_uri));
    int64_t follow_id = stored_follow.has_value() ? stored_follow->id : 0;

    nlohmann::json accept = {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", std::format("{}activities/accept/{}/{}", config.url_root,
                           follow_id, now_seconds)},
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
    return true;
}

mw::E<bool> handleAcceptActivity(const Config& config,
                                 const DataSourceInterface& data,
                                 const Activity& activity)
{
    if(!activity.object.is_object()) return false;
    auto follower = normalizeRef(
        activity.object.contains("actor") ? activity.object["actor"]
                                          : nlohmann::json());
    auto followee = normalizeRef(
        activity.object.contains("object") ? activity.object["object"]
                                           : nlohmann::json());
    if(!follower.has_value() || !followee.has_value()
       || *followee != activity.actor || !isLocalActorUri(config, *follower))
    {
        return false;
    }
    ASSIGN_OR_RETURN(auto follow, data.getFollow(*follower, *followee));
    if(!follow.has_value()) return false;
    DO_OR_RETURN(data.setFollowState(*follower, *followee,
                                     FollowState::ACCEPTED));
    return true;
}

mw::E<bool> handleLikeActivity(const DataSourceInterface& data,
                               const Activity& activity,
                               int64_t now_seconds)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return false;
    ASSIGN_OR_RETURN(auto post, data.getPostByUri(*object_uri));
    if(!post.has_value()) return false;
    Like like;
    like.actor_uri = activity.actor;
    like.post_uri = *object_uri;
    like.activity_uri = activity.id;
    like.created_at = now_seconds;
    DO_OR_RETURN(data.addLike(like));
    return true;
}

mw::E<bool> handleAnnounceActivity(const DataSourceInterface& data,
                                   const Activity& activity,
                                   int64_t now_seconds)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return false;
    ASSIGN_OR_RETURN(auto post, data.getPostByUri(*object_uri));
    if(!post.has_value()) return false;
    if(post->visibility != Visibility::PUBLIC
       && post->visibility != Visibility::UNLISTED)
    {
        return false;
    }
    Boost boost;
    boost.actor_uri = activity.actor;
    boost.post_uri = *object_uri;
    boost.activity_uri = activity.id;
    boost.created_at = now_seconds;
    DO_OR_RETURN(data.addBoost(boost));
    return true;
}

mw::E<bool> handleEmojiReactActivity(const DataSourceInterface& data,
                                     const Activity& activity,
                                     int64_t now_seconds)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return false;
    ASSIGN_OR_RETURN(auto post, data.getPostByUri(*object_uri));
    if(!post.has_value()) return false;
    std::string emoji = ap::reactionContent(activity.raw);
    if(emoji.empty() || emoji.size() > 256) return false;
    Reaction reaction;
    reaction.actor_uri = activity.actor;
    reaction.post_uri = *object_uri;
    reaction.emoji = emoji;
    if(emoji.size() >= 3 && emoji.front() == ':' && emoji.back() == ':')
    {
        std::string shortcode = emoji.substr(1, emoji.size() - 2);
        auto remote_emoji = emojiTagsForObject(activity.raw);
        auto it = remote_emoji.find(shortcode);
        if(it != remote_emoji.end())
        {
            reaction.remote_emoji_url = it->second.image_url;
            reaction.remote_emoji_media_type = it->second.media_type;
        }
    }
    reaction.activity_uri = activity.id;
    reaction.created_at = now_seconds;
    DO_OR_RETURN(data.addReaction(reaction));
    return true;
}

mw::E<bool> handleDeleteActivity(const DataSourceInterface& data,
                                 const Activity& activity)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return false;
    ASSIGN_OR_RETURN(auto post, data.getPostByUri(*object_uri));
    if(!post.has_value() || post->local_author_id.has_value()
       || !post->remote_author_id.has_value())
    {
        return false;
    }
    ASSIGN_OR_RETURN(auto author, data.getRemoteActorById(
        *post->remote_author_id));
    if(!author.has_value() || author->uri != activity.actor) return false;
    DO_OR_RETURN(data.deletePost(post->id));
    return true;
}

mw::E<bool> handleUpdateActivity(const Config& config,
                                 const DataSourceInterface& data,
                                 const Activity& activity,
                                 int64_t now_seconds)
{
    if(!activity.object.is_object())
    {
        return false;
    }
    std::string type = jsonString(activity.object, "type");
    if(type != "Note")
    {
        auto actor_uri = normalizeRef(activity.object);
        if(!actor_uri.has_value() || *actor_uri != activity.actor)
            return false;
        ASSIGN_OR_RETURN(auto existing, data.getRemoteActorByUri(*actor_uri));
        if(!existing.has_value()) return false;

        RemoteActor updated = *existing;
        updated.username = activity.object.value("preferredUsername",
                                                 updated.username);
        if(updated.username.empty()) updated.username = updated.domain;
        updated.display_name = activity.object.value("name",
                                                     updated.display_name);
        if(activity.object.contains("inbox")
           && activity.object["inbox"].is_string())
        {
            updated.inbox = activity.object["inbox"].get<std::string>();
        }
        if(activity.object.contains("endpoints")
           && activity.object["endpoints"].is_object()
           && activity.object["endpoints"].contains("sharedInbox")
           && activity.object["endpoints"]["sharedInbox"].is_string())
        {
            updated.shared_inbox =
                activity.object["endpoints"]["sharedInbox"].get<std::string>();
        }
        if(activity.object.contains("publicKey")
           && activity.object["publicKey"].is_object())
        {
            const auto& key = activity.object["publicKey"];
            if(key.contains("id") && key["id"].is_string())
                updated.public_key_id = key["id"].get<std::string>();
            if(key.contains("publicKeyPem")
               && key["publicKeyPem"].is_string())
            {
                updated.public_key_pem =
                    key["publicKeyPem"].get<std::string>();
            }
        }
        updated.actor_json = activity.object.dump();
        updated.fetched_at = now_seconds;
        ASSIGN_OR_RETURN(auto stored, data.upsertRemoteActor(updated));
        (void)stored;
        return true;
    }
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return false;
    ASSIGN_OR_RETURN(auto existing, data.getPostByUri(*object_uri));
    if(!existing.has_value() || existing->local_author_id.has_value()
       || !existing->remote_author_id.has_value())
    {
        return false;
    }
    ASSIGN_OR_RETURN(auto author, data.getRemoteActorById(
        *existing->remote_author_id));
    auto attributed_to = normalizeRef(activity.object.contains("attributedTo")
        ? activity.object["attributedTo"] : nlohmann::json());
    if(!author.has_value() || author->uri != activity.actor
       || (attributed_to.has_value() && *attributed_to != activity.actor))
    {
        return false;
    }
    ASSIGN_OR_RETURN(auto np, remoteNotePostFromActivity(config, data, activity));
    DO_OR_RETURN(data.updatePost(
        existing->id, np, recipientsForObject(activity.object)));
    DO_OR_RETURN(storeRemoteAttachments(data, activity.object, existing->id));
    return true;
}

mw::E<bool> handleUndoActivity(const DataSourceInterface& data,
                               const Activity& activity)
{
    if(!activity.object.is_object()) return false;
    Activity wrapped;
    ASSIGN_OR_RETURN(wrapped, parseActivity(activity.object));
    if(wrapped.actor != activity.actor) return false;
    auto object_uri = normalizeRef(wrapped.object);
    if(wrapped.type == "Follow" && object_uri.has_value())
    {
        ASSIGN_OR_RETURN(auto follow, data.getFollow(wrapped.actor,
                                                     *object_uri));
        if(!follow.has_value()) return false;
        DO_OR_RETURN(data.removeFollow(wrapped.actor, *object_uri));
        return true;
    }
    if(wrapped.type == "Like" && object_uri.has_value())
    {
        ASSIGN_OR_RETURN(auto likes, data.likesForPost(*object_uri));
        bool exists = false;
        for(const auto& like : likes)
        {
            if(like.actor_uri == wrapped.actor)
            {
                exists = true;
                break;
            }
        }
        if(!exists) return false;
        DO_OR_RETURN(data.removeLike(wrapped.actor, *object_uri));
        return true;
    }
    if(wrapped.type == "Announce" && object_uri.has_value())
    {
        ASSIGN_OR_RETURN(auto boosts, data.boostsForPost(*object_uri));
        bool exists = false;
        for(const auto& boost : boosts)
        {
            if(boost.actor_uri == wrapped.actor)
            {
                exists = true;
                break;
            }
        }
        if(!exists) return false;
        DO_OR_RETURN(data.removeBoost(wrapped.actor, *object_uri));
        return true;
    }
    if(wrapped.type == "EmojiReact" && object_uri.has_value())
    {
        std::string emoji = ap::reactionContent(wrapped.raw);
        if(emoji.empty())
            emoji = jsonString(wrapped.raw, "name");
        if(!emoji.empty())
        {
            ASSIGN_OR_RETURN(auto reactions, data.reactionsForPost(
                *object_uri));
            bool exists = false;
            for(const auto& reaction : reactions)
            {
                if(reaction.actor_uri == wrapped.actor
                   && reaction.emoji == emoji)
                {
                    exists = true;
                    break;
                }
            }
            if(!exists) return false;
            DO_OR_RETURN(data.removeReaction(wrapped.actor, *object_uri,
                                             emoji));
            return true;
        }
    }
    return false;
}

class UnspokenApplication : public ap::Application
{
public:
    UnspokenApplication(const Config& policy, const DataSourceInterface& source)
        : config(policy), data(source)
    {
    }

    mw::E<ap::Decision> decide(ap::Transaction&, const ap::ValidatedActivity&,
                               const ap::LocalRecipient&) override
    {
        return ap::Decision::ACCEPT;
    }

    mw::E<void> apply(ap::Transaction&, const ap::AppliedEvent& event) override
    {
        if(!event.global_effect)
            return {};
        const auto& activity = event.activity;
        auto uri = normalizeRef(activity.object);
        if(!uri)
            return {};
        ASSIGN_OR_RETURN(auto existing, data.getPostByUri(*uri));
        if(activity.type == "Delete")
        {
            if(existing && !existing->local_author_id)
            {
                DO_OR_RETURN(data.deletePost(existing->id));
            }
            return {};
        }
        if(activity.type != "Create" && activity.type != "Update")
            return {};
        if(!activity.object.is_object())
            return {};
        auto type = activity.object.find("type");
        if(type == activity.object.end() || !type->is_string())
            return {};
        std::string object_type = type->get<std::string>();
        if(object_type != "Note" && object_type != "Article" &&
           object_type != "Image")
            return {};
        // Host content is a sanitized projection of the preserved wire object.
        ASSIGN_OR_RETURN(auto post,
                         remoteNotePostFromActivity(config, data, activity));
        if(existing)
        {
            if(activity.type == "Update")
            {
                DO_OR_RETURN(data.updatePost(
                    existing->id, post, recipientsForObject(activity.object)));
                DO_OR_RETURN(storeRemoteAttachments(data, activity.object,
                                                    existing->id));
            }
        }
        else
        {
            ASSIGN_OR_RETURN(
                auto inserted,
                data.insertPost(post, recipientsForObject(activity.object),
                                config.url_root + "p/"));
            DO_OR_RETURN(
                storeRemoteAttachments(data, activity.object, inserted.id));
        }
        return {};
    }

private:
    const Config& config;
    const DataSourceInterface& data;
};

ap::FederationConfig libraryConfig(const Config& config)
{
    ap::FederationConfig result;
    result.transport = transportConfig(config);
    result.activity_uri_prefix = config.url_root + "activities/";
    result.system_actor_uri = config.url_root + "actor";
    result.fetch_depth = config.thread_fetch_max_depth;
    result.max_retries = config.job_max_retries;
    result.retry_base_seconds = config.job_retry_base_delay_seconds;
    result.receipt_retention_seconds = config.seen_activity_retention_seconds;
    return result;
}

// Register exact application URLs and import snapshots only when absent.
mw::E<void> importApplicationState(const Config& config,
                                   const DataSourceSQLite& data,
                                   ap::Session& session)
{
    auto registry = EmojiRegistry::scan(config.emoji_dir, config.url_root);
    Service service(config, data, registry);
    ASSIGN_OR_RETURN(auto tx, ap::Transaction::begin(data.connection()));
    ASSIGN_OR_RETURN(auto users, data.connection().eval<int64_t>(
                                     "SELECT id FROM users ORDER BY id"));
    for(const auto& row : users)
    {
        ASSIGN_OR_RETURN(auto user, data.getUserById(std::get<0>(row)));
        if(!user)
            continue;
        ASSIGN_OR_RETURN(
            auto registered,
            session.localActor(config.url_root + "u/" + user->username));
        if(registered)
            continue;
        ap::LocalActor actor;
        actor.uri = config.url_root + "u/" + user->username;
        actor.key_id = actor.uri + "#main-key";
        actor.private_key_pem = user->private_key_pem;
        std::optional<Attachment> avatar;
        std::optional<Attachment> banner;
        if(user->avatar_attachment_id)
        {
            ASSIGN_OR_RETURN(
                avatar, data.getAttachmentById(*user->avatar_attachment_id));
        }
        if(user->banner_attachment_id)
        {
            ASSIGN_OR_RETURN(
                banner, data.getAttachmentById(*user->banner_attachment_id));
        }
        ASSIGN_OR_RETURN(auto fields, service.renderedProfileFields(*user));
        actor.document =
            actorJson(config, *user, renderPostContent(user->bio, registry),
                      avatar, banner, fields);
        DO_OR_RETURN(session.registerActor(tx, actor));
    }
    ASSIGN_OR_RETURN(auto system_actor, data.getSystemActor());
    if(system_actor)
    {
        ap::LocalActor system;
        system.uri = config.url_root + "actor";
        system.key_id = system.uri + "#main-key";
        system.private_key_pem = system_actor->private_key_pem;
        system.document = systemActorJson(config, system_actor->public_key_pem);
        DO_OR_RETURN(session.registerActor(tx, system));
    }
    ASSIGN_OR_RETURN(auto posts, data.connection().eval<int64_t>(
                                     "SELECT id FROM posts ORDER BY id"));
    for(const auto& row : posts)
    {
        ASSIGN_OR_RETURN(auto post, data.getPostById(std::get<0>(row)));
        if(!post)
            continue;
        ASSIGN_OR_RETURN(auto old, session.object(post->uri));
        if(old)
            continue;
        ASSIGN_OR_RETURN(auto recipients, data.getPostRecipients(post->id));
        nlohmann::json doc;
        std::string owner;
        if(post->local_author_id)
        {
            ASSIGN_OR_RETURN(auto user,
                             data.getUserById(*post->local_author_id));
            if(!user)
                continue;
            owner = config.url_root + "u/" + user->username;
            ASSIGN_OR_RETURN(auto attachments,
                             data.attachmentsForPost(post->id));
            doc = noteJson(config, *post, *user, recipients, attachments,
                           &registry);
            nlohmann::json historical = {
                {"@context", "https://www.w3.org/ns/activitystreams"},
                {"id", post->uri + "/activity"},
                {"type", "Create"},
                {"actor", owner},
                {"object", doc},
                {"to", doc["to"]},
                {"cc", doc["cc"]},
            };
            ASSIGN_OR_RETURN(
                auto outbox,
                data.connection().statementFromStr(
                    "INSERT OR IGNORE INTO "
                    "ap_outbox(activity_uri,actor_uri,document_json) "
                    "VALUES (?,?,?)"));
            DO_OR_RETURN((outbox.bind<std::string, std::string, std::string>(
                post->uri + "/activity", owner, historical.dump())));
            DO_OR_RETURN(data.connection().execute(std::move(outbox)));
        }
        else if(post->remote_author_id)
        {
            ASSIGN_OR_RETURN(auto actor,
                             data.getRemoteActorById(*post->remote_author_id));
            if(!actor)
                continue;
            owner = actor->uri;
            doc = {{"id", post->uri},
                   {"type", "Note"},
                   {"attributedTo", owner},
                   {"content", post->content_html},
                   {"to", nlohmann::json::array()},
                   {"cc", nlohmann::json::array()}};
            for(const auto& r : recipients)
                doc[r.field].push_back(r.recipient_uri);
            if(post->in_reply_to_uri)
                doc["inReplyTo"] = *post->in_reply_to_uri;
        }
        else
            continue;
        // This is a host-specific legacy import, not a new publication.
        ASSIGN_OR_RETURN(
            auto st,
            data.connection().statementFromStr(
                "INSERT INTO ap_objects(uri,owner_uri,local,document_json) "
                "VALUES (?,?,?,?)"));
        DO_OR_RETURN((st.bind<std::string, std::string, int64_t, std::string>(
            post->uri, owner, post->local_author_id ? 1 : 0, doc.dump())));
        DO_OR_RETURN(data.connection().execute(std::move(st)));
    }
    return tx.commit();
}

} // namespace

nlohmann::json actorJson(const Config& config, const User& user,
                         std::string_view summary_html)
{
    return actorJson(config, user, summary_html, std::nullopt, std::nullopt,
                     {});
}

nlohmann::json actorJson(
    const Config& config, const User& user, std::string_view summary_html,
    const std::optional<Attachment>& avatar,
    const std::optional<Attachment>& banner,
    const std::vector<RenderedProfileField>& fields)
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
    if(auto image = actorImageJson(config, avatar); image.has_value())
    {
        j["icon"] = *image;
    }
    if(auto image = actorImageJson(config, banner); image.has_value())
    {
        j["image"] = *image;
    }
    nlohmann::json attachment = nlohmann::json::array();
    for(const auto& field : fields)
    {
        if(field.label.empty() || field.value_html.empty()) continue;
        attachment.push_back({
            {"type", "PropertyValue"},
            {"name", field.label},
            {"value", field.value_html},
        });
    }
    if(!attachment.empty()) j["attachment"] = std::move(attachment);
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

nlohmann::json postTagsForSource(
    const Config& config, const std::vector<PostRecipient>& recipients,
    std::string_view source, const EmojiRegistry* emoji)
{
    return tagsForPostSource(config,recipients,source,emoji);
}

nlohmann::json noteJson(const Config& config, const Post& post,
                        const User& author,
                        const std::vector<PostRecipient>& recipients,
                        const std::vector<Attachment>& attachments,
                        const EmojiRegistry* emoji)
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
            url = localAttachmentUrl(config, a);
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
    if(post.content_source.has_value())
    {
        nlohmann::json tags = tagsForPostSource(config, recipients,
                                                *post.content_source, emoji);
        if(!tags.empty())
        {
            j["content"] = linkMentions(post.content_html,tags);
            j["tag"] = tags;
        }
    }
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
    return actorUpdateActivityJson(config, activity_id, user, summary_html,
                                   std::nullopt, std::nullopt, {},
                                   recipients);
}

nlohmann::json actorUpdateActivityJson(
    const Config& config, std::string_view activity_id, const User& user,
    std::string_view summary_html, const std::optional<Attachment>& avatar,
    const std::optional<Attachment>& banner,
    const std::vector<RenderedProfileField>& fields,
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
        {"object", actorJson(config, user, summary_html, avatar, banner,
                             fields)},
        {"to", to},
        {"cc", cc},
    };
}

nlohmann::json emojiReactActivityJson(
    const Config& config, std::string_view activity_id,
    std::string_view actor_uri, std::string_view object_uri,
    std::string_view emoji_str, const std::vector<PostRecipient>& recipients,
    const EmojiRegistry& emoji_registry)
{
    nlohmann::json to = nlohmann::json::array();
    nlohmann::json cc = nlohmann::json::array();
    for(const auto& r : recipients)
    {
        if(r.field == "to") to.push_back(r.recipient_uri);
        if(r.field == "cc") cc.push_back(r.recipient_uri);
    }

    nlohmann::json j = {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", std::string(activity_id)},
        {"type", "EmojiReact"},
        {"actor", std::string(actor_uri)},
        {"object", std::string(object_uri)},
        {"content", std::string(emoji_str)},
        {"to", to},
        {"cc", cc},
    };

    if(emoji_str.size() >= 3 && emoji_str.front() == ':'
       && emoji_str.back() == ':')
    {
        std::string shortcode(emoji_str.substr(1, emoji_str.size() - 2));
        if(auto info = emoji_registry.lookup(shortcode); info.has_value())
        {
            j["tag"] = nlohmann::json::array({
                {
                    {"type", "Emoji"},
                    {"id", config.url_root + "emoji/" + shortcode},
                    {"name", std::string(emoji_str)},
                    {"icon", {
                        {"type", "Image"},
                        {"mediaType", info->media_type},
                        {"url", info->image_url},
                    }},
                },
            });
        }
    }
    return j;
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

nlohmann::json systemWebFingerJson(const Config& config)
{
    const std::string actor = config.url_root + "actor";
    const auto url = mw::URL::fromStr(config.url_root);
    const auto host = url->host();
    return {
        {"subject", std::format("acct:unspoken@{}", host)},
        {"aliases", nlohmann::json::array({actor})},
        {"links", nlohmann::json::array({{
            {"rel", "self"},
            {"type", "application/activity+json"},
            {"href", actor},
        }})},
    };
}

std::string hostMetaXml(const Config& config)
{
    std::string webfinger = config.url_root
        + ".well-known/webfinger?resource={uri}";
    return std::format(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<XRD xmlns=\"http://docs.oasis-open.org/ns/xri/xrd-1.0\">\n"
        "  <Link rel=\"lrdd\" type=\"application/xrd+xml\" "
        "template=\"{}\" />\n"
        "</XRD>\n",
        webfinger);
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
    return nodeInfoJson(config, 0, 0);
}

nlohmann::json nodeInfoJson(const Config& config, int64_t user_count,
                            int64_t local_post_count)
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
                {"total", user_count},
                {"activeHalfyear", 0},
                {"activeMonth", 0},
            }},
            {"localPosts", local_post_count},
        }},
        {"metadata", {
            {"nodeDescription", config.nodeinfo.description},
        }},
    };
}

mw::E<nlohmann::json> nodeInfoJson(const Config& config,
                                   const DataSourceInterface& data)
{
    ASSIGN_OR_RETURN(auto user_count, data.countUsers());
    ASSIGN_OR_RETURN(auto local_post_count, data.countLocalPosts());
    return nodeInfoJson(config, user_count, local_post_count);
}

mw::E<void> hardenOutboundSession(const Config& config,
                                  mw::HTTPSessionInterface& http,
                                  std::string_view target_url)
{
    return ap::hardenOutboundSession(transportConfig(config), http, target_url);
}

mw::E<mw::HTTPRequest> signedGetRequest(const Config& config,
                                        const SystemActor& system_actor,
                                        mw::CryptoInterface& crypto,
                                        std::string_view uri)
{
    return signedHttpRequest(config, crypto,
                             signingActorForSystem(config, system_actor),
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

mw::E<mw::HTTPRequest>
signedHttpRequest(const Config& config, mw::CryptoInterface& crypto,
                  const SigningActor& actor, std::string_view method,
                  std::string_view uri, std::string_view body,
                  std::string_view content_type)
{
    return ap::signedHttpRequest(transportConfig(config), crypto, actor, method,
                                 uri, body, content_type);
}

mw::E<RemoteActor> fetchRemoteActor(const Config& config,
                                    mw::CryptoInterface& crypto,
                                    mw::HTTPSessionInterface& http,
                                    const SystemActor& system_actor,
                                    std::string_view actor_uri)
{
    return ap::fetchRemoteActor(transportConfig(config), crypto, http,
                                signingActorForSystem(config, system_actor),
                                actor_uri);
}

mw::E<RemoteActorResolution> findOrFetchRemoteActor(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view actor_uri)
{
    ASSIGN_OR_RETURN(auto cached, data.getRemoteActorByUri(actor_uri));
    if(cached.has_value()) return RemoteActorResolution{*cached, true};

    ASSIGN_OR_RETURN(auto actor, fetchRemoteActor(
        config, crypto, http, system_actor, actor_uri));
    return RemoteActorResolution{std::move(actor), false};
}

mw::E<RemoteActor> ensureRemoteActorRetained(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view actor_uri,
    int64_t now_seconds)
{
    ASSIGN_OR_RETURN(auto resolution, findOrFetchRemoteActor(
        config, data, crypto, http, system_actor, actor_uri));
    if(resolution.retained) return resolution.actor;

    if(now_seconds > 0) resolution.actor.fetched_at = now_seconds;
    return data.upsertRemoteActor(resolution.actor);
}

mw::E<RemoteActor> resolveWebFingerActor(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view handle)
{
    auto parsed = parseHandle(handle);
    if(!parsed.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "WebFinger query must be a user@domain handle"));
    }
    const auto& [username, domain] = *parsed;
    if(domain == config.public_domain)
    {
        return std::unexpected(mw::runtimeError(
            "Local handles do not need WebFinger resolution"));
    }

    ASSIGN_OR_RETURN(
        auto actor_uri,
        ap::discoverActorUri(transportConfig(config), http, handle));
    ASSIGN_OR_RETURN(auto resolution,
                     findOrFetchRemoteActor(config, data, crypto, http,
                                            system_actor, actor_uri));
    return resolution.actor;
}

mw::E<Post> fetchRemotePostByUri(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view post_uri)
{
    if(const auto* sqlite = dynamic_cast<const DataSourceSQLite*>(&data))
    {
        UnspokenApplication application(config, data);
        auto policy = libraryConfig(config);
        ap::Session session(policy, sqlite->connection(), crypto, http,
                            application);
        DO_OR_RETURN(importApplicationState(config, *sqlite, session));
        {
            ASSIGN_OR_RETURN(auto tx,
                             ap::Transaction::begin(sqlite->connection()));
            ap::LocalActor system;
            system.uri = policy.system_actor_uri;
            system.key_id = system.uri + "#main-key";
            system.private_key_pem = system_actor.private_key_pem;
            system.document =
                systemActorJson(config, system_actor.public_key_pem);
            DO_OR_RETURN(session.registerActor(tx, system));
            DO_OR_RETURN(tx.commit());
        }
        ASSIGN_OR_RETURN(auto document, session.fetchAndStoreObject(post_uri));
        auto object_uri = normalizeRef(document);
        if(!object_uri)
            return std::unexpected(mw::runtimeError("Missing object ID"));
        ASSIGN_OR_RETURN(auto post, data.getPostByUri(*object_uri));
        if(!post)
            return std::unexpected(mw::runtimeError("Missing post projection"));
        return *post;
    }

    ASSIGN_OR_RETURN(auto existing, data.getPostByUri(post_uri));
    if(existing.has_value()) return *existing;

    ASSIGN_OR_RETURN(auto doc, signedGetJson(config, crypto, http,
                                             system_actor, post_uri));
    Activity activity;
    std::string object_uri;

    if(doc.is_object() && jsonString(doc, "type") == "Note")
    {
        auto id = normalizeRef(doc);
        if(!id.has_value())
        {
            return std::unexpected(mw::runtimeError(
                "Remote post is missing id"));
        }
        auto actor = normalizeRef(doc.contains("attributedTo")
            ? doc["attributedTo"] : nlohmann::json());
        object_uri = *id;
        activity.id = object_uri + "#fetch";
        activity.type = "Create";
        activity.actor = actor.value_or(std::string());
        activity.object = doc;
        activity.raw = {
            {"id", activity.id},
            {"type", "Create"},
            {"actor", activity.actor},
            {"object", doc},
        };
    }
    else if(doc.is_object() && jsonString(doc, "type") == "Create" &&
            doc.contains("object") && doc["object"].is_object() &&
            doc["object"].value("type", std::string()) == "Note")
    {
        ASSIGN_OR_RETURN(activity, parseActivity(doc));
        auto id = normalizeRef(activity.object);
        if(!id.has_value())
        {
            return std::unexpected(mw::runtimeError(
                "Remote Create object is missing id"));
        }
        object_uri = *id;
    }
    else
    {
        return std::unexpected(mw::runtimeError(
            "Remote URL did not resolve to a post"));
    }

    if(activity.actor.empty())
    {
        return std::unexpected(mw::runtimeError(
            "Remote post is missing an actor"));
    }
    DO_OR_RETURN(ensureRemoteActorForObject(
        config, data, crypto, http, system_actor, activity.object,
        activity.actor));
    DO_OR_RETURN(handleCreateActivity(config, data, activity));

    ASSIGN_OR_RETURN(auto post, data.getPostByUri(object_uri));
    if(!post.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Remote post was not stored"));
    }
    return *post;
}

mw::E<VerifiedSignature> verifyHttpSignature(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, const IncomingHttpRequest& req,
    int64_t now_seconds)
{
    ASSIGN_OR_RETURN(
        auto signature,
        ap::parseHttpSignature(transportConfig(config), req, now_seconds));
    ASSIGN_OR_RETURN(auto actor, data.getRemoteActorByUri(signature.actor_uri));
    if(!actor.has_value())
    {
        return std::unexpected(mw::httpError(401, "Unknown signature key"));
    }

    ASSIGN_OR_RETURN(bool ok,
                     ap::verifyParsedHttpSignature(crypto, signature, *actor));
    if(!ok)
    {
        return std::unexpected(mw::httpError(401, "Bad signature"));
    }
    return VerifiedSignature{
        signature.actor_uri,
        signature.key_id,
        *actor,
        true,
        false,
    };
}

mw::E<VerifiedSignature> verifyHttpSignatureWithKeyRefresh(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, const IncomingHttpRequest& req,
    int64_t now_seconds)
{
    ASSIGN_OR_RETURN(
        auto signature,
        ap::parseHttpSignature(transportConfig(config), req, now_seconds));
    ASSIGN_OR_RETURN(auto cached, data.getRemoteActorByUri(
        signature.actor_uri));

    if(!cached.has_value())
    {
        auto fetched = fetchRemoteActor(config, crypto, http, system_actor,
                                        signature.actor_uri);
        if(!fetched.has_value() || fetched->public_key_id != signature.key_id)
        {
            return std::unexpected(mw::httpError(
                401, "Unknown signature key"));
        }
        ASSIGN_OR_RETURN(bool ok, ap::verifyParsedHttpSignature(
                                      crypto, signature, *fetched));
        if(!ok)
        {
            return std::unexpected(mw::httpError(401, "Bad signature"));
        }
        return VerifiedSignature{
            signature.actor_uri,
            signature.key_id,
            std::move(*fetched),
            false,
            false,
        };
    }

    if(cached->public_key_id == signature.key_id)
    {
        ASSIGN_OR_RETURN(
            bool ok, ap::verifyParsedHttpSignature(crypto, signature, *cached));
        if(ok)
        {
            return VerifiedSignature{
                signature.actor_uri,
                signature.key_id,
                *cached,
                true,
                false,
            };
        }
    }

    auto fetched = fetchRemoteActor(config, crypto, http, system_actor,
                                    signature.actor_uri);
    if(!fetched.has_value() || fetched->public_key_id != signature.key_id)
    {
        return std::unexpected(mw::httpError(401, "Bad signature"));
    }
    ASSIGN_OR_RETURN(
        bool ok, ap::verifyParsedHttpSignature(crypto, signature, *fetched));
    if(!ok)
    {
        return std::unexpected(mw::httpError(401, "Bad signature"));
    }
    ASSIGN_OR_RETURN(auto retained, data.upsertRemoteActor(*fetched));
    return VerifiedSignature{
        signature.actor_uri,
        signature.key_id,
        std::move(retained),
        true,
        true,
    };
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
    if(const auto* sqlite = dynamic_cast<const DataSourceSQLite*>(&data))
    {
        mw::Crypto crypto;
        mw::HTTPSession http;
        UnspokenApplication application(config, data);
        auto policy = libraryConfig(config);
        ap::Session session(policy, sqlite->connection(), crypto, http,
                            application);
        ASSIGN_OR_RETURN(bool active, ap::inTransaction(sqlite->connection()));
        ASSIGN_OR_RETURN(auto tx,
                         active ? ap::Transaction::join(sqlite->connection())
                                : ap::Transaction::begin(sqlite->connection()));
        ASSIGN_OR_RETURN(auto local, session.localActor(signer_actor_uri));
        if(!local)
        {
            auto username = localUsernameForActor(config, signer_actor_uri);
            if(!username)
                return std::unexpected(mw::runtimeError("Unknown signer"));
            ASSIGN_OR_RETURN(auto user, data.getUserByUsername(*username));
            if(!user)
                return std::unexpected(mw::runtimeError("Unknown signer"));
            ap::LocalActor actor;
            actor.uri = std::string(signer_actor_uri);
            actor.key_id = actor.uri + "#main-key";
            actor.private_key_pem = user->private_key_pem;
            actor.document =
                actorJson(config, *user, renderMarkdown(user->bio));
            DO_OR_RETURN(session.registerActor(tx, actor));
        }
        ap::Publication publication;
        if(activity.value("actor", std::string()) == signer_actor_uri)
        {
            ASSIGN_OR_RETURN(publication,
                             session.publish(tx, activity, now_seconds));
        }
        else
        {
            ASSIGN_OR_RETURN(auto inboxes, deliveryInboxesForRecipients(
                                               config, data, recipients));
            ASSIGN_OR_RETURN(publication,
                             session.enqueue(tx, signer_actor_uri, activity,
                                             inboxes, now_seconds));
        }
        if(!active)
        {
            DO_OR_RETURN(tx.commit());
        }
        // The facade historically returns job IDs; query those created for
        // this immutable activity rather than exposing outbox sequence as one.
        ASSIGN_OR_RETURN(
            auto st,
            sqlite->connection().statementFromStr(
                "SELECT id FROM ap_jobs WHERE kind='deliver' AND "
                "json_extract(payload_json,'$.activity.id')=? ORDER BY id"));
        DO_OR_RETURN(st.bind<std::string>(publication.activity_uri));
        ASSIGN_OR_RETURN(auto rows,
                         sqlite->connection().eval<int64_t>(std::move(st)));
        std::vector<int64_t> ids;
        for(const auto& row : rows)
            ids.push_back(std::get<0>(row));
        return ids;
    }
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

mw::E<void> enqueueFollowActivity(
    const Config& config, const DataSourceInterface& data,
    const User& viewer, std::string_view target_actor_uri,
    std::string_view activity_id, int64_t now)
{
    const std::string actor_uri = config.url_root + "u/" + viewer.username;
    nlohmann::json activity = {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", std::string(activity_id)},
        {"type", "Follow"},
        {"actor", actor_uri},
        {"object", std::string(target_actor_uri)},
        {"to", nlohmann::json::array({std::string(target_actor_uri)})},
    };
    std::vector<PostRecipient> recipients = {
        {0, std::string(target_actor_uri), "to"},
    };
    ASSIGN_OR_RETURN([[maybe_unused]] auto jobs,
        enqueueOutboundDelivery(config,data,actor_uri,activity,recipients,now));
    return {};
}

mw::E<std::vector<int64_t>> enqueueActorUpdateDelivery(
    const Config& config, const DataSourceInterface& data, const User& user,
    std::string_view summary_html, int64_t now_seconds)
{
    return enqueueActorUpdateDelivery(config, data, user, summary_html,
                                      std::nullopt, std::nullopt, {},
                                      now_seconds);
}

mw::E<std::vector<int64_t>> enqueueActorUpdateDelivery(
    const Config& config, const DataSourceInterface& data, const User& user,
    std::string_view summary_html, const std::optional<Attachment>& avatar,
    const std::optional<Attachment>& banner,
    const std::vector<RenderedProfileField>& fields, int64_t now_seconds)
{
    std::string actor_uri = config.url_root + "u/" + user.username;
    std::vector<PostRecipient> recipients = {
        {0, actor_uri + "/followers", "to"},
    };
    ASSIGN_OR_RETURN(
        auto activity_uri,
        ap::newActivityUri(config.url_root + "activities/update/profile/"));
    nlohmann::json activity =
        actorUpdateActivityJson(config, activity_uri, user, summary_html,
                                avatar, banner, fields, recipients);
    return enqueueOutboundDelivery(
        config, data, actor_uri, activity, recipients, now_seconds);
}

mw::E<int64_t> enqueueFetchThreadJob(const DataSourceInterface& data,
                                     std::string_view root_uri,
                                     int64_t now_seconds)
{
    if(root_uri.empty())
    {
        return std::unexpected(mw::runtimeError(
            "Fetch-thread job requires a root URI"));
    }
    nlohmann::json payload = {
        {"root_uri", std::string(root_uri)},
    };
    return data.enqueueJob("fetch_thread", payload.dump(), now_seconds,
                           now_seconds);
}

mw::E<InboxDispatchResult> dispatchIncomingActivity(
    const Config& config, const DataSourceInterface& data,
    const VerifiedSignature& verified_signature, const Activity& activity,
    int64_t now_seconds, mw::CryptoInterface* crypto,
    mw::HTTPSessionInterface* http, const SystemActor* system_actor)
{
    const bool direct_delivery = activity.actor == verified_signature.actor_uri;
    std::optional<ForwardingPlan> forwarding_plan;
    if(!direct_delivery)
    {
        ASSIGN_OR_RETURN(forwarding_plan, prepareIncomingForwarding(
            config, data, crypto, http, system_actor, activity));
        if(!forwarding_plan.has_value())
        {
            return InboxDispatchResult{InboxDisposition::IGNORED, false};
        }
    }

    ASSIGN_OR_RETURN(auto claim, data.claimIncomingActivity(
        activity.id, now_seconds, config.inbox_processing_lease_seconds));
    if(claim == ActivityClaimResult::ALREADY_PROCESSED)
    {
        return InboxDispatchResult{InboxDisposition::DUPLICATE, false};
    }
    if(claim == ActivityClaimResult::IN_PROGRESS)
    {
        return InboxDispatchResult{InboxDisposition::PROCESSING, false};
    }

    auto release_claim = [&]() {
        auto released = data.releaseIncomingActivity(activity.id);
        if(!released.has_value())
        {
            spdlog::error("Failed to release inbox activity claim {}: {}",
                          activity.id, mw::errorMsg(released.error()));
        }
    };
    auto dispatch = [&]() -> mw::E<InboxDispatchResult> {
        bool forwarded = false;
        if(forwarding_plan.has_value())
        {
            ASSIGN_OR_RETURN(forwarded, executeIncomingForwarding(
                config, data, *forwarding_plan, now_seconds));
        }
        if(!direct_delivery)
        {
            return InboxDispatchResult{
                forwarded ? InboxDisposition::FORWARDED
                          : InboxDisposition::IGNORED,
                false,
            };
        }

        ASSIGN_OR_RETURN(forwarding_plan, prepareIncomingForwarding(
            config, data, crypto, http, system_actor, activity));
        if(forwarding_plan.has_value())
        {
            ASSIGN_OR_RETURN(forwarded, executeIncomingForwarding(
                config, data, *forwarding_plan, now_seconds));
        }

        bool applied = false;
        bool actor_retained = false;
        auto retain_actor = [&]() -> mw::E<void> {
            if(verified_signature.actor_was_retained) return {};
            ASSIGN_OR_RETURN(auto retained, data.upsertRemoteActor(
                verified_signature.actor));
            (void)retained;
            actor_retained = true;
            return {};
        };

        if(activity.type == "Create")
        {
            if(activity.object.is_object())
            {
                ASSIGN_OR_RETURN(applied, handleCreateActivity(
                    config, data, activity, &verified_signature));
                actor_retained = applied
                    && !verified_signature.actor_was_retained;
            }
            else if(auto object_uri = normalizeRef(activity.object);
                    object_uri.has_value() && !isLocalActorUri(config,
                                                               *object_uri))
            {
                if(crypto == nullptr || http == nullptr
                   || system_actor == nullptr)
                {
                    return std::unexpected(mw::runtimeError(
                        "Create object fetch requires federation clients"));
                }
                ASSIGN_OR_RETURN(auto post, fetchRemotePostByUri(
                    config, data, *crypto, *http, *system_actor, *object_uri));
                (void)post;
                applied = true;
            }
        }
        else if(activity.type == "Follow")
        {
            ASSIGN_OR_RETURN(applied, handleFollowActivity(
                config, data, activity, verified_signature, now_seconds,
                actor_retained));
        }
        else if(activity.type == "Accept")
        {
            ASSIGN_OR_RETURN(applied,
                             handleAcceptActivity(config, data, activity));
            if(applied) DO_OR_RETURN(retain_actor());
        }
        else if(activity.type == "Like")
        {
            ASSIGN_OR_RETURN(applied, handleLikeActivity(data, activity,
                                                          now_seconds));
            if(applied) DO_OR_RETURN(retain_actor());
        }
        else if(activity.type == "Announce")
        {
            ASSIGN_OR_RETURN(applied, handleAnnounceActivity(data, activity,
                                                              now_seconds));
            if(applied) DO_OR_RETURN(retain_actor());
        }
        else if(activity.type == "EmojiReact")
        {
            ASSIGN_OR_RETURN(applied, handleEmojiReactActivity(data, activity,
                                                                now_seconds));
            if(applied) DO_OR_RETURN(retain_actor());
        }
        else if(activity.type == "Delete")
        {
            ASSIGN_OR_RETURN(applied, handleDeleteActivity(data, activity));
        }
        else if(activity.type == "Undo")
        {
            ASSIGN_OR_RETURN(applied, handleUndoActivity(data, activity));
        }
        else if(activity.type == "Update")
        {
            ASSIGN_OR_RETURN(applied, handleUpdateActivity(config, data, activity,
                                                            now_seconds));
        }

        InboxDisposition disposition = InboxDisposition::IGNORED;
        if(applied && forwarded)
            disposition = InboxDisposition::APPLIED_AND_FORWARDED;
        else if(applied)
            disposition = InboxDisposition::APPLIED;
        else if(forwarded)
            disposition = InboxDisposition::FORWARDED;
        return InboxDispatchResult{disposition, actor_retained};
    };

    auto result = dispatch();
    if(!result.has_value())
    {
        auto error = std::move(result.error());
        release_claim();
        return std::unexpected(std::move(error));
    }
    auto finalized = data.finalizeIncomingActivity(activity.id, now_seconds);
    if(!finalized.has_value())
    {
        auto error = std::move(finalized.error());
        release_claim();
        return std::unexpected(std::move(error));
    }
    return *result;
}

mw::E<int64_t> runInboxMaintenanceOnce(const Config& config,
                                       const DataSourceInterface& data,
                                       int64_t now_seconds)
{
    return data.pruneIncomingActivities(
        now_seconds - config.seen_activity_retention_seconds,
        config.maintenance_batch_size);
}

mw::E<int64_t> runRemoteActorCollectionOnce(
    const Config& config, const DataSourceInterface& data,
    int64_t now_seconds)
{
    return data.collectUnreferencedRemoteActors(
        now_seconds - config.remote_actor_gc_grace_seconds,
        config.maintenance_batch_size);
}

mw::E<bool> runFederationJobOnce(const Config& config,
                                 const DataSourceInterface& data,
                                 mw::CryptoInterface& crypto,
                                 mw::HTTPSessionInterface& http,
                                 int64_t now_seconds)
{
    if(const auto* sqlite = dynamic_cast<const DataSourceSQLite*>(&data))
    {
        UnspokenApplication application(config, data);
        auto policy = libraryConfig(config);
        ap::Session session(policy, sqlite->connection(), crypto, http,
                            application);
        ASSIGN_OR_RETURN(auto actor_count,
                         sqlite->connection().evalToValue<int64_t>(
                             "SELECT count(*) FROM ap_local_actors"));
        if(actor_count == 0)
        {
            DO_OR_RETURN(importApplicationState(config, *sqlite, session));
        }
        return session.runOnce(now_seconds);
    }
    ASSIGN_OR_RETURN(auto claimed, data.claimJob(now_seconds));
    if(!claimed.has_value()) return false;

    mw::E<void> result;
    if(claimed->kind == "deliver")
    {
        nlohmann::json payload = nlohmann::json::parse(
            claimed->payload_json, nullptr, false);
        result = performDeliveryJob(config, data, crypto, http, payload);
    }
    else if(claimed->kind == "fetch_thread")
    {
        nlohmann::json payload = nlohmann::json::parse(
            claimed->payload_json, nullptr, false);
        result = performFetchThreadJob(config, data, crypto, http, payload);
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

mw::E<void> initializeFederationLibrary(const Config& config,
                                        const DataSourceSQLite& data,
                                        mw::CryptoInterface& crypto,
                                        mw::HTTPSessionInterface& http)
{
    ASSIGN_OR_RETURN(auto system, data.getSystemActor());
    if(!system)
    {
        ASSIGN_OR_RETURN(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
        DO_OR_RETURN(data.setSystemActor(keys.private_key, keys.public_key));
    }
    UnspokenApplication application(config, data);
    auto policy = libraryConfig(config);
    ap::Session session(policy, data.connection(), crypto, http, application);
    DO_OR_RETURN(session.migrate());
    DO_OR_RETURN(importApplicationState(config, data, session));
    ASSIGN_OR_RETURN(auto restored,session.restoreEmojiReactions());
    if(restored > 0)
        spdlog::info("Repaired {} retained emoji reaction activities",restored);
    return {};
}

mw::E<InboxDispatchResult>
receiveFederationInbox(const Config& config, const DataSourceSQLite& data,
                       mw::CryptoInterface& crypto,
                       mw::HTTPSessionInterface& http,
                       const IncomingHttpRequest& request,
                       std::string_view endpoint_actor, int64_t now)
{
    UnspokenApplication application(config, data);
    auto policy = libraryConfig(config);
    ap::Session session(policy, data.connection(), crypto, http, application);
    ASSIGN_OR_RETURN(auto prepared,
                     session.prepareInbox(request, endpoint_actor, now));
    ASSIGN_OR_RETURN(auto result,
                     session.acceptInbox(std::move(prepared), now));
    InboxDisposition disposition = InboxDisposition::IGNORED;
    if(result.duplicate)
        disposition = InboxDisposition::DUPLICATE;
    else if(result.applied && result.forwarded)
        disposition = InboxDisposition::APPLIED_AND_FORWARDED;
    else if(result.applied)
        disposition = InboxDisposition::APPLIED;
    else if(result.forwarded)
        disposition = InboxDisposition::FORWARDED;
    return InboxDispatchResult{disposition, result.applied};
}

mw::E<nlohmann::json> federationActorDocument(const Config& config,
                                              const DataSourceSQLite& data,
                                              std::string_view actor_uri)
{
    mw::Crypto crypto;
    mw::HTTPSession http;
    UnspokenApplication application(config, data);
    auto policy = libraryConfig(config);
    ap::Session session(policy, data.connection(), crypto, http, application);
    ASSIGN_OR_RETURN(auto actor, session.localActor(actor_uri));
    if(!actor)
        return std::unexpected(mw::httpError(404, "Unknown actor"));
    return actor->document;
}

mw::E<std::optional<nlohmann::json>> federationObjectDocument(
    const Config& config, const DataSourceSQLite& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    std::string_view object_uri, std::string_view local_viewer_actor,
    const IncomingHttpRequest& request, int64_t now)
{
    UnspokenApplication application(config, data);
    auto policy = libraryConfig(config);
    ap::Session session(policy, data.connection(), crypto, http, application);
    ASSIGN_OR_RETURN(auto doc,
                     session.objectForActor(object_uri, local_viewer_actor));
    if(doc)
        return doc;
    auto verified = session.authenticate(request, now);
    if(!verified)
        return std::nullopt;
    return session.objectForActor(object_uri, verified->actor_uri);
}

mw::E<nlohmann::json> federationOutboxPage(const Config& config,
                                           const DataSourceSQLite& data,
                                           std::string_view actor_uri,
                                           const Cursor& cursor,
                                           std::string_view self_uri)
{
    mw::Crypto crypto;
    mw::HTTPSession http;
    UnspokenApplication application(config, data);
    auto policy = libraryConfig(config);
    ap::Session session(policy, data.connection(), crypto, http, application);
    return session.outboxPage(actor_uri, cursor, config.posts_per_page,
                              self_uri);
}

} // namespace unspoken
