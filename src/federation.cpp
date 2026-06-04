#include "federation.hpp"

#include <algorithm>
#include <ctime>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>
#include <mw/error.hpp>

#include "attachments.hpp"
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

void appendAll(std::vector<std::string>& out,
               const std::vector<std::string>& in)
{
    out.insert(out.end(), in.begin(), in.end());
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

} // namespace unspoken
