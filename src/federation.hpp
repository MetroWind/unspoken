#pragma once

#include <optional>
#include <unordered_map>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>
#include <mw/crypto.hpp>
#include <mw/error.hpp>
#include <mw/http_client.hpp>

#include "config.hpp"
#include "data.hpp"
#include "structs.hpp"

namespace unspoken
{

struct IncomingHttpRequest
{
    std::string method;
    std::string target;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

struct VerifiedSignature
{
    std::string actor_uri;
    std::string key_id;
};

struct SigningActor
{
    std::string actor_uri;
    std::string key_id;
    std::string private_key_pem;
};

std::vector<std::string> normalizeAddressing(const nlohmann::json& field);
std::optional<std::string> normalizeRef(const nlohmann::json& field);
mw::E<Activity> parseActivity(const nlohmann::json& raw);
bool isPublicAddress(std::string_view uri);

bool wantsActivityJson(std::string_view accept);

nlohmann::json actorJson(const Config& config, const User& user,
                         std::string_view summary_html);
nlohmann::json systemActorJson(const Config& config,
                               std::string_view public_key_pem);
nlohmann::json noteJson(const Config& config, const Post& post,
                        const User& author,
                        const std::vector<PostRecipient>& recipients,
                        const std::vector<Attachment>& attachments);
nlohmann::json webFingerJson(const Config& config, const User& user);
nlohmann::json nodeInfoDiscoveryJson(const Config& config);
nlohmann::json nodeInfoJson(const Config& config);

bool isAllowedOutboundAddress(const mw::SockAddr& addr);
mw::E<void> hardenOutboundSession(mw::HTTPSessionInterface& http);
mw::E<mw::HTTPRequest> signedGetRequest(const Config& config,
                                        const SystemActor& system_actor,
                                        mw::CryptoInterface& crypto,
                                        std::string_view uri);
SigningActor signingActorFor(const Config& config, const User& user);
SigningActor signingActorForSystem(const Config& config,
                                   const SystemActor& system_actor);
mw::E<mw::HTTPRequest> signedHttpRequest(
    mw::CryptoInterface& crypto, const SigningActor& actor,
    std::string_view method, std::string_view uri,
    std::string_view body = "", std::string_view content_type = "");
mw::E<RemoteActor> resolveRemoteActor(const Config& config,
                                      const DataSourceInterface& data,
                                      mw::CryptoInterface& crypto,
                                      mw::HTTPSessionInterface& http,
                                      const SystemActor& system_actor,
                                      std::string_view actor_uri);
mw::E<VerifiedSignature> verifyHttpSignature(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, const IncomingHttpRequest& req,
    int64_t now_seconds);

} // namespace unspoken
