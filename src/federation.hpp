#pragma once

#include <cstdint>
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
#include "emoji.hpp"
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

struct InboxDispatchResult
{
    bool duplicate = false;
};

std::vector<std::string> normalizeAddressing(const nlohmann::json& field);
std::optional<std::string> normalizeRef(const nlohmann::json& field);
mw::E<Activity> parseActivity(const nlohmann::json& raw);
bool isPublicAddress(std::string_view uri);

bool wantsActivityJson(std::string_view accept);

nlohmann::json actorJson(const Config& config, const User& user,
                         std::string_view summary_html);
nlohmann::json actorJson(
    const Config& config, const User& user, std::string_view summary_html,
    const std::optional<Attachment>& avatar,
    const std::optional<Attachment>& banner,
    const std::vector<RenderedProfileField>& fields);
nlohmann::json systemActorJson(const Config& config,
                               std::string_view public_key_pem);
nlohmann::json noteJson(const Config& config, const Post& post,
                        const User& author,
                        const std::vector<PostRecipient>& recipients,
                        const std::vector<Attachment>& attachments,
                        const EmojiRegistry* emoji = nullptr);
nlohmann::json deleteActivityJson(std::string_view activity_id,
                                  std::string_view actor_uri,
                                  std::string_view object_uri,
                                  const std::vector<PostRecipient>& recipients);
nlohmann::json actorUpdateActivityJson(
    const Config& config, std::string_view activity_id, const User& user,
    std::string_view summary_html,
    const std::vector<PostRecipient>& recipients);
nlohmann::json actorUpdateActivityJson(
    const Config& config, std::string_view activity_id, const User& user,
    std::string_view summary_html, const std::optional<Attachment>& avatar,
    const std::optional<Attachment>& banner,
    const std::vector<RenderedProfileField>& fields,
    const std::vector<PostRecipient>& recipients);
nlohmann::json emojiReactActivityJson(
    const Config& config, std::string_view activity_id,
    std::string_view actor_uri, std::string_view object_uri,
    std::string_view emoji, const std::vector<PostRecipient>& recipients,
    const EmojiRegistry& emoji_registry);
nlohmann::json webFingerJson(const Config& config, const User& user);
std::string hostMetaXml(const Config& config);
nlohmann::json nodeInfoDiscoveryJson(const Config& config);
nlohmann::json nodeInfoJson(const Config& config);
nlohmann::json nodeInfoJson(const Config& config, int64_t user_count,
                            int64_t local_post_count);
mw::E<nlohmann::json> nodeInfoJson(const Config& config,
                                   const DataSourceInterface& data);

bool isAllowedOutboundAddress(const mw::SockAddr& addr);
mw::E<void> hardenOutboundSession(mw::HTTPSessionInterface& http);
mw::E<void> hardenOutboundSession(const Config& config,
                                  mw::HTTPSessionInterface& http,
                                  std::string_view target_url);
mw::E<mw::HTTPRequest> signedGetRequest(const Config& config,
                                        const SystemActor& system_actor,
                                        mw::CryptoInterface& crypto,
                                        std::string_view uri);
SigningActor signingActorFor(const Config& config, const User& user);
SigningActor signingActorForSystem(const Config& config,
                                   const SystemActor& system_actor);
mw::E<mw::HTTPRequest> signedHttpRequest(
    const Config& config, mw::CryptoInterface& crypto,
    const SigningActor& actor,
    std::string_view method, std::string_view uri,
    std::string_view body = "", std::string_view content_type = "");
mw::E<RemoteActor> resolveRemoteActor(const Config& config,
                                      const DataSourceInterface& data,
                                      mw::CryptoInterface& crypto,
                                      mw::HTTPSessionInterface& http,
                                      const SystemActor& system_actor,
                                      std::string_view actor_uri,
                                      bool force_refresh = false);
mw::E<RemoteActor> resolveWebFingerActor(const Config& config,
                                         const DataSourceInterface& data,
                                         mw::CryptoInterface& crypto,
                                         mw::HTTPSessionInterface& http,
                                         const SystemActor& system_actor,
                                         std::string_view handle);
mw::E<Post> fetchRemotePostByUri(const Config& config,
                                 const DataSourceInterface& data,
                                 mw::CryptoInterface& crypto,
                                 mw::HTTPSessionInterface& http,
                                 const SystemActor& system_actor,
                                 std::string_view post_uri);
mw::E<VerifiedSignature> verifyHttpSignature(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, const IncomingHttpRequest& req,
    int64_t now_seconds);
mw::E<VerifiedSignature> verifyHttpSignatureWithKeyRefresh(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, const IncomingHttpRequest& req,
    int64_t now_seconds);

mw::E<int64_t> enqueueDeliveryJob(const DataSourceInterface& data,
                                  std::string_view target_inbox,
                                  std::string_view signer_actor_uri,
                                  const nlohmann::json& activity,
                                  int64_t now_seconds);
mw::E<std::vector<std::string>> deliveryInboxesForRecipients(
    const Config& config, const DataSourceInterface& data,
    const std::vector<PostRecipient>& recipients);
mw::E<std::vector<int64_t>> enqueueOutboundDelivery(
    const Config& config, const DataSourceInterface& data,
    std::string_view signer_actor_uri, const nlohmann::json& activity,
    const std::vector<PostRecipient>& recipients, int64_t now_seconds);
mw::E<std::vector<int64_t>> enqueueActorUpdateDelivery(
    const Config& config, const DataSourceInterface& data, const User& user,
    std::string_view summary_html, int64_t now_seconds);
mw::E<std::vector<int64_t>> enqueueActorUpdateDelivery(
    const Config& config, const DataSourceInterface& data, const User& user,
    std::string_view summary_html, const std::optional<Attachment>& avatar,
    const std::optional<Attachment>& banner,
    const std::vector<RenderedProfileField>& fields, int64_t now_seconds);
mw::E<int64_t> enqueueFetchThreadJob(const DataSourceInterface& data,
                                     std::string_view root_uri,
                                     int64_t now_seconds);
mw::E<InboxDispatchResult> dispatchIncomingActivity(
    const Config& config, const DataSourceInterface& data,
    std::string_view verified_actor_uri, const Activity& activity,
    int64_t now_seconds, mw::CryptoInterface* crypto = nullptr,
    mw::HTTPSessionInterface* http = nullptr,
    const SystemActor* system_actor = nullptr);

// Claims and processes at most one runnable federation job. Returns true
// when a job was claimed, false when the queue was empty.
mw::E<bool> runFederationJobOnce(const Config& config,
                                 const DataSourceInterface& data,
                                 mw::CryptoInterface& crypto,
                                 mw::HTTPSessionInterface& http,
                                 int64_t now_seconds);

} // namespace unspoken
