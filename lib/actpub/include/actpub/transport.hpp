#pragma once

#include "types.hpp"

#include <mw/crypto.hpp>
#include <mw/error.hpp>
#include <mw/http_client.hpp>

namespace ap
{

// Explicit development exceptions for private test-network peers.
struct DevConfig
{
    bool allow_http_url_root = false;
    std::vector<std::string> outbound_allow_private_hosts;
};

// Transport policy independent of application configuration and URL layout.
struct TransportConfig
{
    DevConfig dev;
    int http_signature_skew_seconds = 300;
};

// Parsed signature material; verification must succeed before trusting it.
struct SignatureEnvelope
{
    std::string key_id;
    std::string actor_uri;
    std::vector<std::string> signed_headers;
    std::vector<unsigned char> signature;
    std::string signing_input;
};

// Normalize the supported ActivityStreams reference and addressing shapes.
std::optional<std::string> normalizeRef(const nlohmann::json& field);
// Normalize addressing without fetching remote contexts.
std::vector<std::string> normalizeAddressing(const nlohmann::json& field);
// Parse an activity envelope; its content remains untrusted for rendering.
mw::E<Activity> parseActivity(const nlohmann::json& raw);
// Recognize supported spellings of the public audience.
bool isPublicAddress(std::string_view uri);
// Recognize requests for an ActivityPub representation.
bool wantsActivityJson(std::string_view accept);
// Reject private, local, metadata, and unsupported outbound addresses.
bool isAllowedOutboundAddress(const mw::SockAddr& addr);
// Validate a remote URL against production/development scheme policy.
bool isValidRemoteUrl(const DevConfig& dev, std::string_view value);
// Set production outbound protocol and DNS-address restrictions.
mw::E<void> hardenOutboundSession(mw::HTTPSessionInterface& http);
// Apply outbound restrictions including explicit test-network exceptions.
mw::E<void> hardenOutboundSession(const TransportConfig& config,
                                  mw::HTTPSessionInterface& http,
                                  std::string_view target_url);
// Sign the exact request body and target using the supplied actor's key.
mw::E<mw::HTTPRequest>
signedHttpRequest(const TransportConfig& config, mw::CryptoInterface& crypto,
                  const SigningActor& actor, std::string_view method,
                  std::string_view uri, std::string_view body = "",
                  std::string_view content_type = "");
// Fetch and validate a remote actor without retaining it in a database.
mw::E<RemoteActor> fetchRemoteActor(const TransportConfig& config,
                                    mw::CryptoInterface& crypto,
                                    mw::HTTPSessionInterface& http,
                                    const SigningActor& signer,
                                    std::string_view actor_uri);
// Validate signed headers, digest, target, date, and supported algorithm.
mw::E<SignatureEnvelope> parseHttpSignature(const TransportConfig& config,
                                            const IncomingHttpRequest& req,
                                            int64_t now_seconds);
// Verify parsed material against the exact actor and key identifier.
mw::E<bool> verifyParsedHttpSignature(mw::CryptoInterface& crypto,
                                      const SignatureEnvelope& signature,
                                      const RemoteActor& actor);

// Resolve a handle's ActivityPub self link without retaining an identity.
mw::E<std::string> discoverActorUri(const TransportConfig& config,
                                    mw::HTTPSessionInterface& http,
                                    std::string_view handle);
// Build a WebFinger request using the same outbound scheme policy.
mw::E<mw::HTTPRequest> webFingerRequest(const TransportConfig& config,
                                        std::string_view uri);

// Read a response with a hard streaming body limit; harden the session first.
mw::E<mw::HTTPResponse> getBounded(mw::HTTPSessionInterface& http,
                                   const mw::HTTPRequest& request,
                                   size_t max_bytes);
// Deliver while bounding/discarding the response body; harden first.
mw::E<mw::HTTPResponse> postBounded(mw::HTTPSessionInterface& http,
                                    const mw::HTTPRequest& request,
                                    size_t max_bytes);

} // namespace ap
