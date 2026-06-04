#include <string>
#include <chrono>
#include <ctime>
#include <format>
#include <span>
#include <vector>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <mw/crypto.hpp>
#include <mw/http_client.hpp>
#include <mw/test_utils.hpp>

#include "data.hpp"
#include "federation.hpp"
#include "structs.hpp"

using namespace unspoken;

namespace
{

Config testConfig()
{
    Config c;
    c.url_root = "https://f.test/";
    c.public_domain = "example.test";
    return c;
}

User testUser()
{
    User u;
    u.id = 1;
    u.username = "alice";
    u.display_name = "Alice";
    u.public_key_pem = "PUB";
    return u;
}

std::string httpDateFor(int64_t unix_seconds)
{
    std::time_t t = static_cast<std::time_t>(unix_seconds);
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

std::string sha256DigestHeader(std::string_view body)
{
    mw::SHA256Hasher hasher;
    auto digest = hasher.hashToBytes(std::string(body));
    if(!digest.has_value()) return "";
    return "SHA-256=" + mw::base64Encode(
        std::span<unsigned char>(digest->data(), digest->size()), false, true);
}

IncomingHttpRequest signedIncomingRequest(
    mw::CryptoInterface& crypto, std::string_view private_key,
    std::string_view key_id, std::string_view algorithm,
    std::string_view method, std::string_view target,
    std::string_view body, int64_t now, bool include_digest,
    bool sign_digest, std::string_view signed_headers_override = "")
{
    IncomingHttpRequest req;
    req.method = std::string(method);
    req.target = std::string(target);
    req.body = std::string(body);
    req.headers["Host"] = "f.test";
    req.headers["Date"] = httpDateFor(now);
    std::string signed_headers = sign_digest
        ? "(request-target) host date digest"
        : "(request-target) host date";
    if(!signed_headers_override.empty())
        signed_headers = std::string(signed_headers_override);
    if(include_digest)
    {
        req.headers["Digest"] = sha256DigestHeader(body);
    }

    std::vector<std::string> lines;
    if(signed_headers.find("(request-target)") != std::string::npos)
    {
        lines.push_back(std::format(
            "(request-target): {} {}", std::string(method),
            std::string(target)));
    }
    if(signed_headers.find("host") != std::string::npos)
        lines.push_back("host: " + req.headers["Host"]);
    if(signed_headers.find("date") != std::string::npos)
        lines.push_back("date: " + req.headers["Date"]);
    if(sign_digest)
    {
        lines.push_back("digest: " + req.headers["Digest"]);
    }
    std::string input;
    for(size_t i = 0; i < lines.size(); ++i)
    {
        if(i > 0) input.push_back('\n');
        input += lines[i];
    }
    auto sig = crypto.sign(mw::SignatureAlgorithm::RSA_V1_5_SHA256,
                           std::string(private_key), input);
    if(sig.has_value())
    {
        std::string sig64 = mw::base64Encode(
            std::span<unsigned char>(sig->data(), sig->size()), false, true);
        req.headers["Signature"] = std::format(
            R"(keyId="{}",algorithm="{}",headers="{}",signature="{}")",
            key_id, algorithm, signed_headers, sig64);
    }
    return req;
}

class FakeSession : public mw::HTTPSessionInterface
{
public:
    mw::HTTPRequest last_request;
    mw::HTTPResponse response{200, "{}"};
    bool follow = true;
    long redirections = 0;
    std::string protocols;
    std::string redirect_protocols;
    mw::AddressPredicate filter;

    mw::E<const mw::HTTPResponse*> get(const mw::HTTPRequest& req) override
    {
        last_request = req;
        return &response;
    }
    mw::E<const mw::HTTPResponse*> post(const mw::HTTPRequest&) override
    {
        return std::unexpected(mw::runtimeError("unexpected post"));
    }
    mw::E<mw::HTTPResponse> getStream(const mw::HTTPRequest&,
                                      mw::ChunkCallback) override
    {
        return response;
    }
    mw::E<mw::HTTPResponse> postStream(const mw::HTTPRequest&,
                                       mw::ChunkCallback) override
    {
        return response;
    }
    std::chrono::duration<long> transferTimeout() const override
    {
        return std::chrono::seconds(0);
    }
    mw::E<void> transferTimeout(std::chrono::duration<long>) override
    {
        return {};
    }
    std::chrono::duration<long> connectionTimeout() const override
    {
        return std::chrono::seconds(60);
    }
    mw::E<void> connectionTimeout(std::chrono::duration<long>) override
    {
        return {};
    }
    long maxSize() const override { return 0; }
    mw::E<void> maxSize(long) override { return {}; }
    long maxRedirections() const override { return redirections; }
    mw::E<void> maxRedirections(long n) override
    {
        redirections = n;
        return {};
    }
    bool followRedirects() const override { return follow; }
    void followRedirects(bool f) override { follow = f; }
    const mw::AddressPredicate& addressFilter() const override
    {
        return filter;
    }
    void addressFilter(mw::AddressPredicate pred) override
    {
        filter = std::move(pred);
    }
    mw::E<void> allowedProtocols(std::string_view p) override
    {
        protocols = p;
        return {};
    }
    mw::E<void> allowedRedirectProtocols(std::string_view p) override
    {
        redirect_protocols = p;
        return {};
    }
};

} // namespace

TEST(JsonLd, NormalizeAddressingStringArrayAndObjectRefs)
{
    nlohmann::json single = "https://remote.test/u/bob";
    EXPECT_EQ(normalizeAddressing(single),
              std::vector<std::string>({"https://remote.test/u/bob"}));

    nlohmann::json arr = nlohmann::json::array({
        "Public",
        {{"id", "https://remote.test/u/carol"}},
        42,
    });
    EXPECT_EQ(normalizeAddressing(arr),
              std::vector<std::string>(
                  {"Public", "https://remote.test/u/carol"}));
}

TEST(JsonLd, NormalizeRefStringOrObject)
{
    EXPECT_EQ(normalizeRef("https://x.test/a").value(), "https://x.test/a");
    EXPECT_EQ(normalizeRef({{"id", "https://x.test/o"}}).value(),
              "https://x.test/o");
    EXPECT_FALSE(normalizeRef({{"type", "Note"}}).has_value());
}

TEST(JsonLd, PublicAddressAcceptsAllInputForms)
{
    EXPECT_TRUE(isPublicAddress(std::string(AS_PUBLIC)));
    EXPECT_TRUE(isPublicAddress("as:Public"));
    EXPECT_TRUE(isPublicAddress("Public"));
    EXPECT_FALSE(isPublicAddress("https://remote.test/Public"));
}

TEST(JsonLd, ParseActivityNormalizesFields)
{
    nlohmann::json raw = {
        {"id", "https://remote.test/a/1"},
        {"type", "Create"},
        {"actor", {{"id", "https://remote.test/u/bob"}}},
        {"object", {{"id", "https://remote.test/o/1"}}},
        {"to", "Public"},
        {"cc", nlohmann::json::array({"https://f.test/u/alice"})},
    };
    ASSIGN_OR_FAIL(Activity a, parseActivity(raw));
    EXPECT_EQ(a.id, "https://remote.test/a/1");
    EXPECT_EQ(a.type, "Create");
    EXPECT_EQ(a.actor, "https://remote.test/u/bob");
    EXPECT_EQ(a.to, std::vector<std::string>({"Public"}));
    EXPECT_EQ(a.cc, std::vector<std::string>({"https://f.test/u/alice"}));
}

TEST(JsonLd, ParseActivityRejectsImpossibleInput)
{
    nlohmann::json raw = {
        {"type", "Create"},
        {"actor", "https://remote.test/u/bob"},
    };
    EXPECT_FALSE(parseActivity(raw).has_value());
}

TEST(ActivityStreams, ActorJsonShape)
{
    auto j = actorJson(testConfig(), testUser(), "<p>bio</p>");
    EXPECT_EQ(j["type"], "Person");
    EXPECT_EQ(j["id"], "https://f.test/u/alice");
    EXPECT_EQ(j["preferredUsername"], "alice");
    EXPECT_EQ(j["summary"], "<p>bio</p>");
    EXPECT_EQ(j["endpoints"]["sharedInbox"], "https://f.test/inbox");
    EXPECT_EQ(j["publicKey"]["id"], "https://f.test/u/alice#main-key");
    EXPECT_EQ(j["publicKey"]["publicKeyPem"], "PUB");
}

TEST(ActivityStreams, NoteJsonUsesFullPublicIriOnOutput)
{
    Post p;
    p.id = 7;
    p.uri = "https://f.test/p/7";
    p.local_author_id = 1;
    p.content_html = "<p>hello</p>";
    p.created_at = 100;

    std::vector<PostRecipient> recipients = {
        {7, std::string(AS_PUBLIC), "to"},
        {7, "https://f.test/u/alice/followers", "cc"},
    };
    auto j = noteJson(testConfig(), p, testUser(), recipients, {});
    EXPECT_EQ(j["type"], "Note");
    EXPECT_EQ(j["attributedTo"], "https://f.test/u/alice");
    EXPECT_EQ(j["to"][0], std::string(AS_PUBLIC));
    EXPECT_EQ(j["cc"][0], "https://f.test/u/alice/followers");
    EXPECT_EQ(j["published"], "1970-01-01T00:01:40Z");
}

TEST(Discovery, WebFingerCanonicalSubject)
{
    auto j = webFingerJson(testConfig(), testUser());
    EXPECT_EQ(j["subject"], "acct:alice@example.test");
    EXPECT_EQ(j["links"][0]["rel"], "self");
    EXPECT_EQ(j["links"][0]["href"], "https://f.test/u/alice");
}

TEST(Discovery, NodeInfoDiscoveryPointsToUrlRoot)
{
    auto j = nodeInfoDiscoveryJson(testConfig());
    EXPECT_EQ(j["links"][0]["href"], "https://f.test/nodeinfo/2.1");
}

TEST(SSRF, BlocksPrivateAndAllowsPublicAddresses)
{
    EXPECT_FALSE(isAllowedOutboundAddress({
        mw::AddressFamily::IPV4, {127, 0, 0, 1}, 443}));
    EXPECT_FALSE(isAllowedOutboundAddress({
        mw::AddressFamily::IPV4, {10, 0, 0, 1}, 443}));
    EXPECT_FALSE(isAllowedOutboundAddress({
        mw::AddressFamily::IPV4, {169, 254, 169, 254}, 443}));
    EXPECT_FALSE(isAllowedOutboundAddress({
        mw::AddressFamily::IPV6,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 443}));
    EXPECT_FALSE(isAllowedOutboundAddress({
        mw::AddressFamily::IPV6,
        {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 443}));

    EXPECT_TRUE(isAllowedOutboundAddress({
        mw::AddressFamily::IPV4, {93, 184, 216, 34}, 443}));
    EXPECT_TRUE(isAllowedOutboundAddress({
        mw::AddressFamily::IPV6,
        {0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88,
         0x88}, 443}));
}

TEST(SSRF, HardensOutboundSession)
{
    FakeSession http;
    EXPECT_TRUE(mw::isExpected(hardenOutboundSession(http)));
    EXPECT_EQ(http.protocols, "https");
    EXPECT_EQ(http.redirect_protocols, "https");
    EXPECT_EQ(http.redirections, 5);
    ASSERT_TRUE(http.filter);
    EXPECT_FALSE(http.filter({mw::AddressFamily::IPV4, {127, 0, 0, 1}, 443}));
}

TEST(RemoteActor, SignedGetRequestHasCavageSignatureHeaders)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    SystemActor system;
    system.private_key_pem = keys.private_key;
    system.public_key_pem = keys.public_key;

    ASSIGN_OR_FAIL(auto req, signedGetRequest(
        testConfig(), system, crypto, "https://remote.test/u/bob?x=1"));
    EXPECT_EQ(req.url, "https://remote.test/u/bob?x=1");
    EXPECT_EQ(req.header["Accept"], "application/activity+json");
    EXPECT_EQ(req.header["Host"], "remote.test");
    EXPECT_NE(req.header["Date"].find("GMT"), std::string::npos);
    EXPECT_NE(req.header["Signature"].find(
                  R"(keyId="https://f.test/actor#main-key")"),
              std::string::npos);
    EXPECT_NE(req.header["Signature"].find(
                  R"(headers="(request-target) host date")"),
              std::string::npos);
}

TEST(RemoteActor, SignedGetRequestIncludesExplicitNonDefaultPortInHost)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    SystemActor system;
    system.private_key_pem = keys.private_key;
    system.public_key_pem = keys.public_key;

    ASSIGN_OR_FAIL(auto req, signedGetRequest(
        testConfig(), system, crypto, "https://remote.test:8443/u/bob"));
    EXPECT_EQ(req.header["Host"], "remote.test:8443");
}

TEST(RemoteActor, ResolveFetchesSignsAndCachesActor)
{
    Config c = testConfig();
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    SystemActor system;
    system.private_key_pem = keys.private_key;
    system.public_key_pem = keys.public_key;

    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    FakeSession http;
    http.response = mw::HTTPResponse(200, R"({
        "id": "https://remote.test/u/bob",
        "type": "Person",
        "preferredUsername": "bob",
        "name": "Bob",
        "inbox": "https://remote.test/u/bob/inbox",
        "endpoints": {"sharedInbox": "https://remote.test/inbox"},
        "publicKey": {
          "id": "https://remote.test/u/bob#main-key",
          "owner": "https://remote.test/u/bob",
          "publicKeyPem": "PUB"
        }
    })");

    ASSIGN_OR_FAIL(auto actor, resolveRemoteActor(
        c, *db, crypto, http, system, "https://remote.test/u/bob"));
    EXPECT_EQ(actor.uri, "https://remote.test/u/bob");
    EXPECT_EQ(actor.username, "bob");
    EXPECT_EQ(actor.domain, "remote.test");
    ASSERT_TRUE(actor.shared_inbox.has_value());
    EXPECT_EQ(*actor.shared_inbox, "https://remote.test/inbox");
    EXPECT_NE(http.last_request.header["Signature"].find("rsa-sha256"),
              std::string::npos);

    ASSIGN_OR_FAIL(auto cached, db->getRemoteActorByUri(actor.uri));
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached->public_key_id, "https://remote.test/u/bob#main-key");
}

TEST(HttpSignature, VerifiesGoodRsaSha256Signature)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    RemoteActor actor;
    actor.uri = "https://remote.test/u/bob";
    actor.username = "bob";
    actor.domain = "remote.test";
    actor.inbox = "https://remote.test/u/bob/inbox";
    actor.public_key_id = actor.uri + "#main-key";
    actor.public_key_pem = keys.public_key;
    actor.actor_json = "{}";
    ASSIGN_OR_FAIL(actor, db->upsertRemoteActor(actor));

    int64_t now = 100000;
    auto req = signedIncomingRequest(
        crypto, keys.private_key, actor.public_key_id, "rsa-sha256",
        "get", "/p/1", "", now, false, false);
    ASSIGN_OR_FAIL(auto verified, verifyHttpSignature(
        testConfig(), *db, crypto, req, now));
    EXPECT_EQ(verified.actor_uri, actor.uri);
    EXPECT_EQ(verified.key_id, actor.public_key_id);
}

TEST(HttpSignature, AcceptsHs2019LabelForRsaSignature)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    RemoteActor actor;
    actor.uri = "https://remote.test/u/bob";
    actor.username = "bob";
    actor.domain = "remote.test";
    actor.inbox = "https://remote.test/u/bob/inbox";
    actor.public_key_id = actor.uri + "#main-key";
    actor.public_key_pem = keys.public_key;
    actor.actor_json = "{}";
    ASSIGN_OR_FAIL(actor, db->upsertRemoteActor(actor));

    int64_t now = 100000;
    auto req = signedIncomingRequest(
        crypto, keys.private_key, actor.public_key_id, "hs2019",
        "get", "/p/1", "", now, false, false);
    EXPECT_TRUE(verifyHttpSignature(testConfig(), *db, crypto, req, now)
                    .has_value());
}

TEST(HttpSignature, RejectsPostWhenDigestIsNotSigned)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    RemoteActor actor;
    actor.uri = "https://remote.test/u/bob";
    actor.username = "bob";
    actor.domain = "remote.test";
    actor.inbox = "https://remote.test/u/bob/inbox";
    actor.public_key_id = actor.uri + "#main-key";
    actor.public_key_pem = keys.public_key;
    actor.actor_json = "{}";
    ASSIGN_OR_FAIL(actor, db->upsertRemoteActor(actor));

    int64_t now = 100000;
    auto req = signedIncomingRequest(
        crypto, keys.private_key, actor.public_key_id, "rsa-sha256",
        "post", "/inbox", "{}", now, true, false);
    EXPECT_FALSE(verifyHttpSignature(testConfig(), *db, crypto, req, now)
                     .has_value());
}

TEST(HttpSignature, RejectsSignatureWithoutRequestTarget)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    RemoteActor actor;
    actor.uri = "https://remote.test/u/bob";
    actor.username = "bob";
    actor.domain = "remote.test";
    actor.inbox = "https://remote.test/u/bob/inbox";
    actor.public_key_id = actor.uri + "#main-key";
    actor.public_key_pem = keys.public_key;
    actor.actor_json = "{}";
    ASSIGN_OR_FAIL(actor, db->upsertRemoteActor(actor));

    int64_t now = 100000;
    auto req = signedIncomingRequest(
        crypto, keys.private_key, actor.public_key_id, "rsa-sha256",
        "get", "/p/1", "", now, false, false, "date");
    EXPECT_FALSE(verifyHttpSignature(testConfig(), *db, crypto, req, now)
                     .has_value());
}

TEST(HttpSignature, RejectsBadDigest)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    RemoteActor actor;
    actor.uri = "https://remote.test/u/bob";
    actor.username = "bob";
    actor.domain = "remote.test";
    actor.inbox = "https://remote.test/u/bob/inbox";
    actor.public_key_id = actor.uri + "#main-key";
    actor.public_key_pem = keys.public_key;
    actor.actor_json = "{}";
    ASSIGN_OR_FAIL(actor, db->upsertRemoteActor(actor));

    int64_t now = 100000;
    auto req = signedIncomingRequest(
        crypto, keys.private_key, actor.public_key_id, "rsa-sha256",
        "post", "/inbox", "{}", now, true, true);
    req.body = R"({"tampered":true})";
    EXPECT_FALSE(verifyHttpSignature(testConfig(), *db, crypto, req, now)
                     .has_value());
}

TEST(HttpSignature, RejectsDateOutsideSkew)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    RemoteActor actor;
    actor.uri = "https://remote.test/u/bob";
    actor.username = "bob";
    actor.domain = "remote.test";
    actor.inbox = "https://remote.test/u/bob/inbox";
    actor.public_key_id = actor.uri + "#main-key";
    actor.public_key_pem = keys.public_key;
    actor.actor_json = "{}";
    ASSIGN_OR_FAIL(actor, db->upsertRemoteActor(actor));

    Config c = testConfig();
    c.http_signature_skew_seconds = 300;
    int64_t now = 100000;
    auto req = signedIncomingRequest(
        crypto, keys.private_key, actor.public_key_id, "rsa-sha256",
        "get", "/p/1", "", now - 1000, false, false);
    EXPECT_FALSE(verifyHttpSignature(c, *db, crypto, req, now).has_value());
}

TEST(HttpSigning, SignedPostRoundTripsThroughVerifier)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    RemoteActor actor;
    actor.uri = "https://remote.test/u/bob";
    actor.username = "bob";
    actor.domain = "remote.test";
    actor.inbox = "https://remote.test/u/bob/inbox";
    actor.public_key_id = actor.uri + "#main-key";
    actor.public_key_pem = keys.public_key;
    actor.actor_json = "{}";
    ASSIGN_OR_FAIL(actor, db->upsertRemoteActor(actor));

    SigningActor signer{
        actor.uri,
        actor.public_key_id,
        keys.private_key,
    };
    ASSIGN_OR_FAIL(auto out, signedHttpRequest(
        crypto, signer, "POST", "https://f.test/inbox", R"({"type":"Like"})",
        "application/activity+json"));

    IncomingHttpRequest in;
    in.method = "POST";
    in.target = "/inbox";
    in.body = out.request_data;
    in.headers = out.header;
    ASSIGN_OR_FAIL(auto verified, verifyHttpSignature(
        testConfig(), *db, crypto, in, mw::timeToSeconds(mw::Clock::now())));
    EXPECT_EQ(verified.actor_uri, actor.uri);
    EXPECT_TRUE(out.header.contains("Digest"));
    EXPECT_NE(out.header["Signature"].find("digest"), std::string::npos);
}

TEST(HttpSigning, UserAndSystemSignersUseDistinctKeyIds)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto user_keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto system_keys, crypto.generateKeyPair(mw::KeyType::RSA));

    User user = testUser();
    user.private_key_pem = user_keys.private_key;
    user.public_key_pem = user_keys.public_key;
    SystemActor system;
    system.private_key_pem = system_keys.private_key;
    system.public_key_pem = system_keys.public_key;

    auto user_actor = signingActorFor(testConfig(), user);
    auto system_actor = signingActorForSystem(testConfig(), system);
    EXPECT_EQ(user_actor.key_id, "https://f.test/u/alice#main-key");
    EXPECT_EQ(system_actor.key_id, "https://f.test/actor#main-key");
    EXPECT_NE(user_actor.key_id, system_actor.key_id);
}
