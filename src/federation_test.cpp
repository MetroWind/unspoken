#include <string>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
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

NewUser testNewUser(const std::string& username)
{
    NewUser nu;
    nu.username = username;
    nu.display_name = username;
    nu.oidc_iss = "https://issuer.test";
    nu.oidc_sub = username + "-sub";
    nu.private_key_pem = "PRIV";
    nu.public_key_pem = "PUB";
    return nu;
}

RemoteActor testRemoteActor(const std::string& uri)
{
    RemoteActor actor;
    actor.uri = uri;
    actor.username = "remote";
    actor.domain = "remote.test";
    actor.inbox = "https://remote.test/inbox";
    actor.shared_inbox = "https://remote.test/inbox";
    actor.public_key_pem = "PUB";
    actor.public_key_id = uri + "#main-key";
    actor.actor_json = "{}";
    return actor;
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
    bool sign_digest, std::string_view signed_headers_override = "",
    std::string_view digest_override = "")
{
    IncomingHttpRequest req;
    req.method = std::string(method);
    req.target = std::string(target);
    req.body = std::string(body);
    req.headers["Host"] = "f.test";
    req.headers["Date"] = httpDateFor(now);
    req.headers["Content-Type"] = "application/activity+json";
    std::string signed_headers = sign_digest
        ? "(request-target) host date digest"
        : "(request-target) host date";
    if(!signed_headers_override.empty())
        signed_headers = std::string(signed_headers_override);
    if(include_digest)
    {
        req.headers["Digest"] = digest_override.empty()
            ? sha256DigestHeader(body) : std::string(digest_override);
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
    if(signed_headers.find("content-type") != std::string::npos)
        lines.push_back("content-type: " + req.headers["Content-Type"]);
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
    std::vector<mw::HTTPResponse> responses;
    std::vector<std::string> get_urls;
    std::vector<mw::HTTPRequest> get_requests;
    size_t get_count = 0;
    bool post_called = false;
    size_t post_count = 0;
    bool follow = true;
    long redirections = 0;
    std::string protocols;
    std::string redirect_protocols;
    mw::AddressPredicate filter;

    mw::E<const mw::HTTPResponse*> get(const mw::HTTPRequest& req) override
    {
        last_request = req;
        get_requests.push_back(req);
        get_urls.push_back(req.url);
        if(get_count < responses.size())
        {
            response = responses[get_count++];
            return &response;
        }
        ++get_count;
        return &response;
    }
    mw::E<const mw::HTTPResponse*> post(const mw::HTTPRequest& req) override
    {
        post_called = true;
        ++post_count;
        last_request = req;
        return &response;
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
    auto parsed = parseActivity(raw);
    ASSERT_FALSE(parsed.has_value());
    const auto* error = parsed.error().as<mw::HTTPError>();
    ASSERT_NE(error, nullptr);
    EXPECT_EQ(error->code, 400);
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

TEST(ActivityStreams, ActorJsonIncludesRichProfileFields)
{
    Attachment avatar;
    avatar.sha256 = "abc001";
    avatar.extension = "png";
    avatar.media_type = "image/png";
    avatar.original_name = "avatar.png";
    avatar.is_image = true;
    Attachment banner;
    banner.sha256 = "def002";
    banner.extension = "jpg";
    banner.media_type = "image/jpeg";
    banner.original_name = "banner.jpg";
    banner.is_image = true;
    std::vector<RenderedProfileField> fields = {
        {"Blog", "<p><a href=\"https://example.test\">site</a></p>"},
        {"Matrix", "<p>@alice:example.test</p>"},
    };

    auto j = actorJson(testConfig(), testUser(), "<p>bio</p>", avatar,
                       banner, fields);
    EXPECT_EQ(j["icon"]["type"], "Image");
    EXPECT_EQ(j["icon"]["mediaType"], "image/png");
    EXPECT_EQ(j["icon"]["url"], "https://f.test/media/a/abc001.png");
    EXPECT_EQ(j["image"]["url"], "https://f.test/media/d/def002.jpg");
    ASSERT_EQ(j["attachment"].size(), 2u);
    EXPECT_EQ(j["attachment"][0]["type"], "PropertyValue");
    EXPECT_EQ(j["attachment"][0]["name"], "Blog");
    EXPECT_EQ(j["attachment"][0]["value"],
              "<p><a href=\"https://example.test\">site</a></p>");
    EXPECT_EQ(j["attachment"][1]["name"], "Matrix");
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

TEST(ActivityStreams, NoteJsonCarriesMentionAndHashtagTags)
{
    Post p;
    p.id = 7;
    p.uri = "https://f.test/p/7";
    p.local_author_id = 1;
    p.content_html = "<p>hello</p>";
    p.content_source = "hello @bob @mallory@remote.test #Cpp";
    p.created_at = 100;

    std::vector<PostRecipient> recipients = {
        {7, std::string(AS_PUBLIC), "to"},
        {7, "https://f.test/u/bob", "to"},
    };
    auto j = noteJson(testConfig(), p, testUser(), recipients, {});

    ASSERT_TRUE(j.contains("tag"));
    ASSERT_EQ(j["tag"].size(), 2u);
    EXPECT_EQ(j["tag"][0]["type"], "Mention");
    EXPECT_EQ(j["tag"][0]["href"], "https://f.test/u/bob");
    EXPECT_EQ(j["tag"][0]["name"], "@bob");
    EXPECT_EQ(j["tag"][1]["type"], "Hashtag");
    EXPECT_EQ(j["tag"][1]["href"], "https://f.test/tags/cpp");
    EXPECT_EQ(j["tag"][1]["name"], "#Cpp");
}

TEST(ActivityStreams, NoteJsonCarriesResolvedRemoteMentionTags)
{
    Post p;
    p.id = 7;
    p.uri = "https://f.test/p/7";
    p.local_author_id = 1;
    p.content_html = "<p>hello</p>";
    p.content_source = "hello @mallory@remote.test";
    p.created_at = 100;

    std::vector<PostRecipient> recipients = {
        {7, std::string(AS_PUBLIC), "to"},
        {7, "https://remote.test/users/mallory", "to"},
    };
    auto j = noteJson(testConfig(), p, testUser(), recipients, {});

    ASSERT_TRUE(j.contains("tag"));
    ASSERT_EQ(j["tag"].size(), 1u);
    EXPECT_EQ(j["tag"][0]["type"], "Mention");
    EXPECT_EQ(j["tag"][0]["href"], "https://remote.test/users/mallory");
    EXPECT_EQ(j["tag"][0]["name"], "@mallory@remote.test");
}

TEST(ActivityStreams, NoteJsonCarriesAliasedRemoteMentionTag)
{
    Post p;
    p.id = 7;
    p.uri = "https://f.test/p/7";
    p.local_author_id = 1;
    p.content_html = "<p>hello</p>";
    p.content_source = "hello @mw@f.darksair.org";
    p.created_at = 100;

    std::vector<PostRecipient> recipients = {
        {7, std::string(AS_PUBLIC), "to"},
        {7, "https://pleroma.xeno.darksair.org/users/mw", "to"},
    };
    auto j = noteJson(testConfig(), p, testUser(), recipients, {});

    ASSERT_TRUE(j.contains("tag"));
    ASSERT_EQ(j["tag"].size(), 1u);
    EXPECT_EQ(j["tag"][0]["type"], "Mention");
    EXPECT_EQ(j["tag"][0]["href"],
              "https://pleroma.xeno.darksair.org/users/mw");
    EXPECT_EQ(j["tag"][0]["name"], "@mw@f.darksair.org");
}

TEST(ActivityStreams, NoteJsonSkipsAmbiguousAliasedMentionTag)
{
    Post p;
    p.id = 7;
    p.uri = "https://f.test/p/7";
    p.local_author_id = 1;
    p.content_html = "<p>hello</p>";
    p.content_source = "hello @mw@alias.test";
    p.created_at = 100;

    std::vector<PostRecipient> recipients = {
        {7, std::string(AS_PUBLIC), "to"},
        {7, "https://one.test/users/mw", "to"},
        {7, "https://two.test/users/mw", "to"},
    };
    auto j = noteJson(testConfig(), p, testUser(), recipients, {});

    EXPECT_FALSE(j.contains("tag"));
}

TEST(ActivityStreams, NoteJsonCarriesCustomEmojiTags)
{
    namespace fs = std::filesystem;
    fs::path dir = fs::temp_directory_path()
        / ("unspoken_fed_emoji_" + std::to_string(::getpid()));
    fs::create_directories(dir);
    { std::ofstream(dir / "blobcat.png") << "x"; }
    EmojiRegistry emoji = EmojiRegistry::scan(dir.string(),
                                              "https://f.test/");

    Post p;
    p.id = 7;
    p.uri = "https://f.test/p/7";
    p.local_author_id = 1;
    p.content_html = "<p>:blobcat:</p>";
    p.content_source = "hello :blobcat: :unknown:";
    p.created_at = 100;

    std::vector<PostRecipient> recipients = {
        {7, std::string(AS_PUBLIC), "to"},
    };
    auto j = noteJson(testConfig(), p, testUser(), recipients, {}, &emoji);

    ASSERT_TRUE(j.contains("tag"));
    ASSERT_EQ(j["tag"].size(), 1u);
    EXPECT_EQ(j["tag"][0]["type"], "Emoji");
    EXPECT_EQ(j["tag"][0]["name"], ":blobcat:");
    EXPECT_EQ(j["tag"][0]["icon"]["mediaType"], "image/png");
    EXPECT_EQ(j["tag"][0]["icon"]["url"],
              "https://f.test/emoji/blobcat.png");

    fs::remove_all(dir);
}

TEST(ActivityStreams, EmojiReactCarriesCustomEmojiTag)
{
    namespace fs = std::filesystem;
    fs::path dir = fs::temp_directory_path()
        / ("unspoken_react_emoji_" + std::to_string(::getpid()));
    fs::create_directories(dir);
    { std::ofstream(dir / "blobcat.png") << "x"; }
    EmojiRegistry emoji = EmojiRegistry::scan(dir.string(),
                                              "https://f.test/");

    std::vector<PostRecipient> recipients = {
        {0, "https://remote.test/u/bob", "to"},
    };
    auto j = emojiReactActivityJson(
        testConfig(), "https://f.test/a/react/1",
        "https://f.test/u/alice", "https://remote.test/o/1",
        ":blobcat:", recipients, emoji);

    EXPECT_EQ(j["type"], "EmojiReact");
    EXPECT_EQ(j["content"], ":blobcat:");
    EXPECT_EQ(j["to"][0], "https://remote.test/u/bob");
    ASSERT_TRUE(j.contains("tag"));
    EXPECT_EQ(j["tag"][0]["type"], "Emoji");
    EXPECT_EQ(j["tag"][0]["name"], ":blobcat:");
    EXPECT_EQ(j["tag"][0]["icon"]["url"],
              "https://f.test/emoji/blobcat.png");

    fs::remove_all(dir);
}

TEST(ActivityStreams, DeleteActivityCarriesOriginalAudience)
{
    std::vector<PostRecipient> recipients = {
        {7, std::string(AS_PUBLIC), "to"},
        {7, "https://f.test/u/alice/followers", "cc"},
    };
    auto j = deleteActivityJson(
        "https://f.test/a/delete/1", "https://f.test/u/alice",
        "https://f.test/p/7", recipients);
    EXPECT_EQ(j["type"], "Delete");
    EXPECT_EQ(j["actor"], "https://f.test/u/alice");
    EXPECT_EQ(j["object"], "https://f.test/p/7");
    EXPECT_EQ(j["to"][0], std::string(AS_PUBLIC));
    EXPECT_EQ(j["cc"][0], "https://f.test/u/alice/followers");
}

TEST(ActivityStreams, ActorUpdateWrapsActorDocument)
{
    User user = testUser();
    std::vector<PostRecipient> recipients = {
        {0, "https://f.test/u/alice/followers", "to"},
    };
    auto j = actorUpdateActivityJson(
        testConfig(), "https://f.test/a/update/1", user, "<p>bio</p>",
        recipients);
    EXPECT_EQ(j["type"], "Update");
    EXPECT_EQ(j["actor"], "https://f.test/u/alice");
    EXPECT_EQ(j["object"]["type"], "Person");
    EXPECT_EQ(j["object"]["summary"], "<p>bio</p>");
    EXPECT_EQ(j["to"][0], "https://f.test/u/alice/followers");
}

TEST(ActivityStreams, ActorUpdateWrapsRichActorDocument)
{
    User user = testUser();
    Attachment avatar;
    avatar.sha256 = "abc001";
    avatar.extension = "png";
    avatar.media_type = "image/png";
    avatar.original_name = "avatar.png";
    avatar.is_image = true;
    std::vector<RenderedProfileField> fields = {
        {"Blog", "<p>site</p>"},
    };
    std::vector<PostRecipient> recipients = {
        {0, "https://f.test/u/alice/followers", "to"},
    };
    auto j = actorUpdateActivityJson(
        testConfig(), "https://f.test/a/update/1", user, "<p>bio</p>",
        avatar, std::nullopt, fields, recipients);
    EXPECT_EQ(j["type"], "Update");
    EXPECT_EQ(j["object"]["icon"]["url"], "https://f.test/media/a/abc001.png");
    ASSERT_EQ(j["object"]["attachment"].size(), 1u);
    EXPECT_EQ(j["object"]["attachment"][0]["name"], "Blog");
}

TEST(Discovery, WebFingerCanonicalSubject)
{
    auto j = webFingerJson(testConfig(), testUser());
    EXPECT_EQ(j["subject"], "acct:alice@example.test");
    EXPECT_EQ(j["links"][0]["rel"], "self");
    EXPECT_EQ(j["links"][0]["href"], "https://f.test/u/alice");
}

TEST(Discovery, HostMetaPointsToWebFinger)
{
    auto xml = hostMetaXml(testConfig());
    EXPECT_NE(xml.find("rel=\"lrdd\""), std::string::npos);
    EXPECT_NE(xml.find("template=\"https://f.test/.well-known/webfinger?"
                       "resource={uri}\""),
              std::string::npos);
}

TEST(Discovery, NodeInfoDiscoveryPointsToUrlRoot)
{
    auto j = nodeInfoDiscoveryJson(testConfig());
    EXPECT_EQ(j["links"][0]["href"], "https://f.test/nodeinfo/2.1");
}

TEST(Discovery, NodeInfoReportsUsageCounts)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(testNewUser("alice")));

    NewPost local_np;
    local_np.local_author_id = alice.id;
    local_np.content_html = "local";
    local_np.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(auto local_post, db->insertPost(
        local_np, {}, "https://f.test/p/"));
    (void)local_post;

    NewPost remote_np;
    remote_np.uri = "https://remote.test/o/1";
    remote_np.content_html = "remote";
    remote_np.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(auto remote_post, db->insertPost(
        remote_np, {}, "https://f.test/p/"));
    (void)remote_post;

    ASSIGN_OR_FAIL(auto j, nodeInfoJson(testConfig(), *db));
    EXPECT_EQ(j["usage"]["users"]["total"], 1);
    EXPECT_EQ(j["usage"]["localPosts"], 1);
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

TEST(SSRF, DevAllowlistPermitsNamedPrivateHost)
{
    Config c = testConfig();
    c.dev.allow_http_url_root = true;
    c.dev.outbound_allow_private_hosts = {"akkoma.test"};

    FakeSession http;
    EXPECT_TRUE(mw::isExpected(hardenOutboundSession(
        c, http, "http://akkoma.test:4000/u/bob")));
    EXPECT_EQ(http.protocols, "http,https");
    EXPECT_EQ(http.redirect_protocols, "http,https");
    EXPECT_EQ(http.redirections, 0);
    ASSERT_TRUE(http.filter);
    EXPECT_TRUE(http.filter({
        mw::AddressFamily::IPV4, {172, 18, 0, 10}, 4000}));
    EXPECT_FALSE(http.filter({
        mw::AddressFamily::IPV4, {169, 254, 169, 254}, 80}));
}

TEST(SSRF, DevAllowlistIgnoredWhenHttpDevModeOff)
{
    Config c = testConfig();
    c.dev.outbound_allow_private_hosts = {"akkoma.test"};

    FakeSession http;
    EXPECT_TRUE(mw::isExpected(hardenOutboundSession(
        c, http, "https://akkoma.test/u/bob")));
    EXPECT_EQ(http.protocols, "https");
    ASSERT_TRUE(http.filter);
    EXPECT_FALSE(http.filter({
        mw::AddressFamily::IPV4, {172, 18, 0, 10}, 443}));
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

TEST(RemoteActor, RejectsPartialActorDocumentWithoutCaching)
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
        "publicKey": {
          "id": "https://remote.test/u/bob#main-key",
          "publicKeyPem": "PUB"
        }
    })");

    EXPECT_FALSE(resolveRemoteActor(
        c, *db, crypto, http, system, "https://remote.test/u/bob")
                     .has_value());
    ASSIGN_OR_FAIL(auto cached,
                   db->getRemoteActorByUri("https://remote.test/u/bob"));
    EXPECT_FALSE(cached.has_value());
}

TEST(RemoteActor, RejectsMismatchedActorIdWithoutCaching)
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
        "id": "https://remote.test/u/other",
        "type": "Person",
        "preferredUsername": "bob",
        "inbox": "https://remote.test/u/bob/inbox",
        "publicKey": {
          "id": "https://remote.test/u/bob#main-key",
          "owner": "https://remote.test/u/bob",
          "publicKeyPem": "PUB"
        }
    })");

    EXPECT_FALSE(resolveRemoteActor(
        c, *db, crypto, http, system, "https://remote.test/u/bob")
                     .has_value());
    ASSIGN_OR_FAIL(auto cached,
                   db->getRemoteActorByUri("https://remote.test/u/other"));
    EXPECT_FALSE(cached.has_value());
}

TEST(RemoteActor, WebFingerResolvesSelfLinkThenCachesActor)
{
    Config c = testConfig();
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    SystemActor system;
    system.private_key_pem = keys.private_key;
    system.public_key_pem = keys.public_key;

    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    FakeSession http;
    http.responses = {
        mw::HTTPResponse(200, nlohmann::json({
            {"subject", "acct:bob@canonical.remote.test"},
            {"links", nlohmann::json::array({
                {
                    {"rel", "self"},
                    {"type", "application/activity+json"},
                    {"href", "https://remote.test/u/bob"},
                },
            })},
        }).dump()),
        mw::HTTPResponse(200, nlohmann::json({
            {"id", "https://remote.test/u/bob"},
            {"type", "Person"},
            {"preferredUsername", "bob"},
            {"inbox", "https://remote.test/u/bob/inbox"},
            {"publicKey", {
                {"id", "https://remote.test/u/bob#main-key"},
                {"owner", "https://remote.test/u/bob"},
                {"publicKeyPem", "PUB"},
            }},
        }).dump()),
    };

    ASSIGN_OR_FAIL(auto actor, resolveWebFingerActor(
        c, *db, crypto, http, system, "@bob@remote.test"));
    EXPECT_EQ(actor.uri, "https://remote.test/u/bob");
    ASSERT_EQ(http.get_urls.size(), 2u);
    EXPECT_EQ(http.get_urls[0],
              "https://remote.test/.well-known/webfinger?resource="
              "acct%3Abob%40remote.test");
    EXPECT_EQ(http.get_urls[1], "https://remote.test/u/bob");
    ASSERT_EQ(http.get_requests.size(), 2u);
    EXPECT_EQ(http.get_requests[0].header["Accept"],
              "application/jrd+json, application/json");
    EXPECT_EQ(http.get_requests[1].header["Accept"],
              "application/activity+json");

    ASSIGN_OR_FAIL(auto cached, db->getRemoteActorByUri(actor.uri));
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached->username, "bob");
}

TEST(RemotePost, FetchByUriCachesAuthorAndStoresPost)
{
    Config c = testConfig();
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    SystemActor system;
    system.private_key_pem = keys.private_key;
    system.public_key_pem = keys.public_key;

    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    FakeSession http;
    http.responses = {
        mw::HTTPResponse(200, nlohmann::json({
            {"id", "https://remote.test/o/1"},
            {"type", "Note"},
            {"attributedTo", "https://remote.test/u/bob"},
            {"content", "<p>hello</p>"},
            {"to", std::string(AS_PUBLIC)},
        }).dump()),
        mw::HTTPResponse(200, nlohmann::json({
            {"id", "https://remote.test/u/bob"},
            {"type", "Person"},
            {"preferredUsername", "bob"},
            {"name", "Bob"},
            {"inbox", "https://remote.test/u/bob/inbox"},
            {"publicKey", {
                {"id", "https://remote.test/u/bob#main-key"},
                {"owner", "https://remote.test/u/bob"},
                {"publicKeyPem", "PUB"},
            }},
        }).dump()),
    };

    ASSIGN_OR_FAIL(auto post, fetchRemotePostByUri(
        c, *db, crypto, http, system, "https://remote.test/o/1"));
    EXPECT_EQ(post.uri, "https://remote.test/o/1");
    EXPECT_EQ(post.visibility, Visibility::PUBLIC);
    ASSERT_TRUE(post.remote_author_id.has_value());
    ASSERT_EQ(http.get_urls.size(), 2u);
    EXPECT_EQ(http.get_urls[0], "https://remote.test/o/1");
    EXPECT_EQ(http.get_urls[1], "https://remote.test/u/bob");

    ASSIGN_OR_FAIL(auto cached_author,
                   db->getRemoteActorByUri("https://remote.test/u/bob"));
    ASSERT_TRUE(cached_author.has_value());
    EXPECT_EQ(cached_author->username, "bob");

    ASSIGN_OR_FAIL(auto stored, db->getPostByUri("https://remote.test/o/1"));
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->remote_author_id, post.remote_author_id);

    ASSIGN_OR_FAIL(auto cached_post, fetchRemotePostByUri(
        c, *db, crypto, http, system, "https://remote.test/o/1"));
    EXPECT_EQ(cached_post.id, post.id);
    EXPECT_EQ(http.get_urls.size(), 2u);
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

TEST(HttpSignature, UsesForwardedHostForProxiedRequests)
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
        "post", "/inbox", "{}", now, true, true,
        "(request-target) host date digest content-type");
    req.headers["Content-Type"] = "application/activity+json";
    req.headers["Host"] = "127.0.0.1:41189";
    req.headers["X-Forwarded-Host"] = "f.test";

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

TEST(HttpSignature, AcceptsDigestCaseAndMultipleValues)
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
    std::string digest = sha256DigestHeader("{}");
    std::string digest_value = digest.substr(digest.find('=') + 1);
    auto lowercase_req = signedIncomingRequest(
        crypto, keys.private_key, actor.public_key_id, "rsa-sha256",
        "post", "/inbox", "{}", now, true, true, "",
        "sha-256=" + digest_value);
    EXPECT_TRUE(verifyHttpSignature(testConfig(), *db, crypto, lowercase_req,
                                    now).has_value());

    auto multiple_req = signedIncomingRequest(
        crypto, keys.private_key, actor.public_key_id, "rsa-sha256",
        "post", "/inbox", "{}", now, true, true, "",
        "SHA-512=bogus, sha-256= " + digest_value);
    EXPECT_TRUE(verifyHttpSignature(testConfig(), *db, crypto, multiple_req,
                                    now).has_value());
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
        testConfig(), crypto, signer, "POST", "https://f.test/inbox",
        R"({"type":"Like"})", "application/activity+json"));

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

TEST(HttpSignature, RefetchesActorAndRetriesAfterKeyRotation)
{
    Config c = testConfig();
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto old_keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto new_keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto system_keys,
                   crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());

    RemoteActor actor;
    actor.uri = "https://remote.test/u/bob";
    actor.username = "bob";
    actor.domain = "remote.test";
    actor.inbox = "https://remote.test/u/bob/inbox";
    actor.public_key_id = actor.uri + "#main-key";
    actor.public_key_pem = old_keys.public_key;
    actor.actor_json = "{}";
    ASSIGN_OR_FAIL(actor, db->upsertRemoteActor(actor));

    SystemActor system;
    system.private_key_pem = system_keys.private_key;
    system.public_key_pem = system_keys.public_key;
    FakeSession http;
    http.response = mw::HTTPResponse(200, nlohmann::json({
        {"id", actor.uri},
        {"type", "Person"},
        {"preferredUsername", "bob"},
        {"inbox", actor.inbox},
        {"publicKey", {
            {"id", actor.public_key_id},
            {"owner", actor.uri},
            {"publicKeyPem", new_keys.public_key},
        }},
    }).dump());

    int64_t now = 100000;
    auto req = signedIncomingRequest(
        crypto, new_keys.private_key, actor.public_key_id, "rsa-sha256",
        "get", "/p/1", "", now, false, false);

    EXPECT_FALSE(verifyHttpSignature(c, *db, crypto, req, now).has_value());
    ASSIGN_OR_FAIL(auto verified, verifyHttpSignatureWithKeyRefresh(
        c, *db, crypto, http, system, req, now));
    EXPECT_EQ(verified.actor_uri, actor.uri);
    EXPECT_EQ(http.last_request.url, actor.uri);

    ASSIGN_OR_FAIL(auto cached, db->getRemoteActorByUri(actor.uri));
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached->public_key_pem, new_keys.public_key);
}

TEST(FederationJobs, DeliveryJobSignsPostsAndCompletes)
{
    Config c = testConfig();
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());

    NewUser nu;
    nu.username = "alice";
    nu.display_name = "Alice";
    nu.oidc_iss = "https://issuer.test";
    nu.oidc_sub = "alice-sub";
    nu.private_key_pem = keys.private_key;
    nu.public_key_pem = keys.public_key;
    ASSIGN_OR_FAIL(auto user, db->createUser(nu));

    nlohmann::json activity = {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", "https://f.test/a/1"},
        {"type", "Like"},
        {"actor", "https://f.test/u/alice"},
        {"object", "https://remote.test/p/1"},
    };
    ASSIGN_OR_FAIL(auto jid, enqueueDeliveryJob(
        *db, "https://remote.test/inbox", "https://f.test/u/alice",
        activity, 100));
    EXPECT_GT(jid, 0);

    FakeSession http;
    ASSERT_TRUE(runFederationJobOnce(c, *db, crypto, http, 100).value());
    EXPECT_TRUE(http.post_called);
    EXPECT_EQ(http.last_request.url, "https://remote.test/inbox");
    EXPECT_EQ(http.last_request.header["Host"], "remote.test");
    EXPECT_EQ(http.last_request.header["Content-Type"],
              "application/activity+json");
    EXPECT_NE(http.last_request.header["Signature"].find(
                  R"(keyId="https://f.test/u/alice#main-key")"),
              std::string::npos);
    EXPECT_NE(http.last_request.header["Signature"].find("digest"),
              std::string::npos);

    ASSIGN_OR_FAIL(auto none, db->claimJob(100));
    EXPECT_FALSE(none.has_value());
    (void)user;
}

TEST(FederationJobs, FailedDeliveryIsRescheduledWithBackoff)
{
    Config c = testConfig();
    c.job_retry_base_delay_seconds = 10;
    c.job_max_retries = 2;
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());

    NewUser nu;
    nu.username = "alice";
    nu.display_name = "Alice";
    nu.oidc_iss = "https://issuer.test";
    nu.oidc_sub = "alice-sub";
    nu.private_key_pem = keys.private_key;
    nu.public_key_pem = keys.public_key;
    ASSIGN_OR_FAIL(auto user, db->createUser(nu));

    nlohmann::json activity = {
        {"id", "https://f.test/a/2"},
        {"type", "Follow"},
        {"actor", "https://f.test/u/alice"},
        {"object", "https://remote.test/u/bob"},
    };
    ASSIGN_OR_FAIL(auto jid, enqueueDeliveryJob(
        *db, "https://remote.test/inbox", "https://f.test/u/alice",
        activity, 100));
    EXPECT_GT(jid, 0);

    FakeSession http;
    http.response = mw::HTTPResponse(503, "try later");
    ASSERT_TRUE(runFederationJobOnce(c, *db, crypto, http, 100).value());

    ASSIGN_OR_FAIL(auto early, db->claimJob(119));
    EXPECT_FALSE(early.has_value());
    ASSIGN_OR_FAIL(auto retry, db->claimJob(120));
    ASSERT_TRUE(retry.has_value());
    EXPECT_EQ(retry->id, jid);
    EXPECT_EQ(retry->attempts, 1);
    (void)user;
}

TEST(FederationJobs, PeerDowntimeStopsAtRetryCap)
{
    Config c = testConfig();
    c.job_retry_base_delay_seconds = 10;
    c.job_max_retries = 2;
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());

    NewUser nu = testNewUser("alice");
    nu.private_key_pem = keys.private_key;
    nu.public_key_pem = keys.public_key;
    ASSIGN_OR_FAIL(auto user, db->createUser(nu));

    nlohmann::json activity = {
        {"id", "https://f.test/a/peer-down"},
        {"type", "Like"},
        {"actor", "https://f.test/u/alice"},
        {"object", "https://remote.test/p/1"},
    };
    ASSIGN_OR_FAIL(auto jid, enqueueDeliveryJob(
        *db, "https://remote.test/inbox", "https://f.test/u/alice",
        activity, 100));
    EXPECT_GT(jid, 0);

    FakeSession http;
    http.response = mw::HTTPResponse(503, "try later");
    ASSERT_TRUE(runFederationJobOnce(c, *db, crypto, http, 100).value());
    ASSIGN_OR_FAIL(auto early, db->claimJob(119));
    EXPECT_FALSE(early.has_value());

    ASSERT_TRUE(runFederationJobOnce(c, *db, crypto, http, 120).value());
    ASSIGN_OR_FAIL(auto no_more, db->claimJob(1000000));
    EXPECT_FALSE(no_more.has_value());
    EXPECT_EQ(http.post_count, 2u);
    (void)user;
}

TEST(FederationJobs, FetchThreadBackfillsAncestorsWithDepthCap)
{
    Config c = testConfig();
    c.thread_fetch_max_depth = 2;
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    EXPECT_TRUE(db->setSystemActor(keys.private_key, keys.public_key)
                    .has_value());

    FakeSession http;
    http.responses = {
        mw::HTTPResponse(200, nlohmann::json({
            {"id", "https://remote.test/o/child"},
            {"type", "Note"},
            {"attributedTo", "https://remote.test/u/bob"},
            {"content", "<p>child</p>"},
            {"inReplyTo", "https://remote.test/o/parent"},
            {"to", std::string(AS_PUBLIC)},
        }).dump()),
        mw::HTTPResponse(200, nlohmann::json({
            {"id", "https://remote.test/o/parent"},
            {"type", "Note"},
            {"attributedTo", "https://remote.test/u/bob"},
            {"content", "<p>parent</p>"},
            {"inReplyTo", "https://remote.test/o/grandparent"},
            {"to", std::string(AS_PUBLIC)},
        }).dump()),
    };

    ASSIGN_OR_FAIL(auto jid, enqueueFetchThreadJob(
        *db, "https://remote.test/o/child", 100));
    EXPECT_GT(jid, 0);
    ASSERT_TRUE(runFederationJobOnce(c, *db, crypto, http, 100).value());

    ASSIGN_OR_FAIL(auto child,
                   db->getPostByUri("https://remote.test/o/child"));
    ASSERT_TRUE(child.has_value());
    EXPECT_EQ(child->content_html, "<p>child</p>");
    ASSIGN_OR_FAIL(auto parent,
                   db->getPostByUri("https://remote.test/o/parent"));
    ASSERT_TRUE(parent.has_value());
    EXPECT_EQ(parent->content_html, "<p>parent</p>");
    ASSIGN_OR_FAIL(auto grandparent,
                   db->getPostByUri("https://remote.test/o/grandparent"));
    EXPECT_FALSE(grandparent.has_value());
    ASSERT_EQ(http.get_urls.size(), 2u);
    EXPECT_EQ(http.get_urls[0], "https://remote.test/o/child");
    EXPECT_EQ(http.get_urls[1], "https://remote.test/o/parent");
}

TEST(FederationJobs, FetchThreadBackfillsRepliesCollection)
{
    Config c = testConfig();
    c.thread_fetch_max_depth = 2;
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    EXPECT_TRUE(db->setSystemActor(keys.private_key, keys.public_key)
                    .has_value());

    FakeSession http;
    http.responses = {
        mw::HTTPResponse(200, nlohmann::json({
            {"id", "https://remote.test/o/root"},
            {"type", "Note"},
            {"attributedTo", "https://remote.test/u/bob"},
            {"content", "<p>root</p>"},
            {"to", std::string(AS_PUBLIC)},
            {"replies", {
                {"type", "Collection"},
                {"items", nlohmann::json::array({
                    "https://remote.test/o/reply",
                })},
            }},
        }).dump()),
        mw::HTTPResponse(200, nlohmann::json({
            {"id", "https://remote.test/o/reply"},
            {"type", "Note"},
            {"attributedTo", "https://remote.test/u/carol"},
            {"content", "<p>reply</p>"},
            {"inReplyTo", "https://remote.test/o/root"},
            {"to", std::string(AS_PUBLIC)},
        }).dump()),
    };

    ASSIGN_OR_FAIL(auto jid, enqueueFetchThreadJob(
        *db, "https://remote.test/o/root", 100));
    EXPECT_GT(jid, 0);
    ASSERT_TRUE(runFederationJobOnce(c, *db, crypto, http, 100).value());

    ASSIGN_OR_FAIL(auto root,
                   db->getPostByUri("https://remote.test/o/root"));
    ASSERT_TRUE(root.has_value());
    ASSIGN_OR_FAIL(auto reply,
                   db->getPostByUri("https://remote.test/o/reply"));
    ASSERT_TRUE(reply.has_value());
    EXPECT_EQ(reply->in_reply_to_uri.value_or(""),
              "https://remote.test/o/root");
    ASSERT_EQ(http.get_urls.size(), 2u);
    EXPECT_EQ(http.get_urls[0], "https://remote.test/o/root");
    EXPECT_EQ(http.get_urls[1], "https://remote.test/o/reply");
}

TEST(OutboundDelivery, ExpandsFollowersAndPrefersSharedInbox)
{
    Config c = testConfig();
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());

    RemoteActor bob;
    bob.uri = "https://remote.test/u/bob";
    bob.username = "bob";
    bob.domain = "remote.test";
    bob.inbox = "https://remote.test/u/bob/inbox";
    bob.shared_inbox = "https://remote.test/inbox";
    bob.public_key_pem = "PUB";
    bob.public_key_id = bob.uri + "#main-key";
    bob.actor_json = "{}";
    ASSIGN_OR_FAIL(bob, db->upsertRemoteActor(bob));

    RemoteActor carol;
    carol.uri = "https://remote.test/u/carol";
    carol.username = "carol";
    carol.domain = "remote.test";
    carol.inbox = "https://remote.test/u/carol/inbox";
    carol.shared_inbox = "https://remote.test/inbox";
    carol.public_key_pem = "PUB";
    carol.public_key_id = carol.uri + "#main-key";
    carol.actor_json = "{}";
    ASSIGN_OR_FAIL(carol, db->upsertRemoteActor(carol));

    RemoteActor dave;
    dave.uri = "https://other.test/u/dave";
    dave.username = "dave";
    dave.domain = "other.test";
    dave.inbox = "https://other.test/u/dave/inbox";
    dave.public_key_pem = "PUB";
    dave.public_key_id = dave.uri + "#main-key";
    dave.actor_json = "{}";
    ASSIGN_OR_FAIL(dave, db->upsertRemoteActor(dave));

    Follow f1;
    f1.follower_uri = bob.uri;
    f1.followee_uri = "https://f.test/u/alice";
    f1.state = FollowState::ACCEPTED;
    ASSERT_TRUE(db->addFollow(f1).has_value());
    Follow f2;
    f2.follower_uri = carol.uri;
    f2.followee_uri = "https://f.test/u/alice";
    f2.state = FollowState::ACCEPTED;
    ASSERT_TRUE(db->addFollow(f2).has_value());
    Follow f3;
    f3.follower_uri = dave.uri;
    f3.followee_uri = "https://f.test/u/alice";
    f3.state = FollowState::ACCEPTED;
    ASSERT_TRUE(db->addFollow(f3).has_value());

    std::vector<PostRecipient> recipients = {
        {1, std::string(AS_PUBLIC), "to"},
        {1, "https://f.test/u/alice/followers", "cc"},
        {1, "https://f.test/u/local", "to"},
        {1, "https://remote.test/u/bob", "to"},
    };
    ASSIGN_OR_FAIL(auto inboxes, deliveryInboxesForRecipients(
        c, *db, recipients));
    EXPECT_EQ(inboxes, std::vector<std::string>({
        "https://other.test/u/dave/inbox",
        "https://remote.test/inbox",
    }));
}

TEST(OutboundDelivery, EnqueuesOneJobPerExpandedInbox)
{
    Config c = testConfig();
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());

    RemoteActor bob;
    bob.uri = "https://remote.test/u/bob";
    bob.username = "bob";
    bob.domain = "remote.test";
    bob.inbox = "https://remote.test/u/bob/inbox";
    bob.public_key_pem = "PUB";
    bob.public_key_id = bob.uri + "#main-key";
    bob.actor_json = "{}";
    ASSIGN_OR_FAIL(bob, db->upsertRemoteActor(bob));

    std::vector<PostRecipient> recipients = {
        {1, "https://remote.test/u/bob", "to"},
    };
    nlohmann::json activity = {
        {"id", "https://f.test/a/3"},
        {"type", "Create"},
    };
    ASSIGN_OR_FAIL(auto jobs, enqueueOutboundDelivery(
        c, *db, "https://f.test/u/alice", activity, recipients, 100));
    ASSERT_EQ(jobs.size(), 1);

    ASSIGN_OR_FAIL(auto job, db->claimJob(100));
    ASSERT_TRUE(job.has_value());
    EXPECT_EQ(job->id, jobs[0]);
    auto payload = nlohmann::json::parse(job->payload_json);
    EXPECT_EQ(payload["target_inbox"], "https://remote.test/u/bob/inbox");
    EXPECT_EQ(payload["signer_actor"], "https://f.test/u/alice");
}

TEST(InboxDispatch, CreateStoresRemoteNoteAndDedupsRedelivery)
{
    Config c = testConfig();
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto remote, db->upsertRemoteActor(
        testRemoteActor("https://remote.test/u/bob")));

    nlohmann::json raw = {
        {"id", "https://remote.test/a/create/1"},
        {"type", "Create"},
        {"actor", remote.uri},
        {"object", {
            {"id", "https://remote.test/o/1"},
            {"type", "Note"},
            {"attributedTo", remote.uri},
            {"content", "<p onclick=\"bad()\">hello :blobcat: "
                        "<script>alert(1)</script><strong>ok</strong></p>"},
            {"summary", "<span class=\"mention\" onclick=\"bad()\">cw</span>"},
            {"sensitive", true},
            {"tag", nlohmann::json::array({
                {
                    {"type", "Emoji"},
                    {"name", ":blobcat:"},
                    {"icon", {
                        {"type", "Image"},
                        {"mediaType", "image/png"},
                        {"url", "https://remote.test/emoji/blobcat.png"},
                    }},
                },
            })},
            {"to", std::string(AS_PUBLIC)},
            {"cc", nlohmann::json::array({"https://f.test/u/alice"})},
            {"attachment", {
                {"type", "Image"},
                {"mediaType", "image/png"},
                {"url", "https://remote.test/media/1.png"},
                {"name", "one.png"},
            }},
        }},
    };
    ASSIGN_OR_FAIL(auto activity, parseActivity(raw));
    ASSIGN_OR_FAIL(auto first, dispatchIncomingActivity(
        c, *db, remote.uri, activity, 100));
    EXPECT_FALSE(first.duplicate);

    ASSIGN_OR_FAIL(auto post, db->getPostByUri("https://remote.test/o/1"));
    ASSERT_TRUE(post.has_value());
    EXPECT_EQ(post->visibility, Visibility::PUBLIC);
    EXPECT_TRUE(post->sensitive);
    EXPECT_EQ(post->content_html,
              "<p>hello <img class=\"emoji\" "
              "src=\"https://remote.test/emoji/blobcat.png\" "
              "alt=\":blobcat:\" title=\":blobcat:\"> "
              "<strong>ok</strong></p>");
    ASSERT_TRUE(post->summary.has_value());
    EXPECT_EQ(*post->summary, "<span class=\"mention\">cw</span>");
    ASSIGN_OR_FAIL(auto atts, db->attachmentsForPost(post->id));
    ASSERT_EQ(atts.size(), 1);
    EXPECT_TRUE(atts[0].sensitive);
    ASSERT_TRUE(atts[0].remote_url.has_value());
    EXPECT_EQ(*atts[0].remote_url, "https://remote.test/media/1.png");

    ASSIGN_OR_FAIL(auto second, dispatchIncomingActivity(
        c, *db, remote.uri, activity, 101));
    EXPECT_TRUE(second.duplicate);

    for(int i = 0; i < 25; ++i)
    {
        ASSIGN_OR_FAIL(auto redelivery, dispatchIncomingActivity(
            c, *db, remote.uri, activity, 102 + i));
        EXPECT_TRUE(redelivery.duplicate);
    }
    ASSIGN_OR_FAIL(auto stable_post,
                   db->getPostByUri("https://remote.test/o/1"));
    ASSERT_TRUE(stable_post.has_value());
    ASSIGN_OR_FAIL(auto stable_atts, db->attachmentsForPost(post->id));
    EXPECT_EQ(stable_atts.size(), 1u);
}

TEST(InboxDispatch, CreateWithObjectUriFetchesAndStoresRemoteNote)
{
    Config c = testConfig();
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    SystemActor system;
    system.private_key_pem = keys.private_key;
    system.public_key_pem = keys.public_key;

    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto remote, db->upsertRemoteActor(
        testRemoteActor("https://remote.test/u/bob")));
    FakeSession http;
    http.response = mw::HTTPResponse(200, nlohmann::json({
        {"id", "https://remote.test/o/uri-create"},
        {"type", "Note"},
        {"attributedTo", remote.uri},
        {"content", "<p>uri object</p>"},
        {"sensitive", nullptr},
        {"to", std::string(AS_PUBLIC)},
    }).dump());

    nlohmann::json raw = {
        {"id", "https://remote.test/a/create/uri-object"},
        {"type", "Create"},
        {"actor", remote.uri},
        {"object", "https://remote.test/o/uri-create"},
    };
    ASSIGN_OR_FAIL(auto activity, parseActivity(raw));
    ASSIGN_OR_FAIL(auto result, dispatchIncomingActivity(
        c, *db, remote.uri, activity, 100, &crypto, &http, &system));
    EXPECT_FALSE(result.duplicate);

    ASSIGN_OR_FAIL(auto post,
                   db->getPostByUri("https://remote.test/o/uri-create"));
    ASSERT_TRUE(post.has_value());
    EXPECT_EQ(post->content_html, "<p>uri object</p>");
    EXPECT_FALSE(post->sensitive);
    ASSERT_EQ(http.get_urls.size(), 1u);
    EXPECT_EQ(http.get_urls[0], "https://remote.test/o/uri-create");
}

TEST(InboxDispatch, CreateClassifiesRemoteDirectAndFollowersPosts)
{
    Config c = testConfig();
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto remote, db->upsertRemoteActor(
        testRemoteActor("https://remote.test/u/bob")));

    nlohmann::json direct_raw = {
        {"id", "https://remote.test/a/create/direct"},
        {"type", "Create"},
        {"actor", remote.uri},
        {"object", {
            {"id", "https://remote.test/o/direct"},
            {"type", "Note"},
            {"attributedTo", remote.uri},
            {"content", "direct"},
            {"to", nlohmann::json::array({"https://f.test/u/alice"})},
        }},
    };
    ASSIGN_OR_FAIL(auto direct_activity, parseActivity(direct_raw));
    EXPECT_TRUE(dispatchIncomingActivity(
        c, *db, remote.uri, direct_activity, 100).has_value());
    ASSIGN_OR_FAIL(auto direct_post,
                   db->getPostByUri("https://remote.test/o/direct"));
    ASSERT_TRUE(direct_post.has_value());
    EXPECT_EQ(direct_post->visibility, Visibility::DIRECT);

    nlohmann::json followers_raw = {
        {"id", "https://remote.test/a/create/followers"},
        {"type", "Create"},
        {"actor", remote.uri},
        {"object", {
            {"id", "https://remote.test/o/followers"},
            {"type", "Note"},
            {"attributedTo", remote.uri},
            {"content", "followers"},
            {"to", nlohmann::json::array({
                "https://remote.test/u/bob/followers"})},
        }},
    };
    ASSIGN_OR_FAIL(auto followers_activity, parseActivity(followers_raw));
    EXPECT_TRUE(dispatchIncomingActivity(
        c, *db, remote.uri, followers_activity, 101).has_value());
    ASSIGN_OR_FAIL(auto followers_post,
                   db->getPostByUri("https://remote.test/o/followers"));
    ASSERT_TRUE(followers_post.has_value());
    EXPECT_EQ(followers_post->visibility, Visibility::FOLLOWERS);
}

TEST(InboxForwarding, ForwardsFirstSeenActivityAfterRefetchVerification)
{
    Config c = testConfig();
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    SystemActor system;
    system.private_key_pem = keys.private_key;
    system.public_key_pem = keys.public_key;
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(testNewUser("alice")));

    NewPost local_np;
    local_np.local_author_id = alice.id;
    local_np.content_html = "<p>local</p>";
    local_np.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(auto local_post, db->insertPost(
        local_np, {{0, std::string(AS_PUBLIC), "to"}},
        "https://f.test/p/"));

    RemoteActor carol = testRemoteActor("https://remote.test/u/carol");
    carol.inbox = "https://remote.test/u/carol/inbox";
    carol.shared_inbox = std::nullopt;
    ASSIGN_OR_FAIL(carol, db->upsertRemoteActor(carol));
    Follow follow;
    follow.follower_uri = carol.uri;
    follow.followee_uri = "https://f.test/u/alice";
    follow.state = FollowState::ACCEPTED;
    EXPECT_TRUE(db->addFollow(follow).has_value());

    nlohmann::json note = {
        {"id", "https://remote.test/o/reply"},
        {"type", "Note"},
        {"attributedTo", "https://remote.test/u/bob"},
        {"content", "<p>reply</p>"},
        {"inReplyTo", local_post.uri},
        {"to", nlohmann::json::array({
            "https://f.test/u/alice/followers",
        })},
    };
    nlohmann::json raw = {
        {"id", "https://remote.test/a/create-forward/1"},
        {"type", "Create"},
        {"actor", "https://remote.test/u/bob"},
        {"object", note},
        {"to", nlohmann::json::array({
            "https://f.test/u/alice/followers",
        })},
    };
    FakeSession http;
    http.response = mw::HTTPResponse(200, note.dump());
    ASSIGN_OR_FAIL(auto activity, parseActivity(raw));
    ASSIGN_OR_FAIL(auto result, dispatchIncomingActivity(
        c, *db, "https://remote.test/u/bob", activity, 100, &crypto, &http,
        &system));
    EXPECT_FALSE(result.duplicate);

    ASSIGN_OR_FAIL(auto job, db->claimJob(100));
    ASSERT_TRUE(job.has_value());
    auto payload = nlohmann::json::parse(job->payload_json);
    EXPECT_EQ(job->kind, "deliver");
    EXPECT_EQ(payload["target_inbox"], "https://remote.test/u/carol/inbox");
    EXPECT_EQ(payload["signer_actor"], "https://f.test/u/alice");
    EXPECT_EQ(payload["activity"]["id"], raw["id"]);
    ASSERT_EQ(http.get_urls.size(), 1u);
    EXPECT_EQ(http.get_urls[0], "https://remote.test/o/reply");

    ASSIGN_OR_FAIL(auto duplicate, dispatchIncomingActivity(
        c, *db, "https://remote.test/u/bob", activity, 101, &crypto, &http,
        &system));
    EXPECT_TRUE(duplicate.duplicate);
    ASSIGN_OR_FAIL(auto no_more, db->claimJob(101));
    EXPECT_FALSE(no_more.has_value());
}

TEST(InboxForwarding, DoesNotForwardWhenRefetchDoesNotVerifyReference)
{
    Config c = testConfig();
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    SystemActor system;
    system.private_key_pem = keys.private_key;
    system.public_key_pem = keys.public_key;
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(testNewUser("alice")));

    NewPost local_np;
    local_np.local_author_id = alice.id;
    local_np.content_html = "<p>local</p>";
    local_np.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(auto local_post, db->insertPost(
        local_np, {{0, std::string(AS_PUBLIC), "to"}},
        "https://f.test/p/"));

    nlohmann::json embedded_note = {
        {"id", "https://remote.test/o/reply-no-forward"},
        {"type", "Note"},
        {"attributedTo", "https://remote.test/u/bob"},
        {"content", "<p>reply</p>"},
        {"inReplyTo", local_post.uri},
        {"to", nlohmann::json::array({
            "https://f.test/u/alice/followers",
        })},
    };
    nlohmann::json refetched_note = embedded_note;
    refetched_note["inReplyTo"] = "https://remote.test/o/not-ours";
    nlohmann::json raw = {
        {"id", "https://remote.test/a/create-no-forward/1"},
        {"type", "Create"},
        {"actor", "https://remote.test/u/bob"},
        {"object", embedded_note},
        {"to", nlohmann::json::array({
            "https://f.test/u/alice/followers",
        })},
    };
    FakeSession http;
    http.response = mw::HTTPResponse(200, refetched_note.dump());
    ASSIGN_OR_FAIL(auto activity, parseActivity(raw));
    ASSIGN_OR_FAIL(auto result, dispatchIncomingActivity(
        c, *db, "https://remote.test/u/bob", activity, 100, &crypto, &http,
        &system));
    EXPECT_FALSE(result.duplicate);

    ASSIGN_OR_FAIL(auto no_job, db->claimJob(100));
    EXPECT_FALSE(no_job.has_value());
}

TEST(InboxDispatch, FollowAutoAcceptsAndQueuesAccept)
{
    Config c = testConfig();
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    NewUser nu = testNewUser("alice");
    nu.private_key_pem = keys.private_key;
    nu.public_key_pem = keys.public_key;
    ASSIGN_OR_FAIL(auto local, db->createUser(nu));
    ASSIGN_OR_FAIL(auto remote, db->upsertRemoteActor(
        testRemoteActor("https://remote.test/u/bob")));

    nlohmann::json raw = {
        {"id", "https://remote.test/a/follow/1"},
        {"type", "Follow"},
        {"actor", remote.uri},
        {"object", "https://f.test/u/alice"},
    };
    ASSIGN_OR_FAIL(auto activity, parseActivity(raw));
    ASSIGN_OR_FAIL(auto result, dispatchIncomingActivity(
        c, *db, remote.uri, activity, 200));
    EXPECT_FALSE(result.duplicate);

    ASSIGN_OR_FAIL(auto follow, db->getFollow(
        remote.uri, "https://f.test/u/alice"));
    ASSERT_TRUE(follow.has_value());
    EXPECT_EQ(follow->state, FollowState::ACCEPTED);
    ASSERT_TRUE(follow->follow_activity_uri.has_value());
    EXPECT_EQ(*follow->follow_activity_uri,
              raw["id"].get<std::string>());

    ASSIGN_OR_FAIL(auto job, db->claimJob(200));
    ASSERT_TRUE(job.has_value());
    auto payload = nlohmann::json::parse(job->payload_json);
    EXPECT_EQ(payload["target_inbox"], "https://remote.test/inbox");
    EXPECT_EQ(payload["signer_actor"], "https://f.test/u/alice");
    EXPECT_EQ(payload["activity"]["type"], "Accept");
    EXPECT_EQ(payload["activity"]["id"],
              std::format("https://f.test/activities/accept/{}/200",
                          follow->id));
    (void)local;
}

TEST(InboxDispatch, LikeUndoAndPrivateAnnounceIgnored)
{
    Config c = testConfig();
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto local, db->createUser(testNewUser("alice")));
    ASSIGN_OR_FAIL(auto remote, db->upsertRemoteActor(
        testRemoteActor("https://remote.test/u/bob")));

    NewPost np;
    np.local_author_id = local.id;
    np.content_html = "private";
    np.visibility = Visibility::FOLLOWERS;
    ASSIGN_OR_FAIL(auto post, db->insertPost(
        np, {{0, "https://f.test/u/alice/followers", "to"}},
        "https://f.test/p/"));

    nlohmann::json announce_raw = {
        {"id", "https://remote.test/a/announce/1"},
        {"type", "Announce"},
        {"actor", remote.uri},
        {"object", post.uri},
    };
    ASSIGN_OR_FAIL(auto announce, parseActivity(announce_raw));
    EXPECT_TRUE(dispatchIncomingActivity(
        c, *db, remote.uri, announce, 100).has_value());

    nlohmann::json like_raw = {
        {"id", "https://remote.test/a/like/1"},
        {"type", "Like"},
        {"actor", remote.uri},
        {"object", post.uri},
    };
    ASSIGN_OR_FAIL(auto like, parseActivity(like_raw));
    EXPECT_TRUE(dispatchIncomingActivity(
        c, *db, remote.uri, like, 101).has_value());
    ASSIGN_OR_FAIL(auto likes, db->likesForPost(post.uri));
    ASSERT_EQ(likes.size(), 1);

    nlohmann::json react_raw = {
        {"id", "https://remote.test/a/react/1"},
        {"type", "EmojiReact"},
        {"actor", remote.uri},
        {"object", post.uri},
        {"content", ":blobcat:"},
        {"tag", nlohmann::json::array({
            {
                {"type", "Emoji"},
                {"name", "blobcat"},
                {"icon", {
                    {"type", "Image"},
                    {"mediaType", "image/png"},
                    {"url", "http://remote.test/e/blobcat.png"},
                }},
            },
        })},
    };
    ASSIGN_OR_FAIL(auto react, parseActivity(react_raw));
    EXPECT_TRUE(dispatchIncomingActivity(
        c, *db, remote.uri, react, 102).has_value());
    ASSIGN_OR_FAIL(auto reactions, db->reactionsForPost(post.uri));
    ASSERT_EQ(reactions.size(), 1);
    EXPECT_EQ(reactions[0].emoji, ":blobcat:");
    EXPECT_EQ(reactions[0].remote_emoji_url.value_or(""),
              "http://remote.test/e/blobcat.png");

    nlohmann::json undo_raw = {
        {"id", "https://remote.test/a/undo/1"},
        {"type", "Undo"},
        {"actor", remote.uri},
        {"object", like_raw},
    };
    ASSIGN_OR_FAIL(auto undo, parseActivity(undo_raw));
    EXPECT_TRUE(dispatchIncomingActivity(
        c, *db, remote.uri, undo, 103).has_value());
    ASSIGN_OR_FAIL(auto likes_after, db->likesForPost(post.uri));
    EXPECT_TRUE(likes_after.empty());
}

TEST(InboxDispatch, UpdateReplacesKnownRemoteNote)
{
    Config c = testConfig();
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto remote, db->upsertRemoteActor(
        testRemoteActor("https://remote.test/u/bob")));

    NewPost np;
    np.uri = "https://remote.test/o/updated";
    np.remote_author_id = remote.id;
    np.content_html = "old";
    np.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(auto original, db->insertPost(
        np, {{0, std::string(AS_PUBLIC), "to"}}, "https://f.test/p/"));
    Like like;
    like.actor_uri = "https://f.test/u/alice";
    like.post_uri = original.uri;
    like.activity_uri = "https://f.test/activities/like/1";
    EXPECT_TRUE(mw::isExpected(db->addLike(like)));

    nlohmann::json raw = {
        {"id", "https://remote.test/a/update/1"},
        {"type", "Update"},
        {"actor", remote.uri},
        {"object", {
            {"id", "https://remote.test/o/updated"},
            {"type", "Note"},
            {"attributedTo", remote.uri},
            {"content", "<b>new</b>"},
            {"cc", std::string(AS_PUBLIC)},
            {"summary", "changed"},
        }},
    };
    ASSIGN_OR_FAIL(auto activity, parseActivity(raw));
    ASSIGN_OR_FAIL(auto result, dispatchIncomingActivity(
        c, *db, remote.uri, activity, 100));
    EXPECT_FALSE(result.duplicate);

    ASSIGN_OR_FAIL(auto by_id, db->getPostById(original.id));
    ASSERT_TRUE(by_id.has_value());
    ASSIGN_OR_FAIL(auto updated, db->getPostByUri(*np.uri));
    ASSERT_TRUE(updated.has_value());
    EXPECT_EQ(updated->id, original.id);
    EXPECT_EQ(updated->content_html, "<b>new</b>");
    EXPECT_EQ(updated->visibility, Visibility::UNLISTED);
    ASSERT_TRUE(updated->summary.has_value());
    EXPECT_EQ(*updated->summary, "changed");
    ASSIGN_OR_FAIL(auto likes, db->likesForPost(original.uri));
    ASSERT_EQ(likes.size(), 1u);
    EXPECT_EQ(likes[0].actor_uri, "https://f.test/u/alice");
}

TEST(InboxDispatch, UpdateRefreshesCachedRemoteActor)
{
    Config c = testConfig();
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    RemoteActor actor = testRemoteActor("https://remote.test/u/bob");
    actor.display_name = "Old Bob";
    actor.shared_inbox = std::nullopt;
    ASSIGN_OR_FAIL(actor, db->upsertRemoteActor(actor));

    nlohmann::json raw = {
        {"id", "https://remote.test/a/update/actor"},
        {"type", "Update"},
        {"actor", actor.uri},
        {"object", {
            {"id", actor.uri},
            {"type", "Person"},
            {"preferredUsername", "bobby"},
            {"name", "New Bob"},
            {"inbox", "https://remote.test/u/bob/new-inbox"},
            {"endpoints", {
                {"sharedInbox", "https://remote.test/inbox"},
            }},
        }},
    };
    ASSIGN_OR_FAIL(auto activity, parseActivity(raw));
    EXPECT_TRUE(dispatchIncomingActivity(c, *db, actor.uri, activity, 500)
                    .has_value());

    ASSIGN_OR_FAIL(auto updated, db->getRemoteActorByUri(actor.uri));
    ASSERT_TRUE(updated.has_value());
    EXPECT_EQ(updated->username, "bobby");
    EXPECT_EQ(updated->display_name, "New Bob");
    EXPECT_EQ(updated->inbox, "https://remote.test/u/bob/new-inbox");
    ASSERT_TRUE(updated->shared_inbox.has_value());
    EXPECT_EQ(*updated->shared_inbox, "https://remote.test/inbox");
    EXPECT_EQ(updated->public_key_id, actor.public_key_id);
    EXPECT_EQ(updated->fetched_at, 500);
}
