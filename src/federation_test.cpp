#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <mw/test_utils.hpp>

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
