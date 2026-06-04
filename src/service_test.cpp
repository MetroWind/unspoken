#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <mw/error.hpp>
#include <mw/test_utils.hpp>

#include "attachments.hpp"
#include "config.hpp"
#include "data.hpp"
#include "data_mock.hpp"
#include "emoji.hpp"
#include "render.hpp"
#include "service.hpp"
#include "structs.hpp"

using namespace unspoken;

namespace
{

Config testConfig()
{
    Config c;
    c.url_root = "https://f.test/";
    c.public_domain = "f.test";
    c.posts_per_page = 20;
    return c;
}

// Find the recipient with a given field, returning its uri or "".
std::string recipient(const std::vector<PostRecipient>& recs,
                      const std::string& uri)
{
    for(const auto& r : recs) if(r.recipient_uri == uri) return r.field;
    return "";
}

} // namespace

// ─── Addressing / visibility (design §12.5) ────────────────────────────

TEST(ServiceAddressing, PublicToPublicCcFollowers)
{
    Config c = testConfig();
    DataSourceMock data;
    EmojiRegistry emoji;
    Service svc(c, data, emoji);

    auto recs = svc.recipientsFor(Visibility::PUBLIC, "alice", {});
    EXPECT_EQ(recipient(recs, std::string(AS_PUBLIC)), "to");
    EXPECT_EQ(recipient(recs, "https://f.test/u/alice/followers"), "cc");
}

TEST(ServiceAddressing, UnlistedToFollowersCcPublic)
{
    Config c = testConfig();
    DataSourceMock data;
    EmojiRegistry emoji;
    Service svc(c, data, emoji);

    auto recs = svc.recipientsFor(Visibility::UNLISTED, "alice", {});
    EXPECT_EQ(recipient(recs, "https://f.test/u/alice/followers"), "to");
    EXPECT_EQ(recipient(recs, std::string(AS_PUBLIC)), "cc");
}

TEST(ServiceAddressing, FollowersOnlyToFollowersNoPublic)
{
    Config c = testConfig();
    DataSourceMock data;
    EmojiRegistry emoji;
    Service svc(c, data, emoji);

    auto recs = svc.recipientsFor(Visibility::FOLLOWERS, "alice", {});
    EXPECT_EQ(recipient(recs, "https://f.test/u/alice/followers"), "to");
    EXPECT_EQ(recipient(recs, std::string(AS_PUBLIC)), ""); // absent
}

TEST(ServiceAddressing, DirectIsExactlyMentioned)
{
    Config c = testConfig();
    DataSourceMock data;
    EmojiRegistry emoji;
    Service svc(c, data, emoji);

    std::vector<std::string> mentioned{"https://remote.test/u/bob"};
    auto recs = svc.recipientsFor(Visibility::DIRECT, "alice", mentioned);
    EXPECT_EQ(recipient(recs, "https://remote.test/u/bob"), "to");
    // No public, no followers collection for direct.
    EXPECT_EQ(recipient(recs, std::string(AS_PUBLIC)), "");
    EXPECT_EQ(recipient(recs, "https://f.test/u/alice/followers"), "");
}

TEST(ServiceAddressing, MentionsAddedToNonDirect)
{
    Config c = testConfig();
    DataSourceMock data;
    EmojiRegistry emoji;
    Service svc(c, data, emoji);

    std::vector<std::string> mentioned{"https://remote.test/u/bob"};
    auto recs = svc.recipientsFor(Visibility::PUBLIC, "alice", mentioned);
    EXPECT_EQ(recipient(recs, "https://remote.test/u/bob"), "to");
}

// ─── URI construction ──────────────────────────────────────────────────

TEST(ServiceUri, ActorAndHandle)
{
    Config c = testConfig();
    DataSourceMock data;
    EmojiRegistry emoji;
    Service svc(c, data, emoji);

    EXPECT_EQ(svc.actorUri("alice"), "https://f.test/u/alice");
    EXPECT_EQ(svc.followersUri("alice"), "https://f.test/u/alice/followers");
    EXPECT_EQ(svc.handleFor("alice"), "@alice@f.test");
}

TEST(ServiceAuthz, ActorCanViewFollowersPostWhenAcceptedFollower)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(NewUser{
        "alice", "Alice", "", "iss", "sub-a", "PRIV", "PUB"}));
    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);

    NewPost np;
    np.local_author_id = alice.id;
    np.content_html = "<p>secret</p>";
    np.visibility = Visibility::FOLLOWERS;
    ASSIGN_OR_FAIL(Post post, db->insertPost(
        np, svc.recipientsFor(Visibility::FOLLOWERS, "alice", {}),
        "https://f.test/p/"));

    Follow f;
    f.follower_uri = "https://remote.test/u/bob";
    f.followee_uri = svc.actorUri("alice");
    f.state = FollowState::ACCEPTED;
    EXPECT_TRUE(mw::isExpected(db->addFollow(f)));

    ASSIGN_OR_FAIL(bool allowed,
                   svc.canActorViewPost(post, "https://remote.test/u/bob"));
    EXPECT_TRUE(allowed);
    ASSIGN_OR_FAIL(bool denied,
                   svc.canActorViewPost(post, "https://remote.test/u/eve"));
    EXPECT_FALSE(denied);
}

TEST(ServiceAuthz, ActorCanViewDirectPostOnlyWhenAddressed)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(NewUser{
        "alice", "Alice", "", "iss", "sub-a", "PRIV", "PUB"}));
    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);

    NewPost np;
    np.local_author_id = alice.id;
    np.content_html = "<p>dm</p>";
    np.visibility = Visibility::DIRECT;
    ASSIGN_OR_FAIL(Post post, db->insertPost(
        np,
        svc.recipientsFor(Visibility::DIRECT, "alice",
                          {"https://remote.test/u/bob"}),
        "https://f.test/p/"));

    ASSIGN_OR_FAIL(bool allowed,
                   svc.canActorViewPost(post, "https://remote.test/u/bob"));
    EXPECT_TRUE(allowed);
    ASSIGN_OR_FAIL(bool denied,
                   svc.canActorViewPost(post, "https://remote.test/u/eve"));
    EXPECT_FALSE(denied);
}

// ─── Emoji registry / substitution (§13.4) ─────────────────────────────

TEST(Emoji, ShortcodeValidation)
{
    EXPECT_TRUE(isValidShortcode("blob_cat3"));
    EXPECT_FALSE(isValidShortcode(""));
    EXPECT_FALSE(isValidShortcode("Blob"));      // uppercase
    EXPECT_FALSE(isValidShortcode("a-b"));        // dash
}

TEST(Emoji, MediaTypeForExt)
{
    EXPECT_EQ(imageMediaTypeForExt("png"), "image/png");
    EXPECT_EQ(imageMediaTypeForExt("svg"), "image/svg+xml");
    EXPECT_EQ(imageMediaTypeForExt("txt"), "");
}

TEST(Emoji, ScanAndSubstitute)
{
    namespace fs = std::filesystem;
    fs::path dir = fs::temp_directory_path()
        / ("unspoken_emoji_" + std::to_string(::getpid()));
    fs::create_directories(dir);
    { std::ofstream(dir / "blobcat.png") << "x"; }
    { std::ofstream(dir / "BadName.png") << "x"; }   // invalid → skipped

    EmojiRegistry reg = EmojiRegistry::scan(dir.string(), "https://f.test/");
    EXPECT_TRUE(reg.lookup("blobcat").has_value());
    EXPECT_FALSE(reg.lookup("BadName").has_value());
    EXPECT_EQ(reg.lookup("blobcat")->image_url,
              "https://f.test/emoji/blobcat.png");

    std::string out = substituteEmoji("hi :blobcat: and :unknown:", reg);
    EXPECT_NE(out.find("<img class=\"emoji\""), std::string::npos);
    EXPECT_NE(out.find(":unknown:"), std::string::npos); // left verbatim

    fs::remove_all(dir);
}

// ─── Attachments (§17) ─────────────────────────────────────────────────

TEST(Attachments, ExtensionAndHex)
{
    EXPECT_EQ(extensionOf("test.JPG"), "jpg");
    EXPECT_EQ(extensionOf("noext"), "");
    EXPECT_EQ(extensionOf("a.tar.gz"), "gz");
    EXPECT_TRUE(isHexLower("abc123"));
    EXPECT_FALSE(isHexLower("ABC"));
    EXPECT_FALSE(isHexLower(""));
}

TEST(Attachments, ImageClassification)
{
    EXPECT_TRUE(isImageMediaType("image/png"));
    EXPECT_TRUE(isImageMediaType("image/svg+xml"));
    EXPECT_FALSE(isImageMediaType("application/pdf"));
}

TEST(Attachments, StoreHashesShardsAndDedups)
{
    namespace fs = std::filesystem;
    fs::path dir = fs::temp_directory_path()
        / ("unspoken_att_" + std::to_string(::getpid()));
    fs::create_directories(dir);

    std::string bytes = "hello world";
    ASSIGN_OR_FAIL(auto a, storeAttachment(dir.string(), bytes, "greeting.png",
                                           "image/png"));
    // Known SHA-256 of "hello world".
    EXPECT_EQ(a.sha256,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    EXPECT_EQ(a.shard, "b");
    EXPECT_TRUE(a.is_image);
    EXPECT_EQ(a.filename, a.sha256 + ".png");
    EXPECT_TRUE(fs::is_regular_file(a.disk_path));

    // Dedup: storing identical bytes reuses the same path.
    ASSIGN_OR_FAIL(auto b, storeAttachment(dir.string(), bytes, "other.png",
                                           "image/png"));
    EXPECT_EQ(a.disk_path, b.disk_path);

    fs::remove_all(dir);
}

// ─── Markdown rendering (§13.1) ────────────────────────────────────────

TEST(Render, MarkdownProducesHtml)
{
    std::string html = renderMarkdown("hello world");
    EXPECT_FALSE(html.empty());
}
