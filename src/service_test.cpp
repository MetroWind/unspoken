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

TEST(ServiceProfile, LocalRichProfileViewRendersMediaAndFields)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(NewUser{
        "alice", "Alice", "hello **world**", "iss", "sub-a", "PRIV",
        "PUB"}));
    Attachment avatar;
    avatar.sha256 = "abc001";
    avatar.extension = "png";
    avatar.media_type = "image/png";
    avatar.original_name = "avatar.png";
    avatar.is_image = true;
    ASSIGN_OR_FAIL(int64_t avatar_id, db->insertAttachment(avatar));
    Attachment banner;
    banner.sha256 = "def002";
    banner.extension = "jpg";
    banner.media_type = "image/jpeg";
    banner.original_name = "banner.jpg";
    banner.is_image = true;
    ASSIGN_OR_FAIL(int64_t banner_id, db->insertAttachment(banner));

    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);
    UserProfileUpdate update;
    update.display_name = "Alice";
    update.bio = alice.bio;
    update.avatar_attachment_id = avatar_id;
    update.banner_attachment_id = banner_id;
    update.fields = {
        UserProfileField{0, alice.id, " Blog ", "https://example.test", 0},
    };
    EXPECT_TRUE(mw::isExpected(svc.updateProfile(alice, update)));
    ASSIGN_OR_FAIL(auto updated, db->getUserById(alice.id));
    ASSERT_TRUE(updated.has_value());

    ASSIGN_OR_FAIL(auto view, svc.userView(*updated));
    EXPECT_EQ(view["avatar_url"], "https://f.test/media/a/abc001.png");
    EXPECT_EQ(view["banner_url"], "https://f.test/media/d/def002.jpg");
    ASSERT_EQ(view["fields"].size(), 1u);
    EXPECT_EQ(view["fields"][0]["label"], "Blog");
    EXPECT_NE(view["fields"][0]["value_html"].get<std::string>().find(
                  "https://example.test"),
              std::string::npos);
}

TEST(ServiceProfile, RejectsRemoteAvatarAndInvalidField)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(NewUser{
        "alice", "Alice", "", "iss", "sub-a", "PRIV", "PUB"}));
    Attachment remote;
    remote.media_type = "image/png";
    remote.original_name = "remote.png";
    remote.is_image = true;
    remote.remote_url = "https://remote.test/avatar.png";
    ASSIGN_OR_FAIL(int64_t remote_id, db->insertAttachment(remote));

    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);
    UserProfileUpdate update;
    update.display_name = "Alice";
    update.avatar_attachment_id = remote_id;
    EXPECT_FALSE(svc.updateProfile(alice, update).has_value());

    update.avatar_attachment_id = std::nullopt;
    update.fields = {UserProfileField{0, alice.id, "Blog", "", 0}};
    EXPECT_FALSE(svc.updateProfile(alice, update).has_value());
}

TEST(ServiceProfile, RemoteActorViewParsesRichProfileFields)
{
    Config c = testConfig();
    DataSourceMock data;
    EmojiRegistry emoji;
    Service svc(c, data, emoji);

    RemoteActor actor;
    actor.id = 42;
    actor.uri = "https://remote.test/users/bob";
    actor.username = "bob";
    actor.domain = "remote.test";
    actor.display_name = "Bob <Remote>";
    actor.actor_json = R"({
        "name": "Bob JSON",
        "summary": "<p>Hello <script>bad()</script><b>world</b></p>",
        "icon": {"type": "Image", "url": "https://cdn.test/avatar.png"},
        "image": {"type": "Image", "href": "https://cdn.test/banner.jpg"},
        "attachment": [
            {
                "type": "PropertyValue",
                "name": "Blog <site>",
                "value": "<a href=\"https://example.test\">site</a>"
            },
            {
                "type": "PropertyValue",
                "name": "Unsafe",
                "value": "<a href=\"javascript:alert(1)\">bad</a>"
            },
            {"type": "Link", "name": "ignored", "value": "ignored"},
            {"type": "PropertyValue", "name": "", "value": "ignored"}
        ]
    })";

    auto view = svc.remoteActorView(actor);
    EXPECT_EQ(view["id"], 42);
    EXPECT_EQ(view["username"], "bob");
    EXPECT_EQ(view["display_name"], "Bob JSON");
    EXPECT_EQ(view["handle"], "@bob@remote.test");
    EXPECT_EQ(view["profile_url"], actor.uri);
    EXPECT_EQ(view["avatar_url"], "https://cdn.test/avatar.png");
    EXPECT_EQ(view["banner_url"], "https://cdn.test/banner.jpg");
    EXPECT_FALSE(view["is_local"]);

    std::string bio = view["bio_html"];
    EXPECT_EQ(bio.find("script"), std::string::npos);
    EXPECT_NE(bio.find("<b>world</b>"), std::string::npos);

    ASSERT_EQ(view["fields"].size(), 2u);
    EXPECT_EQ(view["fields"][0]["label"], "Blog &lt;site&gt;");
    EXPECT_NE(view["fields"][0]["value_html"].get<std::string>().find(
                  "https://example.test"),
              std::string::npos);
    EXPECT_EQ(view["fields"][1]["label"], "Unsafe");
    EXPECT_EQ(view["fields"][1]["value_html"], "bad");
}

TEST(ServiceProfile, RemoteActorViewAcceptsArraysAndObjectAttachment)
{
    Config c = testConfig();
    DataSourceMock data;
    EmojiRegistry emoji;
    Service svc(c, data, emoji);

    RemoteActor actor;
    actor.uri = "https://remote.test/users/carol";
    actor.username = "carol";
    actor.domain = "remote.test";
    actor.actor_json = R"({
        "icon": [
            "ignored",
            {"type": "Image"},
            {"type": "Image", "url": "https://cdn.test/carol.png"}
        ],
        "image": [
            {"type": "Image", "href": "https://cdn.test/carol.jpg"}
        ],
        "attachment": {
            "type": "PropertyValue",
            "name": "Plain",
            "value": "plain text < ok"
        }
    })";

    auto view = svc.remoteActorView(actor);
    EXPECT_EQ(view["display_name"], "carol");
    EXPECT_EQ(view["avatar_url"], "https://cdn.test/carol.png");
    EXPECT_EQ(view["banner_url"], "https://cdn.test/carol.jpg");
    ASSERT_EQ(view["fields"].size(), 1u);
    EXPECT_EQ(view["fields"][0]["label"], "Plain");
    EXPECT_EQ(view["fields"][0]["value_html"], "plain text &lt; ok");
}

TEST(ServiceProfile, RemoteActorViewToleratesMalformedActorJson)
{
    Config c = testConfig();
    DataSourceMock data;
    EmojiRegistry emoji;
    Service svc(c, data, emoji);

    RemoteActor actor;
    actor.uri = "https://remote.test/users/dave";
    actor.username = "dave";
    actor.domain = "remote.test";
    actor.actor_json = "{";

    auto view = svc.remoteActorView(actor);
    EXPECT_EQ(view["username"], "dave");
    EXPECT_EQ(view["bio_html"], "");
    EXPECT_EQ(view["avatar_url"], "");
    EXPECT_EQ(view["banner_url"], "");
    EXPECT_EQ(view["fields"].size(), 0u);
}

TEST(ServiceFollow, CanFollowRemoteActorUri)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(NewUser{
        "alice", "Alice", "", "iss", "sub-a", "PRIV", "PUB"}));
    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);

    std::string follow_id = "https://f.test/activities/follow/1";
    EXPECT_TRUE(mw::isExpected(svc.setFollowActor(
        alice, "https://remote.test/users/bob", true,
        FollowState::PENDING, follow_id)));

    ASSIGN_OR_FAIL(auto follow, db->getFollow(
        svc.actorUri("alice"), "https://remote.test/users/bob"));
    ASSERT_TRUE(follow.has_value());
    EXPECT_EQ(follow->state, FollowState::PENDING);
    ASSERT_TRUE(follow->follow_activity_uri.has_value());
    EXPECT_EQ(*follow->follow_activity_uri, follow_id);

    EXPECT_TRUE(mw::isExpected(svc.setFollowActor(
        alice, "https://remote.test/users/bob", false)));
    ASSIGN_OR_FAIL(auto gone, db->getFollow(
        svc.actorUri("alice"), "https://remote.test/users/bob"));
    EXPECT_FALSE(gone.has_value());
}

TEST(ServiceTimeline, IncludesAcceptedFollowedRemoteActorPosts)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(NewUser{
        "alice", "Alice", "", "iss", "sub-a", "PRIV", "PUB"}));
    ASSIGN_OR_FAIL(auto remote, db->upsertRemoteActor(RemoteActor{
        0,
        "https://activitypub.academy/users/banulius_amudol",
        "banulius_amudol",
        "activitypub.academy",
        "Banulius",
        "https://activitypub.academy/users/banulius_amudol/inbox",
        std::nullopt,
        "PUB",
        "https://activitypub.academy/users/banulius_amudol#main-key",
        "{}",
        0,
    }));
    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);

    Follow follow;
    follow.follower_uri = svc.actorUri("alice");
    follow.followee_uri = remote.uri;
    follow.state = FollowState::ACCEPTED;
    EXPECT_TRUE(mw::isExpected(db->addFollow(follow)));

    NewPost np;
    np.uri = "https://activitypub.academy/statuses/1";
    np.remote_author_id = remote.id;
    np.content_html = "<p>remote status</p>";
    np.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(auto post, db->insertPost(
        np, {{0, std::string(AS_PUBLIC), "to"}}, "https://f.test/p/"));

    ASSIGN_OR_FAIL(auto timeline, svc.homeTimeline(alice, Cursor{}));
    std::vector<int64_t> ids;
    for(const auto& item : timeline) ids.push_back(item.id);
    EXPECT_NE(std::find(ids.begin(), ids.end(), post.id), ids.end());
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

TEST(ServiceAuthz, UserCanViewRemoteFollowersPostWhenAddressed)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(NewUser{
        "alice", "Alice", "", "iss", "sub-a", "PRIV", "PUB"}));
    ASSIGN_OR_FAIL(auto remote, db->upsertRemoteActor(RemoteActor{
        0,
        "https://remote.test/users/bob",
        "bob",
        "remote.test",
        "Bob",
        "https://remote.test/users/bob/inbox",
        std::optional<std::string>("https://remote.test/inbox"),
        "PUB",
        "https://remote.test/users/bob#main-key",
        "{}",
        0,
    }));
    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);

    NewPost np;
    np.remote_author_id = remote.id;
    np.content_html = "<p>private hello</p>";
    np.visibility = Visibility::FOLLOWERS;
    ASSIGN_OR_FAIL(Post post, db->insertPost(
        np, {{0, svc.actorUri("alice"), "to"}}, "https://f.test/p/"));

    ASSIGN_OR_FAIL(bool allowed, svc.canViewPost(post, alice));
    EXPECT_TRUE(allowed);
    ASSIGN_OR_FAIL(bool denied, svc.canActorViewPost(
        post, "https://remote.test/users/eve"));
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

TEST(Render, ExtractsMentionsAndHashtagsFromMacrodownTree)
{
    EmojiRegistry emoji;
    RenderedPostContent parsed = parsePostContent(
        "hi @bob @bob@f.test @bob #Cpp #cpp", emoji);

    ASSERT_EQ(parsed.mentions.size(), 2u);
    EXPECT_EQ(parsed.mentions[0].name, "@bob");
    EXPECT_EQ(parsed.mentions[0].username, "bob");
    EXPECT_EQ(parsed.mentions[0].domain, "");
    EXPECT_EQ(parsed.mentions[1].name, "@bob@f.test");
    EXPECT_EQ(parsed.mentions[1].username, "bob");
    EXPECT_EQ(parsed.mentions[1].domain, "f.test");
    ASSERT_EQ(parsed.hashtags.size(), 1u);
    EXPECT_EQ(parsed.hashtags[0].name, "#Cpp");
    EXPECT_NE(parsed.html.find("class=\"mention\""), std::string::npos);
    EXPECT_NE(parsed.html.find("class=\"hashtag\""), std::string::npos);
}

TEST(Render, SanitizesRemoteHtmlWithAllowlist)
{
    std::string dirty =
        "<p onclick=\"bad()\">hi <strong>there</strong> "
        "<a href=\"javascript:alert(1)\">bad</a>"
        "<a href=\"https://remote.test/x\" onclick=\"bad()\">ok</a>"
        "<span class=\"mention\" data-x=\"1\">@bob</span>"
        "<span class=\"evil\">x</span>"
        "<script>alert(1)</script><img src=x onerror=bad()></p>";

    EXPECT_EQ(sanitizeRemoteHtml(dirty),
              "<p>hi <strong>there</strong> bad"
              "<a href=\"https://remote.test/x\" "
              "rel=\"nofollow noopener noreferrer\">ok</a>"
              "<span class=\"mention\">@bob</span><span>x</span></p>");
}

TEST(ServicePosting, LocalMentionsBecomeRecipients)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(NewUser{
        "alice", "Alice", "", "iss", "sub-a", "PRIV", "PUB"}));
    ASSIGN_OR_FAIL(User bob, db->createUser(NewUser{
        "bob", "Bob", "", "iss", "sub-b", "PRIV", "PUB"}));
    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);

    ComposeParams cp;
    cp.source = "hello @bob and @carol";
    cp.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(Post post, svc.createPost(alice, cp));
    ASSIGN_OR_FAIL(auto recipients, db->getPostRecipients(post.id));

    EXPECT_EQ(recipient(recipients, "https://f.test/u/bob"), "to");
    EXPECT_EQ(recipient(recipients, "https://f.test/u/carol"), "");
    (void)bob;
}

TEST(ServicePosting, DirectPostUsesLocalMentionRecipients)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(NewUser{
        "alice", "Alice", "", "iss", "sub-a", "PRIV", "PUB"}));
    ASSIGN_OR_FAIL(User bob, db->createUser(NewUser{
        "bob", "Bob", "", "iss", "sub-b", "PRIV", "PUB"}));
    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);

    ComposeParams cp;
    cp.source = "psst @bob@f.test";
    cp.visibility = Visibility::DIRECT;
    ASSIGN_OR_FAIL(Post post, svc.createPost(alice, cp));
    ASSIGN_OR_FAIL(auto recipients, db->getPostRecipients(post.id));

    EXPECT_EQ(recipients.size(), 1u);
    EXPECT_EQ(recipient(recipients, "https://f.test/u/bob"), "to");
    (void)bob;
}

TEST(ServicePosting, DirectPostUsesPreResolvedRemoteMentionRecipients)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(NewUser{
        "alice", "Alice", "", "iss", "sub-a", "PRIV", "PUB"}));
    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);

    ComposeParams cp;
    cp.source = "psst @bob@remote.test";
    cp.visibility = Visibility::DIRECT;
    cp.mentioned_actor_uris = {"https://remote.test/u/bob"};
    ASSIGN_OR_FAIL(Post post, svc.createPost(alice, cp));
    ASSIGN_OR_FAIL(auto recipients, db->getPostRecipients(post.id));

    EXPECT_EQ(recipients.size(), 1u);
    EXPECT_EQ(recipient(recipients, "https://remote.test/u/bob"), "to");
}

TEST(ServiceView, RemoteCustomEmojiReactionRendersImage)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(NewUser{
        "alice", "Alice", "", "iss", "sub-a", "PRIV", "PUB"}));
    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);

    NewPost np;
    np.local_author_id = alice.id;
    np.content_html = "<p>post</p>";
    np.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(Post post, db->insertPost(
        np, svc.recipientsFor(Visibility::PUBLIC, "alice", {}),
        "https://f.test/p/"));
    Reaction reaction;
    reaction.actor_uri = "https://remote.test/u/bob";
    reaction.post_uri = post.uri;
    reaction.emoji = ":blobcat:";
    reaction.remote_emoji_url = "https://remote.test/e/blobcat.png";
    reaction.remote_emoji_media_type = "image/png";
    EXPECT_TRUE(db->addReaction(reaction).has_value());

    ASSIGN_OR_FAIL(auto view, svc.postView(post, std::nullopt));
    ASSERT_EQ(view["reactions"].size(), 1u);
    EXPECT_EQ(view["reactions"][0]["emoji"], ":blobcat:");
    EXPECT_NE(view["reactions"][0]["emoji_html"].get<std::string>().find(
                  "https://remote.test/e/blobcat.png"),
              std::string::npos);
}

TEST(ServiceView, RemotePostShowsRemoteAuthor)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);

    RemoteActor remote;
    remote.uri = "https://remote.test/users/bob";
    remote.username = "bob";
    remote.domain = "remote.test";
    remote.display_name = "Bob Remote";
    remote.inbox = "https://remote.test/users/bob/inbox";
    remote.public_key_pem = "PUB";
    remote.public_key_id = remote.uri + "#main-key";
    remote.actor_json = "{}";
    ASSIGN_OR_FAIL(remote, db->upsertRemoteActor(remote));

    NewPost np;
    np.uri = "https://remote.test/users/bob/statuses/1";
    np.remote_author_id = remote.id;
    np.content_html = "<p>remote reply</p>";
    np.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(Post post, db->insertPost(
        np, {{0, std::string(AS_PUBLIC), "to"}}, "https://f.test/p/"));

    ASSIGN_OR_FAIL(auto view, svc.postView(post, std::nullopt));
    EXPECT_EQ(view["author"]["username"], "bob");
    EXPECT_EQ(view["author"]["display_name"], "Bob Remote");
    EXPECT_EQ(view["author"]["handle"], "@bob@remote.test");
    EXPECT_EQ(view["author"]["profile_url"], remote.uri);
    EXPECT_FALSE(view["author"]["is_local"]);
}
