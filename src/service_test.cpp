#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <mw/error.hpp>
#include <mw/test_utils.hpp>
#include <inja.hpp>

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

TEST(ServiceProfile, FollowListsRenderLocalRemoteAndMissingAccounts)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto alice, db->createUser(NewUser{
        "alice", "Alice <Local>", "", "iss", "sub-a", "PRIV", "PUB"}));
    Config c = testConfig();
    c.url_root = "https://f.test/social/";
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);
    RemoteActor remote;
    remote.uri = "https://remote.test/users/bob";
    remote.username = "bob";
    remote.domain = "remote.test";
    remote.display_name = "Bob <Remote>";
    remote.actor_json = "{}";
    ASSIGN_OR_FAIL(auto stored, db->upsertRemoteActor(remote));
    ASSIGN_OR_FAIL(auto views, svc.followViews({
        {4, svc.actorUri("alice")}, {3, stored.uri},
        {2, "https://missing.test/user?a=1&b=2"},
        {1, "javascript:alert(1)"}}));
    ASSERT_EQ(views.size(), 4);
    EXPECT_EQ(views[0]["profile_url"], svc.actorUri("alice"));
    EXPECT_EQ(views[0]["display_name"], "Alice &lt;Local&gt;");
    EXPECT_EQ(views[1]["handle"], "@bob@remote.test");
    EXPECT_EQ(views[1]["display_name"], "Bob &lt;Remote&gt;");
    EXPECT_EQ(views[2]["profile_url"],
              "https://missing.test/user?a=1&amp;b=2");
    EXPECT_EQ(views[3]["profile_url"], "");
    EXPECT_EQ(views[0]["actor_uri"], svc.actorUri("alice"));
    EXPECT_EQ(views[1]["actor_uri"], stored.uri);
    EXPECT_EQ(views[2]["actor_uri"],
              "https://missing.test/user?a=1&amp;b=2");

    ASSIGN_OR_FAIL(auto profile, svc.userView(alice));
    nlohmann::json ctx = {
        {"site", {{"title", "Test"}, {"root", c.url_root},
                  {"commit", "test"}}},
        {"logged_in", false}, {"error", ""}, {"profile", profile},
        {"results", views}, {"list_title", "Followers"},
        {"list_url", svc.actorUri("alice") + "/followers"},
        {"has_previous", true}, {"has_next", true},
        {"can_unfollow", false},
        {"previous_id", 4}, {"next_id", 1},
    };
    inja::Environment templates("templates/");
    auto html = templates.render_file("follow_list.html", ctx);
    EXPECT_NE(html.find("Alice &lt;Local&gt;"), std::string::npos);
    EXPECT_NE(html.find("/social/u/alice/followers?max_id=1"),
              std::string::npos);
    EXPECT_NE(html.find("/social/u/alice/followers?min_id=4"),
              std::string::npos);
    EXPECT_EQ(html.find(">unfollow</button>"), std::string::npos);

    ctx["logged_in"] = true;
    ctx["me"] = {{"username", "alice"}, {"handle", "@alice@f.test"}};
    ctx["csrf"] = "test-csrf";
    ctx["can_unfollow"] = true;
    html = templates.render_file("follow_list.html", ctx);
    EXPECT_NE(html.find(">unfollow</button>"), std::string::npos);
    EXPECT_NE(html.find("action=\"https://f.test/social/follow\""),
              std::string::npos);
    EXPECT_NE(html.find("name=\"csrf\" value=\"test-csrf\""),
              std::string::npos);
    EXPECT_NE(html.find("name=\"undo\" value=\"1\""), std::string::npos);
    EXPECT_NE(html.find("name=\"actor_uri\" value=\"" + stored.uri + "\""),
              std::string::npos);
    EXPECT_NE(html.find("name=\"actor_uri\" value=\""
                        "https://missing.test/user?a=1&amp;b=2\""),
              std::string::npos);

    ctx["can_unfollow"] = false;
    html = templates.render_file("follow_list.html", ctx);
    EXPECT_EQ(html.find(">unfollow</button>"), std::string::npos);
    ctx["logged_in"] = false;
    ctx["results"] = nlohmann::json::array();
    ctx["has_previous"] = false;
    ctx["has_next"] = false;
    html = templates.render_file("follow_list.html", ctx);
    EXPECT_NE(html.find("No accounts to show."), std::string::npos);
    EXPECT_EQ(html.find("?max_id="), std::string::npos);
    ctx["posts"] = nlohmann::json::array();
    html = templates.render_file("profile.html", ctx);
    EXPECT_NE(html.find("/social/u/alice/followers\""),
              std::string::npos);
    EXPECT_NE(html.find("/social/u/alice/following\""),
              std::string::npos);
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

TEST(ServiceAuthz, RemoteFollowersCollectionRequiresAcceptedFollow)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto alice, db->createUser(NewUser{
        "alice", "Alice", "", "iss", "sub-a", "PRIV", "PUB"}));
    RemoteActor remote;
    remote.uri = "https://remote.test/users/bob";
    remote.username = "bob";
    remote.domain = "remote.test";
    remote.inbox = remote.uri + "/inbox";
    remote.public_key_pem = "PUB";
    remote.public_key_id = remote.uri + "#main-key";
    const std::string followers = "https://remote.test/collections/bob";
    remote.actor_json = nlohmann::json({{"followers", followers}}).dump();
    ASSIGN_OR_FAIL(auto author, db->upsertRemoteActor(remote));
    Config config = testConfig();
    EmojiRegistry emoji;
    Service svc(config, *db, emoji);
    NewPost incoming;
    incoming.uri = "https://remote.test/statuses/1";
    incoming.remote_author_id = author.id;
    incoming.content_html = "followers only";
    incoming.visibility = Visibility::FOLLOWERS;
    ASSIGN_OR_FAIL(auto post, db->insertPost(
        incoming, {{0, followers, "to"}}, "https://f.test/p/"));
    Follow follow;
    follow.follower_uri = svc.actorUri("alice");
    follow.followee_uri = author.uri;
    EXPECT_TRUE(mw::isExpected(db->addFollow(follow)));
    ASSIGN_OR_FAIL(bool pending, svc.canViewPost(post, alice));
    EXPECT_FALSE(pending);
    EXPECT_TRUE(mw::isExpected(db->setFollowState(
        follow.follower_uri, follow.followee_uri, FollowState::ACCEPTED)));
    ASSIGN_OR_FAIL(bool accepted, svc.canViewPost(post, alice));
    EXPECT_TRUE(accepted);
    ASSIGN_OR_FAIL(auto timeline, svc.homeTimeline(alice, Cursor{}));
    ASSERT_EQ(timeline.size(), 1u);
    EXPECT_EQ(timeline.front().id, post.id);
    ASSIGN_OR_FAIL(bool stranger, svc.canActorViewPost(
        post, "https://f.test/u/eve"));
    EXPECT_FALSE(stranger);
    Post direct = post;
    direct.visibility = Visibility::DIRECT;
    ASSIGN_OR_FAIL(bool direct_allowed, svc.canViewPost(direct, alice));
    EXPECT_FALSE(direct_allowed);
    EXPECT_TRUE(mw::isExpected(db->removeFollow(
        follow.follower_uri, follow.followee_uri)));
    ASSIGN_OR_FAIL(bool unfollowed, svc.canViewPost(post, alice));
    EXPECT_FALSE(unfollowed);
    ASSIGN_OR_FAIL(auto after_unfollow, svc.homeTimeline(alice, Cursor{}));
    EXPECT_TRUE(after_unfollow.empty());
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

TEST(ServiceView, LocalPostUsesAvatarOrDefaultAvatar)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(NewUser{
        "alice", "Alice", "", "iss", "sub-a", "PRIV", "PUB"}));
    ASSIGN_OR_FAIL(User bob, db->createUser(NewUser{
        "bob", "Bob", "", "iss", "sub-b", "PRIV", "PUB"}));

    Attachment avatar;
    avatar.sha256 = "abc001";
    avatar.extension = "png";
    avatar.media_type = "image/png";
    avatar.original_name = "avatar.png";
    avatar.is_image = true;
    ASSIGN_OR_FAIL(int64_t avatar_id, db->insertAttachment(avatar));

    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);
    UserProfileUpdate update;
    update.display_name = "Alice";
    update.avatar_attachment_id = avatar_id;
    EXPECT_TRUE(mw::isExpected(svc.updateProfile(alice, update)));

    NewPost alice_new;
    alice_new.local_author_id = alice.id;
    alice_new.content_html = "<p>alice</p>";
    alice_new.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(Post alice_post, db->insertPost(
        alice_new, svc.recipientsFor(Visibility::PUBLIC, "alice", {}),
        "https://f.test/p/"));

    NewPost bob_new;
    bob_new.local_author_id = bob.id;
    bob_new.content_html = "<p>bob</p>";
    bob_new.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(Post bob_post, db->insertPost(
        bob_new, svc.recipientsFor(Visibility::PUBLIC, "bob", {}),
        "https://f.test/p/"));

    ASSIGN_OR_FAIL(auto views, svc.postViews(
        std::vector<Post>{alice_post, bob_post}, std::nullopt));
    EXPECT_EQ(views[0]["author"]["avatar_url"],
              "https://f.test/media/a/abc001.png");
    EXPECT_FALSE(views[0]["author"]["avatar_is_placeholder"]);
    EXPECT_EQ(views[1]["author"]["avatar_url"],
              "https://f.test/static/default_avatar.svg");
    EXPECT_TRUE(views[1]["author"]["avatar_is_placeholder"]);
}

TEST(ServiceView, InvalidLocalAvatarUsesDefaultAvatar)
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
    EXPECT_TRUE(mw::isExpected(db->updateProfileMedia(
        alice.id, remote_id, std::nullopt)));

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

    ASSIGN_OR_FAIL(auto view, svc.postView(post, std::nullopt));
    EXPECT_EQ(view["author"]["avatar_url"],
              "https://f.test/static/default_avatar.svg");
    EXPECT_TRUE(view["author"]["avatar_is_placeholder"]);
}

TEST(ServiceView, MissingLocalAvatarAttachmentUsesDefaultAvatar)
{
    DataSourceMock data;
    User alice;
    alice.id = 1;
    alice.username = "alice";
    alice.display_name = "Alice";
    alice.avatar_attachment_id = 404;

    Post post;
    post.id = 1;
    post.uri = "https://f.test/p/1";
    post.local_author_id = alice.id;
    post.content_html = "<p>post</p>";

    EXPECT_CALL(data, getUserById(alice.id))
        .WillOnce(testing::Return(
            mw::E<std::optional<User>>{std::optional<User>{alice}}));
    EXPECT_CALL(data, getAttachmentById(404))
        .WillOnce(testing::Return(
            mw::E<std::optional<Attachment>>{
                std::optional<Attachment>{}}));
    EXPECT_CALL(data, attachmentsForPost(post.id))
        .WillOnce(testing::Return(
            mw::E<std::vector<Attachment>>{std::vector<Attachment>{}}));
    EXPECT_CALL(data, likesForPost(post.uri))
        .WillOnce(testing::Return(
            mw::E<std::vector<Like>>{std::vector<Like>{}}));
    EXPECT_CALL(data, boostsForPost(post.uri))
        .WillOnce(testing::Return(
            mw::E<std::vector<Boost>>{std::vector<Boost>{}}));
    EXPECT_CALL(data, reactionsForPost(post.uri))
        .WillOnce(testing::Return(
            mw::E<std::vector<Reaction>>{std::vector<Reaction>{}}));

    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, data, emoji);
    ASSIGN_OR_FAIL(auto view, svc.postView(post, std::nullopt));
    EXPECT_EQ(view["author"]["avatar_url"],
              "https://f.test/static/default_avatar.svg");
    EXPECT_TRUE(view["author"]["avatar_is_placeholder"]);
}

TEST(ServiceView, RemoteAuthorUsesValidatedIconUrlAndHref)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);

    RemoteActor remote;
    remote.uri = "https://remote.test/users/bob";
    remote.username = "bob";
    remote.domain = "remote.test";
    remote.display_name = "Bob";
    remote.inbox = "https://remote.test/users/bob/inbox";
    remote.public_key_pem = "PUB";
    remote.public_key_id = remote.uri + "#main-key";
    remote.actor_json = R"json({
        "icon": [
            {"url": "javascript:alert(1)"},
            {"href": "  https://cdn.test/avatar.png?x=1&y=2  "}
        ]
    })json";
    ASSIGN_OR_FAIL(remote, db->upsertRemoteActor(remote));

    NewPost np;
    np.remote_author_id = remote.id;
    np.uri = "https://remote.test/users/bob/statuses/1";
    np.content_html = "<p>remote</p>";
    np.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(Post post, db->insertPost(
        np, {{0, std::string(AS_PUBLIC), "to"}}, "https://f.test/p/"));

    ASSIGN_OR_FAIL(auto view, svc.postView(post, std::nullopt));
    EXPECT_EQ(view["author"]["avatar_url"],
              "https://cdn.test/avatar.png?x=1&amp;y=2");
    EXPECT_FALSE(view["author"]["avatar_is_placeholder"]);
}

TEST(ServiceView, RemoteAuthorMalformedIconUsesDefaultAvatar)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);

    RemoteActor remote;
    remote.uri = "https://remote.test/users/bob";
    remote.username = "bob";
    remote.domain = "remote.test";
    remote.inbox = "https://remote.test/users/bob/inbox";
    remote.public_key_pem = "PUB";
    remote.public_key_id = remote.uri + "#main-key";
    remote.actor_json = R"({"icon": {"url": "ftp://remote.test/a"}})";
    ASSIGN_OR_FAIL(remote, db->upsertRemoteActor(remote));

    NewPost np;
    np.remote_author_id = remote.id;
    np.uri = "https://remote.test/users/bob/statuses/1";
    np.content_html = "<p>remote</p>";
    np.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(Post post, db->insertPost(
        np, {{0, std::string(AS_PUBLIC), "to"}}, "https://f.test/p/"));

    ASSIGN_OR_FAIL(auto view, svc.postView(post, std::nullopt));
    EXPECT_EQ(view["author"]["avatar_url"],
              "https://f.test/static/default_avatar.svg");
    EXPECT_TRUE(view["author"]["avatar_is_placeholder"]);
}

TEST(ServiceView, RemoteAuthorMalformedJsonUsesDefaultAvatar)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);

    RemoteActor remote;
    remote.uri = "https://remote.test/users/bob";
    remote.username = "bob";
    remote.domain = "remote.test";
    remote.inbox = "https://remote.test/users/bob/inbox";
    remote.public_key_pem = "PUB";
    remote.public_key_id = remote.uri + "#main-key";
    remote.actor_json = "{";
    ASSIGN_OR_FAIL(remote, db->upsertRemoteActor(remote));

    NewPost np;
    np.remote_author_id = remote.id;
    np.uri = "https://remote.test/users/bob/statuses/1";
    np.content_html = "<p>remote</p>";
    np.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(Post post, db->insertPost(
        np, {{0, std::string(AS_PUBLIC), "to"}}, "https://f.test/p/"));

    ASSIGN_OR_FAIL(auto view, svc.postView(post, std::nullopt));
    EXPECT_EQ(view["author"]["avatar_url"],
              "https://f.test/static/default_avatar.svg");
    EXPECT_TRUE(view["author"]["avatar_is_placeholder"]);
}

TEST(ServiceView, UnknownAuthorUsesDefaultAvatar)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    Config c = testConfig();
    EmojiRegistry emoji;
    Service svc(c, *db, emoji);

    NewPost np;
    np.content_html = "<p>unknown</p>";
    np.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(Post post, db->insertPost(
        np, {{0, std::string(AS_PUBLIC), "to"}}, "https://f.test/p/"));

    ASSIGN_OR_FAIL(auto view, svc.postView(post, std::nullopt));
    EXPECT_EQ(view["author"]["display_name"], "unknown");
    EXPECT_EQ(view["author"]["avatar_url"],
              "https://f.test/static/default_avatar.svg");
    EXPECT_TRUE(view["author"]["avatar_is_placeholder"]);
}

// Exercise each interaction's identity across idempotent writes and Undo.
class ServiceInteractionIdentity : public ::testing::TestWithParam<int>
{
protected:
    mw::E<void> set(const Service& svc, const User& user, const Post& post,
                    bool on) const
    {
        switch(GetParam())
        {
        case 0: return svc.setLike(user, post, on);
        case 1: return svc.setBoost(user, post, on);
        default: return svc.setReaction(user, post, "👍", on);
        }
    }

    mw::E<std::optional<std::string>> activityUri(
        const DataSourceSQLite& db, const Post& post) const
    {
        switch(GetParam())
        {
        case 0:
        {
            ASSIGN_OR_RETURN(auto rows, db.likesForPost(post.uri));
            if(rows.empty()) return std::nullopt;
            return rows.front().activity_uri;
        }
        case 1:
        {
            ASSIGN_OR_RETURN(auto rows, db.boostsForPost(post.uri));
            if(rows.empty()) return std::nullopt;
            return rows.front().activity_uri;
        }
        default:
        {
            ASSIGN_OR_RETURN(auto rows, db.reactionsForPost(post.uri));
            if(rows.empty()) return std::nullopt;
            return rows.front().activity_uri;
        }
        }
    }
};

TEST_P(ServiceInteractionIdentity, RecreatedInteractionGetsFreshActivityId)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto alice, db->createUser(NewUser{
        "alice", "Alice", "", "iss", "sub-a", "PRIV", "PUB"}));
    Config config = testConfig();
    EmojiRegistry emoji;
    Service svc(config, *db, emoji);
    ComposeParams params;
    params.source = "public post";
    ASSIGN_OR_FAIL(auto post, svc.createPost(alice, params));

    EXPECT_TRUE(set(svc, alice, post, true).has_value());
    ASSIGN_OR_FAIL(auto first_uri, activityUri(*db, post));
    ASSERT_TRUE(first_uri.has_value());
    EXPECT_TRUE(first_uri->starts_with(config.url_root + "activities/"));

    // A repeated enable keeps the persisted ID used by outbound delivery.
    EXPECT_TRUE(set(svc, alice, post, true).has_value());
    ASSIGN_OR_FAIL(auto repeated_uri, activityUri(*db, post));
    EXPECT_EQ(first_uri, repeated_uri);

    EXPECT_TRUE(set(svc, alice, post, false).has_value());
    ASSIGN_OR_FAIL(auto removed_uri, activityUri(*db, post));
    EXPECT_FALSE(removed_uri.has_value());
    EXPECT_TRUE(set(svc, alice, post, true).has_value());
    ASSIGN_OR_FAIL(auto second_uri, activityUri(*db, post));
    ASSERT_TRUE(second_uri.has_value());
    EXPECT_NE(first_uri, second_uri);

    EXPECT_TRUE(set(svc, alice, post, false).has_value());
    EXPECT_TRUE(set(svc, alice, post, true).has_value());
    ASSIGN_OR_FAIL(auto third_uri, activityUri(*db, post));
    ASSERT_TRUE(third_uri.has_value());
    EXPECT_NE(first_uri, third_uri);
    EXPECT_NE(second_uri, third_uri);
}

INSTANTIATE_TEST_SUITE_P(LikeBoostReaction, ServiceInteractionIdentity,
                         ::testing::Values(0, 1, 2));

TEST(Render, RemoteHtmlDecodesEntitiesAndEscapesOnce)
{
    EXPECT_EQ(sanitizeRemoteHtml(
        "<p>A &amp; B &#38; C &#x1F600; &copy; &NotEqualTilde;</p>"),
        "<p>A &amp; B &amp; C 😀 © ≂̸</p>");
    EXPECT_EQ(sanitizeRemoteHtml("&lt;script&gt; &amp;amp; &unknown;"),
              "&lt;script&gt; &amp;amp; &amp;unknown;");
    EXPECT_EQ(sanitizeRemoteHtml(
        "<a href='https://remote.test/?a=1&amp;b=2'>link</a>"),
        "<a href=\"https://remote.test/?a=1&amp;b=2\" "
        "rel=\"nofollow noopener noreferrer\">link</a>");
}

TEST(Render, RemoteHtmlHandlesQuotedAnglesAndEmojiAttributes)
{
    EXPECT_EQ(sanitizeRemoteHtml(
        "<img class='emoji' src='https://remote.test/e?a=1&amp;b=2' "
        "alt='a > b &quot; c' title='A &amp; B' onerror='bad()'>"),
        "<img class=\"emoji\" src=\"https://remote.test/e?a=1&amp;b=2\" "
        "alt=\"a &gt; b &quot; c\" title=\"A &amp; B\">");
}

TEST(Render, RemoteHtmlRejectsEncodedUnsafeUrls)
{
    EXPECT_EQ(sanitizeRemoteHtml(
        "<a href='java&#x73;cript:alert(1)'>one</a>"
        "<a href='java&#9;script:alert(1)'>two</a>"
        "<a href='&#100;ata:text/html,bad'>three</a>"
        "<img class='emoji' src='javascript:bad()'>"
        "<img class='emoji' src='data:image/svg+xml,bad'>"),
        "onetwothree");
}

TEST(Render, RemoteHtmlPreservesFragmentsWhitespaceAndUtf8)
{
    EXPECT_EQ(sanitizeRemoteHtml(""), "");
    EXPECT_EQ(sanitizeRemoteHtml("hello café 世界 😀"), "hello café 世界 😀");
    EXPECT_EQ(sanitizeRemoteHtml("before <b>bold</b> after<br>tail"),
              "before <b>bold</b> after<br>tail");
    EXPECT_EQ(sanitizeRemoteHtml("<pre>  a\n b\t&amp;\n</pre>"),
              "<pre>  a\n b\t&amp;\n</pre>");
}

TEST(Render, RemoteHtmlRepairsNestingAndDropsActiveContent)
{
    EXPECT_EQ(sanitizeRemoteHtml("<p><strong>bold"),
              "<p><strong>bold</strong></p>");
    EXPECT_EQ(sanitizeRemoteHtml("<b>one</b><i>two</i>"),
              "<b>one</b><i>two</i>");
    EXPECT_EQ(sanitizeRemoteHtml(
        "<div>before<!-- comment --><script>bad()</script>"
        "<style>bad{}</style><span onclick='bad()'>after</span></div>"),
        "before<span>after</span>");
    std::string clean = sanitizeRemoteHtml(
        "<p>A &amp; B <a href='https://remote.test/?a=1&amp;b=2'>"
        "link</a><img class='emoji' src='/emoji/a.png' alt='&quot;'></p>");
    EXPECT_EQ(sanitizeRemoteHtml(clean), clean);
}

TEST(ServiceView, PagesDeferEmojiCatalogUntilPickerOpens)
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
    ASSIGN_OR_FAIL(auto post, db->insertPost(
        np, svc.recipientsFor(Visibility::PUBLIC, "alice", {}),
        "https://f.test/p/"));
    ASSIGN_OR_FAIL(auto view, svc.postView(post, alice));

    nlohmann::json ctx = {
        {"site", {{"title", "Test"}, {"root", "/"}, {"commit", "test"}}},
        {"logged_in", true}, {"error", ""}, {"csrf", "test-csrf"},
        {"me", {{"username", "alice"}, {"handle", "@alice@f.test"}}},
        {"timeline", "home"}, {"has_more", false}, {"focus_id", 0},
        {"posts", nlohmann::json::array()},
    };
    for(int i = 0; i < 20; ++i) ctx["posts"].push_back(view);
    inja::Environment templates("templates/");
    auto html = templates.render_file("index.html", ctx);
    const std::string catalog = "id=\"emoji-picker\"";
    auto first = html.find(catalog);
    ASSERT_NE(first, std::string::npos);
    EXPECT_EQ(html.find(catalog, first + catalog.size()), std::string::npos);
    EXPECT_NE(html.find("data-catalog-url=\"/emoji_catalog.json\""),
              std::string::npos);
    EXPECT_EQ(html.find("emoji-choice"), std::string::npos);
    EXPECT_EQ(html.find("emoji-tab"), std::string::npos);
    EXPECT_NE(html.find("name=\"emoji\" value=\"\""), std::string::npos);
    EXPECT_NE(html.find("name=\"csrf\" value=\"test-csrf\""),
              std::string::npos);

    ctx["reply_to_id"] = post.id;
    ctx["reply_prefill"] = "@alice ";
    html = templates.render_file("thread.html", ctx);
    first = html.find(catalog);
    ASSERT_NE(first, std::string::npos);
    EXPECT_EQ(html.find(catalog, first + catalog.size()), std::string::npos);
    EXPECT_EQ(html.find("emoji-choice"), std::string::npos);

    ctx["logged_in"] = false;
    html = templates.render_file("index.html", ctx);
    EXPECT_EQ(html.find(catalog), std::string::npos);

    ctx["logged_in"] = true;
    ctx["post_results"] = ctx["posts"];
    ctx.erase("posts");
    ctx["query"] = "post URL";
    ctx["has_no_results"] = false;
    ctx["results"] = nlohmann::json::array();
    html = templates.render_file("search.html", ctx);
    first = html.find(catalog);
    ASSERT_NE(first, std::string::npos);
    EXPECT_EQ(html.find(catalog, first + catalog.size()), std::string::npos);
}

TEST(ServiceTimeline, RendersFollowedLocalBoostWithEscapedAttribution)
{
    ASSIGN_OR_FAIL(auto data,DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto viewer,data->createUser(NewUser{
        "viewer","Viewer","","iss","viewer","PRIV","PUB"}));
    ASSIGN_OR_FAIL(auto booster,data->createUser(NewUser{
        "booster","<Bob & Co>","","iss","booster","PRIV","PUB"}));
    ASSIGN_OR_FAIL(auto stranger,data->createUser(NewUser{
        "stranger","Stranger","","iss","stranger","PRIV","PUB"}));
    Config config = testConfig();
    EmojiRegistry emoji;
    Service service(config,*data,emoji);
    ASSERT_TRUE(data->addFollow({0,service.actorUri(viewer.username),
        service.actorUri(booster.username),FollowState::ACCEPTED,
        std::nullopt,100}));
    ComposeParams input;
    input.source = "A post from somebody else";
    ASSIGN_OR_FAIL(auto post,service.createPost(stranger,input));
    ASSERT_TRUE(service.setBoost(booster,post,true));
    ASSIGN_OR_FAIL(auto timeline,service.homeTimeline(viewer,{}));
    ASSERT_EQ(timeline.size(),1u);
    ASSIGN_OR_FAIL(auto view,service.postView(timeline.front(),viewer));
    EXPECT_TRUE(view["is_boost"].get<bool>());
    EXPECT_EQ(view["boosted_by"]["display_name"],"&lt;Bob &amp; Co&gt;");
    inja::Environment environment("templates/");
    auto html = environment.render_file("_post.html",{
        {"post",view},{"focus_id",0},{"logged_in",false},
        {"site",{{"root",config.url_root}}}});
    EXPECT_NE(html.find("class=\"boost-attribution\""),std::string::npos);
    EXPECT_NE(html.find("&lt;Bob &amp; Co&gt;"),std::string::npos);
    EXPECT_NE(html.find("A post from somebody else"),std::string::npos);
    EXPECT_EQ(html.find("<Bob & Co>"),std::string::npos);
}
