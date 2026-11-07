#include <filesystem>
#include <string>

#include <gtest/gtest.h>
#include <inja.hpp>
#include <mw/test_utils.hpp>
#include <mw/utils.hpp>

#include "data.hpp"
#include "service.hpp"

using namespace unspoken;

namespace
{

class Notifications : public ::testing::Test
{
protected:
    static constexpr int64_t NOW = 3000000;
    std::unique_ptr<DataSourceSQLite> data;
    Config config;
    EmojiRegistry emoji;
    std::unique_ptr<Service> service;
    User alice;
    User bob;
    Post post;

    void SetUp() override
    {
        ASSIGN_OR_FAIL(data, DataSourceSQLite::newFromMemory());
        config.url_root = "https://local.test/social/";
        ASSIGN_OR_FAIL(alice, data->createUser(NewUser{
            "alice", "Alice", "", "iss", "alice", "PRIV", "PUB"}));
        ASSIGN_OR_FAIL(bob, data->createUser(NewUser{
            "bob", "Bob <script>", "", "iss", "bob", "PRIV", "PUB"}));
        service = std::make_unique<Service>(config, *data, emoji);
        ComposeParams params;
        params.source = "A & B";
        ASSIGN_OR_FAIL(post, service->createPost(alice, params));
    }

    mw::E<void> addLike(int index, int64_t timestamp = NOW)
    {
        std::string actor = "https://remote.test/actor/" + std::to_string(index);
        Like like;
        like.actor_uri = actor;
        like.post_uri = post.uri;
        like.created_at = timestamp;
        DO_OR_RETURN(data->addLike(like));
        return service->notifyInteraction(NotificationKind::LIKE,
            actor, post.uri, timestamp);
    }

    int64_t currentTime() const
    {
        return mw::timeToSeconds(mw::Clock::now());
    }
};

TEST_F(Notifications, LocalInteractionsLinkToTheirOwnerAndSource)
{
    ASSERT_TRUE(service->setLike(bob, post, true));
    ASSERT_TRUE(service->setBoost(bob, post, true));
    ASSERT_TRUE(service->setReaction(bob, post, "❤️", true));
    ASSERT_TRUE(service->setFollow(bob, "alice", true));
    ComposeParams params;
    params.source = "A reply";
    params.in_reply_to_uri = post.uri;
    ASSIGN_OR_FAIL(auto reply, service->createPost(bob, params));
    ASSIGN_OR_FAIL(auto entries, data->notificationsFor(alice.id, currentTime()));
    ASSERT_EQ(entries.size(), 5u);
    EXPECT_EQ(entries[0].kind, NotificationKind::REPLY);
    EXPECT_EQ(entries[0].reply_post_id, reply.id);
    EXPECT_EQ(entries[1].kind, NotificationKind::FOLLOW);
    EXPECT_EQ(entries[2].kind, NotificationKind::REACTION);
    EXPECT_EQ(entries[3].kind, NotificationKind::BOOST);
    EXPECT_EQ(entries[4].kind, NotificationKind::LIKE);
    EXPECT_TRUE(data->notificationsFor(bob.id, currentTime())->empty());
    ASSIGN_OR_FAIL(auto page, service->notificationPage(alice, {}, currentTime()));
    EXPECT_EQ(page["entries"][0]["actor"]["display_name"],
              "Bob &lt;script&gt;");
    EXPECT_EQ(page["entries"][0]["actor"]["profile_url"],
              service->actorUri("bob"));
    EXPECT_EQ(page["entries"][0]["post"]["url"], post.uri);
    EXPECT_EQ(page["entries"][0]["reply"]["url"], reply.uri);
    EXPECT_EQ(page["entries"][2]["emoji"], "❤️");
}

TEST_F(Notifications, SelfActionsAndBookmarksDoNotNotify)
{
    ASSERT_TRUE(service->setLike(alice, post, true));
    ASSERT_TRUE(service->setBoost(alice, post, true));
    ASSERT_TRUE(service->setReaction(alice, post, "❤️", true));
    ASSERT_TRUE(service->setBookmark(bob, post, true));
    ComposeParams params;
    params.source = "self reply";
    params.in_reply_to_uri = post.uri;
    ASSERT_TRUE(service->createPost(alice, params));
    EXPECT_TRUE(data->notificationsFor(alice.id, currentTime())->empty());
}

TEST_F(Notifications, UndoRemovesOnlyTheMatchingEntry)
{
    ASSERT_TRUE(service->setLike(bob, post, true));
    ASSERT_TRUE(service->setBoost(bob, post, true));
    ASSERT_TRUE(service->setReaction(bob, post, "❤️", true));
    ASSERT_TRUE(service->setReaction(bob, post, "👍", true));
    ASSERT_TRUE(service->setFollow(bob, "alice", true));
    ASSERT_TRUE(service->setLike(bob, post, false));
    ASSERT_TRUE(service->setBoost(bob, post, false));
    ASSERT_TRUE(service->setReaction(bob, post, "❤️", false));
    ASSERT_TRUE(service->setFollow(bob, "alice", false));
    ASSIGN_OR_FAIL(auto entries, data->notificationsFor(alice.id, currentTime()));
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].kind, NotificationKind::REACTION);
    ASSIGN_OR_FAIL(auto page, service->notificationPage(alice, {}, currentTime()));
    EXPECT_EQ(page["entries"][0]["emoji"], "👍");
    int64_t previous = entries[0].id;
    ASSERT_TRUE(service->setLike(bob, post, true));
    EXPECT_GT(data->notificationsFor(alice.id, currentTime())->front().id,
              previous);
    ASSERT_TRUE(data->deletePost(post.id));
    EXPECT_TRUE(data->notificationsFor(alice.id, currentTime())->empty());
}

TEST_F(Notifications, NotificationFailureRollsBackInteraction)
{
    ASSERT_TRUE(data->connection().execute(
        "CREATE TRIGGER fail_notification BEFORE INSERT ON notifications "
        "BEGIN SELECT RAISE(ABORT,'injected failure'); END;"));
    EXPECT_FALSE(service->setLike(bob, post, true));
    EXPECT_TRUE(data->likesForPost(post.uri)->empty());
    EXPECT_FALSE(service->setBoost(bob, post, true));
    EXPECT_TRUE(data->boostsForPost(post.uri)->empty());
    ComposeParams params;
    params.source = "reply must roll back";
    params.in_reply_to_uri = post.uri;
    EXPECT_FALSE(service->createPost(bob, params));
    EXPECT_EQ(data->countLocalPosts().value(), 1);
    EXPECT_TRUE(data->notificationsFor(alice.id, currentTime())->empty());
}

TEST_F(Notifications, CountAndAgeLimitsArePerUser)
{
    ASSERT_TRUE(service->setFollow(alice, "bob", true));
    for(int i = 0; i < 101; ++i) ASSERT_TRUE(addLike(i));
    ASSIGN_OR_FAIL(auto entries, data->notificationsFor(alice.id, NOW));
    ASSERT_EQ(entries.size(), 100u);
    EXPECT_EQ(entries.front().actor_uri, "https://remote.test/actor/100");
    EXPECT_EQ(entries.back().actor_uri, "https://remote.test/actor/1");
    EXPECT_EQ(data->likesForPost(post.uri)->size(), 101u);
    EXPECT_EQ(data->notificationsFor(alice.id,
        NOW + NOTIFICATION_RETENTION_SECONDS)->size(), 100u);
    EXPECT_TRUE(data->notificationsFor(alice.id,
        NOW + NOTIFICATION_RETENTION_SECONDS + 1)->empty());
    EXPECT_EQ(data->pruneExpiredNotifications(
        NOW + NOTIFICATION_RETENTION_SECONDS + 1, 7).value(), 7);
    EXPECT_EQ(data->connection().evalToValue<int64_t>(
        "SELECT count(*) FROM notifications WHERE kind=1").value(), 93);
    EXPECT_EQ(data->notificationsFor(bob.id, currentTime())->size(), 1u);
    ASSERT_TRUE(addLike(101, NOW + NOTIFICATION_RETENTION_SECONDS + 1));
    EXPECT_EQ(data->notificationsFor(alice.id,
        NOW + NOTIFICATION_RETENTION_SECONDS + 1)->size(), 1u);
}

TEST_F(Notifications, PagesMoveIndependentlyAcrossGapsAndEqualTimestamps)
{
    for(int i = 0; i < 25; ++i) ASSERT_TRUE(addLike(i));
    ASSIGN_OR_FAIL(auto first, service->notificationPage(alice, {}, NOW));
    ASSERT_EQ(first["entries"].size(), 10u);
    EXPECT_FALSE(first["has_newer"].get<bool>());
    EXPECT_TRUE(first["has_older"].get<bool>());
    Cursor cursor;
    cursor.max_id = first["older_id"].get<int64_t>();
    ASSIGN_OR_FAIL(auto second, service->notificationPage(alice, cursor, NOW));
    ASSERT_EQ(second["entries"].size(), 10u);
    EXPECT_LT(second["newer_id"].get<int64_t>(), *cursor.max_id);
    cursor = {};
    cursor.min_id = second["newer_id"].get<int64_t>();
    ASSIGN_OR_FAIL(auto back, service->notificationPage(alice, cursor, NOW));
    EXPECT_EQ(back["entries"], first["entries"]);
    ASSERT_TRUE(data->removeLike("https://remote.test/actor/24", post.uri));
    cursor = {};
    cursor.max_id = second["older_id"].get<int64_t>();
    ASSIGN_OR_FAIL(auto last, service->notificationPage(alice, cursor, NOW));
    EXPECT_EQ(last["entries"].size(), 5u);
    EXPECT_FALSE(last["has_older"].get<bool>());
    EXPECT_TRUE(last["has_newer"].get<bool>());
    cursor.max_id = 1;
    EXPECT_TRUE(service->notificationPage(alice, cursor, NOW)
                    ->at("entries").empty());
    EXPECT_TRUE(service->notificationPage(bob, {}, NOW)
                    ->at("entries").empty());
    cursor.min_id = 2;
    EXPECT_FALSE(service->notificationPage(alice, cursor, NOW));
}

TEST_F(Notifications, UnreadableRepliesAreSkippedBeforePagination)
{
    for(int i = 0; i < 12; ++i) ASSERT_TRUE(addLike(i, currentTime()));
    ComposeParams params;
    params.source = "secret reply";
    params.in_reply_to_uri = post.uri;
    ASSIGN_OR_FAIL(auto reply, service->createPost(bob, params));
    NewPost edited;
    edited.local_author_id = bob.id;
    edited.content_html = "secret reply";
    edited.in_reply_to_uri = post.uri;
    edited.visibility = Visibility::DIRECT;
    ASSERT_TRUE(data->updatePost(reply.id, edited, {}));
    ASSIGN_OR_FAIL(auto page, service->notificationPage(alice, {}, currentTime()));
    ASSERT_EQ(page["entries"].size(), 10u);
    EXPECT_EQ(page["entries"][0]["kind"], 1);
    EXPECT_TRUE(page["has_older"].get<bool>());
    params.visibility = Visibility::DIRECT;
    EXPECT_TRUE(service->createPost(bob, params));
    EXPECT_EQ(data->notificationsFor(alice.id, currentTime())->size(), 13u);
}

TEST_F(Notifications, MigrationFromSixIsEmptyAndFailureRollsBack)
{
    auto path = std::filesystem::temp_directory_path()
        / "unspoken_notifications_migration.sqlite";
    std::filesystem::remove(path);
    {
        ASSIGN_OR_FAIL(auto db, DataSourceSQLite::fromFile(path.string()));
        ASSIGN_OR_FAIL(auto user, db->createUser(NewUser{
            "owner", "Owner", "", "iss", "owner", "PRIV", "PUB"}));
        NewPost params;
        params.local_author_id = user.id;
        params.content_html = "preserved";
        ASSERT_TRUE(db->insertPost(params, {}, config.url_root + "p/"));
        ASSERT_TRUE(db->connection().execute(
            "DROP TRIGGER notification_follow_pending"));
        ASSERT_TRUE(db->connection().execute(
            "DROP TRIGGER notification_reply_parent"));
        ASSERT_TRUE(db->connection().execute("DROP TABLE notifications"));
        ASSERT_TRUE(db->connection().execute(
            "ALTER TABLE posts DROP COLUMN updated_at"));
        ASSERT_TRUE(db->connection().execute("PRAGMA user_version=6"));
        ASSERT_TRUE(db->connection().execute(
            "CREATE INDEX idx_notifications_expiry ON posts(id)"));
    }
    EXPECT_FALSE(DataSourceSQLite::fromFile(path.string()));
    {
        ASSIGN_OR_FAIL(auto raw, mw::SQLite::connectFile(path.string()));
        EXPECT_EQ(raw->evalToValue<int64_t>("PRAGMA user_version").value(), 6);
        EXPECT_EQ(raw->evalToValue<int64_t>(
            "SELECT count(*) FROM sqlite_master "
            "WHERE name='notifications'").value(), 0);
        ASSERT_TRUE(raw->execute("DROP INDEX idx_notifications_expiry"));
    }
    {
        ASSIGN_OR_FAIL(auto db, DataSourceSQLite::fromFile(path.string()));
        EXPECT_EQ(db->getSchemaVersion().value(), 8);
        EXPECT_EQ(db->countLocalPosts().value(), 1);
        EXPECT_EQ(db->getPostById(1)->value().content_html, "preserved");
        EXPECT_TRUE(db->notificationsFor(1, currentTime())->empty());
    }
    std::filesystem::remove(path);
}

TEST_F(Notifications, ReplyReparentingAndDeletionRemoveEntries)
{
    ComposeParams params;
    params.source = "a reply";
    params.in_reply_to_uri = post.uri;
    ASSIGN_OR_FAIL(auto reply, service->createPost(bob, params));
    NewPost edit;
    edit.local_author_id = bob.id;
    edit.content_html = "a reply";
    ASSERT_TRUE(data->updatePost(reply.id, edit, {}));
    EXPECT_TRUE(data->notificationsFor(alice.id, currentTime())->empty());
    ASSIGN_OR_FAIL(reply, service->createPost(bob, params));
    ASSERT_EQ(data->notificationsFor(alice.id, currentTime())->size(), 1u);
    ASSERT_TRUE(data->deletePost(reply.id));
    EXPECT_TRUE(data->notificationsFor(alice.id, currentTime())->empty());
}

TEST_F(Notifications, PendingFollowsDoNotNotifyAndDowngradesRemoveEntries)
{
    ASSERT_TRUE(service->setFollowActor(bob, service->actorUri("alice"),
        true, FollowState::PENDING));
    EXPECT_TRUE(data->notificationsFor(alice.id, currentTime())->empty());
    ASSERT_TRUE(service->setFollow(bob, "alice", true));
    ASSERT_EQ(data->notificationsFor(alice.id, currentTime())->size(), 1u);
    ASSERT_TRUE(data->setFollowState(service->actorUri("bob"),
        service->actorUri("alice"), FollowState::PENDING));
    EXPECT_TRUE(data->notificationsFor(alice.id, currentTime())->empty());
}

TEST_F(Notifications, ExcerptsRespectWarningsAndUtf8AndTemplatesEscapeText)
{
    NewPost warning;
    warning.local_author_id = alice.id;
    warning.content_html = "secret body";
    warning.summary = "Warning <private> & sensitive";
    ASSIGN_OR_FAIL(auto warned, data->insertPost(warning, {},
        config.url_root + "p/"));
    ASSERT_TRUE(service->setLike(bob, warned, true));
    NewPost unicode;
    unicode.local_author_id = alice.id;
    for(int i = 0; i < 90; ++i) unicode.content_html += "🐈";
    ASSIGN_OR_FAIL(auto cats, data->insertPost(unicode, {},
        config.url_root + "p/"));
    ASSERT_TRUE(service->setLike(bob, cats, true));
    ASSIGN_OR_FAIL(auto page, service->notificationPage(alice, {}, currentTime()));
    std::string expected;
    for(int i = 0; i < 80; ++i) expected += "🐈";
    expected += "…";
    EXPECT_EQ(page["entries"][0]["post"]["excerpt"], expected);
    EXPECT_EQ(page["entries"][1]["post"]["excerpt"],
              "Warning &lt;private&gt; &amp; sensitive");
    page["older_url"] = "?notifications_max_id=1&amp;max_id=42#notifications";
    page["newer_url"] = "";
    page["latest_url"] = "#notifications";
    nlohmann::json context = {{"notifications", page}};
    inja::Environment templates("templates/");
    auto html = templates.render_file("_notifications.html", context);
    EXPECT_NE(html.find("Bob &lt;script&gt;"), std::string::npos);
    EXPECT_EQ(html.find("<script>"), std::string::npos);
    EXPECT_EQ(html.find("secret body"), std::string::npos);
    EXPECT_NE(html.find("<time datetime="), std::string::npos);
    EXPECT_NE(html.find(cats.uri), std::string::npos);
}

} // namespace
