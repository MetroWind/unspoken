#include <algorithm>
#include <filesystem>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <mw/database.hpp>
#include <mw/error.hpp>
#include <mw/test_utils.hpp>

#include "data.hpp"
#include "data_mock.hpp"
#include "structs.hpp"

using namespace unspoken;
using ::testing::IsEmpty;
using ::testing::Return;
using ::testing::SizeIs;

namespace
{

NewUser sampleUser(const std::string& name)
{
    NewUser nu;
    nu.username = name;
    nu.display_name = name + " display";
    nu.bio = "hi";
    nu.oidc_iss = "https://kc/realms/main";
    nu.oidc_sub = "sub-" + name;
    nu.private_key_pem = "PRIV";
    nu.public_key_pem = "PUB";
    return nu;
}

// Insert a local public post by author, returning the stored Post.
Post insertLocalPost(const DataSourceSQLite& db, int64_t author_id,
                     const std::string& body)
{
    NewPost np;
    np.local_author_id = author_id;
    np.content_html = body;
    np.content_source = body;
    np.visibility = Visibility::PUBLIC;
    auto r = db.insertPost(np, {}, "https://f.test/p/");
    EXPECT_TRUE(mw::isExpected(r));
    return r.value();
}

RemoteActor sampleRemoteActor(const std::string& uri)
{
    RemoteActor actor;
    actor.uri = uri;
    actor.username = "remote";
    actor.domain = "remote.test";
    actor.display_name = "Remote";
    actor.inbox = uri + "/inbox";
    actor.public_key_pem = "PUB";
    actor.public_key_id = uri + "#main-key";
    actor.actor_json = "{}";
    return actor;
}

} // namespace

TEST(Data, SchemaVersionIsThree)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(int64_t v, db->getSchemaVersion());
    EXPECT_EQ(v, 3);
}

TEST(Data, OpensAndMigratesVersionOneDatabase)
{
    namespace fs = std::filesystem;
    fs::path fixture = "tests/fixtures/db/v1.sqlite";
    fs::path path = fs::temp_directory_path()
        / "unspoken_v1_migration_test.sqlite";

    auto removeTempDb = [&]() {
        std::error_code ignored;
        fs::remove(path, ignored);
        fs::remove(path.string() + "-wal", ignored);
        fs::remove(path.string() + "-shm", ignored);
    };

    ASSERT_TRUE(fs::exists(fixture));
    removeTempDb();
    std::error_code ec;
    fs::copy_file(fixture, path, fs::copy_options::overwrite_existing, ec);
    ASSERT_FALSE(ec) << ec.message();

    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::fromFile(path.string()));
    ASSIGN_OR_FAIL(int64_t version, db->getSchemaVersion());
    EXPECT_EQ(version, 3);
    ASSIGN_OR_FAIL(auto user, db->getUserByUsername("mw"));
    ASSERT_TRUE(user.has_value());
    EXPECT_FALSE(user->avatar_attachment_id.has_value());
    ASSIGN_OR_FAIL(auto attachments, db->attachmentsForPost(20));
    ASSERT_THAT(attachments, SizeIs(2));
    EXPECT_TRUE(attachments[0].remote_url.has_value());
    EXPECT_TRUE(attachments[1].remote_url.has_value());
    ASSIGN_OR_FAIL(auto local_attachments, db->attachmentsForPost(17));
    ASSERT_THAT(local_attachments, SizeIs(1));
    EXPECT_FALSE(local_attachments[0].remote_url.has_value());
    EXPECT_EQ(local_attachments[0].sha256,
              "4ce55f868061b887f63d165c109c551e"
              "ca1a030215f8fad897ed6e827f78f939");
    EXPECT_EQ(local_attachments[0].extension, "webp");
    ASSIGN_OR_FAIL(auto sessions, db->getSessionUser(
        "placeholder-session-token-1", 0));
    ASSERT_TRUE(sessions.has_value());
    EXPECT_EQ(*sessions, user->id);
    ASSIGN_OR_FAIL(auto nonce, db->takePendingLogin(
        "placeholder-login-state"));
    ASSERT_TRUE(nonce.has_value());
    EXPECT_EQ(*nonce, "placeholder-login-nonce");

    ASSIGN_OR_FAIL(auto post21_attachments, db->attachmentsForPost(21));
    ASSERT_THAT(post21_attachments, SizeIs(1));
    EXPECT_TRUE(post21_attachments[0].remote_url.has_value());
    ASSIGN_OR_FAIL(auto post17_attachments, db->attachmentsForPost(17));
    ASSERT_THAT(post17_attachments, SizeIs(1));
    EXPECT_FALSE(post17_attachments[0].sensitive);

    removeTempDb();
}

TEST(Data, MigratesVersionTwoActorAndActivityStateToVersionThree)
{
    namespace fs = std::filesystem;
    fs::path fixture = "tests/fixtures/db/v1.sqlite";
    fs::path path = fs::temp_directory_path()
        / "unspoken_v2_migration_test.sqlite";
    auto remove_temp_db = [&]() {
        std::error_code ignored;
        fs::remove(path, ignored);
        fs::remove(path.string() + "-wal", ignored);
        fs::remove(path.string() + "-shm", ignored);
    };
    remove_temp_db();
    std::error_code ec;
    fs::copy_file(fixture, path, fs::copy_options::overwrite_existing, ec);
    ASSERT_FALSE(ec) << ec.message();

    {
        ASSIGN_OR_FAIL(auto conn, mw::SQLite::connectFile(path.string()));
        DataSourceSQLite version_two(std::move(conn));
        ASSERT_TRUE(version_two.migrate1To2().has_value());
        ASSIGN_OR_FAIL(auto version, version_two.getSchemaVersion());
        EXPECT_EQ(version, 2);
    }
    {
        ASSIGN_OR_FAIL(auto conn, mw::SQLite::connectFile(path.string()));
        ASSERT_TRUE(conn->execute(
            "INSERT INTO remote_actors "
            "(uri, username, domain, display_name, inbox, shared_inbox, "
            "public_key_pem, public_key_id, actor_json, fetched_at) VALUES "
            "('https://remote.test/u/bob', 'bob', 'remote.test', 'Bob', "
            "'https://remote.test/u/bob/inbox', NULL, 'PUB', "
            "'https://remote.test/u/bob#main-key', '{}', 1234);").has_value());
        ASSERT_TRUE(conn->execute(
            "INSERT INTO seen_activities (activity_uri, seen_at) VALUES "
            "('https://remote.test/a/old', 4321);").has_value());
    }

    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::fromFile(path.string()));
    ASSIGN_OR_FAIL(auto version, db->getSchemaVersion());
    EXPECT_EQ(version, 3);
    ASSIGN_OR_FAIL(auto actor, db->getRemoteActorByUri(
        "https://remote.test/u/bob"));
    ASSERT_TRUE(actor.has_value());
    EXPECT_EQ(actor->username, "bob");
    EXPECT_EQ(actor->fetched_at, 1234);
    EXPECT_EQ(actor->retained_at, 1234);
    ASSIGN_OR_FAIL(auto claim, db->claimIncomingActivity(
        "https://remote.test/a/old", 5000, 10));
    EXPECT_EQ(claim, ActivityClaimResult::ALREADY_PROCESSED);
    remove_temp_db();
}

TEST(Data, FailedVersionTwoMigrationRollsBackSchemaChanges)
{
    namespace fs = std::filesystem;
    fs::path fixture = "tests/fixtures/db/v1.sqlite";
    fs::path path = fs::temp_directory_path()
        / "unspoken_v2_migration_rollback_test.sqlite";
    auto remove_temp_db = [&]() {
        std::error_code ignored;
        fs::remove(path, ignored);
        fs::remove(path.string() + "-wal", ignored);
        fs::remove(path.string() + "-shm", ignored);
    };
    remove_temp_db();
    std::error_code ec;
    fs::copy_file(fixture, path, fs::copy_options::overwrite_existing, ec);
    ASSERT_FALSE(ec) << ec.message();
    {
        ASSIGN_OR_FAIL(auto conn, mw::SQLite::connectFile(path.string()));
        DataSourceSQLite version_two(std::move(conn));
        ASSERT_TRUE(version_two.migrate1To2().has_value());
    }
    {
        ASSIGN_OR_FAIL(auto conn, mw::SQLite::connectFile(path.string()));
        ASSERT_TRUE(conn->execute(
            "CREATE TRIGGER fail_v2_to_v3_retention_update "
            "BEFORE UPDATE OF retained_at ON remote_actors "
            "BEGIN SELECT RAISE(ABORT, 'injected migration failure'); END;")
                        .has_value());
    }
    EXPECT_FALSE(DataSourceSQLite::fromFile(path.string()).has_value());
    ASSIGN_OR_FAIL(auto conn, mw::SQLite::connectFile(path.string()));
    ASSIGN_OR_FAIL(auto version, conn->evalToValue<int64_t>(
        "PRAGMA user_version;"));
    EXPECT_EQ(version, 2);
    ASSIGN_OR_FAIL(auto columns, conn->eval<std::string>(
        "SELECT name FROM pragma_table_info('remote_actors');"));
    EXPECT_EQ(std::count_if(columns.begin(), columns.end(),
                            [](const auto& column) {
        return std::get<0>(column) == "retained_at";
    }), 0);
    remove_temp_db();
}

TEST(Data, UserRoundTrip)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User u, db->createUser(sampleUser("alice")));
    EXPECT_GT(u.id, 0);

    ASSIGN_OR_FAIL(auto by_id, db->getUserById(u.id));
    ASSERT_TRUE(by_id.has_value());
    EXPECT_EQ(by_id->username, "alice");

    ASSIGN_OR_FAIL(auto by_name, db->getUserByUsername("alice"));
    ASSERT_TRUE(by_name.has_value());
    EXPECT_EQ(by_name->id, u.id);

    ASSIGN_OR_FAIL(auto by_sub,
                   db->getUserByOidcSub("https://kc/realms/main", "sub-alice"));
    ASSERT_TRUE(by_sub.has_value());
    EXPECT_EQ(by_sub->id, u.id);

    ASSIGN_OR_FAIL(auto missing, db->getUserByUsername("nobody"));
    EXPECT_FALSE(missing.has_value());

    EXPECT_TRUE(mw::isExpected(
        db->updateUserProfile(u.id, "Alice New", "new bio")));
    ASSIGN_OR_FAIL(auto updated, db->getUserById(u.id));
    ASSERT_TRUE(updated.has_value());
    EXPECT_EQ(updated->display_name, "Alice New");
    EXPECT_EQ(updated->bio, "new bio");
    ASSIGN_OR_FAIL(auto user_count, db->countUsers());
    EXPECT_EQ(user_count, 1);
}

TEST(Data, UsernameIsUnique)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    EXPECT_TRUE(mw::isExpected(db->createUser(sampleUser("bob"))));
    NewUser dup = sampleUser("bob");
    dup.oidc_sub = "sub-other";
    EXPECT_FALSE(db->createUser(dup).has_value());
}

TEST(Data, LocalPostGetsUriFromId)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User u, db->createUser(sampleUser("alice")));
    Post p = insertLocalPost(*db, u.id, "hello world");
    EXPECT_EQ(p.uri, "https://f.test/p/" + std::to_string(p.id));

    ASSIGN_OR_FAIL(auto by_uri, db->getPostByUri(p.uri));
    ASSERT_TRUE(by_uri.has_value());
    EXPECT_EQ(by_uri->id, p.id);
    EXPECT_EQ(by_uri->content_html, "hello world");
    ASSIGN_OR_FAIL(auto local_count, db->countLocalPosts());
    EXPECT_EQ(local_count, 1);
}

TEST(Data, RemotePostKeepsItsUri)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    NewPost np;
    np.uri = "https://remote.test/objects/1";
    np.content_html = "remote post";
    np.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(Post p, db->insertPost(np, {}, "https://f.test/p/"));
    EXPECT_EQ(p.uri, "https://remote.test/objects/1");
    ASSIGN_OR_FAIL(auto local_count, db->countLocalPosts());
    EXPECT_EQ(local_count, 0);
}

TEST(Data, PostRecipientsStored)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User u, db->createUser(sampleUser("alice")));
    NewPost np;
    np.local_author_id = u.id;
    np.content_html = "hi";
    np.visibility = Visibility::PUBLIC;
    std::vector<PostRecipient> recips = {
        {0, std::string(AS_PUBLIC), "to"},
        {0, "https://f.test/u/alice/followers", "cc"},
    };
    ASSIGN_OR_FAIL(Post p, db->insertPost(np, recips, "https://f.test/p/"));
    ASSIGN_OR_FAIL(auto stored, db->getPostRecipients(p.id));
    EXPECT_THAT(stored, SizeIs(2));
}

TEST(Data, DeletePostRemovesItAndRecipients)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User u, db->createUser(sampleUser("alice")));
    Post p = insertLocalPost(*db, u.id, "doomed");
    EXPECT_TRUE(mw::isExpected(db->deletePost(p.id)));
    ASSIGN_OR_FAIL(auto gone, db->getPostById(p.id));
    EXPECT_FALSE(gone.has_value());
    ASSIGN_OR_FAIL(auto recips, db->getPostRecipients(p.id));
    EXPECT_THAT(recips, IsEmpty());
}

TEST(Data, ThreadForReturnsRecursiveReplyChain)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User u, db->createUser(sampleUser("alice")));
    Post root = insertLocalPost(*db, u.id, "root");

    NewPost reply;
    reply.local_author_id = u.id;
    reply.content_html = "reply";
    reply.content_source = "reply";
    reply.visibility = Visibility::PUBLIC;
    reply.in_reply_to_uri = root.uri;
    ASSIGN_OR_FAIL(Post child, db->insertPost(
        reply, {}, "https://f.test/p/"));

    NewPost grandchild = reply;
    grandchild.content_html = "grandchild";
    grandchild.content_source = "grandchild";
    grandchild.in_reply_to_uri = child.uri;
    ASSIGN_OR_FAIL(Post nested, db->insertPost(
        grandchild, {}, "https://f.test/p/"));

    NewPost sibling = reply;
    sibling.content_html = "sibling";
    sibling.content_source = "sibling";
    sibling.in_reply_to_uri = root.uri;
    ASSIGN_OR_FAIL(Post other, db->insertPost(
        sibling, {}, "https://f.test/p/"));

    ASSIGN_OR_FAIL(auto thread, db->threadFor(nested.uri));
    std::vector<int64_t> ids;
    for(const auto& post : thread) ids.push_back(post.id);
    EXPECT_NE(std::find(ids.begin(), ids.end(), root.id), ids.end());
    EXPECT_NE(std::find(ids.begin(), ids.end(), child.id), ids.end());
    EXPECT_NE(std::find(ids.begin(), ids.end(), nested.id), ids.end());
    EXPECT_NE(std::find(ids.begin(), ids.end(), other.id), ids.end());
}

TEST(Data, RemoteActorUpsert)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    RemoteActor a;
    a.uri = "https://remote.test/u/bob";
    a.username = "bob";
    a.domain = "remote.test";
    a.display_name = "Bob";
    a.inbox = "https://remote.test/u/bob/inbox";
    a.public_key_pem = "PUB";
    a.public_key_id = a.uri + "#main-key";
    a.actor_json = "{}";
    a.fetched_at = 1;
    ASSIGN_OR_FAIL(RemoteActor stored, db->upsertRemoteActor(a));
    EXPECT_GT(stored.id, 0);
    EXPECT_EQ(stored.retained_at, 1);

    // Upsert again with a new display name updates in place.
    a.display_name = "Bobby";
    a.fetched_at = 2;
    ASSIGN_OR_FAIL(RemoteActor stored2, db->upsertRemoteActor(a));
    EXPECT_EQ(stored2.id, stored.id);
    EXPECT_EQ(stored2.display_name, "Bobby");
    EXPECT_EQ(stored2.fetched_at, 2);
    EXPECT_EQ(stored2.retained_at, 1);

    ASSIGN_OR_FAIL(auto got, db->getRemoteActorByUri(a.uri));
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->username, "bob");
    ASSIGN_OR_FAIL(auto by_id, db->getRemoteActorById(stored.id));
    ASSERT_TRUE(by_id.has_value());
    EXPECT_EQ(by_id->uri, a.uri);
}

TEST(Data, CollectsOnlyExpiredUnreferencedRemoteActors)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    std::vector<RemoteActor> actors;
    for(int i = 0; i < 8; ++i)
    {
        ASSIGN_OR_FAIL(auto actor, db->upsertRemoteActor(sampleRemoteActor(
            std::format("https://remote.test/u/{}", i))));
        ASSERT_TRUE(db->touchRemoteActorRetention(actor.uri, 1).has_value());
        actors.push_back(std::move(actor));
    }

    NewPost remote_post;
    remote_post.uri = "https://remote.test/p/author";
    remote_post.remote_author_id = actors[1].id;
    remote_post.content_html = "remote post";
    remote_post.visibility = Visibility::PUBLIC;
    ASSERT_TRUE(db->insertPost(remote_post, {}, "https://f.test/p/").has_value());
    ASSERT_TRUE(db->touchRemoteActorRetention(actors[1].uri, 1).has_value());

    ASSERT_TRUE(db->addFollow(Follow{0, actors[2].uri,
                                     "https://f.test/u/alice",
                                     FollowState::ACCEPTED, {}, 0}).has_value());
    ASSERT_TRUE(db->touchRemoteActorRetention(actors[2].uri, 1).has_value());
    ASSERT_TRUE(db->addLike(Like{0, actors[3].uri,
                                 "https://f.test/p/1", {}, 0}).has_value());
    ASSERT_TRUE(db->touchRemoteActorRetention(actors[3].uri, 1).has_value());
    ASSERT_TRUE(db->addBoost(Boost{0, actors[4].uri,
                                   "https://f.test/p/1", {}, 0}).has_value());
    ASSERT_TRUE(db->touchRemoteActorRetention(actors[4].uri, 1).has_value());
    ASSERT_TRUE(db->addReaction(Reaction{0, actors[5].uri,
                                         "https://f.test/p/1", "👍",
                                         {}, {}, {}, 0}).has_value());
    ASSERT_TRUE(db->touchRemoteActorRetention(actors[5].uri, 1).has_value());
    NewPost recipient_post;
    recipient_post.local_author_id = 1;
    recipient_post.content_html = "recipient";
    recipient_post.visibility = Visibility::PUBLIC;
    ASSERT_TRUE(db->insertPost(
        recipient_post, {{0, actors[6].uri, "to"}}, "https://f.test/p/")
                    .has_value());
    ASSERT_TRUE(db->touchRemoteActorRetention(actors[6].uri, 1).has_value());

    ASSIGN_OR_FAIL(auto first, db->collectUnreferencedRemoteActors(2, 1));
    EXPECT_EQ(first, 1);
    ASSIGN_OR_FAIL(auto first_actor, db->getRemoteActorByUri(actors[0].uri));
    EXPECT_FALSE(first_actor.has_value());
    ASSIGN_OR_FAIL(auto second, db->collectUnreferencedRemoteActors(2, 1));
    EXPECT_EQ(second, 1);
    ASSIGN_OR_FAIL(auto second_actor, db->getRemoteActorByUri(actors[7].uri));
    EXPECT_FALSE(second_actor.has_value());
    for(int i = 1; i < 7; ++i)
    {
        ASSIGN_OR_FAIL(auto actor, db->getRemoteActorByUri(actors[i].uri));
        EXPECT_TRUE(actor.has_value());
    }
}

TEST(Data, RemovingInteractionRestartsActorCollectionGracePeriod)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto actor, db->upsertRemoteActor(
        sampleRemoteActor("https://remote.test/u/interaction")));
    ASSERT_TRUE(db->touchRemoteActorRetention(actor.uri, 1).has_value());
    ASSERT_TRUE(db->addLike(
        Like{0, actor.uri, "https://f.test/p/1", {}, 0}).has_value());
    ASSERT_TRUE(db->touchRemoteActorRetention(actor.uri, 1).has_value());
    ASSERT_TRUE(db->removeLike(actor.uri, "https://f.test/p/1").has_value());
    ASSIGN_OR_FAIL(auto stored, db->getRemoteActorByUri(actor.uri));
    ASSERT_TRUE(stored.has_value());
    EXPECT_GT(stored->retained_at, 1);
}

TEST(Data, RecentUnreferencedActorWaitsForCollectionGracePeriod)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto actor, db->upsertRemoteActor(
        sampleRemoteActor("https://remote.test/u/recent")));
    ASSERT_TRUE(db->touchRemoteActorRetention(actor.uri, 100).has_value());
    ASSIGN_OR_FAIL(auto deleted, db->collectUnreferencedRemoteActors(100, 10));
    EXPECT_EQ(deleted, 0);
    ASSIGN_OR_FAIL(auto stored, db->getRemoteActorByUri(actor.uri));
    EXPECT_TRUE(stored.has_value());
}

TEST(Data, SystemActorRoundTrip)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto empty, db->getSystemActor());
    EXPECT_FALSE(empty.has_value());

    EXPECT_TRUE(mw::isExpected(db->setSystemActor("PRIV", "PUB")));
    ASSIGN_OR_FAIL(auto stored, db->getSystemActor());
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->private_key_pem, "PRIV");
    EXPECT_EQ(stored->public_key_pem, "PUB");

    EXPECT_TRUE(mw::isExpected(db->setSystemActor("PRIV2", "PUB2")));
    ASSIGN_OR_FAIL(auto updated, db->getSystemActor());
    ASSERT_TRUE(updated.has_value());
    EXPECT_EQ(updated->private_key_pem, "PRIV2");
    EXPECT_EQ(updated->public_key_pem, "PUB2");
}

TEST(Data, FollowLifecycle)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    Follow f;
    f.follower_uri = "https://remote.test/u/bob";
    f.followee_uri = "https://f.test/u/alice";
    f.state = FollowState::PENDING;
    EXPECT_TRUE(mw::isExpected(db->addFollow(f)));

    EXPECT_TRUE(mw::isExpected(db->setFollowState(
        f.follower_uri, f.followee_uri, FollowState::ACCEPTED)));
    ASSIGN_OR_FAIL(auto got, db->getFollow(f.follower_uri, f.followee_uri));
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->state, FollowState::ACCEPTED);

    ASSIGN_OR_FAIL(auto followers, db->followerUris(f.followee_uri));
    EXPECT_THAT(followers, SizeIs(1));
    ASSIGN_OR_FAIL(auto following, db->followingUris(f.follower_uri));
    EXPECT_THAT(following, SizeIs(1));

    EXPECT_TRUE(mw::isExpected(
        db->removeFollow(f.follower_uri, f.followee_uri)));
    ASSIGN_OR_FAIL(auto gone, db->getFollow(f.follower_uri, f.followee_uri));
    EXPECT_FALSE(gone.has_value());
}

TEST(Data, FollowCollectionsAreCursorPaginated)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    const std::string alice = "https://f.test/u/alice";
    const std::string bob = "https://remote.test/u/bob";
    const std::string carol = "https://remote.test/u/carol";
    const std::string dave = "https://remote.test/u/dave";

    ASSERT_TRUE(db->addFollow(Follow{0, bob, alice,
                                     FollowState::ACCEPTED, {}, 0})
                    .has_value());
    ASSERT_TRUE(db->addFollow(Follow{0, carol, alice,
                                     FollowState::ACCEPTED, {}, 0})
                    .has_value());
    ASSERT_TRUE(db->addFollow(Follow{0, dave, alice,
                                     FollowState::ACCEPTED, {}, 0})
                    .has_value());

    ASSIGN_OR_FAIL(auto first, db->followerPage(alice, Cursor{}, 2));
    ASSERT_EQ(first.size(), 2);
    EXPECT_EQ(first[0].actor_uri, dave);
    EXPECT_EQ(first[1].actor_uri, carol);

    Cursor older;
    older.max_id = first.back().id;
    ASSIGN_OR_FAIL(auto second, db->followerPage(alice, older, 2));
    ASSERT_EQ(second.size(), 1);
    EXPECT_EQ(second[0].actor_uri, bob);

    ASSIGN_OR_FAIL(auto following, db->followingPage(bob, Cursor{}, 10));
    ASSERT_EQ(following.size(), 1);
    EXPECT_EQ(following[0].actor_uri, alice);
}

TEST(Data, LikesBoostsReactions)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    const std::string post = "https://f.test/p/1";
    const std::string actor = "https://remote.test/u/bob";

    EXPECT_TRUE(mw::isExpected(db->addLike(Like{0, actor, post, {}, 0})));
    // Duplicate like is a no-op (unique pair).
    EXPECT_TRUE(mw::isExpected(db->addLike(Like{0, actor, post, {}, 0})));
    ASSIGN_OR_FAIL(auto likes, db->likesForPost(post));
    EXPECT_THAT(likes, SizeIs(1));
    EXPECT_TRUE(mw::isExpected(db->removeLike(actor, post)));
    ASSIGN_OR_FAIL(auto likes2, db->likesForPost(post));
    EXPECT_THAT(likes2, IsEmpty());

    EXPECT_TRUE(mw::isExpected(db->addBoost(Boost{0, actor, post, {}, 0})));
    ASSIGN_OR_FAIL(auto boosts, db->boostsForPost(post));
    EXPECT_THAT(boosts, SizeIs(1));
    EXPECT_TRUE(mw::isExpected(db->removeBoost(actor, post)));
    ASSIGN_OR_FAIL(auto boosts2, db->boostsForPost(post));
    EXPECT_THAT(boosts2, IsEmpty());

    EXPECT_TRUE(mw::isExpected(
        db->addReaction(Reaction{0, actor, post, ":blobcat:",
                                 "https://remote.test/e/blobcat.png",
                                 "image/png", {}, 0})));
    EXPECT_TRUE(mw::isExpected(
        db->addReaction(Reaction{0, actor, post, "👍", {}, {}, {}, 0})));
    ASSIGN_OR_FAIL(auto reacts, db->reactionsForPost(post));
    EXPECT_THAT(reacts, SizeIs(2));
    EXPECT_EQ(reacts[0].remote_emoji_url.value_or(""),
              "https://remote.test/e/blobcat.png");
    EXPECT_EQ(reacts[0].remote_emoji_media_type.value_or(""), "image/png");
}

TEST(Data, Bookmarks)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User u, db->createUser(sampleUser("alice")));
    Post p = insertLocalPost(*db, u.id, "bm");
    EXPECT_TRUE(mw::isExpected(db->addBookmark(u.id, p.id)));
    ASSIGN_OR_FAIL(auto bms, db->bookmarksFor(u.id, Cursor{}, 20));
    EXPECT_THAT(bms, SizeIs(1));
    EXPECT_TRUE(mw::isExpected(db->removeBookmark(u.id, p.id)));
    ASSIGN_OR_FAIL(auto bms2, db->bookmarksFor(u.id, Cursor{}, 20));
    EXPECT_THAT(bms2, IsEmpty());
}

TEST(Data, AttachmentDeduplicatesAndPostRelationsCarrySensitivity)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User u, db->createUser(sampleUser("alice")));

    NewPost np;
    np.local_author_id = u.id;
    np.content_html = "with media";
    np.sensitive = true;
    np.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(Post p, db->insertPost(np, {}, "https://f.test/p/"));

    Attachment a;
    a.sha256 = "abcdef";
    a.extension = "png";
    a.media_type = "image/png";
    a.original_name = "first.png";
    a.is_image = true;
    ASSIGN_OR_FAIL(int64_t first_id, db->insertAttachment(a));

    a.original_name = "second.png";
    ASSIGN_OR_FAIL(int64_t second_id, db->insertAttachment(a));
    EXPECT_EQ(second_id, first_id);

    EXPECT_TRUE(mw::isExpected(db->attachToPost(first_id, p.id)));
    ASSIGN_OR_FAIL(auto atts, db->attachmentsForPost(p.id));
    ASSERT_THAT(atts, SizeIs(1));
    EXPECT_EQ(atts[0].id, first_id);
    EXPECT_EQ(atts[0].extension, "png");
    EXPECT_EQ(atts[0].original_name, "first.png");
    EXPECT_TRUE(atts[0].sensitive);
}

TEST(Data, RemoteAttachmentDeduplicatesByUrl)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    Attachment a;
    a.media_type = "image/jpeg";
    a.original_name = "remote.jpg";
    a.is_image = true;
    a.remote_url = "https://remote.test/media/1.jpg";

    ASSIGN_OR_FAIL(int64_t first_id, db->insertAttachment(a));
    a.original_name = "renamed.jpg";
    ASSIGN_OR_FAIL(int64_t second_id, db->insertAttachment(a));
    EXPECT_EQ(second_id, first_id);
}

TEST(Data, ProfileMediaAndFieldsRoundTrip)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User u, db->createUser(sampleUser("alice")));

    Attachment avatar;
    avatar.sha256 = "abc001";
    avatar.extension = "png";
    avatar.media_type = "image/png";
    avatar.original_name = "avatar.png";
    avatar.is_image = true;
    ASSIGN_OR_FAIL(int64_t avatar_id, db->insertAttachment(avatar));

    UserProfileUpdate update;
    update.display_name = "Alice Updated";
    update.bio = "new bio";
    update.avatar_attachment_id = avatar_id;
    update.fields = {
        {0, u.id, "Blog", "https://example.test", 10},
        {0, u.id, "Matrix", "@alice:example.test", 20},
    };
    EXPECT_TRUE(mw::isExpected(db->replaceUserProfile(update, u.id)));

    ASSIGN_OR_FAIL(auto stored, db->getUserById(u.id));
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->display_name, "Alice Updated");
    ASSERT_TRUE(stored->avatar_attachment_id.has_value());
    EXPECT_EQ(*stored->avatar_attachment_id, avatar_id);
    EXPECT_FALSE(stored->banner_attachment_id.has_value());

    ASSIGN_OR_FAIL(auto fields, db->profileFieldsForUser(u.id));
    ASSERT_THAT(fields, SizeIs(2));
    EXPECT_EQ(fields[0].label, "Blog");
    EXPECT_EQ(fields[1].label, "Matrix");
    EXPECT_EQ(fields[0].sort_order, 10);
}

TEST(Data, DeleteUnreferencedAttachmentsHonorsReferences)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User u, db->createUser(sampleUser("alice")));
    Post p = insertLocalPost(*db, u.id, "with relation");

    Attachment kept;
    kept.sha256 = "aaa111";
    kept.extension = "png";
    kept.media_type = "image/png";
    kept.original_name = "kept.png";
    kept.is_image = true;
    ASSIGN_OR_FAIL(int64_t kept_id, db->insertAttachment(kept));
    EXPECT_TRUE(mw::isExpected(db->attachToPost(kept_id, p.id)));

    Attachment removed = kept;
    removed.sha256 = "bbb222";
    removed.original_name = "removed.png";
    ASSIGN_OR_FAIL(int64_t removed_id, db->insertAttachment(removed));

    EXPECT_TRUE(mw::isExpected(db->deleteUnreferencedAttachments(
        {kept_id, removed_id})));
    ASSIGN_OR_FAIL(auto kept_after, db->getAttachmentById(kept_id));
    EXPECT_TRUE(kept_after.has_value());
    ASSIGN_OR_FAIL(auto removed_after, db->getAttachmentById(removed_id));
    EXPECT_FALSE(removed_after.has_value());

    EXPECT_TRUE(mw::isExpected(db->updateProfileMedia(u.id, kept_id, {})));
    EXPECT_TRUE(mw::isExpected(db->deletePost(p.id)));
    EXPECT_TRUE(mw::isExpected(db->deleteUnreferencedAttachments({kept_id})));
    ASSIGN_OR_FAIL(auto profile_kept, db->getAttachmentById(kept_id));
    EXPECT_TRUE(profile_kept.has_value());
}

TEST(Data, SessionLifecycle)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User u, db->createUser(sampleUser("alice")));
    EXPECT_TRUE(mw::isExpected(db->createSession("tok", u.id, 1000)));

    ASSIGN_OR_FAIL(auto live, db->getSessionUser("tok", 500));
    ASSERT_TRUE(live.has_value());
    EXPECT_EQ(*live, u.id);

    // Expired session yields nothing.
    ASSIGN_OR_FAIL(auto expired, db->getSessionUser("tok", 2000));
    EXPECT_FALSE(expired.has_value());

    EXPECT_TRUE(mw::isExpected(db->deleteSession("tok")));
    ASSIGN_OR_FAIL(auto deleted, db->getSessionUser("tok", 500));
    EXPECT_FALSE(deleted.has_value());
}

TEST(Data, PendingLoginTakenOnce)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    EXPECT_TRUE(mw::isExpected(db->addPendingLogin("state1", "nonce1", 0)));
    ASSIGN_OR_FAIL(auto first, db->takePendingLogin("state1"));
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(*first, "nonce1");
    // Second take finds nothing (consumed).
    ASSIGN_OR_FAIL(auto second, db->takePendingLogin("state1"));
    EXPECT_FALSE(second.has_value());
    // Unknown state yields nothing (CSRF mismatch).
    ASSIGN_OR_FAIL(auto unknown, db->takePendingLogin("bogus"));
    EXPECT_FALSE(unknown.has_value());
}

TEST(Data, ActivityDedupClaimFinalizeReleaseAndPrune)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto first, db->claimIncomingActivity("https://a/1", 0, 10));
    EXPECT_EQ(first, ActivityClaimResult::CLAIMED);
    ASSIGN_OR_FAIL(auto in_progress,
                   db->claimIncomingActivity("https://a/1", 5, 10));
    EXPECT_EQ(in_progress, ActivityClaimResult::IN_PROGRESS);
    EXPECT_TRUE(mw::isExpected(db->finalizeIncomingActivity(
        "https://a/1", 100)));
    ASSIGN_OR_FAIL(auto complete,
                   db->claimIncomingActivity("https://a/1", 11, 10));
    EXPECT_EQ(complete, ActivityClaimResult::ALREADY_PROCESSED);

    ASSIGN_OR_FAIL(auto retry, db->claimIncomingActivity("https://a/2", 0, 10));
    EXPECT_EQ(retry, ActivityClaimResult::CLAIMED);
    EXPECT_TRUE(mw::isExpected(db->releaseIncomingActivity("https://a/2")));
    ASSIGN_OR_FAIL(auto reclaimed,
                   db->claimIncomingActivity("https://a/2", 1, 10));
    EXPECT_EQ(reclaimed, ActivityClaimResult::CLAIMED);

    ASSIGN_OR_FAIL(auto expired,
                   db->claimIncomingActivity("https://a/3", 0, 10));
    EXPECT_EQ(expired, ActivityClaimResult::CLAIMED);
    ASSIGN_OR_FAIL(auto reclaimed_expired,
                   db->claimIncomingActivity("https://a/3", 10, 10));
    EXPECT_EQ(reclaimed_expired, ActivityClaimResult::CLAIMED);

    ASSIGN_OR_FAIL(auto processing,
                   db->claimIncomingActivity("https://a/processing", 0, 100));
    EXPECT_EQ(processing, ActivityClaimResult::CLAIMED);

    ASSIGN_OR_FAIL(auto old, db->claimIncomingActivity("https://a/old", 0, 10));
    EXPECT_EQ(old, ActivityClaimResult::CLAIMED);
    EXPECT_TRUE(mw::isExpected(db->finalizeIncomingActivity(
        "https://a/old", 10)));
    ASSIGN_OR_FAIL(auto newer,
                   db->claimIncomingActivity("https://a/newer", 0, 10));
    EXPECT_EQ(newer, ActivityClaimResult::CLAIMED);
    EXPECT_TRUE(mw::isExpected(db->finalizeIncomingActivity(
        "https://a/newer", 20)));
    ASSIGN_OR_FAIL(auto one_pruned, db->pruneIncomingActivities(21, 1));
    EXPECT_EQ(one_pruned, 1);
    ASSIGN_OR_FAIL(auto old_again,
                   db->claimIncomingActivity("https://a/old", 21, 10));
    EXPECT_EQ(old_again, ActivityClaimResult::CLAIMED);
    ASSIGN_OR_FAIL(auto remaining_pruned, db->pruneIncomingActivities(21, 10));
    EXPECT_EQ(remaining_pruned, 1);
    ASSIGN_OR_FAIL(auto still_processing,
                   db->claimIncomingActivity("https://a/processing", 21, 100));
    EXPECT_EQ(still_processing, ActivityClaimResult::IN_PROGRESS);
    ASSIGN_OR_FAIL(auto newer_again,
                   db->claimIncomingActivity("https://a/newer", 21, 10));
    EXPECT_EQ(newer_again, ActivityClaimResult::CLAIMED);
}

TEST(Data, JobClaimAndComplete)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(int64_t jid,
                   db->enqueueJob("deliver", R"({"x":1})", 0, 0));
    EXPECT_GT(jid, 0);

    ASSIGN_OR_FAIL(auto claimed, db->claimJob(0));
    ASSERT_TRUE(claimed.has_value());
    EXPECT_EQ(claimed->id, jid);
    EXPECT_EQ(claimed->kind, "deliver");

    // No more runnable jobs (the one is now 'running').
    ASSIGN_OR_FAIL(auto none, db->claimJob(0));
    EXPECT_FALSE(none.has_value());

    EXPECT_TRUE(mw::isExpected(db->completeJob(jid)));
}

TEST(Data, JobRunAfterGatesClaim)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(int64_t jid,
                   db->enqueueJob("deliver", "{}", 100, 0));
    // Not runnable yet at t=50.
    ASSIGN_OR_FAIL(auto early, db->claimJob(50));
    EXPECT_FALSE(early.has_value());
    // Runnable at t=100.
    ASSIGN_OR_FAIL(auto ready, db->claimJob(100));
    ASSERT_TRUE(ready.has_value());
    EXPECT_EQ(ready->id, jid);
}

TEST(Data, JobFailBacksOffThenGivesUp)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(int64_t jid, db->enqueueJob("deliver", "{}", 0, 0));
    ASSIGN_OR_FAIL(auto claimed, db->claimJob(0));
    ASSERT_TRUE(claimed.has_value());

    // First failure with max_retries=2: rescheduled with backoff.
    EXPECT_TRUE(mw::isExpected(
        db->failJob(jid, "boom", 0, /*base*/10, /*max*/2)));
    // attempts is now 1 (< 2): still pending but run_after in the future.
    ASSIGN_OR_FAIL(auto not_yet, db->claimJob(0));
    EXPECT_FALSE(not_yet.has_value());
    // Far enough in the future it is runnable again.
    ASSIGN_OR_FAIL(auto retry, db->claimJob(1000000));
    ASSERT_TRUE(retry.has_value());

    // Second failure reaches max_retries=2: gives up (state='failed').
    EXPECT_TRUE(mw::isExpected(
        db->failJob(jid, "boom2", 0, 10, 2)));
    ASSIGN_OR_FAIL(auto dead, db->claimJob(1000000));
    EXPECT_FALSE(dead.has_value());
}

// ─── Cursor pagination stability (design §16.3, decision C4) ───────

TEST(Data, CursorPaginationStableUnderInsertionAndDeletion)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User u, db->createUser(sampleUser("alice")));

    std::vector<int64_t> ids;
    for(int i = 0; i < 10; ++i)
    {
        ids.push_back(insertLocalPost(*db, u.id,
                                      "post " + std::to_string(i)).id);
    }

    // First page: newest 4 (ids 10,9,8,7 in DESC).
    ASSIGN_OR_FAIL(auto page1, db->timelinePublic(Cursor{}, 4));
    ASSERT_THAT(page1, SizeIs(4));
    EXPECT_EQ(page1.front().id, ids[9]);
    EXPECT_EQ(page1.back().id, ids[6]);

    // Insert a new post AND delete an already-seen one. Neither should
    // shift the next page (cursor is keyed on id, not offset).
    int64_t fresh = insertLocalPost(*db, u.id, "fresh").id;
    EXPECT_TRUE(mw::isExpected(db->deletePost(ids[9])));

    // Next page after the last id we saw (ids[6]).
    Cursor c;
    c.max_id = page1.back().id; // ids[6]
    ASSIGN_OR_FAIL(auto page2, db->timelinePublic(c, 4));
    ASSERT_THAT(page2, SizeIs(4));
    // Strictly older than ids[6]: 5,4,3,2.
    EXPECT_EQ(page2.front().id, ids[5]);
    EXPECT_EQ(page2.back().id, ids[2]);
    // The freshly-inserted post (id > ids[6]) must NOT appear here.
    for(const auto& p : page2)
    {
        EXPECT_NE(p.id, fresh);
        EXPECT_LT(p.id, ids[6]);
    }

    // min_id walks the newer direction and returns newest-first.
    Cursor newer;
    newer.min_id = ids[6];
    ASSIGN_OR_FAIL(auto page_newer, db->timelinePublic(newer, 100));
    ASSERT_FALSE(page_newer.empty());
    EXPECT_GT(page_newer.front().id, page_newer.back().id);
    for(const auto& p : page_newer)
    {
        EXPECT_GT(p.id, ids[6]);
    }
}

TEST(Data, PublicTimelineExcludesNonPublic)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User u, db->createUser(sampleUser("alice")));
    insertLocalPost(*db, u.id, "public one");

    NewPost np;
    np.local_author_id = u.id;
    np.content_html = "secret";
    np.visibility = Visibility::FOLLOWERS;
    ASSERT_TRUE(mw::isExpected(db->insertPost(np, {}, "https://f.test/p/")));

    ASSIGN_OR_FAIL(auto tl, db->timelinePublic(Cursor{}, 20));
    EXPECT_THAT(tl, SizeIs(1));
    EXPECT_EQ(tl[0].content_html, "public one");
}

TEST(Data, HomeTimelineIncludesRepliesToUsersPosts)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(sampleUser("alice")));
    ASSIGN_OR_FAIL(User bob, db->createUser(sampleUser("bob")));
    Post alice_post = insertLocalPost(*db, alice.id, "alice root");
    Post bob_post = insertLocalPost(*db, bob.id, "bob root");

    RemoteActor remote;
    remote.uri = "https://remote.test/users/carol";
    remote.username = "carol";
    remote.domain = "remote.test";
    remote.inbox = "https://remote.test/users/carol/inbox";
    remote.public_key_pem = "PUB";
    remote.public_key_id = remote.uri + "#main-key";
    remote.actor_json = "{}";
    ASSIGN_OR_FAIL(remote, db->upsertRemoteActor(remote));

    NewPost reply_to_alice;
    reply_to_alice.uri = "https://remote.test/statuses/reply-alice";
    reply_to_alice.remote_author_id = remote.id;
    reply_to_alice.content_html = "reply to alice";
    reply_to_alice.visibility = Visibility::PUBLIC;
    reply_to_alice.in_reply_to_uri = alice_post.uri;
    ASSIGN_OR_FAIL(auto alice_reply, db->insertPost(
        reply_to_alice, {}, "https://f.test/p/"));

    NewPost reply_to_bob = reply_to_alice;
    reply_to_bob.uri = "https://remote.test/statuses/reply-bob";
    reply_to_bob.content_html = "reply to bob";
    reply_to_bob.in_reply_to_uri = bob_post.uri;
    ASSIGN_OR_FAIL(auto bob_reply, db->insertPost(
        reply_to_bob, {}, "https://f.test/p/"));

    ASSIGN_OR_FAIL(auto tl, db->homeTimelinePosts(
        std::vector<int64_t>{alice.id}, {}, alice.id, Cursor{}, 20,
        "https://f.test/u/alice"));
    std::vector<int64_t> ids;
    for(const auto& post : tl) ids.push_back(post.id);

    EXPECT_NE(std::find(ids.begin(), ids.end(), alice_post.id), ids.end());
    EXPECT_NE(std::find(ids.begin(), ids.end(), alice_reply.id), ids.end());
    EXPECT_EQ(std::find(ids.begin(), ids.end(), bob_reply.id), ids.end());
}

TEST(Data, HomeTimelineIncludesPostsAddressedToUser)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(sampleUser("alice")));
    ASSIGN_OR_FAIL(auto remote, db->upsertRemoteActor(RemoteActor{
        0,
        "https://remote.test/users/carol",
        "carol",
        "remote.test",
        "Carol",
        "https://remote.test/users/carol/inbox",
        std::nullopt,
        "PUB",
        "https://remote.test/users/carol#main-key",
        "{}",
        0,
    }));

    NewPost addressed;
    addressed.uri = "https://remote.test/statuses/mention";
    addressed.remote_author_id = remote.id;
    addressed.content_html = "hi alice";
    addressed.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(auto post, db->insertPost(
        addressed, {{0, "https://f.test/u/alice", "to"}},
        "https://f.test/p/"));

    ASSIGN_OR_FAIL(auto tl, db->homeTimelinePosts(
        std::vector<int64_t>{alice.id}, {}, alice.id, Cursor{}, 20,
        "https://f.test/u/alice"));

    std::vector<int64_t> ids;
    for(const auto& item : tl) ids.push_back(item.id);
    EXPECT_NE(std::find(ids.begin(), ids.end(), post.id), ids.end());
}

TEST(Data, HomeTimelineIncludesFollowedRemoteAuthors)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(sampleUser("alice")));
    ASSIGN_OR_FAIL(auto followed, db->upsertRemoteActor(RemoteActor{
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
    ASSIGN_OR_FAIL(auto other, db->upsertRemoteActor(RemoteActor{
        0,
        "https://remote.test/users/other",
        "other",
        "remote.test",
        "Other",
        "https://remote.test/users/other/inbox",
        std::nullopt,
        "PUB",
        "https://remote.test/users/other#main-key",
        "{}",
        0,
    }));

    NewPost followed_post;
    followed_post.uri = "https://activitypub.academy/statuses/1";
    followed_post.remote_author_id = followed.id;
    followed_post.content_html = "followed remote";
    followed_post.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(auto included, db->insertPost(
        followed_post, {{0, std::string(AS_PUBLIC), "to"}},
        "https://f.test/p/"));

    NewPost other_post = followed_post;
    other_post.uri = "https://remote.test/statuses/1";
    other_post.remote_author_id = other.id;
    other_post.content_html = "other remote";
    ASSIGN_OR_FAIL(auto excluded, db->insertPost(
        other_post, {{0, std::string(AS_PUBLIC), "to"}},
        "https://f.test/p/"));

    ASSIGN_OR_FAIL(auto tl, db->homeTimelinePosts(
        std::vector<int64_t>{alice.id}, std::vector<int64_t>{followed.id},
        alice.id, Cursor{}, 20, "https://f.test/u/alice"));

    std::vector<int64_t> ids;
    for(const auto& item : tl) ids.push_back(item.id);
    EXPECT_NE(std::find(ids.begin(), ids.end(), included.id), ids.end());
    EXPECT_EQ(std::find(ids.begin(), ids.end(), excluded.id), ids.end());
}

TEST(Data, HomeTimelineHidesUnaddressedRemotePrivateFollowedPosts)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(User alice, db->createUser(sampleUser("alice")));
    ASSIGN_OR_FAIL(auto followed, db->upsertRemoteActor(RemoteActor{
        0,
        "https://remote.test/users/carol",
        "carol",
        "remote.test",
        "Carol",
        "https://remote.test/users/carol/inbox",
        std::nullopt,
        "PUB",
        "https://remote.test/users/carol#main-key",
        "{}",
        0,
    }));

    NewPost public_post;
    public_post.uri = "https://remote.test/statuses/public";
    public_post.remote_author_id = followed.id;
    public_post.content_html = "public";
    public_post.visibility = Visibility::PUBLIC;
    ASSIGN_OR_FAIL(auto included, db->insertPost(
        public_post, {{0, std::string(AS_PUBLIC), "to"}},
        "https://f.test/p/"));

    NewPost private_post = public_post;
    private_post.uri = "https://remote.test/statuses/private";
    private_post.content_html = "private";
    private_post.visibility = Visibility::DIRECT;
    ASSIGN_OR_FAIL(auto excluded, db->insertPost(
        private_post, {{0, "https://remote.test/users/other", "to"}},
        "https://f.test/p/"));

    NewPost addressed_post = private_post;
    addressed_post.uri = "https://remote.test/statuses/addressed";
    addressed_post.content_html = "addressed";
    ASSIGN_OR_FAIL(auto addressed, db->insertPost(
        addressed_post, {{0, "https://f.test/u/alice", "to"}},
        "https://f.test/p/"));

    ASSIGN_OR_FAIL(auto tl, db->homeTimelinePosts(
        std::vector<int64_t>{alice.id}, std::vector<int64_t>{followed.id},
        alice.id, Cursor{}, 20, "https://f.test/u/alice"));

    std::vector<int64_t> ids;
    for(const auto& item : tl) ids.push_back(item.id);
    EXPECT_NE(std::find(ids.begin(), ids.end(), included.id), ids.end());
    EXPECT_NE(std::find(ids.begin(), ids.end(), addressed.id), ids.end());
    EXPECT_EQ(std::find(ids.begin(), ids.end(), excluded.id), ids.end());
}

// ─── withWriteRetry behavior ───────────────────────────────────────

// Smoke test that the gmock DataSource implements the interface and can
// stand in for the real one (used by upper-layer tests in later phases).
TEST(DataMock, StandsInForInterface)
{
    DataSourceMock mock;
    User u;
    u.id = 7;
    u.username = "mockuser";
    EXPECT_CALL(mock, getUserById(7))
        .WillOnce(Return(mw::E<std::optional<User>>{std::optional<User>{u}}));

    const DataSourceInterface& iface = mock;
    ASSIGN_OR_FAIL(auto got, iface.getUserById(7));
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->username, "mockuser");
}

TEST(WriteRetry, RetriesRetryableErrorThenSucceeds)
{
    int calls = 0;
    auto txn = [&]() -> mw::E<void> {
        ++calls;
        if(calls < 3)
        {
            return std::unexpected(mw::runtimeError("database is locked"));
        }
        return {};
    };
    EXPECT_TRUE(mw::isExpected(withWriteRetry(txn, 5)));
    EXPECT_EQ(calls, 3);
}

TEST(WriteRetry, DoesNotRetryNonRetryableError)
{
    int calls = 0;
    auto txn = [&]() -> mw::E<void> {
        ++calls;
        return std::unexpected(mw::runtimeError("syntax error"));
    };
    EXPECT_FALSE(withWriteRetry(txn, 5).has_value());
    EXPECT_EQ(calls, 1);
}

TEST(WriteRetry, GivesUpAfterMaxRetries)
{
    int calls = 0;
    auto txn = [&]() -> mw::E<void> {
        ++calls;
        return std::unexpected(mw::runtimeError("SQLITE_BUSY: database busy"));
    };
    EXPECT_FALSE(withWriteRetry(txn, 3).has_value());
    EXPECT_EQ(calls, 4); // initial + 3 retries
}
