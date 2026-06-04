#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <gmock/gmock.h>
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

} // namespace

TEST(Data, SchemaVersionIsOne)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(int64_t v, db->getSchemaVersion());
    EXPECT_EQ(v, 1);
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
    ASSIGN_OR_FAIL(RemoteActor stored, db->upsertRemoteActor(a));
    EXPECT_GT(stored.id, 0);

    // Upsert again with a new display name updates in place.
    a.display_name = "Bobby";
    ASSIGN_OR_FAIL(RemoteActor stored2, db->upsertRemoteActor(a));
    EXPECT_EQ(stored2.id, stored.id);
    EXPECT_EQ(stored2.display_name, "Bobby");

    ASSIGN_OR_FAIL(auto got, db->getRemoteActorByUri(a.uri));
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->username, "bob");
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
    EXPECT_TRUE(mw::isExpected(db->removeBoost(actor, post)));

    EXPECT_TRUE(mw::isExpected(
        db->addReaction(Reaction{0, actor, post, ":blobcat:", {}, 0})));
    EXPECT_TRUE(mw::isExpected(
        db->addReaction(Reaction{0, actor, post, "👍", {}, 0})));
    ASSIGN_OR_FAIL(auto reacts, db->reactionsForPost(post));
    EXPECT_THAT(reacts, SizeIs(2));
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

TEST(Data, ActivityDedup)
{
    ASSIGN_OR_FAIL(auto db, DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(bool first, db->markActivitySeen("https://a/1", 0));
    EXPECT_TRUE(first);
    ASSIGN_OR_FAIL(bool again, db->markActivitySeen("https://a/1", 0));
    EXPECT_FALSE(again);
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
