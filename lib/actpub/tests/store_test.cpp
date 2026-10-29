#include <actpub/store.hpp>
#include <gtest/gtest.h>
#include <mw/test_utils.hpp>

TEST(FederationStore, FreshSchemaAndRelationshipRollback)
{
    ASSIGN_OR_FAIL(auto db, mw::SQLite::connectMemory());
    ap::Store store(*db);
    ASSERT_TRUE(store.migrate().has_value());
    ASSERT_TRUE(store.migrate().has_value());
    {
        ASSIGN_OR_FAIL(auto tx, ap::Transaction::begin(*db));
        ap::Follow follow;
        follow.follower_uri = "https://remote.test/a";
        follow.followee_uri = "https://local.test/writer";
        follow.state = ap::FollowState::ACCEPTED;
        follow.follow_activity_uri = "https://remote.test/follow/1";
        ASSERT_TRUE(store.addFollow(follow).has_value());
        EXPECT_EQ(store.followerUris(follow.followee_uri).value().size(), 1u);
    }
    EXPECT_TRUE(
        store.followerUris("https://local.test/writer").value().empty());
    EXPECT_EQ(db->evalToValue<int64_t>(
                    "SELECT count(*) FROM sqlite_master WHERE name='users'")
                  .value(),
              0);
}

TEST(FederationStore, ActorAndInteractionRoundTrip)
{
    ASSIGN_OR_FAIL(auto db, mw::SQLite::connectMemory());
    ap::Store store(*db);
    ASSERT_TRUE(store.migrate().has_value());
    ap::RemoteActor actor;
    actor.uri = "https://remote.test/actor";
    actor.username = "writer";
    actor.domain = "remote.test";
    actor.inbox = actor.uri + "/inbox";
    actor.public_key_id = actor.uri + "#key";
    actor.public_key_pem = "PUBLIC";
    actor.actor_json = "{}";
    ASSIGN_OR_FAIL(auto stored, store.upsertRemoteActor(actor));
    EXPECT_EQ(store.getRemoteActorById(stored.id).value()->uri, actor.uri);
    ap::Like like;
    like.actor_uri = actor.uri;
    like.post_uri = "https://local.test/article";
    like.activity_uri = "https://remote.test/like/1";
    ASSERT_TRUE(store.addLike(like).has_value());
    ASSERT_TRUE(store.addLike(like).has_value());
    auto rows = store.likesForPost(like.post_uri).value();
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows.front().activity_uri, like.activity_uri);
    ASSERT_TRUE(store.removeLike(like.actor_uri, like.post_uri).has_value());
    EXPECT_TRUE(store.likesForPost(like.post_uri).value().empty());
}

TEST(FederationStore, ExpiredJobIsRecoveredAndOldWorkerCannotComplete)
{
    ASSIGN_OR_FAIL(auto db, mw::SQLite::connectMemory());
    ap::Store store(*db);
    ASSERT_TRUE(store.migrate().has_value());
    ASSERT_TRUE(store.enqueueJob("deliver", "{}", 100, 100).has_value());
    ASSIGN_OR_FAIL(auto first, store.claimJob(100, 10));
    ASSERT_TRUE(first.has_value());
    EXPECT_FALSE(store.claimJob(109, 10).value().has_value());
    ASSIGN_OR_FAIL(auto second, store.claimJob(110, 10));
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(first->id, second->id);
    EXPECT_NE(first->lease_token, second->lease_token);
    EXPECT_FALSE(store.completeJob(*first).has_value());
    EXPECT_FALSE(store.failJob(*first, "late", 110, 30, 8).has_value());
    EXPECT_TRUE(store.completeJob(*second).has_value());
    EXPECT_FALSE(store.claimJob(200).value().has_value());
}

TEST(FederationStore, LaterDeliveryCannotOvertakeEarlierRetry)
{
    ASSIGN_OR_FAIL(auto db, mw::SQLite::connectMemory());
    ap::Store store(*db);
    ASSERT_TRUE(store.migrate().has_value());
    nlohmann::json payload = {{"target_inbox", "https://remote.test/inbox"},
                              {"signer_actor", "https://local.test/actor"}};
    ASSIGN_OR_FAIL(auto first_id,
                   store.enqueueJob("deliver", payload.dump(), 100, 100));
    ASSIGN_OR_FAIL(auto second_id,
                   store.enqueueJob("deliver", payload.dump(), 100, 100));
    ASSIGN_OR_FAIL(auto first, store.claimJob(100));
    ASSERT_TRUE(first);
    EXPECT_EQ(first->id, first_id);
    ASSERT_TRUE(store.failJob(*first, "offline", 100, 30, 8).has_value());
    EXPECT_FALSE(store.claimJob(101).value().has_value());
    ASSIGN_OR_FAIL(auto retried, store.claimJob(160));
    ASSERT_TRUE(retried);
    EXPECT_EQ(retried->id, first_id);
    ASSERT_TRUE(store.completeJob(*retried).has_value());
    EXPECT_EQ(store.claimJob(160).value()->id, second_id);
}

TEST(FederationStore, ApplicationPinsProtectActorUntilReleased)
{
    ASSIGN_OR_FAIL(auto db, mw::SQLite::connectMemory());
    ap::Store store(*db);
    ASSERT_TRUE(store.migrate().has_value());
    ap::RemoteActor actor;
    actor.uri = "https://remote.test/writer";
    actor.actor_json = "{}";
    actor.fetched_at = 1;
    ASSERT_TRUE(store.upsertRemoteActor(actor).has_value());
    ASSERT_TRUE(store.pinActor(actor.uri, "comment", "123").has_value());
    ASSERT_TRUE(store.pinActor(actor.uri, "comment", "123").has_value());
    EXPECT_EQ(store.collectUnreferencedRemoteActors(2, 10).value(), 0);
    ASSERT_TRUE(store.unpinActor(actor.uri, "comment", "123", 2).has_value());
    EXPECT_EQ(store.collectUnreferencedRemoteActors(2, 10).value(), 0);
    EXPECT_EQ(store.collectUnreferencedRemoteActors(3, 10).value(), 1);
}
