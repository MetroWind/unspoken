#include <actpub/engine.hpp>
#include <gtest/gtest.h>
#include <mw/test_utils.hpp>
#include <mw/utils.hpp>

namespace
{

class TestApplication : public ap::Application
{
public:
    bool fail = false;
    mw::E<ap::Decision> decide(ap::Transaction&, const ap::ValidatedActivity&,
                               const ap::LocalRecipient&) override
    {
        return ap::Decision::ACCEPT;
    }
    mw::E<void> apply(ap::Transaction& tx, const ap::AppliedEvent&) override
    {
        DO_OR_RETURN(
            tx.connection().execute("INSERT INTO host_events VALUES (1)"));
        if(fail)
            return std::unexpected(
                mw::runtimeError("Injected projection failure"));
        return {};
    }
};

class FederationEngine : public ::testing::Test
{
protected:
    std::unique_ptr<mw::SQLite> db;
    mw::Crypto crypto;
    mw::HTTPSession http;
    TestApplication application;
    ap::FederationConfig config;
    std::unique_ptr<ap::Session> session;
    ap::SigningActor remote_signer;
    int64_t now = mw::timeToSeconds(mw::Clock::now());

    void SetUp() override
    {
        db = mw::SQLite::connectMemory().value();
        ASSERT_TRUE(
            db->execute("CREATE TABLE host_events(value INTEGER)").has_value());
        config.system_actor_uri = "https://local.test/writer";
        config.activity_uri_prefix = "https://local.test/activities/";
        session = std::make_unique<ap::Session>(config, *db, crypto, http,
                                                application);
        ASSERT_TRUE(session->migrate().has_value());
        auto local_keys = crypto.generateKeyPair(mw::KeyType::RSA).value();
        ap::LocalActor local;
        local.uri = config.system_actor_uri;
        local.key_id = local.uri + "#key";
        local.private_key_pem = local_keys.private_key;
        local.document = {{"id", local.uri},
                          {"type", "Person"},
                          {"inbox", local.uri + "/inbox"},
                          {"outbox", local.uri + "/outbox"},
                          {"followers", local.uri + "/followers"}};
        auto tx = ap::Transaction::begin(*db).value();
        ASSERT_TRUE(session->registerActor(tx, local).has_value());
        ASSERT_TRUE(tx.commit().has_value());
        auto remote_keys = crypto.generateKeyPair(mw::KeyType::RSA).value();
        ap::RemoteActor remote;
        remote.uri = "https://remote.test/writer";
        remote.inbox = remote.uri + "/inbox";
        remote.public_key_id = remote.uri + "#key";
        remote.public_key_pem = remote_keys.public_key;
        remote.actor_json = "{}";
        ASSERT_TRUE(ap::Store(*db).upsertRemoteActor(remote).has_value());
        remote_signer = {remote.uri, remote.public_key_id,
                         remote_keys.private_key};
    }

    nlohmann::json create() const
    {
        nlohmann::json object = {
            {"id", "https://remote.test/article"},
            {"type", "Article"},
            {"attributedTo", remote_signer.actor_uri},
            {"content", "<script>raw()</script>A &amp; B"},
            {"to", nlohmann::json::array({config.system_actor_uri})}};
        return {{"id", "https://remote.test/create/1"},
                {"type", "Create"},
                {"actor", remote_signer.actor_uri},
                {"object", object},
                {"to", object["to"]}};
    }

    ap::IncomingHttpRequest request(const nlohmann::json& activity)
    {
        auto wire =
            ap::signedHttpRequest(config.transport, crypto, remote_signer,
                                  "POST", "https://local.test/inbox",
                                  activity.dump(), "application/activity+json")
                .value();
        return {"POST", "/inbox", wire.header, activity.dump()};
    }
};

TEST_F(FederationEngine, IncomingProjectionAndReceiptCommitTogether)
{
    auto raw = create();
    auto req = request(raw);
    ASSIGN_OR_FAIL(auto prepared, session->prepareInbox(req, "", now));
    ASSIGN_OR_FAIL(auto result, session->acceptInbox(std::move(prepared), now));
    EXPECT_TRUE(result.applied);
    EXPECT_EQ(session->object("https://remote.test/article").value().value(),
              raw["object"]);
    EXPECT_EQ(
        db->evalToValue<int64_t>("SELECT count(*) FROM host_events").value(),
        1);
    ASSIGN_OR_FAIL(auto repeated, session->prepareInbox(req, "", now));
    ASSIGN_OR_FAIL(auto duplicate,
                   session->acceptInbox(std::move(repeated), now));
    EXPECT_TRUE(duplicate.duplicate);
    EXPECT_EQ(
        db->evalToValue<int64_t>("SELECT count(*) FROM host_events").value(),
        1);
}

TEST_F(FederationEngine, FollowersOnlyCreateReachesAcceptedLocalFollower)
{
    ap::Store store(*db);
    ASSIGN_OR_FAIL(auto remote, store.getRemoteActorByUri(
        remote_signer.actor_uri));
    ASSERT_TRUE(remote);
    const std::string followers = remote->uri + "/followers";
    remote->actor_json = nlohmann::json({{"followers", followers}}).dump();
    ASSERT_TRUE(store.upsertRemoteActor(*remote).has_value());
    ap::Follow follow;
    follow.follower_uri = config.system_actor_uri;
    follow.followee_uri = remote->uri;
    ASSERT_TRUE(store.addFollow(follow).has_value());
    auto raw = create();
    raw["to"] = nlohmann::json::array({followers});
    raw["object"]["to"] = raw["to"];
    auto req = request(raw);
    ASSIGN_OR_FAIL(auto pending, session->prepareInbox(req, "", now));
    ASSIGN_OR_FAIL(auto skipped, session->acceptInbox(std::move(pending), now));
    EXPECT_FALSE(skipped.applied);
    EXPECT_EQ(db->evalToValue<int64_t>(
        "SELECT count(*) FROM host_events").value(), 0);

    ASSERT_TRUE(store.setFollowState(follow.follower_uri, follow.followee_uri,
                                    ap::FollowState::ACCEPTED).has_value());
    // An unapplied inbox activity can be retried after recipient selection.
    ASSIGN_OR_FAIL(auto prepared, session->prepareInbox(req, "", now));
    ASSIGN_OR_FAIL(auto result, session->acceptInbox(std::move(prepared), now));
    EXPECT_TRUE(result.applied);
    EXPECT_EQ(db->evalToValue<int64_t>(
        "SELECT count(*) FROM host_events").value(), 1);
    ASSIGN_OR_FAIL(auto repeated, session->prepareInbox(req, "", now));
    ASSIGN_OR_FAIL(auto duplicate,
                   session->acceptInbox(std::move(repeated), now));
    EXPECT_TRUE(duplicate.duplicate);
    EXPECT_EQ(db->evalToValue<int64_t>(
        "SELECT count(*) FROM host_events").value(), 1);

    raw["id"] = "https://remote.test/create/2";
    raw["object"]["id"] = "https://remote.test/article/2";
    raw["to"] = nlohmann::json::array({"https://other.test/followers"});
    raw["object"]["to"] = raw["to"];
    auto unrelated_req = request(raw);
    ASSIGN_OR_FAIL(auto unrelated,
                   session->prepareInbox(unrelated_req, "", now));
    ASSIGN_OR_FAIL(auto rejected,
                   session->acceptInbox(std::move(unrelated), now));
    EXPECT_FALSE(rejected.applied);
    EXPECT_EQ(db->evalToValue<int64_t>(
        "SELECT count(*) FROM host_events").value(), 1);
}

TEST_F(FederationEngine, FailedProjectionRollsBackObjectAndReceipt)
{
    application.fail = true;
    auto req = request(create());
    ASSIGN_OR_FAIL(auto prepared, session->prepareInbox(req, "", now));
    EXPECT_FALSE(session->acceptInbox(std::move(prepared), now).has_value());
    EXPECT_FALSE(
        session->object("https://remote.test/article").value().has_value());
    EXPECT_EQ(
        db->evalToValue<int64_t>("SELECT count(*) FROM host_events").value(),
        0);
    EXPECT_EQ(db->evalToValue<int64_t>("SELECT count(*) FROM ap_inbox_receipts")
                  .value(),
              0);
    application.fail = false;
    ASSIGN_OR_FAIL(auto retry, session->prepareInbox(req, "", now));
    EXPECT_TRUE(session->acceptInbox(std::move(retry), now).value().applied);
}

TEST_F(FederationEngine, LocalContentAndPublicationRollBackTogether)
{
    auto tx = ap::Transaction::begin(*db).value();
    ASSERT_TRUE(db->execute("INSERT INTO host_events VALUES (1)").has_value());
    nlohmann::json object = {{"id", "https://local.test/photo"},
                             {"type", "Image"},
                             {"attributedTo", config.system_actor_uri},
                             {"to", nlohmann::json::array({ap::AS_PUBLIC})}};
    nlohmann::json activity = {{"id", "https://local.test/create/1"},
                               {"type", "Create"},
                               {"actor", config.system_actor_uri},
                               {"object", object},
                               {"to", object["to"]}};
    ASSERT_TRUE(session->publish(tx, activity).has_value());
    ASSERT_TRUE(tx.rollback().has_value());
    EXPECT_FALSE(
        session->object("https://local.test/photo").value().has_value());
    EXPECT_EQ(
        db->evalToValue<int64_t>("SELECT count(*) FROM ap_outbox").value(), 0);
    EXPECT_EQ(
        db->evalToValue<int64_t>("SELECT count(*) FROM host_events").value(),
        0);
}

TEST_F(FederationEngine, BareEmojiTagUsesDefaultImageMediaType)
{
    auto raw = create();
    ASSIGN_OR_FAIL(auto prepared, session->prepareInbox(request(raw), "", now));
    ASSERT_TRUE(session->acceptInbox(std::move(prepared), now).value().applied);
    nlohmann::json reaction = {
        {"id", "https://remote.test/react/1"},
        {"type", "EmojiReact"},
        {"actor", remote_signer.actor_uri},
        {"object", "https://remote.test/article"},
        {"content", ":blob:"},
        {"to", nlohmann::json::array({config.system_actor_uri})},
        {"tag", nlohmann::json::array(
                    {{{"type", "Emoji"},
                      {"name", "blob"},
                      {"icon",
                       {{"type", "Image"},
                        {"url", "https://remote.test/blob.png"}}}}})}};
    ASSIGN_OR_FAIL(auto incoming,
                   session->prepareInbox(request(reaction), "", now));
    ASSERT_TRUE(session->acceptInbox(std::move(incoming), now).value().applied);
    auto reactions =
        ap::Store(*db).reactionsForPost("https://remote.test/article").value();
    ASSERT_EQ(reactions.size(), 1u);
    EXPECT_EQ(reactions.front().remote_emoji_url,
              "https://remote.test/blob.png");
    EXPECT_EQ(reactions.front().remote_emoji_media_type, "image/png");
}

TEST_F(FederationEngine, PrivateObjectAndActivityAreNotPubliclyEnumerable)
{
    auto tx = ap::Transaction::begin(*db).value();
    nlohmann::json object = {
        {"id", "https://local.test/private"},
        {"type", "Note"},
        {"attributedTo", config.system_actor_uri},
        {"content", "private"},
        {"to", nlohmann::json::array({remote_signer.actor_uri})}};
    nlohmann::json activity = {{"id", "https://local.test/create/private"},
                               {"type", "Create"},
                               {"actor", config.system_actor_uri},
                               {"object", object},
                               {"to", object["to"]}};
    ASSERT_TRUE(session->publish(tx, activity).has_value());
    ASSERT_TRUE(tx.commit().has_value());
    EXPECT_FALSE(session->objectForActor("https://local.test/private").value());
    EXPECT_TRUE(session
                    ->objectForActor("https://local.test/private",
                                     remote_signer.actor_uri)
                    .value());
    auto page = session
                    ->outboxPage(config.system_actor_uri, {}, 20,
                                 "https://local.test/outbox?page=true")
                    .value();
    EXPECT_TRUE(page["orderedItems"].empty());
}

TEST_F(FederationEngine, MalformedContentIsRejectedBeforeHostProjection)
{
    auto raw = create();
    raw["object"]["content"] = 42;
    EXPECT_FALSE(session->prepareInbox(request(raw), "", now).has_value());
    EXPECT_EQ(
        db->evalToValue<int64_t>("SELECT count(*) FROM host_events").value(),
        0);
}

TEST_F(FederationEngine, ReusedActivityIdCannotChangeAuthenticatedContent)
{
    auto raw = create();
    ASSIGN_OR_FAIL(auto first, session->prepareInbox(request(raw), "", now));
    ASSERT_TRUE(session->acceptInbox(std::move(first), now).value().applied);
    raw["object"]["content"] = "replacement";
    ASSIGN_OR_FAIL(auto second, session->prepareInbox(request(raw), "", now));
    EXPECT_FALSE(session->acceptInbox(std::move(second), now).has_value());
    EXPECT_EQ(
        db->evalToValue<int64_t>("SELECT count(*) FROM host_events").value(),
        1);
}

TEST_F(FederationEngine, LaterRecipientDoesNotRepeatGlobalObjectMutation)
{
    auto raw = create();
    raw["to"].push_back("https://local.test/reader");
    raw["object"]["to"] = raw["to"];
    ASSIGN_OR_FAIL(auto first, session->prepareInbox(request(raw), "", now));
    ASSERT_TRUE(session->acceptInbox(std::move(first), now).value().applied);
    auto local = session->localActor(config.system_actor_uri).value().value();
    local.uri = "https://local.test/reader";
    local.document["id"] = local.uri;
    local.key_id = local.uri + "#key";
    {
        ASSIGN_OR_FAIL(auto tx, ap::Transaction::begin(*db));
        ASSERT_TRUE(session->registerActor(tx, local).has_value());
        ASSERT_TRUE(tx.commit().has_value());
    }
    ASSIGN_OR_FAIL(auto second, session->prepareInbox(request(raw), "", now));
    EXPECT_TRUE(session->acceptInbox(std::move(second), now).value().applied);
    EXPECT_EQ(
        db->evalToValue<int64_t>("SELECT count(*) FROM ap_objects").value(), 1);
    EXPECT_EQ(
        db->evalToValue<int64_t>("SELECT count(*) FROM host_events").value(),
        2);
}

TEST_F(FederationEngine, RemoteActorCannotAllocateObjectsOnLocalOrigin)
{
    auto raw = create();
    raw["object"]["id"] = "https://local.test/forged";
    ASSIGN_OR_FAIL(auto prepared, session->prepareInbox(request(raw), "", now));
    EXPECT_FALSE(
        session->acceptInbox(std::move(prepared), now).value().applied);
    EXPECT_FALSE(session->object("https://local.test/forged").value());
    EXPECT_EQ(
        db->evalToValue<int64_t>("SELECT count(*) FROM host_events").value(),
        0);
}

} // namespace
