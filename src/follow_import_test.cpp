#include "follow_import.hpp"

#include <sstream>
#include <gtest/gtest.h>
#include <actpub/transaction.hpp>
#include <mw/test_utils.hpp>

namespace unspoken
{
namespace
{
// Replace only the transfer boundary; retain production session configuration.
class ImportHttp : public mw::HTTPSession
{
public:
    const DataSourceSQLite* data = nullptr;
    std::vector<mw::HTTPResponse> responses;
    std::vector<mw::HTTPRequest> requests;

    mw::E<mw::HTTPResponse> getStream(
        const mw::HTTPRequest& request,mw::ChunkCallback consume) override
    {
        EXPECT_FALSE(ap::inTransaction(data->connection()).value());
        EXPECT_EQ(connectionTimeout(),std::chrono::seconds(5));
        EXPECT_EQ(transferTimeout(),std::chrono::seconds(20));
        requests.push_back(request);
        if(responses.empty())
            return std::unexpected(mw::runtimeError("Injected offline server"));
        auto response = responses.front();
        responses.erase(responses.begin());
        if(!consume(response.payload))
            return std::unexpected(mw::runtimeError(mw::HTTP_ABORTED_BY_CALLER));
        response.payload.clear();
        return response;
    }
};

class FollowImport : public ::testing::Test
{
protected:
    Config config;
    std::unique_ptr<DataSourceSQLite> data;
    mw::Crypto crypto;
    ImportHttp http;
    User user;

    void SetUp() override
    {
        config.url_root = "https://local.test/social/";
        config.public_domain = "handles.test";
        ASSIGN_OR_FAIL(data,DataSourceSQLite::newFromMemory());
        http.data = data.get();
        NewUser input;
        input.username = "viewer";
        input.oidc_iss = "https://issuer.test/";
        input.oidc_sub = "viewer";
        input.private_key_pem = "private";
        input.public_key_pem = "public";
        ASSIGN_OR_FAIL(user,data->createUser(input));
        ASSIGN_OR_FAIL(auto keys,crypto.generateKeyPair(mw::KeyType::RSA));
        ASSERT_TRUE(data->setSystemActor(keys.private_key,keys.public_key));
    }

    void program(const std::string& username,const std::string& actor_uri,
                 bool include_actor = true)
    {
        nlohmann::json webfinger = {{"links",nlohmann::json::array({
            {{"rel","self"},{"type","application/activity+json"},
             {"href",actor_uri}}})}};
        http.responses.emplace_back(200,webfinger.dump());
        if(!include_actor) return;
        nlohmann::json actor = {{"id",actor_uri},{"type","Person"},
            {"preferredUsername",username},{"inbox",actor_uri+"/inbox"},
            {"publicKey",{{"id",actor_uri+"#key"},{"owner",actor_uri},
                          {"publicKeyPem","public"}}}};
        http.responses.emplace_back(200,actor.dump());
    }

    mw::E<FollowImportResult> run(const std::string& text)
    {
        std::istringstream input(text);
        std::ostringstream output;
        return importFollows(config,*data,crypto,http,user,input,output,
                              std::chrono::milliseconds(0));
    }
};
} // namespace

TEST_F(FollowImport, QueuesPendingFollowAndSkipsDuplicatesAndReruns)
{
    program("remote","https://remote.test/users/remote");
    ASSIGN_OR_FAIL(auto result,run(
        "\xef\xbb\xbf @remote@REMOTE.TEST \r\nremote@remote.test\n\n# comment\n"));
    EXPECT_EQ(result.queued,1);
    EXPECT_EQ(result.skipped,1);
    EXPECT_EQ(result.failed,0);
    ASSERT_EQ(http.requests.size(),2u);
    EXPECT_FALSE(http.requests[0].header.contains("Signature"));
    EXPECT_TRUE(http.requests[1].header.contains("Signature"));
    const auto actor = "https://remote.test/users/remote";
    ASSIGN_OR_FAIL(auto follow,data->getFollow(config.url_root+"u/viewer",actor));
    ASSERT_TRUE(follow);
    EXPECT_EQ(follow->state,FollowState::PENDING);
    ASSIGN_OR_FAIL(auto job,data->claimJob(9999999999));
    ASSERT_TRUE(job);
    auto payload = nlohmann::json::parse(job->payload_json);
    EXPECT_EQ(payload["activity"]["type"],"Follow");
    EXPECT_EQ(payload["activity"]["id"],*follow->follow_activity_uri);
    EXPECT_EQ(payload["activity"]["actor"],config.url_root+"u/viewer");
    EXPECT_EQ(payload["activity"]["object"],actor);
    EXPECT_EQ(payload["target_inbox"],std::string(actor)+"/inbox");
    program("remote",actor,false);
    ASSIGN_OR_FAIL(auto rerun,run("@remote@remote.test\n"));
    EXPECT_EQ(rerun.queued,0);
    EXPECT_EQ(rerun.skipped,1);
    EXPECT_EQ(data->getFollow(config.url_root+"u/viewer",actor).value()
        ->follow_activity_uri,follow->follow_activity_uri);
    EXPECT_EQ(data->connection().evalToValue<int64_t>(
        "SELECT count(*) FROM ap_jobs").value(),1);
    EXPECT_EQ(data->getSchemaVersion().value(),6);
}

TEST_F(FollowImport, ContinuesAfterResolutionAndValidationFailures)
{
    http.responses.emplace_back(503,"offline");
    program("ok","https://remote.test/users/ok");
    ASSIGN_OR_FAIL(auto result,run(
        "not-a-handle\n@bad@remote.test\n@ok@remote.test\n"));
    EXPECT_EQ(result.queued,1);
    EXPECT_EQ(result.failed,2);
    EXPECT_EQ(http.requests.size(),3u);
    EXPECT_TRUE(data->getFollow(config.url_root+"u/viewer",
                                "https://remote.test/users/ok").value());
}

TEST_F(FollowImport, AddsLocalFollowsAndSkipsSelfAndAcceptedFollows)
{
    NewUser input;
    input.username = "neighbor";
    input.oidc_iss = "https://issuer.test/";
    input.oidc_sub = "neighbor";
    input.private_key_pem = "private";
    input.public_key_pem = "public";
    ASSERT_TRUE(data->createUser(input));
    ASSIGN_OR_FAIL(auto result,run(
        "@viewer@handles.test\n@neighbor@handles.test\n"
        "@neighbor@local.test\n@missing@handles.test\n"));
    EXPECT_EQ(result.local,1);
    EXPECT_EQ(result.skipped,2);
    EXPECT_EQ(result.failed,1);
    EXPECT_TRUE(http.requests.empty());
    auto follow = data->getFollow(config.url_root+"u/viewer",
                                  config.url_root+"u/neighbor").value();
    ASSERT_TRUE(follow);
    EXPECT_EQ(follow->state,FollowState::ACCEPTED);
    EXPECT_EQ(data->connection().evalToValue<int64_t>(
        "SELECT count(*) FROM ap_jobs").value(),0);
}

TEST_F(FollowImport, QueueFailureRollsBackNewActorAndPendingFollow)
{
    ASSERT_TRUE(data->connection().execute(
        "CREATE TRIGGER fail_import_job BEFORE INSERT ON ap_jobs "
        "BEGIN SELECT RAISE(ABORT,'injected queue failure'); END;"));
    program("remote","https://remote.test/users/remote");
    ASSIGN_OR_FAIL(auto result,run("@remote@remote.test\n"));
    EXPECT_EQ(result.failed,1);
    EXPECT_EQ(result.queued,0);
    EXPECT_FALSE(data->getFollow(config.url_root+"u/viewer",
                                 "https://remote.test/users/remote").value());
    EXPECT_FALSE(data->getRemoteActorByUri(
        "https://remote.test/users/remote").value());
    EXPECT_EQ(data->connection().evalToValue<int64_t>(
        "SELECT count(*) FROM ap_outbox").value(),0);
    ASSERT_TRUE(data->connection().execute("DROP TRIGGER fail_import_job"));
    program("remote","https://remote.test/users/remote");
    ASSIGN_OR_FAIL(auto retry,run("@remote@remote.test\n"));
    EXPECT_EQ(retry.queued,1);
}

TEST_F(FollowImport, AliasesResolveToOneFollow)
{
    program("remote","https://remote.test/users/remote");
    program("remote","https://remote.test/users/remote",false);
    ASSIGN_OR_FAIL(auto result,run(
        "@remote@remote.test\n@alias@elsewhere.test\n"));
    EXPECT_EQ(result.queued,1);
    EXPECT_EQ(result.skipped,1);
    EXPECT_EQ(data->connection().evalToValue<int64_t>(
        "SELECT count(*) FROM ap_jobs").value(),1);
}
} // namespace unspoken
