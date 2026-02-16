#include <gmock/gmock.h>
#include <gtest/gtest.h>

#define private public
#define protected public
#include "app.hpp"
#undef private
#undef protected

#include <cstddef>
#include <filesystem>

#include <mw/crypto_mock.hpp>
#include <mw/http_client_mock.hpp>

#include "config.hpp"
#include "database_mock.hpp"

using ::testing::_;
using ::testing::ByMove;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;

class AppRemoteUserTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        Config::get().server_url_root = "https://example.com";
        Config::get().db_path = ":memory:";
    }
};

TEST_F(AppRemoteUserTest, FetchRemoteActor)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto http_mock = std::make_unique<NiceMock<mw::HTTPSessionMock>>();
    auto crypto_mock = std::make_unique<NiceMock<mw::CryptoMock>>();

    auto http_ptr = http_mock.get();
    auto crypto_ptr = crypto_mock.get();

    User system_user;
    system_user.username = "__system__";
    system_user.uri = "https://example.com";
    system_user.private_key = "private_key";

    EXPECT_CALL(*crypto_ptr, sign(_, _, _))
        .WillOnce(Return(std::vector<uint8_t>{1, 2, 3}));

    std::string remote_actor_json = R"({"id": "test"})";
    mw::HTTPResponse resp;
    resp.status = 200;
    resp.payload.resize(remote_actor_json.size());
    std::transform(remote_actor_json.begin(), remote_actor_json.end(),
                   resp.payload.begin(), [](char c) { return std::byte(c); });

    EXPECT_CALL(*http_ptr, get(testing::A<const mw::HTTPRequest&>()))
        .WillOnce(Return(&resp));

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 0};
    App app(std::move(db_mock), listen, std::move(http_mock),
            std::move(crypto_mock));

    auto res =
        app.fetchRemoteActor("https://remote.com/users/alice", system_user);
    EXPECT_TRUE(res.has_value());
    EXPECT_EQ(res->at("id"), "test");
}

TEST_F(AppRemoteUserTest, ParseRemoteActor)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto http_mock = std::make_unique<NiceMock<mw::HTTPSessionMock>>();
    auto crypto_mock = std::make_unique<NiceMock<mw::CryptoMock>>();

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 0};
    App app(std::move(db_mock), listen, std::move(http_mock),
            std::move(crypto_mock));

    std::string remote_actor_json = R"({
        "id": "https://remote.com/users/alice",
        "preferredUsername": "alice",
        "name": "Alice Wonderland",
        "summary": "Just a test",
        "inbox": "https://remote.com/users/alice/inbox",
        "publicKey": {
            "publicKeyPem": "public_key_pem"
        }
    })";

    auto j = nlohmann::json::parse(remote_actor_json);

    User u = app.parseRemoteActor(j, "https://remote.com/users/alice");

    EXPECT_EQ(u.uri, "https://remote.com/users/alice");
    EXPECT_EQ(u.username, "alice");
    EXPECT_EQ(u.display_name, "Alice Wonderland");
    EXPECT_EQ(u.bio, "Just a test");
    EXPECT_EQ(u.inbox, "https://remote.com/users/alice/inbox");
    EXPECT_EQ(u.public_key, "public_key_pem");
    EXPECT_EQ(u.host, "remote.com");
}

TEST_F(AppRemoteUserTest, EnsureRemoteUserFetchSuccess)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto http_mock = std::make_unique<NiceMock<mw::HTTPSessionMock>>();
    auto crypto_mock = std::make_unique<NiceMock<mw::CryptoMock>>();

    auto db_ptr = db_mock.get();
    auto http_ptr = http_mock.get();
    auto crypto_ptr = crypto_mock.get();

    User system_user;
    system_user.username = "__system__";
    system_user.uri = "https://example.com";
    system_user.private_key = "private_key";

    EXPECT_CALL(*db_ptr, getUserByUri("https://remote.com/users/alice"))
        .WillOnce(Return(std::nullopt)); // First check fails

    EXPECT_CALL(*db_ptr, getUserByUri("https://example.com"))
        .WillRepeatedly(
            Return(std::make_optional(system_user))); // System actor fetch

    EXPECT_CALL(*crypto_ptr, sign(_, _, _))
        .WillRepeatedly(Return(std::vector<uint8_t>{1, 2, 3}));

    std::string remote_actor_json = R"({
        "id": "https://remote.com/users/alice",
        "type": "Person",
        "preferredUsername": "alice",
        "inbox": "https://remote.com/users/alice/inbox",
        "publicKey": {
            "id": "https://remote.com/users/alice#main-key",
            "owner": "https://remote.com/users/alice",
            "publicKeyPem": "public_key_pem"
        }
    })";

    mw::HTTPResponse resp;
    resp.status = 200;
    resp.payload.resize(remote_actor_json.size());
    std::transform(remote_actor_json.begin(), remote_actor_json.end(),
                   resp.payload.begin(), [](char c) { return std::byte(c); });

    EXPECT_CALL(*http_ptr, get(testing::A<const mw::HTTPRequest&>()))
        .WillOnce(Return(&resp));

    EXPECT_CALL(*db_ptr, createUser(_))
        .WillOnce(Invoke(
            [](const User& u) -> mw::E<int64_t>
            {
                EXPECT_EQ(u.username, "alice");
                EXPECT_EQ(u.uri, "https://remote.com/users/alice");
                EXPECT_EQ(u.public_key, "public_key_pem");
                return 123;
            }));

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 0};
    App app(std::move(db_mock), listen, std::move(http_mock),
            std::move(crypto_mock));

    auto res = app.ensureRemoteUser("https://remote.com/users/alice");
    EXPECT_TRUE(res.has_value());
    EXPECT_EQ(res.value(), 123);
}

TEST_F(AppRemoteUserTest, ResolveRemoteUser_HostMeta)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto http_mock = std::make_unique<NiceMock<mw::HTTPSessionMock>>();
    auto db_ptr = db_mock.get();
    auto http_ptr = http_mock.get();

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 0};
    App app(std::move(db_mock), listen, std::move(http_mock), nullptr);

    auto set_payload = [](mw::HTTPResponse& resp, const std::string& data)
    {
        resp.payload.resize(data.size());
        std::transform(data.begin(), data.end(), resp.payload.begin(),
                       [](char c) { return std::byte(c); });
    };

    // 1. host-meta request
    std::string host_meta_xml =
        R"(<?xml version="1.0" encoding="UTF-8"?><XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0"><Link type="application/xrd+xml" template="https://example.com/api/webfinger?resource={uri}" rel="lrdd" /></XRD>)";
    mw::HTTPResponse host_meta_resp;
    host_meta_resp.status = 200;
    set_payload(host_meta_resp, host_meta_xml);

    // 2. WebFinger request (using template)
    std::string webfinger_json =
        R"({"links":[{"rel":"self","type":"application/activity+json","href":"https://example.com/users/alice"}]})";
    mw::HTTPResponse wf_resp;
    wf_resp.status = 200;
    set_payload(wf_resp, webfinger_json);

    // Expect host-meta call (getWebFingerUrl calls get(string) ->
    // get(HTTPRequest))
    EXPECT_CALL(*http_ptr, get(testing::_))
        .WillOnce(Invoke(
            [&](const mw::HTTPRequest& req) -> mw::E<const mw::HTTPResponse*>
            {
                EXPECT_EQ(req.url, "https://example.com/.well-known/host-meta");
                return &host_meta_resp;
            }))
        .WillOnce(Invoke(
            [&](const mw::HTTPRequest& req) -> mw::E<const mw::HTTPResponse*>
            {
                // Template replacement verification
                EXPECT_EQ(req.url,
                          "https://example.com/api/"
                          "webfinger?resource=acct%3Aalice%40example.com");
                return &wf_resp;
            }));

    User u;
    u.id = 123;
    u.uri = "https://example.com/users/alice";
    EXPECT_CALL(*db_ptr, getUserByUri("https://example.com/users/alice"))
        .WillRepeatedly(Return(std::make_optional(u)));
    EXPECT_CALL(*db_ptr, getUserById(123))
        .WillRepeatedly(Return(std::make_optional(u)));

    auto res = app.resolveRemoteUser("alice", "example.com");
    EXPECT_TRUE(res.has_value());
    EXPECT_TRUE(res.value().has_value());
    EXPECT_EQ(res.value()->id, 123);
}

TEST_F(AppRemoteUserTest, ResolveRemoteUser_Fallback)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto http_mock = std::make_unique<NiceMock<mw::HTTPSessionMock>>();
    auto db_ptr = db_mock.get();
    auto http_ptr = http_mock.get();

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 0};
    App app(std::move(db_mock), listen, std::move(http_mock), nullptr);

    auto set_payload = [](mw::HTTPResponse& resp, const std::string& data)
    {
        resp.payload.resize(data.size());
        std::transform(data.begin(), data.end(), resp.payload.begin(),
                       [](char c) { return std::byte(c); });
    };

    // 1. host-meta request (Fail)
    mw::HTTPResponse host_meta_resp;
    host_meta_resp.status = 404;

    // 2. WebFinger request (Fallback)
    std::string webfinger_json =
        R"({"links":[{"rel":"self","type":"application/activity+json","href":"https://example.com/users/bob"}]})";
    mw::HTTPResponse wf_resp;
    wf_resp.status = 200;
    set_payload(wf_resp, webfinger_json);

    // Expect host-meta call
    EXPECT_CALL(*http_ptr, get(testing::_))
        .WillOnce(Return(&host_meta_resp))
        .WillOnce(Invoke(
            [&](const mw::HTTPRequest& req) -> mw::E<const mw::HTTPResponse*>
            {
                EXPECT_EQ(req.url,
                          "https://example.com/.well-known/"
                          "webfinger?resource=acct%3abob%40example.com");
                return &wf_resp;
            }));

    User u;
    u.id = 456;
    u.uri = "https://example.com/users/bob";
    EXPECT_CALL(*db_ptr, getUserByUri("https://example.com/users/bob"))
        .WillRepeatedly(Return(std::make_optional(u)));
    EXPECT_CALL(*db_ptr, getUserById(456))
        .WillRepeatedly(Return(std::make_optional(u)));

    auto res = app.resolveRemoteUser("bob", "example.com");
    EXPECT_TRUE(res.has_value());
    EXPECT_TRUE(res.value().has_value());
    EXPECT_EQ(res.value()->id, 456);
}
