#include <gtest/gtest.h>
#include <gmock/gmock.h>

#define private public
#define protected public
#include "app.hpp"
#undef private
#undef protected

#include "database_mock.hpp"
#include <mw/http_client_mock.hpp>
#include <mw/crypto_mock.hpp>
#include "config.hpp"
#include <filesystem>
#include <cstddef>

using ::testing::_;
using ::testing::Return;
using ::testing::NiceMock;
using ::testing::Invoke;
using ::testing::ByMove;

class AppRemoteUserTest : public ::testing::Test {
protected:
    void SetUp() override {
        Config::get().server_url_root = "https://example.com";
        Config::get().db_path = ":memory:";
    }
};

TEST_F(AppRemoteUserTest, FetchRemoteActor) {
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
    std::transform(remote_actor_json.begin(), remote_actor_json.end(), resp.payload.begin(), 
                   [](char c) { return std::byte(c); });

    EXPECT_CALL(*http_ptr, get(testing::A<const mw::HTTPRequest&>()))
        .WillOnce(Return(&resp));

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 0};
    App app(std::move(db_mock), listen, std::move(http_mock), std::move(crypto_mock));
    
    auto res = app.fetchRemoteActor("https://remote.com/users/alice", system_user);
    EXPECT_TRUE(res.has_value());
    EXPECT_EQ(res->at("id"), "test");
}

TEST_F(AppRemoteUserTest, ParseRemoteActor) {
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto http_mock = std::make_unique<NiceMock<mw::HTTPSessionMock>>();
    auto crypto_mock = std::make_unique<NiceMock<mw::CryptoMock>>();

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 0};
    App app(std::move(db_mock), listen, std::move(http_mock), std::move(crypto_mock));

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

TEST_F(AppRemoteUserTest, EnsureRemoteUserFetchSuccess) {
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
        .WillRepeatedly(Return(std::make_optional(system_user))); // System actor fetch

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
    std::transform(remote_actor_json.begin(), remote_actor_json.end(), resp.payload.begin(), 
                   [](char c) { return std::byte(c); });

    EXPECT_CALL(*http_ptr, get(testing::A<const mw::HTTPRequest&>()))
        .WillOnce(Return(&resp));

    EXPECT_CALL(*db_ptr, createUser(_))
        .WillOnce(Invoke([](const User& u) -> mw::E<int64_t> {
            EXPECT_EQ(u.username, "alice");
            EXPECT_EQ(u.uri, "https://remote.com/users/alice");
            EXPECT_EQ(u.public_key, "public_key_pem");
            return 123;
        }));

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 0};
    App app(std::move(db_mock), listen, std::move(http_mock), std::move(crypto_mock));

    auto res = app.ensureRemoteUser("https://remote.com/users/alice");
    EXPECT_TRUE(res.has_value());
    EXPECT_EQ(res.value(), 123);
}
