#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "app.hpp"
#include "database_mock.hpp"
#include <mw/http_client.hpp>
#include <mw/http_client_mock.hpp>
#include "http_utils.hpp"
#include "config.hpp"
#include <filesystem>
#include <fstream>
#include <thread>

using ::testing:: _;
using ::testing::Return;
using ::testing::NiceMock;
using ::testing::HasSubstr;

class AppTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        Config::get().server_url_root = "http://localhost:18080";
        Config::get().posts_per_page = 20;
        Config::get().db_path = ":memory:";
        Config::get().data_dir = ".";
        Config::get().port = 18080;
        Config::get().nodeinfo.name = "TestNode";
    }

    void TearDown() override
    {
        Config::get() = Config();
    }
};

TEST_F(AppTest, IndexPage)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto* db_ptr = db_mock.get();

    // Mock Public Timeline
    std::vector<Post> posts;
    Post p1;
    p1.content_html = "<p>Hello</p>";
    p1.created_at = 1234567890;
    p1.author_id = 1;
    posts.push_back(p1);

    User u1;
    u1.id = 1;
    u1.username = "alice";
    u1.display_name = "Alice";

    EXPECT_CALL(*db_ptr, getSession(_)).WillRepeatedly(Return(std::nullopt));
    EXPECT_CALL(*db_ptr, getPublicTimeline(_, _)).WillRepeatedly(Return(posts));
    EXPECT_CALL(*db_ptr, getUserById(1)).WillRepeatedly(Return(std::make_optional(u1)));

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);

    auto start_res = app.start();
    ASSERT_TRUE(start_res) << "Failed to start app: " << mw::errorMsg(start_res.error());

    {
        mw::HTTPSession client;
        auto res = client.get("http://localhost:18080/");
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ((*res)->status, 200);
        EXPECT_THAT((*res)->payloadAsStr(), HasSubstr("Alice"));
        EXPECT_THAT((*res)->payloadAsStr(), HasSubstr("<p>Hello</p>"));
    }

    app.stop();
    app.wait();
}

TEST_F(AppTest, UserProfile)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto* db_ptr = db_mock.get();

    User u1;
    u1.id = 1;
    u1.username = "alice";
    u1.display_name = "Alice";
    u1.uri = "http://localhost:18080/u/alice";

    EXPECT_CALL(*db_ptr, getUserByUsername("alice")).WillRepeatedly(Return(std::make_optional(u1)));
    EXPECT_CALL(*db_ptr, getUserPosts(1, _, _)).WillRepeatedly(Return(std::vector<Post>{}));
    EXPECT_CALL(*db_ptr, getSession(_)).WillRepeatedly(Return(std::nullopt));

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);

    auto start_res = app.start();
    ASSERT_TRUE(start_res) << "Failed to start app: " << mw::errorMsg(start_res.error());

    {
        mw::HTTPSession client;
        auto res = client.get("http://localhost:18080/u/alice");
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ((*res)->status, 200);
        EXPECT_THAT((*res)->payloadAsStr(), HasSubstr("Alice"));
    }

    app.stop();
    app.wait();
}

TEST_F(AppTest, PostCreation_Unauthorized)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);

    auto start_res = app.start();
    ASSERT_TRUE(start_res) << "Failed to start app: " << mw::errorMsg(start_res.error());

    {
        mw::HTTPSession client;
        mw::HTTPRequest req("http://localhost:18080/post");
        req.setPayload("content=Hello");
        // Missing session cookie

        auto res = client.post(req);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ((*res)->status, 403);
    }

    app.stop();
    app.wait();
}

TEST_F(AppTest, WebFinger_Found)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto* db_ptr = db_mock.get();

    User u1;
    u1.id = 1;
    u1.username = "alice";
    u1.uri = "http://localhost:18080/u/alice";

    EXPECT_CALL(*db_ptr, getUserByUsername("alice")).WillRepeatedly(Return(std::make_optional(u1)));

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);

    auto start_res = app.start();
    ASSERT_TRUE(start_res) << "Failed to start app: " << mw::errorMsg(start_res.error());

    {
        mw::HTTPSession client;
        auto res = client.get("http://localhost:18080/.well-known/webfinger?resource=acct:alice@localhost");
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ((*res)->status, 200);
        auto j = nlohmann::json::parse((*res)->payloadAsStr());
        EXPECT_EQ(j["subject"], "acct:alice@localhost");
    }

    app.stop();
    app.wait();
}

TEST_F(AppTest, SearchPage)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto* db_ptr = db_mock.get();

    User u1;
    u1.id = 1;
    u1.username = "alice";
    u1.display_name = "Alice";
    u1.uri = "http://localhost:18080/u/alice";

    EXPECT_CALL(*db_ptr, getUserByUsername("alice")).WillRepeatedly(Return(std::make_optional(u1)));
    EXPECT_CALL(*db_ptr, getSession(_)).WillRepeatedly(Return(std::nullopt));

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);

    auto start_res = app.start();
    ASSERT_TRUE(start_res) << "Failed to start app: " << mw::errorMsg(start_res.error());

    {
        mw::HTTPSession client;
        // Test 1: Search page load (no query)
        {
            auto res = client.get("http://localhost:18080/search");
            ASSERT_TRUE(res.has_value());
            EXPECT_EQ((*res)->status, 200);
            EXPECT_THAT((*res)->payloadAsStr(), HasSubstr("<form action=\"/search\""));
        }

        // Test 2: Search with query finding local user
        {
            auto res = client.get("http://localhost:18080/search?q=alice");
            ASSERT_TRUE(res.has_value());
            EXPECT_EQ((*res)->status, 200);
            EXPECT_THAT((*res)->payloadAsStr(), HasSubstr("Alice"));
            EXPECT_THAT((*res)->payloadAsStr(), HasSubstr("@alice"));
        }
    }

    app.stop();
    app.wait();
}

TEST_F(AppTest, NodeInfo)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);

    auto start_res = app.start();
    ASSERT_TRUE(start_res);

    {
        mw::HTTPSession client;
        {
            auto res = client.get("http://localhost:18080/.well-known/nodeinfo");
            ASSERT_TRUE(res.has_value());
            EXPECT_EQ((*res)->status, 200);
            auto j = nlohmann::json::parse((*res)->payloadAsStr());
            EXPECT_TRUE(j["links"].is_array());
        }
        {
            auto res = client.get("http://localhost:18080/nodeinfo/2.0");
            ASSERT_TRUE(res.has_value());
            EXPECT_EQ((*res)->status, 200);
            auto j = nlohmann::json::parse((*res)->payloadAsStr());
            EXPECT_EQ(j["version"], "2.0");
            EXPECT_EQ(j["metadata"]["nodeName"], "TestNode");
        }
    }
    app.stop();
    app.wait();
}

TEST_F(AppTest, AuthEndpoints_Unavailable)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);

    auto start_res = app.start();
    ASSERT_TRUE(start_res);

    {
        mw::HTTPSession client;
        {
            auto res = client.get("http://localhost:18080/auth/login");
            ASSERT_TRUE(res.has_value());
            EXPECT_EQ((*res)->status, 503);
        }
        {
            auto res = client.get("http://localhost:18080/auth/callback");
            ASSERT_TRUE(res.has_value());
            EXPECT_EQ((*res)->status, 503);
        }
    }
    app.stop();
    app.wait();
}

TEST_F(AppTest, Auth_Logout)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto* db_ptr = db_mock.get();

    EXPECT_CALL(*db_ptr, deleteSession("test_token")).Times(1);

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);
    app.start();

    {
        mw::HTTPSession client;
        mw::HTTPRequest req("http://localhost:18080/auth/logout");
        req.addHeader("Cookie", "session=test_token");
        auto res = client.get(req);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ((*res)->status, 302);
    }

    app.stop();
    app.wait();
}

TEST_F(AppTest, Auth_SetupUsername)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);
    app.start();

    {
        mw::HTTPSession client;

        // No cookie -> redirect to login
        {
            auto res = client.get("http://localhost:18080/auth/setup_username");
            ASSERT_TRUE(res.has_value());
            EXPECT_EQ((*res)->status, 302);
        }

        // With cookie -> show form
        {
            mw::HTTPRequest req("http://localhost:18080/auth/setup_username");
            req.addHeader("Cookie", "pending_oidc_sub=123");
            auto res = client.get(req);
            ASSERT_TRUE(res.has_value());
            EXPECT_EQ((*res)->status, 200);
            EXPECT_THAT((*res)->payloadAsStr(), HasSubstr("Setup Username"));
        }
    }
    app.stop();
    app.wait();
}

TEST_F(AppTest, Auth_SetupUsernamePost)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto* db_ptr = db_mock.get();

    EXPECT_CALL(*db_ptr, getUserByUsername("alice")).WillOnce(Return(std::nullopt));
    EXPECT_CALL(*db_ptr, createUser(_)).WillOnce(Return(1));
    EXPECT_CALL(*db_ptr, createSession(_)).WillOnce(Return(mw::E<void>{}));

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);
    app.start();

    {
        mw::HTTPSession client;
        mw::HTTPRequest req("http://localhost:18080/auth/setup_username");
        req.addHeader("Cookie", "pending_oidc_sub=123");
        req.setPayload("username=alice");
        auto res = client.post(req);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ((*res)->status, 302);
    }

    app.stop();
    app.wait();
}

TEST_F(AppTest, Inbox_Verification)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto* db_ptr = db_mock.get();

    auto verifier_db = std::make_unique<NiceMock<DatabaseMock>>();
    auto* verifier_db_ptr = verifier_db.get();

    User remote_user;
    remote_user.uri = "https://remote.test/alice";
    auto crypto = std::make_unique<mw::Crypto>();
    auto keys = crypto->generateKeyPair(mw::KeyType::RSA).value();
    remote_user.public_key = keys.public_key;

    EXPECT_CALL(*verifier_db_ptr, getUserByUri("https://remote.test/alice")).WillRepeatedly(Return(std::make_optional(remote_user)));

    auto verifier = std::make_unique<SignatureVerifier>(
        std::make_unique<mw::HTTPSessionMock>(),
        std::make_unique<mw::Crypto>(),
        std::move(verifier_db),
        "http://localhost:18080"
    );

    EXPECT_CALL(*db_ptr, getUserByUri("http://localhost:18080")).WillRepeatedly(Return(std::nullopt));
    EXPECT_CALL(*db_ptr, getUserByUsername("__system__")).WillRepeatedly(Return(std::nullopt));
    EXPECT_CALL(*db_ptr, createUser(_)).WillRepeatedly(Return(1));

    EXPECT_CALL(*db_ptr, getUserByUri("https://remote.test/alice")).WillRepeatedly(Return(std::make_optional(remote_user)));
    EXPECT_CALL(*db_ptr, createPost(_)).WillOnce(Return(mw::E<int64_t>{1}));

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen, nullptr, nullptr, std::move(verifier));

    app.start();

    {
        mw::HTTPSession client;
        mw::HTTPRequest req("http://localhost:18080/inbox");
        std::string payload = R"({"type": "Create", "object": {"type": "Note", "id": "https://remote.test/note/1", "content": "Hello"}})";
        req.setPayload(payload);

        std::string date = http_utils::getHttpDate();
        auto digest_bytes = mw::SHA256Hasher().hashToBytes(payload).value();
        std::string digest = "SHA-256=" + mw::base64Encode(digest_bytes);
        std::string to_sign = "(request-target): post /inbox\nhost: localhost:18080\ndate: " + date + "\ndigest: " + digest;
        auto sig_bytes = crypto->sign(mw::SignatureAlgorithm::RSA_V1_5_SHA256, keys.private_key, to_sign).value();
        std::string signature = mw::base64Encode(sig_bytes);
        std::string sig_header = "keyId=\"https://remote.test/alice#main-key\",algorithm=\"hs2019\",headers=\" (request-target) host date digest\",signature=\"" + signature + "\"";

        req.addHeader("Date", date);
        req.addHeader("Host", "localhost:18080");
        req.addHeader("Digest", digest);
        req.addHeader("Signature", sig_header);

        auto res = client.post(req);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ((*res)->status, 202);
    }

    app.stop();
    app.wait();
}

TEST_F(AppTest, UserOutbox)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto* db_ptr = db_mock.get();

    User u1;
    u1.id = 1;
    u1.username = "alice";
    u1.uri = "http://localhost:18080/u/alice";

    EXPECT_CALL(*db_ptr, getUserByUsername("alice")).WillRepeatedly(Return(std::make_optional(u1)));
    EXPECT_CALL(*db_ptr, getUserPosts(1, _, _)).WillRepeatedly(Return(std::vector<Post>{}));

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);
    app.start();

    {
        mw::HTTPSession client;
        auto res = client.get("http://localhost:18080/u/alice/outbox");
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ((*res)->status, 200);
        auto j = nlohmann::json::parse((*res)->payloadAsStr());
        EXPECT_EQ(j["type"], "OrderedCollection");
    }

    app.stop();
    app.wait();
}

TEST_F(AppTest, ApiUpload_Unauthorized)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);
    app.start();

    {
        mw::HTTPSession client;
        mw::HTTPRequest req("http://localhost:18080/api/upload");
        auto res = client.post(req);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ((*res)->status, 403);
    }

    app.stop();
    app.wait();
}

TEST_F(AppTest, ApiUpload_NoFile)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto* db_ptr = db_mock.get();
    User u1; u1.id = 1; u1.username = "alice";
    Session s; s.token = "token"; s.user_id = 1; s.expires_at = 9999999999; s.csrf_token = "csrf";
    EXPECT_CALL(*db_ptr, getSession("token")).WillRepeatedly(Return(std::make_optional(s)));
    EXPECT_CALL(*db_ptr, getUserById(1)).WillRepeatedly(Return(std::make_optional(u1)));

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);
    app.start();

    {
        mw::HTTPSession client;
        mw::HTTPRequest req("http://localhost:18080/api/upload");
        req.addHeader("Cookie", "session=token");
        req.setPayload("csrf_token=csrf");
        auto res = client.post(req);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ((*res)->status, 500);
    }

    app.stop();
    app.wait();
}

TEST_F(AppTest, ApiFollow_Unauthorized)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);
    app.start();

    {
        mw::HTTPSession client;
        mw::HTTPRequest req("http://localhost:18080/api/follow");
        auto res = client.post(req);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ((*res)->status, 403);
    }

    app.stop();
    app.wait();
}

TEST_F(AppTest, ApiFollow_Authorized)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto* db_ptr = db_mock.get();

    User u1; u1.id = 1; u1.username = "alice"; u1.uri = "http://localhost:18080/u/alice";
    User u2; u2.id = 2; u2.username = "bob"; u2.uri = "http://localhost:18080/u/bob";

    Session s; s.token = "token"; s.user_id = 1; s.expires_at = 9999999999; s.csrf_token = "csrf";

    EXPECT_CALL(*db_ptr, getSession("token")).WillRepeatedly(Return(std::make_optional(s)));
    EXPECT_CALL(*db_ptr, getUserById(1)).WillRepeatedly(Return(std::make_optional(u1)));
    EXPECT_CALL(*db_ptr, getUserByUri("http://localhost:18080/u/bob")).WillOnce(Return(std::make_optional(u2)));
    EXPECT_CALL(*db_ptr, getFollow(1, 2)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(*db_ptr, createFollow(_)).WillOnce(Return(mw::E<void>{}));

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);
    app.start();

    {
        mw::HTTPSession client;
        mw::HTTPRequest req("http://localhost:18080/api/follow");
        req.addHeader("Cookie", "session=token");
        req.setPayload("uri=http://localhost:18080/u/bob&csrf_token=csrf");
        auto res = client.post(req);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ((*res)->status, 302);
    }

    app.stop();
    app.wait();
}

TEST_F(AppTest, PostCreation_Authorized)
{
    auto db_mock = std::make_unique<NiceMock<DatabaseMock>>();
    auto* db_ptr = db_mock.get();

    User u1;
    u1.id = 1;
    u1.username = "alice";
    u1.uri = "http://localhost:18080/u/alice";

    Session s;
    s.token = "token";
    s.user_id = 1;
    s.expires_at = 9999999999;
    s.csrf_token = "csrf";

    EXPECT_CALL(*db_ptr, getSession("token")).WillRepeatedly(Return(std::make_optional(s)));
    EXPECT_CALL(*db_ptr, getUserById(1)).WillRepeatedly(Return(std::make_optional(u1)));
    EXPECT_CALL(*db_ptr, createPost(_)).WillOnce(Return(mw::E<int64_t>{1}));
    EXPECT_CALL(*db_ptr, getFollowers(1)).WillRepeatedly(Return(std::vector<User>{}));

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 18080};
    App app(std::move(db_mock), listen);
    app.start();

    {
        mw::HTTPSession client;
        mw::HTTPRequest req("http://localhost:18080/post");
        req.addHeader("Cookie", "session=token");
        req.setPayload("content=Hello&csrf_token=csrf");

        auto res = client.post(req);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ((*res)->status, 302);
    }

    app.stop();
    app.wait();
}