#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "app.hpp"
#include "database_mock.hpp"
#include <mw/http_client.hpp>
#include "config.hpp"
#include <filesystem>
#include <fstream>
#include <thread>

using ::testing::_;
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
        Config::get().port = 18080;
        Config::get().nodeinfo.name = "TestNode";
    }

    void TearDown() override
    {
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
        // Note: header keys might be case-insensitive or normalized.
        // libmw usually normalizes? or I should check implementation.
        // I'll check payload content instead of headers to be safe, or assume standard casing.
        auto j = nlohmann::json::parse((*res)->payloadAsStr());
        EXPECT_EQ(j["subject"], "acct:alice@localhost");
    }
    
    app.stop();
    app.wait();
}