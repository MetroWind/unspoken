#include <gtest/gtest.h>
#include "database.hpp"
#include <filesystem>
#include <spdlog/spdlog.h>

class DatabaseTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        db_path = "test_actpub.db";
        if (std::filesystem::exists(db_path))
        {
            std::filesystem::remove(db_path);
        }
        db = std::make_unique<Database>(db_path);
        auto res = db->init();
        if (!res)
        {
            FAIL() << "Failed to init database: " << mw::errorMsg(res.error());
        }
    }

    void TearDown() override
    {
        db.reset();
        if (std::filesystem::exists(db_path))
        {
            std::filesystem::remove(db_path);
        }
    }

    std::string db_path;
    std::unique_ptr<Database> db;
};

TEST_F(DatabaseTest, UserCRUD)
{
    User u;
    u.username = "alice";
    u.display_name = "Alice";
    u.bio = "I am Alice";
    u.uri = "https://example.com/users/alice";
    u.public_key = "PUBKEY";
    u.created_at = 123456789;

    auto create_res = db->createUser(u);
    ASSERT_TRUE(create_res.has_value());
    int64_t id = *create_res;
    EXPECT_GT(id, 0);

    auto get_res = db->getUserById(id);
    ASSERT_TRUE(get_res.has_value());
    ASSERT_TRUE(get_res.value().has_value());
    EXPECT_EQ(get_res.value()->username, "alice");
    EXPECT_EQ(get_res.value()->uri, u.uri);

    auto get_res_uri = db->getUserByUri(u.uri);
    ASSERT_TRUE(get_res_uri.has_value());
    ASSERT_TRUE(get_res_uri.value().has_value());
    EXPECT_EQ(get_res_uri.value()->id, id);
}

TEST_F(DatabaseTest, PostTimeline)
{
    User u;
    u.username = "bob";
    u.uri = "https://example.com/users/bob";
    u.created_at = 100;
    auto uid = db->createUser(u);
    ASSERT_TRUE(uid.has_value());

    Post p;
    p.uri = "https://example.com/posts/1";
    p.author_id = *uid;
    p.content_html = "<p>Hello</p>";
    p.content_source = "Hello";
    p.visibility = Visibility::Public;
    p.created_at = 200;
    p.is_local = true;

    auto pid = db->createPost(p);
    if (!pid)
    {
        FAIL() << "Failed to create post: " << mw::errorMsg(pid.error());
    }
    ASSERT_TRUE(pid.has_value());

    auto timeline = db->getPublicTimeline(10, 0);
    ASSERT_TRUE(timeline.has_value());
    EXPECT_EQ(timeline->size(), 1);
    EXPECT_EQ((*timeline)[0].uri, p.uri);
}
