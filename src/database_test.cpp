#include <filesystem>

#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include "database.hpp"

class DatabaseTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        db_path = "test_actpub.db";
        if(std::filesystem::exists(db_path))
        {
            std::filesystem::remove(db_path);
        }
        db = std::make_unique<Database>(db_path);
        auto res = db->init();
        if(!res)
        {
            FAIL() << "Failed to init database: " << mw::errorMsg(res.error());
        }
    }

    void TearDown() override
    {
        db.reset();
        if(std::filesystem::exists(db_path))
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
    u.oidc_subject = "sub123";

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
    EXPECT_EQ(get_res_uri.value()->id, id);

    auto get_res_name = db->getUserByUsername("alice");
    ASSERT_TRUE(get_res_name.has_value());
    EXPECT_EQ(get_res_name.value()->id, id);

    auto get_res_sub = db->getUserByOidcSubject("sub123");
    ASSERT_TRUE(get_res_sub.has_value());
    EXPECT_EQ(get_res_sub.value()->id, id);
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
    p.visibility = Visibility::PUBLIC;
    p.created_at = 200;
    p.is_local = true;

    auto pid = db->createPost(p);
    ASSERT_TRUE(pid.has_value());

    auto timeline = db->getPublicTimeline(10, 0);
    ASSERT_TRUE(timeline.has_value());
    EXPECT_EQ(timeline->size(), 1);
    EXPECT_EQ((*timeline)[0].uri, p.uri);

    auto p_ById = db->getPostById(*pid);
    ASSERT_TRUE(p_ById.has_value());
    EXPECT_EQ(p_ById.value()->content_html, "<p>Hello</p>");

    auto p_ByUri = db->getPostByUri(p.uri);
    ASSERT_TRUE(p_ByUri.has_value());
    EXPECT_EQ(p_ByUri.value()->id, *pid);
}

TEST_F(DatabaseTest, FollowDAO)
{
    User u1, u2;
    u1.username = "u1";
    u1.uri = "u1";
    u2.username = "u2";
    u2.uri = "u2";
    auto id1 = *db->createUser(u1);
    auto id2 = *db->createUser(u2);

    Follow f;
    f.follower_id = id1;
    f.target_id = id2;
    f.status = 0;
    f.uri = "follow_uri";

    ASSERT_TRUE(db->createFollow(f));

    auto got = db->getFollow(id1, id2);
    ASSERT_TRUE(got.has_value());
    ASSERT_TRUE(got.value().has_value());
    EXPECT_EQ(got.value()->status, 0);

    ASSERT_TRUE(db->updateFollowStatus(id1, id2, 1));
    got = db->getFollow(id1, id2);
    EXPECT_EQ(got.value()->status, 1);

    auto followers = db->getFollowers(id2);
    ASSERT_TRUE(followers.has_value());
    ASSERT_EQ(followers->size(), 1);
    EXPECT_EQ((*followers)[0].id, id1);
}

TEST_F(DatabaseTest, MediaDAO)
{
    User u;
    u.username = "u";
    u.uri = "u";
    auto uid = *db->createUser(u);

    Media m;
    m.hash = "abc";
    m.filename = "abc.jpg";
    m.mime_type = "image/jpeg";
    m.uploader_id = uid;

    auto mid = db->createMedia(m);
    ASSERT_TRUE(mid.has_value());

    auto got = db->getMediaByHash("abc");
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got.value()->filename, "abc.jpg");
}

TEST_F(DatabaseTest, JobDAO)
{
    Job j;
    j.type = "test";
    j.payload = "{}";
    j.attempts = 0;
    j.status = 0;
    j.next_try = 100;

    auto jid = db->enqueueJob(j);
    ASSERT_TRUE(jid.has_value());

    auto jobs = db->getPendingJobs(10);
    ASSERT_TRUE(jobs.has_value());
    ASSERT_EQ(jobs->size(), 1);
    EXPECT_EQ((*jobs)[0].id, *jid);

    ASSERT_TRUE(db->updateJob(*jid, 1, 1, 200));
    // It shouldn't be pending anymore if we query for pending?
    // Implementation of getPendingJobs usually filters by status=0 and time.

    jobs = db->getPendingJobs(10);
    EXPECT_TRUE(jobs->empty()); // Status 1 is not pending? 0=Pending.

    ASSERT_TRUE(db->deleteJob(*jid));
}

TEST_F(DatabaseTest, SessionDAO)
{
    User u;
    u.username = "u";
    u.uri = "u";
    auto uid = *db->createUser(u);

    Session s;
    s.token = "tok";
    s.user_id = uid;
    s.expires_at = 2000;
    s.csrf_token = "csrf";

    ASSERT_TRUE(db->createSession(s));

    auto got = db->getSession("tok");
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got.value()->user_id, uid);

    ASSERT_TRUE(db->deleteSession("tok"));
    got = db->getSession("tok");
    EXPECT_FALSE(got.value().has_value());
}