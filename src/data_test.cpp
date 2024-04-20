#include <gtest/gtest.h>

#include "data.hpp"
#include "data_types.hpp"
#include "test_utils.hpp"

TEST(DataSourceSQLite, User)
{
    ASSIGN_OR_FAIL(auto data, DataSourceSqlite::newFromMemory());
    ASSERT_TRUE(data->createUser("mw").has_value());
    ASSIGN_OR_FAIL(auto user, data->getUser("mw"));
    ASSERT_TRUE(user.has_value());
    EXPECT_EQ(user.name, "mw");
    ASSIGN_OR_FAIL(user, data->getUser("lalala"));
    ASSERT_FALSE(user.has_value());
}

TEST(DataSourceSQLite, CanPostAndGetTimelineAndDelete)
{
    Post p;
    p.content = "aaa";
    p.author = "mw";
    ASSIGN_OR_FAIL(auto data, DataSourceSqlite::newFromMemory());
    ASSERT_TRUE(data->createUser("mw").has_value());
    ASSERT_TRUE(data->createUser("yy").has_value());
    ASSERT_TRUE(data->follow("yy", "mw").has_value());
    {
        Post p;
        p.content = "aaa";
        p.author = "mw";
        ASSERT_TRUE(data->post(std::move(p)).has_value());
    }
    {
        Post p;
        p.content = "bbb";
        p.author = "yy";
        ASSERT_TRUE(data->post(std::move(p)).has_value());
    }
    uint64_t mw_pid;
    {
        TimelineSpec tl;
        tl.type = TimelineSpec::USER_INDEX;
        tl.user = "mw";
        tl.begin = 0;
        tl.count = 10;
        ASSIGN_OR_FAIL(auto ps, data->getTimeline(tl));
        ASSERT_EQ(ps.size(), 1);
        EXPECT_EQ(ps[0].content, "aaa");
        EXPECT_EQ(ps[0].author, "mw");
        EXPECT_TRUE(ps[0].id.has_value());
        mw_pid = *ps[0].id;
    }
    {
        TimelineSpec tl;
        tl.type = TimelineSpec::USER_INDEX;
        tl.user = "yy";
        tl.begin = 0;
        tl.count = 10;
        ASSIGN_OR_FAIL(auto ps, data->getTimeline(tl));
        ASSERT_EQ(ps.size(), 2);
        EXPECT_EQ(ps[0].content, "aaa");
        EXPECT_EQ(ps[0].author, "mw");
        EXPECT_EQ(ps[1].content, "bbb");
        EXPECT_EQ(ps[1].author, "yy");
        EXPECT_TRUE(ps[1].id.has_value());
    }
    {
        TimelineSpec tl;
        tl.type = TimelineSpec::USER;
        tl.user = "yy";
        tl.begin = 0;
        tl.count = 10;
        ASSIGN_OR_FAIL(auto ps, data->getTimeline(tl));
        ASSERT_EQ(ps.size(), 1);
        EXPECT_EQ(ps[0].content, "bbb");
        EXPECT_EQ(ps[0].author, "yy");
    }
    ASSERT_TRUE(data->deletePost(mw_pid).has_value());
    TimelineSpec tl;
    tl.type = TimelineSpec::USER_INDEX;
    tl.user = "mw";
    tl.begin = 0;
    tl.count = 10;
    ASSIGN_OR_FAIL(auto ps, data->getTimeline(tl));
    ASSERT_TRUE(ps.empty());
}
