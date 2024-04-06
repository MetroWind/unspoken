#include <gtest/gtest.h>

#include "error.hpp"
#include "test_utils.hpp"
#include "types.hpp"

TEST(FediUser, CanParse)
{
    ASSIGN_OR_FAIL(FediUser u, FediUser::fromStr("mw@f.darksair.org"));
    EXPECT_EQ(u.name, "mw");
    EXPECT_EQ(u.server, "f.darksair.org");

    ASSIGN_OR_FAIL(FediUser u2, FediUser::fromStr("@mw@f.darksair.org"));
    EXPECT_EQ(u2.name, "mw");
    EXPECT_EQ(u2.server, "f.darksair.org");
}

TEST(FediUser, FailOnInvalidID)
{
    {
        auto u = FediUser::fromStr("");
        ASSERT_FALSE(u.has_value());
        EXPECT_EQ(errorMsg(u.error()), "Invalid account string: ");
    }
    {
        auto u = FediUser::fromStr("@");
        ASSERT_FALSE(u.has_value());
        EXPECT_EQ(errorMsg(u.error()), "Invalid account string: @");
    }
    {
        auto u = FediUser::fromStr("@@");
        ASSERT_FALSE(u.has_value());
        EXPECT_EQ(errorMsg(u.error()), "Invalid account string: @@");
    }
    {
        auto u = FediUser::fromStr("@@@");
        ASSERT_FALSE(u.has_value());
        EXPECT_EQ(errorMsg(u.error()), "Invalid account string: @@@");
    }
    {
        auto u = FediUser::fromStr("@ ");
        ASSERT_FALSE(u.has_value());
        EXPECT_EQ(errorMsg(u.error()), "Invalid account string: @");
    }
    {
        auto u = FediUser::fromStr(" @");
        ASSERT_FALSE(u.has_value());
        EXPECT_EQ(errorMsg(u.error()), "Invalid account string: @");
    }
    {
        auto u = FediUser::fromStr("@aaa@bbb@ccc");
        ASSERT_FALSE(u.has_value());
        EXPECT_EQ(errorMsg(u.error()), "Invalid account string: @aaa@bbb@ccc");
    }
    {
        auto u = FediUser::fromStr("aaa@bbb@ccc");
        ASSERT_FALSE(u.has_value());
        EXPECT_EQ(errorMsg(u.error()), "Invalid account string: aaa@bbb@ccc");
    }
}
