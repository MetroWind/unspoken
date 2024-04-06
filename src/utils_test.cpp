#include <chrono>

#include <gtest/gtest.h>

#include "utils.hpp"

TEST(Utils, CanCalculateDaysSinceNewYear)
{
    Time t = std::chrono::sys_days(std::chrono::year_month_day(
        std::chrono::year(2000), std::chrono::January, std::chrono::day(3)));
    EXPECT_EQ(daysSinceNewYear(t), 2);
}

TEST(Utils, CanStripStringFromLeft)
{
    EXPECT_EQ(lstrip(""), "");
    EXPECT_EQ(lstrip(" "), "");
    EXPECT_EQ(lstrip("  "), "");
    EXPECT_EQ(lstrip(" a "), "a ");
    EXPECT_EQ(lstrip("  a "), "a ");
    EXPECT_EQ(lstrip("a "), "a ");
}

TEST(Utils, CanStripStringFromRight)
{
    EXPECT_EQ(rstrip(""), "");
    EXPECT_EQ(rstrip(" "), "");
    EXPECT_EQ(rstrip("  "), "");
    EXPECT_EQ(rstrip(" a "), " a");
    EXPECT_EQ(rstrip(" a  "), " a");
    EXPECT_EQ(rstrip(" a"), " a");
}

TEST(Utils, CanStripStringFromBothSides)
{
    EXPECT_EQ(strip(""), "");
    EXPECT_EQ(strip(" "), "");
    EXPECT_EQ(strip("  "), "");
    EXPECT_EQ(strip(" a "), "a");
    EXPECT_EQ(strip(" a  "), "a");
    EXPECT_EQ(strip("a"), "a");
}
