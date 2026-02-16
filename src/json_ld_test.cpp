#include <gtest/gtest.h>

#include "json_ld.hpp"

TEST(JsonLdTest, GetId)
{
    nlohmann::json j = {{"id", "https://example.com"}};
    EXPECT_EQ(json_ld::getId(j, "id"), "https://example.com");

    nlohmann::json j2 = {{"actor", {{"id", "https://example.com"}}}};
    EXPECT_EQ(json_ld::getId(j2, "actor"), "https://example.com");

    nlohmann::json j3 = {{"icon", {{"href", "https://example.com/icon.png"}}}};
    EXPECT_EQ(json_ld::getId(j3, "icon"), "https://example.com/icon.png");
}

TEST(JsonLdTest, AsList)
{
    nlohmann::json j = {{"to", "user1"}};
    auto l = json_ld::asList(j, "to");
    ASSERT_EQ(l.size(), 1);
    EXPECT_EQ(l[0], "user1");

    nlohmann::json j2 = {{"to", {"user1", "user2"}}};
    auto l2 = json_ld::asList(j2, "to");
    ASSERT_EQ(l2.size(), 2);
    EXPECT_EQ(l2[0], "user1");
    EXPECT_EQ(l2[1], "user2");
}

TEST(JsonLdTest, HasType)
{
    nlohmann::json j = {{"type", "Note"}};
    EXPECT_TRUE(json_ld::hasType(j, "Note"));
    EXPECT_FALSE(json_ld::hasType(j, "Person"));

    nlohmann::json j2 = {{"type", {"Person", "Actor"}}};
    EXPECT_TRUE(json_ld::hasType(j2, "Person"));
    EXPECT_TRUE(json_ld::hasType(j2, "Actor"));
}
