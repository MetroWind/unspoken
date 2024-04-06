#include <memory>
#include <chrono>

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <httplib.h>

#include "federation.hpp"
#include "error.hpp"
#include "test_utils.hpp"

TEST(WebFingerQuery, CanParseURLParam)
{
    {
        httplib::Request req;
        req.params.emplace("resource", "acct:aaa@bbb");
        ASSIGN_OR_FAIL(auto query, WebFingerQuery::fromRequest(req));
        EXPECT_EQ(query.type, WebFingerQuery::RESOURCE);
        EXPECT_EQ(query.resource_type, WebFingerQuery::ACCOUNT);
        EXPECT_EQ(query.arg, "aaa@bbb");
    }
    {
        httplib::Request req;
        req.params.emplace("resource", "acct:");
        ASSIGN_OR_FAIL(auto query, WebFingerQuery::fromRequest(req));
        EXPECT_EQ(query.type, WebFingerQuery::RESOURCE);
        EXPECT_EQ(query.resource_type, WebFingerQuery::ACCOUNT);
        EXPECT_TRUE(query.arg.empty());
    }
}

TEST(WebFingerQuery, CanFailWithInvalidParam)
{
    {
        httplib::Request req;
        auto r = WebFingerQuery::fromRequest(req);
        ASSERT_FALSE(r.has_value());
        EXPECT_EQ(errorMsg(r.error()), "Unsupported webfinger query.");
    }
    {
        httplib::Request req;
        req.params.emplace("aaa", "acct:aaa@bbb");
        auto r = WebFingerQuery::fromRequest(req);
        ASSERT_FALSE(r.has_value());
        EXPECT_EQ(errorMsg(r.error()), "Unsupported webfinger query.");
    }
    {
        httplib::Request req;
        req.params.emplace("resource", "aaa@bbb");
        auto r = WebFingerQuery::fromRequest(req);
        ASSERT_FALSE(r.has_value());
        EXPECT_EQ(errorMsg(r.error()), "Invalid webfinger query.");
    }
    {
        httplib::Request req;
        req.params.emplace("resource", "id:aaa@bbb");
        auto r = WebFingerQuery::fromRequest(req);
        ASSERT_FALSE(r.has_value());
        EXPECT_EQ(errorMsg(r.error()), "Unsupported resource type in webfinger.");
    }
}
