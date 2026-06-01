#include <gtest/gtest.h>

#include <mw/error.hpp>

#include "config.hpp"

namespace
{

// A minimally-valid config to mutate in tests.
Config validBase()
{
    Config c;
    c.url_root = "https://f.mws.rocks/fedi";
    c.oidc.issuer = "https://kc.example/realms/main";
    c.oidc.client_id = "unspoken";
    c.oidc.client_secret = "secret";
    c.database_path = ":memory:";
    return c;
}

} // namespace

TEST(Config, NormalizesTrailingSlashOnUrlRoot)
{
    Config c = validBase();
    c.url_root = "https://f.mws.rocks/fedi";
    ASSERT_TRUE(c.validateAndFinalize().has_value());
    EXPECT_EQ(c.url_root, "https://f.mws.rocks/fedi/");
}

TEST(Config, CollapsesMultipleTrailingSlashes)
{
    Config c = validBase();
    c.url_root = "https://f.mws.rocks///";
    ASSERT_TRUE(c.validateAndFinalize().has_value());
    EXPECT_EQ(c.url_root, "https://f.mws.rocks/");
}

TEST(Config, PublicDomainDefaultsToUrlRootHost)
{
    Config c = validBase();
    c.url_root = "https://f.mws.rocks/fedi/";
    c.public_domain = "";
    ASSERT_TRUE(c.validateAndFinalize().has_value());
    EXPECT_EQ(c.public_domain, "f.mws.rocks");
}

TEST(Config, PublicDomainOverrideKept)
{
    Config c = validBase();
    c.public_domain = "mws.rocks";
    ASSERT_TRUE(c.validateAndFinalize().has_value());
    EXPECT_EQ(c.public_domain, "mws.rocks");
}

TEST(Config, RejectsMissingUrlRoot)
{
    Config c = validBase();
    c.url_root = "";
    EXPECT_FALSE(c.validateAndFinalize().has_value());
}

TEST(Config, RejectsNonHttpsUrlRoot)
{
    Config c = validBase();
    c.url_root = "http://f.mws.rocks/";
    EXPECT_FALSE(c.validateAndFinalize().has_value());
}

TEST(Config, RejectsMissingOidc)
{
    Config c = validBase();
    c.oidc.client_secret = "";
    EXPECT_FALSE(c.validateAndFinalize().has_value());
}

TEST(Config, RejectsNonPositiveTuning)
{
    Config c = validBase();
    c.posts_per_page = 0;
    EXPECT_FALSE(c.validateAndFinalize().has_value());
}
