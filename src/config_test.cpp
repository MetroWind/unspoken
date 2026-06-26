#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

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
    c.attachment_dir = std::filesystem::temp_directory_path().string();
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

TEST(Config, FromYamlAllowsMissingPublicDomain)
{
    std::filesystem::path path =
        std::filesystem::temp_directory_path() / "unspoken_config_test.yaml";
    std::ofstream out(path);
    out << R"(
url_root: "https://f.mws.rocks/"
listen_address: "127.0.0.1"
listen_port: 8080
database_path: ":memory:"
attachment_dir: "/tmp"
oidc:
  issuer: "https://kc.example/realms/main"
  client_id: "unspoken"
  client_secret: "secret"
)";
    out.close();

    auto config = Config::fromYaml(path);
    std::filesystem::remove(path);

    ASSERT_TRUE(config.has_value()) << mw::errorMsg(config.error());
    EXPECT_EQ(config->public_domain, "f.mws.rocks");
}

TEST(Config, FromYamlReadsVerbose)
{
    std::filesystem::path path =
        std::filesystem::temp_directory_path()
        / "unspoken_config_verbose_test.yaml";
    std::ofstream out(path);
    out << R"(
url_root: "https://f.mws.rocks/"
verbose: true
database_path: ":memory:"
attachment_dir: "/tmp"
oidc:
  issuer: "https://kc.example/realms/main"
  client_id: "unspoken"
  client_secret: "secret"
)";
    out.close();

    auto config = Config::fromYaml(path);
    std::filesystem::remove(path);

    ASSERT_TRUE(config.has_value()) << mw::errorMsg(config.error());
    EXPECT_TRUE(config->verbose);
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

TEST(Config, RejectsMissingAttachmentDir)
{
    Config c = validBase();
    c.attachment_dir =
        (std::filesystem::temp_directory_path()
         / "unspoken_missing_attachment_dir").string();
    EXPECT_FALSE(c.validateAndFinalize().has_value());
}
