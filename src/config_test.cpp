#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

#include "config.hpp"

TEST(ConfigTest, Load)
{
    std::string test_file = "test_config_test.yaml";
    std::ofstream f(test_file);
    f << "server_url_root: https://example.com\n"
      << "port: 8080\n"
      << "oidc_issuer_url: https://auth.com\n"
      << "oidc_client_id: client\n"
      << "oidc_secret: secret\n"
      << "secret_key: key\n"
      << "nodeinfo:\n"
      << "  name: MyNode\n"
      << "  description: desc\n";
    f.close();

    Config::get().load(test_file);
    EXPECT_EQ(Config::get().server_url_root, "https://example.com");
    EXPECT_EQ(Config::get().port, 8080);
    EXPECT_EQ(Config::get().nodeinfo.name, "MyNode");

    std::string expected_db =
        (std::filesystem::path(".") / "unspoken.db").string();
    EXPECT_EQ(Config::get().db_path, expected_db);

    std::filesystem::remove(test_file);
}
