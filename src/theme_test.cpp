#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <unistd.h>

#include "theme.hpp"

namespace
{
class ThemeTest : public testing::Test
{
protected:
    std::filesystem::path dir;

    void SetUp() override
    {
        std::string pattern = "/tmp/unspoken_themes_XXXXXX";
        char* result = mkdtemp(pattern.data());
        ASSERT_NE(result, nullptr);
        dir = result;
    }

    void TearDown() override { std::filesystem::remove_all(dir); }

    void theme(const std::string& id, const std::string& manifest)
    {
        std::filesystem::create_directory(dir / id);
        std::ofstream(dir / id / "info.yaml") << manifest;
    }
};
}

TEST_F(ThemeTest, LoadsAncestorsAndSortsEachLayer)
{
    theme("base", "name: Dark\n");
    theme("light", "parent: base\n");
    theme("wide", "parent: light\n");
    std::ofstream(dir / "base" / "20-layout.css");
    std::ofstream(dir / "base" / "10-reset.css");
    std::ofstream(dir / "light" / "style.css");
    std::ofstream(dir / "wide" / "style.css");
    unspoken::ThemeManager manager;
    ASSERT_TRUE(manager.loadDir(dir));
    EXPECT_EQ(manager.all().at("base").name, "Dark");
    EXPECT_EQ(manager.all().at("light").name, "light");
    EXPECT_EQ(manager.stylesheets("wide"), (std::vector<std::string>{
        "base/10-reset.css", "base/20-layout.css",
        "light/style.css", "wide/style.css"}));
    EXPECT_TRUE(manager.stylesheets("unknown").empty());
}

TEST_F(ThemeTest, RejectsMissingParentAndKeepsPreviousCatalog)
{
    theme("base", "name: Dark\n");
    unspoken::ThemeManager manager;
    ASSERT_TRUE(manager.loadDir(dir));
    theme("child", "parent: missing\n");
    EXPECT_FALSE(manager.loadDir(dir));
    EXPECT_EQ(manager.all().size(), 1);
}

TEST_F(ThemeTest, RejectsCycles)
{
    theme("one", "parent: two\n");
    theme("two", "parent: one\n");
    unspoken::ThemeManager manager;
    EXPECT_FALSE(manager.loadDir(dir));
    std::ofstream(dir / "one" / "info.yaml") << "parent: one\n";
    EXPECT_FALSE(manager.loadDir(dir));
}

TEST_F(ThemeTest, RejectsInvalidManifestAndUnsafeIdentifiers)
{
    theme("base", "parent: [bad]\n");
    unspoken::ThemeManager manager;
    EXPECT_FALSE(manager.loadDir(dir));
    std::ofstream(dir / "base" / "info.yaml") << "[]\n";
    EXPECT_FALSE(manager.loadDir(dir));
    std::ofstream(dir / "base" / "info.yaml") << "name: Dark\n";
    theme("bad name", "name: Bad\n");
    EXPECT_FALSE(manager.loadDir(dir));
}
