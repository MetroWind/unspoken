#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include <mw/error.hpp>

#include "emoji.hpp"

namespace
{

std::filesystem::path tempPath(std::string_view name)
{
    return std::filesystem::temp_directory_path()
        / std::string(name);
}

void writeFile(const std::filesystem::path& path, std::string_view text)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
}

} // namespace

TEST(EmojiData, LoadsValidJsonInOrder)
{
    auto path = tempPath("unspoken_emoji_data_valid.json");
    writeFile(path, R"({
  "source": {
    "unicode_version": "17.0.0",
    "url": "fixture",
    "generated_at": "2026-06-29"
  },
  "categories": [
    {
      "id": "smileys_emotion",
      "label": "Smileys & Emotion",
      "representative_emoji": "😀",
      "subgroups": [
        {
          "id": "face_smiling",
          "label": "face-smiling",
          "emoji": [
            {
              "emoji": "😀",
              "name": "grinning face",
              "version": "E1.0"
            },
            {
              "emoji": "☺️",
              "name": "smiling face",
              "version": "E0.6"
            }
          ]
        }
      ]
    },
    {
      "id": "symbols",
      "label": "Symbols",
      "representative_emoji": "❤",
      "subgroups": [
        {
          "id": "heart",
          "label": "heart",
          "emoji": [
            {
              "emoji": "❤",
              "name": "red heart",
              "version": "E0.6"
            }
          ]
        }
      ]
    }
  ]
})");

    auto categories = unspoken::loadUnicodeEmojiCategories(path.string());
    std::filesystem::remove(path);

    ASSERT_TRUE(categories.has_value()) << mw::errorMsg(categories.error());
    ASSERT_EQ(categories->size(), 2u);
    EXPECT_EQ((*categories)[0].id, "smileys_emotion");
    EXPECT_EQ((*categories)[0].representative_emoji, "😀");
    ASSERT_EQ((*categories)[0].subgroups.size(), 1u);
    EXPECT_EQ((*categories)[0].subgroups[0].emoji[0].emoji, "😀");
    EXPECT_EQ((*categories)[0].subgroups[0].emoji[1].name, "smiling face");
    EXPECT_EQ((*categories)[1].label, "Symbols");
}

TEST(EmojiData, RejectsMalformedJson)
{
    auto path = tempPath("unspoken_emoji_data_malformed.json");
    writeFile(path, "{");

    auto categories = unspoken::loadUnicodeEmojiCategories(path.string());
    std::filesystem::remove(path);

    EXPECT_FALSE(categories.has_value());
}

TEST(EmojiData, RejectsMissingRequiredFields)
{
    auto path = tempPath("unspoken_emoji_data_missing_fields.json");
    writeFile(path, R"({"categories":[{"id":"symbols"}]})");

    auto categories = unspoken::loadUnicodeEmojiCategories(path.string());
    std::filesystem::remove(path);

    EXPECT_FALSE(categories.has_value());
}
