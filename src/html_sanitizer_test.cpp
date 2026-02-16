#include <gtest/gtest.h>

#include "html_sanitizer.hpp"

TEST(HtmlSanitizerTest, BasicText)
{
    std::string input = "Hello World";
    EXPECT_EQ(HtmlSanitizer::sanitize(input), "Hello World");
}

TEST(HtmlSanitizerTest, AllowedTags)
{
    std::string input = "<p>Hello <b>World</b></p>";
    EXPECT_EQ(HtmlSanitizer::sanitize(input), "<p>Hello <b>World</b></p>");
}

TEST(HtmlSanitizerTest, DisallowedTags)
{
    std::string input = "<script>alert('xss')</script><p>Safe</p>";
    EXPECT_EQ(HtmlSanitizer::sanitize(input), "<p>Safe</p>");
}

TEST(HtmlSanitizerTest, DisallowedTagsWithContent)
{
    std::string input = "<iframe>Bad content</iframe>";
    EXPECT_EQ(HtmlSanitizer::sanitize(input), "");
}

TEST(HtmlSanitizerTest, UnknownTags)
{
    std::string input = "<foo>Bar</foo>";
    EXPECT_EQ(HtmlSanitizer::sanitize(input), "Bar");
}

TEST(HtmlSanitizerTest, Attributes)
{
    std::string input =
        "<a href=\"https://example.com\" onclick=\"bad()\">Link</a>";
    // onclick should be removed.
    EXPECT_EQ(HtmlSanitizer::sanitize(input),
              "<a href=\"https://example.com\">Link</a>");
}

TEST(HtmlSanitizerTest, UnsafeUrl)
{
    std::string input = "<a href=\"javascript:alert(1)\">Link</a>";
    EXPECT_EQ(HtmlSanitizer::sanitize(input), "<a>Link</a>");
}

TEST(HtmlSanitizerTest, Fragment)
{
    std::string input = "Just text";
    EXPECT_EQ(HtmlSanitizer::sanitize(input), "Just text");
}

TEST(HtmlSanitizerTest, VoidTags)
{
    std::string input = "<br><img src=\"test.jpg\" />";
    std::string expected = "<br /><img src=\"test.jpg\" />";
    EXPECT_EQ(HtmlSanitizer::sanitize(input), expected);
}