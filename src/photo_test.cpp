#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <inja.hpp>
#include <mw/test_utils.hpp>
#include <sstream>

#include "attachments.hpp"
#include "data.hpp"
#include "federation.hpp"
#include "nspic_import.hpp"
#include "photo_processing.hpp"
#include "render.hpp"
#include "service.hpp"

using namespace unspoken;
namespace
{
std::string fixture(const std::string &name = "red")
{
    std::ifstream file("tests/fixtures/photos/" + name + ".png",
                       std::ios::binary);
    return {std::istreambuf_iterator<char>(file), {}};
}

class Photos : public testing::Test
{
  protected:
    std::filesystem::path root;
    Config config;
    std::unique_ptr<DataSourceSQLite> data;
    User author;
    EmojiRegistry emoji;

    void SetUp() override
    {
        root = std::filesystem::temp_directory_path() /
               ("unspoken_photos_" + std::to_string(getpid()) + "_" +
                testing::UnitTest::GetInstance()->current_test_info()->name());
        std::filesystem::remove_all(root);
        std::filesystem::create_directories(root / "images");
        config.url_root = "https://f.test/";
        config.public_domain = "f.test";
        config.database_path = (root / "app.sqlite").string();
        config.attachment_dir = (root / "uploads").string();
        config.link_previews_enabled = false;
        ASSIGN_OR_FAIL(data, DataSourceSQLite::fromFile(config.database_path));
        ASSIGN_OR_FAIL(author,
                       data->createUser(NewUser{"alice", "Alice", "", "iss",
                                                "alice", "PRIV", "PUB"}));
    }

    void TearDown() override
    {
        data.reset();
        std::filesystem::remove_all(root);
    }

    int64_t upload(const std::string &name = "red")
    {
        auto stored = storeAttachment(config.attachment_dir, fixture(name),
                                      "image.png", "image/png")
                          .value();
        Attachment attachment;
        attachment.sha256 = stored.sha256;
        attachment.extension = "png";
        attachment.media_type = "image/png";
        attachment.original_name = "image.png";
        attachment.is_image = true;
        return data->insertAttachment(attachment).value();
    }

    NspicImportOptions source()
    {
        auto source_path = root / "source.sqlite";
        auto db = mw::SQLite::connectFile(source_path.string()).value();
        EXPECT_TRUE(db->execute(
            "CREATE TABLE albums(id INTEGER PRIMARY KEY,title TEXT)"));
        EXPECT_TRUE(
            db->execute("CREATE TABLE posts(id INTEGER PRIMARY KEY,desc "
                        "TEXT,upload_time INTEGER,album INTEGER)"));
        EXPECT_TRUE(
            db->execute("CREATE TABLE images(id INTEGER PRIMARY KEY,path "
                        "TEXT,width INTEGER,height INTEGER,post INTEGER)"));
        EXPECT_TRUE(db->execute("INSERT INTO albums VALUES(1,'Old album')"));
        EXPECT_TRUE(db->execute(
            "INSERT INTO posts VALUES(2,'<b> & @alice *caption*',100,1)"));
        EXPECT_TRUE(
            db->execute("INSERT INTO posts VALUES(1,'first',100,NULL)"));
        EXPECT_TRUE(
            db->execute("INSERT INTO images VALUES(3,'blue.png',2,3,2)"));
        EXPECT_TRUE(
            db->execute("INSERT INTO images VALUES(2,'red.png',2,3,2)"));
        EXPECT_TRUE(
            db->execute("INSERT INTO images VALUES(1,'red.png',2,3,1)"));
        std::ofstream(root / "images/red.png", std::ios::binary) << fixture();
        std::ofstream(root / "images/blue.png", std::ios::binary)
            << fixture("blue");
        return {source_path.string(), (root / "images").string(), "personal",
                "alice", true};
    }
};
} // namespace

TEST(PhotoKind, ExactWireKeyAndCompatibilityDefaults)
{
    EXPECT_EQ(postKindFromStr("photo"), PostKind::PHOTO);
    EXPECT_FALSE(postKindFromStr("PHOTO"));
    EXPECT_EQ(remotePostKind({{"post_kind", "photo"}}), PostKind::SOCIAL);
    EXPECT_EQ(remotePostKind({{"postKind", "photo"}}), PostKind::SOCIAL);
    EXPECT_EQ(remotePostKind({{"attachment", {{{"type", "Image"}}}}}),
              PostKind::SOCIAL);
    for(auto value :
        {nlohmann::json(nullptr), nlohmann::json(1), nlohmann::json(true),
         nlohmann::json("PHOTO"), nlohmann::json("unknown"),
         nlohmann::json::array({"photo"}), nlohmann::json::object()})
        EXPECT_EQ(remotePostKind({{POST_KIND_IRI, value}}), PostKind::SOCIAL);
    EXPECT_EQ(remotePostKind({{POST_KIND_IRI, "photo"}}), PostKind::PHOTO);
}

TEST(PhotoProcessing, FullyDecodesRasterAndRejectsCorruptionAndSvg)
{
    ASSIGN_OR_FAIL(auto info, validatePhoto(fixture()));
    EXPECT_EQ(info.width, 2u);
    EXPECT_EQ(info.height, 3u);
    EXPECT_EQ(info.extension, "png");
    EXPECT_FALSE(validatePhoto("not an image"));
    EXPECT_FALSE(validatePhoto(fixture().substr(0, 45)));
    EXPECT_FALSE(validatePhoto(
        "<svg xmlns='http://www.w3.org/2000/svg' width='1' height='1'/>"));
    EXPECT_FALSE(validatePhoto("%PDF-1.7\n"));
}

TEST(PhotoProcessing, SupportedRasterFixtures)
{
    for(const auto &extension : {"jpg", "gif", "webp"})
    {
        std::ifstream file(std::string("tests/fixtures/photos/red.") +
                               extension,
                           std::ios::binary);
        std::string bytes(std::istreambuf_iterator<char>(file), {});
        ASSIGN_OR_FAIL(auto info, validatePhoto(bytes));
        EXPECT_EQ(info.extension, extension);
        EXPECT_EQ(info.width, 2u);
        EXPECT_EQ(info.height, 3u);
    }
}

TEST_F(Photos, LocalValidationAndImmutableEdits)
{
    Service service(config, *data, emoji);
    ComposeParams params;
    params.post_kind = PostKind::PHOTO;
    params.source = "Caption";
    EXPECT_FALSE(service.createPost(author, params));
    auto red = upload();
    auto blue = upload("blue");
    params.attachment_ids = {blue, red};
    params.attachment_descriptions = {{blue, "Blue"}, {red, ""}};
    ASSIGN_OR_FAIL(auto post, service.createPost(author, params));
    EXPECT_EQ(post.post_kind, PostKind::PHOTO);
    auto attachments = data->attachmentsForPost(post.id).value();
    ASSERT_EQ(attachments.size(), 2u);
    EXPECT_EQ(attachments[0].id, blue);
    EXPECT_EQ(attachments[1].description, "");
    params.attachment_ids = {red, red};
    EXPECT_FALSE(service.createPost(author, params));
    ComposeParams edit;
    edit.source = "Changed caption";
    ASSIGN_OR_FAIL(auto edited, service.editPost(author, post.id, edit));
    EXPECT_EQ(edited.post_kind, PostKind::PHOTO);
    EXPECT_EQ(edited.uri, post.uri);
    EXPECT_EQ(data->attachmentsForPost(post.id)->size(), 2u);
    edit.post_kind_supplied = true;
    EXPECT_FALSE(service.editPost(author, post.id, edit));
    params.post_kind = PostKind::SOCIAL;
    params.attachment_ids = {red};
    params.attachment_descriptions = {{red, "Independent"}};
    ASSIGN_OR_FAIL(auto social, service.createPost(author, params));
    EXPECT_EQ(social.post_kind, PostKind::SOCIAL);
    EXPECT_EQ(data->attachmentsForPost(post.id)->at(1).description, "");
    EXPECT_EQ(data->attachmentsForPost(social.id)->at(0).description,
              "Independent");
}

TEST_F(Photos, StreamFiltersBeforePagingAndKeepsEventCursors)
{
    std::vector<Post> photos;
    std::vector<Post> social;
    for(int i = 0; i < 15; ++i)
    {
        NewPost params;
        params.local_author_id = author.id;
        params.content_html = "post";
        params.post_kind = i % 2 ? PostKind::PHOTO : PostKind::SOCIAL;
        auto post =
            data->insertPost(params, {}, config.url_root + "p/").value();
        (i % 2 ? photos : social).push_back(post);
    }
    NewPost reply;
    reply.post_kind = PostKind::PHOTO;
    reply.local_author_id = author.id;
    reply.in_reply_to_uri = photos.front().uri;
    auto photo_reply =
        data->insertPost(reply, {}, config.url_root + "p/").value();
    auto page = data->timelinePublic(PostKind::PHOTO, {}, 3).value();
    ASSERT_EQ(page.size(), 3u);
    EXPECT_EQ(page.front().id, photos.back().id);
    Cursor cursor;
    cursor.max_id = page.back().id;
    auto next = data->timelinePublic(PostKind::PHOTO, cursor, 3).value();
    ASSERT_EQ(next.size(), 3u);
    cursor = {};
    cursor.min_id = next.front().id;
    auto previous = data->timelinePublic(PostKind::PHOTO, cursor, 3).value();
    EXPECT_EQ(previous.front().id, page.front().id);
    EXPECT_EQ(previous.back().id, page.back().id);
    auto actor = config.url_root + "u/alice";
    ASSERT_TRUE(
        data->addBoost({0, actor, photos.front().uri, std::nullopt, 123}));
    auto home = data->homeTimelinePosts(PostKind::PHOTO, {author.id}, {},
                                        author.id, {}, 3, actor)
                    .value();
    ASSERT_EQ(home.size(), 3u);
    EXPECT_EQ(home.front().id, photos.front().id);
    EXPECT_TRUE(home.front().boosted_by_uri);
    EXPECT_GT(home.front().timeline_id, photo_reply.id);
    cursor = {};
    cursor.max_id = home.back().timeline_id;
    auto home_next = data->homeTimelinePosts(PostKind::PHOTO, {author.id}, {},
                                             author.id, cursor, 3, actor)
                         .value();
    EXPECT_EQ(home_next.size(), 3u);
    cursor = {};
    cursor.min_id = home_next.front().timeline_id;
    auto home_previous =
        data->homeTimelinePosts(PostKind::PHOTO, {author.id}, {}, author.id,
                                cursor, 3, actor)
            .value();
    EXPECT_EQ(home_previous.front().id, home.front().id);
    auto socials = data->timelinePublic(PostKind::SOCIAL, {}, 20).value();
    EXPECT_EQ(socials.size(), social.size());
    EXPECT_TRUE(
        data->connection()
            .execute(
                "INSERT INTO posts(uri,post_kind,created_at) VALUES('bad',2,1)")
            .has_value() == false);
    EXPECT_EQ(data->getPostById(photo_reply.id)->value().post_kind,
              PostKind::PHOTO);
    EXPECT_EQ(data->threadFor(photos.front().uri)->size(), 2u);
}

TEST_F(Photos, ViewEscapesDescriptionsAndSerializesKind)
{
    Service service(config, *data, emoji);
    ComposeParams params;
    params.post_kind = PostKind::PHOTO;
    params.attachment_ids = {upload()};
    params.attachment_descriptions[params.attachment_ids[0]] = "\"<script>";
    params.sensitive = true;
    ASSIGN_OR_FAIL(auto post, service.createPost(author, params));
    ASSIGN_OR_FAIL(auto view, service.postView(post, author));
    EXPECT_EQ(view["photos"].size(), 1u);
    EXPECT_TRUE(view["attachments"].empty());
    const auto description = view["photos"][0]["original_name"]
        .get<std::string>();
    EXPECT_EQ(description.find("<script>"), std::string::npos);
    EXPECT_NE(description.find("&lt;script&gt;"), std::string::npos);
    EXPECT_TRUE(view["photos"][0]["sensitive"].get<bool>());
    auto wire = noteJson(config, post, author, {},
                         data->attachmentsForPost(post.id).value());
    EXPECT_EQ(wire[POST_KIND_IRI], "photo");
}

TEST_F(Photos, ScrollPipsMatchPhotosAndHideForSingleImage)
{
    Service service(config, *data, emoji);
    ComposeParams params;
    params.post_kind = PostKind::PHOTO;
    params.attachment_ids = {upload(), upload("blue")};
    ASSIGN_OR_FAIL(auto post, service.createPost(author, params));
    ASSIGN_OR_FAIL(auto view, service.postView(post, author));
    // A sensitive photo's details wrapper is the slide targeted by its pip.
    view["photos"][0]["sensitive"] = true;
    inja::Environment templates("templates/");
    templates.set_trim_blocks(true);
    templates.set_lstrip_blocks(true);
    nlohmann::json context = {{"post", view}, {"logged_in", false},
        {"focus_id", 0}, {"site", {{"root", "/"}}}};
    auto html = templates.render_file("_photo_post.html", context);
    EXPECT_NE(html.find("class=\"scroll-pips\""), std::string::npos);
    EXPECT_NE(html.find("class=\"scroll-pip active\""), std::string::npos);
    EXPECT_NE(html.find("aria-label=\"Photo 1 of 2\""), std::string::npos);
    EXPECT_NE(html.find("aria-label=\"Photo 2 of 2\""), std::string::npos);
    auto target = "photo-" + std::to_string(post.id) + "-"
        + std::to_string(params.attachment_ids[0]);
    EXPECT_NE(html.find("<details class=\"sensitive\" id=\"" + target + "\""),
              std::string::npos);
    EXPECT_NE(html.find("aria-controls=\"" + target + "\""),
              std::string::npos);
    context["post"]["photos"].erase(1);
    html = templates.render_file("_photo_post.html", context);
    EXPECT_EQ(html.find("class=\"scroll-pips\""), std::string::npos);
}

TEST_F(Photos, ImportDryRunRerunsDeduplicatesAndDoesNotBroadcast)
{
    auto options = source();
    std::ostringstream report;
    auto db_size = std::filesystem::file_size(config.database_path);
    ASSERT_TRUE(importNspic(config, options, report));
    EXPECT_NE(report.str().find("would_import"), std::string::npos);
    EXPECT_FALSE(std::filesystem::exists(config.attachment_dir));
    EXPECT_EQ(data->countLocalPosts().value(), 0);
    EXPECT_EQ(std::filesystem::file_size(config.database_path), db_size);
    options.dry_run = false;
    ASSERT_TRUE(importNspic(config, options, report));
    EXPECT_EQ(data->countLocalPosts().value(), 2);
    auto posts =
        data->postsForAuthors(PostKind::PHOTO, {author.id}, {}, 10).value();
    ASSERT_EQ(posts.size(), 2u);
    EXPECT_EQ(posts.back().content_source, "first");
    EXPECT_EQ(posts.front().published, "1970-01-01T00:01:40Z");
    Service service(config, *data, emoji);
    EXPECT_EQ(service.postView(posts.front(), author).value()["created_at"],
              "1970-01-01 00:01:40");
    EXPECT_EQ(posts.front().content_html,
              "<p>&lt;b&gt; &amp; @alice *caption*</p>");
    auto media = data->attachmentsForPost(posts.front().id).value();
    ASSERT_EQ(media.size(), 2u);
    EXPECT_EQ(media.front().description, "");
    EXPECT_EQ(media.front().id,
              data->attachmentsForPost(posts.back().id)->front().id);
    auto parsed = parsePostContent(*posts.front().content_source, emoji);
    EXPECT_EQ(plainTextExcerpt(parsed.html), "<b> & @alice *caption*");
    EXPECT_TRUE(parsed.mentions.empty());
    EXPECT_TRUE(importNspic(config, options, report));
    EXPECT_EQ(data->countLocalPosts().value(), 2);
    EXPECT_EQ(data->connection()
                  .evalToValue<int64_t>("SELECT count(*) FROM jobs")
                  .value(),
              0);
    EXPECT_EQ(data->connection()
                  .evalToValue<int64_t>("SELECT count(*) FROM notifications")
                  .value(),
              0);
    ASSERT_TRUE(data->deletePost(posts.front().id));
    ASSERT_TRUE(importNspic(config, options, report));
    EXPECT_EQ(data->countLocalPosts().value(), 1);
    std::ifstream original(root / "images/red.png", std::ios::binary);
    EXPECT_EQ(std::string(std::istreambuf_iterator<char>(original), {}),
              fixture());
    std::ofstream(root / "images/blue.png", std::ios::binary) << fixture();
    EXPECT_FALSE(importNspic(config, options, report));
}

TEST_F(Photos, ImportPreflightsEntireSourceAndRejectsEscapes)
{
    auto options = source();
    std::filesystem::remove(root / "images/blue.png");
    options.dry_run = false;
    std::ostringstream report;
    EXPECT_FALSE(importNspic(config, options, report));
    EXPECT_EQ(data->countLocalPosts().value(), 0);
    EXPECT_FALSE(std::filesystem::exists(config.attachment_dir));
    auto source_db = mw::SQLite::connectFile(options.source_db).value();
    ASSERT_TRUE(source_db->execute(
        "UPDATE images SET path='../escape.png' WHERE id=3"));
    std::ofstream(root / "escape.png", std::ios::binary) << fixture();
    EXPECT_FALSE(importNspic(config, options, report));
    ASSERT_TRUE(
        source_db->execute("UPDATE images SET path='escape.png' WHERE id=3"));
    std::filesystem::create_symlink(root / "escape.png",
                                    root / "images/escape.png");
    EXPECT_FALSE(importNspic(config, options, report));
    EXPECT_EQ(data->countLocalPosts().value(), 0);
}

TEST_F(Photos, ImportFailureResumesAndCleansOnlyUnreferencedCopies)
{
    auto options = source();
    options.dry_run = false;
    ASSERT_TRUE(data->connection().execute(
        "CREATE TRIGGER reject_second_import BEFORE INSERT ON nspic_imports "
        "WHEN NEW.source_post_id=2 "
        "BEGIN SELECT RAISE(ABORT,'interrupted import'); END"));
    std::ostringstream report;
    EXPECT_FALSE(importNspic(config, options, report));
    EXPECT_EQ(data->countLocalPosts().value(), 1);
    auto first = data->postsForAuthors(PostKind::PHOTO, {author.id}, {}, 10)
                     .value()
                     .front();
    auto shared = data->attachmentsForPost(first.id).value().front();
    auto path = std::filesystem::path(config.attachment_dir) /
                shared.sha256.substr(0, 1) /
                (shared.sha256 + "." + shared.extension);
    EXPECT_TRUE(std::filesystem::exists(path));
    EXPECT_EQ(data->connection()
                  .evalToValue<int64_t>("SELECT count(*) FROM attachments")
                  .value(),
              1);
    ASSERT_TRUE(
        data->connection().execute("DROP TRIGGER reject_second_import"));
    ASSERT_TRUE(importNspic(config, options, report));
    EXPECT_EQ(data->countLocalPosts().value(), 2);
    EXPECT_EQ(data->connection()
                  .evalToValue<int64_t>("SELECT count(*) FROM nspic_imports")
                  .value(),
              2);
    EXPECT_EQ(data->connection()
                  .evalToValue<int64_t>("SELECT count(*) FROM attachments")
                  .value(),
              2);
}

TEST_F(Photos, MigrationNineDefaultsAndRollsBackOnFailure)
{
    auto post = data->insertPost(NewPost{}, {}, config.url_root + "p/").value();
    auto &db = data->connection();
    for(auto sql :
        {"DROP TABLE nspic_imports", "DROP INDEX idx_posts_kind_id",
         "DROP INDEX idx_posts_local_author_kind_id",
         "DROP INDEX idx_posts_remote_author_kind_id",
         "ALTER TABLE posts DROP COLUMN post_kind", "PRAGMA user_version=9",
         "CREATE INDEX idx_posts_kind_id ON posts(id)"})
        ASSERT_TRUE(db.execute(sql));
    EXPECT_FALSE(data->migrate9To10());
    EXPECT_EQ(data->getSchemaVersion().value(), 9);
    EXPECT_EQ(db.evalToValue<int64_t>(
                    "SELECT count(*) FROM pragma_table_info('posts') "
                    "WHERE name='post_kind'")
                  .value(),
              0);
    ASSERT_TRUE(db.execute("DROP INDEX idx_posts_kind_id"));
    ASSERT_TRUE(data->migrate9To10());
    EXPECT_EQ(data->getSchemaVersion().value(), 10);
    EXPECT_EQ(data->getPostById(post.id)->value().post_kind, PostKind::SOCIAL);
    EXPECT_EQ(db.evalToValue<int64_t>(
                    "SELECT count(*) FROM sqlite_master "
                    "WHERE type='index' AND name IN ('idx_posts_kind_id',"
                    "'idx_posts_local_author_kind_id','idx_posts_remote_author_"
                    "kind_id')")
                  .value(),
              3);
    EXPECT_FALSE(db.execute("UPDATE posts SET post_kind=2"));
}

TEST(PhotoProcessing, EncodesEveryConfiguredFormatWithinBounds)
{
    for(const auto &format : {"jpeg", "webp", "avif", "jpegxl"})
    {
        SCOPED_TRACE(format);
        ASSIGN_OR_FAIL(auto output,
                       processPhoto(fixture("landscape"), {format, 80}));
        EXPECT_EQ(output.info.width, 1024u);
        EXPECT_EQ(output.info.height, 512u);
        EXPECT_NE(output.bytes, fixture("landscape"));
        EXPECT_EQ(output.bytes.find("unspoken-secret-metadata"),
                  std::string::npos);
        ASSIGN_OR_FAIL(auto decoded, validatePhoto(output.bytes));
        EXPECT_EQ(decoded.width, output.info.width);
        EXPECT_EQ(decoded.extension, output.info.extension);
        auto expected = std::string(format) == "jpeg"     ? "jpg"
                        : std::string(format) == "jpegxl" ? "jxl"
                                                          : format;
        EXPECT_EQ(output.info.extension, expected);
    }
}

TEST(PhotoProcessing, PreservesAspectRatioAndDoesNotUpscale)
{
    ASSIGN_OR_FAIL(auto portrait,
                   processPhoto(fixture("portrait"), {"webp", 85}));
    EXPECT_EQ(portrait.info.width, 512u);
    EXPECT_EQ(portrait.info.height, 1024u);
    ASSIGN_OR_FAIL(auto small, processPhoto(fixture(), {"webp", 85}));
    EXPECT_EQ(small.info.width, 2u);
    EXPECT_EQ(small.info.height, 3u);
}

TEST(PhotoProcessing, AppliesOrientationBeforeDiscardingMetadata)
{
    std::ifstream file("tests/fixtures/photos/oriented.jpg", std::ios::binary);
    std::string bytes(std::istreambuf_iterator<char>(file), {});
    ASSIGN_OR_FAIL(auto output, processPhoto(bytes, {"jpeg", 85}));
    EXPECT_EQ(output.info.width, 60u);
    EXPECT_EQ(output.info.height, 120u);
    EXPECT_EQ(output.bytes.find("Exif"), std::string::npos);
    EXPECT_EQ(output.bytes.find("unspoken-secret-metadata"), std::string::npos);
}

TEST(PhotoProcessing, CompositesJpegTransparencyOnWhite)
{
    ASSIGN_OR_FAIL(auto transparent,
                   processPhoto(fixture("transparent"), {"jpeg", 85}));
    ASSIGN_OR_FAIL(auto white, processPhoto(fixture("white"), {"jpeg", 85}));
    EXPECT_EQ(transparent.bytes, white.bytes);
    ASSIGN_OR_FAIL(auto alpha,
                   processPhoto(fixture("transparent"), {"webp", 85}));
    EXPECT_NE(alpha.bytes,
              processPhoto(fixture("white"), {"webp", 85}).value().bytes);
}

TEST(PhotoProcessing, EncodesFirstFrameAndHonorsQuality)
{
    std::ifstream file("tests/fixtures/photos/animated.gif", std::ios::binary);
    std::string bytes(std::istreambuf_iterator<char>(file), {});
    ASSIGN_OR_FAIL(auto frame, processPhoto(bytes, {"webp", 85}));
    EXPECT_EQ(frame.info.width, 20u);
    EXPECT_EQ(frame.bytes.find("ANIM"), std::string::npos);
    ASSIGN_OR_FAIL(auto low, processPhoto(fixture("landscape"), {"jpeg", 20}));
    ASSIGN_OR_FAIL(auto high, processPhoto(fixture("landscape"), {"jpeg", 95}));
    EXPECT_NE(low.bytes, high.bytes);
    EXPECT_FALSE(processPhoto(fixture(), {"png", 85}));
    EXPECT_FALSE(processPhoto(fixture(), {"webp", 0}));
    EXPECT_FALSE(processPhoto(fixture(), {"webp", 101}));
}

TEST_F(Photos, StoresOnlyCanonicalCompressedPhotoAndLeavesSocialBytesIntact)
{
    const auto input = fixture("landscape");
    ASSIGN_OR_FAIL(auto photo,
                   storePhoto(config.attachment_dir, input, config.photos));
    EXPECT_EQ(photo.media_type, "image/webp");
    EXPECT_TRUE(photo.filename.ends_with(".webp"));
    std::ifstream file(photo.disk_path, std::ios::binary);
    std::string encoded(std::istreambuf_iterator<char>(file), {});
    EXPECT_NE(encoded, input);
    EXPECT_EQ(validatePhoto(encoded).value().width, 1024u);
    size_t file_count = 0;
    for(const auto &entry :
        std::filesystem::recursive_directory_iterator(config.attachment_dir))
        if(entry.is_regular_file()) ++file_count;
    EXPECT_EQ(file_count, 1u);
    ASSIGN_OR_FAIL(auto social, storeAttachment(config.attachment_dir, input,
                                                "original.png", "image/png"));
    std::ifstream original(social.disk_path, std::ios::binary);
    EXPECT_EQ(std::string(std::istreambuf_iterator<char>(original), {}), input);
    EXPECT_EQ(social.media_type, "image/png");
}
