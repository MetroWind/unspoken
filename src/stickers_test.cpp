#include "stickers.hpp"

#include <filesystem>
#include <fstream>
#include <unistd.h>

#include <gtest/gtest.h>
#include <mw/test_utils.hpp>
#include <actpub/transaction.hpp>
#include <mw/url.hpp>

#include "data.hpp"
#include "service.hpp"
#include "federation.hpp"

using namespace unspoken;

namespace
{

class Stickers : public testing::Test
{
protected:
    std::filesystem::path root = std::filesystem::temp_directory_path()
        / ("unspoken_stickers_" + std::to_string(::getpid()));
    Config config;
    EmojiRegistry emoji;

    void SetUp() override
    {
        std::filesystem::remove_all(root);
        std::filesystem::create_directories(root / "cats");
        config.url_root = "https://f.test/sub/";
        config.public_domain = "f.test";
        config.sticker_dir = root.string();
        config.attachment_dir = (root / "uploads").string();
        file("cats/A sleepy cat%?#.WEBP");
    }

    void TearDown() override
    {
        std::filesystem::remove_all(root);
    }

    void file(const std::string& name, const std::string& bytes = "image")
    {
        std::ofstream(root / name, std::ios::binary) << bytes;
    }

    User user(const DataSourceSQLite& data)
    {
        NewUser value;
        value.username = "alice";
        value.oidc_iss = "issuer";
        value.oidc_sub = "alice";
        value.private_key_pem = "private";
        value.public_key_pem = "public";
        return data.createUser(value).value();
    }
};

} // namespace

TEST_F(Stickers, MissingEmptyAndUnreadableRoots)
{
    ASSIGN_OR_FAIL(auto missing, StickerRegistry::scan(
        (root / "absent").string(), config.url_root));
    EXPECT_TRUE(missing.empty());
    EXPECT_FALSE(std::filesystem::exists(root / "absent"));
    EXPECT_FALSE(StickerRegistry::scan(
        (root / "cats/A sleepy cat%?#.WEBP").string(), config.url_root));
    std::filesystem::create_directory(root / "empty");
    ASSIGN_OR_FAIL(auto empty, StickerRegistry::scan(
        (root / "empty").string(), config.url_root));
    EXPECT_TRUE(empty.empty());
    std::filesystem::permissions(root / "cats",
                                  std::filesystem::perms::none);
    if(::geteuid() != 0)
    {
        EXPECT_FALSE(StickerRegistry::scan(root.string(), config.url_root));
    }
    std::filesystem::permissions(root / "cats",
                                  std::filesystem::perms::owner_all);
}

TEST_F(Stickers, DiscoveryAndUrlRoundTrips)
{
    std::filesystem::create_directories(root / "birds");
    std::filesystem::create_directories(root / "empty");
    std::filesystem::create_directories(root / "cats/nested");
    file("birds/こんにちは.png");
    file("cats/same.png");
    file("cats/same.gif");
    file("cats/.hidden.png");
    file("cats/control\n.png");
    file("cats/empty.png", "");
    file("cats/vector.svg");
    file("cats/movie.mp4");
    file("root.png");
    std::filesystem::create_symlink(root / "birds/こんにちは.png",
                                     root / "cats/link.png");
    std::filesystem::create_directory_symlink(root / "birds", root / "linked");
    ASSIGN_OR_FAIL(auto registry, StickerRegistry::scan(root.string(),
                                                        config.url_root));
    ASSERT_EQ(registry.all().size(), 2u);
    EXPECT_EQ(registry.all()[0].name, "birds");
    EXPECT_EQ(registry.all()[1].stickers.size(), 3u);
    const auto& sticker = registry.all()[1].stickers[0];
    EXPECT_EQ(sticker.name, "A sleepy cat%?#");
    EXPECT_EQ(sticker.media_type, "image/webp");
    EXPECT_EQ(sticker.url,
        "https://f.test/sub/stickers/cats/A%20sleepy%20cat%25%3F%23.WEBP");
    EXPECT_EQ(registry.all()[1].stickers[1].filename, "same.gif");
    EXPECT_TRUE(registry.lookup(sticker.key));
    EXPECT_FALSE(registry.lookup("https://arbitrary.test/image.png"));
    EXPECT_FALSE(std::filesystem::exists(config.attachment_dir));
    EXPECT_EQ(registry.catalog()[0]["stickers"][0]["name"], "こんにちは");
    EXPECT_EQ(mw::URL::decode(mw::URL::encode(sticker.filename)),
              sticker.filename);
}

TEST_F(Stickers, PathsRejectTraversalAndSymlinks)
{
    for(const auto& component : {"", ".", "..", ".hidden", "a/b", "a\\b",
                                 "a\nb", "a\x7f"})
    {
        EXPECT_FALSE(stickerPath(root.string(), component, "image.png"));
        EXPECT_FALSE(stickerPath(root.string(), "cats", component));
    }
    EXPECT_FALSE(validStickerName(std::string("nul\0.png", 8)));
    EXPECT_FALSE(validStickerName("\xc0\xaf"));
    EXPECT_FALSE(validStickerName("\xed\xa0\x80"));
    EXPECT_FALSE(validStickerName("\xf4\x90\x80\x80"));
    EXPECT_TRUE(validStickerName("こんにちは %?#"));
    EXPECT_FALSE(stickerPath(root.string(), "cats", "missing.png"));
    file("cats/unsafe.svg");
    EXPECT_FALSE(stickerPath(root.string(), "cats", "unsafe.svg"));
    std::filesystem::create_symlink(root / "cats/A sleepy cat%?#.WEBP",
                                     root / "cats/link.png");
    std::filesystem::create_directory_symlink(root / "cats", root / "other");
    EXPECT_FALSE(stickerPath(root.string(), "cats", "link.png"));
    EXPECT_FALSE(stickerPath(root.string(), "other", "A sleepy cat%?#.WEBP"));
    // A literal percent-encoded name is a filename, never decoded twice.
    file("cats/%2e%2e.png");
    EXPECT_TRUE(stickerPath(root.string(), "cats", "%2e%2e.png"));
    // Serving is independent of startup catalog membership.
    file("cats/new.avif");
    EXPECT_TRUE(stickerPath(root.string(), "cats", "new.avif"));
}

TEST_F(Stickers, PostLifecycleSnapshotsAndFederation)
{
    ASSIGN_OR_FAIL(auto data, DataSourceSQLite::newFromMemory());
    auto author = user(*data);
    ASSIGN_OR_FAIL(auto registry, StickerRegistry::scan(root.string(),
                                                        config.url_root));
    Service service(config, *data, emoji, registry);
    ComposeParams params;
    params.sticker_action = StickerAction::SET;
    params.sticker = registry.all()[0].stickers[0].key;
    params.sensitive = true;
    ASSIGN_OR_FAIL(auto post, service.createPost(author, params));
    params.in_reply_to_uri = post.uri;
    ASSIGN_OR_FAIL(auto reply, service.createPost(author, params));
    EXPECT_EQ(reply.in_reply_to_uri, post.uri);
    ASSIGN_OR_FAIL(auto media, data->attachmentsForPost(post.id));
    ASSERT_EQ(media.size(), 1u);
    EXPECT_EQ(media[0].role, AttachmentRole::STICKER);
    EXPECT_EQ(data->connection().evalToValue<std::string>(
        "SELECT type FROM pragma_table_info('post_attachments') "
        "WHERE name='role'").value(), "INTEGER");
    EXPECT_EQ(data->connection().evalToValue<std::string>(
        "SELECT typeof(role) FROM post_attachments LIMIT 1").value(),
        "integer");
    EXPECT_EQ(media[0].description, "A sleepy cat%?#");
    EXPECT_TRUE(media[0].sensitive);
    ASSIGN_OR_FAIL(auto count, data->connection().evalToValue<int64_t>(
        "SELECT count(*) FROM attachments"));
    EXPECT_EQ(count, 1);
    EXPECT_FALSE(std::filesystem::exists(config.attachment_dir));
    auto note = noteJson(config, post, author, {}, media, &emoji);
    EXPECT_EQ(note["attachment"][0]["url"], params.sticker);
    EXPECT_EQ(note["attachment"][0]["name"], "A sleepy cat%?#");
    ASSIGN_OR_FAIL(auto view, service.postView(post, author));
    EXPECT_TRUE(view["attachments"].empty());
    EXPECT_FALSE(view["sticker"].is_null());
    params.sticker_action = StickerAction::CLEAR;
    params.sticker.clear();
    EXPECT_FALSE(service.editPost(author, post.id, params));
    EXPECT_EQ(data->attachmentsForPost(post.id)->size(), 1u);
    params.source = "edited";
    params.sticker_action = StickerAction::KEEP;
    std::filesystem::remove(root / "cats/A sleepy cat%?#.WEBP");
    EXPECT_TRUE(service.editPost(author, post.id, params));
    EXPECT_EQ(data->attachmentsForPost(post.id)->at(0).description,
              "A sleepy cat%?#");
    params.sticker_action = StickerAction::SET;
    params.sticker = registry.all()[0].stickers[0].key;
    EXPECT_FALSE(service.editPost(author, post.id, params));
    params.sticker_action = StickerAction::CLEAR;
    params.sticker.clear();
    EXPECT_TRUE(service.editPost(author, post.id, params));
    EXPECT_TRUE(data->attachmentsForPost(post.id)->empty());
}

TEST_F(Stickers, PromotionConstraintsAndRollback)
{
    ASSIGN_OR_FAIL(auto data, DataSourceSQLite::newFromMemory());
    auto author = user(*data);
    ASSIGN_OR_FAIL(auto registry, StickerRegistry::scan(root.string(),
                                                        config.url_root));
    Service service(config, *data, emoji, registry);
    ComposeParams params;
    params.source = "hello";
    ASSIGN_OR_FAIL(auto post, service.createPost(author, params));
    Attachment asset;
    asset.remote_url = registry.all()[0].stickers[0].url;
    asset.media_type = "image/webp";
    asset.original_name = "asset-wide name";
    asset.is_image = true;
    ASSIGN_OR_FAIL(auto id, data->insertAttachment(asset));
    ASSERT_TRUE(data->attachToPost(id, post.id));
    ASSERT_TRUE(data->setPostSticker(post.id, id, "saved description"));
    ASSIGN_OR_FAIL(auto media, data->attachmentsForPost(post.id));
    ASSERT_EQ(media.size(), 1u);
    EXPECT_EQ(media[0].description, "saved description");
    EXPECT_EQ(noteJson(config, post, author, {}, media, &emoji)
        ["attachment"][0]["name"], "saved description");
    EXPECT_FALSE(data->setPostSticker(post.id, id, ""));
    EXPECT_FALSE(data->connection().execute(
        "UPDATE post_attachments SET description=NULL"));
    EXPECT_FALSE(data->connection().execute(
        "UPDATE post_attachments SET description=''"));
    EXPECT_FALSE(data->connection().execute(
        "UPDATE post_attachments SET role=2"));
    // A failing edit must restore both content and the existing relation.
    ASSERT_TRUE(data->connection().execute(
        "CREATE TRIGGER reject_sticker BEFORE INSERT ON post_attachments "
        "WHEN NEW.role=1 BEGIN SELECT RAISE(ABORT,'test'); END"));
    params.source = "changed";
    params.sticker_action = StickerAction::SET;
    params.sticker = *asset.remote_url;
    EXPECT_FALSE(service.editPost(author, post.id, params));
    EXPECT_EQ(data->getPostById(post.id)->value().content_source, "hello");
    EXPECT_EQ(data->attachmentsForPost(post.id)->at(0).description,
              "saved description");
    EXPECT_TRUE(stickerPath(root.string(), "cats", "A sleepy cat%?#.WEBP"));
}

TEST_F(Stickers, OuterFailureRollsBackNewUrlAsset)
{
    ASSIGN_OR_FAIL(auto data, DataSourceSQLite::newFromMemory());
    auto author = user(*data);
    ASSIGN_OR_FAIL(auto registry, StickerRegistry::scan(root.string(),
                                                        config.url_root));
    Service service(config, *data, emoji, registry);
    ComposeParams params;
    params.sticker_action = StickerAction::SET;
    params.sticker = registry.all()[0].stickers[0].key;
    {
        ASSIGN_OR_FAIL(auto transaction, ap::Transaction::begin(data->connection()));
        ASSERT_TRUE(service.createPost(author, params));
        // Simulate failure of subsequent outbound enqueue; outer scope aborts.
    }
    EXPECT_EQ(data->connection().evalToValue<int64_t>(
        "SELECT count(*) FROM attachments").value(), 0);
    EXPECT_EQ(data->connection().evalToValue<int64_t>(
        "SELECT count(*) FROM posts").value(), 0);
    params.sticker = "https://unregistered.test/file.png";
    EXPECT_FALSE(service.createPost(author, params));
    params.sticker_action = StickerAction::KEEP;
    EXPECT_FALSE(service.createPost(author, params));
    params.sticker.clear();
    params.source = " \n\t";
    EXPECT_FALSE(service.createPost(author, params));
}

TEST_F(Stickers, MigrationEightToNineAndUniqueSticker)
{
    auto path = root / "migration.sqlite";
    int64_t post_id;
    int64_t asset_id;
    {
        ASSIGN_OR_FAIL(auto data, DataSourceSQLite::fromFile(path.string()));
        auto author = user(*data);
        Service service(config, *data, emoji);
        ComposeParams params;
        params.source = "retained";
        ASSIGN_OR_FAIL(auto post, service.createPost(author, params));
        post_id = post.id;
        Attachment asset;
        asset.remote_url = "https://f.test/stickers/one.png";
        asset.original_name = "legacy description";
        asset.media_type = "image/png";
        asset.is_image = true;
        ASSIGN_OR_FAIL(asset_id, data->insertAttachment(asset));
        ASSERT_TRUE(data->attachToPost(asset_id, post.id));
        auto& db = data->connection();
        ASSERT_TRUE(db.execute("DROP TRIGGER description_INSERT"));
        ASSERT_TRUE(db.execute("DROP TRIGGER description_UPDATE"));
        ASSERT_TRUE(db.execute("DROP INDEX idx_post_attachments_one_sticker"));
        ASSERT_TRUE(db.execute("ALTER TABLE post_attachments DROP COLUMN role"));
        ASSERT_TRUE(db.execute(
            "ALTER TABLE post_attachments DROP COLUMN description"));
        ASSERT_TRUE(db.execute("PRAGMA user_version=8"));
    }
    ASSIGN_OR_FAIL(auto data, DataSourceSQLite::fromFile(path.string()));
    EXPECT_EQ(data->getSchemaVersion().value(), 9);
    ASSIGN_OR_FAIL(auto media, data->attachmentsForPost(post_id));
    ASSERT_EQ(media.size(), 1u);
    EXPECT_EQ(media[0].role, AttachmentRole::ATTACHMENT);
    EXPECT_EQ(data->connection().evalToValue<std::string>(
        "SELECT type FROM pragma_table_info('post_attachments') "
        "WHERE name='role'").value(), "INTEGER");
    EXPECT_EQ(data->connection().evalToValue<int64_t>(
        "SELECT role FROM post_attachments LIMIT 1").value(), 0);
    EXPECT_EQ(media[0].description, "legacy description");
    ASSERT_TRUE(data->setPostSticker(post_id, asset_id, "snapshot"));
    Attachment other;
    other.remote_url = "https://f.test/stickers/two.png";
    ASSIGN_OR_FAIL(auto second_id, data->insertAttachment(other));
    ASSERT_TRUE(data->attachToPost(second_id, post_id));
    EXPECT_FALSE(data->connection().execute(
        "UPDATE post_attachments SET role=1,description='duplicate' "
        "WHERE role=0"));
    // Replacement preserves other ordinary relationships and appends sticker.
    ASSERT_TRUE(data->setPostSticker(post_id, second_id, "replacement"));
    ASSIGN_OR_FAIL(auto promoted, data->attachmentsForPost(post_id));
    ASSERT_EQ(promoted.size(), 1u);
    EXPECT_EQ(promoted[0].id, second_id);
    EXPECT_EQ(promoted[0].description, "replacement");
}

TEST_F(Stickers, OrdinaryMediaDescriptionsSurviveUrlReuse)
{
    ASSIGN_OR_FAIL(auto data, DataSourceSQLite::newFromMemory());
    auto author = user(*data);
    Service service(config, *data, emoji);
    ComposeParams params;
    params.source = "post";
    ASSIGN_OR_FAIL(auto first, service.createPost(author, params));
    ASSIGN_OR_FAIL(auto second, service.createPost(author, params));
    Attachment image;
    image.remote_url = "https://remote.test/shared.png";
    image.media_type = "image/png";
    image.is_image = true;
    image.original_name = "first asset name";
    image.post_id = first.id;
    image.description = "First <description>";
    ASSIGN_OR_FAIL(auto asset_id, data->insertAttachment(image));
    image.post_id = second.id;
    image.original_name = "second asset name";
    image.description = "Second description";
    ASSIGN_OR_FAIL(auto reused_id, data->insertAttachment(image));
    EXPECT_EQ(asset_id, reused_id);
    ASSIGN_OR_FAIL(auto first_media, data->attachmentsForPost(first.id));
    ASSIGN_OR_FAIL(auto second_media, data->attachmentsForPost(second.id));
    EXPECT_EQ(first_media[0].description, "First <description>");
    EXPECT_EQ(second_media[0].description, "Second description");
    EXPECT_EQ(noteJson(config, first, author, {}, first_media, &emoji)
        ["attachment"][0]["name"], "First <description>");
    EXPECT_EQ(noteJson(config, second, author, {}, second_media, &emoji)
        ["attachment"][0]["name"], "Second description");
    ASSIGN_OR_FAIL(auto view, service.postView(first, author));
    EXPECT_EQ(view["attachments"][0]["original_name"],
              "First &lt;description&gt;");
    // Asset lookup has no post-specific description.
    ASSIGN_OR_FAIL(auto bare, data->getAttachmentById(asset_id));
    ASSERT_TRUE(bare);
    EXPECT_FALSE(bare->description);
    EXPECT_EQ(bare->original_name, "first asset name");
    image.description = "Edited second description";
    ASSERT_TRUE(data->insertAttachment(image));
    EXPECT_EQ(data->attachmentsForPost(first.id)->at(0).description,
              "First <description>");
    EXPECT_EQ(data->attachmentsForPost(second.id)->at(0).description,
              "Edited second description");
}

TEST_F(Stickers, UploadDescriptionsSurviveAssetReuse)
{
    ASSIGN_OR_FAIL(auto data, DataSourceSQLite::newFromMemory());
    auto author = user(*data);
    Service service(config, *data, emoji);
    Attachment image;
    image.sha256 = "abcdef";
    image.extension = "png";
    image.media_type = "image/png";
    image.is_image = true;
    image.original_name = "first.png";
    ASSIGN_OR_FAIL(auto id, data->insertAttachment(image));
    ComposeParams params;
    params.attachment_ids = {id};
    params.attachment_descriptions[id] = "first.png";
    ASSIGN_OR_FAIL(auto first, service.createPost(author, params));
    params.attachment_descriptions[id] = "second.png";
    ASSIGN_OR_FAIL(auto second, service.createPost(author, params));
    EXPECT_EQ(data->attachmentsForPost(first.id)->at(0).description,
              "first.png");
    EXPECT_EQ(data->attachmentsForPost(second.id)->at(0).description,
              "second.png");
}
