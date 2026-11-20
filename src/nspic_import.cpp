#include "nspic_import.hpp"

#include <actpub/transaction.hpp>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mw/crypto.hpp>
#include <mw/database.hpp>
#include <mw/utils.hpp>
#include <ostream>
#include <set>
#include <sqlite3.h>
#include <tuple>
#include <vector>

#include "attachments.hpp"
#include "data.hpp"
#include "photo_processing.hpp"
#include "service.hpp"

namespace unspoken
{
namespace
{
namespace fs = std::filesystem;

void closeSource(sqlite3 *db)
{
    sqlite3_close(db);
}
using ReadConnection = std::unique_ptr<sqlite3, decltype(&closeSource)>;

mw::E<ReadConnection> openReadOnly(const std::string &path)
{
    sqlite3 *handle = nullptr;
    auto code =
        sqlite3_open_v2(path.c_str(), &handle,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nullptr);
    ReadConnection connection(handle, closeSource);
    if(code != SQLITE_OK)
        return std::unexpected(
            mw::runtimeError("Cannot open read-only database: " + path));
    sqlite3_busy_timeout(handle, 5000);
    // Retain a consistent read snapshot without changing journal mode.
    if(sqlite3_exec(handle, "BEGIN", nullptr, nullptr, nullptr) != SQLITE_OK)
        return std::unexpected(mw::runtimeError(sqlite3_errmsg(handle)));
    return connection;
}

template <typename... Types>
mw::E<std::vector<std::tuple<Types...>>> readRows(sqlite3 *connection,
                                                  std::string_view sql)
{
    ASSIGN_OR_RETURN(auto statement,
                     mw::SQLiteStatement::fromStr(connection, sql));
    // libmw's statement evaluator borrows only the statement's connection.
    mw::SQLite evaluator;
    return evaluator.eval<Types...>(std::move(statement));
}

struct SourceImage
{
    std::string path;
};

struct SourcePost
{
    int64_t id = 0;
    std::string caption;
    int64_t published = 0;
    nlohmann::json album = nullptr;
    std::vector<SourceImage> images;
    std::string digest;
    std::optional<int64_t> mapped_post;
    bool mapped = false;
    uint64_t bytes = 0;
};

mw::E<std::string> readImage(const NspicImportOptions &options,
                             const std::string &relative, int64_t max_bytes)
{
    fs::path path(relative);
    if(path.empty() || path.is_absolute() ||
       relative.find('\0') != std::string::npos ||
       relative.find('\\') != std::string::npos)
        return std::unexpected(mw::runtimeError("Invalid source image path"));
    for(const auto &component : path)
        if(component == "..")
            return std::unexpected(
                mw::runtimeError("Source image path contains traversal"));
    std::error_code error;
    auto root = fs::canonical(options.image_dir, error);
    if(error) return std::unexpected(mw::runtimeError("Invalid image root"));
    auto resolved = fs::canonical(root / path, error);
    if(error)
        return std::unexpected(
            mw::runtimeError("Missing source image: " + relative));
    auto contained = resolved.lexically_relative(root);
    if(contained.empty() || *contained.begin() == ".." ||
       !fs::is_regular_file(resolved, error) || error)
        return std::unexpected(mw::runtimeError(
            "Source image escapes root or is not a regular file: " + relative));
    std::ifstream file(resolved, std::ios::binary | std::ios::ate);
    auto size = file.tellg();
    if(!file || size <= 0 || size > max_bytes)
        return std::unexpected(
            mw::runtimeError("Empty or oversized source image: " + relative));
    std::string bytes(static_cast<size_t>(size), '\0');
    file.seekg(0);
    if(!file.read(bytes.data(), size))
        return std::unexpected(
            mw::runtimeError("Cannot read source image: " + relative));
    return bytes;
}

mw::E<void> hashField(mw::SHA256IncrementalHasher &hasher,
                      std::string_view field)
{
    // Fixed-width big-endian byte lengths remove separator ambiguities.
    std::string length(8, '\0');
    auto size = static_cast<uint64_t>(field.size());
    for(int i = 7; i >= 0; --i)
    {
        length[i] = static_cast<char>(size & 255);
        size >>= 8;
    }
    DO_OR_RETURN(hasher.update(length));
    return hasher.update(field);
}

mw::E<void> preparePost(const Config &config, const NspicImportOptions &options,
                        SourcePost &post)
{
    if(post.published < -62135596800LL || post.published > 253402300799LL)
        return std::unexpected(
            mw::runtimeError("Invalid publication timestamp"));
    if(post.images.empty())
        return std::unexpected(mw::runtimeError("Source post has no images"));
    mw::SHA256IncrementalHasher hasher;
    DO_OR_RETURN(hashField(hasher, "nspic-v1"));
    DO_OR_RETURN(hashField(hasher, post.caption));
    DO_OR_RETURN(hashField(hasher, std::to_string(post.published)));
    DO_OR_RETURN(hashField(hasher, post.album.dump()));
    DO_OR_RETURN(hashField(hasher, std::to_string(post.images.size())));
    post.bytes = 0;
    std::set<std::string> seen;
    for(const auto &image : post.images)
    {
        ASSIGN_OR_RETURN(auto bytes, readImage(options, image.path,
                                               config.max_upload_bytes));
        ASSIGN_OR_RETURN(auto processed, processPhoto(bytes, config.photos));
        mw::SHA256Hasher asset_hasher;
        ASSIGN_OR_RETURN(auto asset_hash,
                         asset_hasher.hashToHexStr(processed.bytes));
        if(!seen.insert(asset_hash).second)
            return std::unexpected(
                mw::runtimeError("Duplicate source image in one post"));
        DO_OR_RETURN(hashField(hasher, bytes));
        post.bytes += bytes.size();
    }
    ASSIGN_OR_RETURN(auto digest, hasher.finalizeToHexStr());
    post.digest = "sha256:nspic-v1:" + digest;
    return {};
}

mw::E<std::vector<SourcePost>> sourcePosts(sqlite3 *source)
{
    ASSIGN_OR_RETURN(
        auto invalid,
        (readRows<int64_t>(
            source,
            "SELECT id FROM posts WHERE typeof(upload_time) != 'integer'")));
    if(!invalid.empty())
        return std::unexpected(
            mw::runtimeError("Source contains invalid publication timestamps"));
    ASSIGN_OR_RETURN(
        auto rows,
        (readRows<int64_t, std::string, int64_t, std::optional<int64_t>,
                  std::optional<std::string>>(
            source,
            "SELECT p.id,COALESCE(p.desc,''),p.upload_time,p.album,a.title "
            "FROM posts p LEFT JOIN albums a ON a.id=p.album "
            "ORDER BY p.upload_time ASC,p.id ASC")));
    std::vector<SourcePost> posts;
    for(const auto &[id, caption, published, album_id, title] : rows)
    {
        SourcePost post;
        post.id = id;
        post.caption = caption;
        post.published = published;
        if(album_id)
            post.album = {{"id", *album_id},
                          {"title", title ? nlohmann::json(*title)
                                          : nlohmann::json(nullptr)}};
        ASSIGN_OR_RETURN(
            auto statement,
            mw::SQLiteStatement::fromStr(
                source,
                "SELECT path FROM images WHERE post=? ORDER BY id ASC"));
        DO_OR_RETURN(statement.bind<int64_t>(id));
        mw::SQLite evaluator;
        ASSIGN_OR_RETURN(auto images,
                         evaluator.eval<std::string>(std::move(statement)));
        for(const auto &[path] : images)
            post.images.push_back({path});
        posts.push_back(std::move(post));
    }
    return posts;
}

mw::E<void> checkMapping(sqlite3 *destination,
                         const NspicImportOptions &options, int64_t author_id,
                         SourcePost &post)
{
    ASSIGN_OR_RETURN(
        auto tables,
        (readRows<int64_t>(
            destination,
            "SELECT 1 FROM sqlite_master WHERE name='nspic_imports'")));
    if(tables.empty()) return {};
    ASSIGN_OR_RETURN(
        auto statement,
        mw::SQLiteStatement::fromStr(
            destination,
            "SELECT author_id,post_id,source_digest FROM nspic_imports "
            "WHERE source_key=? AND source_post_id=?"));
    DO_OR_RETURN(
        (statement.bind<std::string, int64_t>(options.source_key, post.id)));
    mw::SQLite evaluator;
    ASSIGN_OR_RETURN(
        auto rows,
        (evaluator.eval<int64_t, std::optional<int64_t>, std::string>(
            std::move(statement))));
    if(rows.empty()) return {};
    const auto &[author, post_id, digest] = rows.front();
    if(author != author_id || digest != post.digest)
        return std::unexpected(
            mw::runtimeError("Import mapping changed; explicit operator "
                             "reconciliation required"));
    post.mapped = true;
    post.mapped_post = post_id;
    return {};
}

std::string plainMarkdown(std::string_view text)
{
    // MacroDown returns literal text nodes verbatim. Escape HTML first, then
    // protect every punctuation token from Markdown and mention parsing.
    // Entity-encoded indentation also prevents accidental code/list blocks.
    std::string result;
    for(unsigned char c : mw::escapeHTML(text))
    {
        if(c == '\n')
            result += "<br>\n";
        else if(c == ' ')
            result += "\\&\\#32\\;";
        else if(c == '\t')
            result += "\\&\\#9\\;";
        else
        {
            if(c < 128 && std::ispunct(c)) result.push_back('\\');
            result.push_back(static_cast<char>(c));
        }
    }
    return result;
}

std::string plainHtml(std::string_view text)
{
    auto html = mw::escapeHTML(text);
    std::string result;
    for(char c : html)
        if(c == '\n')
            result += "<br>\n";
        else
            result.push_back(c);
    return "<p>" + result + "</p>";
}

nlohmann::json reportPost(const Config &config, const SourcePost &post,
                          const std::string &status)
{
    return {{"source_post_id", post.id},
            {"status", status},
            {"files", post.images.size()},
            {"bytes", post.bytes},
            {"album", post.album},
            {"source_digest", post.digest},
            {"post_url", post.mapped_post
                             ? nlohmann::json(config.url_root + "p/" +
                                              std::to_string(*post.mapped_post))
                             : nlohmann::json(nullptr)}};
}

mw::E<Post> writePost(const Config &config, const DataSourceSQLite &data,
                      const NspicImportOptions &options, const SourcePost &post,
                      int64_t author_id, std::vector<StoredFile> &copied)
{
    ASSIGN_OR_RETURN(auto transaction,
                     ap::Transaction::begin(data.connection()));
    NewPost np;
    np.post_kind = PostKind::PHOTO;
    np.local_author_id = author_id;
    np.content_html = plainHtml(post.caption);
    np.content_source = plainMarkdown(post.caption);
    np.published = formatDatetime(post.published);
    np.previews_enabled = false;
    std::vector<PostRecipient> recipients = {
        {0, std::string(AS_PUBLIC), "to"},
        {0, config.url_root + "u/" + options.author + "/followers", "cc"}};
    ASSIGN_OR_RETURN(auto created,
                     data.insertPost(np, recipients, config.url_root + "p/"));
    for(const auto &image : post.images)
    {
        ASSIGN_OR_RETURN(auto bytes, readImage(options, image.path,
                                               config.max_upload_bytes));
        ASSIGN_OR_RETURN(auto stored, storePhoto(config.attachment_dir, bytes,
                                                 config.photos));
        copied.push_back(stored);
        Attachment attachment;
        attachment.post_id = created.id;
        attachment.sha256 = stored.sha256;
        attachment.extension = extensionOf(stored.filename);
        attachment.media_type = stored.media_type;
        attachment.is_image = true;
        attachment.original_name = fs::path(image.path).filename().string();
        attachment.description = "";
        DO_OR_RETURN(data.insertAttachment(attachment));
    }
    ASSIGN_OR_RETURN(
        auto mapping,
        data.connection().statementFromStr(
            "INSERT INTO "
            "nspic_imports(source_key,source_post_id,author_id,post_id,"
            "source_digest,imported_at) VALUES(?,?,?,?,?,?)"));
    DO_OR_RETURN((mapping.bind<std::string, int64_t, int64_t, int64_t,
                               std::string, int64_t>(
        options.source_key, post.id, author_id, created.id, post.digest,
        mw::timeToSeconds(mw::Clock::now()))));
    DO_OR_RETURN(data.connection().execute(std::move(mapping)));
    DO_OR_RETURN(transaction.commit());
    return created;
}
} // namespace

mw::E<void> importNspic(const Config &config, const NspicImportOptions &options,
                        std::ostream &report)
{
    if(options.source_key.empty() || options.author.empty())
        return std::unexpected(mw::runtimeError(
            "An existing local author and stable source-key are required"));
    std::error_code path_error;
    if(fs::equivalent(options.source_db, config.database_path, path_error) &&
       !path_error)
        return std::unexpected(
            mw::runtimeError("Source and destination databases must differ"));
    DO_OR_RETURN(initializePhotoProcessing());
    ASSIGN_OR_RETURN(auto source, openReadOnly(options.source_db));
    ASSIGN_OR_RETURN(auto destination, openReadOnly(config.database_path));
    ASSIGN_OR_RETURN(
        auto author_query,
        mw::SQLiteStatement::fromStr(destination.get(),
                                     "SELECT id FROM users WHERE username=?"));
    DO_OR_RETURN(author_query.bind<std::string>(options.author));
    mw::SQLite evaluator;
    ASSIGN_OR_RETURN(auto authors,
                     evaluator.eval<int64_t>(std::move(author_query)));
    if(authors.size() != 1)
        return std::unexpected(mw::runtimeError(
            "Import author must be an existing local account"));
    auto author_id = std::get<0>(authors.front());
    ASSIGN_OR_RETURN(auto posts, sourcePosts(source.get()));
    report << nlohmann::json(
                  {{"type", "source"},
                   {"source_key", options.source_key},
                   {"dry_run", options.dry_run},
                   {"image_order",
                    "images.id ASC; independent order is unrecoverable"},
                   {"originals",
                    "stored nspic images; camera originals may be absent"}})
                  .dump()
           << '\n';
    bool invalid = false;
    for(auto &post : posts)
    {
        auto prepared = preparePost(config, options, post);
        if(prepared)
            prepared =
                checkMapping(destination.get(), options, author_id, post);
        if(!prepared)
        {
            auto row = reportPost(config, post, "invalid");
            row["error"] = mw::errorMsg(prepared.error());
            report << row.dump() << '\n';
            invalid = true;
        }
        else if(options.dry_run)
            report << reportPost(config, post,
                                 post.mapped ? "skipped" : "would_import")
                          .dump()
                   << '\n';
    }
    if(invalid)
        return std::unexpected(mw::runtimeError(
            "Preflight failed; no posts or files were imported"));
    if(options.dry_run) return {};
    destination.reset();
    ASSIGN_OR_RETURN(auto data,
                     DataSourceSQLite::fromFile(config.database_path,
                                                config.sqlite_busy_timeout_ms));
    for(auto &post : posts)
    {
        if(post.mapped)
        {
            report << reportPost(config, post, "skipped").dump() << '\n';
            continue;
        }
        // Detect changes between preflight and the write pass.
        auto expected_digest = post.digest;
        auto prepared = preparePost(config, options, post);
        if(!prepared || post.digest != expected_digest)
        {
            auto row = reportPost(config, post, "failed");
            row["error"] = "Source changed after preflight";
            report << row.dump() << '\n';
            return std::unexpected(
                mw::runtimeError("Source changed after preflight"));
        }
        std::vector<StoredFile> copied;
        auto created =
            writePost(config, *data, options, post, author_id, copied);
        if(!created)
        {
            auto row = reportPost(config, post, "failed");
            row["error"] = mw::errorMsg(created.error());
            auto cleanup = data->cleanupStoredAttachments(copied);
            if(!cleanup) row["cleanup_error"] = mw::errorMsg(cleanup.error());
            report << row.dump() << '\n';
            return std::unexpected(created.error());
        }
        post.mapped_post = created->id;
        report << reportPost(config, post, "imported").dump() << '\n';
    }
    return {};
}
} // namespace unspoken
