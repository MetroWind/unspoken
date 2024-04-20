#include <algorithm>
#include <memory>
#include <string>
#include <ranges>
#include <expected>

#include "data.hpp"
#include "data_types.hpp"
#include "database.hpp"
#include "error.hpp"
#include "utils.hpp"

static E<std::unique_ptr<DataSourceSQLite>> DataSourceSQLite::newFromMemory()
{
    auto result = std::make_unique<DataSourceSQLite>();
    ASSIGN_OR_RETURN(result->db, SQLite::connectMemory());
    DO_OR_RETURN(result->setupTables());
    return result;
}

static E<std::unique_ptr<DataSourceSQLite>>
DataSourceSQLite::fromDBFile(const std::string& f);
{
    auto result = std::make_unique<DataSourceSQLite>();
    ASSIGN_OR_RETURN(result->db, SQLite::connectFile(f));
    DO_OR_RETURN(result->setupTables());
    return result;
}

E<void> DataSourceSQLite::createUser(std::string_view name)
{
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "INSERT INTO Users (name) VALUES (?);"));
    DO_OR_RETURN(sql.bind(name));
    return db->execute(std::move(sql));
}

E<std::optional<LocalUser>> DataSourceSQLite::getUser(std::string_view name)
{
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "SELECT name, desc, avatar_attch_hash, time_join, public_key, "
        "private_key FROM Users WHERE name = ?;"));
    DO_OR_RETURN(sql.bind(name));
    ASSIGN_OR_RETURN(auto users, db->eval<std::string, std::string, std::string,
                     int64_t, std::string, std::string>(std::move(sql)));
    if(users.empty())
    {
        return std::nullopt;
    }

    LocalUser result;
    result.name = std::get<0>(users[0]);
    result.desc = std::get<1>(users[0]);
    result.avatar.file = std::get<2>(users[0]);
    result.time_join = secondsToTime(std::get<3>(users[0]));
    result.keys.public_key = base64Decode(std::get<4>(users[0]));
    result.keys.private_key = base64Decode(std::get<5>(users[0]));
    return result;
}

E<void> DataSourceSQLite::post(Post&& p)
{
    if(p.remote())
    {
        return addRemotePost(p);
    }
    else
    {
        return addLocalPost(p);
    }
}

E<void> deletePost(uint64_t id)
{
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "SELECT count(*) FROM Posts WHERE id = ?;"));
    DO_OR_RETURN(sql.bind(id));
    ASSIGN_OR_RETURN(auto counts, db->eval<int64_t>(std::move(sql)));
    int64_t count = std::get<0>(std::move(counts)[0]);
    if(count == 0)
    {
        return std::unexpected(
            runtimeError(std::format("Post with ID {} not found.", id)));
    }

    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "DELETE FROM Posts WHERE id = ?;"));
    DO_OR_RETURN(sql.bind(id));
    return db->execute(std::move(sql));
}

// ========== Privates ==============================================>

E<void> DataSourceSQLite::setupTables() const
{
    DO_OR_RETURN(db->execute(R"(
CREATE TABLE IF NOT EXISTS Attachments
(
 -- Relative path of the attachment. It is relative to the attachment dir.
 file TEXT PRIMARY KEY
);
)"));
    DO_OR_RETURN(db->execute(R"(
CREATE TABLE IF NOT EXISTS Users -- Records of local users
(id INTEGER PRIMARY KEY ASC,
 name TEXT UNIQUE, -- local name of the user, without the server part.
 desc TEXT,        -- Description of the user. Appears in the user profile.
 -- The attachment file of the user’s avatar. Must be a key in the
 -- Attachments table.
 avatar_attch_file TEXT REFERENCES Attachments (file) ON DELETE SET NULL,
 time_join INTEGER, -- Time of account creation in seconds since UNIX epoch.
 public_key TEXT,   -- Public key of the user in DER-encoded bytes.
 private_key TEXT   -- Private key of the user in DER-encoded bytes.
);
)"));

    DO_OR_RETURN(db->execute(R"(
CREATE TABLE IF NOT EXISTS Posts -- Records of all posts, local and remote.
(id INTEGER PRIMARY KEY ASC,
 visibility INTEGER,    -- The int value of Post:visibility.
 time_creation INTEGER, -- Time of creation in seconds since UNIX epoch.
 -- Time of update in seconds since UNIX epoch. For posts that are
 -- never updated, this is the same as time_creation.
 time_update INTEGER,
 title TEXT,            -- Title of the post.
 -- Content of the post body. This is CommonMark for local posts, and
 -- HTML for remote posts.
 content TEXT,
 remote_attch TEXT,     -- URLs of the attachments for remote posts.
 remote_url TEXT UNIQUE -- Remote URL of the remote post.
);
)"));
    DO_OR_RETURN(db->execute(R"(
-- Records of post-attachment relations
CREATE TABLE IF NOT EXISTS PostsAttachments
(post_id INTEGER REFERENCES posts (id) ON DELETE CASCADE,
 attch_file TEXT REFERENCES Attachments (file) ON DELETE CASCADE,
 UNIQUE (post_id, attch_hash)
);
)"));
    DO_OR_RETURN(db->execute(R"(
CREATE TABLE IF NOT EXISTS Likes
( -- Name of the user that likes the post. For local user this is the
  -- local name without the server part. For remote user this is
  -- name@server.
 user TEXT,
 post_id INTEGER REFERENCES posts (id) ON DELETE CASCADE,
 UNIQUE (user, post_id)
);
)"));
    return {};
}

E<void> DataSourceSQLite::addRemotePost(const Post& p) const
{
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "SELECT id FROM Posts WHERE remote_url = ?;"));
    DO_OR_RETURN(sql.bind(p.remote_url));
    ASSIGN_OR_RETURN(auto posts, db->eval<int64_t>(std::move(sql)));
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "INSERT INTO Posts (visibility, time_creation, time_update, title,"
        " content, remote_attch, remote_url) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) "
        "ON CONFLICT DO UPDATE SET visibility = ?1, time_update = ?3,"
        " title = ?4, content = ?5, remote_attch = ?6;"));
    DO_OR_RETURN(sql.bind(
        static_cast<int>(p.visibility), timeToSeconds(p.time_creation),
        timeToSeconds(p.time_update), p.title, p.content,
        joinStrs(std::begin(p.remote_attachments), " "), p.remote_url));
    return db->execute(std::move(sql));
}

E<void> DataSourceSQLite::addLocalPost(const Post& p) const
{
    int64_t pid;
    if(p.id.has_value())
    {
        pid = *p.id;
        ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
            "UPDATE Posts SET visibility = ?, time_update = ?, title = ?,"
            " content = ? WHERE id = ?;"))
        DO_OR_RETURN(sql.bind(
            static_cast<int>(p.visibility), timeToSeconds(Clock::now()),
            p.title, p.content, pid));
        DO_OR_RETURN(db->execute(std::move(sql)));
    }
    else
    {
        ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
            "INSERT INTO Posts (visibility, time_creation, time_update, title,"
            " content) VALUES (?, ?, ?, ?, ?);"));
        DO_OR_RETURN(sql.bind(
            static_cast<int>(p.visibility), timeToSeconds(Clock::now()),
            p.title, p.content));
        DO_OR_RETURN(db->execute(std::move(sql)));
        pid = db->lastInsertRowID();
    }
    return updateAttachments(pid, p.attachments);
}

E<std::vector<int64_t>> DataSourceSQLite::findPostsByAttachment(
    const Attachment& attachments) const
{
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "SELECT post_id from PostsAttachments where attch_file = ?;"));
    DO_OR_RETURN(sql.bind(att.file));
    ASSIGN_OR_RETURN(std::vector<std::tuple<int64_t>> ids,
                     db->eval<int64_t>(std::move(sql)));
    return std::ranges::to<std::vector>(ids | std::views::transform(
        [](const auto& t) { return std::get<0>(t); }));
}

E<void> addAttachment(int64_t post_id, const Attachment& att) const
{
    ASSIGN_OR_RETURN(auto sql, db->statementFromStr(
        "INSERT INTO PostsAttachments (post_id, attch_file) VALUES (?, ?);"));
    DO_OR_RETURN(sql.bind(post_id, att.file));
    return db->execute(std::move(sql));
}

E<void> DataSourceSQLite::updateAttachments(
    int64_t post_id, std::span<Attachment> attachments) const
{
    for(const Attachments& att: attachments)
    {
        ASSIGN_OR_RETURN(auto ids, findPostsByAttachment(att));
        if(ids.empty() ||
           !std::contains(std::begin(ids), std::end(ids), post_id))
        {
            DO_OR_RETURN(addAttachment(int64_t post_id, att));
        }
    }
}
