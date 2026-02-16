#include "database.hpp"

#include <iostream>

#include <mw/error.hpp>
#include <mw/utils.hpp>
#include <spdlog/spdlog.h>

Database::Database(const std::string& path) : db_path(path) {}

mw::E<void> Database::init()
{
    auto conn = mw::SQLite::connectFile(db_path);
    if(!conn)
    {
        return std::unexpected(conn.error());
    }
    db = std::move(*conn);

    DO_OR_RETURN(db->execute("PRAGMA journal_mode=WAL;"));
    DO_OR_RETURN(db->execute("PRAGMA foreign_keys=ON;"));

    return migrate();
}

mw::E<void> Database::migrate()
{
    auto version_res = db->evalToValue<int>("PRAGMA user_version;");
    if(!version_res)
    {
        return std::unexpected(version_res.error());
    }

    int version = *version_res;

    if(version == 0)
    {
        spdlog::info("Creating database schema v1...");

        const std::vector<std::string> statements = {
            R"(CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                display_name TEXT,
                bio TEXT,
                email TEXT,
                uri TEXT UNIQUE,
                public_key TEXT,
                private_key TEXT,
                host TEXT,
                created_at INTEGER,
                avatar_path TEXT,
                oidc_subject TEXT UNIQUE,
                inbox TEXT,
                shared_inbox TEXT,
                outbox TEXT,
                followers TEXT,
                following TEXT
            );)",

            R"(CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uri TEXT UNIQUE,
                author_id INTEGER,
                content_html TEXT,
                content_source TEXT,
                in_reply_to_uri TEXT,
                visibility INTEGER,
                created_at INTEGER,
                is_local BOOLEAN,
                FOREIGN KEY(author_id) REFERENCES users(id)
            );)",

            R"(CREATE TABLE IF NOT EXISTS follows (
                follower_id INTEGER,
                target_id INTEGER,
                status INTEGER,
                uri TEXT,
                PRIMARY KEY(follower_id, target_id),
                FOREIGN KEY(follower_id) REFERENCES users(id),
                FOREIGN KEY(target_id) REFERENCES users(id)
            );)",

            R"(CREATE TABLE IF NOT EXISTS likes (
                user_id INTEGER,
                post_id INTEGER,
                created_at INTEGER,
                PRIMARY KEY(user_id, post_id),
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(post_id) REFERENCES posts(id)
            );)",

            R"(CREATE TABLE IF NOT EXISTS announces (
                user_id INTEGER,
                post_id INTEGER,
                created_at INTEGER,
                PRIMARY KEY(user_id, post_id),
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(post_id) REFERENCES posts(id)
            );)",

            R"(CREATE TABLE IF NOT EXISTS bookmarks (
                user_id INTEGER,
                post_id INTEGER,
                created_at INTEGER,
                PRIMARY KEY(user_id, post_id),
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(post_id) REFERENCES posts(id)
            );)",

            R"(CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT,
                payload TEXT,
                attempts INTEGER,
                next_try INTEGER,
                status INTEGER
            );)",

            R"(CREATE TABLE IF NOT EXISTS media (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT UNIQUE,
                filename TEXT,
                mime_type TEXT,
                uploader_id INTEGER,
                FOREIGN KEY(uploader_id) REFERENCES users(id)
            );)",

            R"(CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER,
                expires_at INTEGER,
                csrf_token TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );)",

            R"(CREATE TABLE IF NOT EXISTS system_config (
                key TEXT PRIMARY KEY,
                value TEXT
            );)",

            "PRAGMA user_version = 1;"};

        for(const auto& sql : statements)
        {
            auto res = db->execute(sql);
            if(!res)
            {
                spdlog::error("Failed to execute SQL: {}", sql);
                return std::unexpected(res.error());
            }
        }
    }

    return {};
}

mw::E<void> Database::updateUser(const User& user)
{
    const char* sql =
        "UPDATE users SET username = ?, display_name = ?, bio = ?, "
        "email = ?, uri = ?, public_key = ?, private_key = ?, host = ?, "
        "created_at = ?, avatar_path = ?, oidc_subject = ?, inbox = ?, "
        "shared_inbox = ?, "
        "outbox = ?, followers = ?, following = ? "
        "WHERE id = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));

    DO_OR_RETURN(stmt.bind(
        user.username, user.display_name, user.bio, user.email, user.uri,
        user.public_key, user.private_key, user.host, user.created_at,
        user.avatar_path, user.oidc_subject, user.inbox, user.shared_inbox,
        user.outbox, user.followers, user.following, user.id));

    return db->execute(std::move(stmt));
}

mw::E<int64_t> Database::createUser(const User& user)
{
    const char* sql =
        "INSERT INTO users (username, display_name, bio, "
        "email, uri, public_key, private_key, host, "
        "created_at, avatar_path, oidc_subject, inbox, shared_inbox, "
        "outbox, followers, following) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));

    DO_OR_RETURN(stmt.bind(
        user.username, user.display_name, user.bio, user.email, user.uri,
        user.public_key, user.private_key, user.host, user.created_at,
        user.avatar_path, user.oidc_subject, user.inbox, user.shared_inbox,
        user.outbox, user.followers, user.following));

    DO_OR_RETURN(db->execute(std::move(stmt)));
    return db->lastInsertRowID();
}

using UserTuple =
    std::tuple<int64_t, std::string, std::string, std::string,
               std::optional<std::string>, std::string, std::string,
               std::optional<std::string>, std::optional<std::string>, int64_t,
               std::optional<std::string>, std::optional<std::string>,
               std::optional<std::string>, std::optional<std::string>,
               std::optional<std::string>, std::optional<std::string>,
               std::optional<std::string>>;

static User rowToUser(const UserTuple& row)
{
    User u;
    u.id = std::get<0>(row);
    u.username = std::get<1>(row);
    u.display_name = std::get<2>(row);
    u.bio = std::get<3>(row);
    u.email = std::get<4>(row);
    u.uri = std::get<5>(row);
    u.public_key = std::get<6>(row);
    u.private_key = std::get<7>(row);
    u.host = std::get<8>(row);
    u.created_at = std::get<9>(row);
    u.avatar_path = std::get<10>(row);
    u.oidc_subject = std::get<11>(row);
    u.inbox = std::get<12>(row);
    u.shared_inbox = std::get<13>(row);
    u.outbox = std::get<14>(row);
    u.followers = std::get<15>(row);
    u.following = std::get<16>(row);
    return u;
}

mw::E<std::optional<User>> Database::getUserById(int64_t id)
{
    const char* sql = "SELECT id, username, display_name, bio, email, uri, "
                      "public_key, private_key, host, created_at, "
                      "avatar_path, oidc_subject, inbox, shared_inbox, "
                      "outbox, followers, following FROM users WHERE id = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(id));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, std::string, std::string, std::string,
                  std::string, std::string, std::string, std::string, int64_t,
                  std::string, std::string, std::string, std::string,
                  std::string, std::string, std::string>(std::move(stmt))));

    if(rows.empty())
    {
        return std::nullopt;
    }
    return rowToUser(rows[0]);
}

mw::E<std::optional<User>> Database::getUserByUsername(const std::string& name)
{
    const char* sql =
        "SELECT id, username, display_name, bio, email, uri, "
        "public_key, private_key, host, created_at, "
        "avatar_path, oidc_subject, inbox, shared_inbox, "
        "outbox, followers, following FROM users WHERE username = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(name));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, std::string, std::string, std::string,
                  std::string, std::string, std::string, std::string, int64_t,
                  std::string, std::string, std::string, std::string,
                  std::string, std::string, std::string>(std::move(stmt))));
    if(rows.empty())
    {
        return std::nullopt;
    }
    return rowToUser(rows[0]);
}

mw::E<std::optional<User>> Database::getUserByUri(const std::string& uri)
{
    const char* sql = "SELECT id, username, display_name, bio, email, uri, "
                      "public_key, private_key, host, created_at, "
                      "avatar_path, oidc_subject, inbox, shared_inbox, "
                      "outbox, followers, following FROM users WHERE uri = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(uri));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, std::string, std::string, std::string,
                  std::string, std::string, std::string, std::string, int64_t,
                  std::string, std::string, std::string, std::string,
                  std::string, std::string, std::string>(std::move(stmt))));
    if(rows.empty())
    {
        return std::nullopt;
    }
    return rowToUser(rows[0]);
}

mw::E<std::optional<User>>
Database::getUserByOidcSubject(const std::string& sub)
{
    const char* sql =
        "SELECT id, username, display_name, bio, email, uri, "
        "public_key, private_key, host, created_at, "
        "avatar_path, oidc_subject, inbox, shared_inbox, "
        "outbox, followers, following FROM users WHERE oidc_subject = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(sub));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, std::string, std::string, std::string,
                  std::string, std::string, std::string, std::string, int64_t,
                  std::string, std::string, std::string, std::string,
                  std::string, std::string, std::string>(std::move(stmt))));
    if(rows.empty())
    {
        return std::nullopt;
    }
    return rowToUser(rows[0]);
}

mw::E<int64_t> Database::createPost(const Post& post)
{
    const char* sql = "INSERT INTO posts (uri, author_id, content_html, "
                      "content_source, in_reply_to_uri, visibility, "
                      "created_at, is_local) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));

    DO_OR_RETURN(stmt.bind(post.uri, post.author_id, post.content_html,
                           post.content_source, post.in_reply_to_uri,
                           static_cast<int>(post.visibility), post.created_at,
                           post.is_local ? 1 : 0));

    DO_OR_RETURN(db->execute(std::move(stmt)));
    return db->lastInsertRowID();
}

using PostTuple =
    std::tuple<int64_t, std::string, int64_t, std::string, std::string,
               std::optional<std::string>, int, int64_t, int>;

static Post rowToPost(const PostTuple& row)
{
    Post p;
    p.id = std::get<0>(row);
    p.uri = std::get<1>(row);
    p.author_id = std::get<2>(row);
    p.content_html = std::get<3>(row);
    p.content_source = std::get<4>(row);
    p.in_reply_to_uri = std::get<5>(row);
    p.visibility = static_cast<Visibility>(std::get<6>(row));
    p.created_at = std::get<7>(row);
    p.is_local = std::get<8>(row) != 0;
    return p;
}

mw::E<std::optional<Post>> Database::getPostById(int64_t id)
{
    const char* sql = "SELECT id, uri, author_id, content_html, "
                      "content_source, in_reply_to_uri, visibility, "
                      "created_at, is_local FROM posts WHERE id = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(id));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, int64_t, std::string, std::string,
                  std::optional<std::string>, int, int64_t, int>(
            std::move(stmt))));
    if(rows.empty())
    {
        return std::nullopt;
    }
    return rowToPost(rows[0]);
}

mw::E<std::optional<Post>> Database::getPostByUri(const std::string& uri)
{
    const char* sql = "SELECT id, uri, author_id, content_html, "
                      "content_source, in_reply_to_uri, visibility, "
                      "created_at, is_local FROM posts WHERE uri = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(uri));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, int64_t, std::string, std::string,
                  std::optional<std::string>, int, int64_t, int>(
            std::move(stmt))));
    if(rows.empty())
    {
        return std::nullopt;
    }
    return rowToPost(rows[0]);
}

mw::E<std::vector<Post>> Database::getTimeline(int64_t user_id, int limit,
                                               int offset)
{
    const char* sql = "SELECT p.id, p.uri, p.author_id, p.content_html, "
                      "p.content_source, p.in_reply_to_uri, p.visibility, "
                      "p.created_at, p.is_local FROM posts p "
                      "WHERE p.author_id = ? OR p.author_id IN "
                      "(SELECT target_id FROM follows WHERE follower_id = ? "
                      "AND status = 1) "
                      "ORDER BY p.created_at DESC LIMIT ? OFFSET ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(user_id, user_id, limit, offset));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, int64_t, std::string, std::string,
                  std::optional<std::string>, int, int64_t, int>(
            std::move(stmt))));

    std::vector<Post> posts;
    for(const auto& row : rows)
    {
        posts.push_back(rowToPost(row));
    }
    return posts;
}

mw::E<std::vector<Post>> Database::getUserPosts(int64_t author_id, int limit,
                                                int offset)
{
    const char* sql = "SELECT id, uri, author_id, content_html, "
                      "content_source, in_reply_to_uri, visibility, "
                      "created_at, is_local FROM posts "
                      "WHERE author_id = ? ORDER BY created_at DESC "
                      "LIMIT ? OFFSET ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(author_id, limit, offset));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, int64_t, std::string, std::string,
                  std::optional<std::string>, int, int64_t, int>(
            std::move(stmt))));

    std::vector<Post> posts;
    for(const auto& row : rows)
    {
        posts.push_back(rowToPost(row));
    }
    return posts;
}

mw::E<std::vector<Post>> Database::getPublicTimeline(int limit, int offset)
{
    const char* sql = "SELECT id, uri, author_id, content_html, "
                      "content_source, in_reply_to_uri, visibility, "
                      "created_at, is_local FROM posts "
                      "WHERE visibility = 0 ORDER BY created_at DESC "
                      "LIMIT ? OFFSET ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(limit, offset));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, int64_t, std::string, std::string,
                  std::optional<std::string>, int, int64_t, int>(
            std::move(stmt))));

    std::vector<Post> posts;
    for(const auto& row : rows)
    {
        posts.push_back(rowToPost(row));
    }
    return posts;
}

mw::E<void> Database::createFollow(const Follow& follow)
{
    const char* sql = "INSERT OR REPLACE INTO follows (follower_id, "
                      "target_id, status, uri) VALUES (?, ?, ?, ?);";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(follow.follower_id, follow.target_id, follow.status,
                           follow.uri));
    return db->execute(std::move(stmt));
}

mw::E<void> Database::updateFollowStatus(int64_t follower_id, int64_t target_id,
                                         int status)
{
    const char* sql = "UPDATE follows SET status = ? WHERE follower_id = ? "
                      "AND target_id = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(status, follower_id, target_id));
    return db->execute(std::move(stmt));
}

mw::E<std::optional<Follow>> Database::getFollow(int64_t follower_id,
                                                 int64_t target_id)
{
    const char* sql = "SELECT follower_id, target_id, status, uri "
                      "FROM follows WHERE follower_id = ? AND target_id = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(follower_id, target_id));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, int64_t, int, std::string>(
                                    std::move(stmt))));
    if(rows.empty())
    {
        return std::nullopt;
    }
    Follow f;
    f.follower_id = std::get<0>(rows[0]);
    f.target_id = std::get<1>(rows[0]);
    f.status = std::get<2>(rows[0]);
    f.uri = std::get<3>(rows[0]);
    return f;
}

mw::E<std::vector<User>> Database::getFollowers(int64_t target_id)
{
    const char* sql =
        "SELECT u.id, u.username, u.display_name, u.bio, "
        "u.email, u.uri, u.public_key, u.private_key, u.host, "
        "u.created_at, u.avatar_path, u.oidc_subject, "
        "u.inbox, u.shared_inbox, u.outbox, u.followers, u.following "
        "FROM follows f JOIN users u ON f.follower_id = u.id "
        "WHERE f.target_id = ? AND f.status = 1;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(target_id));

    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, std::string, std::string,
                  std::optional<std::string>, std::string, std::string,
                  std::optional<std::string>, std::optional<std::string>,
                  int64_t, std::optional<std::string>,
                  std::optional<std::string>, std::optional<std::string>,
                  std::optional<std::string>, std::optional<std::string>,
                  std::optional<std::string>, std::optional<std::string>>(
            std::move(stmt))));

    std::vector<User> users;
    for(const auto& row : rows)
    {
        users.push_back(rowToUser(row));
    }
    return users;
}

mw::E<int64_t> Database::createMedia(const Media& media)
{
    const char* sql = "INSERT INTO media (hash, filename, mime_type, "
                      "uploader_id) VALUES (?, ?, ?, ?);";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(media.hash, media.filename, media.mime_type,
                           media.uploader_id));
    DO_OR_RETURN(db->execute(std::move(stmt)));
    return db->lastInsertRowID();
}

mw::E<std::optional<Media>> Database::getMediaByHash(const std::string& hash)
{
    const char* sql = "SELECT id, hash, filename, mime_type, uploader_id "
                      "FROM media WHERE hash = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(hash));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, std::string, std::string, int64_t>(
            std::move(stmt))));
    if(rows.empty())
    {
        return std::nullopt;
    }
    Media m;
    m.id = std::get<0>(rows[0]);
    m.hash = std::get<1>(rows[0]);
    m.filename = std::get<2>(rows[0]);
    m.mime_type = std::get<3>(rows[0]);
    m.uploader_id = std::get<4>(rows[0]);
    return m;
}

mw::E<int64_t> Database::enqueueJob(const Job& job)
{
    const char* sql = "INSERT INTO jobs (type, payload, attempts, "
                      "next_try, status) VALUES (?, ?, ?, ?, ?);";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(job.type, job.payload, job.attempts, job.next_try,
                           job.status));
    DO_OR_RETURN(db->execute(std::move(stmt)));
    return db->lastInsertRowID();
}

mw::E<std::vector<Job>> Database::getPendingJobs(int limit)
{
    const char* sql = "SELECT id, type, payload, attempts, next_try, status "
                      "FROM jobs WHERE status = 0 AND next_try <= ? LIMIT ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(mw::timeToSeconds(mw::Clock::now()), limit));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, std::string, int, int64_t, int>(
            std::move(stmt))));

    std::vector<Job> jobs;
    for(const auto& row : rows)
    {
        Job j;
        j.id = std::get<0>(row);
        j.type = std::get<1>(row);
        j.payload = std::get<2>(row);
        j.attempts = std::get<3>(row);
        j.next_try = std::get<4>(row);
        j.status = std::get<5>(row);
        jobs.push_back(j);
    }
    return jobs;
}

mw::E<void> Database::updateJob(int64_t id, int status, int attempts,
                                int64_t next_try)
{
    const char* sql = "UPDATE jobs SET status = ?, attempts = ?, "
                      "next_try = ? WHERE id = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(status, attempts, next_try, id));
    return db->execute(std::move(stmt));
}

mw::E<void> Database::deleteJob(int64_t id)
{
    ASSIGN_OR_RETURN(auto stmt,
                     db->statementFromStr("DELETE FROM jobs WHERE id = ?;"));
    DO_OR_RETURN(stmt.bind(id));
    return db->execute(std::move(stmt));
}

mw::E<void> Database::createSession(const Session& session)
{
    const char* sql =
        "INSERT INTO sessions (token, user_id, expires_at, csrf_token) "
        "VALUES (?, ?, ?, ?);";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(session.token, session.user_id, session.expires_at,
                           session.csrf_token));
    return db->execute(std::move(stmt));
}

mw::E<std::optional<Session>> Database::getSession(const std::string& token)
{
    const char* sql =
        "SELECT token, user_id, expires_at, csrf_token FROM sessions "
        "WHERE token = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(token));
    ASSIGN_OR_RETURN(auto rows,
                     (db->eval<std::string, int64_t, int64_t, std::string>(
                         std::move(stmt))));
    if(rows.empty())
    {
        return std::nullopt;
    }
    Session s;
    s.token = std::get<0>(rows[0]);
    s.user_id = std::get<1>(rows[0]);
    s.expires_at = std::get<2>(rows[0]);
    s.csrf_token = std::get<3>(rows[0]);
    return s;
}

mw::E<void> Database::deleteSession(const std::string& token)
{
    const char* sql = "DELETE FROM sessions WHERE token = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(token));
    return db->execute(std::move(stmt));
}

mw::E<std::optional<std::string>>
Database::getSystemConfig(const std::string& key)
{
    const char* sql = "SELECT value FROM system_config WHERE key = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(key));
    ASSIGN_OR_RETURN(auto rows, db->eval<std::string>(std::move(stmt)));

    if(rows.empty())
    {
        return std::nullopt;
    }
    return std::get<0>(rows[0]);
}

mw::E<void> Database::setSystemConfig(const std::string& key,
                                      const std::string& value)
{
    const char* sql =
        "INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?);";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(key, value));
    return db->execute(std::move(stmt));
}
