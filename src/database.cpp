#include "database.hpp"
#include <mw/error.hpp>
#include <mw/utils.hpp>
#include <spdlog/spdlog.h>
#include <iostream>

namespace mw::internal
{
E<void> bindOne(const SQLiteStatement& sql, int i, const std::string& x);
E<void> bindOne(const SQLiteStatement& sql, int i, int x);
E<void> bindOne(const SQLiteStatement& sql, int i, int64_t x);
E<void> bindOne(const SQLiteStatement& sql, int i, std::nullopt_t _);
}

Database::Database(const std::string& path)
    : db_path(path)
{
}

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
                oidc_subject TEXT UNIQUE
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
                FOREIGN KEY(user_id) REFERENCES users(id)
            );)",

            "PRAGMA user_version = 1;"
        };

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

mw::E<int64_t> Database::createUser(const User& user)
{
    const char* sql = "INSERT INTO users (username, display_name, bio, "
                      "email, uri, public_key, private_key, host, "
                      "created_at, avatar_path, oidc_subject) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));

    DO_OR_RETURN(mw::internal::bindOne(stmt, 1, user.username));
    DO_OR_RETURN(mw::internal::bindOne(stmt, 2, user.display_name));
    DO_OR_RETURN(mw::internal::bindOne(stmt, 3, user.bio));
    if(user.email) { DO_OR_RETURN(mw::internal::bindOne(stmt, 4, *user.email)); } else { DO_OR_RETURN(mw::internal::bindOne(stmt, 4, std::nullopt)); }
    DO_OR_RETURN(mw::internal::bindOne(stmt, 5, user.uri));
    DO_OR_RETURN(mw::internal::bindOne(stmt, 6, user.public_key));
    if(user.private_key) { DO_OR_RETURN(mw::internal::bindOne(stmt, 7, *user.private_key)); } else { DO_OR_RETURN(mw::internal::bindOne(stmt, 7, std::nullopt)); }
    if(user.host) { DO_OR_RETURN(mw::internal::bindOne(stmt, 8, *user.host)); } else { DO_OR_RETURN(mw::internal::bindOne(stmt, 8, std::nullopt)); }
    DO_OR_RETURN(mw::internal::bindOne(stmt, 9, user.created_at));
    if(user.avatar_path) { DO_OR_RETURN(mw::internal::bindOne(stmt, 10, *user.avatar_path)); } else { DO_OR_RETURN(mw::internal::bindOne(stmt, 10, std::nullopt)); }
    if(user.oidc_subject) { DO_OR_RETURN(mw::internal::bindOne(stmt, 11, *user.oidc_subject)); } else { DO_OR_RETURN(mw::internal::bindOne(stmt, 11, std::nullopt)); }

    DO_OR_RETURN(db->execute(std::move(stmt)));
    return db->lastInsertRowID();
}

using UserTuple = std::tuple<int64_t, std::string, std::string, std::string,
                             std::string, std::string, std::string,
                             std::string, std::string, int64_t, std::string, std::string>;

static User rowToUser(const UserTuple& row)
{
    User u;
    u.id = std::get<0>(row);
    u.username = std::get<1>(row);
    u.display_name = std::get<2>(row);
    u.bio = std::get<3>(row);
    if(!std::get<4>(row).empty()) u.email = std::get<4>(row);
    u.uri = std::get<5>(row);
    u.public_key = std::get<6>(row);
    if(!std::get<7>(row).empty()) u.private_key = std::get<7>(row);
    if(!std::get<8>(row).empty()) u.host = std::get<8>(row);
    u.created_at = std::get<9>(row);
    if(!std::get<10>(row).empty()) u.avatar_path = std::get<10>(row);
    if(!std::get<11>(row).empty()) u.oidc_subject = std::get<11>(row);
    return u;
}

mw::E<std::optional<User>> Database::getUserById(int64_t id)
{
    const char* sql = "SELECT id, username, display_name, bio, email, uri, "
                      "public_key, private_key, host, created_at, "
                      "avatar_path, oidc_subject FROM users WHERE id = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(id));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
                                          std::string, std::string, std::string,
                                          std::string, std::string, std::string,
                                          int64_t, std::string, std::string>(
                                    std::move(stmt))));

    if(rows.empty()) return std::nullopt;
    return rowToUser(rows[0]);
}

mw::E<std::optional<User>> Database::getUserByUsername(const std::string& name)
{
    const char* sql = "SELECT id, username, display_name, bio, email, uri, "
                      "public_key, private_key, host, created_at, "
                      "avatar_path, oidc_subject FROM users WHERE username = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(name));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
                                          std::string, std::string, std::string,
                                          std::string, std::string, std::string,
                                          int64_t, std::string, std::string>(
                                    std::move(stmt))));
    if(rows.empty()) return std::nullopt;
    return rowToUser(rows[0]);
}

mw::E<std::optional<User>> Database::getUserByUri(const std::string& uri)
{
    const char* sql = "SELECT id, username, display_name, bio, email, uri, "
                      "public_key, private_key, host, created_at, "
                      "avatar_path, oidc_subject FROM users WHERE uri = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(uri));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
                                          std::string, std::string, std::string,
                                          std::string, std::string, std::string,
                                          int64_t, std::string, std::string>(
                                    std::move(stmt))));
    if(rows.empty()) return std::nullopt;
    return rowToUser(rows[0]);
}

mw::E<std::optional<User>> Database::getUserByOidcSubject(const std::string& sub)
{
    const char* sql = "SELECT id, username, display_name, bio, email, uri, "
                      "public_key, private_key, host, created_at, "
                      "avatar_path, oidc_subject FROM users WHERE oidc_subject = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(sub));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
                                          std::string, std::string, std::string,
                                          std::string, std::string, std::string,
                                          int64_t, std::string, std::string>(
                                    std::move(stmt))));
    if(rows.empty()) return std::nullopt;
    return rowToUser(rows[0]);
}

mw::E<int64_t> Database::createPost(const Post& post)
{
    const char* sql = "INSERT INTO posts (uri, author_id, content_html, "
                      "content_source, in_reply_to_uri, visibility, "
                      "created_at, is_local) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));

    DO_OR_RETURN(mw::internal::bindOne(stmt, 1, post.uri));
    DO_OR_RETURN(mw::internal::bindOne(stmt, 2, post.author_id));
    DO_OR_RETURN(mw::internal::bindOne(stmt, 3, post.content_html));
    DO_OR_RETURN(mw::internal::bindOne(stmt, 4, post.content_source));
    if(post.in_reply_to_uri) { DO_OR_RETURN(mw::internal::bindOne(stmt, 5, *post.in_reply_to_uri)); } else { DO_OR_RETURN(mw::internal::bindOne(stmt, 5, std::nullopt)); }
    DO_OR_RETURN(mw::internal::bindOne(stmt, 6, static_cast<int>(post.visibility)));
    DO_OR_RETURN(mw::internal::bindOne(stmt, 7, post.created_at));
    DO_OR_RETURN(mw::internal::bindOne(stmt, 8, post.is_local ? 1 : 0));

    DO_OR_RETURN(db->execute(std::move(stmt)));
    return db->lastInsertRowID();
}

using PostTuple = std::tuple<int64_t, std::string, int64_t, std::string,
                             std::string, std::string, int, int64_t, int>;

static Post rowToPost(const PostTuple& row)
{
    Post p;
    p.id = std::get<0>(row);
    p.uri = std::get<1>(row);
    p.author_id = std::get<2>(row);
    p.content_html = std::get<3>(row);
    p.content_source = std::get<4>(row);
    if(!std::get<5>(row).empty()) p.in_reply_to_uri = std::get<5>(row);
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
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, int64_t,
                                          std::string, std::string, std::string,
                                          int, int64_t, int>(std::move(stmt))));
    if(rows.empty()) return std::nullopt;
    return rowToPost(rows[0]);
}

mw::E<std::optional<Post>> Database::getPostByUri(const std::string& uri)
{
    const char* sql = "SELECT id, uri, author_id, content_html, "
                      "content_source, in_reply_to_uri, visibility, "
                      "created_at, is_local FROM posts WHERE uri = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(uri));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, int64_t,
                                          std::string, std::string, std::string,
                                          int, int64_t, int>(std::move(stmt))));
    if(rows.empty()) return std::nullopt;
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
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, int64_t,
                                          std::string, std::string, std::string,
                                          int, int64_t, int>(std::move(stmt))));

    std::vector<Post> posts;
    for(const auto& row : rows) posts.push_back(rowToPost(row));
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
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, int64_t,
                                          std::string, std::string, std::string,
                                          int, int64_t, int>(std::move(stmt))));

    std::vector<Post> posts;
    for(const auto& row : rows) posts.push_back(rowToPost(row));
    return posts;
}

mw::E<void> Database::createFollow(const Follow& follow)
{
    const char* sql = "INSERT OR REPLACE INTO follows (follower_id, "
                      "target_id, status, uri) VALUES (?, ?, ?, ?);";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(follow.follower_id, follow.target_id,
                           follow.status, follow.uri));
    return db->execute(std::move(stmt));
}

mw::E<void> Database::updateFollowStatus(int64_t follower_id,
                                         int64_t target_id, int status)
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
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, int64_t, int,
                                          std::string>(std::move(stmt))));
    if(rows.empty()) return std::nullopt;
    Follow f;
    f.follower_id = std::get<0>(rows[0]);
    f.target_id = std::get<1>(rows[0]);
    f.status = std::get<2>(rows[0]);
    f.uri = std::get<3>(rows[0]);
    return f;
}

mw::E<int64_t> Database::enqueueJob(const Job& job)
{
    const char* sql = "INSERT INTO jobs (type, payload, attempts, "
                      "next_try, status) VALUES (?, ?, ?, ?, ?);";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(job.type, job.payload, job.attempts,
                           job.next_try, job.status));
    DO_OR_RETURN(db->execute(std::move(stmt)));
    return db->lastInsertRowID();
}

mw::E<std::vector<Job>> Database::getPendingJobs(int limit)
{
    const char* sql = "SELECT id, type, payload, attempts, next_try, status "
                      "FROM jobs WHERE status = 0 AND next_try <= ? LIMIT ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(mw::timeToSeconds(mw::Clock::now()), limit));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
                                          int, int64_t, int>(std::move(stmt))));

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
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(
                                    "DELETE FROM jobs WHERE id = ?;"));
    DO_OR_RETURN(stmt.bind(id));
    return db->execute(std::move(stmt));
}

mw::E<void> Database::createSession(const Session& session)
{
    const char* sql = "INSERT INTO sessions (token, user_id, expires_at) "
                      "VALUES (?, ?, ?);";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(session.token, session.user_id, session.expires_at));
    return db->execute(std::move(stmt));
}

mw::E<std::optional<Session>> Database::getSession(const std::string& token)
{
    const char* sql = "SELECT token, user_id, expires_at FROM sessions "
                      "WHERE token = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(token));
    ASSIGN_OR_RETURN(auto rows, (db->eval<std::string, int64_t,
                                          int64_t>(std::move(stmt))));
    if(rows.empty()) return std::nullopt;
    Session s;
    s.token = std::get<0>(rows[0]);
    s.user_id = std::get<1>(rows[0]);
    s.expires_at = std::get<2>(rows[0]);
    return s;
}

mw::E<void> Database::deleteSession(const std::string& token)
{
    const char* sql = "DELETE FROM sessions WHERE token = ?;";
    ASSIGN_OR_RETURN(auto stmt, db->statementFromStr(sql));
    DO_OR_RETURN(stmt.bind(token));
    return db->execute(std::move(stmt));
}
