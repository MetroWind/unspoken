#include <algorithm>
#include <cctype>
#include <cstdint>
#include <format>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <mw/database.hpp>
#include <mw/error.hpp>
#include <mw/utils.hpp>

#include "data.hpp"
#include "structs.hpp"

namespace unspoken
{

namespace
{

// Column list shared by every post SELECT, in a fixed order.
constexpr const char* POST_COLS =
    "id, uri, local_author_id, remote_author_id, content_html, "
    "content_source, summary, sensitive, visibility, in_reply_to_uri, "
    "created_at, published";

using PostRow = std::tuple<
    int64_t, std::string, std::optional<int64_t>, std::optional<int64_t>,
    std::string, std::optional<std::string>, std::optional<std::string>,
    int64_t, std::string, std::optional<std::string>, int64_t,
    std::optional<std::string>>;

mw::E<Post> rowToPost(const PostRow& row)
{
    Post p;
    p.id = std::get<0>(row);
    p.uri = std::get<1>(row);
    p.local_author_id = std::get<2>(row);
    p.remote_author_id = std::get<3>(row);
    p.content_html = std::get<4>(row);
    p.content_source = std::get<5>(row);
    p.summary = std::get<6>(row);
    p.sensitive = std::get<7>(row) != 0;
    auto vis = visibilityFromStr(std::get<8>(row));
    if(!vis.has_value())
    {
        return std::unexpected(mw::runtimeError(std::format(
            "Invalid visibility in DB: {}", std::get<8>(row))));
    }
    p.visibility = *vis;
    p.in_reply_to_uri = std::get<9>(row);
    p.created_at = std::get<10>(row);
    p.published = std::get<11>(row);
    return p;
}

int64_t now()
{
    return mw::timeToSeconds(mw::Clock::now());
}

// Bind a single int64 value at a 1-based positional placeholder. Used
// where the number of placeholders varies with the cursor, so a single
// variadic bind<>() call won't do.
mw::E<void> internalBindAt(const mw::SQLiteStatement& st, int i, int64_t v)
{
    return mw::internal::bindOne(st, i, v);
}

} // namespace

bool isRetryableSqlError(const mw::Error& e)
{
    const std::string& msg = mw::errorMsg(e);
    std::string lower;
    lower.reserve(msg.size());
    for(char c : msg)
    {
        lower.push_back(static_cast<char>(std::tolower(
            static_cast<unsigned char>(c))));
    }
    return lower.find("busy") != std::string::npos ||
           lower.find("locked") != std::string::npos;
}

mw::E<void> withWriteRetry(const std::function<mw::E<void>()>& txn,
                           int max_retries)
{
    int attempt = 0;
    while(true)
    {
        auto result = txn();
        if(result.has_value())
        {
            return {};
        }
        if(attempt >= max_retries || !isRetryableSqlError(result.error()))
        {
            return std::unexpected(result.error());
        }
        // Short linear backoff before retrying.
        std::this_thread::sleep_for(
            std::chrono::milliseconds(5 * (attempt + 1)));
        ++attempt;
    }
}

// ─── Connection setup and schema ───────────────────────────────────

mw::E<void> DataSourceSQLite::createSchema(mw::SQLite& db)
{
    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " username TEXT NOT NULL UNIQUE,"
        " display_name TEXT NOT NULL DEFAULT '',"
        " bio TEXT NOT NULL DEFAULT '',"
        " oidc_iss TEXT NOT NULL,"
        " oidc_sub TEXT NOT NULL,"
        " private_key_pem TEXT NOT NULL,"
        " public_key_pem TEXT NOT NULL,"
        " created_at INTEGER NOT NULL);"));
    DO_OR_RETURN(db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oidc "
        "ON users(oidc_iss, oidc_sub);"));

    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS system_actor ("
        " id INTEGER PRIMARY KEY CHECK (id = 1),"
        " private_key_pem TEXT NOT NULL,"
        " public_key_pem TEXT NOT NULL,"
        " created_at INTEGER NOT NULL);"));

    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS remote_actors ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " uri TEXT NOT NULL UNIQUE,"
        " username TEXT NOT NULL,"
        " domain TEXT NOT NULL,"
        " display_name TEXT NOT NULL DEFAULT '',"
        " inbox TEXT NOT NULL,"
        " shared_inbox TEXT,"
        " public_key_pem TEXT NOT NULL,"
        " public_key_id TEXT NOT NULL,"
        " actor_json TEXT NOT NULL,"
        " fetched_at INTEGER NOT NULL);"));
    DO_OR_RETURN(db.execute(
        "CREATE INDEX IF NOT EXISTS idx_remote_actors_domain "
        "ON remote_actors(domain);"));

    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS posts ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " uri TEXT NOT NULL UNIQUE,"
        " local_author_id INTEGER,"
        " remote_author_id INTEGER,"
        " content_html TEXT NOT NULL,"
        " content_source TEXT,"
        " summary TEXT,"
        " sensitive INTEGER NOT NULL DEFAULT 0,"
        " visibility TEXT NOT NULL,"
        " in_reply_to_uri TEXT,"
        " created_at INTEGER NOT NULL,"
        " published TEXT);"));
    DO_OR_RETURN(db.execute(
        "CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at);"));
    DO_OR_RETURN(db.execute(
        "CREATE INDEX IF NOT EXISTS idx_posts_inreplyto "
        "ON posts(in_reply_to_uri);"));
    DO_OR_RETURN(db.execute(
        "CREATE INDEX IF NOT EXISTS idx_posts_local_author "
        "ON posts(local_author_id);"));

    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS post_recipients ("
        " post_id INTEGER NOT NULL,"
        " recipient_uri TEXT NOT NULL,"
        " field TEXT NOT NULL);"));
    DO_OR_RETURN(db.execute(
        "CREATE INDEX IF NOT EXISTS idx_post_recipients_post "
        "ON post_recipients(post_id);"));

    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS attachments ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " post_id INTEGER,"
        " sha256 TEXT NOT NULL,"
        " media_type TEXT NOT NULL,"
        " original_name TEXT NOT NULL,"
        " is_image INTEGER NOT NULL DEFAULT 0,"
        " sensitive INTEGER NOT NULL DEFAULT 0,"
        " remote_url TEXT);"));
    DO_OR_RETURN(db.execute(
        "CREATE INDEX IF NOT EXISTS idx_attachments_post "
        "ON attachments(post_id);"));

    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS follows ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " follower_uri TEXT NOT NULL,"
        " followee_uri TEXT NOT NULL,"
        " state TEXT NOT NULL,"
        " follow_activity_uri TEXT,"
        " created_at INTEGER NOT NULL);"));
    DO_OR_RETURN(db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_follows_pair "
        "ON follows(follower_uri, followee_uri);"));

    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS likes ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " actor_uri TEXT NOT NULL,"
        " post_uri TEXT NOT NULL,"
        " activity_uri TEXT,"
        " created_at INTEGER NOT NULL);"));
    DO_OR_RETURN(db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_likes_pair "
        "ON likes(actor_uri, post_uri);"));

    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS boosts ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " actor_uri TEXT NOT NULL,"
        " post_uri TEXT NOT NULL,"
        " activity_uri TEXT,"
        " created_at INTEGER NOT NULL);"));
    DO_OR_RETURN(db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_boosts_pair "
        "ON boosts(actor_uri, post_uri);"));

    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS reactions ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " actor_uri TEXT NOT NULL,"
        " post_uri TEXT NOT NULL,"
        " emoji TEXT NOT NULL,"
        " activity_uri TEXT,"
        " created_at INTEGER NOT NULL);"));
    DO_OR_RETURN(db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_reactions_triple "
        "ON reactions(actor_uri, post_uri, emoji);"));

    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS bookmarks ("
        " user_id INTEGER NOT NULL,"
        " post_id INTEGER NOT NULL,"
        " created_at INTEGER NOT NULL,"
        " PRIMARY KEY (user_id, post_id));"));

    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS sessions ("
        " token TEXT PRIMARY KEY,"
        " user_id INTEGER NOT NULL,"
        " created_at INTEGER NOT NULL,"
        " expires_at INTEGER NOT NULL);"));

    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS pending_logins ("
        " state TEXT PRIMARY KEY,"
        " nonce TEXT NOT NULL,"
        " created_at INTEGER NOT NULL);"));

    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS seen_activities ("
        " activity_uri TEXT PRIMARY KEY,"
        " seen_at INTEGER NOT NULL);"));

    DO_OR_RETURN(db.execute(
        "CREATE TABLE IF NOT EXISTS jobs ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " kind TEXT NOT NULL,"
        " payload_json TEXT NOT NULL,"
        " state TEXT NOT NULL,"
        " attempts INTEGER NOT NULL DEFAULT 0,"
        " run_after INTEGER NOT NULL,"
        " last_error TEXT,"
        " created_at INTEGER NOT NULL);"));
    DO_OR_RETURN(db.execute(
        "CREATE INDEX IF NOT EXISTS idx_jobs_runnable "
        "ON jobs(state, run_after);"));

    return {};
}

mw::E<std::unique_ptr<DataSourceSQLite>>
DataSourceSQLite::fromFile(const std::string& db_file, int busy_timeout_ms)
{
    // busy_timeout (block-and-wait on a locked DB rather than failing
    // immediately) is set on connect by libmw (design §7.2).
    ASSIGN_OR_RETURN(auto conn,
                     mw::SQLite::connectFile(db_file, busy_timeout_ms));
    // Enable WAL so readers and the single writer don't block each other.
    // In-memory databases don't support WAL; ignore the result there.
    (void)conn->execute("PRAGMA journal_mode=WAL;");
    DO_OR_RETURN(conn->execute("PRAGMA foreign_keys=ON;"));

    auto data_source = std::make_unique<DataSourceSQLite>(std::move(conn));

    ASSIGN_OR_RETURN(int64_t version, data_source->getSchemaVersion());
    // user_version dispatch: 0 = fresh DB. Future migrations slot in as
    // additional cases (design §7.1).
    switch(version)
    {
    case 0:
        DO_OR_RETURN(createSchema(*data_source->db));
        DO_OR_RETURN(data_source->setSchemaVersion(1));
        break;
    case 1:
        break;
    default:
        return std::unexpected(mw::runtimeError(std::format(
            "Database schema version {} is newer than supported (1)",
            version)));
    }
    return data_source;
}

mw::E<std::unique_ptr<DataSourceSQLite>> DataSourceSQLite::newFromMemory()
{
    return fromFile(":memory:");
}

mw::E<int64_t> DataSourceSQLite::getSchemaVersion() const
{
    return db->evalToValue<int64_t>("PRAGMA user_version;");
}

mw::E<void> DataSourceSQLite::setSchemaVersion(int64_t v) const
{
    // PRAGMA does not accept bound parameters.
    return db->execute(std::format("PRAGMA user_version = {};", v));
}

// ─── Users ─────────────────────────────────────────────────────────

mw::E<User> DataSourceSQLite::createUser(const NewUser& nu) const
{
    int64_t created = now();
    auto insert = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "INSERT INTO users (username, display_name, bio, oidc_iss, "
            "oidc_sub, private_key_pem, public_key_pem, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?);"));
        DO_OR_RETURN((st.bind<std::string, std::string, std::string,
                      std::string, std::string, std::string, std::string,
                      int64_t>(
            nu.username, nu.display_name, nu.bio, nu.oidc_iss, nu.oidc_sub,
            nu.private_key_pem, nu.public_key_pem, created)));
        return db->execute(std::move(st));
    };
    DO_OR_RETURN(withWriteRetry(insert));

    User u;
    u.id = db->lastInsertRowID();
    u.username = nu.username;
    u.display_name = nu.display_name;
    u.bio = nu.bio;
    u.oidc_iss = nu.oidc_iss;
    u.oidc_sub = nu.oidc_sub;
    u.private_key_pem = nu.private_key_pem;
    u.public_key_pem = nu.public_key_pem;
    u.created_at = created;
    return u;
}

namespace
{

using UserRow = std::tuple<int64_t, std::string, std::string, std::string,
                           std::string, std::string, std::string, std::string,
                           int64_t>;

User rowToUser(const UserRow& row)
{
    User u;
    u.id = std::get<0>(row);
    u.username = std::get<1>(row);
    u.display_name = std::get<2>(row);
    u.bio = std::get<3>(row);
    u.oidc_iss = std::get<4>(row);
    u.oidc_sub = std::get<5>(row);
    u.private_key_pem = std::get<6>(row);
    u.public_key_pem = std::get<7>(row);
    u.created_at = std::get<8>(row);
    return u;
}

constexpr const char* USER_COLS =
    "id, username, display_name, bio, oidc_iss, oidc_sub, private_key_pem, "
    "public_key_pem, created_at";

} // namespace

mw::E<std::optional<User>> DataSourceSQLite::getUserById(int64_t id) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(std::format(
        "SELECT {} FROM users WHERE id = ?;", USER_COLS)));
    DO_OR_RETURN(st.bind<int64_t>(id));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
        std::string, std::string, std::string, std::string, std::string,
        int64_t>(std::move(st))));
    if(rows.empty()) return std::optional<User>{};
    return std::optional<User>{rowToUser(rows[0])};
}

mw::E<std::optional<User>>
DataSourceSQLite::getUserByUsername(std::string_view username) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(std::format(
        "SELECT {} FROM users WHERE username = ?;", USER_COLS)));
    DO_OR_RETURN(st.bind<std::string>(std::string(username)));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
        std::string, std::string, std::string, std::string, std::string,
        int64_t>(std::move(st))));
    if(rows.empty()) return std::optional<User>{};
    return std::optional<User>{rowToUser(rows[0])};
}

mw::E<std::optional<User>>
DataSourceSQLite::getUserByOidcSub(std::string_view iss,
                                   std::string_view sub) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(std::format(
        "SELECT {} FROM users WHERE oidc_iss = ? AND oidc_sub = ?;",
        USER_COLS)));
    DO_OR_RETURN((st.bind<std::string, std::string>(
        std::string(iss), std::string(sub))));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
        std::string, std::string, std::string, std::string, std::string,
        int64_t>(std::move(st))));
    if(rows.empty()) return std::optional<User>{};
    return std::optional<User>{rowToUser(rows[0])};
}

mw::E<void>
DataSourceSQLite::updateUserProfile(int64_t id, std::string_view display_name,
                                    std::string_view bio) const
{
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "UPDATE users SET display_name = ?, bio = ? WHERE id = ?;"));
        DO_OR_RETURN((st.bind<std::string, std::string, int64_t>(
            std::string(display_name), std::string(bio), id)));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<std::vector<User>>
DataSourceSQLite::searchUsers(std::string_view query, int limit) const
{
    // Case-insensitive substring match on username or display_name. The
    // LIKE wildcards are escaped so a query containing %/_ is literal.
    std::string escaped;
    for(char c : query)
    {
        if(c == '%' || c == '_' || c == '\\') escaped.push_back('\\');
        escaped.push_back(c);
    }
    std::string pattern = "%" + escaped + "%";
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(std::format(
        "SELECT {} FROM users WHERE username LIKE ? ESCAPE '\\' "
        "OR display_name LIKE ? ESCAPE '\\' ORDER BY username ASC LIMIT ?;",
        USER_COLS)));
    DO_OR_RETURN((st.bind<std::string, std::string, int64_t>(
        pattern, pattern, static_cast<int64_t>(limit))));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
        std::string, std::string, std::string, std::string, std::string,
        int64_t>(std::move(st))));
    std::vector<User> out;
    out.reserve(rows.size());
    for(const auto& r : rows) out.push_back(rowToUser(r));
    return out;
}

// ─── System actor ────────────────────────────────────────────────────

mw::E<std::optional<SystemActor>> DataSourceSQLite::getSystemActor() const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(
        "SELECT private_key_pem, public_key_pem, created_at "
        "FROM system_actor WHERE id = 1;"));
    ASSIGN_OR_RETURN(auto rows,
                     (db->eval<std::string, std::string, int64_t>(
                         std::move(st))));
    if(rows.empty()) return std::optional<SystemActor>{};
    SystemActor actor;
    actor.private_key_pem = std::get<0>(rows[0]);
    actor.public_key_pem = std::get<1>(rows[0]);
    actor.created_at = std::get<2>(rows[0]);
    return actor;
}

mw::E<void>
DataSourceSQLite::setSystemActor(std::string_view private_key_pem,
                                 std::string_view public_key_pem) const
{
    int64_t created = now();
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "INSERT INTO system_actor "
            "(id, private_key_pem, public_key_pem, created_at) "
            "VALUES (1, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            "private_key_pem = excluded.private_key_pem, "
            "public_key_pem = excluded.public_key_pem;"));
        DO_OR_RETURN((st.bind<std::string, std::string, int64_t>(
            std::string(private_key_pem), std::string(public_key_pem),
            created)));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

// ─── Remote actors ─────────────────────────────────────────────────

mw::E<RemoteActor>
DataSourceSQLite::upsertRemoteActor(const RemoteActor& a) const
{
    int64_t fetched = a.fetched_at != 0 ? a.fetched_at : now();
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "INSERT INTO remote_actors (uri, username, domain, display_name, "
            "inbox, shared_inbox, public_key_pem, public_key_id, actor_json, "
            "fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(uri) DO UPDATE SET username=excluded.username, "
            "domain=excluded.domain, display_name=excluded.display_name, "
            "inbox=excluded.inbox, shared_inbox=excluded.shared_inbox, "
            "public_key_pem=excluded.public_key_pem, "
            "public_key_id=excluded.public_key_id, "
            "actor_json=excluded.actor_json, fetched_at=excluded.fetched_at;"));
        DO_OR_RETURN((st.bind<std::string, std::string, std::string,
            std::string, std::string, std::optional<std::string>, std::string,
            std::string, std::string, int64_t>(
            a.uri, a.username, a.domain, a.display_name, a.inbox,
            a.shared_inbox, a.public_key_pem, a.public_key_id, a.actor_json,
            fetched)));
        return db->execute(std::move(st));
    };
    DO_OR_RETURN(withWriteRetry(txn));

    ASSIGN_OR_RETURN(auto stored, getRemoteActorByUri(a.uri));
    if(!stored.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor vanished immediately after upsert"));
    }
    return *stored;
}

mw::E<std::optional<RemoteActor>>
DataSourceSQLite::getRemoteActorByUri(std::string_view uri) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(
        "SELECT id, uri, username, domain, display_name, inbox, shared_inbox, "
        "public_key_pem, public_key_id, actor_json, fetched_at "
        "FROM remote_actors WHERE uri = ?;"));
    DO_OR_RETURN(st.bind<std::string>(std::string(uri)));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
        std::string, std::string, std::string, std::optional<std::string>,
        std::string, std::string, std::string, int64_t>(std::move(st))));
    if(rows.empty()) return std::optional<RemoteActor>{};
    const auto& r = rows[0];
    RemoteActor a;
    a.id = std::get<0>(r);
    a.uri = std::get<1>(r);
    a.username = std::get<2>(r);
    a.domain = std::get<3>(r);
    a.display_name = std::get<4>(r);
    a.inbox = std::get<5>(r);
    a.shared_inbox = std::get<6>(r);
    a.public_key_pem = std::get<7>(r);
    a.public_key_id = std::get<8>(r);
    a.actor_json = std::get<9>(r);
    a.fetched_at = std::get<10>(r);
    return std::optional<RemoteActor>{std::move(a)};
}

// ─── Posts ─────────────────────────────────────────────────────────

mw::E<Post>
DataSourceSQLite::insertPost(const NewPost& np,
                             const std::vector<PostRecipient>& recipients,
                             std::string_view local_uri_prefix) const
{
    int64_t created = now();
    int64_t new_id = 0;
    std::string final_uri;

    auto txn = [&]() -> mw::E<void> {
        DO_OR_RETURN(db->execute("BEGIN;"));
        auto rollback = [&](mw::Error e) -> mw::E<void> {
            (void)db->execute("ROLLBACK;");
            return std::unexpected(std::move(e));
        };

        // For local posts the URI embeds the not-yet-known id, so insert
        // with a guaranteed-unique random placeholder, then update.
        std::string insert_uri = np.uri.value_or("");
        bool is_local = !np.uri.has_value();
        {
            std::string sql = std::format(
                "INSERT INTO posts (uri, local_author_id, remote_author_id, "
                "content_html, content_source, summary, sensitive, "
                "visibility, in_reply_to_uri, created_at, published) VALUES "
                "({}, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                is_local ? "lower(hex(randomblob(16)))" : "?");
            auto st_e = db->statementFromStr(sql);
            if(!st_e.has_value()) return rollback(st_e.error());
            auto& st = *st_e;
            // Bind starting at the first '?'. For local the uri is filled
            // by SQL, so the first bound param is local_author_id.
            mw::E<void> b = is_local
                ? st.bind<std::optional<int64_t>, std::optional<int64_t>,
                          std::string, std::optional<std::string>,
                          std::optional<std::string>, int64_t, std::string,
                          std::optional<std::string>, int64_t,
                          std::optional<std::string>>(
                      np.local_author_id, np.remote_author_id, np.content_html,
                      np.content_source, np.summary, np.sensitive ? 1 : 0,
                      std::string(visibilityToStr(np.visibility)),
                      np.in_reply_to_uri, created, np.published)
                : st.bind<std::string, std::optional<int64_t>,
                          std::optional<int64_t>, std::string,
                          std::optional<std::string>,
                          std::optional<std::string>, int64_t, std::string,
                          std::optional<std::string>, int64_t,
                          std::optional<std::string>>(
                      insert_uri, np.local_author_id, np.remote_author_id,
                      np.content_html, np.content_source, np.summary,
                      np.sensitive ? 1 : 0,
                      std::string(visibilityToStr(np.visibility)),
                      np.in_reply_to_uri, created, np.published);
            if(!b.has_value()) return rollback(b.error());
            auto ex = db->execute(std::move(st));
            if(!ex.has_value()) return rollback(ex.error());
        }

        new_id = db->lastInsertRowID();
        if(is_local)
        {
            final_uri = std::format("{}{}", local_uri_prefix, new_id);
            auto up_e = db->statementFromStr(
                "UPDATE posts SET uri = ? WHERE id = ?;");
            if(!up_e.has_value()) return rollback(up_e.error());
            auto& up = *up_e;
            auto b = up.bind<std::string, int64_t>(final_uri, new_id);
            if(!b.has_value()) return rollback(b.error());
            auto ex = db->execute(std::move(up));
            if(!ex.has_value()) return rollback(ex.error());
        }
        else
        {
            final_uri = insert_uri;
        }

        for(const auto& rec : recipients)
        {
            auto r_e = db->statementFromStr(
                "INSERT INTO post_recipients (post_id, recipient_uri, field) "
                "VALUES (?, ?, ?);");
            if(!r_e.has_value()) return rollback(r_e.error());
            auto& rst = *r_e;
            auto b = rst.bind<int64_t, std::string, std::string>(
                new_id, rec.recipient_uri, rec.field);
            if(!b.has_value()) return rollback(b.error());
            auto ex = db->execute(std::move(rst));
            if(!ex.has_value()) return rollback(ex.error());
        }

        return db->execute("COMMIT;");
    };
    DO_OR_RETURN(withWriteRetry(txn));

    ASSIGN_OR_RETURN(auto stored, getPostById(new_id));
    if(!stored.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Post vanished immediately after insert"));
    }
    return *stored;
}

mw::E<std::optional<Post>> DataSourceSQLite::getPostById(int64_t id) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(std::format(
        "SELECT {} FROM posts WHERE id = ?;", POST_COLS)));
    DO_OR_RETURN(st.bind<int64_t>(id));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string,
        std::optional<int64_t>, std::optional<int64_t>, std::string,
        std::optional<std::string>, std::optional<std::string>, int64_t,
        std::string, std::optional<std::string>, int64_t,
        std::optional<std::string>>(std::move(st))));
    if(rows.empty()) return std::optional<Post>{};
    ASSIGN_OR_RETURN(Post p, rowToPost(rows[0]));
    return std::optional<Post>{std::move(p)};
}

mw::E<std::optional<Post>>
DataSourceSQLite::getPostByUri(std::string_view uri) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(std::format(
        "SELECT {} FROM posts WHERE uri = ?;", POST_COLS)));
    DO_OR_RETURN(st.bind<std::string>(std::string(uri)));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string,
        std::optional<int64_t>, std::optional<int64_t>, std::string,
        std::optional<std::string>, std::optional<std::string>, int64_t,
        std::string, std::optional<std::string>, int64_t,
        std::optional<std::string>>(std::move(st))));
    if(rows.empty()) return std::optional<Post>{};
    ASSIGN_OR_RETURN(Post p, rowToPost(rows[0]));
    return std::optional<Post>{std::move(p)};
}

mw::E<void> DataSourceSQLite::deletePost(int64_t id) const
{
    auto txn = [&]() -> mw::E<void> {
        DO_OR_RETURN(db->execute("BEGIN;"));
        auto rollback = [&](mw::Error e) -> mw::E<void> {
            (void)db->execute("ROLLBACK;");
            return std::unexpected(std::move(e));
        };
        {
            auto st_e = db->statementFromStr(
                "DELETE FROM post_recipients WHERE post_id = ?;");
            if(!st_e.has_value()) return rollback(st_e.error());
            auto b = st_e->bind<int64_t>(id);
            if(!b.has_value()) return rollback(b.error());
            auto ex = db->execute(std::move(*st_e));
            if(!ex.has_value()) return rollback(ex.error());
        }
        {
            auto st_e = db->statementFromStr(
                "DELETE FROM attachments WHERE post_id = ?;");
            if(!st_e.has_value()) return rollback(st_e.error());
            auto b = st_e->bind<int64_t>(id);
            if(!b.has_value()) return rollback(b.error());
            auto ex = db->execute(std::move(*st_e));
            if(!ex.has_value()) return rollback(ex.error());
        }
        {
            auto st_e = db->statementFromStr("DELETE FROM posts WHERE id = ?;");
            if(!st_e.has_value()) return rollback(st_e.error());
            auto b = st_e->bind<int64_t>(id);
            if(!b.has_value()) return rollback(b.error());
            auto ex = db->execute(std::move(*st_e));
            if(!ex.has_value()) return rollback(ex.error());
        }
        return db->execute("COMMIT;");
    };
    return withWriteRetry(txn);
}

mw::E<std::vector<PostRecipient>>
DataSourceSQLite::getPostRecipients(int64_t post_id) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(
        "SELECT post_id, recipient_uri, field FROM post_recipients "
        "WHERE post_id = ?;"));
    DO_OR_RETURN(st.bind<int64_t>(post_id));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string>(
        std::move(st))));
    std::vector<PostRecipient> out;
    out.reserve(rows.size());
    for(const auto& r : rows)
    {
        out.push_back(PostRecipient{std::get<0>(r), std::get<1>(r),
                                    std::get<2>(r)});
    }
    return out;
}

namespace
{

// Build a cursor-paginated SELECT over posts. `extra_where` is an
// additional predicate (without WHERE/AND), or empty. Returns rows
// newest-first.
std::string buildTimelineSql(const Cursor& c, std::string_view extra_where)
{
    std::string where;
    auto add = [&](const std::string& clause) {
        where += where.empty() ? " WHERE " : " AND ";
        where += clause;
    };
    if(!extra_where.empty()) add(std::string(extra_where));
    if(c.max_id.has_value()) add("id < ?");
    if(c.min_id.has_value()) add("id > ?");

    // min_id walks the newer direction: select ascending then reverse so
    // the page is still newest-first. Otherwise descending.
    const char* order = c.min_id.has_value() ? "ASC" : "DESC";
    return std::format("SELECT {} FROM posts{} ORDER BY id {} LIMIT ?;",
                       POST_COLS, where, order);
}

} // namespace

mw::E<std::vector<Post>>
DataSourceSQLite::timelinePublic(const Cursor& c, int limit) const
{
    std::string sql = buildTimelineSql(c, "visibility = 'public'");
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(sql));
    // Bind in the order placeholders appear: max_id?, min_id?, limit.
    int idx = 1;
    if(c.max_id.has_value())
        DO_OR_RETURN(internalBindAt(st, idx++, *c.max_id));
    if(c.min_id.has_value())
        DO_OR_RETURN(internalBindAt(st, idx++, *c.min_id));
    DO_OR_RETURN(internalBindAt(st, idx++, static_cast<int64_t>(limit)));

    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string,
        std::optional<int64_t>, std::optional<int64_t>, std::string,
        std::optional<std::string>, std::optional<std::string>, int64_t,
        std::string, std::optional<std::string>, int64_t,
        std::optional<std::string>>(std::move(st))));
    std::vector<Post> out;
    out.reserve(rows.size());
    for(const auto& r : rows)
    {
        ASSIGN_OR_RETURN(Post p, rowToPost(r));
        out.push_back(std::move(p));
    }
    if(c.min_id.has_value())
    {
        std::reverse(out.begin(), out.end());
    }
    return out;
}

mw::E<std::vector<Post>>
DataSourceSQLite::timelineHome(int64_t user_id, const Cursor& c,
                              int limit) const
{
    // Phase 1: the user's own posts. The follow-graph expansion (posts
    // from accounts the user follows) is wired in the service layer in
    // Phase 3, which has the url_root needed to build the user's actor
    // URI and resolve follows. The data primitives (followingUris,
    // timeline-by-author) it composes live here.
    std::string sql = buildTimelineSql(c, "local_author_id = ?");
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(sql));
    int idx = 1;
    DO_OR_RETURN(internalBindAt(st, idx++, user_id));
    if(c.max_id.has_value())
        DO_OR_RETURN(internalBindAt(st, idx++, *c.max_id));
    if(c.min_id.has_value())
        DO_OR_RETURN(internalBindAt(st, idx++, *c.min_id));
    DO_OR_RETURN(internalBindAt(st, idx++, static_cast<int64_t>(limit)));

    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string,
        std::optional<int64_t>, std::optional<int64_t>, std::string,
        std::optional<std::string>, std::optional<std::string>, int64_t,
        std::string, std::optional<std::string>, int64_t,
        std::optional<std::string>>(std::move(st))));
    std::vector<Post> out;
    out.reserve(rows.size());
    for(const auto& r : rows)
    {
        ASSIGN_OR_RETURN(Post p, rowToPost(r));
        out.push_back(std::move(p));
    }
    if(c.min_id.has_value()) std::reverse(out.begin(), out.end());
    return out;
}

mw::E<std::vector<Post>>
DataSourceSQLite::postsForAuthors(const std::vector<int64_t>& author_ids,
                                  const Cursor& c, int limit) const
{
    if(author_ids.empty()) return std::vector<Post>{};

    // Build "local_author_id IN (?,?,...)" then the cursor predicates.
    std::string in_list;
    for(size_t i = 0; i < author_ids.size(); ++i)
        in_list += (i == 0) ? "?" : ",?";
    std::string where = std::format("local_author_id IN ({})", in_list);
    std::string sql = buildTimelineSql(c, where);

    ASSIGN_OR_RETURN(auto st, db->statementFromStr(sql));
    int idx = 1;
    for(int64_t id : author_ids)
        DO_OR_RETURN(internalBindAt(st, idx++, id));
    if(c.max_id.has_value())
        DO_OR_RETURN(internalBindAt(st, idx++, *c.max_id));
    if(c.min_id.has_value())
        DO_OR_RETURN(internalBindAt(st, idx++, *c.min_id));
    DO_OR_RETURN(internalBindAt(st, idx++, static_cast<int64_t>(limit)));

    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string,
        std::optional<int64_t>, std::optional<int64_t>, std::string,
        std::optional<std::string>, std::optional<std::string>, int64_t,
        std::string, std::optional<std::string>, int64_t,
        std::optional<std::string>>(std::move(st))));
    std::vector<Post> out;
    out.reserve(rows.size());
    for(const auto& r : rows)
    {
        ASSIGN_OR_RETURN(Post p, rowToPost(r));
        out.push_back(std::move(p));
    }
    if(c.min_id.has_value()) std::reverse(out.begin(), out.end());
    return out;
}

mw::E<std::vector<Post>>
DataSourceSQLite::threadFor(std::string_view root_uri) const
{
    // Posts whose uri == root, or that reply (directly) to it. Recursive
    // ancestor/descendant backfill across servers is Phase 6; this is the
    // local slice used by the thread view.
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(std::format(
        "SELECT {} FROM posts WHERE uri = ? OR in_reply_to_uri = ? "
        "ORDER BY created_at ASC, id ASC;", POST_COLS)));
    DO_OR_RETURN((st.bind<std::string, std::string>(
        std::string(root_uri), std::string(root_uri))));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string,
        std::optional<int64_t>, std::optional<int64_t>, std::string,
        std::optional<std::string>, std::optional<std::string>, int64_t,
        std::string, std::optional<std::string>, int64_t,
        std::optional<std::string>>(std::move(st))));
    std::vector<Post> out;
    out.reserve(rows.size());
    for(const auto& r : rows)
    {
        ASSIGN_OR_RETURN(Post p, rowToPost(r));
        out.push_back(std::move(p));
    }
    return out;
}

// ─── Follows ───────────────────────────────────────────────────────

mw::E<void> DataSourceSQLite::addFollow(const Follow& f) const
{
    int64_t created = f.created_at != 0 ? f.created_at : now();
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "INSERT INTO follows (follower_uri, followee_uri, state, "
            "follow_activity_uri, created_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(follower_uri, followee_uri) DO UPDATE SET "
            "state=excluded.state, "
            "follow_activity_uri=excluded.follow_activity_uri;"));
        DO_OR_RETURN((st.bind<std::string, std::string, std::string,
            std::optional<std::string>, int64_t>(
            f.follower_uri, f.followee_uri,
            std::string(followStateToStr(f.state)), f.follow_activity_uri,
            created)));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<std::optional<Follow>>
DataSourceSQLite::getFollow(std::string_view follower_uri,
                            std::string_view followee_uri) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(
        "SELECT id, follower_uri, followee_uri, state, follow_activity_uri, "
        "created_at FROM follows WHERE follower_uri = ? AND followee_uri = ?;"));
    DO_OR_RETURN((st.bind<std::string, std::string>(
        std::string(follower_uri), std::string(followee_uri))));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
        std::string, std::optional<std::string>, int64_t>(std::move(st))));
    if(rows.empty()) return std::optional<Follow>{};
    const auto& r = rows[0];
    Follow f;
    f.id = std::get<0>(r);
    f.follower_uri = std::get<1>(r);
    f.followee_uri = std::get<2>(r);
    auto state = followStateFromStr(std::get<3>(r));
    f.state = state.value_or(FollowState::PENDING);
    f.follow_activity_uri = std::get<4>(r);
    f.created_at = std::get<5>(r);
    return std::optional<Follow>{std::move(f)};
}

mw::E<void>
DataSourceSQLite::setFollowState(std::string_view follower_uri,
                                 std::string_view followee_uri,
                                 FollowState s) const
{
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "UPDATE follows SET state = ? WHERE follower_uri = ? "
            "AND followee_uri = ?;"));
        DO_OR_RETURN((st.bind<std::string, std::string, std::string>(
            std::string(followStateToStr(s)), std::string(follower_uri),
            std::string(followee_uri))));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<void>
DataSourceSQLite::removeFollow(std::string_view follower_uri,
                               std::string_view followee_uri) const
{
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "DELETE FROM follows WHERE follower_uri = ? AND followee_uri = ?;"));
        DO_OR_RETURN((st.bind<std::string, std::string>(
            std::string(follower_uri), std::string(followee_uri))));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<std::vector<std::string>>
DataSourceSQLite::followerUris(std::string_view followee_uri) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(
        "SELECT follower_uri FROM follows WHERE followee_uri = ? "
        "AND state = 'accepted';"));
    DO_OR_RETURN(st.bind<std::string>(std::string(followee_uri)));
    ASSIGN_OR_RETURN(auto rows, db->eval<std::string>(std::move(st)));
    std::vector<std::string> out;
    out.reserve(rows.size());
    for(const auto& r : rows) out.push_back(std::get<0>(r));
    return out;
}

mw::E<std::vector<std::string>>
DataSourceSQLite::followingUris(std::string_view follower_uri) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(
        "SELECT followee_uri FROM follows WHERE follower_uri = ? "
        "AND state = 'accepted';"));
    DO_OR_RETURN(st.bind<std::string>(std::string(follower_uri)));
    ASSIGN_OR_RETURN(auto rows, db->eval<std::string>(std::move(st)));
    std::vector<std::string> out;
    out.reserve(rows.size());
    for(const auto& r : rows) out.push_back(std::get<0>(r));
    return out;
}

// ─── Likes / boosts / reactions / bookmarks ────────────────────────

mw::E<void> DataSourceSQLite::addLike(const Like& l) const
{
    int64_t created = l.created_at != 0 ? l.created_at : now();
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "INSERT INTO likes (actor_uri, post_uri, activity_uri, created_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(actor_uri, post_uri) DO NOTHING;"));
        DO_OR_RETURN((st.bind<std::string, std::string,
            std::optional<std::string>, int64_t>(
            l.actor_uri, l.post_uri, l.activity_uri, created)));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<void> DataSourceSQLite::removeLike(std::string_view actor_uri,
                                         std::string_view post_uri) const
{
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "DELETE FROM likes WHERE actor_uri = ? AND post_uri = ?;"));
        DO_OR_RETURN((st.bind<std::string, std::string>(
            std::string(actor_uri), std::string(post_uri))));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<std::vector<Like>>
DataSourceSQLite::likesForPost(std::string_view post_uri) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(
        "SELECT id, actor_uri, post_uri, activity_uri, created_at FROM likes "
        "WHERE post_uri = ? ORDER BY created_at ASC;"));
    DO_OR_RETURN(st.bind<std::string>(std::string(post_uri)));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
        std::optional<std::string>, int64_t>(std::move(st))));
    std::vector<Like> out;
    out.reserve(rows.size());
    for(const auto& r : rows)
    {
        Like l;
        l.id = std::get<0>(r);
        l.actor_uri = std::get<1>(r);
        l.post_uri = std::get<2>(r);
        l.activity_uri = std::get<3>(r);
        l.created_at = std::get<4>(r);
        out.push_back(std::move(l));
    }
    return out;
}

mw::E<void> DataSourceSQLite::addBoost(const Boost& b) const
{
    int64_t created = b.created_at != 0 ? b.created_at : now();
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "INSERT INTO boosts (actor_uri, post_uri, activity_uri, "
            "created_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(actor_uri, post_uri) DO NOTHING;"));
        DO_OR_RETURN((st.bind<std::string, std::string,
            std::optional<std::string>, int64_t>(
            b.actor_uri, b.post_uri, b.activity_uri, created)));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<void> DataSourceSQLite::removeBoost(std::string_view actor_uri,
                                          std::string_view post_uri) const
{
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "DELETE FROM boosts WHERE actor_uri = ? AND post_uri = ?;"));
        DO_OR_RETURN((st.bind<std::string, std::string>(
            std::string(actor_uri), std::string(post_uri))));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<void> DataSourceSQLite::addReaction(const Reaction& r) const
{
    int64_t created = r.created_at != 0 ? r.created_at : now();
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "INSERT INTO reactions (actor_uri, post_uri, emoji, activity_uri, "
            "created_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(actor_uri, post_uri, emoji) DO NOTHING;"));
        DO_OR_RETURN((st.bind<std::string, std::string, std::string,
            std::optional<std::string>, int64_t>(
            r.actor_uri, r.post_uri, r.emoji, r.activity_uri, created)));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<void> DataSourceSQLite::removeReaction(std::string_view actor_uri,
                                             std::string_view post_uri,
                                             std::string_view emoji) const
{
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "DELETE FROM reactions WHERE actor_uri = ? AND post_uri = ? "
            "AND emoji = ?;"));
        DO_OR_RETURN((st.bind<std::string, std::string, std::string>(
            std::string(actor_uri), std::string(post_uri),
            std::string(emoji))));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<std::vector<Reaction>>
DataSourceSQLite::reactionsForPost(std::string_view post_uri) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(
        "SELECT id, actor_uri, post_uri, emoji, activity_uri, created_at "
        "FROM reactions WHERE post_uri = ? ORDER BY created_at ASC;"));
    DO_OR_RETURN(st.bind<std::string>(std::string(post_uri)));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
        std::string, std::optional<std::string>, int64_t>(std::move(st))));
    std::vector<Reaction> out;
    out.reserve(rows.size());
    for(const auto& r : rows)
    {
        Reaction re;
        re.id = std::get<0>(r);
        re.actor_uri = std::get<1>(r);
        re.post_uri = std::get<2>(r);
        re.emoji = std::get<3>(r);
        re.activity_uri = std::get<4>(r);
        re.created_at = std::get<5>(r);
        out.push_back(std::move(re));
    }
    return out;
}

mw::E<void> DataSourceSQLite::addBookmark(int64_t user_id,
                                          int64_t post_id) const
{
    int64_t created = now();
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "INSERT INTO bookmarks (user_id, post_id, created_at) "
            "VALUES (?, ?, ?) ON CONFLICT(user_id, post_id) DO NOTHING;"));
        DO_OR_RETURN((st.bind<int64_t, int64_t, int64_t>(
            user_id, post_id, created)));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<void> DataSourceSQLite::removeBookmark(int64_t user_id,
                                             int64_t post_id) const
{
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "DELETE FROM bookmarks WHERE user_id = ? AND post_id = ?;"));
        DO_OR_RETURN((st.bind<int64_t, int64_t>(user_id, post_id)));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<bool> DataSourceSQLite::isBookmarked(int64_t user_id,
                                           int64_t post_id) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(
        "SELECT 1 FROM bookmarks WHERE user_id = ? AND post_id = ? LIMIT 1;"));
    DO_OR_RETURN((st.bind<int64_t, int64_t>(user_id, post_id)));
    ASSIGN_OR_RETURN(auto rows, db->eval<int64_t>(std::move(st)));
    return !rows.empty();
}

mw::E<std::vector<Post>>
DataSourceSQLite::bookmarksFor(int64_t user_id, const Cursor& c,
                              int limit) const
{
    // Join bookmarks to posts; cursor on posts.id.
    std::string where = " WHERE b.user_id = ?";
    if(c.max_id.has_value()) where += " AND p.id < ?";
    if(c.min_id.has_value()) where += " AND p.id > ?";
    const char* order = c.min_id.has_value() ? "ASC" : "DESC";
    std::string sql = std::format(
        "SELECT {} FROM posts p JOIN bookmarks b ON b.post_id = p.id{} "
        "ORDER BY p.id {} LIMIT ?;",
        // qualify columns with p.
        "p.id, p.uri, p.local_author_id, p.remote_author_id, p.content_html, "
        "p.content_source, p.summary, p.sensitive, p.visibility, "
        "p.in_reply_to_uri, p.created_at, p.published",
        where, order);
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(sql));
    int idx = 1;
    DO_OR_RETURN(internalBindAt(st, idx++, user_id));
    if(c.max_id.has_value())
        DO_OR_RETURN(internalBindAt(st, idx++, *c.max_id));
    if(c.min_id.has_value())
        DO_OR_RETURN(internalBindAt(st, idx++, *c.min_id));
    DO_OR_RETURN(internalBindAt(st, idx++, static_cast<int64_t>(limit)));

    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string,
        std::optional<int64_t>, std::optional<int64_t>, std::string,
        std::optional<std::string>, std::optional<std::string>, int64_t,
        std::string, std::optional<std::string>, int64_t,
        std::optional<std::string>>(std::move(st))));
    std::vector<Post> out;
    out.reserve(rows.size());
    for(const auto& r : rows)
    {
        ASSIGN_OR_RETURN(Post p, rowToPost(r));
        out.push_back(std::move(p));
    }
    if(c.min_id.has_value()) std::reverse(out.begin(), out.end());
    return out;
}

// ─── Attachments ───────────────────────────────────────────────────

mw::E<int64_t> DataSourceSQLite::insertAttachment(const Attachment& a) const
{
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "INSERT INTO attachments (post_id, sha256, media_type, "
            "original_name, is_image, sensitive, remote_url) "
            "VALUES (?, ?, ?, ?, ?, ?, ?);"));
        DO_OR_RETURN((st.bind<std::optional<int64_t>, std::string, std::string,
            std::string, int64_t, int64_t, std::optional<std::string>>(
            a.post_id, a.sha256, a.media_type, a.original_name,
            a.is_image ? 1 : 0, a.sensitive ? 1 : 0, a.remote_url)));
        return db->execute(std::move(st));
    };
    DO_OR_RETURN(withWriteRetry(txn));
    return db->lastInsertRowID();
}

mw::E<void> DataSourceSQLite::attachToPost(int64_t attachment_id,
                                           int64_t post_id) const
{
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "UPDATE attachments SET post_id = ? WHERE id = ?;"));
        DO_OR_RETURN((st.bind<int64_t, int64_t>(post_id, attachment_id)));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<std::vector<Attachment>>
DataSourceSQLite::attachmentsForPost(int64_t post_id) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(
        "SELECT id, post_id, sha256, media_type, original_name, is_image, "
        "sensitive, remote_url FROM attachments WHERE post_id = ? "
        "ORDER BY id ASC;"));
    DO_OR_RETURN(st.bind<int64_t>(post_id));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::optional<int64_t>,
        std::string, std::string, std::string, int64_t, int64_t,
        std::optional<std::string>>(std::move(st))));
    std::vector<Attachment> out;
    out.reserve(rows.size());
    for(const auto& r : rows)
    {
        Attachment a;
        a.id = std::get<0>(r);
        a.post_id = std::get<1>(r);
        a.sha256 = std::get<2>(r);
        a.media_type = std::get<3>(r);
        a.original_name = std::get<4>(r);
        a.is_image = std::get<5>(r) != 0;
        a.sensitive = std::get<6>(r) != 0;
        a.remote_url = std::get<7>(r);
        out.push_back(std::move(a));
    }
    return out;
}

// ─── Sessions ──────────────────────────────────────────────────────

mw::E<void> DataSourceSQLite::createSession(std::string_view token,
                                            int64_t user_id,
                                            int64_t expires_at) const
{
    int64_t created = now();
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) "
            "VALUES (?, ?, ?, ?);"));
        DO_OR_RETURN((st.bind<std::string, int64_t, int64_t, int64_t>(
            std::string(token), user_id, created, expires_at)));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<std::optional<int64_t>>
DataSourceSQLite::getSessionUser(std::string_view token, int64_t now_ts) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(
        "SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?;"));
    DO_OR_RETURN((st.bind<std::string, int64_t>(std::string(token), now_ts)));
    ASSIGN_OR_RETURN(auto rows, db->eval<int64_t>(std::move(st)));
    if(rows.empty()) return std::optional<int64_t>{};
    return std::optional<int64_t>{std::get<0>(rows[0])};
}

mw::E<void> DataSourceSQLite::deleteSession(std::string_view token) const
{
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "DELETE FROM sessions WHERE token = ?;"));
        DO_OR_RETURN(st.bind<std::string>(std::string(token)));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

// ─── Pending logins ────────────────────────────────────────────────

mw::E<void> DataSourceSQLite::addPendingLogin(std::string_view state,
                                              std::string_view nonce,
                                              int64_t created_at) const
{
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "INSERT INTO pending_logins (state, nonce, created_at) "
            "VALUES (?, ?, ?);"));
        DO_OR_RETURN((st.bind<std::string, std::string, int64_t>(
            std::string(state), std::string(nonce), created_at)));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<std::optional<std::string>>
DataSourceSQLite::takePendingLogin(std::string_view state) const
{
    std::optional<std::string> nonce;
    auto txn = [&]() -> mw::E<void> {
        DO_OR_RETURN(db->execute("BEGIN;"));
        auto rollback = [&](mw::Error e) -> mw::E<void> {
            (void)db->execute("ROLLBACK;");
            return std::unexpected(std::move(e));
        };
        nonce.reset();
        {
            auto sel_e = db->statementFromStr(
                "SELECT nonce FROM pending_logins WHERE state = ?;");
            if(!sel_e.has_value()) return rollback(sel_e.error());
            auto b = sel_e->bind<std::string>(std::string(state));
            if(!b.has_value()) return rollback(b.error());
            auto rows_e = db->eval<std::string>(std::move(*sel_e));
            if(!rows_e.has_value()) return rollback(rows_e.error());
            if(!rows_e->empty()) nonce = std::get<0>((*rows_e)[0]);
        }
        if(nonce.has_value())
        {
            auto del_e = db->statementFromStr(
                "DELETE FROM pending_logins WHERE state = ?;");
            if(!del_e.has_value()) return rollback(del_e.error());
            auto b = del_e->bind<std::string>(std::string(state));
            if(!b.has_value()) return rollback(b.error());
            auto ex = db->execute(std::move(*del_e));
            if(!ex.has_value()) return rollback(ex.error());
        }
        return db->execute("COMMIT;");
    };
    DO_OR_RETURN(withWriteRetry(txn));
    return nonce;
}

// ─── Activity dedup ────────────────────────────────────────────────

mw::E<bool> DataSourceSQLite::markActivitySeen(std::string_view uri,
                                               int64_t now_ts) const
{
    bool inserted = false;
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "INSERT INTO seen_activities (activity_uri, seen_at) "
            "VALUES (?, ?) ON CONFLICT(activity_uri) DO NOTHING;"));
        DO_OR_RETURN((st.bind<std::string, int64_t>(
            std::string(uri), now_ts)));
        DO_OR_RETURN(db->execute(std::move(st)));
        inserted = db->changedRowsCount() > 0;
        return {};
    };
    DO_OR_RETURN(withWriteRetry(txn));
    return inserted;
}

// ─── Job queue ─────────────────────────────────────────────────────

mw::E<int64_t> DataSourceSQLite::enqueueJob(std::string_view kind,
                                            std::string_view payload_json,
                                            int64_t run_after,
                                            int64_t now_ts) const
{
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "INSERT INTO jobs (kind, payload_json, state, attempts, "
            "run_after, created_at) VALUES (?, ?, 'pending', 0, ?, ?);"));
        DO_OR_RETURN((st.bind<std::string, std::string, int64_t, int64_t>(
            std::string(kind), std::string(payload_json), run_after, now_ts)));
        return db->execute(std::move(st));
    };
    DO_OR_RETURN(withWriteRetry(txn));
    return db->lastInsertRowID();
}

mw::E<std::optional<Job>> DataSourceSQLite::claimJob(int64_t now_ts) const
{
    std::optional<Job> claimed;
    auto txn = [&]() -> mw::E<void> {
        DO_OR_RETURN(db->execute("BEGIN IMMEDIATE;"));
        auto rollback = [&](mw::Error e) -> mw::E<void> {
            (void)db->execute("ROLLBACK;");
            return std::unexpected(std::move(e));
        };
        claimed.reset();
        int64_t job_id = 0;
        {
            auto sel_e = db->statementFromStr(
                "SELECT id, kind, payload_json, state, attempts, run_after, "
                "last_error, created_at FROM jobs WHERE state = 'pending' "
                "AND run_after <= ? ORDER BY run_after ASC, id ASC LIMIT 1;");
            if(!sel_e.has_value()) return rollback(sel_e.error());
            auto b = sel_e->bind<int64_t>(now_ts);
            if(!b.has_value()) return rollback(b.error());
            auto rows_e = db->eval<int64_t, std::string, std::string,
                std::string, int64_t, int64_t, std::optional<std::string>,
                int64_t>(std::move(*sel_e));
            if(!rows_e.has_value()) return rollback(rows_e.error());
            if(rows_e->empty())
            {
                return db->execute("COMMIT;");
            }
            const auto& r = (*rows_e)[0];
            Job j;
            j.id = std::get<0>(r);
            j.kind = std::get<1>(r);
            j.payload_json = std::get<2>(r);
            j.state = "running";
            j.attempts = std::get<4>(r);
            j.run_after = std::get<5>(r);
            j.last_error = std::get<6>(r);
            j.created_at = std::get<7>(r);
            claimed = std::move(j);
            job_id = claimed->id;
        }
        {
            auto up_e = db->statementFromStr(
                "UPDATE jobs SET state = 'running' WHERE id = ?;");
            if(!up_e.has_value()) return rollback(up_e.error());
            auto b = up_e->bind<int64_t>(job_id);
            if(!b.has_value()) return rollback(b.error());
            auto ex = db->execute(std::move(*up_e));
            if(!ex.has_value()) return rollback(ex.error());
        }
        return db->execute("COMMIT;");
    };
    DO_OR_RETURN(withWriteRetry(txn));
    return claimed;
}

mw::E<void> DataSourceSQLite::completeJob(int64_t job_id) const
{
    auto txn = [&]() -> mw::E<void> {
        ASSIGN_OR_RETURN(auto st, db->statementFromStr(
            "UPDATE jobs SET state = 'done' WHERE id = ?;"));
        DO_OR_RETURN(st.bind<int64_t>(job_id));
        return db->execute(std::move(st));
    };
    return withWriteRetry(txn);
}

mw::E<void> DataSourceSQLite::failJob(int64_t job_id, std::string_view error,
                                      int64_t now_ts, int base_delay_seconds,
                                      int max_retries) const
{
    auto txn = [&]() -> mw::E<void> {
        DO_OR_RETURN(db->execute("BEGIN;"));
        auto rollback = [&](mw::Error e) -> mw::E<void> {
            (void)db->execute("ROLLBACK;");
            return std::unexpected(std::move(e));
        };
        int64_t attempts = 0;
        {
            auto sel_e = db->statementFromStr(
                "SELECT attempts FROM jobs WHERE id = ?;");
            if(!sel_e.has_value()) return rollback(sel_e.error());
            auto b = sel_e->bind<int64_t>(job_id);
            if(!b.has_value()) return rollback(b.error());
            auto rows_e = db->eval<int64_t>(std::move(*sel_e));
            if(!rows_e.has_value()) return rollback(rows_e.error());
            if(rows_e->empty()) return db->execute("COMMIT;");
            attempts = std::get<0>((*rows_e)[0]);
        }
        int64_t new_attempts = attempts + 1;
        // Exponential backoff: base * 2^attempts (design §14.4).
        int64_t delay = static_cast<int64_t>(base_delay_seconds)
            * (static_cast<int64_t>(1) << std::min<int64_t>(new_attempts, 30));
        bool give_up = new_attempts >= max_retries;
        {
            auto up_e = db->statementFromStr(
                "UPDATE jobs SET attempts = ?, last_error = ?, state = ?, "
                "run_after = ? WHERE id = ?;");
            if(!up_e.has_value()) return rollback(up_e.error());
            auto b = up_e->bind<int64_t, std::string, std::string, int64_t,
                int64_t>(new_attempts, std::string(error),
                         give_up ? "failed" : "pending",
                         give_up ? now_ts : now_ts + delay, job_id);
            if(!b.has_value()) return rollback(b.error());
            auto ex = db->execute(std::move(*up_e));
            if(!ex.has_value()) return rollback(ex.error());
        }
        return db->execute("COMMIT;");
    };
    return withWriteRetry(txn);
}

} // namespace unspoken
