#include <actpub/store.hpp>
#include <actpub/identity.hpp>

#include <algorithm>
#include <cctype>
#include <format>
#include <functional>
#include <thread>
#include <mw/utils.hpp>

namespace ap
{
namespace
{
int64_t now()
{
    return mw::timeToSeconds(mw::Clock::now());
}

mw::E<void> touchRemoteActorRetentionByUri(mw::SQLite& db,
                                           std::string_view actor_uri,
                                           int64_t retained_at)
{
    ASSIGN_OR_RETURN(
        auto st,
        db.statementFromStr(
            "UPDATE ap_remote_actors SET retained_at = ? WHERE uri = ?;"));
    DO_OR_RETURN(
        (st.bind<int64_t, std::string>(retained_at, std::string(actor_uri))));
    return db.execute(std::move(st));
}

mw::E<void> internalBindAt(const mw::SQLiteStatement& st, int i, int64_t v)
{
    return mw::internal::bindOne(st, i, v);
}

std::string buildFollowPageSql(const Cursor& c, std::string_view uri_column,
                               std::string_view select_column)
{
    std::string where =
        std::format("{} = ? AND state = 'accepted'", uri_column);
    if(c.max_id.has_value())
        where += " AND id < ?";
    if(c.min_id.has_value())
        where += " AND id > ?";
    const char* order = c.min_id.has_value() ? "ASC" : "DESC";
    return std::format(
        "SELECT id, {} FROM ap_follows WHERE {} ORDER BY id {} LIMIT ?;",
        select_column, where, order);
}

mw::E<std::vector<ActorCollectionItem>>
rowsToActorCollection(const std::vector<std::tuple<int64_t, std::string>>& rows,
                      bool reverse_order)
{
    std::vector<ActorCollectionItem> out;
    out.reserve(rows.size());
    for(const auto& r : rows)
    {
        out.push_back(ActorCollectionItem{std::get<0>(r), std::get<1>(r)});
    }
    if(reverse_order)
        std::reverse(out.begin(), out.end());
    return out;
}

} // namespace

bool isRetryableSqlError(const mw::Error& e)
{
    const std::string& msg = mw::errorMsg(e);
    std::string lower;
    lower.reserve(msg.size());
    for(char c : msg)
    {
        lower.push_back(
            static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return lower.find("busy") != std::string::npos ||
           lower.find("locked") != std::string::npos;
}

mw::E<void> withWriteRetry(const std::function<mw::E<void>()>& txn,
                           int max_retries = 5)
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

namespace
{

mw::E<void> withDataWrite(mw::SQLite& db,
                          const std::function<mw::E<void>()>& operation)
{
    ASSIGN_OR_RETURN(bool active, ap::inTransaction(db));
    if(active)
    {
        ASSIGN_OR_RETURN(auto scope, ap::Savepoint::begin(db));
        DO_OR_RETURN(operation());
        return scope.release();
    }
    auto run = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(auto transaction, ap::Transaction::begin(db));
        DO_OR_RETURN(operation());
        return transaction.commit();
    };
    return withWriteRetry(run);
}

} // namespace

mw::E<void> Store::migrate() const
{
    auto txn = [&]() -> mw::E<void>
    {
        DO_OR_RETURN(db->execute(
            "CREATE TABLE IF NOT EXISTS ap_schema ("
            "id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL)"));
        ASSIGN_OR_RETURN(
            auto versions,
            db->eval<int64_t>("SELECT version FROM ap_schema WHERE id=1"));
        if(!versions.empty() && std::get<0>(versions.front()) != 1)
            return std::unexpected(
                mw::runtimeError("Unsupported ActivityPub schema version"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE TABLE IF NOT EXISTS ap_system_actor ( id INTEGER PRIMARY KEY CHECK (id = 1), private_key_pem TEXT NOT NULL, public_key_pem TEXT NOT NULL, created_at INTEGER NOT NULL);)SQL"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE TABLE IF NOT EXISTS ap_remote_actors ( id INTEGER PRIMARY KEY AUTOINCREMENT, uri TEXT NOT NULL UNIQUE, username TEXT NOT NULL, domain TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '', inbox TEXT NOT NULL, shared_inbox TEXT, public_key_pem TEXT NOT NULL, public_key_id TEXT NOT NULL, actor_json TEXT NOT NULL, fetched_at INTEGER NOT NULL, retained_at INTEGER NOT NULL DEFAULT 0);)SQL"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE INDEX IF NOT EXISTS ap_idx_remote_actors_domain ON ap_remote_actors(domain);)SQL"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE INDEX IF NOT EXISTS ap_idx_remote_actors_retained ON ap_remote_actors(retained_at, id);)SQL"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE TABLE IF NOT EXISTS ap_follows ( id INTEGER PRIMARY KEY AUTOINCREMENT, follower_uri TEXT NOT NULL, followee_uri TEXT NOT NULL, state TEXT NOT NULL, follow_activity_uri TEXT, created_at INTEGER NOT NULL);)SQL"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE UNIQUE INDEX IF NOT EXISTS ap_idx_follows_pair ON ap_follows(follower_uri, followee_uri);)SQL"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE TABLE IF NOT EXISTS ap_likes ( id INTEGER PRIMARY KEY AUTOINCREMENT, actor_uri TEXT NOT NULL, post_uri TEXT NOT NULL, activity_uri TEXT, created_at INTEGER NOT NULL);)SQL"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE UNIQUE INDEX IF NOT EXISTS ap_idx_likes_pair ON ap_likes(actor_uri, post_uri);)SQL"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE TABLE IF NOT EXISTS ap_boosts ( id INTEGER PRIMARY KEY AUTOINCREMENT, actor_uri TEXT NOT NULL, post_uri TEXT NOT NULL, activity_uri TEXT, created_at INTEGER NOT NULL);)SQL"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE UNIQUE INDEX IF NOT EXISTS ap_idx_boosts_pair ON ap_boosts(actor_uri, post_uri);)SQL"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE TABLE IF NOT EXISTS ap_reactions ( id INTEGER PRIMARY KEY AUTOINCREMENT, actor_uri TEXT NOT NULL, post_uri TEXT NOT NULL, emoji TEXT NOT NULL, remote_emoji_url TEXT, remote_emoji_media_type TEXT, activity_uri TEXT, created_at INTEGER NOT NULL);)SQL"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE UNIQUE INDEX IF NOT EXISTS ap_idx_reactions_triple ON ap_reactions(actor_uri, post_uri, emoji);)SQL"));
        DO_OR_RETURN(db->execute(
            "CREATE TABLE IF NOT EXISTS ap_seen_activities ("
            "activity_uri TEXT PRIMARY KEY, state TEXT NOT NULL, "
            "claimed_at INTEGER, processed_at INTEGER, "
            "CHECK(state IN ('processing','processed')), "
            "CHECK((state='processing' AND claimed_at IS NOT NULL) OR "
            "(state='processed' AND processed_at IS NOT NULL)))"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE INDEX IF NOT EXISTS ap_idx_seen_activities_processed ON ap_seen_activities(processed_at) WHERE state = 'processed';)SQL"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE INDEX IF NOT EXISTS ap_idx_seen_activities_processing ON ap_seen_activities(claimed_at) WHERE state = 'processing';)SQL"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE TABLE IF NOT EXISTS ap_jobs ( id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, payload_json TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, run_after INTEGER NOT NULL, last_error TEXT, created_at INTEGER NOT NULL, lease_token TEXT, lease_until INTEGER);)SQL"));
        DO_OR_RETURN(db->execute(
            R"SQL(CREATE INDEX IF NOT EXISTS ap_idx_jobs_runnable ON ap_jobs(state, run_after);)SQL"));
        DO_OR_RETURN(db->execute(
            "CREATE TABLE IF NOT EXISTS ap_actor_refs (actor_uri TEXT NOT NULL,"
            "owner_kind TEXT NOT NULL, owner_key TEXT NOT NULL,"
            "PRIMARY KEY(actor_uri,owner_kind,owner_key))"));
        for(const char* sql :
            {"CREATE TABLE IF NOT EXISTS ap_local_actors (uri TEXT PRIMARY KEY,"
             "key_id TEXT NOT NULL,private_key_pem TEXT NOT NULL,"
             "document_json TEXT NOT NULL)",
             "CREATE TABLE IF NOT EXISTS ap_objects (sequence INTEGER PRIMARY "
             "KEY "
             "AUTOINCREMENT,uri TEXT NOT NULL UNIQUE,owner_uri TEXT NOT NULL,"
             "local INTEGER NOT NULL,document_json TEXT NOT NULL,deleted "
             "INTEGER "
             "NOT NULL DEFAULT 0)",
             "CREATE TABLE IF NOT EXISTS ap_outbox (sequence INTEGER PRIMARY "
             "KEY "
             "AUTOINCREMENT,activity_uri TEXT NOT NULL UNIQUE,actor_uri TEXT "
             "NOT NULL,"
             "document_json TEXT NOT NULL)",
             "CREATE TABLE IF NOT EXISTS ap_inbox_activities (activity_uri "
             "TEXT "
             "PRIMARY KEY,actor_uri TEXT NOT NULL,document_json TEXT NOT NULL,"
             "applied INTEGER NOT NULL DEFAULT 0,processed_at INTEGER NOT "
             "NULL)",
             "CREATE TABLE IF NOT EXISTS ap_inbox_receipts (activity_uri TEXT "
             "NOT NULL,"
             "recipient_uri TEXT NOT NULL,PRIMARY "
             "KEY(activity_uri,recipient_uri))",
             "CREATE TABLE IF NOT EXISTS ap_delivery_keys (activity_uri TEXT "
             "NOT NULL,"
             "signer_uri TEXT NOT NULL,inbox TEXT NOT NULL,"
             "PRIMARY KEY(activity_uri,signer_uri,inbox))",
             "CREATE INDEX IF NOT EXISTS ap_objects_owner ON "
             "ap_objects(owner_uri)",
             "CREATE INDEX IF NOT EXISTS ap_outbox_actor ON "
             "ap_outbox(actor_uri,sequence)"})
            DO_OR_RETURN(db->execute(sql));
        DO_OR_RETURN(
            db->execute("INSERT OR IGNORE INTO ap_schema VALUES (1,1)"));
        return {};
    };
    return withDataWrite(*db, txn);
}

mw::E<std::optional<SystemActor>> Store::getSystemActor() const
{
    ASSIGN_OR_RETURN(auto st,
                     db->statementFromStr(
                         "SELECT private_key_pem, public_key_pem, created_at "
                         "FROM ap_system_actor WHERE id = 1;"));
    ASSIGN_OR_RETURN(auto rows, (db->eval<std::string, std::string, int64_t>(
                                    std::move(st))));
    if(rows.empty())
        return std::optional<SystemActor>{};
    SystemActor actor;
    actor.private_key_pem = std::get<0>(rows[0]);
    actor.public_key_pem = std::get<1>(rows[0]);
    actor.created_at = std::get<2>(rows[0]);
    return actor;
}

mw::E<void> Store::setSystemActor(std::string_view private_key_pem,
                                  std::string_view public_key_pem) const
{
    int64_t created = now();
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st, db->statementFromStr(
                         "INSERT INTO ap_system_actor "
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
    return withDataWrite(*db, txn);
}

mw::E<RemoteActor> Store::upsertRemoteActor(const RemoteActor& a) const
{
    int64_t fetched = a.fetched_at != 0 ? a.fetched_at : now();
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr(
                "INSERT INTO ap_remote_actors (uri, username, domain, "
                "display_name, "
                "inbox, shared_inbox, public_key_pem, public_key_id, "
                "actor_json, "
                "fetched_at, retained_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "
                "?, ?) "
                "ON CONFLICT(uri) DO UPDATE SET username=excluded.username, "
                "domain=excluded.domain, display_name=excluded.display_name, "
                "inbox=excluded.inbox, shared_inbox=excluded.shared_inbox, "
                "public_key_pem=excluded.public_key_pem, "
                "public_key_id=excluded.public_key_id, "
                "actor_json=excluded.actor_json, "
                "fetched_at=excluded.fetched_at;"));
        DO_OR_RETURN(
            (st.bind<std::string, std::string, std::string, std::string,
                     std::string, std::optional<std::string>, std::string,
                     std::string, std::string, int64_t, int64_t>(
                a.uri, a.username, a.domain, a.display_name, a.inbox,
                a.shared_inbox, a.public_key_pem, a.public_key_id, a.actor_json,
                fetched, fetched)));
        return db->execute(std::move(st));
    };
    DO_OR_RETURN(withDataWrite(*db, txn));

    ASSIGN_OR_RETURN(auto stored, getRemoteActorByUri(a.uri));
    if(!stored.has_value())
    {
        return std::unexpected(
            mw::runtimeError("Remote actor vanished immediately after upsert"));
    }
    return *stored;
}

mw::E<std::optional<RemoteActor>> Store::getRemoteActorById(int64_t id) const
{
    ASSIGN_OR_RETURN(
        auto st, db->statementFromStr("SELECT id, uri, username, domain, "
                                      "display_name, inbox, shared_inbox, "
                                      "public_key_pem, public_key_id, "
                                      "actor_json, fetched_at, retained_at "
                                      "FROM ap_remote_actors WHERE id = ?;"));
    DO_OR_RETURN(st.bind<int64_t>(id));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, std::string, std::string, std::string,
                  std::string, std::optional<std::string>, std::string,
                  std::string, std::string, int64_t, int64_t>(std::move(st))));
    if(rows.empty())
        return std::optional<RemoteActor>{};
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
    a.retained_at = std::get<11>(r);
    return std::optional<RemoteActor>{std::move(a)};
}

mw::E<std::optional<RemoteActor>>
Store::getRemoteActorByUri(std::string_view uri) const
{
    ASSIGN_OR_RETURN(
        auto st, db->statementFromStr("SELECT id, uri, username, domain, "
                                      "display_name, inbox, shared_inbox, "
                                      "public_key_pem, public_key_id, "
                                      "actor_json, fetched_at, retained_at "
                                      "FROM ap_remote_actors WHERE uri = ?;"));
    DO_OR_RETURN(st.bind<std::string>(std::string(uri)));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, std::string, std::string, std::string,
                  std::string, std::optional<std::string>, std::string,
                  std::string, std::string, int64_t, int64_t>(std::move(st))));
    if(rows.empty())
        return std::optional<RemoteActor>{};
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
    a.retained_at = std::get<11>(r);
    return std::optional<RemoteActor>{std::move(a)};
}

mw::E<void> Store::touchRemoteActorRetention(std::string_view actor_uri,
                                             int64_t now_seconds) const
{
    auto txn = [&]() -> mw::E<void>
    { return touchRemoteActorRetentionByUri(*db, actor_uri, now_seconds); };
    return withDataWrite(*db, txn);
}

mw::E<void> Store::addFollow(const Follow& f) const
{
    int64_t created = f.created_at != 0 ? f.created_at : now();
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr(
                "INSERT INTO ap_follows (follower_uri, followee_uri, state, "
                "follow_activity_uri, created_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(follower_uri, followee_uri) DO UPDATE SET "
                "state=excluded.state, "
                "follow_activity_uri=excluded.follow_activity_uri;"));
        DO_OR_RETURN((st.bind<std::string, std::string, std::string,
                              std::optional<std::string>, int64_t>(
            f.follower_uri, f.followee_uri,
            std::string(followStateToStr(f.state)), f.follow_activity_uri,
            created)));
        DO_OR_RETURN(db->execute(std::move(st)));
        DO_OR_RETURN(
            touchRemoteActorRetentionByUri(*db, f.follower_uri, created));
        return touchRemoteActorRetentionByUri(*db, f.followee_uri, created);
    };
    return withDataWrite(*db, txn);
}

mw::E<std::optional<Follow>>
Store::getFollow(std::string_view follower_uri,
                 std::string_view followee_uri) const
{
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(
                                  "SELECT id, follower_uri, followee_uri, "
                                  "state, follow_activity_uri, "
                                  "created_at FROM ap_follows WHERE "
                                  "follower_uri = ? AND followee_uri = ?;"));
    DO_OR_RETURN((st.bind<std::string, std::string>(
        std::string(follower_uri), std::string(followee_uri))));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, std::string, std::string,
                  std::optional<std::string>, int64_t>(std::move(st))));
    if(rows.empty())
        return std::optional<Follow>{};
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

mw::E<void> Store::setFollowState(std::string_view follower_uri,
                                  std::string_view followee_uri,
                                  FollowState s) const
{
    int64_t retained_at = now();
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr(
                "UPDATE ap_follows SET state = ? WHERE follower_uri = ? "
                "AND followee_uri = ?;"));
        DO_OR_RETURN((st.bind<std::string, std::string, std::string>(
            std::string(followStateToStr(s)), std::string(follower_uri),
            std::string(followee_uri))));
        DO_OR_RETURN(db->execute(std::move(st)));
        DO_OR_RETURN(
            touchRemoteActorRetentionByUri(*db, follower_uri, retained_at));
        return touchRemoteActorRetentionByUri(*db, followee_uri, retained_at);
    };
    return withDataWrite(*db, txn);
}

mw::E<void> Store::removeFollow(std::string_view follower_uri,
                                std::string_view followee_uri) const
{
    int64_t retained_at = now();
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr("DELETE FROM ap_follows WHERE follower_uri = "
                                 "? AND followee_uri = ?;"));
        DO_OR_RETURN((st.bind<std::string, std::string>(
            std::string(follower_uri), std::string(followee_uri))));
        DO_OR_RETURN(db->execute(std::move(st)));
        DO_OR_RETURN(
            touchRemoteActorRetentionByUri(*db, follower_uri, retained_at));
        return touchRemoteActorRetentionByUri(*db, followee_uri, retained_at);
    };
    return withDataWrite(*db, txn);
}

mw::E<std::vector<std::string>>
Store::followerUris(std::string_view followee_uri) const
{
    ASSIGN_OR_RETURN(
        auto st,
        db->statementFromStr(
            "SELECT follower_uri FROM ap_follows WHERE followee_uri = ? "
            "AND state = 'accepted';"));
    DO_OR_RETURN(st.bind<std::string>(std::string(followee_uri)));
    ASSIGN_OR_RETURN(auto rows, db->eval<std::string>(std::move(st)));
    std::vector<std::string> out;
    out.reserve(rows.size());
    for(const auto& r : rows)
        out.push_back(std::get<0>(r));
    return out;
}

mw::E<std::vector<std::string>>
Store::followingUris(std::string_view follower_uri) const
{
    ASSIGN_OR_RETURN(
        auto st,
        db->statementFromStr(
            "SELECT followee_uri FROM ap_follows WHERE follower_uri = ? "
            "AND state = 'accepted';"));
    DO_OR_RETURN(st.bind<std::string>(std::string(follower_uri)));
    ASSIGN_OR_RETURN(auto rows, db->eval<std::string>(std::move(st)));
    std::vector<std::string> out;
    out.reserve(rows.size());
    for(const auto& r : rows)
        out.push_back(std::get<0>(r));
    return out;
}

mw::E<std::vector<ActorCollectionItem>>
Store::followerPage(std::string_view followee_uri, const Cursor& c,
                    int limit) const
{
    std::string sql = buildFollowPageSql(c, "followee_uri", "follower_uri");
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(sql));
    int idx = 1;
    DO_OR_RETURN(mw::internal::bindOne(st, idx++, std::string(followee_uri)));
    if(c.max_id.has_value())
        DO_OR_RETURN(internalBindAt(st, idx++, *c.max_id));
    if(c.min_id.has_value())
        DO_OR_RETURN(internalBindAt(st, idx++, *c.min_id));
    DO_OR_RETURN(internalBindAt(st, idx++, static_cast<int64_t>(limit)));
    ASSIGN_OR_RETURN(auto rows,
                     (db->eval<int64_t, std::string>(std::move(st))));
    return rowsToActorCollection(rows, c.min_id.has_value());
}

mw::E<std::vector<ActorCollectionItem>>
Store::followingPage(std::string_view follower_uri, const Cursor& c,
                     int limit) const
{
    std::string sql = buildFollowPageSql(c, "follower_uri", "followee_uri");
    ASSIGN_OR_RETURN(auto st, db->statementFromStr(sql));
    int idx = 1;
    DO_OR_RETURN(mw::internal::bindOne(st, idx++, std::string(follower_uri)));
    if(c.max_id.has_value())
        DO_OR_RETURN(internalBindAt(st, idx++, *c.max_id));
    if(c.min_id.has_value())
        DO_OR_RETURN(internalBindAt(st, idx++, *c.min_id));
    DO_OR_RETURN(internalBindAt(st, idx++, static_cast<int64_t>(limit)));
    ASSIGN_OR_RETURN(auto rows,
                     (db->eval<int64_t, std::string>(std::move(st))));
    return rowsToActorCollection(rows, c.min_id.has_value());
}

mw::E<void> Store::addLike(const Like& l) const
{
    int64_t created = l.created_at != 0 ? l.created_at : now();
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr("INSERT INTO ap_likes (actor_uri, post_uri, "
                                 "activity_uri, created_at) "
                                 "VALUES (?, ?, ?, ?) ON CONFLICT(actor_uri, "
                                 "post_uri) DO NOTHING;"));
        DO_OR_RETURN((st.bind<std::string, std::string,
                              std::optional<std::string>, int64_t>(
            l.actor_uri, l.post_uri, l.activity_uri, created)));
        DO_OR_RETURN(db->execute(std::move(st)));
        return touchRemoteActorRetentionByUri(*db, l.actor_uri, created);
    };
    return withDataWrite(*db, txn);
}

mw::E<void> Store::removeLike(std::string_view actor_uri,
                              std::string_view post_uri) const
{
    int64_t retained_at = now();
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr(
                "DELETE FROM ap_likes WHERE actor_uri = ? AND post_uri = ?;"));
        DO_OR_RETURN((st.bind<std::string, std::string>(
            std::string(actor_uri), std::string(post_uri))));
        DO_OR_RETURN(db->execute(std::move(st)));
        return touchRemoteActorRetentionByUri(*db, actor_uri, retained_at);
    };
    return withDataWrite(*db, txn);
}

mw::E<std::vector<Like>> Store::likesForPost(std::string_view post_uri) const
{
    ASSIGN_OR_RETURN(
        auto st,
        db->statementFromStr("SELECT id, actor_uri, post_uri, activity_uri, "
                             "created_at FROM ap_likes "
                             "WHERE post_uri = ? ORDER BY created_at ASC;"));
    DO_OR_RETURN(st.bind<std::string>(std::string(post_uri)));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
                                          std::optional<std::string>, int64_t>(
                                    std::move(st))));
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

mw::E<void> Store::addBoost(const Boost& b) const
{
    int64_t created = b.created_at != 0 ? b.created_at : now();
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr(
                "INSERT INTO ap_boosts (actor_uri, post_uri, activity_uri, "
                "created_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(actor_uri, post_uri) DO NOTHING;"));
        DO_OR_RETURN((st.bind<std::string, std::string,
                              std::optional<std::string>, int64_t>(
            b.actor_uri, b.post_uri, b.activity_uri, created)));
        DO_OR_RETURN(db->execute(std::move(st)));
        return touchRemoteActorRetentionByUri(*db, b.actor_uri, created);
    };
    return withDataWrite(*db, txn);
}

mw::E<void> Store::removeBoost(std::string_view actor_uri,
                               std::string_view post_uri) const
{
    int64_t retained_at = now();
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr(
                "DELETE FROM ap_boosts WHERE actor_uri = ? AND post_uri = ?;"));
        DO_OR_RETURN((st.bind<std::string, std::string>(
            std::string(actor_uri), std::string(post_uri))));
        DO_OR_RETURN(db->execute(std::move(st)));
        return touchRemoteActorRetentionByUri(*db, actor_uri, retained_at);
    };
    return withDataWrite(*db, txn);
}

mw::E<std::vector<Boost>> Store::boostsForPost(std::string_view post_uri) const
{
    ASSIGN_OR_RETURN(
        auto st,
        db->statementFromStr(
            "SELECT id, actor_uri, post_uri, activity_uri, created_at "
            "FROM ap_boosts WHERE post_uri = ? ORDER BY created_at ASC;"));
    DO_OR_RETURN(st.bind<std::string>(std::string(post_uri)));
    ASSIGN_OR_RETURN(auto rows, (db->eval<int64_t, std::string, std::string,
                                          std::optional<std::string>, int64_t>(
                                    std::move(st))));
    std::vector<Boost> out;
    out.reserve(rows.size());
    for(const auto& r : rows)
    {
        Boost b;
        b.id = std::get<0>(r);
        b.actor_uri = std::get<1>(r);
        b.post_uri = std::get<2>(r);
        b.activity_uri = std::get<3>(r);
        b.created_at = std::get<4>(r);
        out.push_back(std::move(b));
    }
    return out;
}

mw::E<void> Store::addReaction(const Reaction& r) const
{
    int64_t created = r.created_at != 0 ? r.created_at : now();
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr(
                "INSERT INTO ap_reactions (actor_uri, post_uri, emoji, "
                "remote_emoji_url, remote_emoji_media_type, activity_uri, "
                "created_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(actor_uri, post_uri, emoji) DO NOTHING;"));
        DO_OR_RETURN(
            (st.bind<std::string, std::string, std::string,
                     std::optional<std::string>, std::optional<std::string>,
                     std::optional<std::string>, int64_t>(
                r.actor_uri, r.post_uri, r.emoji, r.remote_emoji_url,
                r.remote_emoji_media_type, r.activity_uri, created)));
        DO_OR_RETURN(db->execute(std::move(st)));
        return touchRemoteActorRetentionByUri(*db, r.actor_uri, created);
    };
    return withDataWrite(*db, txn);
}

mw::E<void> Store::removeReaction(std::string_view actor_uri,
                                  std::string_view post_uri,
                                  std::string_view emoji) const
{
    int64_t retained_at = now();
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr(
                "DELETE FROM ap_reactions WHERE actor_uri = ? AND post_uri = ? "
                "AND emoji = ?;"));
        DO_OR_RETURN((st.bind<std::string, std::string, std::string>(
            std::string(actor_uri), std::string(post_uri),
            std::string(emoji))));
        DO_OR_RETURN(db->execute(std::move(st)));
        return touchRemoteActorRetentionByUri(*db, actor_uri, retained_at);
    };
    return withDataWrite(*db, txn);
}

mw::E<std::vector<Reaction>>
Store::reactionsForPost(std::string_view post_uri) const
{
    ASSIGN_OR_RETURN(
        auto st,
        db->statementFromStr(
            "SELECT id, actor_uri, post_uri, emoji, remote_emoji_url, "
            "remote_emoji_media_type, activity_uri, created_at "
            "FROM ap_reactions WHERE post_uri = ? ORDER BY created_at ASC;"));
    DO_OR_RETURN(st.bind<std::string>(std::string(post_uri)));
    ASSIGN_OR_RETURN(
        auto rows,
        (db->eval<int64_t, std::string, std::string, std::string,
                  std::optional<std::string>, std::optional<std::string>,
                  std::optional<std::string>, int64_t>(std::move(st))));
    std::vector<Reaction> out;
    out.reserve(rows.size());
    for(const auto& r : rows)
    {
        Reaction re;
        re.id = std::get<0>(r);
        re.actor_uri = std::get<1>(r);
        re.post_uri = std::get<2>(r);
        re.emoji = std::get<3>(r);
        re.remote_emoji_url = std::get<4>(r);
        re.remote_emoji_media_type = std::get<5>(r);
        re.activity_uri = std::get<6>(r);
        re.created_at = std::get<7>(r);
        out.push_back(std::move(re));
    }
    return out;
}

mw::E<int64_t> Store::enqueueJob(std::string_view kind,
                                 std::string_view payload, int64_t run_after,
                                 int64_t created) const
{
    int64_t id = 0;
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr(
                "INSERT INTO "
                "ap_jobs(kind,payload_json,state,run_after,created_at) "
                "VALUES (?,?,'pending',?,?)"));
        DO_OR_RETURN((st.bind<std::string, std::string, int64_t, int64_t>(
            std::string(kind), std::string(payload), run_after, created)));
        DO_OR_RETURN(db->execute(std::move(st)));
        id = db->lastInsertRowID();
        return {};
    };
    DO_OR_RETURN(withDataWrite(*db, txn));
    return id;
}

mw::E<std::optional<Job>> Store::claimJob(int64_t now_ts,
                                          int64_t lease_seconds) const
{
    if(lease_seconds <= 0)
        return std::unexpected(mw::runtimeError("Invalid job lease duration"));
    std::optional<Job> claimed;
    auto txn = [&]() -> mw::E<void>
    {
        claimed.reset();
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr(
                "SELECT id,kind,payload_json,attempts,run_after,last_error,"
                "created_at FROM ap_jobs j WHERE "
                "((state='pending' AND run_after<=?) OR "
                "(state='running' AND lease_until<=?)) AND NOT EXISTS("
                "SELECT 1 FROM ap_jobs older WHERE older.id<j.id "
                "AND older.kind='deliver' AND j.kind='deliver' "
                "AND older.state IN ('pending','running') AND "
                "json_extract(CASE WHEN json_valid(older.payload_json) THEN "
                "older.payload_json ELSE '{}' END,'$.target_inbox')="
                "json_extract(CASE WHEN json_valid(j.payload_json) THEN "
                "j.payload_json ELSE '{}' END,'$.target_inbox') AND "
                "json_extract(CASE WHEN json_valid(older.payload_json) THEN "
                "older.payload_json ELSE '{}' END,'$.signer_actor')="
                "json_extract(CASE WHEN json_valid(j.payload_json) THEN "
                "j.payload_json ELSE '{}' END,'$.signer_actor')) "
                "ORDER BY run_after,id LIMIT 1"));
        DO_OR_RETURN((st.bind<int64_t, int64_t>(now_ts, now_ts)));
        ASSIGN_OR_RETURN(
            auto rows,
            (db->eval<int64_t, std::string, std::string, int64_t, int64_t,
                      std::optional<std::string>, int64_t>(std::move(st))));
        if(rows.empty())
            return {};
        const auto& row = rows.front();
        Job job;
        job.id = std::get<0>(row);
        job.kind = std::get<1>(row);
        job.payload_json = std::get<2>(row);
        job.attempts = std::get<3>(row);
        job.run_after = std::get<4>(row);
        job.last_error = std::get<5>(row);
        job.created_at = std::get<6>(row);
        job.state = "running";
        job.lease_until = now_ts + lease_seconds;
        ASSIGN_OR_RETURN(job.lease_token, newActivityUri(""));
        ASSIGN_OR_RETURN(
            auto update,
            db->statementFromStr("UPDATE ap_jobs SET "
                                 "state='running',lease_token=?,lease_until=? "
                                 "WHERE id=?"));
        DO_OR_RETURN((update.bind<std::string, int64_t, int64_t>(
            job.lease_token, job.lease_until, job.id)));
        DO_OR_RETURN(db->execute(std::move(update)));
        claimed = std::move(job);
        return {};
    };
    DO_OR_RETURN(withDataWrite(*db, txn));
    return claimed;
}

mw::E<void> Store::completeJob(const Job& job) const
{
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st, db->statementFromStr(
                         "UPDATE ap_jobs SET "
                         "state='done',lease_token=NULL,lease_until=NULL "
                         "WHERE id=? AND state='running' AND lease_token=?"));
        DO_OR_RETURN((st.bind<int64_t, std::string>(job.id, job.lease_token)));
        DO_OR_RETURN(db->execute(std::move(st)));
        if(db->changedRowsCount() != 1)
            return std::unexpected(mw::runtimeError("Job lease was lost"));
        return {};
    };
    return withDataWrite(*db, txn);
}

mw::E<void> Store::failJob(const Job& job, std::string_view error,
                           int64_t now_ts, int base_delay_seconds,
                           int max_retries) const
{
    if(base_delay_seconds <= 0 || max_retries <= 0)
        return std::unexpected(mw::runtimeError("Invalid job retry policy"));
    auto txn = [&]() -> mw::E<void>
    {
        int64_t failures = job.attempts + 1;
        int64_t delay = std::min<int64_t>(
            86400, static_cast<int64_t>(base_delay_seconds) *
                       (int64_t{1} << std::min<int64_t>(failures, 30)));
        ASSIGN_OR_RETURN(
            auto st, db->statementFromStr(
                         "UPDATE ap_jobs SET "
                         "attempts=?,last_error=?,state=?,run_after=?,"
                         "lease_token=NULL,lease_until=NULL "
                         "WHERE id=? AND state='running' AND lease_token=?"));
        DO_OR_RETURN((
            st.bind<int64_t, std::string, std::string, int64_t, int64_t,
                    std::string>(failures, std::string(error.substr(0, 1024)),
                                 failures >= max_retries ? "failed" : "pending",
                                 now_ts + delay, job.id, job.lease_token)));
        DO_OR_RETURN(db->execute(std::move(st)));
        if(db->changedRowsCount() != 1)
            return std::unexpected(mw::runtimeError("Job lease was lost"));
        return {};
    };
    return withDataWrite(*db, txn);
}

mw::E<ActivityClaimResult>
Store::claimIncomingActivity(std::string_view activity_uri, int64_t now_seconds,
                             int64_t lease_seconds) const
{
    ActivityClaimResult result = ActivityClaimResult::IN_PROGRESS;
    auto txn = [&]() -> mw::E<void>
    {
        DO_OR_RETURN(db->execute("SAVEPOINT unspoken_operation;"));
        auto rollback = [&](mw::Error e) -> mw::E<void>
        {
            (void)db->execute(
                "ROLLBACK TO unspoken_operation; RELEASE unspoken_operation;");
            return std::unexpected(std::move(e));
        };

        auto select_e = db->statementFromStr(
            "SELECT state, claimed_at FROM ap_seen_activities "
            "WHERE activity_uri = ?;");
        if(!select_e.has_value())
            return rollback(select_e.error());
        auto select = std::move(*select_e);
        if(auto r = select.bind<std::string>(std::string(activity_uri));
           !r.has_value())
            return rollback(r.error());
        auto rows_e =
            db->eval<std::string, std::optional<int64_t>>(std::move(select));
        if(!rows_e.has_value())
            return rollback(rows_e.error());

        if(rows_e->empty())
        {
            auto insert_e = db->statementFromStr(
                "INSERT INTO ap_seen_activities "
                "(activity_uri, state, claimed_at, processed_at) "
                "VALUES (?, 'processing', ?, NULL);");
            if(!insert_e.has_value())
                return rollback(insert_e.error());
            auto b = insert_e->bind<std::string, int64_t>(
                std::string(activity_uri), now_seconds);
            if(!b.has_value())
                return rollback(b.error());
            auto executed = db->execute(std::move(*insert_e));
            if(!executed.has_value())
                return rollback(executed.error());
            result = ActivityClaimResult::CLAIMED;
            return db->execute("RELEASE unspoken_operation;");
        }

        const auto& row = (*rows_e)[0];
        if(std::get<0>(row) == "processed")
        {
            result = ActivityClaimResult::ALREADY_PROCESSED;
            return db->execute("RELEASE unspoken_operation;");
        }
        const auto claimed_at = std::get<1>(row);
        if(claimed_at.has_value() && *claimed_at > now_seconds - lease_seconds)
        {
            result = ActivityClaimResult::IN_PROGRESS;
            return db->execute("RELEASE unspoken_operation;");
        }

        auto update_e = db->statementFromStr(
            "UPDATE ap_seen_activities SET claimed_at = ? "
            "WHERE activity_uri = ? AND state = 'processing';");
        if(!update_e.has_value())
            return rollback(update_e.error());
        auto b = update_e->bind<int64_t, std::string>(
            now_seconds, std::string(activity_uri));
        if(!b.has_value())
            return rollback(b.error());
        auto executed = db->execute(std::move(*update_e));
        if(!executed.has_value())
            return rollback(executed.error());
        result = ActivityClaimResult::CLAIMED;
        return db->execute("RELEASE unspoken_operation;");
    };
    DO_OR_RETURN(withDataWrite(*db, txn));
    return result;
}

mw::E<void> Store::finalizeIncomingActivity(std::string_view activity_uri,
                                            int64_t now_seconds) const
{
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st, db->statementFromStr(
                         "UPDATE ap_seen_activities SET state = 'processed', "
                         "claimed_at = NULL, processed_at = ? "
                         "WHERE activity_uri = ? AND state = 'processing';"));
        DO_OR_RETURN((st.bind<int64_t, std::string>(
            now_seconds, std::string(activity_uri))));
        DO_OR_RETURN(db->execute(std::move(st)));
        if(db->changedRowsCount() != 1)
        {
            return std::unexpected(mw::runtimeError(
                "Inbox activity claim was lost before finalization"));
        }
        return {};
    };
    return withDataWrite(*db, txn);
}

mw::E<void> Store::releaseIncomingActivity(std::string_view activity_uri) const
{
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr(
                "DELETE FROM ap_seen_activities WHERE activity_uri = ? "
                "AND state = 'processing';"));
        DO_OR_RETURN(st.bind<std::string>(std::string(activity_uri)));
        return db->execute(std::move(st));
    };
    return withDataWrite(*db, txn);
}

mw::E<int64_t> Store::pruneIncomingActivities(int64_t cutoff_seconds,
                                              int batch_size) const
{
    if(batch_size <= 0)
    {
        return std::unexpected(mw::runtimeError(
            "Inbox activity maintenance batch size must be positive"));
    }
    int64_t pruned = 0;
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr(
                "DELETE FROM ap_seen_activities WHERE activity_uri IN ("
                " SELECT activity_uri FROM ap_seen_activities "
                " WHERE state = 'processed' AND processed_at < ? "
                " ORDER BY processed_at ASC LIMIT ?"
                ");"));
        DO_OR_RETURN((st.bind<int64_t, int>(cutoff_seconds, batch_size)));
        DO_OR_RETURN(db->execute(std::move(st)));
        pruned = db->changedRowsCount();
        ASSIGN_OR_RETURN(
            auto select,
            db->statementFromStr("SELECT activity_uri FROM ap_inbox_activities "
                                 "WHERE processed_at<? "
                                 "ORDER BY processed_at,activity_uri LIMIT ?"));
        DO_OR_RETURN((select.bind<int64_t, int64_t>(
            cutoff_seconds, std::max<int64_t>(0, batch_size - pruned))));
        ASSIGN_OR_RETURN(auto expired,
                         db->eval<std::string>(std::move(select)));
        for(const auto& row : expired)
        {
            const auto& uri = std::get<0>(row);
            ASSIGN_OR_RETURN(
                auto receipts,
                db->statementFromStr(
                    "DELETE FROM ap_inbox_receipts WHERE activity_uri=?"));
            DO_OR_RETURN(receipts.bind<std::string>(uri));
            DO_OR_RETURN(db->execute(std::move(receipts)));
            ASSIGN_OR_RETURN(
                auto activity,
                db->statementFromStr(
                    "DELETE FROM ap_inbox_activities WHERE activity_uri=?"));
            DO_OR_RETURN(activity.bind<std::string>(uri));
            DO_OR_RETURN(db->execute(std::move(activity)));
            pruned += db->changedRowsCount();
        }

        return {};
    };
    DO_OR_RETURN(withDataWrite(*db, txn));
    return pruned;
}

mw::E<int64_t> Store::collectUnreferencedRemoteActors(int64_t cutoff_seconds,
                                                      int batch_size) const
{
    if(batch_size <= 0)
        return std::unexpected(mw::runtimeError("Invalid collection batch"));
    int64_t removed = 0;
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(auto st,
                         db->statementFromStr(
                             "DELETE FROM ap_remote_actors WHERE id IN ("
                             "SELECT a.id FROM ap_remote_actors a WHERE "
                             "a.retained_at < ? "
                             "AND NOT EXISTS(SELECT 1 FROM ap_actor_refs r "
                             "WHERE r.actor_uri=a.uri) "
                             "AND NOT EXISTS(SELECT 1 FROM ap_follows f WHERE "
                             "f.follower_uri=a.uri OR f.followee_uri=a.uri) "
                             "AND NOT EXISTS(SELECT 1 FROM ap_likes l WHERE "
                             "l.actor_uri=a.uri) "
                             "AND NOT EXISTS(SELECT 1 FROM ap_boosts b WHERE "
                             "b.actor_uri=a.uri) "
                             "AND NOT EXISTS(SELECT 1 FROM ap_reactions r "
                             "WHERE r.actor_uri=a.uri) "
                             "AND NOT EXISTS(SELECT 1 FROM ap_jobs j WHERE "
                             "j.state IN ('pending','running') AND "
                             "(instr(j.payload_json,a.uri)>0 "
                             "OR instr(j.payload_json,a.inbox)>0)) "
                             "ORDER BY a.retained_at,a.id LIMIT ?)"));
        DO_OR_RETURN((st.bind<int64_t, int64_t>(cutoff_seconds, batch_size)));
        DO_OR_RETURN(db->execute(std::move(st)));
        removed = db->changedRowsCount();
        return {};
    };
    DO_OR_RETURN(withDataWrite(*db, txn));
    return removed;
}

mw::E<void> Store::pinActor(std::string_view actor_uri,
                            std::string_view owner_kind,
                            std::string_view owner_key) const
{
    if(owner_kind.empty() || owner_key.empty())
        return std::unexpected(mw::runtimeError("Actor pin requires an owner"));
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(auto actor, getRemoteActorByUri(actor_uri));
        if(!actor)
            return std::unexpected(mw::runtimeError("Unknown remote actor"));
        ASSIGN_OR_RETURN(
            auto st, db->statementFromStr(
                         "INSERT OR IGNORE INTO ap_actor_refs VALUES (?,?,?)"));
        DO_OR_RETURN((st.bind<std::string, std::string, std::string>(
            std::string(actor_uri), std::string(owner_kind),
            std::string(owner_key))));
        return db->execute(std::move(st));
    };
    return withDataWrite(*db, txn);
}

mw::E<void> Store::unpinActor(std::string_view actor_uri,
                              std::string_view owner_kind,
                              std::string_view owner_key, int64_t now_ts) const
{
    auto txn = [&]() -> mw::E<void>
    {
        ASSIGN_OR_RETURN(
            auto st,
            db->statementFromStr("DELETE FROM ap_actor_refs WHERE actor_uri=? "
                                 "AND owner_kind=? AND owner_key=?"));
        DO_OR_RETURN((st.bind<std::string, std::string, std::string>(
            std::string(actor_uri), std::string(owner_kind),
            std::string(owner_key))));
        DO_OR_RETURN(db->execute(std::move(st)));
        return touchRemoteActorRetentionByUri(*db, actor_uri, now_ts);
    };
    return withDataWrite(*db, txn);
}

} // namespace ap
