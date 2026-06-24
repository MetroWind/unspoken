#pragma once

// The data module (design §7): the ONLY code that issues SQL. It
// exposes typed functions returning mw::E<T>; callers above this layer
// see only structs from the struct module, never a sqlite handle.

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <mw/database.hpp>
#include <mw/error.hpp>

#include "structs.hpp"

namespace unspoken
{

// Retry a write transaction that may see SQLITE_BUSY / SQLITE_LOCKED
// even after the connection's busy_timeout (e.g. during a WAL
// checkpoint). The callable should be idempotent: it may run more than
// once. Non-retryable errors are returned immediately. (Design §7.2.)
mw::E<void> withWriteRetry(const std::function<mw::E<void>()>& txn,
                           int max_retries = 5);

// True if an error looks like transient SQLite write contention.
bool isRetryableSqlError(const mw::Error& e);

// The interface that upper layers depend on. A mock implements this so
// federation/app logic is testable without real SQL.
class DataSourceInterface
{
public:
    virtual ~DataSourceInterface() = default;

    virtual mw::E<int64_t> getSchemaVersion() const = 0;

    // ── Users ───────────────────────────────────────────────────
    virtual mw::E<User> createUser(const NewUser& nu) const = 0;
    virtual mw::E<std::optional<User>>
    getUserById(int64_t id) const = 0;
    virtual mw::E<std::optional<User>>
    getUserByUsername(std::string_view username) const = 0;
    virtual mw::E<std::optional<User>>
    getUserByOidcSub(std::string_view iss, std::string_view sub) const = 0;
    virtual mw::E<void>
    updateUserProfile(int64_t id, std::string_view display_name,
                      std::string_view bio) const = 0;
    // Local user search by username / display-name substring (case-
    // insensitive), for the search page (§16.9). Remote (WebFinger)
    // search is Phase 6.
    virtual mw::E<std::vector<User>>
    searchUsers(std::string_view query, int limit) const = 0;

    // ── System actor ─────────────────────────────────────────────
    virtual mw::E<std::optional<SystemActor>> getSystemActor() const = 0;
    virtual mw::E<void>
    setSystemActor(std::string_view private_key_pem,
                   std::string_view public_key_pem) const = 0;

    // ── Remote actors ───────────────────────────────────────────
    virtual mw::E<RemoteActor>
    upsertRemoteActor(const RemoteActor& a) const = 0;
    virtual mw::E<std::optional<RemoteActor>>
    getRemoteActorById(int64_t id) const = 0;
    virtual mw::E<std::optional<RemoteActor>>
    getRemoteActorByUri(std::string_view uri) const = 0;

    // ── Posts ───────────────────────────────────────────────────
    // Inserts the post and its recipients. For local posts (uri unset)
    // the uri is assigned after insert as "<url_root>p/<id>"; the caller
    // supplies url_root via local_uri_prefix (e.g. ".../p/"). Returns
    // the inserted Post (with id and uri populated).
    virtual mw::E<Post>
    insertPost(const NewPost& np,
               const std::vector<PostRecipient>& recipients,
               std::string_view local_uri_prefix) const = 0;
    virtual mw::E<std::optional<Post>> getPostById(int64_t id) const = 0;
    virtual mw::E<std::optional<Post>>
    getPostByUri(std::string_view uri) const = 0;
    virtual mw::E<void> deletePost(int64_t id) const = 0;
    virtual mw::E<std::vector<PostRecipient>>
    getPostRecipients(int64_t post_id) const = 0;
    // Public global timeline: only 'public' posts, newest first, one
    // cursor page (design §16.2).
    virtual mw::E<std::vector<Post>>
    timelinePublic(const Cursor& c, int limit) const = 0;
    // Home timeline: posts by the user and by accounts they follow.
    virtual mw::E<std::vector<Post>>
    timelineHome(int64_t user_id, const Cursor& c, int limit) const = 0;
    // Posts authored by any of the given local users, newest first, one
    // cursor page. The service layer passes the viewer plus the local
    // accounts they follow to assemble the home timeline (§16.3).
    virtual mw::E<std::vector<Post>>
    postsForAuthors(const std::vector<int64_t>& local_author_ids,
                    const Cursor& c, int limit) const = 0;
    // Home timeline posts: authored by viewer/followed local accounts,
    // plus replies to the viewer's own local posts.
    virtual mw::E<std::vector<Post>>
    homeTimelinePosts(const std::vector<int64_t>& local_author_ids,
                      int64_t reply_author_id, const Cursor& c,
                      int limit) const = 0;
    // All posts that share a reply chain root (by in_reply_to_uri /
    // uri), for the thread view.
    virtual mw::E<std::vector<Post>>
    threadFor(std::string_view root_uri) const = 0;

    // ── Follows ─────────────────────────────────────────────────
    virtual mw::E<void> addFollow(const Follow& f) const = 0;
    virtual mw::E<std::optional<Follow>>
    getFollow(std::string_view follower_uri,
              std::string_view followee_uri) const = 0;
    virtual mw::E<void>
    setFollowState(std::string_view follower_uri,
                   std::string_view followee_uri, FollowState s) const = 0;
    virtual mw::E<void>
    removeFollow(std::string_view follower_uri,
                 std::string_view followee_uri) const = 0;
    // The follower actor URIs of a given (local) actor.
    virtual mw::E<std::vector<std::string>>
    followerUris(std::string_view followee_uri) const = 0;
    virtual mw::E<std::vector<std::string>>
    followingUris(std::string_view follower_uri) const = 0;
    virtual mw::E<std::vector<ActorCollectionItem>>
    followerPage(std::string_view followee_uri, const Cursor& c,
                 int limit) const = 0;
    virtual mw::E<std::vector<ActorCollectionItem>>
    followingPage(std::string_view follower_uri, const Cursor& c,
                  int limit) const = 0;

    // ── Likes / boosts / reactions / bookmarks ──────────────────
    virtual mw::E<void> addLike(const Like& l) const = 0;
    virtual mw::E<void>
    removeLike(std::string_view actor_uri, std::string_view post_uri) const = 0;
    virtual mw::E<std::vector<Like>>
    likesForPost(std::string_view post_uri) const = 0;

    virtual mw::E<void> addBoost(const Boost& b) const = 0;
    virtual mw::E<void>
    removeBoost(std::string_view actor_uri,
                std::string_view post_uri) const = 0;

    virtual mw::E<void> addReaction(const Reaction& r) const = 0;
    virtual mw::E<void>
    removeReaction(std::string_view actor_uri, std::string_view post_uri,
                   std::string_view emoji) const = 0;
    virtual mw::E<std::vector<Reaction>>
    reactionsForPost(std::string_view post_uri) const = 0;

    virtual mw::E<void> addBookmark(int64_t user_id, int64_t post_id) const = 0;
    virtual mw::E<void>
    removeBookmark(int64_t user_id, int64_t post_id) const = 0;
    virtual mw::E<bool>
    isBookmarked(int64_t user_id, int64_t post_id) const = 0;
    virtual mw::E<std::vector<Post>>
    bookmarksFor(int64_t user_id, const Cursor& c, int limit) const = 0;

    // ── Attachments ─────────────────────────────────────────────
    virtual mw::E<int64_t> insertAttachment(const Attachment& a) const = 0;
    virtual mw::E<void>
    attachToPost(int64_t attachment_id, int64_t post_id) const = 0;
    virtual mw::E<std::vector<Attachment>>
    attachmentsForPost(int64_t post_id) const = 0;

    // ── Sessions ────────────────────────────────────────────────
    virtual mw::E<void>
    createSession(std::string_view token, int64_t user_id,
                  int64_t expires_at) const = 0;
    // Returns the user_id if the session exists and has not expired.
    virtual mw::E<std::optional<int64_t>>
    getSessionUser(std::string_view token, int64_t now) const = 0;
    virtual mw::E<void> deleteSession(std::string_view token) const = 0;

    // ── Pending OIDC logins (state + nonce) ─────────────────────
    virtual mw::E<void>
    addPendingLogin(std::string_view state, std::string_view nonce,
                    int64_t created_at) const = 0;
    // Atomically fetch-and-remove the nonce for a state. nullopt if the
    // state is unknown (CSRF mismatch).
    virtual mw::E<std::optional<std::string>>
    takePendingLogin(std::string_view state) const = 0;

    // ── Activity dedup ──────────────────────────────────────────
    // Returns true if newly inserted, false if already seen (the
    // activity is a redelivery).
    virtual mw::E<bool> markActivitySeen(std::string_view uri,
                                         int64_t now) const = 0;

    // ── Job queue ───────────────────────────────────────────────
    virtual mw::E<int64_t>
    enqueueJob(std::string_view kind, std::string_view payload_json,
               int64_t run_after, int64_t now) const = 0;
    // Atomically claim the oldest runnable job (pending, run_after<=now),
    // marking it 'running'. nullopt if none runnable.
    virtual mw::E<std::optional<Job>> claimJob(int64_t now) const = 0;
    virtual mw::E<void> completeJob(int64_t job_id) const = 0;
    // Record a failure; either reschedule with backoff (pending) or give
    // up (failed) when attempts reach max_retries.
    virtual mw::E<void>
    failJob(int64_t job_id, std::string_view error, int64_t now,
            int base_delay_seconds, int max_retries) const = 0;

protected:
    virtual mw::E<void> setSchemaVersion(int64_t v) const = 0;
};

// The concrete SQLite-backed data source. Each thread should hold its
// own instance (its own connection) over the same database file
// (design §7.2: one connection per thread + WAL).
class DataSourceSQLite : public DataSourceInterface
{
public:
    explicit DataSourceSQLite(std::unique_ptr<mw::SQLite> conn)
            : db(std::move(conn)) {}
    ~DataSourceSQLite() override = default;

    // Open (creating if needed) the database file, enable WAL, set
    // busy_timeout, and ensure the schema exists at version 1.
    static mw::E<std::unique_ptr<DataSourceSQLite>>
    fromFile(const std::string& db_file, int busy_timeout_ms = 5000);
    static mw::E<std::unique_ptr<DataSourceSQLite>> newFromMemory();

    mw::E<int64_t> getSchemaVersion() const override;

    mw::E<User> createUser(const NewUser& nu) const override;
    mw::E<std::optional<User>> getUserById(int64_t id) const override;
    mw::E<std::optional<User>>
    getUserByUsername(std::string_view username) const override;
    mw::E<std::optional<User>>
    getUserByOidcSub(std::string_view iss, std::string_view sub) const override;
    mw::E<void> updateUserProfile(int64_t id, std::string_view display_name,
                                  std::string_view bio) const override;
    mw::E<std::vector<User>>
    searchUsers(std::string_view query, int limit) const override;
    mw::E<std::optional<SystemActor>> getSystemActor() const override;
    mw::E<void> setSystemActor(std::string_view private_key_pem,
                               std::string_view public_key_pem) const override;

    mw::E<RemoteActor> upsertRemoteActor(const RemoteActor& a) const override;
    mw::E<std::optional<RemoteActor>>
    getRemoteActorById(int64_t id) const override;
    mw::E<std::optional<RemoteActor>>
    getRemoteActorByUri(std::string_view uri) const override;

    mw::E<Post> insertPost(const NewPost& np,
                           const std::vector<PostRecipient>& recipients,
                           std::string_view local_uri_prefix) const override;
    mw::E<std::optional<Post>> getPostById(int64_t id) const override;
    mw::E<std::optional<Post>>
    getPostByUri(std::string_view uri) const override;
    mw::E<void> deletePost(int64_t id) const override;
    mw::E<std::vector<PostRecipient>>
    getPostRecipients(int64_t post_id) const override;
    mw::E<std::vector<Post>>
    timelinePublic(const Cursor& c, int limit) const override;
    mw::E<std::vector<Post>>
    timelineHome(int64_t user_id, const Cursor& c, int limit) const override;
    mw::E<std::vector<Post>>
    postsForAuthors(const std::vector<int64_t>& local_author_ids,
                    const Cursor& c, int limit) const override;
    mw::E<std::vector<Post>>
    homeTimelinePosts(const std::vector<int64_t>& local_author_ids,
                      int64_t reply_author_id, const Cursor& c,
                      int limit) const override;
    mw::E<std::vector<Post>> threadFor(std::string_view root_uri) const override;

    mw::E<void> addFollow(const Follow& f) const override;
    mw::E<std::optional<Follow>>
    getFollow(std::string_view follower_uri,
              std::string_view followee_uri) const override;
    mw::E<void> setFollowState(std::string_view follower_uri,
                               std::string_view followee_uri,
                               FollowState s) const override;
    mw::E<void> removeFollow(std::string_view follower_uri,
                             std::string_view followee_uri) const override;
    mw::E<std::vector<std::string>>
    followerUris(std::string_view followee_uri) const override;
    mw::E<std::vector<std::string>>
    followingUris(std::string_view follower_uri) const override;
    mw::E<std::vector<ActorCollectionItem>>
    followerPage(std::string_view followee_uri, const Cursor& c,
                 int limit) const override;
    mw::E<std::vector<ActorCollectionItem>>
    followingPage(std::string_view follower_uri, const Cursor& c,
                  int limit) const override;

    mw::E<void> addLike(const Like& l) const override;
    mw::E<void> removeLike(std::string_view actor_uri,
                           std::string_view post_uri) const override;
    mw::E<std::vector<Like>>
    likesForPost(std::string_view post_uri) const override;

    mw::E<void> addBoost(const Boost& b) const override;
    mw::E<void> removeBoost(std::string_view actor_uri,
                            std::string_view post_uri) const override;

    mw::E<void> addReaction(const Reaction& r) const override;
    mw::E<void> removeReaction(std::string_view actor_uri,
                               std::string_view post_uri,
                               std::string_view emoji) const override;
    mw::E<std::vector<Reaction>>
    reactionsForPost(std::string_view post_uri) const override;

    mw::E<void> addBookmark(int64_t user_id, int64_t post_id) const override;
    mw::E<void> removeBookmark(int64_t user_id, int64_t post_id) const override;
    mw::E<bool> isBookmarked(int64_t user_id, int64_t post_id) const override;
    mw::E<std::vector<Post>>
    bookmarksFor(int64_t user_id, const Cursor& c, int limit) const override;

    mw::E<int64_t> insertAttachment(const Attachment& a) const override;
    mw::E<void> attachToPost(int64_t attachment_id,
                             int64_t post_id) const override;
    mw::E<std::vector<Attachment>>
    attachmentsForPost(int64_t post_id) const override;

    mw::E<void> createSession(std::string_view token, int64_t user_id,
                              int64_t expires_at) const override;
    mw::E<std::optional<int64_t>>
    getSessionUser(std::string_view token, int64_t now) const override;
    mw::E<void> deleteSession(std::string_view token) const override;

    mw::E<void> addPendingLogin(std::string_view state, std::string_view nonce,
                                int64_t created_at) const override;
    mw::E<std::optional<std::string>>
    takePendingLogin(std::string_view state) const override;

    mw::E<bool> markActivitySeen(std::string_view uri,
                                 int64_t now) const override;

    mw::E<int64_t> enqueueJob(std::string_view kind,
                              std::string_view payload_json,
                              int64_t run_after, int64_t now) const override;
    mw::E<std::optional<Job>> claimJob(int64_t now) const override;
    mw::E<void> completeJob(int64_t job_id) const override;
    mw::E<void> failJob(int64_t job_id, std::string_view error, int64_t now,
                        int base_delay_seconds, int max_retries) const override;

    // Do not use.
    DataSourceSQLite() = default;

protected:
    mw::E<void> setSchemaVersion(int64_t v) const override;

private:
    static mw::E<void> createSchema(mw::SQLite& db);

    std::unique_ptr<mw::SQLite> db;
};

} // namespace unspoken
