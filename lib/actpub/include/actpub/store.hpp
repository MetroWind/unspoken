#pragma once

#include "transaction.hpp"
#include "types.hpp"

namespace ap
{

// Concrete federation persistence on a borrowed SQLite connection.
// Writes compose with a caller transaction, or own a short transaction.
class Store
{
public:
    // The connection must outlive this non-owning store.
    explicit Store(mw::SQLite& connection) : db(&connection) {}
    // Create/upgrade only the library's prefixed schema.
    mw::E<void> migrate() const;
    // Share the exact connection with application repositories.
    mw::SQLite& connection() const
    {
        return *db;
    }

    // Read protocol state using this store's connection.
    mw::E<std::optional<SystemActor>> getSystemActor() const;

    // Persist protocol state using this store's connection.
    mw::E<void> setSystemActor(std::string_view private_key_pem,
                               std::string_view public_key_pem) const;

    // Persist protocol state using this store's connection.
    mw::E<RemoteActor> upsertRemoteActor(const RemoteActor& a) const;

    // Read protocol state using this store's connection.
    mw::E<std::optional<RemoteActor>> getRemoteActorById(int64_t id) const;

    // Read protocol state using this store's connection.
    mw::E<std::optional<RemoteActor>>
    getRemoteActorByUri(std::string_view uri) const;

    // Persist protocol state using this store's connection.
    mw::E<void> touchRemoteActorRetention(std::string_view actor_uri,
                                          int64_t now_seconds) const;

    // Persist protocol state using this store's connection.
    mw::E<void> addFollow(const Follow& f) const;

    // Read protocol state using this store's connection.
    mw::E<std::optional<Follow>> getFollow(std::string_view follower_uri,
                                           std::string_view followee_uri) const;

    // Persist protocol state using this store's connection.
    mw::E<void> setFollowState(std::string_view follower_uri,
                               std::string_view followee_uri,
                               FollowState s) const;

    // Persist protocol state using this store's connection.
    mw::E<void> removeFollow(std::string_view follower_uri,
                             std::string_view followee_uri) const;

    // Read protocol state using this store's connection.
    mw::E<std::vector<std::string>>
    followerUris(std::string_view followee_uri) const;

    // Read protocol state using this store's connection.
    mw::E<std::vector<std::string>>
    followingUris(std::string_view follower_uri) const;

    // Read protocol state using this store's connection.
    mw::E<std::vector<ActorCollectionItem>>
    followerPage(std::string_view followee_uri, const Cursor& c,
                 int limit) const;

    // Read protocol state using this store's connection.
    mw::E<std::vector<ActorCollectionItem>>
    followingPage(std::string_view follower_uri, const Cursor& c,
                  int limit) const;

    // Persist protocol state using this store's connection.
    mw::E<void> addLike(const Like& l) const;

    // Persist protocol state using this store's connection.
    mw::E<void> removeLike(std::string_view actor_uri,
                           std::string_view post_uri) const;

    // Read protocol state using this store's connection.
    mw::E<std::vector<Like>> likesForPost(std::string_view post_uri) const;

    // Persist protocol state using this store's connection.
    mw::E<void> addBoost(const Boost& b) const;

    // Persist protocol state using this store's connection.
    mw::E<void> removeBoost(std::string_view actor_uri,
                            std::string_view post_uri) const;

    // Read protocol state using this store's connection.
    mw::E<std::vector<Boost>> boostsForPost(std::string_view post_uri) const;

    // Persist protocol state using this store's connection.
    mw::E<void> addReaction(const Reaction& r) const;

    // Persist protocol state using this store's connection.
    mw::E<void> removeReaction(std::string_view actor_uri,
                               std::string_view post_uri,
                               std::string_view emoji) const;

    // Read protocol state using this store's connection.
    mw::E<std::vector<Reaction>>
    reactionsForPost(std::string_view post_uri) const;

    // Persist a job in the caller's transaction, without network I/O.
    mw::E<int64_t> enqueueJob(std::string_view kind, std::string_view payload,
                              int64_t run_after, int64_t now) const;
    // Claim pending work or recover an expired lease using a fresh token.
    mw::E<std::optional<Job>> claimJob(int64_t now,
                                       int64_t lease_seconds = 120) const;
    // Complete only the job lease held by this exact claimant.
    mw::E<void> completeJob(const Job& job) const;
    // Record failure only for this lease and schedule a bounded retry.
    mw::E<void> failJob(const Job& job, std::string_view error, int64_t now,
                        int base_delay_seconds, int max_retries) const;

    // Compatibility receipt persistence on the shared connection.
    mw::E<ActivityClaimResult>
    claimIncomingActivity(std::string_view activity_uri, int64_t now_seconds,
                          int64_t lease_seconds) const;

    // Compatibility receipt persistence on the shared connection.
    mw::E<void> finalizeIncomingActivity(std::string_view activity_uri,
                                         int64_t now_seconds) const;

    // Compatibility receipt persistence on the shared connection.
    mw::E<void> releaseIncomingActivity(std::string_view activity_uri) const;

    // Compatibility receipt persistence on the shared connection.
    mw::E<int64_t> pruneIncomingActivities(int64_t cutoff_seconds,
                                           int batch_size) const;

    // Collect identities without protocol references or explicit host pins.
    mw::E<int64_t> collectUnreferencedRemoteActors(int64_t cutoff_seconds,
                                                   int batch_size) const;

    // Retain a remote identity referenced only by application-owned records.
    mw::E<void> pinActor(std::string_view actor_uri,
                         std::string_view owner_kind,
                         std::string_view owner_key) const;
    // Release one application reference and start its collection grace period.
    mw::E<void> unpinActor(std::string_view actor_uri,
                           std::string_view owner_kind,
                           std::string_view owner_key, int64_t now) const;

private:
    mw::SQLite* db;
};

} // namespace ap
