#pragma once

#include <set>
#include "store.hpp"
#include "transport.hpp"

namespace ap
{

// Finite protocol limits and identities, independent of host configuration.
struct FederationConfig
{
    TransportConfig transport;
    std::string activity_uri_prefix;
    std::string system_actor_uri;
    size_t max_inbox_bytes = 1024 * 1024;
    size_t max_document_bytes = 2 * 1024 * 1024;
    size_t max_json_depth = 64;
    size_t max_recipients = 100;
    int fetch_depth = 20;
    int job_lease_seconds = 1100;
    size_t max_fetch_requests = 32;
    int max_retries = 8;
    int retry_base_seconds = 30;
    int64_t receipt_retention_seconds = 2592000;
};

// A library-managed local actor, with host-produced public document fields.
struct LocalActor
{
    std::string uri;
    std::string key_id;
    std::string private_key_pem;
    nlohmann::json document;
};

// Application disposition after protocol authentication and authorization.
enum class Decision
{
    ACCEPT,
    IGNORE,
    REJECT,
    PENDING_APPROVAL
};

// One registered local recipient of an incoming operation.
struct LocalRecipient
{
    std::string actor_uri;
};

// An incoming protocol operation; content has no HTML safety guarantee.
class ValidatedActivity
{
public:
    // Return the normalized activity, including its untrusted content fields.
    const Activity& activity() const
    {
        return value;
    }

private:
    explicit ValidatedActivity(Activity input) : value(std::move(input)) {}
    Activity value;
    friend class Session;
};

// An accepted protocol effect for the application's transactional projection.
struct AppliedEvent
{
    Activity activity;
    std::string recipient_uri;
    RemoteActor actor;
    bool global_effect = true;
};

// Host policy/projection integration; all persistence uses the shared SQLite.
class Application
{
public:
    virtual ~Application() = default;
    // Choose relevance or moderation; cannot override failed protocol checks.
    virtual mw::E<Decision> decide(Transaction& tx,
                                   const ValidatedActivity& activity,
                                   const LocalRecipient& recipient) = 0;
    // Update host records atomically with protocol effects and receipts.
    // Content is untrusted; perform host-specific sanitization before display.
    virtual mw::E<void> apply(Transaction& tx, const AppliedEvent& event) = 0;
};

// Authenticated, bounded evidence prepared without holding a write lock.
class PreparedInbox
{
public:
    PreparedInbox(const PreparedInbox&) = delete;
    PreparedInbox& operator=(const PreparedInbox&) = delete;
    PreparedInbox(PreparedInbox&&) = default;
    PreparedInbox& operator=(PreparedInbox&&) = default;

private:
    PreparedInbox() = default;
    Activity activity;
    VerifiedSignature verified;
    std::string endpoint_actor;
    std::vector<std::pair<std::string, std::string>> forward_collections;
    nlohmann::json forward_document;
    // Origin-fetched public boost target, staged until inbox commit.
    std::optional<nlohmann::json> announced_object;
    std::optional<RemoteActor> announced_author;
    int64_t prepared_at = 0;
    const void* session_identity = nullptr;
    friend class Session;
};

// Durable incoming outcome, distinct from an operational failure.
struct InboxResult
{
    bool duplicate = false;
    bool applied = false;
    bool forwarded = false;
};

// Identity of a provisionally queued local operation; commit before success.
struct Publication
{
    std::string activity_uri;
    int64_t sequence = 0;
    size_t target_count = 0;
};

// Federation operations on one caller-owned connection and transport context.
class Session
{
public:
    // Borrow all dependencies; they must outlive the session.
    Session(const FederationConfig& config, mw::SQLite& db,
            mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
            Application& application);
    // Initialize the library's schema before routes/workers run.
    mw::E<void> migrate();
    // Persist a host-supplied actor identity; never infer it from a URL prefix.
    mw::E<void> registerActor(Transaction& tx, const LocalActor& actor);
    // Look up an exact local actor identity, including signing metadata.
    mw::E<std::optional<LocalActor>> localActor(std::string_view uri) const;
    // Read a protocol object snapshot; content remains untrusted for rendering.
    mw::E<std::optional<nlohmann::json>> object(std::string_view uri) const;
    // Read a snapshot only when the supplied authenticated actor may view it.
    mw::E<std::optional<nlohmann::json>>
    objectForActor(std::string_view uri,
                   std::string_view authenticated_actor_uri = "") const;
    // Authenticate a protocol GET without granting any object permissions.
    mw::E<VerifiedSignature> authenticate(const IncomingHttpRequest& request,
                                          int64_t now);
    // Return a public-only outbox page using stable library sequence cursors.
    mw::E<nlohmann::json> outboxPage(std::string_view actor_uri,
                                     const Cursor& cursor, int limit,
                                     std::string_view self_uri) const;
    // Record a local activity and recipient snapshot atomically, without I/O.
    mw::E<Publication> publish(Transaction& tx, const nlohmann::json& activity,
                               int64_t now = 0);
    // Prepare signature/object evidence outside any write transaction.
    mw::E<PreparedInbox> prepareInbox(const IncomingHttpRequest& request,
                                      std::string_view endpoint_actor,
                                      int64_t now);
    // Commit accepted protocol effects, host projections, and receipts
    // together.
    mw::E<InboxResult> acceptInbox(PreparedInbox&& prepared, int64_t now);
    // Process one leased delivery/resolve job; false means the queue is idle.
    mw::E<bool> runOnce(int64_t now);
    // Fetch a remote object using a registered local signing identity.
    mw::E<nlohmann::json> fetchObject(std::string_view uri);
    // Fetch a remote content object and atomically project accepted content.
    mw::E<nlohmann::json> fetchAndStoreObject(std::string_view uri);
    // Preserve immutable legacy delivery identities during Unspoken migration.
    mw::E<Publication> enqueue(Transaction& tx, std::string_view signer,
                               const nlohmann::json& activity,
                               const std::vector<std::string>& inboxes,
                               int64_t now = 0);

private:
    const FederationConfig& config;
    mw::SQLite& db;
    mw::CryptoInterface& crypto;
    mw::HTTPSessionInterface& http;
    Application& application;
    Store store;
    mw::E<void> checkTransaction(Transaction& tx) const;
    mw::E<SigningActor> signer(std::string_view uri) const;
    mw::E<VerifiedSignature> verify(const IncomingHttpRequest& request,
                                    int64_t now);
    mw::E<std::vector<std::string>> recipients(const Activity& activity) const;
    mw::E<void> importFetchedObject(const nlohmann::json& document,
                                    size_t& budget);
    mw::E<void> fetchThread(std::string_view uri, int depth,
                            std::set<std::string>& seen, size_t& budget);
    mw::E<bool> applyProtocol(Transaction& tx, const PreparedInbox& prepared,
                              std::string_view recipient, Decision decision,
                              int64_t now);
};

} // namespace ap
