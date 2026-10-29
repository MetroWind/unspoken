#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <nlohmann/json.hpp>

namespace ap
{

// The ActivityStreams public audience identifier.
inline constexpr std::string_view AS_PUBLIC =
    "https://www.w3.org/ns/activitystreams#Public";

// Keys for server-level signed fetches.
struct SystemActor
{
    std::string private_key_pem;
    std::string public_key_pem;
    int64_t created_at = 0;
};

// A fetched remote identity, retained only when referenced.
struct RemoteActor
{
    int64_t id = 0;
    std::string uri;      // the actor id
    std::string username; // preferredUsername
    std::string domain;   // for @user@domain handle
    std::string display_name;
    std::string inbox;
    std::optional<std::string> shared_inbox;
    std::string public_key_pem;
    std::string public_key_id; // the keyId in signatures
    std::string actor_json;    // raw cached actor doc
    int64_t fetched_at = 0;
    int64_t retained_at = 0; // latest local-reference transition
};

// Remote identity and its prior retention status.
struct RemoteActorResolution
{
    // The retained or transient document selected by lookup.
    RemoteActor actor;
    // Whether the document was retained before this lookup began.
    bool retained = false;
};

// A normalized activity with its unmodified wire document.
struct Activity
{
    std::string id;        // canonical URI
    std::string type;      // "Create", "Follow", ...
    std::string actor;     // canonical actor URI
    nlohmann::json object; // embedded object or {"id": "..."}
    std::vector<std::string> to;
    std::vector<std::string> cc;
    nlohmann::json raw; // the original, for forwarding verbatim
};

// Exact request bytes and target used for signature verification.
struct IncomingHttpRequest
{
    std::string method;
    std::string target;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

// Identity established by successful HTTP signature verification.
struct VerifiedSignature
{
    // The actor URI authenticated by the selected public key.
    std::string actor_uri;
    // The precise key identifier supplied in the Signature header.
    std::string key_id;
    // The retained or transient actor document used for verification.
    RemoteActor actor;
    // Whether the actor existed in durable storage before verification.
    bool actor_was_retained = false;
    // Whether a freshly fetched key successfully replaced a retained key.
    bool key_was_refreshed = false;
};

// Local actor identity and private signing material.
struct SigningActor
{
    std::string actor_uri;
    std::string key_id;
    std::string private_key_pem;
};

enum class FollowState
{
    PENDING,
    ACCEPTED,
};

inline std::string_view followStateToStr(FollowState s)
{
    switch(s)
    {
    case FollowState::PENDING:
        return "pending";
    case FollowState::ACCEPTED:
        return "accepted";
    }
    return "pending";
}

inline std::optional<FollowState> followStateFromStr(std::string_view s)
{
    if(s == "pending")
        return FollowState::PENDING;
    if(s == "accepted")
        return FollowState::ACCEPTED;
    return std::nullopt;
}

// Protocol Follow value.
struct Follow
{
    int64_t id = 0;
    std::string follower_uri;
    std::string followee_uri;
    FollowState state = FollowState::PENDING;
    std::optional<std::string> follow_activity_uri;
    int64_t created_at = 0;
};

// Protocol ActorCollectionItem value.
struct ActorCollectionItem
{
    int64_t id = 0;
    std::string actor_uri;
};

// Protocol Like value.
struct Like
{
    int64_t id = 0;
    std::string actor_uri;
    std::string post_uri;
    std::optional<std::string> activity_uri;
    int64_t created_at = 0;
};

// Protocol Boost value.
struct Boost
{
    int64_t id = 0;
    std::string actor_uri;
    std::string post_uri;
    std::optional<std::string> activity_uri;
    int64_t created_at = 0;
};

// Protocol Reaction value.
struct Reaction
{
    int64_t id = 0;
    std::string actor_uri;
    std::string post_uri;
    std::string emoji; // unicode emoji or :shortcode:
    std::optional<std::string> remote_emoji_url;
    std::optional<std::string> remote_emoji_media_type;
    std::optional<std::string> activity_uri;
    int64_t created_at = 0;
};

// Protocol Job value.
struct Job
{
    int64_t id = 0;
    std::string kind; // 'deliver' | 'resolve_actor' | ...
    std::string payload_json;
    std::string state; // 'pending' | 'running' | 'done' | 'failed'
    int64_t attempts = 0;
    int64_t run_after = 0; // earliest unix time to run
    std::optional<std::string> last_error;
    int64_t created_at = 0;
    std::string lease_token;
    int64_t lease_until = 0;
};

// Protocol Cursor value.
struct Cursor
{
    std::optional<int64_t> max_id; // items with id < max_id (older)
    std::optional<int64_t> min_id; // items with id > min_id (newer)
};

// Legacy inbox claim outcome used by the migration adapter.
enum class ActivityClaimResult
{
    CLAIMED,           // This request owns the processing lease.
    ALREADY_PROCESSED, // A previous request completed the activity.
    IN_PROGRESS,       // Another request owns an unexpired lease.
};

} // namespace ap
