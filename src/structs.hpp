#pragma once

// The struct module (design §8): pure data definitions for the notable
// domain objects. No behavior beyond trivial helpers. Depended on by
// every other module.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>
#include <actpub/types.hpp>

namespace unspoken
{

// The ActivityStreams public-addressing IRI. Defined ONCE here and
// referenced everywhere (design §8, decision D3) so a typo can never
// silently break public-visibility detection. The full IRI is always
// what we emit on output; isPublicAddress() (JSON-LD layer) recognizes
// the compact/bare input forms.
using ap::AS_PUBLIC;

enum class Visibility
{
    PUBLIC,
    UNLISTED,
    FOLLOWERS,
    DIRECT,
};

// Serialize/parse the Visibility enum to the lowercase tokens stored in
// posts.visibility ('public'|'unlisted'|'followers'|'direct').
inline std::string_view visibilityToStr(Visibility v)
{
    switch(v)
    {
    case Visibility::PUBLIC:    return "public";
    case Visibility::UNLISTED:  return "unlisted";
    case Visibility::FOLLOWERS: return "followers";
    case Visibility::DIRECT:    return "direct";
    }
    return "public";
}

inline std::optional<Visibility> visibilityFromStr(std::string_view s)
{
    if(s == "public")    return Visibility::PUBLIC;
    if(s == "unlisted")  return Visibility::UNLISTED;
    if(s == "followers") return Visibility::FOLLOWERS;
    if(s == "direct")    return Visibility::DIRECT;
    return std::nullopt;
}

using ap::FollowState;
using ap::followStateFromStr;
using ap::followStateToStr;

// A local account. One row per OIDC subject that finished username
// setup.
struct User
{
    int64_t id = 0;
    std::string username;       // immutable once set
    std::string display_name;
    std::string bio;            // markdown source
    std::optional<int64_t> avatar_attachment_id;
    std::optional<int64_t> banner_attachment_id;
    std::string oidc_iss;
    std::string oidc_sub;
    std::string private_key_pem;
    std::string public_key_pem;
    int64_t created_at = 0;     // unix seconds
};

// Fields needed to create a new user (id/created_at filled by the DB).
struct NewUser
{
    std::string username;
    std::string display_name;
    std::string bio;
    std::string oidc_iss;
    std::string oidc_sub;
    std::string private_key_pem;
    std::string public_key_pem;
};

// Server-wide ActivityPub actor for keyless server operations. Its
// keypair is persisted once and reused across restarts.
using ap::SystemActor;
// A remote actor document. Values fetched only for one operation have id ==
// 0; values retained by the data layer have id > 0.
using ap::RemoteActor;
// A remote actor lookup result and whether it was retained before lookup.
using ap::RemoteActorResolution;
// A post. BOTH local and remote posts live in one table (PRD line 207).
struct Post
{
    int64_t id = 0;
    std::string uri;            // local: url_root/p/<id>; remote: origin URI
    std::optional<int64_t> local_author_id;
    std::optional<int64_t> remote_author_id;
    std::string content_html;   // rendered, sanitized HTML
    std::optional<std::string> content_source; // markdown source (local only)
    std::optional<std::string> summary;         // content warning text
    bool sensitive = false;
    Visibility visibility = Visibility::PUBLIC;
    std::optional<std::string> in_reply_to_uri;
    int64_t created_at = 0;     // local insertion time (cursor ordering)
    std::optional<std::string> published; // original timestamp (remote)
};

// Fields to create a new post. The uri for local posts is assigned
// after insert (it embeds the new id), so insertPost backfills it.
struct NewPost
{
    std::optional<std::string> uri; // set for remote; nullopt for local
    std::optional<int64_t> local_author_id;
    std::optional<int64_t> remote_author_id;
    std::string content_html;
    std::optional<std::string> content_source;
    std::optional<std::string> summary;
    bool sensitive = false;
    Visibility visibility = Visibility::PUBLIC;
    std::optional<std::string> in_reply_to_uri;
    std::optional<std::string> published;
};

// One row per (post, recipient) of the addressing audience. Used for
// private-post authorization and delivery.
struct PostRecipient
{
    int64_t post_id = 0;
    std::string recipient_uri;  // actor URI or Public/Followers collection
    std::string field;          // "to" | "cc"
};

struct Attachment
{
    int64_t id = 0;
    // Relation metadata populated for post attachment views.
    std::optional<int64_t> post_id;
    std::string sha256;         // lowercase hex
    std::string extension;      // lowercase, no dot; local attachments only
    std::string media_type;     // MIME
    std::string original_name;
    bool is_image = false;
    // Relation metadata populated for post attachment views.
    bool sensitive = false;
    std::optional<std::string> remote_url; // set for remote attachments
};

// Maximum number of metadata rows a local profile may contain.
inline constexpr int MAX_PROFILE_FIELDS = 8;

// One local profile metadata row owned by a user.
struct UserProfileField
{
    int64_t id = 0;
    int64_t user_id = 0;
    std::string label;
    std::string value;
    int sort_order = 0;
};

// Editable profile data submitted as a complete profile state.
struct UserProfileUpdate
{
    std::string display_name;
    std::string bio;
    std::optional<int64_t> avatar_attachment_id;
    std::optional<int64_t> banner_attachment_id;
    std::vector<UserProfileField> fields;
};

// One profile metadata row after Markdown rendering for ActivityPub output.
struct RenderedProfileField
{
    std::string label;
    std::string value_html;
};

// A follow relationship. Stores actor URIs so it uniformly covers local
// and remote on both sides.
using ap::ActorCollectionItem;
using ap::Boost;
using ap::Follow;
using ap::Like;
using ap::Reaction;
// A persisted background job (design §14).
using ap::Job;
// A normalized, parser-friendly view of an incoming activity (§9).
using ap::Activity;
// Cursor pagination (decision C4). Keyed on the integer id.
using ap::Cursor;
} // namespace unspoken
