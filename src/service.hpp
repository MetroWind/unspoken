#pragma once

// The service layer: local-only business logic (Phase 3). Handlers stay
// thin (design §1.2) and call these methods; a future C2S API reuses the
// same surface. Federation (signing, delivery, remote fetch) is layered on
// in later phases — this module performs only local persistence and view
// assembly, with no network egress.

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>
#include <mw/error.hpp>

#include "config.hpp"
#include "data.hpp"
#include "emoji.hpp"
#include "structs.hpp"

namespace unspoken
{

// Parameters for composing a new local post.
struct ComposeParams
{
    std::string source;                       // markdown
    Visibility visibility = Visibility::PUBLIC;
    std::optional<std::string> summary;       // content warning
    bool sensitive = false;
    std::optional<std::string> in_reply_to_uri;
    std::vector<int64_t> attachment_ids;      // draft attachments to attach
};

class Service
{
public:
    Service(const Config& conf, const DataSourceInterface& data_source,
            const EmojiRegistry& emoji_registry)
            : config(conf), data(data_source), emoji(emoji_registry)
    {}

    // ── URI construction (design §6.2) ──────────────────────────────
    std::string actorUri(std::string_view username) const;
    std::string followersUri(std::string_view username) const;
    std::string handleFor(std::string_view username) const; // @u@public_domain

    // ── Addressing (design §12.5) ───────────────────────────────────
    // to/cc recipients for a visibility, given the author and any
    // mentioned actor URIs (mentions are Phase 6 → usually empty).
    std::vector<PostRecipient>
    recipientsFor(Visibility vis, std::string_view author_username,
                  const std::vector<std::string>& mentioned) const;

    // ── Posting ─────────────────────────────────────────────────────
    mw::E<Post> createPost(const User& author, const ComposeParams& p) const;
    // Authorization to view a (possibly private) post over HTML
    // (design §16.6). The viewer is the logged-in user, or nullopt.
    mw::E<bool> canViewPost(const Post& post,
                            const std::optional<User>& viewer) const;

    // ── Timelines ───────────────────────────────────────────────────
    // Home timeline: the viewer's own posts plus posts from local
    // accounts they follow (design §16.3), one cursor page.
    mw::E<std::vector<Post>>
    homeTimeline(const User& viewer, const Cursor& c) const;

    // ── Interactions (local-only semantics) ─────────────────────────
    mw::E<void> setLike(const User& viewer, const Post& p, bool on) const;
    mw::E<void> setBoost(const User& viewer, const Post& p, bool on) const;
    mw::E<void> setReaction(const User& viewer, const Post& p,
                            std::string_view emoji, bool on) const;
    mw::E<void> setBookmark(const User& viewer, const Post& p, bool on) const;
    mw::E<void> setFollow(const User& viewer, std::string_view target_username,
                          bool on) const;

    // ── View models (nlohmann::json for Inja) ───────────────────────
    // Build a render-ready object for one post, resolving author,
    // attachments, counts, and viewer-relative flags.
    mw::E<nlohmann::json>
    postView(const Post& p, const std::optional<User>& viewer) const;
    mw::E<nlohmann::json>
    postViews(const std::vector<Post>& posts,
              const std::optional<User>& viewer) const;
    // A user profile view (header fields + rendered bio).
    nlohmann::json userView(const User& u) const;

    const EmojiRegistry& emojiRegistry() const { return emoji; }

private:
    const Config& config;
    const DataSourceInterface& data;
    const EmojiRegistry& emoji;
};

// Format a unix timestamp (seconds) as "YYYY-MM-DD HH:MM" UTC.
std::string formatTimestamp(int64_t unix_seconds);

} // namespace unspoken
