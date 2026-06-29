#pragma once

#include <atomic>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>
#include <inja.hpp>
#include <mw/crypto.hpp>
#include <mw/error.hpp>
#include <mw/http_server.hpp>
#include <mw/url.hpp>

#include "config.hpp"
#include "data.hpp"
#include "emoji.hpp"
#include "structs.hpp"

// The app module: the HTTP server, routing, and request handlers.
// Handlers are kept thin (design §1.2); business logic belongs in the
// service/federation/data layers. Phase 3 adds the local-only UI:
// composing/viewing posts, timelines, interactions, profile editing,
// attachments, custom emoji, and threads — all without network egress.
class App : public mw::HTTPServer
{
public:
    using Request = mw::HTTPServer::Request;
    using Response = mw::HTTPServer::Response;

    App() = delete;
    explicit App(const Config& conf);
    ~App();

    // Build a URL under the configured url_root.
    std::string urlFor(const std::string& path = "") const;

private:
    void setup() override;

    // The calling thread's own SQLite connection (design §7.2: one
    // connection per thread + WAL). Lazily opened on first use.
    mw::E<unspoken::DataSourceSQLite*> dataSource() const;

    // ── Cookies ─────────────────────────────────────────────────────
    std::optional<std::string> cookie(const Request& req,
                                      std::string_view name) const;
    void setCookie(Response& res, std::string_view name,
                   std::string_view value, int64_t max_age_seconds) const;
    void clearCookie(Response& res, std::string_view name) const;
    std::string cookiePath() const;

    // The single current-user abstraction (design §15.4): resolves the
    // user behind the session cookie. The future C2S API extends this.
    mw::E<std::optional<unspoken::User>> currentUser(const Request& req) const;

    // ── Rendering / context helpers ─────────────────────────────────
    // Common template context: site fields, login state, csrf token.
    nlohmann::json baseContext(const Request& req,
                               const std::optional<unspoken::User>& viewer)
        const;
    void render(Response& res, int status, const std::string& tmpl,
                const nlohmann::json& data) const;
    // The session token from the cookie (empty if none).
    std::string sessionToken(const Request& req) const;
    // Verify the per-session CSRF token on a state-changing POST.
    bool csrfOk(const Request& req) const;
    // Redirect target after a POST: the Referer if present, else home.
    std::string redirectTarget(const Request& req) const;

    // ── Handlers ────────────────────────────────────────────────────
    void handleHealth(const Request& req, Response& res) const;
    void handleIndex(const Request& req, Response& res) const;
    void handleLogin(const Request& req, Response& res) const;
    void handleCallback(const Request& req, Response& res) const;
    void handleSetupGet(const Request& req, Response& res) const;
    void handleSetupPost(const Request& req, Response& res) const;
    void handleLogout(const Request& req, Response& res) const;

    void handleUserProfile(const Request& req, Response& res) const;
    void handlePostView(const Request& req, Response& res) const;
    void handlePostCreate(const Request& req, Response& res) const;
    void handlePostDelete(const Request& req, Response& res) const;
    void handleReply(const Request& req, Response& res) const;
    void handleLike(const Request& req, Response& res) const;
    void handleBoost(const Request& req, Response& res) const;
    void handleReact(const Request& req, Response& res) const;
    void handleBookmark(const Request& req, Response& res) const;
    void handleBookmarks(const Request& req, Response& res) const;
    void handleFollow(const Request& req, Response& res) const;
    void handleProfileGet(const Request& req, Response& res) const;
    void handleProfilePost(const Request& req, Response& res) const;
    void handleSearch(const Request& req, Response& res) const;
    void handleMedia(const Request& req, Response& res) const;
    void handleEmoji(const Request& req, Response& res) const;
    void handleSystemActor(const Request& req, Response& res) const;
    void handleWebFinger(const Request& req, Response& res) const;
    void handleHostMeta(const Request& req, Response& res) const;
    void handleNodeInfoDiscovery(const Request& req, Response& res) const;
    void handleNodeInfo(const Request& req, Response& res) const;
    void handleInbox(const Request& req, Response& res) const;
    void handleOutbox(const Request& req, Response& res) const;
    void handleFollowersCollection(const Request& req, Response& res) const;
    void handleFollowingCollection(const Request& req, Response& res) const;

    mw::E<unspoken::SystemActor> systemActor() const;
    void startJobWorkers();
    void stopJobWorkers();
    void jobWorkerLoop(int worker_id) const;

    Config config;
    mw::URL base_url;
    // A 32-byte server key (raw bytes) generated at startup. Used for the
    // encrypted setup cookie (AES-256-GCM) and CSRF token derivation.
    std::string server_key;
    // Crypto is stateless; mutable so const handlers can use it.
    mutable mw::Crypto crypto;
    // Server-wide custom emoji, scanned once at startup (design §13.4).
    unspoken::EmojiRegistry emoji;
    std::vector<unspoken::UnicodeEmojiCategory> unicode_emoji;
    // Inja template environment (render_file reads templates/*.html).
    // mutable: inja::Environment::render_file is non-const.
    mutable inja::Environment templates;

    std::atomic<bool> job_workers_stop = false;
    std::vector<std::thread> job_worker_threads;
};
