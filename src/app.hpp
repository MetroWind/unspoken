#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <mw/crypto.hpp>
#include <mw/error.hpp>
#include <mw/http_server.hpp>
#include <mw/url.hpp>

#include "config.hpp"
#include "data.hpp"
#include "structs.hpp"

// The app module: the HTTP server, routing, and request handlers.
// Handlers are kept thin (design §1.2); business logic belongs in the
// service/federation/data layers. Phase 2 adds the OIDC login flow,
// sessions, and CSRF on top of the Phase 0 skeleton.
class App : public mw::HTTPServer
{
public:
    using Request = mw::HTTPServer::Request;
    using Response = mw::HTTPServer::Response;

    App() = delete;
    explicit App(const Config& conf);

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

    // ── Handlers ────────────────────────────────────────────────────
    void handleHealth(const Request& req, Response& res) const;
    void handleIndex(const Request& req, Response& res) const;
    void handleLogin(const Request& req, Response& res) const;
    void handleCallback(const Request& req, Response& res) const;
    void handleSetupGet(const Request& req, Response& res) const;
    void handleSetupPost(const Request& req, Response& res) const;
    void handleLogout(const Request& req, Response& res) const;

    Config config;
    mw::URL base_url;
    // A 32-byte server key (raw bytes) generated at startup. Used for the
    // encrypted setup cookie (AES-256-GCM) and CSRF token derivation.
    std::string server_key;
    // Crypto is stateless; mutable so const handlers can use it.
    mutable mw::Crypto crypto;
};
