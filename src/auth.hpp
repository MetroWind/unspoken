#pragma once

// Authentication: OpenID Connect (Authorization Code flow) and stateful
// sessions (design §15). We implement the OIDC flow directly here rather
// than via mw::AuthOpenIDConnect, because the design requires full
// ID-token validation (JWKS signature, iss/aud/exp/nonce) which that
// helper does not expose.
//
// This module is split into two parts:
//   * Pure, I/O-free helpers (JWT/JWKS, base64url, username rules) that
//     are unit-tested directly.
//   * The Authenticator service that orchestrates login/callback/setup/
//     session/CSRF against the data module and an HTTP client.
//
// Handlers stay thin (design §1.2): all of the logic below is callable by
// a future C2S API too.

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <nlohmann/json.hpp>
#include <mw/crypto.hpp>
#include <mw/error.hpp>
#include <mw/http_client.hpp>

#include "config.hpp"
#include "data.hpp"
#include "structs.hpp"

namespace unspoken
{

// The session cookie / storage-prefix constants (design §16.10). Every
// cookie we set is prefixed with "unspoken-".
inline constexpr std::string_view SESSION_COOKIE = "unspoken-session";
inline constexpr std::string_view SETUP_COOKIE = "unspoken-setup";
// Session lifetime: 30 days.
inline constexpr int64_t SESSION_TTL_SECONDS = 30 * 24 * 3600;

// ─── OIDC discovery + ID-token validation (pure helpers) ───────────────

struct OidcEndpoints
{
    std::string authorization_endpoint;
    std::string token_endpoint;
    std::string jwks_uri;
    std::string userinfo_endpoint;      // optional; "" if absent
};

mw::E<OidcEndpoints> parseDiscovery(const nlohmann::json& doc);

// Validated claims from an OIDC ID token.
struct IdTokenClaims
{
    std::string iss;
    std::string sub;
    std::string aud;
    int64_t exp = 0;
    std::optional<std::string> nonce;
    std::optional<std::string> name;
    std::optional<std::string> preferred_username;
};

// base64url (RFC 7515 §2) without padding.
std::string base64UrlEncode(std::span<const unsigned char> bytes);
mw::E<std::vector<unsigned char>> base64UrlDecode(std::string_view s);

// Convert an RSA JWK (modulus n and exponent e, both base64url) to a PEM
// SubjectPublicKeyInfo usable by mw::Crypto::verifySignature.
mw::E<std::string> rsaJwkToPem(std::string_view n_b64url,
                               std::string_view e_b64url);
// Inverse of rsaJwkToPem: extract (n, e) base64url from an RSA public
// PEM. Used to build JWKS documents in tests.
mw::E<std::pair<std::string, std::string>>
rsaPemToJwkParams(const std::string& pem);

// Verify a compact RS256 JWS against a PEM public key; on success returns
// the decoded payload JSON. Does NOT validate claims.
mw::E<nlohmann::json> verifyRs256(std::string_view jwt, const std::string& pem,
                                  mw::CryptoInterface& crypto);

// Sign a compact RS256 JWS from JSON header and payload.
mw::E<std::string> signRs256Jwt(const nlohmann::json& header,
                                const nlohmann::json& payload,
                                const std::string& private_key_pem,
                                mw::CryptoInterface& crypto);

// Find the JWKS key matching the JWT header `kid` (or the sole key),
// verify the signature, return the payload JSON.
mw::E<nlohmann::json> verifyJwtWithJwks(std::string_view jwt,
                                        const nlohmann::json& jwks,
                                        mw::CryptoInterface& crypto);

// Validate standard ID-token claims (iss, aud, exp, nonce). `now` is unix
// seconds. A small leeway is allowed on exp.
mw::E<IdTokenClaims> validateClaims(const nlohmann::json& payload,
                                    std::string_view issuer,
                                    std::string_view client_id,
                                    std::string_view expected_nonce,
                                    int64_t now);

// Full ID-token validation: signature (via JWKS) + claims.
mw::E<IdTokenClaims> validateIdToken(std::string_view jwt,
                                     const nlohmann::json& jwks,
                                     std::string_view issuer,
                                     std::string_view client_id,
                                     std::string_view expected_nonce,
                                     int64_t now,
                                     mw::CryptoInterface& crypto);

// ─── Tokens, usernames ─────────────────────────────────────────────────

// A cryptographically-random token as lowercase hex (n_bytes of entropy).
std::string randomToken(size_t n_bytes = 32);

// Username rules (design §16.5): charset [a-z0-9_], length 1..30, not a
// reserved route/word. Uniqueness is checked separately against the DB.
bool isReservedUsername(std::string_view name);
mw::E<void> validateUsername(std::string_view name);

// ─── The Authenticator service ─────────────────────────────────────────

class Authenticator
{
public:
    // `http` is used for OIDC network calls (discovery, token, JWKS). It
    // need not be SSRF-guarded: the issuer is operator-configured and
    // trusted, unlike remote-actor URLs (design §11).
    Authenticator(const Config& conf, const DataSourceInterface& data_source,
                  mw::CryptoInterface& crypto_impl, std::string_view srv_key,
                  mw::HTTPSessionInterface& http_client)
            : config(conf), data(data_source), crypto(crypto_impl),
              server_key(srv_key), http(http_client)
    {}

    // Pre-authenticated identity carried from /callback to /setup-username
    // for a brand-new OIDC subject.
    struct PreAuth
    {
        std::string iss;
        std::string sub;
        std::string suggested_name;
    };

    struct Session
    {
        std::string token;
        int64_t expires_at = 0;
        int64_t user_id = 0;
    };

    // Either an existing user got a session, or a new subject needs setup.
    struct CallbackOutcome
    {
        std::optional<Session> session;
        std::optional<PreAuth> needs_setup;
    };

    // /login: generate state+nonce, persist, return the provider redirect.
    mw::E<std::string> beginLogin() const;

    // /callback: validate state (CSRF), exchange code, validate ID token,
    // resolve identity by (iss, sub).
    mw::E<CallbackOutcome> completeCallback(std::string_view state,
                                            std::string_view code) const;

    // /setup-username POST: validate the username, create the user (with a
    // fresh RSA keypair), and open a session.
    mw::E<Session> finishSetup(const PreAuth& id, std::string_view username,
                               std::string_view display_name) const;

    // currentUser abstraction (design §15.4): resolve the user behind a
    // session cookie value. nullopt = no/invalid/expired session.
    mw::E<std::optional<User>> userForSession(std::string_view token) const;

    mw::E<void> logout(std::string_view token) const;

    // CSRF (design §16.4): a per-session token, stable for the session's
    // life, derived (HMAC-like) from the session token and the server key
    // so it can sit in form HTML without leaking the session cookie.
    std::string csrfFor(std::string_view session_token) const;
    bool checkCsrf(std::string_view session_token,
                   std::string_view presented) const;

    // The encrypted pre-auth cookie (AES-256-GCM, authenticated) used to
    // carry identity across the setup-username round trip without a DB row.
    mw::E<std::string> sealPreAuth(const PreAuth& id) const;
    mw::E<PreAuth> openPreAuth(std::string_view sealed) const;
    // CSRF token bound to a specific sealed pre-auth blob (no session yet).
    std::string setupCsrfFor(std::string_view sealed) const;
    bool checkSetupCsrf(std::string_view sealed,
                        std::string_view presented) const;

private:
    mw::E<OidcEndpoints> discover() const;
    mw::E<nlohmann::json> tokenExchange(const OidcEndpoints& ep,
                                        std::string_view code) const;
    mw::E<nlohmann::json> fetchJwks(const OidcEndpoints& ep) const;
    std::string redirectUri() const;
    // Stable keyed digest used for both CSRF families.
    std::string keyedDigest(std::string_view label,
                            std::string_view value) const;

    const Config& config;
    const DataSourceInterface& data;
    mw::CryptoInterface& crypto;
    std::string server_key;          // 32 raw bytes for AES-256-GCM
    mw::HTTPSessionInterface& http;
};

} // namespace unspoken
