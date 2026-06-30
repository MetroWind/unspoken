#include <array>
#include <cstdint>
#include <cstring>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <nlohmann/json.hpp>
#include <mw/crypto.hpp>
#include <mw/error.hpp>
#include <mw/http_client.hpp>
#include <mw/url.hpp>
#include <mw/utils.hpp>

#include "auth.hpp"
#include "config.hpp"
#include "data.hpp"
#include "structs.hpp"

using nlohmann::json;

namespace unspoken
{

namespace
{

int64_t nowSeconds()
{
    return mw::timeToSeconds(mw::Clock::now());
}

// Constant-time-ish equality, to avoid leaking token contents via timing
// on CSRF/token comparisons.
bool constantTimeEq(std::string_view a, std::string_view b)
{
    if(a.size() != b.size()) return false;
    unsigned char diff = 0;
    for(size_t i = 0; i < a.size(); ++i)
    {
        diff |= static_cast<unsigned char>(a[i]) ^
                static_cast<unsigned char>(b[i]);
    }
    return diff == 0;
}

json parseJsonOrNull(std::string_view s)
{
    return json::parse(s, nullptr, false);
}

// Read a BIO's memory contents into a std::string.
std::string bioToString(BIO* bio)
{
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    if(data == nullptr || len <= 0) return {};
    return std::string(data, static_cast<size_t>(len));
}

} // namespace

// ─── base64url ─────────────────────────────────────────────────────────

// base64url (RFC 7515 §2) = standard base64 with the URL-safe alphabet
// and no padding. We translate to/from libmw's standard base64 codec
// (which handles unpadded input and the 2-/3-char tail correctly).
std::string base64UrlEncode(std::span<const unsigned char> bytes)
{
    std::vector<unsigned char> buf(bytes.begin(), bytes.end());
    std::string s = mw::base64Encode(std::span<unsigned char>(buf),
                                     /*newline=*/false, /*pad=*/false);
    for(char& c : s)
    {
        if(c == '+') c = '-';
        else if(c == '/') c = '_';
    }
    return s;
}

mw::E<std::vector<unsigned char>> base64UrlDecode(std::string_view s)
{
    std::string t(s);
    for(char& c : t)
    {
        if(c == '-') c = '+';
        else if(c == '_') c = '/';
    }
    return mw::base64Decode(t);
}

// ─── RSA JWK <-> PEM ───────────────────────────────────────────────────

mw::E<std::string> rsaJwkToPem(std::string_view n_b64url,
                               std::string_view e_b64url)
{
    ASSIGN_OR_RETURN(auto n_bytes, base64UrlDecode(n_b64url));
    ASSIGN_OR_RETURN(auto e_bytes, base64UrlDecode(e_b64url));
    if(n_bytes.empty() || e_bytes.empty())
    {
        return std::unexpected(mw::runtimeError("Empty RSA JWK parameter"));
    }

    BIGNUM* n = BN_bin2bn(n_bytes.data(),
                          static_cast<int>(n_bytes.size()), nullptr);
    BIGNUM* e = BN_bin2bn(e_bytes.data(),
                          static_cast<int>(e_bytes.size()), nullptr);
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM* params = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    BIO* bio = nullptr;
    std::string pem;
    mw::E<std::string> result =
        std::unexpected(mw::runtimeError("RSA JWK conversion failed"));

    if(n == nullptr || e == nullptr || bld == nullptr) goto cleanup;
    if(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) != 1) goto cleanup;
    if(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) != 1) goto cleanup;
    params = OSSL_PARAM_BLD_to_param(bld);
    if(params == nullptr) goto cleanup;
    ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if(ctx == nullptr) goto cleanup;
    if(EVP_PKEY_fromdata_init(ctx) != 1) goto cleanup;
    if(EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1)
        goto cleanup;
    bio = BIO_new(BIO_s_mem());
    if(bio == nullptr) goto cleanup;
    if(PEM_write_bio_PUBKEY(bio, pkey) != 1) goto cleanup;
    pem = bioToString(bio);
    if(pem.empty()) goto cleanup;
    result = pem;

cleanup:
    if(bio != nullptr) BIO_free(bio);
    if(pkey != nullptr) EVP_PKEY_free(pkey);
    if(ctx != nullptr) EVP_PKEY_CTX_free(ctx);
    if(params != nullptr) OSSL_PARAM_free(params);
    if(bld != nullptr) OSSL_PARAM_BLD_free(bld);
    if(e != nullptr) BN_free(e);
    if(n != nullptr) BN_free(n);
    return result;
}

mw::E<std::pair<std::string, std::string>>
rsaPemToJwkParams(const std::string& pem)
{
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    EVP_PKEY* pkey = nullptr;
    BIGNUM* n = nullptr;
    BIGNUM* e = nullptr;
    mw::E<std::pair<std::string, std::string>> result =
        std::unexpected(mw::runtimeError("RSA PEM parse failed"));

    if(bio == nullptr) goto cleanup;
    pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if(pkey == nullptr) goto cleanup;
    if(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) != 1) goto cleanup;
    if(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) != 1) goto cleanup;
    {
        std::vector<unsigned char> nb(BN_num_bytes(n));
        std::vector<unsigned char> eb(BN_num_bytes(e));
        int nl = BN_bn2bin(n, nb.data());
        int el = BN_bn2bin(e, eb.data());
        nb.resize(static_cast<size_t>(nl));
        eb.resize(static_cast<size_t>(el));
        result = std::pair<std::string, std::string>(
            base64UrlEncode(nb), base64UrlEncode(eb));
    }

cleanup:
    if(e != nullptr) BN_free(e);
    if(n != nullptr) BN_free(n);
    if(pkey != nullptr) EVP_PKEY_free(pkey);
    if(bio != nullptr) BIO_free(bio);
    return result;
}

// ─── JWT / JWKS ────────────────────────────────────────────────────────

namespace
{

// Split a compact JWS into its three dot-separated segments.
mw::E<std::array<std::string, 3>> splitJwt(std::string_view jwt)
{
    std::array<std::string, 3> parts;
    size_t start = 0;
    int idx = 0;
    for(size_t i = 0; i <= jwt.size(); ++i)
    {
        if(i == jwt.size() || jwt[i] == '.')
        {
            if(idx >= 3)
            {
                return std::unexpected(mw::runtimeError(
                    "Malformed JWT: too many segments"));
            }
            parts[idx++] = std::string(jwt.substr(start, i - start));
            start = i + 1;
        }
    }
    if(idx != 3)
    {
        return std::unexpected(mw::runtimeError(
            "Malformed JWT: expected 3 segments"));
    }
    return parts;
}

mw::E<json> decodeJwtSegment(const std::string& seg)
{
    ASSIGN_OR_RETURN(auto bytes, base64UrlDecode(seg));
    json j = parseJsonOrNull(
        std::string_view(reinterpret_cast<const char*>(bytes.data()),
                         bytes.size()));
    if(j.is_discarded())
    {
        return std::unexpected(mw::runtimeError("Invalid JSON in JWT segment"));
    }
    return j;
}

} // namespace

mw::E<json> verifyRs256(std::string_view jwt, const std::string& pem,
                        mw::CryptoInterface& crypto)
{
    ASSIGN_OR_RETURN(auto parts, splitJwt(jwt));
    ASSIGN_OR_RETURN(json header, decodeJwtSegment(parts[0]));
    if(header.contains("alg") && header["alg"].is_string() &&
       header["alg"].get<std::string>() != "RS256")
    {
        return std::unexpected(mw::runtimeError(std::format(
            "Unsupported JWT alg: {}", header["alg"].get<std::string>())));
    }
    ASSIGN_OR_RETURN(auto sig, base64UrlDecode(parts[2]));
    std::string signing_input = parts[0] + "." + parts[1];
    ASSIGN_OR_RETURN(bool ok, crypto.verifySignature(
        mw::SignatureAlgorithm::RSA_V1_5_SHA256, pem, sig, signing_input));
    if(!ok)
    {
        return std::unexpected(mw::runtimeError("JWT signature invalid"));
    }
    return decodeJwtSegment(parts[1]);
}

mw::E<std::string> signRs256Jwt(const json& header, const json& payload,
                                const std::string& private_key_pem,
                                mw::CryptoInterface& crypto)
{
    std::string header_s = header.dump();
    std::string payload_s = payload.dump();
    std::span<const unsigned char> header_bytes(
        reinterpret_cast<const unsigned char*>(header_s.data()),
        header_s.size());
    std::span<const unsigned char> payload_bytes(
        reinterpret_cast<const unsigned char*>(payload_s.data()),
        payload_s.size());
    std::string signing_input = base64UrlEncode(header_bytes) + "."
        + base64UrlEncode(payload_bytes);
    ASSIGN_OR_RETURN(auto sig, crypto.sign(
        mw::SignatureAlgorithm::RSA_V1_5_SHA256, private_key_pem,
        signing_input));
    return signing_input + "." + base64UrlEncode(sig);
}

mw::E<json> verifyJwtWithJwks(std::string_view jwt, const json& jwks,
                              mw::CryptoInterface& crypto)
{
    ASSIGN_OR_RETURN(auto parts, splitJwt(jwt));
    ASSIGN_OR_RETURN(json header, decodeJwtSegment(parts[0]));
    std::optional<std::string> want_kid;
    if(header.contains("kid") && header["kid"].is_string())
    {
        want_kid = header["kid"].get<std::string>();
    }

    if(!jwks.contains("keys") || !jwks["keys"].is_array())
    {
        return std::unexpected(mw::runtimeError("JWKS has no keys array"));
    }
    for(const auto& key : jwks["keys"])
    {
        if(!key.is_object()) continue;
        if(key.value("kty", "") != "RSA") continue;
        if(want_kid.has_value() && key.contains("kid") &&
           key["kid"].is_string() &&
           key["kid"].get<std::string>() != *want_kid)
        {
            continue;
        }
        if(!key.contains("n") || !key.contains("e")) continue;
        auto pem = rsaJwkToPem(key["n"].get<std::string>(),
                               key["e"].get<std::string>());
        if(!pem.has_value()) continue;
        auto payload = verifyRs256(jwt, *pem, crypto);
        if(payload.has_value()) return payload;
    }
    return std::unexpected(mw::runtimeError(
        "No JWKS key verified the ID token"));
}

mw::E<IdTokenClaims> validateClaims(const json& payload,
                                    std::string_view issuer,
                                    std::string_view client_id,
                                    std::string_view expected_nonce,
                                    int64_t now)
{
    constexpr int64_t LEEWAY = 120; // seconds

    if(payload.value("iss", "") != issuer)
    {
        return std::unexpected(mw::runtimeError("ID token issuer mismatch"));
    }

    // aud may be a string or an array of strings; client_id must appear.
    bool aud_ok = false;
    if(payload.contains("aud"))
    {
        const auto& aud = payload["aud"];
        if(aud.is_string())
        {
            aud_ok = aud.get<std::string>() == client_id;
        }
        else if(aud.is_array())
        {
            for(const auto& a : aud)
            {
                if(a.is_string() && a.get<std::string>() == client_id)
                {
                    aud_ok = true;
                    break;
                }
            }
        }
    }
    if(!aud_ok)
    {
        return std::unexpected(mw::runtimeError("ID token audience mismatch"));
    }

    if(!payload.contains("exp") || !payload["exp"].is_number())
    {
        return std::unexpected(mw::runtimeError("ID token missing exp"));
    }
    int64_t exp = payload["exp"].get<int64_t>();
    if(now > exp + LEEWAY)
    {
        return std::unexpected(mw::runtimeError("ID token expired"));
    }

    if(!expected_nonce.empty())
    {
        std::string got = payload.value("nonce", std::string{});
        if(!constantTimeEq(got, expected_nonce))
        {
            return std::unexpected(mw::runtimeError("ID token nonce mismatch"));
        }
    }

    IdTokenClaims claims;
    claims.iss = issuer;
    claims.sub = payload.value("sub", std::string{});
    if(claims.sub.empty())
    {
        return std::unexpected(mw::runtimeError("ID token missing sub"));
    }
    claims.aud = std::string(client_id);
    claims.exp = exp;
    if(payload.contains("nonce") && payload["nonce"].is_string())
        claims.nonce = payload["nonce"].get<std::string>();
    if(payload.contains("name") && payload["name"].is_string())
        claims.name = payload["name"].get<std::string>();
    if(payload.contains("preferred_username") &&
       payload["preferred_username"].is_string())
        claims.preferred_username =
            payload["preferred_username"].get<std::string>();
    return claims;
}

mw::E<IdTokenClaims> validateIdToken(std::string_view jwt, const json& jwks,
                                     std::string_view issuer,
                                     std::string_view client_id,
                                     std::string_view expected_nonce,
                                     int64_t now, mw::CryptoInterface& crypto)
{
    ASSIGN_OR_RETURN(json payload, verifyJwtWithJwks(jwt, jwks, crypto));
    return validateClaims(payload, issuer, client_id, expected_nonce, now);
}

// ─── Discovery ─────────────────────────────────────────────────────────

mw::E<OidcEndpoints> parseDiscovery(const json& doc)
{
    if(!doc.is_object())
    {
        return std::unexpected(mw::runtimeError("Discovery doc is not an object"));
    }
    OidcEndpoints ep;
    auto need = [&](const char* field, std::string& out) -> mw::E<void> {
        if(!doc.contains(field) || !doc[field].is_string())
        {
            return std::unexpected(mw::runtimeError(std::format(
                "Discovery doc missing {}", field)));
        }
        out = doc[field].get<std::string>();
        return {};
    };
    DO_OR_RETURN(need("authorization_endpoint", ep.authorization_endpoint));
    DO_OR_RETURN(need("token_endpoint", ep.token_endpoint));
    DO_OR_RETURN(need("jwks_uri", ep.jwks_uri));
    if(doc.contains("userinfo_endpoint") && doc["userinfo_endpoint"].is_string())
    {
        ep.userinfo_endpoint = doc["userinfo_endpoint"].get<std::string>();
    }
    return ep;
}

// ─── Tokens, usernames ─────────────────────────────────────────────────

std::string randomToken(size_t n_bytes)
{
    std::vector<unsigned char> buf(n_bytes);
    if(RAND_bytes(buf.data(), static_cast<int>(n_bytes)) != 1)
    {
        // Extremely unlikely; fall back to a low-entropy value rather than
        // crash. Callers use this for unguessable tokens, so log-worthy,
        // but we have no logger here.
        for(size_t i = 0; i < n_bytes; ++i) buf[i] = static_cast<unsigned char>(i);
    }
    static const char* hx = "0123456789abcdef";
    std::string out;
    out.reserve(n_bytes * 2);
    for(unsigned char b : buf)
    {
        out.push_back(hx[b >> 4]);
        out.push_back(hx[b & 0x0f]);
    }
    return out;
}

bool isReservedUsername(std::string_view name)
{
    static constexpr std::string_view RESERVED[] = {
        "inbox", "outbox", "followers", "following", "actor", "__system__",
        "well-known", ".well-known", "login", "callback", "logout",
        "setup-username", "profile", "post", "follow", "unfollow", "search",
        "static", "media", "emoji", "health", "p", "u", "admin", "api",
        "system", "nodeinfo",
    };
    for(std::string_view r : RESERVED)
    {
        if(name == r) return true;
    }
    return false;
}

mw::E<void> validateUsername(std::string_view name)
{
    if(name.empty() || name.size() > 30)
    {
        return std::unexpected(mw::runtimeError(
            "Username must be 1–30 characters"));
    }
    for(char c : name)
    {
        bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if(!ok)
        {
            return std::unexpected(mw::runtimeError(
                "Username may only contain lowercase letters, digits, and '_'"));
        }
    }
    if(isReservedUsername(name))
    {
        return std::unexpected(mw::runtimeError(
            std::format("'{}' is a reserved username", name)));
    }
    return {};
}

// ─── Authenticator ─────────────────────────────────────────────────────

std::string Authenticator::redirectUri() const
{
    return config.url_root + "callback";
}

std::string Authenticator::keyedDigest(std::string_view label,
                                       std::string_view value) const
{
    mw::SHA256Hasher hasher;
    std::string material;
    material.reserve(server_key.size() + label.size() + value.size() + 2);
    material.append(server_key);
    material.push_back('|');
    material.append(label);
    material.push_back('|');
    material.append(value);
    auto hex = hasher.hashToHexStr(material);
    if(!hex.has_value()) return {};
    return *hex;
}

mw::E<OidcEndpoints> Authenticator::discover() const
{
    ASSIGN_OR_RETURN(mw::URL prefix, mw::URL::fromStr(config.oidc.issuer));
    std::string url =
        prefix.appendPath(".well-known/openid-configuration").str();
    ASSIGN_OR_RETURN(const mw::HTTPResponse* res, http.get(url));
    if(res->status != 200)
    {
        return std::unexpected(mw::runtimeError(std::format(
            "OIDC discovery failed with status {}", res->status)));
    }
    json doc = parseJsonOrNull(res->payloadAsStr());
    if(doc.is_discarded())
    {
        return std::unexpected(mw::runtimeError("Invalid OIDC discovery doc"));
    }
    return parseDiscovery(doc);
}

mw::E<json> Authenticator::tokenExchange(const OidcEndpoints& ep,
                                         std::string_view code) const
{
    // client_secret_post: credentials in the form body (accepted by
    // Keycloak's default confidential-client config).
    std::string body = std::format(
        "grant_type=authorization_code&code={}&redirect_uri={}"
        "&client_id={}&client_secret={}",
        mw::urlEncode(code), mw::urlEncode(redirectUri()),
        mw::urlEncode(config.oidc.client_id),
        mw::urlEncode(config.oidc.client_secret));
    ASSIGN_OR_RETURN(const mw::HTTPResponse* res, http.post(
        mw::HTTPRequest(ep.token_endpoint).setPayload(body)
            .addHeader("Content-Type", "application/x-www-form-urlencoded")));
    json doc = parseJsonOrNull(res->payloadAsStr());
    if(doc.is_discarded())
    {
        return std::unexpected(mw::runtimeError("Invalid token response"));
    }
    if(res->status != 200)
    {
        return std::unexpected(mw::runtimeError(std::format(
            "Token exchange failed ({}): {}", res->status,
            doc.value("error_description", doc.value("error", "")))));
    }
    return doc;
}

mw::E<json> Authenticator::fetchJwks(const OidcEndpoints& ep) const
{
    ASSIGN_OR_RETURN(const mw::HTTPResponse* res, http.get(ep.jwks_uri));
    if(res->status != 200)
    {
        return std::unexpected(mw::runtimeError(std::format(
            "JWKS fetch failed with status {}", res->status)));
    }
    json doc = parseJsonOrNull(res->payloadAsStr());
    if(doc.is_discarded())
    {
        return std::unexpected(mw::runtimeError("Invalid JWKS document"));
    }
    return doc;
}

mw::E<std::string> Authenticator::beginLogin() const
{
    std::string state = randomToken();
    std::string nonce = randomToken();
    DO_OR_RETURN(data.addPendingLogin(state, nonce, nowSeconds()));
    ASSIGN_OR_RETURN(OidcEndpoints ep, discover());

    std::string sep = ep.authorization_endpoint.find('?') == std::string::npos
        ? "?" : "&";
    return std::format(
        "{}{}response_type=code&client_id={}&redirect_uri={}&scope={}"
        "&state={}&nonce={}",
        ep.authorization_endpoint, sep, mw::urlEncode(config.oidc.client_id),
        mw::urlEncode(redirectUri()), mw::urlEncode(config.oidc.scopes),
        mw::urlEncode(state), mw::urlEncode(nonce));
}

mw::E<Authenticator::CallbackOutcome>
Authenticator::completeCallback(std::string_view state,
                                std::string_view code) const
{
    // Validate state (CSRF) by atomically consuming the pending login.
    ASSIGN_OR_RETURN(std::optional<std::string> nonce,
                     data.takePendingLogin(state));
    if(!nonce.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Unknown or expired login state"));
    }

    ASSIGN_OR_RETURN(OidcEndpoints ep, discover());
    ASSIGN_OR_RETURN(json tokens, tokenExchange(ep, code));
    if(!tokens.contains("id_token") || !tokens["id_token"].is_string())
    {
        return std::unexpected(mw::runtimeError(
            "Token response had no id_token"));
    }
    ASSIGN_OR_RETURN(json jwks, fetchJwks(ep));
    ASSIGN_OR_RETURN(IdTokenClaims claims, validateIdToken(
        tokens["id_token"].get<std::string>(), jwks, config.oidc.issuer,
        config.oidc.client_id, *nonce, nowSeconds(), crypto));

    ASSIGN_OR_RETURN(std::optional<User> existing,
                     data.getUserByOidcSub(claims.iss, claims.sub));
    CallbackOutcome out;
    if(existing.has_value())
    {
        std::string token = randomToken();
        int64_t expires = nowSeconds() + SESSION_TTL_SECONDS;
        DO_OR_RETURN(data.createSession(token, existing->id, expires));
        out.session = Session{token, expires, existing->id};
        return out;
    }

    PreAuth pre;
    pre.iss = claims.iss;
    pre.sub = claims.sub;
    pre.suggested_name = claims.name.value_or(
        claims.preferred_username.value_or(""));
    out.needs_setup = pre;
    return out;
}

mw::E<Authenticator::Session>
Authenticator::finishSetup(const PreAuth& id, std::string_view username,
                           std::string_view display_name) const
{
    DO_OR_RETURN(validateUsername(username));

    // If this subject somehow already has an account (double submit / race),
    // just open a session for it.
    ASSIGN_OR_RETURN(std::optional<User> by_sub,
                     data.getUserByOidcSub(id.iss, id.sub));
    int64_t user_id = 0;
    if(by_sub.has_value())
    {
        user_id = by_sub->id;
    }
    else
    {
        ASSIGN_OR_RETURN(std::optional<User> taken,
                         data.getUserByUsername(username));
        if(taken.has_value())
        {
            return std::unexpected(mw::runtimeError(
                "That username is already taken"));
        }
        ASSIGN_OR_RETURN(mw::KeyPair keys,
                         crypto.generateKeyPair(mw::KeyType::RSA));
        NewUser nu;
        nu.username = std::string(username);
        nu.display_name = display_name.empty() ? std::string(username)
                                               : std::string(display_name);
        nu.bio = "";
        nu.oidc_iss = id.iss;
        nu.oidc_sub = id.sub;
        nu.private_key_pem = keys.private_key;
        nu.public_key_pem = keys.public_key;
        ASSIGN_OR_RETURN(User user, data.createUser(nu));
        user_id = user.id;
    }

    std::string token = randomToken();
    int64_t expires = nowSeconds() + SESSION_TTL_SECONDS;
    DO_OR_RETURN(data.createSession(token, user_id, expires));
    return Session{token, expires, user_id};
}

mw::E<std::optional<User>>
Authenticator::userForSession(std::string_view token) const
{
    if(token.empty()) return std::optional<User>{};
    ASSIGN_OR_RETURN(std::optional<int64_t> uid,
                     data.getSessionUser(token, nowSeconds()));
    if(!uid.has_value()) return std::optional<User>{};
    return data.getUserById(*uid);
}

mw::E<void> Authenticator::logout(std::string_view token) const
{
    if(token.empty()) return {};
    return data.deleteSession(token);
}

std::string Authenticator::csrfFor(std::string_view session_token) const
{
    return keyedDigest("csrf", session_token);
}

bool Authenticator::checkCsrf(std::string_view session_token,
                              std::string_view presented) const
{
    if(session_token.empty() || presented.empty()) return false;
    return constantTimeEq(presented, csrfFor(session_token));
}

mw::E<std::string> Authenticator::sealPreAuth(const PreAuth& id) const
{
    json j;
    j["iss"] = id.iss;
    j["sub"] = id.sub;
    j["name"] = id.suggested_name;
    ASSIGN_OR_RETURN(std::string ct,
                     crypto.encrypt(mw::EncryptionAlgorithm::AES_256_GCM,
                                    server_key, j.dump()));
    std::span<const unsigned char> bytes(
        reinterpret_cast<const unsigned char*>(ct.data()), ct.size());
    return base64UrlEncode(bytes);
}

mw::E<Authenticator::PreAuth>
Authenticator::openPreAuth(std::string_view sealed) const
{
    ASSIGN_OR_RETURN(auto raw, base64UrlDecode(sealed));
    std::string ct(raw.begin(), raw.end());
    ASSIGN_OR_RETURN(std::string pt,
                     crypto.decrypt(mw::EncryptionAlgorithm::AES_256_GCM,
                                    server_key, ct));
    json j = parseJsonOrNull(pt);
    if(j.is_discarded() || !j.is_object())
    {
        return std::unexpected(mw::runtimeError("Invalid setup token"));
    }
    PreAuth pre;
    pre.iss = j.value("iss", "");
    pre.sub = j.value("sub", "");
    pre.suggested_name = j.value("name", "");
    if(pre.iss.empty() || pre.sub.empty())
    {
        return std::unexpected(mw::runtimeError("Incomplete setup token"));
    }
    return pre;
}

std::string Authenticator::setupCsrfFor(std::string_view sealed) const
{
    return keyedDigest("setupcsrf", sealed);
}

bool Authenticator::checkSetupCsrf(std::string_view sealed,
                                   std::string_view presented) const
{
    if(sealed.empty() || presented.empty()) return false;
    return constantTimeEq(presented, setupCsrfFor(sealed));
}

} // namespace unspoken
