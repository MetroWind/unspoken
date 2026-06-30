#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>
#include <mw/crypto.hpp>
#include <mw/error.hpp>
#include <mw/http_client_mock.hpp>
#include <mw/test_utils.hpp>

#include "auth.hpp"
#include "config.hpp"
#include "data.hpp"
#include "data_mock.hpp"
#include "structs.hpp"

using namespace unspoken;
using nlohmann::json;
using ::testing::_;
using ::testing::Return;

namespace
{

Config validConfig()
{
    Config c;
    c.url_root = "https://f.test/";
    c.public_domain = "f.test";
    c.oidc.issuer = "https://kc.test/realms/main";
    c.oidc.client_id = "unspoken";
    c.oidc.client_secret = "secret";
    return c;
}

std::string b64u(std::string_view s)
{
    std::span<const unsigned char> sp(
        reinterpret_cast<const unsigned char*>(s.data()), s.size());
    return base64UrlEncode(sp);
}

// Build a signed RS256 ID token and the matching JWKS from a keypair.
struct SignedToken
{
    std::string jwt;
    json jwks;
};

SignedToken makeIdToken(mw::Crypto& crypto, const mw::KeyPair& kp,
                        const json& payload)
{
    json header{{"alg", "RS256"}, {"kid", "k1"}, {"typ", "JWT"}};
    std::string si = b64u(header.dump()) + "." + b64u(payload.dump());
    auto sig = crypto.sign(mw::SignatureAlgorithm::RSA_V1_5_SHA256,
                           kp.private_key, si);
    EXPECT_TRUE(sig.has_value());
    std::string sigb = base64UrlEncode(
        std::span<const unsigned char>(sig->data(), sig->size()));
    auto params = rsaPemToJwkParams(kp.public_key);
    EXPECT_TRUE(params.has_value());
    json jwks{{"keys", json::array({json{
        {"kty", "RSA"}, {"kid", "k1"},
        {"n", params->first}, {"e", params->second}}})}};
    return SignedToken{si + "." + sigb, jwks};
}

} // namespace

// ─── base64url ─────────────────────────────────────────────────────────

TEST(AuthBase64Url, RoundTrip)
{
    for(std::string_view s : {"", "f", "fo", "foo", "foob", "fooba",
                              "foobar", "\x00\x01\x02\xff\xfe"})
    {
        std::span<const unsigned char> sp(
            reinterpret_cast<const unsigned char*>(s.data()), s.size());
        std::string enc = base64UrlEncode(sp);
        EXPECT_EQ(enc.find('+'), std::string::npos);
        EXPECT_EQ(enc.find('/'), std::string::npos);
        EXPECT_EQ(enc.find('='), std::string::npos);
        ASSIGN_OR_FAIL(auto dec, base64UrlDecode(enc));
        std::string back(dec.begin(), dec.end());
        EXPECT_EQ(back, std::string(s));
    }
}

// ─── RSA JWK <-> PEM ───────────────────────────────────────────────────

TEST(AuthJwk, PemRoundTripVerifies)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto kp, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto params, rsaPemToJwkParams(kp.public_key));
    ASSIGN_OR_FAIL(auto pem, rsaJwkToPem(params.first, params.second));

    // The reconstructed PEM must verify a signature made by the private key.
    std::string data = "hello signing world";
    ASSIGN_OR_FAIL(auto sig, crypto.sign(
        mw::SignatureAlgorithm::RSA_V1_5_SHA256, kp.private_key, data));
    ASSIGN_OR_FAIL(bool ok, crypto.verifySignature(
        mw::SignatureAlgorithm::RSA_V1_5_SHA256, pem, sig, data));
    EXPECT_TRUE(ok);
}

TEST(AuthJwt, SignRs256JwtCanBeVerified)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto kp, crypto.generateKeyPair(mw::KeyType::RSA));
    json header{{"typ", "JWT"}, {"alg", "RS256"}, {"kid", "k1"}};
    json payload{{"iss", "https://kc.test/realms/main"},
                 {"sub", "user-1"},
                 {"aud", "unspoken"},
                 {"exp", 1'700'003'600},
                 {"nonce", "n-123"}};

    ASSIGN_OR_FAIL(auto jwt, signRs256Jwt(header, payload, kp.private_key,
                                          crypto));
    ASSIGN_OR_FAIL(auto verified, verifyRs256(jwt, kp.public_key, crypto));

    EXPECT_EQ(verified["sub"], "user-1");
    EXPECT_EQ(verified["nonce"], "n-123");
}

// ─── ID-token validation ───────────────────────────────────────────────

TEST(AuthIdToken, ValidTokenPasses)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto kp, crypto.generateKeyPair(mw::KeyType::RSA));
    int64_t now = 1'700'000'000;
    json payload{{"iss", "https://kc.test/realms/main"}, {"sub", "user-1"},
                 {"aud", "unspoken"}, {"exp", now + 3600},
                 {"nonce", "n-123"}, {"name", "Sample User"}};
    SignedToken tok = makeIdToken(crypto, kp, payload);

    ASSIGN_OR_FAIL(auto claims, validateIdToken(
        tok.jwt, tok.jwks, "https://kc.test/realms/main", "unspoken",
        "n-123", now, crypto));
    EXPECT_EQ(claims.sub, "user-1");
    EXPECT_EQ(claims.iss, "https://kc.test/realms/main");
    EXPECT_EQ(claims.name.value_or(""), "Sample User");
}

TEST(AuthIdToken, AudienceArrayAccepted)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto kp, crypto.generateKeyPair(mw::KeyType::RSA));
    int64_t now = 1'700'000'000;
    json payload{{"iss", "https://kc.test/realms/main"}, {"sub", "u"},
                 {"aud", json::array({"other", "unspoken"})},
                 {"exp", now + 60}};
    SignedToken tok = makeIdToken(crypto, kp, payload);
    auto claims = validateIdToken(tok.jwt, tok.jwks,
        "https://kc.test/realms/main", "unspoken", "", now, crypto);
    EXPECT_TRUE(claims.has_value());
}

TEST(AuthIdToken, TamperedSignatureRejected)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto kp, crypto.generateKeyPair(mw::KeyType::RSA));
    int64_t now = 1'700'000'000;
    json payload{{"iss", "https://kc.test/realms/main"}, {"sub", "u"},
                 {"aud", "unspoken"}, {"exp", now + 60}, {"nonce", "n"}};
    SignedToken tok = makeIdToken(crypto, kp, payload);
    // Flip a character in the payload segment.
    tok.jwt[tok.jwt.find('.') + 5] ^= 0x01;
    auto claims = validateIdToken(tok.jwt, tok.jwks,
        "https://kc.test/realms/main", "unspoken", "n", now, crypto);
    EXPECT_FALSE(claims.has_value());
}

TEST(AuthIdToken, NonceMismatchRejected)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto kp, crypto.generateKeyPair(mw::KeyType::RSA));
    int64_t now = 1'700'000'000;
    json payload{{"iss", "https://kc.test/realms/main"}, {"sub", "u"},
                 {"aud", "unspoken"}, {"exp", now + 60}, {"nonce", "real"}};
    SignedToken tok = makeIdToken(crypto, kp, payload);
    auto claims = validateIdToken(tok.jwt, tok.jwks,
        "https://kc.test/realms/main", "unspoken", "expected", now, crypto);
    EXPECT_FALSE(claims.has_value());
}

TEST(AuthIdToken, ExpiredRejected)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto kp, crypto.generateKeyPair(mw::KeyType::RSA));
    int64_t now = 1'700'000'000;
    json payload{{"iss", "https://kc.test/realms/main"}, {"sub", "u"},
                 {"aud", "unspoken"}, {"exp", now - 10'000}};
    SignedToken tok = makeIdToken(crypto, kp, payload);
    auto claims = validateIdToken(tok.jwt, tok.jwks,
        "https://kc.test/realms/main", "unspoken", "", now, crypto);
    EXPECT_FALSE(claims.has_value());
}

TEST(AuthIdToken, WrongIssuerRejected)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto kp, crypto.generateKeyPair(mw::KeyType::RSA));
    int64_t now = 1'700'000'000;
    json payload{{"iss", "https://evil.test"}, {"sub", "u"},
                 {"aud", "unspoken"}, {"exp", now + 60}};
    SignedToken tok = makeIdToken(crypto, kp, payload);
    auto claims = validateIdToken(tok.jwt, tok.jwks,
        "https://kc.test/realms/main", "unspoken", "", now, crypto);
    EXPECT_FALSE(claims.has_value());
}

TEST(AuthIdToken, WrongKeyRejected)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto kp, crypto.generateKeyPair(mw::KeyType::RSA));
    ASSIGN_OR_FAIL(auto other, crypto.generateKeyPair(mw::KeyType::RSA));
    int64_t now = 1'700'000'000;
    json payload{{"iss", "https://kc.test/realms/main"}, {"sub", "u"},
                 {"aud", "unspoken"}, {"exp", now + 60}};
    SignedToken tok = makeIdToken(crypto, kp, payload);
    // Replace the JWKS key with an unrelated public key.
    ASSIGN_OR_FAIL(auto params, rsaPemToJwkParams(other.public_key));
    tok.jwks["keys"][0]["n"] = params.first;
    tok.jwks["keys"][0]["e"] = params.second;
    auto claims = validateIdToken(tok.jwt, tok.jwks,
        "https://kc.test/realms/main", "unspoken", "", now, crypto);
    EXPECT_FALSE(claims.has_value());
}

// ─── Username rules ────────────────────────────────────────────────────

TEST(AuthUsername, AcceptsValid)
{
    EXPECT_TRUE(validateUsername("alice").has_value());
    EXPECT_TRUE(validateUsername("a_b_2").has_value());
}

TEST(AuthUsername, RejectsBadCharsAndLength)
{
    EXPECT_FALSE(validateUsername("").has_value());
    EXPECT_FALSE(validateUsername("Alice").has_value());   // uppercase
    EXPECT_FALSE(validateUsername("a b").has_value());      // space
    EXPECT_FALSE(validateUsername("a-b").has_value());      // dash
    EXPECT_FALSE(validateUsername(std::string(31, 'a')).has_value());
}

TEST(AuthUsername, RejectsReserved)
{
    EXPECT_FALSE(validateUsername("inbox").has_value());
    EXPECT_FALSE(validateUsername("actor").has_value());
    EXPECT_FALSE(validateUsername("__system__").has_value());
}

// ─── randomToken ───────────────────────────────────────────────────────

TEST(AuthToken, RandomTokensDifferAndAreHex)
{
    std::string a = randomToken(16);
    std::string b = randomToken(16);
    EXPECT_EQ(a.size(), 32u);
    EXPECT_NE(a, b);
    for(char c : a)
    {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
}

// ─── CSRF ──────────────────────────────────────────────────────────────

TEST(AuthCsrf, AcceptsMatchingRejectsOthers)
{
    auto db = DataSourceSQLite::newFromMemory();
    ASSERT_TRUE(db.has_value());
    mw::Crypto crypto;
    mw::HTTPSessionMock http;
    std::string key(32, 'k');
    Authenticator auth(validConfig(), **db, crypto, key, http);

    std::string token = randomToken();
    std::string csrf = auth.csrfFor(token);
    EXPECT_FALSE(csrf.empty());
    EXPECT_TRUE(auth.checkCsrf(token, csrf));
    EXPECT_FALSE(auth.checkCsrf(token, "wrong"));
    EXPECT_FALSE(auth.checkCsrf(token, ""));
    EXPECT_FALSE(auth.checkCsrf("", csrf));
    // A different session token yields a different CSRF token.
    EXPECT_NE(csrf, auth.csrfFor(randomToken()));
}

// ─── Encrypted setup cookie ────────────────────────────────────────────

TEST(AuthSetupCookie, SealOpenRoundTripAndTamper)
{
    auto db = DataSourceSQLite::newFromMemory();
    ASSERT_TRUE(db.has_value());
    mw::Crypto crypto;
    mw::HTTPSessionMock http;
    std::string key(32, 's');
    Authenticator auth(validConfig(), **db, crypto, key, http);

    Authenticator::PreAuth pre{"https://kc.test/realms/main", "sub-9", "Nine"};
    ASSIGN_OR_FAIL(std::string sealed, auth.sealPreAuth(pre));
    ASSIGN_OR_FAIL(auto opened, auth.openPreAuth(sealed));
    EXPECT_EQ(opened.iss, pre.iss);
    EXPECT_EQ(opened.sub, pre.sub);
    EXPECT_EQ(opened.suggested_name, pre.suggested_name);

    // Tampering with the ciphertext must fail authentication (GCM).
    std::string tampered = sealed;
    tampered[tampered.size() / 2] ^= 0x01;
    EXPECT_FALSE(auth.openPreAuth(tampered).has_value());

    // Setup CSRF is bound to the sealed value.
    std::string c = auth.setupCsrfFor(sealed);
    EXPECT_TRUE(auth.checkSetupCsrf(sealed, c));
    EXPECT_FALSE(auth.checkSetupCsrf(sealed, "no"));
}

// ─── State mismatch on callback (CSRF) ─────────────────────────────────

TEST(AuthCallback, UnknownStateRejected)
{
    DataSourceMock data;
    mw::Crypto crypto;
    mw::HTTPSessionMock http;
    std::string key(32, 'k');
    Authenticator auth(validConfig(), data, crypto, key, http);

    // Unknown state → takePendingLogin yields nullopt → error, no HTTP.
    EXPECT_CALL(data, takePendingLogin(_))
        .WillOnce(Return(mw::E<std::optional<std::string>>(std::nullopt)));
    auto out = auth.completeCallback("bogus-state", "some-code");
    EXPECT_FALSE(out.has_value());
}

// ─── Session lifecycle (setup -> session -> logout) ────────────────────

TEST(AuthSession, SetupCreatesUserAndSessionThenLogout)
{
    auto db = DataSourceSQLite::newFromMemory();
    ASSERT_TRUE(db.has_value());
    mw::Crypto crypto;
    mw::HTTPSessionMock http;
    std::string key(32, 'k');
    Authenticator auth(validConfig(), **db, crypto, key, http);

    Authenticator::PreAuth pre{"https://kc.test/realms/main", "sub-1", "Al"};
    ASSIGN_OR_FAIL(auto session, auth.finishSetup(pre, "alice", "Alice"));
    EXPECT_FALSE(session.token.empty());
    EXPECT_GT(session.user_id, 0);

    ASSIGN_OR_FAIL(auto user, auth.userForSession(session.token));
    ASSERT_TRUE(user.has_value());
    EXPECT_EQ(user->username, "alice");
    EXPECT_EQ(user->display_name, "Alice");
    EXPECT_FALSE(user->private_key_pem.empty());
    EXPECT_FALSE(user->public_key_pem.empty());

    // A bogus token resolves to nobody.
    ASSIGN_OR_FAIL(auto none, auth.userForSession("not-a-token"));
    EXPECT_FALSE(none.has_value());

    // After logout the session no longer resolves.
    EXPECT_TRUE(mw::isExpected(auth.logout(session.token)));
    ASSIGN_OR_FAIL(auto gone, auth.userForSession(session.token));
    EXPECT_FALSE(gone.has_value());
}

TEST(AuthSession, DuplicateUsernameRejected)
{
    auto db = DataSourceSQLite::newFromMemory();
    ASSERT_TRUE(db.has_value());
    mw::Crypto crypto;
    mw::HTTPSessionMock http;
    std::string key(32, 'k');
    Authenticator auth(validConfig(), **db, crypto, key, http);

    Authenticator::PreAuth a{"https://kc.test/realms/main", "sub-a", ""};
    Authenticator::PreAuth b{"https://kc.test/realms/main", "sub-b", ""};
    ASSIGN_OR_FAIL(auto sa, auth.finishSetup(a, "bob", "Bob"));
    (void)sa;
    // Different subject, same username → rejected.
    EXPECT_FALSE(auth.finishSetup(b, "bob", "Bob2").has_value());
}

TEST(AuthSession, DiscoveryParsesEndpoints)
{
    json doc{{"authorization_endpoint", "https://kc.test/auth"},
             {"token_endpoint", "https://kc.test/token"},
             {"jwks_uri", "https://kc.test/certs"},
             {"userinfo_endpoint", "https://kc.test/userinfo"}};
    ASSIGN_OR_FAIL(auto ep, parseDiscovery(doc));
    EXPECT_EQ(ep.authorization_endpoint, "https://kc.test/auth");
    EXPECT_EQ(ep.token_endpoint, "https://kc.test/token");
    EXPECT_EQ(ep.jwks_uri, "https://kc.test/certs");

    json missing{{"authorization_endpoint", "x"}};
    EXPECT_FALSE(parseDiscovery(missing).has_value());
}
