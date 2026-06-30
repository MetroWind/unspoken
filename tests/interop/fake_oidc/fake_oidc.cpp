#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

#include <nlohmann/json.hpp>
#include <mw/crypto.hpp>
#include <mw/error.hpp>
#include <mw/http_server.hpp>
#include <mw/url.hpp>
#include <mw/utils.hpp>

#include "auth.hpp"

using json = nlohmann::json;

namespace
{

struct UserFixture
{
    std::string sub;
    std::string name;
    std::string preferred_username;
};

struct CodeRecord
{
    std::string username;
    std::string client_id;
    std::string redirect_uri;
    std::string nonce;
    int64_t issued_at = 0;
    bool used = false;
};

struct FakeOidcConfig
{
    std::string issuer = "http://fake-oidc.test:9000";
    std::string listen_host = "0.0.0.0";
    int listen_port = 9000;
    std::string client_id = "unspoken-interop";
    std::string client_secret = "unspoken-interop-secret";
    std::string default_user = "alice";
    int token_ttl_seconds = 3600;
    std::string private_key_path = "jwt_private.pem";
    std::string public_jwk_path = "jwt_public.jwk";
};

std::unordered_map<std::string, UserFixture> users()
{
    return {
        {"alice", {"alice-sub", "Alice", "alice"}},
        {"carol", {"carol-sub", "Carol", "carol"}},
    };
}

int64_t nowSeconds()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string envOr(const char* name, std::string fallback)
{
    const char* value = std::getenv(name);
    if(value == nullptr || std::string_view(value).empty()) return fallback;
    return value;
}

int envIntOr(const char* name, int fallback)
{
    const char* value = std::getenv(name);
    if(value == nullptr) return fallback;
    try
    {
        return std::stoi(value);
    }
    catch(...)
    {
        return fallback;
    }
}

FakeOidcConfig loadConfig()
{
    FakeOidcConfig c;
    c.issuer = envOr("OIDC_ISSUER", c.issuer);
    c.listen_host = envOr("OIDC_LISTEN_HOST", c.listen_host);
    c.listen_port = envIntOr("OIDC_LISTEN_PORT", c.listen_port);
    c.client_id = envOr("OIDC_CLIENT_ID", c.client_id);
    c.client_secret = envOr("OIDC_CLIENT_SECRET", c.client_secret);
    c.default_user = envOr("OIDC_DEFAULT_USER", c.default_user);
    c.token_ttl_seconds =
        envIntOr("OIDC_TOKEN_TTL_SECONDS", c.token_ttl_seconds);
    c.private_key_path = envOr("OIDC_PRIVATE_KEY", c.private_key_path);
    c.public_jwk_path = envOr("OIDC_PUBLIC_JWK", c.public_jwk_path);
    return c;
}

mw::E<std::string> readFile(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if(!in)
    {
        return std::unexpected(mw::runtimeError(
            std::format("Cannot open {}", path.string())));
    }
    return std::string(std::istreambuf_iterator<char>(in),
                       std::istreambuf_iterator<char>());
}

std::string decodeFormComponent(std::string_view value)
{
    std::string out;
    for(size_t i = 0; i < value.size(); ++i)
    {
        if(value[i] == '+')
        {
            out.push_back(' ');
        }
        else if(value[i] == '%' && i + 2 < value.size())
        {
            unsigned int byte = 0;
            std::string hex(value.substr(i + 1, 2));
            if(std::sscanf(hex.c_str(), "%x", &byte) == 1)
            {
                out.push_back(static_cast<char>(byte));
                i += 2;
            }
        }
        else
        {
            out.push_back(value[i]);
        }
    }
    return out;
}

std::unordered_map<std::string, std::string> parseForm(std::string_view body)
{
    std::unordered_map<std::string, std::string> out;
    size_t pos = 0;
    while(pos <= body.size())
    {
        size_t amp = body.find('&', pos);
        std::string_view item = body.substr(
            pos, amp == std::string_view::npos ? amp : amp - pos);
        size_t eq = item.find('=');
        if(eq != std::string_view::npos)
        {
            out[decodeFormComponent(item.substr(0, eq))] =
                decodeFormComponent(item.substr(eq + 1));
        }
        if(amp == std::string_view::npos) break;
        pos = amp + 1;
    }
    return out;
}

std::optional<std::pair<std::string, std::string>>
basicAuth(const mw::HTTPServer::Request& req)
{
    auto it = req.headers.find("Authorization");
    if(it == req.headers.end()) return std::nullopt;
    constexpr std::string_view prefix = "Basic ";
    if(!std::string_view(it->second).starts_with(prefix)) return std::nullopt;
    auto decoded = mw::base64Decode(
        std::string(it->second.substr(prefix.size())));
    if(!decoded.has_value()) return std::nullopt;
    std::string text(decoded->begin(), decoded->end());
    size_t colon = text.find(':');
    if(colon == std::string::npos) return std::nullopt;
    return std::make_pair(text.substr(0, colon), text.substr(colon + 1));
}

void setJson(mw::HTTPServer::Response& res, const json& body)
{
    res.status = 200;
    res.set_content(body.dump(), "application/json");
}

void badRequest(mw::HTTPServer::Response& res, std::string_view msg)
{
    res.status = 400;
    res.set_content(std::string(msg), "text/plain");
}

class FakeOidcServer : public mw::HTTPServer
{
public:
    FakeOidcServer(FakeOidcConfig conf, std::string private_key,
                   json public_jwk)
            : mw::HTTPServer(mw::IPSocketInfo{conf.listen_host,
                                              conf.listen_port}),
              config(std::move(conf)),
              private_key_pem(std::move(private_key)),
              public_jwk_doc(std::move(public_jwk)),
              selected_user(config.default_user)
    {}

private:
    void setup() override
    {
        server.Get("/.well-known/openid-configuration",
                   [this](const Request&, Response& res)
        {
            setJson(res, discovery());
        });
        server.Get("/jwks", [this](const Request&, Response& res)
        {
            res.set_header("Cache-Control", "no-store");
            setJson(res, json{{"keys", json::array({public_jwk_doc})}});
        });
        server.Get("/select-user", [this](const Request&, Response& res)
        {
            setJson(res, json{{"username", selected_user}});
        });
        server.Post("/select-user", [this](const Request& req, Response& res)
        {
            json body = json::parse(req.body, nullptr, false);
            std::string username = body.is_object()
                ? body.value("username", "") : "";
            auto fixtures = users();
            auto it = fixtures.find(username);
            if(it == fixtures.end())
            {
                res.status = 404;
                res.set_content("Unknown user", "text/plain");
                return;
            }
            selected_user = username;
            setJson(res, json{{"username", username}, {"sub", it->second.sub}});
        });
        server.Get("/authorize", [this](const Request& req, Response& res)
        {
            handleAuthorize(req, res);
        });
        server.Post("/token", [this](const Request& req, Response& res)
        {
            handleToken(req, res);
        });
    }

    json discovery() const
    {
        return {
            {"issuer", config.issuer},
            {"authorization_endpoint", config.issuer + "/authorize"},
            {"token_endpoint", config.issuer + "/token"},
            {"jwks_uri", config.issuer + "/jwks"},
            {"response_types_supported", json::array({"code"})},
            {"subject_types_supported", json::array({"public"})},
            {"id_token_signing_alg_values_supported", json::array({"RS256"})},
            {"scopes_supported", json::array({"openid", "profile"})},
            {"claims_supported", json::array({
                "iss", "sub", "aud", "exp", "iat", "nonce",
                "preferred_username", "name",
            })},
            {"token_endpoint_auth_methods_supported", json::array({
                "client_secret_post", "client_secret_basic",
            })},
        };
    }

    void handleAuthorize(const Request& req, Response& res)
    {
        std::string client_id = req.get_param_value("client_id");
        std::string redirect_uri = req.get_param_value("redirect_uri");
        std::string response_type = req.get_param_value("response_type");
        std::string scope = req.get_param_value("scope");
        std::string state = req.get_param_value("state");
        std::string nonce = req.get_param_value("nonce");
        if(response_type != "code" || client_id != config.client_id
           || !redirect_uri.starts_with("http://unspoken.test:8080/callback")
           || scope.find("openid") == std::string::npos || state.empty()
           || nonce.empty())
        {
            badRequest(res, "Invalid authorization request");
            return;
        }

        std::string code = unspoken::randomToken(16);
        codes[code] = CodeRecord{
            selected_user, client_id, redirect_uri, nonce, nowSeconds(), false};
        res.set_redirect(std::format("{}?code={}&state={}", redirect_uri,
                                     mw::urlEncode(code),
                                     mw::urlEncode(state)));
    }

    void handleToken(const Request& req, Response& res)
    {
        auto form = parseForm(req.body);
        if(auto basic = basicAuth(req); basic.has_value())
        {
            form["client_id"] = basic->first;
            form["client_secret"] = basic->second;
        }
        auto code_it = form.find("code");
        if(form["grant_type"] != "authorization_code"
           || code_it == form.end()
           || form["client_id"] != config.client_id
           || form["client_secret"] != config.client_secret)
        {
            tokenError(res, "invalid_request", "token request is invalid");
            return;
        }
        auto record_it = codes.find(code_it->second);
        if(record_it == codes.end() || record_it->second.used
           || nowSeconds() - record_it->second.issued_at > 300
           || form["redirect_uri"] != record_it->second.redirect_uri)
        {
            tokenError(res, "invalid_grant",
                       "authorization code is invalid");
            return;
        }

        record_it->second.used = true;
        auto fixtures = users();
        const auto& user = fixtures.at(record_it->second.username);
        int64_t iat = nowSeconds();
        json header{{"typ", "JWT"}, {"alg", "RS256"},
                    {"kid", "interop-rsa-1"}};
        json payload{
            {"iss", config.issuer},
            {"sub", user.sub},
            {"aud", config.client_id},
            {"exp", iat + config.token_ttl_seconds},
            {"iat", iat},
            {"nonce", record_it->second.nonce},
            {"preferred_username", user.preferred_username},
            {"name", user.name},
        };
        mw::Crypto crypto;
        auto jwt = unspoken::signRs256Jwt(header, payload, private_key_pem,
                                          crypto);
        if(!jwt.has_value())
        {
            res.status = 500;
            res.set_content(mw::errorMsg(jwt.error()), "text/plain");
            return;
        }
        setJson(res, json{
            {"access_token", unspoken::randomToken(16)},
            {"token_type", "Bearer"},
            {"expires_in", config.token_ttl_seconds},
            {"scope", "openid profile"},
            {"id_token", *jwt},
        });
    }

    void tokenError(Response& res, std::string_view error,
                    std::string_view description)
    {
        res.status = 400;
        res.set_content(json{{"error", error},
                             {"error_description", description}}.dump(),
                        "application/json");
    }

    FakeOidcConfig config;
    std::string private_key_pem;
    json public_jwk_doc;
    std::string selected_user;
    std::unordered_map<std::string, CodeRecord> codes;
};

} // namespace

int main()
{
    FakeOidcConfig config = loadConfig();
    auto private_key = readFile(config.private_key_path);
    if(!private_key.has_value())
    {
        std::fprintf(stderr, "%s\n", mw::errorMsg(private_key.error()).c_str());
        return 1;
    }
    auto jwk_text = readFile(config.public_jwk_path);
    if(!jwk_text.has_value())
    {
        std::fprintf(stderr, "%s\n", mw::errorMsg(jwk_text.error()).c_str());
        return 1;
    }
    json jwk = json::parse(*jwk_text, nullptr, false);
    if(!jwk.is_object())
    {
        std::fprintf(stderr, "Invalid JWK fixture\n");
        return 1;
    }

    FakeOidcServer server(config, *private_key, jwk);
    auto started = server.start();
    if(!started.has_value())
    {
        std::fprintf(stderr, "%s\n", mw::errorMsg(started.error()).c_str());
        return 1;
    }
    server.wait();
    return 0;
}
