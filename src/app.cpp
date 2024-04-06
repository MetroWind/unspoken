#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <memory>
#include <regex>
#include <sstream>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include <httplib.h>
#include <inja.hpp>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "app.hpp"
#include "auth.hpp"
#include "config.hpp"
#include "error.hpp"
#include "http_client.hpp"
#include "url.hpp"
#include "types.hpp"
#include "utils.hpp"

#define _ASSIGN_OR_RESPOND_ERROR(tmp, var, val, res, the_code)                   \
    auto tmp = val;                                                     \
    if(!tmp.has_value())                                                \
    {                                                                   \
        if(std::holds_alternative<HTTPError>(tmp.error()))              \
        {                                                               \
            const HTTPError& e = std::get<HTTPError>(tmp.error());      \
            res.status = e.code;                                        \
            res.set_content(e.msg, CONTENT_TYPE_TEXT);                       \
            return;                                                     \
        }                                                               \
        else                                                            \
        {                                                               \
            res.status = (the_code);                                        \
            res.set_content(std::visit([](const auto& e) { return e.msg; }, \
                                       tmp.error()),                    \
                            CONTENT_TYPE_TEXT);                              \
            return;                                                     \
        }                                                               \
    }                                                                   \
    var = std::move(tmp).value()

// Val should be a rvalue.
#define ASSIGN_OR_RESPOND_ERROR(var, val, res, code)                         \
    _ASSIGN_OR_RESPOND_ERROR(_CONCAT_NAMES(assign_or_return_tmp, __COUNTER__), \
                             var, val, res, code)

namespace {

constexpr char CONTENT_TYPE_JSON[] = "application/json";
constexpr char CONTENT_TYPE_HTML[] = "text/html";
constexpr char CONTENT_TYPE_TEXT[] = "text/plain";

std::unordered_map<std::string, std::string> parseCookies(std::string_view value)
{
    std::unordered_map<std::string, std::string> cookies;
    size_t begin = 0;
    while(true)
    {
        if(begin >= value.size())
        {
            break;
        }

        size_t semicolon = value.find(';', begin);
        if(semicolon == std::string::npos)
        {
            semicolon = value.size();
        }

        std::string_view section = value.substr(begin, semicolon - begin);

        begin = semicolon + 1;
        // Skip spaces
        while(begin < value.size() && value[begin] == ' ')
        {
            begin++;
        }

        size_t equal = section.find('=');
        if(equal == std::string::npos) continue;
        cookies.emplace(section.substr(0, equal),
                        section.substr(equal+1, semicolon - equal - 1));
        if(semicolon >= value.size())
        {
            continue;
        }
    }
    return cookies;
}

void setTokenCookies(const Tokens& tokens, httplib::Response& res)
{
    int64_t expire_sec = 300;
    if(tokens.expiration.has_value())
    {
        auto expire = std::chrono::duration_cast<std::chrono::seconds>(
            *tokens.expiration - Clock::now());
        expire_sec = expire.count();
    }
    res.set_header("Set-Cookie", std::format(
                       "access-token={}; Max-Age={}",
                       urlEncode(tokens.access_token), expire_sec));
    // Add refresh token to cookie, with one month expiration.
    if(tokens.refresh_token.has_value())
    {
        expire_sec = 1800;
        if(tokens.refresh_expiration.has_value())
        {
            auto expire = std::chrono::duration_cast<std::chrono::seconds>(
                *tokens.refresh_expiration - Clock::now());
            expire_sec = expire.count();
        }

        res.set_header("Set-Cookie", std::format(
                           "refresh-token={}; Max-Age={}",
                           urlEncode(*tokens.refresh_token), expire_sec));
    }
}

void copyToHttplibReq(const HTTPRequest& src, httplib::Request& dest)
{
    std::string type = "text/plain";
    if(auto it = src.header.find("Content-Type");
       it != std::end(src.header))
    {
        type = src.header.at("Content-Type");
    }
    dest.set_header("Content-Type", type);
    dest.body = src.request_data;
    for(const auto& [key, value]: src.header)
    {
        if(key != "Content-Type")
        {
            dest.set_header(key, value);
        }
    }
}

} // namespace

E<WebFingerQuery> WebFingerQuery::fromRequest(const httplib::Request& req)
{
    WebFingerQuery query;
    if(req.has_param("resource"))
    {
        query.type = RESOURCE;
    }
    else
    {
        return std::unexpected(runtimeError("Unsupported webfinger query."));
    }
    std::string value = req.get_param_value("resource");
    size_t sep = value.find(':');
    if(sep == std::string::npos)
    {
        return std::unexpected(runtimeError("Invalid webfinger query."));
    }
    std::string_view resource_type(value.data(), sep);
    if(resource_type == "acct")
    {
        query.resource_type = ACCOUNT;
    }
    else
    {
        return std::unexpected(runtimeError(
            "Unsupported resource type in webfinger."));
    }
    query.arg = value.substr(sep + 1);
    return query;
}

E<App::SessionValidation> App::validateSession(const httplib::Request& req) const
{
    if(!req.has_header("Cookie"))
    {
        spdlog::debug("Request has no cookie.");
        return SessionValidation::invalid();
    }

    auto cookies = parseCookies(req.get_header_value("Cookie"));
    if(auto it = cookies.find("access-token");
       it != std::end(cookies))
    {
        spdlog::debug("Cookie has access token.");
        Tokens tokens;
        tokens.access_token = it->second;
        E<UserInfo> user = auth->getUser(tokens);
        if(user.has_value())
        {
            return SessionValidation::valid(*std::move(user));
        }
    }
    // No access token or access token expired
    if(auto it = cookies.find("refresh-token");
       it != std::end(cookies))
    {
        spdlog::debug("Cookie has refresh token.");
        // Try to refresh the tokens.
        ASSIGN_OR_RETURN(Tokens tokens, auth->refreshTokens(it->second));
        ASSIGN_OR_RETURN(UserInfo user, auth->getUser(tokens));
        return SessionValidation::refreshed(std::move(user), std::move(tokens));
    }
    return SessionValidation::invalid();
}

App::App(const Configuration& conf, std::unique_ptr<AuthInterface> openid_auth,
         std::unique_ptr<DataSourceInterface> data)
        : config(conf),
          templates((std::filesystem::path(config.data_dir) / "templates" / "")
                    .string()),
          auth(std::move(openid_auth)),
          data_source(std::move(data)),
          crypto(),
          url_manager(config),
          fed(config, *data_source, crypto, url_manager)
{
    templates.add_callback("url_for", 2, [&](const inja::Arguments& args)
    {
        return urlFor(args.at(0)->get_ref<const std::string&>(),
                      args.at(1)->get_ref<const std::string&>());
    });
}

std::string App::urlFor(const std::string& name,
                        const std::string& arg) const
{
    return url_manager.urlFor(name, arg);
}

void App::handleIndex(const httplib::Request& req, httplib::Response& res) const
{
    E<SessionValidation> session = validateSession(req);
    if(!session.has_value())
    {
        return;
    }

    switch(session->status)
    {
    case SessionValidation::INVALID:
        // TODO: What to do?
        return;
    case SessionValidation::VALID:
        res.set_redirect(urlFor("weekly", session->user.name), 302);
        return;
    case SessionValidation::REFRESHED:
        setTokenCookies(session->new_tokens, res);
        res.set_redirect(urlFor("weekly", session->user.name), 302);
        return;
    }
}

void App::handleLogin(httplib::Response& res) const
{
    res.set_redirect(auth->initialURL(), 301);
}

void App::handleOpenIDRedirect(const httplib::Request& req,
                               httplib::Response& res) const
{
    if(req.has_param("error"))
    {
        res.status = 500;
        if(req.has_param("error_description"))
        {
            res.set_content(
                std::format("{}: {}.", req.get_param_value("error"),
                            req.get_param_value("error_description")),
                CONTENT_TYPE_TEXT);
        }
        return;
    }
    else if(!req.has_param("code"))
    {
        res.status = 500;
        res.set_content("No error or code in auth response", CONTENT_TYPE_TEXT);
        return;
    }

    std::string code = req.get_param_value("code");
    spdlog::debug("OpenID server visited {} with code {}.", req.path, code);
    ASSIGN_OR_RESPOND_ERROR(Tokens tokens, auth->authenticate(code), res, 500);
    ASSIGN_OR_RESPOND_ERROR(UserInfo user, auth->getUser(tokens), res, 500);

    setTokenCookies(tokens, res);
    res.set_redirect(urlFor("index", ""), 301);
}

void App::handleWebFinger(const httplib::Request& req, httplib::Response& res)
{
    ASSIGN_OR_RESPOND_ERROR(nlohmann::json data, fed.handleWebFinger(req),
                            res, 500);
    res.set_content(data.dump(), CONTENT_TYPE_JSON);
}

void App::handleUserInfo(httplib::Response& res, const std::string& username)
{
    ASSIGN_OR_RESPOND_ERROR(nlohmann::json data, fed.handleUserInfo(username),
                            res, 500);
    res.set_content(data.dump(), CONTENT_TYPE_JSON);
}

E<std::string> App::httpSig(const std::string& username, const std::string& key,
                            const httplib::Request& req)
{
    Time now = Clock::now();
    // Time expire = now + std::chrono::minutes(5);
    ASSIGN_OR_RETURN(URL prefix, URL::fromStr(config.url_prefix));
    const std::string key_id = prefix.appendPath(urlFor("user", username))
        .str() + KEY_URL_SUFFIX;
    const std::string_view target = req.path;
    const std::time_t now_t = std::chrono::system_clock::to_time_t(now);
    char date[128];
    size_t date_length = std::strftime(date, 128, "%a, %d %b %Y %H:%M:%S GMT",
                                       std::gmtime(&now_t));
    if(date_length >= 128 || date_length == 0)
    {
        return std::unexpected(runtimeError(
            "Failed to convert time to string."));
    }
    const std::string str_to_sign =
        std::format("(request-target): post {}\nhost: {}\ndate: {}",
                    target, server_host, date);
    const std::string sig = base64Encode(crypto.sig(key, str_to_sign));
    return std::format(R"(keyId="{}",headers="(request-target) host date",signature="{}")",
                       key_id, sig);
}

void App::start()
{
    httplib::Server server;
    std::string statics_dir = (std::filesystem::path(config.data_dir) /
                               "statics").string();
    spdlog::info("Mounting static dir at {}...", statics_dir);
    auto ret = server.set_mount_point("/statics", statics_dir);
    if (!ret)
    {
        spdlog::error("Failed to mount statics");
    }

    server.Get("/", [&](const httplib::Request& req,
                        httplib::Response& res)
    {
        handleIndex(req, res);
    });

    server.Get("/login", [&]([[maybe_unused]] const httplib::Request& req,
                             httplib::Response& res)
    {
        handleLogin(res);
    });

    server.Get("/openid-redirect", [&](const httplib::Request& req,
                                       httplib::Response& res)
    {
        handleOpenIDRedirect(req, res);
    });

    server.Get("/fed/user/:name",
               [&](const httplib::Request& req, httplib::Response& res)
    {
        handleUserInfo(res, req.path_params.at("name"));
    });

    spdlog::info("Listening at http://{}:{}/...", config.listen_address,
                 config.listen_port);
    server.listen(config.listen_address, config.listen_port);
}
