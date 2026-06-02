#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <openssl/rand.h>
#include <spdlog/spdlog.h>
#include <mw/crypto.hpp>
#include <mw/error.hpp>
#include <mw/http_client.hpp>
#include <mw/http_server.hpp>
#include <mw/url.hpp>
#include <mw/utils.hpp>

#include "app.hpp"
#include "auth.hpp"
#include "commit.hpp"
#include "config.hpp"
#include "data.hpp"
#include "structs.hpp"

using unspoken::Authenticator;

namespace
{

mw::HTTPServer::ListenAddress listenAddrFromConfig(const Config& config)
{
    mw::IPSocketInfo sock;
    sock.address = config.listen_address;
    sock.port = config.listen_port;
    return sock;
}

mw::URL baseUrlFromConfig(const Config& config)
{
    // url_root is validated in Config::validateAndFinalize(), so this
    // parse cannot fail by the time App is constructed.
    auto u = mw::URL::fromStr(config.url_root);
    if(u.has_value())
    {
        return *std::move(u);
    }
    return mw::URL();
}

// Generate the per-process 32-byte server key (AES-256-GCM + CSRF).
std::string generateServerKey()
{
    std::string key(32, '\0');
    if(RAND_bytes(reinterpret_cast<unsigned char*>(key.data()), 32) != 1)
    {
        spdlog::warn("RAND_bytes failed generating server key");
    }
    return key;
}

std::string htmlEscape(std::string_view s)
{
    return mw::escapeHTML(s);
}

// Minimal HTML page shell. The rich Inja-templated UI lands in Phase 3;
// Phase 2 only needs functional pages for login/setup.
std::string page(std::string_view title, std::string_view body)
{
    return std::format(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, "
        "initial-scale=1\"><title>{}</title>"
        "<link rel=\"stylesheet\" href=\"static/style.css\"></head>"
        "<body><main>{}</main></body></html>",
        htmlEscape(title), body);
}

void sendHtml(mw::HTTPServer::Response& res, int status, const std::string& html)
{
    res.status = status;
    res.set_content(html, "text/html; charset=utf-8");
}

} // namespace

App::App(const Config& conf)
        : mw::HTTPServer(listenAddrFromConfig(conf)),
          config(conf),
          base_url(baseUrlFromConfig(conf)),
          server_key(generateServerKey())
{}

std::string App::urlFor(const std::string& path) const
{
    if(path.empty())
    {
        return base_url.str();
    }
    return mw::URL(base_url).appendPath(path).str();
}

mw::E<unspoken::DataSourceSQLite*> App::dataSource() const
{
    thread_local std::unique_ptr<unspoken::DataSourceSQLite> conn;
    if(!conn)
    {
        ASSIGN_OR_RETURN(conn, unspoken::DataSourceSQLite::fromFile(
            config.database_path, config.sqlite_busy_timeout_ms));
    }
    return conn.get();
}

// ─── Cookies ───────────────────────────────────────────────────────────

std::string App::cookiePath() const
{
    std::string p = base_url.path();
    if(p.empty()) return "/";
    if(p.back() != '/') p.push_back('/');
    return p;
}

std::optional<std::string> App::cookie(const Request& req,
                                       std::string_view name) const
{
    auto it = req.headers.find("Cookie");
    if(it == req.headers.end()) return std::nullopt;
    std::string_view header = it->second;
    size_t pos = 0;
    while(pos < header.size())
    {
        size_t semi = header.find(';', pos);
        std::string_view pair = header.substr(
            pos, semi == std::string_view::npos ? semi : semi - pos);
        pair = mw::strip(pair);
        size_t eq = pair.find('=');
        if(eq != std::string_view::npos)
        {
            std::string_view k = pair.substr(0, eq);
            if(k == name)
            {
                return std::string(pair.substr(eq + 1));
            }
        }
        if(semi == std::string_view::npos) break;
        pos = semi + 1;
    }
    return std::nullopt;
}

void App::setCookie(Response& res, std::string_view name,
                    std::string_view value, int64_t max_age_seconds) const
{
    // Secure + HttpOnly + SameSite=Lax (design §15.4).
    res.set_header("Set-Cookie", std::format(
        "{}={}; Path={}; Max-Age={}; HttpOnly; Secure; SameSite=Lax",
        name, value, cookiePath(), max_age_seconds));
}

void App::clearCookie(Response& res, std::string_view name) const
{
    res.set_header("Set-Cookie", std::format(
        "{}=; Path={}; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
        name, cookiePath()));
}

mw::E<std::optional<unspoken::User>>
App::currentUser(const Request& req) const
{
    ASSIGN_OR_RETURN(auto* ds, dataSource());
    mw::HTTPSession http;
    Authenticator auth(config, *ds, crypto, server_key, http);
    auto token = cookie(req, unspoken::SESSION_COOKIE);
    if(!token.has_value()) return std::optional<unspoken::User>{};
    return auth.userForSession(*token);
}

// ─── Handlers ──────────────────────────────────────────────────────────

void App::handleHealth([[maybe_unused]] const Request& req,
                       Response& res) const
{
    res.status = 200;
    res.set_content(
        std::string("unspoken ") + unspoken::GIT_COMMIT_HASH + " ok",
        "text/plain");
}

void App::handleIndex(const Request& req, Response& res) const
{
    ASSIGN_OR_RESPOND_ERROR(auto user, currentUser(req), res);
    std::string body;
    if(user.has_value())
    {
        ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
        mw::HTTPSession http;
        Authenticator auth(config, *ds, crypto, server_key, http);
        auto token = cookie(req, unspoken::SESSION_COOKIE).value_or("");
        std::string csrf = auth.csrfFor(token);
        body = std::format(
            "<h1>unspoken</h1><p>Logged in as <strong>@{}@{}</strong> "
            "({}).</p>"
            "<form method=\"post\" action=\"logout\">"
            "<input type=\"hidden\" name=\"csrf\" value=\"{}\">"
            "<button type=\"submit\">Log out</button></form>",
            htmlEscape(user->username), htmlEscape(config.public_domain),
            htmlEscape(user->display_name), htmlEscape(csrf));
    }
    else
    {
        body = "<h1>unspoken</h1><p>Not logged in.</p>"
               "<p><a href=\"login\">Log in</a></p>";
    }
    sendHtml(res, 200, page("unspoken", body));
}

void App::handleLogin([[maybe_unused]] const Request& req, Response& res) const
{
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    mw::HTTPSession http;
    Authenticator auth(config, *ds, crypto, server_key, http);
    ASSIGN_OR_RESPOND_ERROR(std::string url, auth.beginLogin(), res);
    res.set_redirect(url);
}

void App::handleCallback(const Request& req, Response& res) const
{
    if(req.has_param("error"))
    {
        sendHtml(res, 400, page("Login error", std::format(
            "<h1>Login failed</h1><p>{}</p>",
            htmlEscape(req.get_param_value("error")))));
        return;
    }
    if(!req.has_param("state") || !req.has_param("code"))
    {
        sendHtml(res, 400, page("Login error",
            "<h1>Login failed</h1><p>Missing state or code.</p>"));
        return;
    }

    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    mw::HTTPSession http;
    Authenticator auth(config, *ds, crypto, server_key, http);
    ASSIGN_OR_RESPOND_ERROR(auto outcome, auth.completeCallback(
        req.get_param_value("state"), req.get_param_value("code")), res);

    if(outcome.session.has_value())
    {
        setCookie(res, unspoken::SESSION_COOKIE, outcome.session->token,
                  unspoken::SESSION_TTL_SECONDS);
        res.set_redirect(urlFor());
        return;
    }

    // New subject: stash identity in an encrypted cookie and go to setup.
    ASSIGN_OR_RESPOND_ERROR(std::string sealed,
                            auth.sealPreAuth(*outcome.needs_setup), res);
    setCookie(res, unspoken::SETUP_COOKIE, sealed, 600);
    res.set_redirect(urlFor("setup-username"));
}

void App::handleSetupGet(const Request& req, Response& res) const
{
    auto sealed = cookie(req, unspoken::SETUP_COOKIE);
    if(!sealed.has_value())
    {
        res.set_redirect(urlFor("login"));
        return;
    }
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    mw::HTTPSession http;
    Authenticator auth(config, *ds, crypto, server_key, http);
    ASSIGN_OR_RESPOND_ERROR(auto pre, auth.openPreAuth(*sealed), res);
    std::string csrf = auth.setupCsrfFor(*sealed);

    std::string body = std::format(
        "<h1>Choose a username</h1>"
        "<p>This is permanent and appears in your handle "
        "<code>@username@{}</code>.</p>"
        "<form method=\"post\" action=\"setup-username\">"
        "<input type=\"hidden\" name=\"csrf\" value=\"{}\">"
        "<label>Username <input name=\"username\" pattern=\"[a-z0-9_]+\" "
        "maxlength=\"30\" required></label>"
        "<label>Display name <input name=\"display_name\" value=\"{}\"></label>"
        "<button type=\"submit\">Create account</button></form>",
        htmlEscape(config.public_domain), htmlEscape(csrf),
        htmlEscape(pre.suggested_name));
    sendHtml(res, 200, page("Choose a username", body));
}

void App::handleSetupPost(const Request& req, Response& res) const
{
    auto sealed = cookie(req, unspoken::SETUP_COOKIE);
    if(!sealed.has_value())
    {
        res.set_redirect(urlFor("login"));
        return;
    }
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    mw::HTTPSession http;
    Authenticator auth(config, *ds, crypto, server_key, http);

    std::string presented = req.has_param("csrf")
        ? req.get_param_value("csrf") : "";
    if(!auth.checkSetupCsrf(*sealed, presented))
    {
        sendHtml(res, 400, page("Error", "<h1>Invalid CSRF token</h1>"));
        return;
    }
    ASSIGN_OR_RESPOND_ERROR(auto pre, auth.openPreAuth(*sealed), res);

    std::string username = req.has_param("username")
        ? req.get_param_value("username") : "";
    std::string display_name = req.has_param("display_name")
        ? req.get_param_value("display_name") : "";

    auto session = auth.finishSetup(pre, username, display_name);
    if(!session.has_value())
    {
        // Validation/uniqueness failures are user errors → re-show the form.
        std::string csrf = auth.setupCsrfFor(*sealed);
        std::string body = std::format(
            "<h1>Choose a username</h1>"
            "<p class=\"error\">{}</p>"
            "<form method=\"post\" action=\"setup-username\">"
            "<input type=\"hidden\" name=\"csrf\" value=\"{}\">"
            "<label>Username <input name=\"username\" value=\"{}\" "
            "pattern=\"[a-z0-9_]+\" maxlength=\"30\" required></label>"
            "<label>Display name <input name=\"display_name\" value=\"{}\">"
            "</label>"
            "<button type=\"submit\">Create account</button></form>",
            htmlEscape(mw::errorMsg(session.error())), htmlEscape(csrf),
            htmlEscape(username), htmlEscape(display_name));
        sendHtml(res, 400, page("Choose a username", body));
        return;
    }

    clearCookie(res, unspoken::SETUP_COOKIE);
    setCookie(res, unspoken::SESSION_COOKIE, session->token,
              unspoken::SESSION_TTL_SECONDS);
    res.set_redirect(urlFor());
}

void App::handleLogout(const Request& req, Response& res) const
{
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    mw::HTTPSession http;
    Authenticator auth(config, *ds, crypto, server_key, http);

    auto token = cookie(req, unspoken::SESSION_COOKIE).value_or("");
    std::string presented = req.has_param("csrf")
        ? req.get_param_value("csrf") : "";
    if(!auth.checkCsrf(token, presented))
    {
        sendHtml(res, 400, page("Error", "<h1>Invalid CSRF token</h1>"));
        return;
    }
    if(auto lr = auth.logout(token); !lr.has_value())
    {
        res.status = 500;
        res.set_content(mw::errorMsg(lr.error()), "text/plain");
        return;
    }
    clearCookie(res, unspoken::SESSION_COOKIE);
    res.set_redirect(urlFor());
}

// ─── Routing ───────────────────────────────────────────────────────────

void App::setup()
{
    if(std::filesystem::is_directory(config.static_dir))
    {
        spdlog::info("Mounting static dir at /static from {}...",
                     config.static_dir);
        if(!server.set_mount_point("/static", config.static_dir))
        {
            spdlog::warn("Failed to mount static dir {}", config.static_dir);
        }
    }
    else
    {
        spdlog::info("Static dir {} does not exist; not mounting.",
                     config.static_dir);
    }

    server.Get("/health", [&](const Request& req, Response& res)
    {
        handleHealth(req, res);
    });
    server.Get("/", [&](const Request& req, Response& res)
    {
        handleIndex(req, res);
    });
    server.Get("/login", [&](const Request& req, Response& res)
    {
        handleLogin(req, res);
    });
    server.Get("/callback", [&](const Request& req, Response& res)
    {
        handleCallback(req, res);
    });
    server.Get("/setup-username", [&](const Request& req, Response& res)
    {
        handleSetupGet(req, res);
    });
    server.Post("/setup-username", [&](const Request& req, Response& res)
    {
        handleSetupPost(req, res);
    });
    server.Post("/logout", [&](const Request& req, Response& res)
    {
        handleLogout(req, res);
    });
}
