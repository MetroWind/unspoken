#include <cstdint>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/rand.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <inja.hpp>
#include <mw/crypto.hpp>
#include <mw/error.hpp>
#include <mw/http_client.hpp>
#include <mw/http_server.hpp>
#include <mw/url.hpp>
#include <mw/utils.hpp>

#include "app.hpp"
#include "attachments.hpp"
#include "auth.hpp"
#include "commit.hpp"
#include "config.hpp"
#include "data.hpp"
#include "federation.hpp"
#include "render.hpp"
#include "service.hpp"
#include "structs.hpp"

using unspoken::Authenticator;
using unspoken::Service;

#undef ASSIGN_OR_RESPOND_ERROR
#define _UNSPOKEN_ASSIGN_OR_RESPOND_ERROR(tmp, var, val, res)          \
    auto tmp = val;                                                     \
    if(!tmp.has_value())                                                \
    {                                                                   \
        respondError(tmp.error(), res);                                 \
        return;                                                         \
    }                                                                   \
    var = std::move(tmp).value()

#define ASSIGN_OR_RESPOND_ERROR(var, val, res)                         \
    _UNSPOKEN_ASSIGN_OR_RESPOND_ERROR(                                 \
        _CONCAT_NAMES(assign_or_return_tmp, __COUNTER__), var, val, res)

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
    auto u = mw::URL::fromStr(config.url_root);
    if(u.has_value()) return *std::move(u);
    return mw::URL();
}

std::string generateServerKey()
{
    std::string key(32, '\0');
    if(RAND_bytes(reinterpret_cast<unsigned char*>(key.data()), 32) != 1)
    {
        spdlog::warn("RAND_bytes failed generating server key");
    }
    return key;
}

inja::Environment makeEnv(const Config& config)
{
    std::string path = config.template_dir;
    if(!path.empty() && path.back() != '/') path.push_back('/');
    inja::Environment env(path);
    env.set_trim_blocks(true);
    env.set_lstrip_blocks(true);
    return env;
}

// Read a POST form field, returning "" when absent.
std::string param(const mw::HTTPServer::Request& req, const char* name)
{
    if(req.has_param(name)) return req.get_param_value(name);
    auto file = req.get_file_value(name);
    if(file.filename.empty()) return file.content;
    return "";
}

bool hasParam(const mw::HTTPServer::Request& req, const char* name)
{
    return !param(req, name).empty();
}

std::optional<int64_t> parseInt64(std::string_view value)
{
    if(value.empty()) return std::nullopt;
    int64_t out = 0;
    const char* first = value.data();
    const char* last = value.data() + value.size();
    auto [ptr, ec] = std::from_chars(first, last, out);
    if(ec != std::errc() || ptr != last || out <= 0) return std::nullopt;
    return out;
}

std::optional<unspoken::Cursor>
cursorFromRequest(const mw::HTTPServer::Request& req,
                  mw::HTTPServer::Response& res, bool allow_min)
{
    unspoken::Cursor cursor;
    if(req.has_param("max_id"))
    {
        auto parsed = parseInt64(req.get_param_value("max_id"));
        if(!parsed.has_value())
        {
            res.status = 400;
            res.set_content("Bad cursor", "text/plain");
            return std::nullopt;
        }
        cursor.max_id = *parsed;
    }
    if(allow_min && req.has_param("min_id"))
    {
        auto parsed = parseInt64(req.get_param_value("min_id"));
        if(!parsed.has_value())
        {
            res.status = 400;
            res.set_content("Bad cursor", "text/plain");
            return std::nullopt;
        }
        cursor.min_id = *parsed;
    }
    return cursor;
}

std::string headerValue(const mw::HTTPServer::Request& req,
                        const std::string& name)
{
    auto it = req.headers.find(name);
    if(it == req.headers.end()) return "";
    return it->second;
}

void setJson(mw::HTTPServer::Response& res, const nlohmann::json& json,
             const char* content_type = "application/activity+json")
{
    res.status = 200;
    res.set_content(json.dump(), content_type);
}

unspoken::IncomingHttpRequest incomingRequest(
    const mw::HTTPServer::Request& req)
{
    unspoken::IncomingHttpRequest out;
    out.method = req.method;
    out.target = req.target.empty() ? req.path : req.target;
    out.body = req.body;
    for(const auto& [k, v] : req.headers) out.headers[k] = v;
    return out;
}

void respondError(const mw::Error& error, mw::HTTPServer::Response& res)
{
    if(const auto* e = error.as<mw::HTTPError>())
    {
        res.status = e->code;
        res.set_content(e->code >= 500 ? "Internal server error" : e->msg,
                        "text/plain");
        if(e->code >= 500) spdlog::error("HTTP {}: {}", e->code, e->msg);
    }
    else
    {
        spdlog::error("Internal error: {}", mw::errorMsg(error));
        res.status = 500;
        res.set_content("Internal server error", "text/plain");
    }
}

// Map a failed E<void> onto the response and report whether it failed.
// (libmw provides ASSIGN_OR_RESPOND_ERROR only for value-returning E<T>.)
bool respondIfError(const mw::E<void>& r, mw::HTTPServer::Response& res)
{
    if(r.has_value()) return false;
    respondError(r.error(), res);
    return true;
}

bool respondIfCannotView(const Service& svc, const unspoken::Post& post,
                         const std::optional<unspoken::User>& viewer,
                         mw::HTTPServer::Response& res)
{
    auto visible = svc.canViewPost(post, viewer);
    if(!visible.has_value())
    {
        respondError(visible.error(), res);
        return true;
    }
    if(!*visible)
    {
        res.status = 404;
        res.set_content("Not found", "text/plain");
        return true;
    }
    return false;
}

nlohmann::json collectionRootJson(const std::string& collection_uri)
{
    return {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", collection_uri},
        {"type", "OrderedCollection"},
        {"first", collection_uri + "?page=true"},
    };
}

std::string pageUrl(const std::string& collection_uri, std::string_view key,
                    int64_t value)
{
    return std::format("{}?page=true&{}={}", collection_uri, key, value);
}

nlohmann::json collectionPageJson(
    const std::string& collection_uri, const std::string& self_uri,
    const nlohmann::json& ordered_items, std::optional<int64_t> next_max_id,
    std::optional<int64_t> prev_min_id)
{
    nlohmann::json page = {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", self_uri},
        {"type", "OrderedCollectionPage"},
        {"partOf", collection_uri},
        {"orderedItems", ordered_items},
    };
    if(next_max_id.has_value())
        page["next"] = pageUrl(collection_uri, "max_id", *next_max_id);
    if(prev_min_id.has_value())
        page["prev"] = pageUrl(collection_uri, "min_id", *prev_min_id);
    return page;
}

} // namespace

App::App(const Config& conf)
        : mw::HTTPServer(listenAddrFromConfig(conf)),
          config(conf),
          base_url(baseUrlFromConfig(conf)),
          server_key(generateServerKey()),
          emoji(unspoken::EmojiRegistry::scan(conf.emoji_dir, conf.url_root)),
          templates(makeEnv(conf))
{}

App::~App()
{
    stopJobWorkers();
}

std::string App::urlFor(const std::string& path) const
{
    if(path.empty()) return base_url.str();
    return mw::URL(base_url).appendPath(path).str();
}

void App::startJobWorkers()
{
    if(config.job_workers <= 0 || !job_worker_threads.empty()) return;
    job_workers_stop = false;
    for(int i = 0; i < config.job_workers; ++i)
    {
        job_worker_threads.emplace_back([this, i] { jobWorkerLoop(i); });
    }
    spdlog::info("Started {} federation job worker(s)",
                 config.job_workers);
}

void App::stopJobWorkers()
{
    job_workers_stop = true;
    for(auto& t : job_worker_threads)
    {
        if(t.joinable()) t.join();
    }
    job_worker_threads.clear();
}

void App::jobWorkerLoop(int worker_id) const
{
    auto db = unspoken::DataSourceSQLite::fromFile(
        config.database_path, config.sqlite_busy_timeout_ms);
    if(!db.has_value())
    {
        spdlog::error("Federation worker {} failed to open DB: {}",
                      worker_id, mw::errorMsg(db.error()));
        return;
    }

    mw::Crypto local_crypto;
    mw::HTTPSession http;
    while(!job_workers_stop)
    {
        int64_t now = mw::timeToSeconds(mw::Clock::now());
        auto ran = unspoken::runFederationJobOnce(
            config, **db, local_crypto, http, now);
        if(!ran.has_value())
        {
            spdlog::warn("Federation worker {} failed: {}",
                         worker_id, mw::errorMsg(ran.error()));
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }
        if(!*ran)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
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
            if(k == name) return std::string(pair.substr(eq + 1));
        }
        if(semi == std::string_view::npos) break;
        pos = semi + 1;
    }
    return std::nullopt;
}

void App::setCookie(Response& res, std::string_view name,
                    std::string_view value, int64_t max_age_seconds) const
{
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

std::string App::sessionToken(const Request& req) const
{
    return cookie(req, unspoken::SESSION_COOKIE).value_or("");
}

// ─── Rendering helpers ─────────────────────────────────────────────────

nlohmann::json
App::baseContext(const Request& req,
                 const std::optional<unspoken::User>& viewer) const
{
    nlohmann::json ctx;
    ctx["site"]["title"] = "unspoken";
    ctx["site"]["public_domain"] = mw::escapeHTML(config.public_domain);
    ctx["site"]["root"] = cookiePath();
    ctx["site"]["commit"] = unspoken::GIT_COMMIT_HASH;
    ctx["logged_in"] = viewer.has_value();
    ctx["error"] = "";
    // Default so _post.html can compare against it on non-thread pages
    // (post ids start at 1, so 0 never highlights).
    ctx["focus_id"] = 0;

    // Emoji picker data (escaped URLs) for composers.
    nlohmann::json emoji_arr = nlohmann::json::array();
    for(const auto& e : emoji.all())
    {
        nlohmann::json ej;
        ej["shortcode"] = mw::escapeHTML(e.shortcode);
        ej["image_url"] = mw::escapeHTML(e.image_url);
        emoji_arr.push_back(std::move(ej));
    }
    ctx["emoji"] = emoji_arr;

    if(viewer.has_value())
    {
        nlohmann::json me;
        me["username"] = mw::escapeHTML(viewer->username);
        me["display_name"] = mw::escapeHTML(
            viewer->display_name.empty() ? viewer->username
                                         : viewer->display_name);
        me["handle"] = mw::escapeHTML(std::format(
            "@{}@{}", viewer->username, config.public_domain));
        ctx["me"] = me;

        if(auto ds = dataSource(); ds.has_value())
        {
            mw::HTTPSession http;
            Authenticator auth(config, **ds, crypto, server_key, http);
            ctx["csrf"] = auth.csrfFor(sessionToken(req));
        }
    }
    return ctx;
}

void App::render(Response& res, int status, const std::string& tmpl,
                 const nlohmann::json& data) const
{
    try
    {
        std::string html = templates.render_file(tmpl, data);
        res.status = status;
        res.set_content(html, "text/html; charset=utf-8");
    }
    catch(const std::exception& e)
    {
        spdlog::error("Template render error ({}): {}", tmpl, e.what());
        res.status = 500;
        res.set_content("Template error", "text/plain");
    }
}

bool App::csrfOk(const Request& req) const
{
    auto ds = dataSource();
    if(!ds.has_value()) return false;
    mw::HTTPSession http;
    Authenticator auth(config, **ds, crypto, server_key, http);
    return auth.checkCsrf(sessionToken(req), param(req, "csrf"));
}

std::string App::redirectTarget(const Request& req) const
{
    if(auto it = req.headers.find("Referer"); it != req.headers.end()
       && !it->second.empty())
    {
        return it->second;
    }
    return urlFor();
}

// ─── Auth handlers (Phase 2; unchanged behavior) ───────────────────────

void App::handleHealth([[maybe_unused]] const Request& req,
                       Response& res) const
{
    res.status = 200;
    res.set_content(
        std::string("unspoken ") + unspoken::GIT_COMMIT_HASH + " ok",
        "text/plain");
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
        auto ctx = baseContext(req, std::nullopt);
        ctx["error"] = mw::escapeHTML(req.get_param_value("error"));
        render(res, 400, "error.html", ctx);
        return;
    }
    if(!req.has_param("state") || !req.has_param("code"))
    {
        auto ctx = baseContext(req, std::nullopt);
        ctx["error"] = "Missing state or code.";
        render(res, 400, "error.html", ctx);
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

    auto ctx = baseContext(req, std::nullopt);
    ctx["csrf"] = auth.setupCsrfFor(*sealed);
    ctx["suggested_name"] = mw::escapeHTML(pre.suggested_name);
    ctx["error"] = "";
    render(res, 200, "setup_username.html", ctx);
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

    if(!auth.checkSetupCsrf(*sealed, param(req, "csrf")))
    {
        auto ctx = baseContext(req, std::nullopt);
        ctx["error"] = "Invalid CSRF token.";
        render(res, 400, "error.html", ctx);
        return;
    }
    ASSIGN_OR_RESPOND_ERROR(auto pre, auth.openPreAuth(*sealed), res);

    std::string username = param(req, "username");
    std::string display_name = param(req, "display_name");

    auto session = auth.finishSetup(pre, username, display_name);
    if(!session.has_value())
    {
        auto ctx = baseContext(req, std::nullopt);
        ctx["csrf"] = auth.setupCsrfFor(*sealed);
        ctx["suggested_name"] = mw::escapeHTML(username);
        ctx["error"] = mw::escapeHTML(mw::errorMsg(session.error()));
        render(res, 400, "setup_username.html", ctx);
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

    if(!auth.checkCsrf(sessionToken(req), param(req, "csrf")))
    {
        auto ctx = baseContext(req, std::nullopt);
        ctx["error"] = "Invalid CSRF token.";
        render(res, 400, "error.html", ctx);
        return;
    }
    if(auto lr = auth.logout(sessionToken(req)); !lr.has_value())
    {
        respondError(lr.error(), res);
        return;
    }
    clearCookie(res, unspoken::SESSION_COOKIE);
    res.set_redirect(urlFor());
}

// ─── Timeline ──────────────────────────────────────────────────────────

void App::handleIndex(const Request& req, Response& res) const
{
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    Service svc(config, *ds, emoji);

    auto parsed_cursor = cursorFromRequest(req, res, true);
    if(!parsed_cursor.has_value()) return;
    unspoken::Cursor cursor = *parsed_cursor;

    std::vector<unspoken::Post> posts;
    if(viewer.has_value())
    {
        ASSIGN_OR_RESPOND_ERROR(posts, svc.homeTimeline(*viewer, cursor), res);
    }
    else
    {
        ASSIGN_OR_RESPOND_ERROR(
            posts, ds->timelinePublic(cursor, config.posts_per_page), res);
    }

    ASSIGN_OR_RESPOND_ERROR(auto post_views, svc.postViews(posts, viewer), res);
    auto ctx = baseContext(req, viewer);
    ctx["posts"] = post_views;
    ctx["timeline"] = viewer.has_value() ? "home" : "public";
    if(!posts.empty())
    {
        ctx["next_max_id"] = posts.back().id;
        ctx["has_more"] = (static_cast<int>(posts.size())
                           == config.posts_per_page);
    }
    else
    {
        ctx["has_more"] = false;
    }
    render(res, 200, "index.html", ctx);
}

// ─── Profile (view) ────────────────────────────────────────────────────

void App::handleUserProfile(const Request& req, Response& res) const
{
    std::string username = req.path_params.at("username");
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    Service svc(config, *ds, emoji);

    ASSIGN_OR_RESPOND_ERROR(auto user, ds->getUserByUsername(username), res);
    if(!user.has_value())
    {
        auto ctx = baseContext(req, viewer);
        ctx["error"] = "No such user.";
        render(res, 404, "error.html", ctx);
        return;
    }

    if(unspoken::wantsActivityJson(headerValue(req, "Accept")))
    {
        setJson(res, unspoken::actorJson(config, *user,
                                         unspoken::renderPostContent(
                                             user->bio, emoji)));
        return;
    }

    auto parsed_cursor = cursorFromRequest(req, res, false);
    if(!parsed_cursor.has_value()) return;
    unspoken::Cursor cursor = *parsed_cursor;
    std::vector<int64_t> ids{user->id};
    ASSIGN_OR_RESPOND_ERROR(
        auto posts, ds->postsForAuthors(ids, cursor, config.posts_per_page),
        res);
    // Hide private posts the viewer may not see.
    std::vector<unspoken::Post> visible;
    for(auto& p : posts)
    {
        ASSIGN_OR_RESPOND_ERROR(bool ok, svc.canViewPost(p, viewer), res);
        if(ok) visible.push_back(std::move(p));
    }
    ASSIGN_OR_RESPOND_ERROR(auto post_views, svc.postViews(visible, viewer),
                            res);

    auto ctx = baseContext(req, viewer);
    ctx["profile"] = svc.userView(*user);
    ctx["posts"] = post_views;
    bool is_self = viewer.has_value() && viewer->id == user->id;
    ctx["is_self"] = is_self;
    if(viewer.has_value() && !is_self)
    {
        ASSIGN_OR_RESPOND_ERROR(
            auto f, ds->getFollow(svc.actorUri(viewer->username),
                                  svc.actorUri(user->username)), res);
        ctx["following"] = f.has_value();
    }
    else
    {
        ctx["following"] = false;
    }
    if(!visible.empty())
        ctx["next_max_id"] = visible.back().id;
    render(res, 200, "profile.html", ctx);
}

// ─── Post / thread (view) ──────────────────────────────────────────────

void App::handlePostView(const Request& req, Response& res) const
{
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    Service svc(config, *ds, emoji);

    int64_t id = 0;
    try { id = std::stoll(req.path_params.at("id")); }
    catch(...) { id = 0; }

    ASSIGN_OR_RESPOND_ERROR(auto post, ds->getPostById(id), res);
    if(!post.has_value())
    {
        auto ctx = baseContext(req, viewer);
        ctx["error"] = "Not found.";
        render(res, 404, "error.html", ctx);
        return;
    }

    bool ap_json = unspoken::wantsActivityJson(headerValue(req, "Accept"));
    bool visible = false;
    ASSIGN_OR_RESPOND_ERROR(visible, svc.canViewPost(*post, viewer), res);
    if(!visible && ap_json)
    {
        auto system = systemActor();
        mw::HTTPSession http;
        auto verified = system.has_value()
            ? unspoken::verifyHttpSignatureWithKeyRefresh(
                  config, *ds, crypto, http, *system, incomingRequest(req),
                  mw::timeToSeconds(mw::Clock::now()))
            : unspoken::verifyHttpSignature(
                  config, *ds, crypto, incomingRequest(req),
                  mw::timeToSeconds(mw::Clock::now()));
        if(verified.has_value())
        {
            ASSIGN_OR_RESPOND_ERROR(
                visible, svc.canActorViewPost(*post, verified->actor_uri),
                res);
        }
    }
    if(!visible)
    {
        // 404 (not 403) so private-post existence is not revealed (§16.6).
        if(ap_json)
        {
            res.status = 404;
            res.set_content("Not found", "text/plain");
            return;
        }
        auto ctx = baseContext(req, viewer);
        ctx["error"] = "Not found.";
        render(res, 404, "error.html", ctx);
        return;
    }

    if(ap_json)
    {
        if(!post->local_author_id.has_value())
        {
            res.status = 404;
            res.set_content("Not found", "text/plain");
            return;
        }
        ASSIGN_OR_RESPOND_ERROR(auto author,
                                ds->getUserById(*post->local_author_id), res);
        if(!author.has_value())
        {
            res.status = 404;
            res.set_content("Not found", "text/plain");
            return;
        }
        ASSIGN_OR_RESPOND_ERROR(auto recipients,
                                ds->getPostRecipients(post->id), res);
        ASSIGN_OR_RESPOND_ERROR(auto atts,
                                ds->attachmentsForPost(post->id), res);
        setJson(res, unspoken::noteJson(config, *post, *author, recipients,
                                        atts, &emoji));
        return;
    }

    // Thread root: walk up one level if this is a reply we host.
    std::string root_uri = post->uri;
    if(post->in_reply_to_uri.has_value())
    {
        ASSIGN_OR_RESPOND_ERROR(auto parent,
                                ds->getPostByUri(*post->in_reply_to_uri), res);
        if(parent.has_value()) root_uri = parent->uri;
    }
    if(!post->local_author_id.has_value() || post->in_reply_to_uri.has_value())
    {
        int64_t now = mw::timeToSeconds(mw::Clock::now());
        ASSIGN_OR_RESPOND_ERROR(auto job, unspoken::enqueueFetchThreadJob(
            *ds, root_uri, now), res);
        (void)job;
    }
    ASSIGN_OR_RESPOND_ERROR(auto thread, ds->threadFor(root_uri), res);
    // Filter to viewable posts.
    std::vector<unspoken::Post> visible_thread;
    for(auto& p : thread)
    {
        ASSIGN_OR_RESPOND_ERROR(bool ok, svc.canViewPost(p, viewer), res);
        if(ok) visible_thread.push_back(std::move(p));
    }
    if(visible_thread.empty()) visible_thread.push_back(*post);
    ASSIGN_OR_RESPOND_ERROR(auto views, svc.postViews(visible_thread, viewer),
                            res);

    auto ctx = baseContext(req, viewer);
    ctx["posts"] = views;
    ctx["focus_id"] = post->id;
    ctx["reply_to_id"] = post->id;
    render(res, 200, "thread.html", ctx);
}

// ─── Compose / reply / delete ──────────────────────────────────────────

namespace
{

// Parse the visibility form field; default to public.
unspoken::Visibility visibilityParam(const std::string& v)
{
    auto parsed = unspoken::visibilityFromStr(v);
    return parsed.value_or(unspoken::Visibility::PUBLIC);
}

nlohmann::json remoteActorView(const unspoken::RemoteActor& actor)
{
    nlohmann::json j;
    j["id"] = actor.id;
    j["username"] = mw::escapeHTML(actor.username);
    j["display_name"] = mw::escapeHTML(
        actor.display_name.empty() ? actor.username : actor.display_name);
    j["handle"] = mw::escapeHTML(std::format("@{}@{}", actor.username,
                                             actor.domain));
    j["profile_url"] = mw::escapeHTML(actor.uri);
    j["bio_html"] = "";
    nlohmann::json doc = nlohmann::json::parse(actor.actor_json, nullptr,
                                               false);
    if(doc.is_object() && doc.contains("summary")
       && doc["summary"].is_string())
    {
        j["bio_html"] = unspoken::sanitizeRemoteHtml(
            doc["summary"].get<std::string>());
    }
    return j;
}

bool looksRemoteHandle(std::string_view query,
                       std::string_view public_domain)
{
    query = mw::strip(query);
    if(query.starts_with('@')) query.remove_prefix(1);
    size_t at = query.find('@');
    if(at == std::string_view::npos || at == 0 || at + 1 >= query.size())
        return false;
    if(query.find('@', at + 1) != std::string_view::npos) return false;
    return query.substr(at + 1) != public_domain;
}

mw::E<std::vector<std::string>> remoteMentionActorUris(
    const Config& config, const unspoken::DataSourceInterface& data,
    mw::CryptoInterface& crypto, const unspoken::SystemActor& system_actor,
    std::string_view source, const unspoken::EmojiRegistry& emoji)
{
    unspoken::RenderedPostContent parsed =
        unspoken::parsePostContent(std::string(source), emoji);
    std::vector<std::string> out;
    std::set<std::string> seen;
    mw::HTTPSession http;
    for(const auto& mention : parsed.mentions)
    {
        if(mention.domain.empty() || mention.domain == config.public_domain)
            continue;
        ASSIGN_OR_RETURN(auto actor, unspoken::resolveWebFingerActor(
            config, data, crypto, http, system_actor, mention.name));
        if(seen.insert(actor.uri).second) out.push_back(actor.uri);
    }
    return out;
}

mw::E<void> enqueueCreateActivity(
    const Config& config, const unspoken::DataSourceInterface& data,
    const unspoken::EmojiRegistry& emoji, const unspoken::Post& post,
    const unspoken::User& author, int64_t now)
{
    ASSIGN_OR_RETURN(auto recipients, data.getPostRecipients(post.id));
    ASSIGN_OR_RETURN(auto attachments, data.attachmentsForPost(post.id));
    const std::string actor_uri = config.url_root + "u/" + author.username;
    auto note = unspoken::noteJson(config, post, author, recipients,
                                   attachments, &emoji);
    nlohmann::json activity = {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", post.uri + "/activity"},
        {"type", "Create"},
        {"actor", actor_uri},
        {"object", note},
        {"to", note["to"]},
        {"cc", note["cc"]},
    };
    ASSIGN_OR_RETURN(auto jobs, unspoken::enqueueOutboundDelivery(
        config, data, actor_uri, activity, recipients, now));
    (void)jobs;
    return {};
}

} // namespace

void App::handlePostCreate(const Request& req, Response& res) const
{
    if(!csrfOk(req)) { res.status = 400; res.set_content("Bad CSRF",
                                                         "text/plain");
                       return; }
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    if(!viewer.has_value()) { res.status = 401;
                              res.set_content("Login required", "text/plain");
                              return; }
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    Service svc(config, *ds, emoji);

    unspoken::ComposeParams cp;
    cp.source = param(req, "content");
    cp.visibility = visibilityParam(param(req, "visibility"));
    std::string summary = param(req, "summary");
    if(!summary.empty()) cp.summary = summary;
    cp.sensitive = hasParam(req, "sensitive");
    std::string reply_to = param(req, "in_reply_to");
    if(!reply_to.empty()) cp.in_reply_to_uri = reply_to;

    // Attachments (multipart): store each file, create draft attachment rows.
    if(req.is_multipart_form_data())
    {
        for(const auto& file : req.get_file_values("attachments"))
        {
            if(file.content.empty()) continue;
            if(static_cast<int64_t>(file.content.size())
               > config.max_upload_bytes)
            {
                res.status = 413;
                res.set_content("Attachment too large", "text/plain");
                return;
            }
            ASSIGN_OR_RESPOND_ERROR(
                auto stored,
                unspoken::storeAttachment(config.attachment_dir, file.content,
                                          file.filename, file.content_type),
                res);
            unspoken::Attachment a;
            a.sha256 = stored.sha256;
            a.media_type = stored.media_type;
            a.original_name = file.filename;
            a.is_image = stored.is_image;
            a.sensitive = cp.sensitive;
            ASSIGN_OR_RESPOND_ERROR(int64_t aid, ds->insertAttachment(a), res);
            cp.attachment_ids.push_back(aid);
        }
    }

    if(cp.source.empty() && cp.attachment_ids.empty())
    {
        res.status = 400;
        res.set_content("Empty post", "text/plain");
        return;
    }

    ASSIGN_OR_RESPOND_ERROR(auto system_actor, systemActor(), res);
    ASSIGN_OR_RESPOND_ERROR(cp.mentioned_actor_uris,
                            remoteMentionActorUris(
                                config, *ds, crypto, system_actor,
                                cp.source, emoji), res);
    ASSIGN_OR_RESPOND_ERROR(auto post, svc.createPost(*viewer, cp), res);
    int64_t now = mw::timeToSeconds(mw::Clock::now());
    if(respondIfError(enqueueCreateActivity(config, *ds, emoji, post,
                                            *viewer, now), res))
    {
        return;
    }
    res.set_redirect(urlFor("p/" + std::to_string(post.id)));
}

void App::handleReply(const Request& req, Response& res) const
{
    // Replies reuse the compose path; the parent URI is resolved from id.
    if(!csrfOk(req)) { res.status = 400; res.set_content("Bad CSRF",
                                                         "text/plain");
                       return; }
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    if(!viewer.has_value()) { res.status = 401;
                              res.set_content("Login required", "text/plain");
                              return; }
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    Service svc(config, *ds, emoji);

    int64_t id = 0;
    try { id = std::stoll(req.path_params.at("id")); } catch(...) {}
    ASSIGN_OR_RESPOND_ERROR(auto parent, ds->getPostById(id), res);
    if(!parent.has_value()) { res.status = 404;
                              res.set_content("No such post", "text/plain");
                              return; }
    if(respondIfCannotView(svc, *parent, viewer, res)) return;

    unspoken::ComposeParams cp;
    cp.source = param(req, "content");
    cp.visibility = visibilityParam(param(req, "visibility"));
    cp.in_reply_to_uri = parent->uri;
    if(cp.source.empty()) { res.status = 400;
                            res.set_content("Empty reply", "text/plain");
                            return; }
    ASSIGN_OR_RESPOND_ERROR(auto system_actor, systemActor(), res);
    ASSIGN_OR_RESPOND_ERROR(cp.mentioned_actor_uris,
                            remoteMentionActorUris(
                                config, *ds, crypto, system_actor,
                                cp.source, emoji), res);
    ASSIGN_OR_RESPOND_ERROR(auto post, svc.createPost(*viewer, cp), res);
    int64_t now = mw::timeToSeconds(mw::Clock::now());
    if(respondIfError(enqueueCreateActivity(config, *ds, emoji, post,
                                            *viewer, now), res))
    {
        return;
    }
    res.set_redirect(urlFor("p/" + std::to_string(post.id)));
}

void App::handlePostDelete(const Request& req, Response& res) const
{
    if(!csrfOk(req)) { res.status = 400; res.set_content("Bad CSRF",
                                                         "text/plain");
                       return; }
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    if(!viewer.has_value()) { res.status = 401;
                              res.set_content("Login required", "text/plain");
                              return; }
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);

    int64_t id = 0;
    try { id = std::stoll(req.path_params.at("id")); } catch(...) {}
    ASSIGN_OR_RESPOND_ERROR(auto post, ds->getPostById(id), res);
    if(!post.has_value()
       || post->local_author_id.value_or(-1) != viewer->id)
    {
        // 404 either way: don't reveal others' posts you can't delete.
        res.status = 404;
        res.set_content("Not found", "text/plain");
        return;
    }
    Service svc(config, *ds, emoji);
    ASSIGN_OR_RESPOND_ERROR(auto recipients, ds->getPostRecipients(id), res);
    int64_t now = mw::timeToSeconds(mw::Clock::now());
    const std::string actor_uri = svc.actorUri(viewer->username);
    nlohmann::json activity = unspoken::deleteActivityJson(
        std::format("{}activities/delete/{}/{}", config.url_root, id, now),
        actor_uri, post->uri, recipients);
    ASSIGN_OR_RESPOND_ERROR(auto jobs, unspoken::enqueueOutboundDelivery(
        config, *ds, actor_uri, activity, recipients, now), res);
    (void)jobs;
    if(respondIfError(ds->deletePost(id), res)) return;
    res.set_redirect(urlFor());
}

// ─── Interactions ──────────────────────────────────────────────────────

namespace
{
// True if the form's "undo" flag is set (toggle off).
bool isUndo(const mw::HTTPServer::Request& req)
{
    return param(req, "undo") == "1";
}
} // namespace

void App::handleLike(const Request& req, Response& res) const
{
    if(!csrfOk(req)) { res.status = 400; res.set_content("Bad CSRF",
                                                         "text/plain");
                       return; }
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    if(!viewer.has_value()) { res.status = 401;
                              res.set_content("Login required", "text/plain");
                              return; }
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    Service svc(config, *ds, emoji);
    int64_t id = 0;
    try { id = std::stoll(req.path_params.at("id")); } catch(...) {}
    ASSIGN_OR_RESPOND_ERROR(auto post, ds->getPostById(id), res);
    if(!post.has_value()) { res.status = 404;
                            res.set_content("No such post", "text/plain");
                            return; }
    if(respondIfCannotView(svc, *post, viewer, res)) return;
    if(respondIfError(svc.setLike(*viewer, *post, !isUndo(req)), res)) return;
    res.set_redirect(redirectTarget(req));
}

void App::handleBoost(const Request& req, Response& res) const
{
    if(!csrfOk(req)) { res.status = 400; res.set_content("Bad CSRF",
                                                         "text/plain");
                       return; }
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    if(!viewer.has_value()) { res.status = 401;
                              res.set_content("Login required", "text/plain");
                              return; }
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    Service svc(config, *ds, emoji);
    int64_t id = 0;
    try { id = std::stoll(req.path_params.at("id")); } catch(...) {}
    ASSIGN_OR_RESPOND_ERROR(auto post, ds->getPostById(id), res);
    if(!post.has_value()) { res.status = 404;
                            res.set_content("No such post", "text/plain");
                            return; }
    if(respondIfCannotView(svc, *post, viewer, res)) return;
    if(respondIfError(svc.setBoost(*viewer, *post, !isUndo(req)), res)) return;
    res.set_redirect(redirectTarget(req));
}

void App::handleReact(const Request& req, Response& res) const
{
    if(!csrfOk(req)) { res.status = 400; res.set_content("Bad CSRF",
                                                         "text/plain");
                       return; }
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    if(!viewer.has_value()) { res.status = 401;
                              res.set_content("Login required", "text/plain");
                              return; }
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    Service svc(config, *ds, emoji);
    int64_t id = 0;
    try { id = std::stoll(req.path_params.at("id")); } catch(...) {}
    ASSIGN_OR_RESPOND_ERROR(auto post, ds->getPostById(id), res);
    if(!post.has_value()) { res.status = 404;
                            res.set_content("No such post", "text/plain");
                            return; }
    if(respondIfCannotView(svc, *post, viewer, res)) return;
    std::string e = param(req, "emoji");
    if(e.empty()) { res.status = 400; res.set_content("No emoji",
                                                      "text/plain");
                    return; }
    bool undo = isUndo(req);
    if(respondIfError(svc.setReaction(*viewer, *post, e, !undo), res))
        return;
    if(!undo && post->remote_author_id.has_value())
    {
        ASSIGN_OR_RESPOND_ERROR(auto remote_author,
                                ds->getRemoteActorById(
                                    *post->remote_author_id), res);
        if(remote_author.has_value())
        {
            int64_t now = mw::timeToSeconds(mw::Clock::now());
            std::string actor_uri = svc.actorUri(viewer->username);
            std::vector<unspoken::PostRecipient> recipients = {
                {0, remote_author->uri, "to"},
            };
            nlohmann::json activity = unspoken::emojiReactActivityJson(
                config,
                std::format("{}activities/react/{}/{}/{}",
                            config.url_root, viewer->id, post->id, now),
                actor_uri, post->uri, e, recipients, emoji);
            ASSIGN_OR_RESPOND_ERROR(auto jobs,
                                    unspoken::enqueueOutboundDelivery(
                                        config, *ds, actor_uri, activity,
                                        recipients, now), res);
            (void)jobs;
        }
    }
    res.set_redirect(redirectTarget(req));
}

void App::handleBookmark(const Request& req, Response& res) const
{
    if(!csrfOk(req)) { res.status = 400; res.set_content("Bad CSRF",
                                                         "text/plain");
                       return; }
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    if(!viewer.has_value()) { res.status = 401;
                              res.set_content("Login required", "text/plain");
                              return; }
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    Service svc(config, *ds, emoji);
    int64_t id = 0;
    try { id = std::stoll(req.path_params.at("id")); } catch(...) {}
    ASSIGN_OR_RESPOND_ERROR(auto post, ds->getPostById(id), res);
    if(!post.has_value()) { res.status = 404;
                            res.set_content("No such post", "text/plain");
                            return; }
    if(respondIfCannotView(svc, *post, viewer, res)) return;
    if(respondIfError(svc.setBookmark(*viewer, *post, !isUndo(req)), res)) return;
    res.set_redirect(redirectTarget(req));
}

void App::handleBookmarks(const Request& req, Response& res) const
{
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    if(!viewer.has_value()) { res.set_redirect(urlFor("login")); return; }
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    Service svc(config, *ds, emoji);
    auto parsed_cursor = cursorFromRequest(req, res, false);
    if(!parsed_cursor.has_value()) return;
    unspoken::Cursor cursor = *parsed_cursor;
    ASSIGN_OR_RESPOND_ERROR(
        auto posts, ds->bookmarksFor(viewer->id, cursor, config.posts_per_page),
        res);
    ASSIGN_OR_RESPOND_ERROR(auto views, svc.postViews(posts, viewer), res);
    auto ctx = baseContext(req, viewer);
    ctx["posts"] = views;
    ctx["timeline"] = "bookmarks";
    render(res, 200, "bookmarks.html", ctx);
}

void App::handleFollow(const Request& req, Response& res) const
{
    if(!csrfOk(req)) { res.status = 400; res.set_content("Bad CSRF",
                                                         "text/plain");
                       return; }
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    if(!viewer.has_value()) { res.status = 401;
                              res.set_content("Login required", "text/plain");
                              return; }
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    Service svc(config, *ds, emoji);
    std::string target = param(req, "username");
    // Local follow only in Phase 3 (remote follow is Phase 5).
    ASSIGN_OR_RESPOND_ERROR(auto target_user, ds->getUserByUsername(target),
                            res);
    if(!target_user.has_value()) { res.status = 404;
                                   res.set_content("No such user",
                                                   "text/plain");
                                   return; }
    if(respondIfError(svc.setFollow(*viewer, target, !isUndo(req)), res)) return;
    res.set_redirect(redirectTarget(req));
}

// ─── Profile edit ──────────────────────────────────────────────────────

void App::handleProfileGet(const Request& req, Response& res) const
{
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    if(!viewer.has_value()) { res.set_redirect(urlFor("login")); return; }
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    Service svc(config, *ds, emoji);
    auto ctx = baseContext(req, viewer);
    ctx["profile"] = svc.userView(*viewer);
    render(res, 200, "profile_edit.html", ctx);
}

void App::handleProfilePost(const Request& req, Response& res) const
{
    if(!csrfOk(req)) { res.status = 400; res.set_content("Bad CSRF",
                                                         "text/plain");
                       return; }
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    if(!viewer.has_value()) { res.status = 401;
                              res.set_content("Login required", "text/plain");
                              return; }
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    std::string display_name = param(req, "display_name");
    std::string bio = param(req, "bio");
    if(respondIfError(ds->updateUserProfile(viewer->id, display_name, bio), res)) return;
    ASSIGN_OR_RESPOND_ERROR(auto updated, ds->getUserById(viewer->id), res);
    if(updated.has_value())
    {
        int64_t now = mw::timeToSeconds(mw::Clock::now());
        std::string actor_uri = config.url_root + "u/" + updated->username;
        std::vector<unspoken::PostRecipient> recipients = {
            {0, actor_uri + "/followers", "to"},
        };
        nlohmann::json activity = unspoken::actorUpdateActivityJson(
            config,
            std::format("{}activities/update/profile/{}/{}",
                        config.url_root, updated->id, now),
            *updated, unspoken::renderPostContent(updated->bio, emoji),
            recipients);
        ASSIGN_OR_RESPOND_ERROR(auto jobs, unspoken::enqueueOutboundDelivery(
            config, *ds, actor_uri, activity, recipients, now), res);
        (void)jobs;
    }
    res.set_redirect(urlFor("u/" + viewer->username));
}

// ─── Search ────────────────────────────────────────────────────────────

void App::handleSearch(const Request& req, Response& res) const
{
    ASSIGN_OR_RESPOND_ERROR(auto viewer, currentUser(req), res);
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    Service svc(config, *ds, emoji);
    std::string query{mw::strip(param(req, "q"))};
    auto ctx = baseContext(req, viewer);
    ctx["query"] = mw::escapeHTML(query);
    nlohmann::json results = nlohmann::json::array();
    if(!query.empty())
    {
        if(looksRemoteHandle(query, config.public_domain))
        {
            ASSIGN_OR_RESPOND_ERROR(auto system_actor, systemActor(), res);
            mw::HTTPSession http;
            auto remote = unspoken::resolveWebFingerActor(
                config, *ds, crypto, http, system_actor, query);
            if(remote.has_value()) results.push_back(remoteActorView(*remote));
        }
        else
        {
            std::string q = query;
            if(!q.empty() && q.front() == '@') q.erase(q.begin());
            ASSIGN_OR_RESPOND_ERROR(auto users, ds->searchUsers(q, 50), res);
            for(const auto& u : users) results.push_back(svc.userView(u));
        }
    }
    ctx["results"] = results;
    render(res, 200, "search.html", ctx);
}

// ─── Media / emoji serving ─────────────────────────────────────────────

void App::handleMedia(const Request& req, Response& res) const
{
    // /media/<shard>/<filename>. Validate segments to prevent traversal.
    std::string shard = req.path_params.at("shard");
    std::string filename = req.path_params.at("filename");
    std::string hashpart = filename;
    if(auto dot = hashpart.find('.'); dot != std::string::npos)
        hashpart = hashpart.substr(0, dot);

    if(shard.size() != 1 || !unspoken::isHexLower(shard)
       || !unspoken::isHexLower(hashpart) || filename.find('/') != std::string::npos)
    {
        res.status = 404;
        res.set_content("Not found", "text/plain");
        return;
    }

    namespace fs = std::filesystem;
    fs::path path = fs::path(config.attachment_dir) / shard / filename;
    std::error_code ec;
    if(!fs::is_regular_file(path, ec))
    {
        res.status = 404;
        res.set_content("Not found", "text/plain");
        return;
    }
    std::ifstream f(path, std::ios::binary);
    std::string bytes((std::istreambuf_iterator<char>(f)),
                      std::istreambuf_iterator<char>());

    std::string ext = unspoken::extensionOf(filename);
    std::string mime = unspoken::mediaTypeForExtension(ext);
    if(mime.empty()) mime = "application/octet-stream";

    // Non-image types are served download-only with nosniff (§17.2).
    if(!unspoken::isImageMediaType(mime))
    {
        res.set_header("Content-Disposition", "attachment");
        res.set_header("X-Content-Type-Options", "nosniff");
    }
    res.status = 200;
    res.set_content(bytes, mime);
}

void App::handleEmoji(const Request& req, Response& res) const
{
    std::string filename = req.path_params.at("filename");
    // Reject any path separators / traversal.
    if(filename.find('/') != std::string::npos
       || filename.find("..") != std::string::npos)
    {
        res.status = 404;
        res.set_content("Not found", "text/plain");
        return;
    }
    namespace fs = std::filesystem;
    fs::path path = fs::path(config.emoji_dir) / filename;
    std::error_code ec;
    if(!fs::is_regular_file(path, ec))
    {
        res.status = 404;
        res.set_content("Not found", "text/plain");
        return;
    }
    std::ifstream f(path, std::ios::binary);
    std::string bytes((std::istreambuf_iterator<char>(f)),
                      std::istreambuf_iterator<char>());
    std::string ext = unspoken::extensionOf(filename);
    std::string mime = unspoken::imageMediaTypeForExt(ext);
    if(mime.empty()) mime = "application/octet-stream";
    res.status = 200;
    res.set_content(bytes, mime);
}

// ─── Federation discovery / actors ────────────────────────────────────

mw::E<unspoken::SystemActor> App::systemActor() const
{
    ASSIGN_OR_RETURN(auto* ds, dataSource());
    ASSIGN_OR_RETURN(auto existing, ds->getSystemActor());
    if(existing.has_value()) return *existing;

    ASSIGN_OR_RETURN(auto keys, crypto.generateKeyPair(mw::KeyType::RSA));
    DO_OR_RETURN(ds->setSystemActor(keys.private_key, keys.public_key));
    ASSIGN_OR_RETURN(auto stored, ds->getSystemActor());
    if(!stored.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Failed to persist system actor"));
    }
    return *stored;
}

void App::handleSystemActor([[maybe_unused]] const Request& req,
                            Response& res) const
{
    ASSIGN_OR_RESPOND_ERROR(auto actor, systemActor(), res);
    setJson(res, unspoken::systemActorJson(config, actor.public_key_pem));
}

void App::handleWebFinger(const Request& req, Response& res) const
{
    if(!req.has_param("resource"))
    {
        res.status = 400;
        res.set_content("Missing resource", "text/plain");
        return;
    }

    std::string resource = req.get_param_value("resource");
    constexpr std::string_view PREFIX = "acct:";
    if(!resource.starts_with(PREFIX))
    {
        res.status = 404;
        res.set_content("Not found", "text/plain");
        return;
    }
    std::string acct = resource.substr(PREFIX.size());
    size_t at = acct.rfind('@');
    if(at == std::string::npos || at == 0 || at + 1 >= acct.size())
    {
        res.status = 404;
        res.set_content("Not found", "text/plain");
        return;
    }
    std::string username = acct.substr(0, at);
    std::string domain = acct.substr(at + 1);
    std::string url_host = base_url.host();
    if(domain != config.public_domain && domain != url_host)
    {
        res.status = 404;
        res.set_content("Not found", "text/plain");
        return;
    }

    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    ASSIGN_OR_RESPOND_ERROR(auto user, ds->getUserByUsername(username), res);
    if(!user.has_value())
    {
        res.status = 404;
        res.set_content("Not found", "text/plain");
        return;
    }
    setJson(res, unspoken::webFingerJson(config, *user),
            "application/jrd+json");
}

void App::handleNodeInfoDiscovery([[maybe_unused]] const Request& req,
                                  Response& res) const
{
    setJson(res, unspoken::nodeInfoDiscoveryJson(config),
            "application/json");
}

void App::handleNodeInfo([[maybe_unused]] const Request& req,
                         Response& res) const
{
    setJson(res, unspoken::nodeInfoJson(config), "application/json");
}

void App::handleInbox(const Request& req, Response& res) const
{
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    int64_t now = mw::timeToSeconds(mw::Clock::now());
    ASSIGN_OR_RESPOND_ERROR(auto system, systemActor(), res);
    mw::HTTPSession http;
    ASSIGN_OR_RESPOND_ERROR(auto verified,
                            unspoken::verifyHttpSignatureWithKeyRefresh(
        config, *ds, crypto, http, system, incomingRequest(req), now), res);

    nlohmann::json raw = nlohmann::json::parse(req.body, nullptr, false);
    if(!raw.is_object())
    {
        res.status = 400;
        res.set_content("Activity must be JSON object", "text/plain");
        return;
    }
    ASSIGN_OR_RESPOND_ERROR(auto activity, unspoken::parseActivity(raw), res);
    ASSIGN_OR_RESPOND_ERROR(auto result, unspoken::dispatchIncomingActivity(
        config, *ds, verified.actor_uri, activity, now, &crypto, &http,
        &system), res);
    res.status = result.duplicate ? 200 : 202;
    res.set_content("", "text/plain");
}

void App::handleOutbox(const Request& req, Response& res) const
{
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    std::string username = req.path_params.at("username");
    ASSIGN_OR_RESPOND_ERROR(auto user, ds->getUserByUsername(username), res);
    if(!user.has_value())
    {
        res.status = 404;
        res.set_content("Not found", "text/plain");
        return;
    }

    const std::string actor_uri = config.url_root + "u/" + user->username;
    const std::string collection_uri = actor_uri + "/outbox";
    if(!req.has_param("page"))
    {
        setJson(res, collectionRootJson(collection_uri));
        return;
    }

    auto cursor = cursorFromRequest(req, res, true);
    if(!cursor.has_value()) return;
    ASSIGN_OR_RESPOND_ERROR(auto posts, ds->postsForAuthors(
        std::vector<int64_t>{user->id}, *cursor, config.posts_per_page), res);

    nlohmann::json items = nlohmann::json::array();
    for(const auto& post : posts)
    {
        ASSIGN_OR_RESPOND_ERROR(auto recipients,
                                ds->getPostRecipients(post.id), res);
        ASSIGN_OR_RESPOND_ERROR(auto attachments,
                                ds->attachmentsForPost(post.id), res);
        auto note = unspoken::noteJson(config, post, *user, recipients,
                                       attachments, &emoji);
        items.push_back({
            {"@context", "https://www.w3.org/ns/activitystreams"},
            {"id", post.uri + "/activity"},
            {"type", "Create"},
            {"actor", actor_uri},
            {"object", note},
            {"to", note["to"]},
            {"cc", note["cc"]},
        });
    }

    std::optional<int64_t> next;
    std::optional<int64_t> prev;
    if(!posts.empty())
    {
        if(static_cast<int>(posts.size()) == config.posts_per_page)
            next = posts.back().id;
        prev = posts.front().id;
    }
    setJson(res, collectionPageJson(collection_uri, req.target, items,
                                    next, prev));
}

void App::handleFollowersCollection(const Request& req, Response& res) const
{
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    std::string username = req.path_params.at("username");
    ASSIGN_OR_RESPOND_ERROR(auto user, ds->getUserByUsername(username), res);
    if(!user.has_value())
    {
        res.status = 404;
        res.set_content("Not found", "text/plain");
        return;
    }

    const std::string actor_uri = config.url_root + "u/" + user->username;
    const std::string collection_uri = actor_uri + "/followers";
    if(!req.has_param("page"))
    {
        setJson(res, collectionRootJson(collection_uri));
        return;
    }
    auto cursor = cursorFromRequest(req, res, true);
    if(!cursor.has_value()) return;
    ASSIGN_OR_RESPOND_ERROR(auto followers, ds->followerPage(
        actor_uri, *cursor, config.posts_per_page), res);
    nlohmann::json items = nlohmann::json::array();
    for(const auto& item : followers) items.push_back(item.actor_uri);

    std::optional<int64_t> next;
    std::optional<int64_t> prev;
    if(!followers.empty())
    {
        if(static_cast<int>(followers.size()) == config.posts_per_page)
            next = followers.back().id;
        prev = followers.front().id;
    }
    setJson(res, collectionPageJson(collection_uri, req.target, items,
                                    next, prev));
}

void App::handleFollowingCollection(const Request& req, Response& res) const
{
    ASSIGN_OR_RESPOND_ERROR(auto* ds, dataSource(), res);
    std::string username = req.path_params.at("username");
    ASSIGN_OR_RESPOND_ERROR(auto user, ds->getUserByUsername(username), res);
    if(!user.has_value())
    {
        res.status = 404;
        res.set_content("Not found", "text/plain");
        return;
    }

    const std::string actor_uri = config.url_root + "u/" + user->username;
    const std::string collection_uri = actor_uri + "/following";
    if(!req.has_param("page"))
    {
        setJson(res, collectionRootJson(collection_uri));
        return;
    }
    auto cursor = cursorFromRequest(req, res, true);
    if(!cursor.has_value()) return;
    ASSIGN_OR_RESPOND_ERROR(auto following, ds->followingPage(
        actor_uri, *cursor, config.posts_per_page), res);
    nlohmann::json items = nlohmann::json::array();
    for(const auto& item : following) items.push_back(item.actor_uri);

    std::optional<int64_t> next;
    std::optional<int64_t> prev;
    if(!following.empty())
    {
        if(static_cast<int>(following.size()) == config.posts_per_page)
            next = following.back().id;
        prev = following.front().id;
    }
    setJson(res, collectionPageJson(collection_uri, req.target, items,
                                    next, prev));
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

    startJobWorkers();

    server.Get("/health", [&](const Request& req, Response& res)
    { handleHealth(req, res); });
    server.Get("/", [&](const Request& req, Response& res)
    { handleIndex(req, res); });
    server.Get("/actor", [&](const Request& req, Response& res)
    { handleSystemActor(req, res); });
    server.Get("/.well-known/webfinger", [&](const Request& req, Response& res)
    { handleWebFinger(req, res); });
    server.Get("/.well-known/nodeinfo", [&](const Request& req, Response& res)
    { handleNodeInfoDiscovery(req, res); });
    server.Get("/nodeinfo/2.1", [&](const Request& req, Response& res)
    { handleNodeInfo(req, res); });
    server.Post("/inbox", [&](const Request& req, Response& res)
    { handleInbox(req, res); });

    // Auth (Phase 2).
    server.Get("/login", [&](const Request& req, Response& res)
    { handleLogin(req, res); });
    server.Get("/callback", [&](const Request& req, Response& res)
    { handleCallback(req, res); });
    server.Get("/setup-username", [&](const Request& req, Response& res)
    { handleSetupGet(req, res); });
    server.Post("/setup-username", [&](const Request& req, Response& res)
    { handleSetupPost(req, res); });
    server.Post("/logout", [&](const Request& req, Response& res)
    { handleLogout(req, res); });

    // Profile edit, search, bookmarks.
    server.Get("/profile", [&](const Request& req, Response& res)
    { handleProfileGet(req, res); });
    server.Post("/profile", [&](const Request& req, Response& res)
    { handleProfilePost(req, res); });
    server.Get("/search", [&](const Request& req, Response& res)
    { handleSearch(req, res); });
    server.Get("/bookmarks", [&](const Request& req, Response& res)
    { handleBookmarks(req, res); });

    // Compose / interactions.
    server.Post("/post", [&](const Request& req, Response& res)
    { handlePostCreate(req, res); });
    server.Post("/post/:id/reply", [&](const Request& req, Response& res)
    { handleReply(req, res); });
    server.Post("/post/:id/delete", [&](const Request& req, Response& res)
    { handlePostDelete(req, res); });
    server.Post("/post/:id/like", [&](const Request& req, Response& res)
    { handleLike(req, res); });
    server.Post("/post/:id/boost", [&](const Request& req, Response& res)
    { handleBoost(req, res); });
    server.Post("/post/:id/react", [&](const Request& req, Response& res)
    { handleReact(req, res); });
    server.Post("/post/:id/bookmark", [&](const Request& req, Response& res)
    { handleBookmark(req, res); });
    server.Post("/follow", [&](const Request& req, Response& res)
    { handleFollow(req, res); });

    // Views with path params.
    server.Get("/u/:username/outbox", [&](const Request& req, Response& res)
    { handleOutbox(req, res); });
    server.Get("/u/:username/followers", [&](const Request& req, Response& res)
    { handleFollowersCollection(req, res); });
    server.Get("/u/:username/following", [&](const Request& req, Response& res)
    { handleFollowingCollection(req, res); });
    server.Get("/u/:username", [&](const Request& req, Response& res)
    { handleUserProfile(req, res); });
    server.Post("/u/:username/inbox", [&](const Request& req, Response& res)
    { handleInbox(req, res); });
    server.Get("/p/:id", [&](const Request& req, Response& res)
    { handlePostView(req, res); });

    // Media + emoji.
    server.Get("/media/:shard/:filename", [&](const Request& req, Response& res)
    { handleMedia(req, res); });
    server.Get("/emoji/:filename", [&](const Request& req, Response& res)
    { handleEmoji(req, res); });
}
