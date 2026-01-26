#include "app.hpp"
#include "config.hpp"
#include <mw/http_client.hpp>
#include <mw/url.hpp>
#include <mw/crypto.hpp>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <random>

static std::string getCookie(const mw::HTTPServer::Request& req, const std::string& name)
{
    if(!req.has_header("Cookie")) return "";
    std::string cookies = req.get_header_value("Cookie");
    std::string search = name + "=";
    size_t pos = cookies.find(search);
    if(pos == std::string::npos) return "";
    
    std::string val = cookies.substr(pos + search.size());
    size_t end_pos = val.find(';');
    if(end_pos != std::string::npos) val = val.substr(0, end_pos);
    return val;
}

App::App(std::shared_ptr<Database> database,
         const mw::HTTPServer::ListenAddress& listen)
    : mw::HTTPServer(listen), db(database)
{
}

mw::E<void> App::run()
{
    const auto& conf = Config::get();
    
    auto root_url = mw::URL::fromStr(conf.server_url_root);
    if(!root_url)
    {
        return std::unexpected(root_url.error());
    }

    auto redirect_url = *root_url;
    redirect_url.appendPath("auth/callback");

    auto auth_res = mw::AuthOpenIDConnect::create(
        conf.oidc_issuer_url,
        conf.oidc_client_id,
        conf.oidc_secret,
        redirect_url.str(),
        std::make_unique<mw::HTTPSession>());
    
    if(!auth_res)
    {
        return std::unexpected(auth_res.error());
    }
    auth = std::move(*auth_res);

    spdlog::info("Listening on {}:{}", root_url->host(), conf.port);

    auto res = start();
    if(!res)
    {
        return res;
    }

    wait();
    return {};
}

void App::setup()
{
    server.Get("/", [this](const mw::HTTPServer::Request& req,
                            mw::HTTPServer::Response& res)
    {
        auto user = getCurrentUser(req);
        auto posts_res = db->getPublicTimeline(20, 0);
        nlohmann::json data;
        data["logged_in"] = user.has_value();
        if(user)
        {
            data["username"] = user->username;
        }
        
        data["posts"] = nlohmann::json::array();
        if(posts_res)
        {
            for(const auto& p : *posts_res)
            {
                nlohmann::json pj;
                pj["content_html"] = p.content_html;
                pj["created_at"] = mw::timeToStr(mw::secondsToTime(p.created_at));
                
                auto author = db->getUserById(p.author_id);
                if(author && author.value())
                {
                    pj["author_name"] = author.value()->display_name.empty() ? 
                                       author.value()->username : 
                                       author.value()->display_name;
                }
                else
                {
                    pj["author_name"] = "Unknown";
                }
                data["posts"].push_back(pj);
            }
        }

        render(res, "index.html", data);
    });

    server.Get("/auth/login", [this](const mw::HTTPServer::Request&,
                                     mw::HTTPServer::Response& res)
    {
        res.set_redirect(auth->initialURL());
    });

    server.Get("/auth/callback", [this](const mw::HTTPServer::Request& req,
                                        mw::HTTPServer::Response& res)
    {
        if(!req.has_param("code"))
        {
            res.status = 400;
            res.set_content("Missing code", "text/plain");
            return;
        }

        auto code = req.get_param_value("code");
        auto tokens_res = auth->authenticate(code);
        if(!tokens_res)
        {
            res.status = 500;
            res.set_content(mw::errorMsg(tokens_res.error()), "text/plain");
            return;
        }

        auto oidc_user_res = auth->getUser(*tokens_res);
        if(!oidc_user_res)
        {
            res.status = 500;
            res.set_content(mw::errorMsg(oidc_user_res.error()), "text/plain");
            return;
        }

        auto existing_user = db->getUserByOidcSubject(oidc_user_res->id);
        if(existing_user && existing_user.value())
        {
            Session s;
            s.token = generateToken();
            s.user_id = existing_user.value()->id;
            s.expires_at = mw::timeToSeconds(mw::Clock::now()) + 3600 * 24 * 7;
            
            auto sess_res = db->createSession(s);
            if(!sess_res)
            {
                res.status = 500;
                res.set_content("Failed to create session", "text/plain");
                return;
            }

            res.set_header("Set-Cookie", "session=" + s.token + "; Path=/; HttpOnly");
            res.set_redirect("/");
        }
        else
        {
            res.set_header("Set-Cookie", "pending_oidc_sub=" + oidc_user_res->id + "; Path=/; HttpOnly");
            res.set_redirect("/auth/setup_username");
        }
    });

    server.Get("/auth/setup_username", [this](const mw::HTTPServer::Request& req,
                                              mw::HTTPServer::Response& res)
    {
        if(getCookie(req, "pending_oidc_sub").empty())
        {
            res.set_redirect("/auth/login");
            return;
        }
        render(res, "setup_username.html", {});
    });

    server.Post("/auth/setup_username", [this](const mw::HTTPServer::Request& req,
                                               mw::HTTPServer::Response& res)
    {
        std::string oidc_sub = getCookie(req, "pending_oidc_sub");
        if(oidc_sub.empty())
        {
            res.set_redirect("/auth/login");
            return;
        }

        std::string username = req.get_param_value("username");
        if(username.empty())
        {
            res.status = 400;
            res.set_content("Username required", "text/plain");
            return;
        }

        auto existing = db->getUserByUsername(username);
        if(existing && existing.value())
        {
            res.status = 400;
            res.set_content("Username already taken", "text/plain");
            return;
        }
        
        auto root_url = mw::URL::fromStr(Config::get().server_url_root);
        if(!root_url)
        {
             res.status = 500;
             res.set_content("Invalid server config", "text/plain");
             return;
        }

        User u;
        u.username = username;
        u.oidc_subject = oidc_sub;
        u.uri = root_url->appendPath("u").appendPath(username).str();
        u.created_at = mw::timeToSeconds(mw::Clock::now());
        
        auto keys_res = mw::generateEd25519KeyPair();
        if (!keys_res)
        {
            res.status = 500;
            res.set_content("Failed to generate keys: " + mw::errorMsg(keys_res.error()), "text/plain");
            return;
        }
        u.public_key = keys_res->public_key;
        u.private_key = keys_res->private_key;

        auto create_res = db->createUser(u);
        if(!create_res)
        {
            res.status = 500;
            res.set_content("Failed to create user: " + mw::errorMsg(create_res.error()), "text/plain");
            return;
        }

        Session s;
        s.token = generateToken();
        s.user_id = *create_res;
        s.expires_at = mw::timeToSeconds(mw::Clock::now()) + 3600 * 24 * 7;
        db->createSession(s);

        res.set_header("Set-Cookie", "session=" + s.token + "; Path=/; HttpOnly");
        res.set_header("Set-Cookie", "pending_oidc_sub=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
        res.set_redirect("/");
    });

    server.Get("/auth/logout", [this](const mw::HTTPServer::Request& req,
                                      mw::HTTPServer::Response& res)
    {
        std::string token = getCookie(req, "session");
        if(!token.empty())
        {
            db->deleteSession(token);
        }
        res.set_header("Set-Cookie", "session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
        res.set_redirect("/");
    });

    server.Get("/.well-known/webfinger", [this](const mw::HTTPServer::Request& req,
                                                mw::HTTPServer::Response& res)
    {
        if(!req.has_param("resource"))
        {
            res.status = 400;
            res.set_content("Missing resource parameter", "text/plain");
            return;
        }

        std::string resource = req.get_param_value("resource");
        std::string username;
        
        // Expected format: acct:user@domain
        if(resource.starts_with("acct:"))
        {
            resource = resource.substr(5);
        }

        size_t at_pos = resource.find('@');
        if(at_pos != std::string::npos)
        {
            username = resource.substr(0, at_pos);
            // Ideally check domain matches ours
        }
        else
        {
            // Fallback or invalid
            username = resource;
        }

        auto user = db->getUserByUsername(username);
        if(!user || !user.value())
        {
            res.status = 404;
            res.set_content("User not found", "text/plain");
            return;
        }

        nlohmann::json j;
        j["subject"] = "acct:" + username + "@" + mw::URL::fromStr(Config::get().server_url_root)->host();
        j["links"] = nlohmann::json::array();

        nlohmann::json link_self;
        link_self["rel"] = "self";
        link_self["type"] = "application/activity+json";
        link_self["href"] = user.value()->uri;
        j["links"].push_back(link_self);

        nlohmann::json link_profile;
        link_profile["rel"] = "http://webfinger.net/rel/profile-page";
        link_profile["type"] = "text/html";
        link_profile["href"] = user.value()->uri; // TODO: Separate profile URL?
        j["links"].push_back(link_profile);

        res.set_content(j.dump(), "application/jrd+json");
    });

    server.Get("/.well-known/nodeinfo", [this](const mw::HTTPServer::Request&,
                                               mw::HTTPServer::Response& res)
    {
        nlohmann::json j;
        j["links"] = nlohmann::json::array();
        
        nlohmann::json link;
        link["rel"] = "http://nodeinfo.diaspora.software/ns/schema/2.0";
        
        auto root_url = mw::URL::fromStr(Config::get().server_url_root);
        if (root_url)
        {
             link["href"] = root_url->appendPath("nodeinfo/2.0").str();
        }
        
        j["links"].push_back(link);
        
        res.set_content(j.dump(), "application/json");
    });

    server.Get("/nodeinfo/2.0", [this](const mw::HTTPServer::Request&,
                                       mw::HTTPServer::Response& res)
    {
        const auto& conf = Config::get();
        nlohmann::json j;
        j["version"] = "2.0";
        j["software"]["name"] = "actpub";
        j["software"]["version"] = "0.1.0";
        j["protocols"] = {"activitypub"};
        j["services"]["outbound"] = nlohmann::json::array();
        j["services"]["inbound"] = nlohmann::json::array();
        j["usage"]["users"]["total"] = 1; // TODO: Count users
        j["usage"]["users"]["activeMonth"] = 1; 
        j["usage"]["users"]["activeHalfyear"] = 1;
        j["openRegistrations"] = false;
        j["metadata"]["nodeName"] = conf.nodeinfo.name;
        j["metadata"]["nodeDescription"] = conf.nodeinfo.description;

        res.set_content(j.dump(), "application/json");
    });
}

void App::render(mw::HTTPServer::Response& res, const std::string& template_name,
                 const nlohmann::json& data)
{
    try
    {
        std::string path = "./templates/" + template_name;
        res.set_content(inja_env.render_file(path, data), "text/html");
    }
    catch(const std::exception& e)
    {
        spdlog::error("Template error: {}", e.what());
        res.status = 500;
        res.set_content("Internal Server Error", "text/plain");
    }
}

std::optional<User> App::getCurrentUser(const mw::HTTPServer::Request& req)
{
    std::string token = getCookie(req, "session");
    if(token.empty()) return std::nullopt;
    
    auto sess = db->getSession(token);
    if(sess && sess.value())
    {
        if(sess.value()->expires_at > mw::timeToSeconds(mw::Clock::now()))
        {
            auto user = db->getUserById(sess.value()->user_id);
            if(user && user.value()) return user.value();
        }
        else
        {
            db->deleteSession(token);
        }
    }
    return std::nullopt;
}

std::string App::generateToken()
{
    static const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);

    std::string s;
    s.reserve(32);
    for(int i = 0; i < 32; i++) s += charset[dis(gen)];
    return s;
}
