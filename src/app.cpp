#include "app.hpp"
#include "config.hpp"
#include "json_ld.hpp"
#include <mw/http_client.hpp>
#include <mw/url.hpp>
#include <mw/crypto.hpp>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <macrodown.h>
#include <random>
#include <unordered_set>
#include <filesystem>
#include <fstream>

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

App::App(std::unique_ptr<Database> database,
         const mw::HTTPServer::ListenAddress& listen)
    : mw::HTTPServer(listen), db(std::move(database))
{
    // inja_env.set_template_path("./templates/");
    http_client = std::make_unique<mw::HTTPSession>();
    crypto = std::make_unique<mw::Crypto>();
    sig_verifier = std::make_unique<SignatureVerifier>(std::make_unique<mw::HTTPSession>(), std::make_unique<mw::Crypto>());
    
    auto job_db = std::make_unique<Database>(Config::get().db_path);
    if(auto res = job_db->init(); !res)
    {
        spdlog::error("Failed to init JobQueue database: {}", mw::errorMsg(res.error()));
    }
    job_queue = std::make_unique<JobQueue>(std::move(job_db), std::make_unique<mw::HTTPSession>(), std::make_unique<mw::Crypto>());
}

mw::E<void> App::run()
{
    const auto& conf = Config::get();
    
    auto root_url = mw::URL::fromStr(conf.server_url_root);
    if(!root_url)
    {
        return std::unexpected(root_url.error());
    }

    job_queue->start();

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
    server.set_mount_point("/uploads", "./uploads");

    server.Get("/", [this](const mw::HTTPServer::Request& req,
                            mw::HTTPServer::Response& res)
    {
        auto sess = getCurrentSession(req);
        nlohmann::json data;
        data["logged_in"] = sess.has_value();
        if(sess)
        {
            auto user = db->getUserById(sess->user_id);
            if(user && user.value()) data["username"] = user.value()->username;
            data["csrf_token"] = sess->csrf_token;
        }
        
        data["posts"] = nlohmann::json::array();
        auto posts_res = db->getPublicTimeline(20, 0);
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
            s.csrf_token = generateToken();
            
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
        
        auto keys_res = crypto->generateKeyPair(mw::KeyType::ED25519);
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
        s.csrf_token = generateToken();
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
        
        if(resource.starts_with("acct:"))
        {
            resource = resource.substr(5);
        }

        size_t at_pos = resource.find('@');
        if(at_pos != std::string::npos)
        {
            username = resource.substr(0, at_pos);
        }
        else
        {
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
        link_profile["href"] = user.value()->uri; 
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
        j["usage"]["users"]["total"] = 1; 
        j["usage"]["users"]["activeMonth"] = 1; 
        j["usage"]["users"]["activeHalfyear"] = 1;
        j["openRegistrations"] = false;
        j["metadata"]["nodeName"] = conf.nodeinfo.name;
        j["metadata"]["nodeDescription"] = conf.nodeinfo.description;

        res.set_content(j.dump(), "application/json");
    });

    server.Post("/inbox", [this](const mw::HTTPServer::Request& req,
                                 mw::HTTPServer::Response& res)
    {
        std::string sender;
        ASSIGN_OR_RESPOND_ERROR(sender, sig_verifier->verify(req, "POST", "/inbox"), res);
        
        try
        {
            auto j = nlohmann::json::parse(req.body);
            auto process_res = processActivity(j, sender);
            if(!process_res)
            {
                spdlog::error("Failed to process activity: {}", mw::errorMsg(process_res.error()));
                res.status = 500; 
                return;
            }
            res.status = 202; 
        }
        catch(const std::exception& e)
        {
            res.status = 400;
            res.set_content("Invalid JSON", "text/plain");
        }
    });

    server.Get("/u/:username/outbox", [this](const mw::HTTPServer::Request& req,
                                             mw::HTTPServer::Response& res)
    {
        std::string username = req.get_param_value("username");
        auto user = db->getUserByUsername(username);
        if(!user || !user.value())
        {
            res.status = 404;
            res.set_content("User not found", "text/plain");
            return;
        }

        auto posts_res = db->getUserPosts(user.value()->id, 20, 0);
        if(!posts_res)
        {
            res.status = 500;
            return;
        }

        nlohmann::json j;
        j["@context"] = "https://www.w3.org/ns/activitystreams";
        j["id"] = user.value()->uri + "/outbox";
        j["type"] = "OrderedCollection";
        j["totalItems"] = posts_res->size(); // Approximate for now
        j["orderedItems"] = nlohmann::json::array();

        for(const auto& p : *posts_res)
        {
            nlohmann::json activity;
            activity["type"] = "Create";
            activity["actor"] = user.value()->uri;
            activity["object"] = {
                {"id", p.uri},
                {"type", "Note"},
                {"content", p.content_html},
                {"attributedTo", user.value()->uri},
                {"published", mw::timeToISO8601(mw::secondsToTime(p.created_at))},
                {"to", {"https://www.w3.org/ns/activitystreams#Public"}}
            };
            j["orderedItems"].push_back(activity);
        }

        res.set_content(j.dump(), "application/activity+json");
    });

    server.Post("/post", [this](const mw::HTTPServer::Request& req,
                                mw::HTTPServer::Response& res)
    {
        auto user = getCurrentUser(req);
        if(!user)
        {
            res.status = 403;
            res.set_content("Login required", "text/plain");
            return;
        }

        if(!checkCSRF(req))
        {
            res.status = 403;
            res.set_content("CSRF Check Failed", "text/plain");
            return;
        }

        std::string content = req.get_param_value("content");
        if(content.empty())
        {
            res.status = 400;
            res.set_content("Content empty", "text/plain");
            return;
        }

        auto create_res = createPost(*user, content);
        if(!create_res)
        {
            res.status = 500;
            res.set_content("Failed to create post: " + mw::errorMsg(create_res.error()), "text/plain");
            return;
        }

        res.set_redirect("/");
    });

    server.Post("/api/upload", [this](const mw::HTTPServer::Request& req,
                                      mw::HTTPServer::Response& res)
    {
        auto user = getCurrentUser(req);
        if(!user)
        {
            res.status = 403;
            return;
        }

        if(!checkCSRF(req))
        {
            res.status = 403;
            res.set_content("CSRF Check Failed", "text/plain");
            return;
        }

        auto result = handleUpload(req, *user);
        if(!result)
        {
            res.status = 500;
            res.set_content(mw::errorMsg(result.error()), "text/plain");
            return;
        }

        nlohmann::json j;
        j["url"] = *result;
        res.set_content(j.dump(), "application/json");
    });

    server.Get("/search", [this](const mw::HTTPServer::Request& req,
                                 mw::HTTPServer::Response& res)
    {
        auto sess = getCurrentSession(req);
        nlohmann::json data;
        data["logged_in"] = sess.has_value();
        if(sess)
        {
            auto user = db->getUserById(sess->user_id);
            if(user && user.value()) data["username"] = user.value()->username;
            data["csrf_token"] = sess->csrf_token;
        }

        if (req.has_param("q"))
        {
            std::string q = req.get_param_value("q");
            data["q"] = q;
            
            if (q.starts_with("@")) q = q.substr(1);
            
            std::string username = q;
            std::string domain;
            size_t at_pos = q.find('@');
            if (at_pos != std::string::npos)
            {
                username = q.substr(0, at_pos);
                domain = q.substr(at_pos + 1);
            }

            std::optional<User> result;
            auto root_url = mw::URL::fromStr(Config::get().server_url_root);
            std::string local_host = root_url ? root_url->host() : "";

            if (domain.empty() || domain == local_host)
            {
                auto db_res = db->getUserByUsername(username);
                if (db_res && db_res.value()) result = db_res.value();
            }
            else
            {
                auto remote_res = resolveRemoteUser(username, domain);
                if (remote_res && remote_res.value()) result = remote_res.value();
            }
            
            if (result)
            {
                nlohmann::json u;
                u["display_name"] = result->display_name;
                u["username"] = result->username;
                u["host"] = result->host ? *result->host : "";
                u["bio"] = result->bio;
                u["uri"] = result->uri;
                data["result"] = u;
            }
        }

        render(res, "search.html", data);
    });

    server.Get("/u/:username", [this](const mw::HTTPServer::Request& req,
                                      mw::HTTPServer::Response& res)
    {
        // Check Accept header for JSON
        if (req.has_header("Accept") && req.get_header_value("Accept").find("application/activity+json") != std::string::npos)
        {
            // Redirect to outbox or return Actor JSON?
            // Usually returns Actor JSON.
            // For now let's just return 404 for JSON if not implemented or redirect to outbox?
            // Actually, /u/user IS the actor ID, so it should return Actor JSON.
            // I'll skip that for now as I implemented outbox separately.
        }

        std::string username = req.get_param_value("username");
        auto user_res = db->getUserByUsername(username);
        if(!user_res || !user_res.value())
        {
            res.status = 404;
            res.set_content("User not found", "text/plain");
            return;
        }
        auto target = *user_res.value();

        auto current_user = getCurrentUser(req);
        bool is_following = false;
        bool is_self = false;
        if(current_user)
        {
            is_self = (current_user->id == target.id);
            auto follow = db->getFollow(current_user->id, target.id);
            if(follow && follow.value() && follow.value()->status == 1) is_following = true;
        }

        auto sess = getCurrentSession(req);
        auto posts_res = db->getUserPosts(target.id, 20, 0);
        
        nlohmann::json data;
        data["user"]["display_name"] = target.display_name;
        data["user"]["username"] = target.username;
        data["user"]["host"] = target.host ? *target.host : "";
        data["user"]["bio"] = target.bio;
        data["user"]["uri"] = target.uri;
        data["user"]["avatar_path"] = target.avatar_path ? *target.avatar_path : "";
        data["logged_in"] = current_user.has_value();
        data["is_following"] = is_following;
        data["is_self"] = is_self;
        if(current_user) data["username"] = current_user->username;
        if(sess) data["csrf_token"] = sess->csrf_token;

        data["posts"] = nlohmann::json::array();
        if(posts_res)
        {
            for(const auto& p : *posts_res)
            {
                nlohmann::json pj;
                pj["content_html"] = p.content_html;
                pj["created_at"] = mw::timeToStr(mw::secondsToTime(p.created_at));
                data["posts"].push_back(pj);
            }
        }

        render(res, "profile.html", data);
    });

    server.Post("/api/follow", [this](const mw::HTTPServer::Request& req,
                                      mw::HTTPServer::Response& res)
    {
        auto user = getCurrentUser(req);
        if(!user)
        {
            res.status = 403;
            return;
        }

        if(!checkCSRF(req))
        {
            res.status = 403;
            res.set_content("CSRF Check Failed", "text/plain");
            return;
        }

        std::string uri = req.get_param_value("uri");
        auto target_res = db->getUserByUri(uri);
        if(!target_res || !target_res.value())
        {
            res.status = 404;
            return;
        }
        auto target = *target_res.value();

        auto existing = db->getFollow(user->id, target.id);
        if(existing && existing.value())
        {
            res.set_redirect("/u/" + target.username);
            return;
        }

        Follow f;
        f.follower_id = user->id;
        f.target_id = target.id;
        f.status = 0;
        f.uri = user->uri + "/follows/" + std::to_string(mw::timeToSeconds(mw::Clock::now()));

        if (target.isLocal())
        {
            f.status = 1;
        }

        db->createFollow(f);

        if (!target.isLocal())
        {
            sendFollowActivity(*user, target);
        }

        res.set_redirect("/u/" + target.username);
    });
}

mw::E<void> App::sendFollowActivity(const User& follower, const User& target)
{
    nlohmann::json activity;
    activity["@context"] = "https://www.w3.org/ns/activitystreams";
    activity["type"] = "Follow";
    activity["id"] = follower.uri + "/follows/" + std::to_string(mw::timeToSeconds(mw::Clock::now()));
    activity["actor"] = follower.uri;
    activity["object"] = target.uri;

    if (!target.inbox) return {}; // Can't send

    Job j;
    j.type = "deliver_activity";
    j.attempts = 0;
    j.status = 0;
    j.next_try = mw::timeToSeconds(mw::Clock::now());
    
    nlohmann::json payload;
    payload["inbox"] = *target.inbox;
    payload["activity"] = activity;
    payload["sender_uri"] = follower.uri;
    j.payload = payload.dump();

    return db->enqueueJob(j).transform([](auto){});
}

mw::E<std::optional<User>> App::resolveRemoteUser(const std::string& username, const std::string& domain)
{
    std::string wf_url = "https://" + domain + "/.well-known/webfinger?resource=acct:" + username + "@" + domain;
    
    ASSIGN_OR_RETURN(auto res_ptr, http_client->get(wf_url));
    if(res_ptr->status != 200) return std::nullopt;

    nlohmann::json j;
    try
    {
        j = nlohmann::json::parse(res_ptr->payloadAsStr());
    }
    catch(...) { return std::nullopt; }

    std::string actor_uri;
    if(j.contains("links") && j["links"].is_array())
    {
        for(const auto& link : j["links"])
        {
            if(link.value("rel", "") == "self" && 
               link.value("type", "") == "application/activity+json")
            {
                actor_uri = link.value("href", "");
                break;
            }
        }
    }

    if(actor_uri.empty()) return std::nullopt;

    ASSIGN_OR_RETURN(auto uid, ensureRemoteUser(actor_uri));
    return db->getUserById(uid);
}

mw::E<void> App::createPost(const User& author, const std::string& content)
{
    macrodown::MacroDown md;
    auto tree = md.parse(content);
    std::string html = md.render(*tree);

    Post p;
    p.author_id = author.id;
    p.content_html = html;
    p.content_source = content;
    p.created_at = mw::timeToSeconds(mw::Clock::now());
    p.is_local = true;
    p.visibility = Visibility::PUBLIC;
    
    p.uri = Config::get().server_url_root + "/p/" +
            std::to_string(p.created_at);

    DO_OR_RETURN(db->createPost(p));

    nlohmann::json activity;
    activity["@context"] = "https://www.w3.org/ns/activitystreams";
    activity["type"] = "Create";
    activity["id"] = p.uri + "/activity";
    activity["actor"] = author.uri;
    activity["object"] = {
        {"id", p.uri},
        {"type", "Note"},
        {"content", p.content_html},
        {"published", mw::timeToISO8601(mw::secondsToTime(p.created_at))},
        {"attributedTo", author.uri},
        {"to", {"https://www.w3.org/ns/activitystreams#Public"}},
        {"cc", {author.uri + "/followers"}}
    };

    auto followers_res = db->getFollowers(author.id);
    if(followers_res)
    {
        std::unordered_set<std::string> inboxes;
        for(const auto& f : *followers_res)
        {
            if(f.shared_inbox && !f.shared_inbox->empty())
            {
                inboxes.insert(*f.shared_inbox);
            }
            else if(f.inbox && !f.inbox->empty())
            {
                inboxes.insert(*f.inbox);
            }
        }

        for(const auto& inbox : inboxes)
        {
            Job j;
            j.type = "deliver_activity";
            j.attempts = 0;
            j.status = 0;
            j.next_try = mw::timeToSeconds(mw::Clock::now());
            
            nlohmann::json payload;
            payload["inbox"] = inbox;
            payload["activity"] = activity;
            payload["sender_uri"] = author.uri;
            j.payload = payload.dump();

            db->enqueueJob(j);
        }
    }

    spdlog::info("Created post: {}", p.uri);

    return {};
}

mw::E<std::string> App::handleUpload(const mw::HTTPServer::Request& req,
                                     const User& uploader)
{
    if(!req.has_file("file"))
    {
        return std::unexpected(mw::runtimeError("No file"));
    }
    const auto& file = req.get_file_value("file");
    
    auto hash_res = mw::SHA256Hasher().hashToHexStr(file.content);
    if(!hash_res) return std::unexpected(hash_res.error());
    std::string hash = *hash_res;

    auto existing = db->getMediaByHash(hash);
    if(existing && existing.value())
    {
        std::filesystem::path p(existing.value()->filename);
        std::string ext = p.extension().string();
        return Config::get().server_url_root + "/uploads/" +
               hash.substr(0,1) + "/" + hash + ext;
    }

    std::filesystem::path upload_dir = "uploads";
    upload_dir /= hash.substr(0, 1);
    std::filesystem::create_directories(upload_dir);
    
    std::string ext = std::filesystem::path(file.filename).extension().string();
    if(ext.empty()) ext = ".bin";
    
    std::string final_name = hash + ext;
    std::filesystem::path final_path = upload_dir / final_name;
    
    std::ofstream ofs(final_path, std::ios::binary);
    ofs.write(file.content.data(), file.content.size());
    ofs.close();

    Media m;
    m.hash = hash;
    m.filename = final_name;
    m.mime_type = file.content_type;
    m.uploader_id = uploader.id;
    
    DO_OR_RETURN(db->createMedia(m));

    return Config::get().server_url_root + "/uploads/" +
           hash.substr(0,1) + "/" + final_name;
}

mw::E<void> App::processActivity(const nlohmann::json& activity, const std::string& sender_id)
{
    std::string type = activity["type"];
    
    if(type == "Create")
    {
        return handleCreate(activity, sender_id);
    }
    else if(type == "Follow")
    {
        return handleFollow(activity, sender_id);
    }
    else if(type == "Accept")
    {
        return handleAccept(activity, sender_id);
    }
    
    return {};
}

mw::E<int64_t> App::ensureRemoteUser(const std::string& uri)
{
    auto user = db->getUserByUri(uri);
    if(user && user.value())
    {
        return user.value()->id;
    }

    // Fetch Actor
    ASSIGN_OR_RETURN(auto res_ptr, http_client->get(uri));
    if(res_ptr->status != 200)
    {
        return std::unexpected(mw::httpError(502, "Failed to fetch remote actor"));
    }

    nlohmann::json j;
    try
    {
        j = nlohmann::json::parse(res_ptr->payloadAsStr());
    }
    catch(...)
    {
        return std::unexpected(mw::httpError(502, "Invalid JSON from remote actor"));
    }

    User u;
    u.uri = uri;
    u.username = j["preferredUsername"];
    u.display_name = j.value("name", "");
    u.bio = j.value("summary", "");
    u.created_at = mw::timeToSeconds(mw::Clock::now()); // Approximate
    
    if(j.contains("publicKey") && j["publicKey"].contains("publicKeyPem"))
    {
        u.public_key = j["publicKey"]["publicKeyPem"];
    }
    else if(j.contains("publicKeyPem"))
    {
        u.public_key = j["publicKeyPem"];
    }
    
    if(j.contains("icon") && j["icon"].contains("url"))
    {
        u.avatar_path = j["icon"]["url"];
    }

    u.inbox = json_ld::getId(j, "inbox");
    if(j.contains("endpoints") && j["endpoints"].contains("sharedInbox"))
    {
        u.shared_inbox = json_ld::getId(j["endpoints"], "sharedInbox");
    }

    auto url = mw::URL::fromStr(uri);
    if(url)
    {
        u.host = url->host();
    }

    return db->createUser(u);
}

mw::E<void> App::handleCreate(const nlohmann::json& activity, const std::string& sender_id)
{
    auto object = activity["object"];
    if(!json_ld::hasType(object, "Note")) return {};

    ASSIGN_OR_RETURN(auto author_id, ensureRemoteUser(sender_id));

    Post p;
    p.uri = json_ld::getId(object, "id");
    p.author_id = author_id;
    p.content_html = object.value("content", "");
    p.content_source = ""; // Remote posts usually don't have source
    p.visibility = Visibility::PUBLIC; // Simplified for now
    
    std::string pub = "1970-01-01T00:00:00Z";
    if(object.contains("published")) pub = object["published"];
    auto time_res = mw::strToDate(pub); 
    if (time_res) p.created_at = mw::timeToSeconds(*time_res);
    else p.created_at = mw::timeToSeconds(mw::Clock::now()); 
    p.is_local = false;

    return db->createPost(p).transform([](auto){});
}

mw::E<void> App::handleFollow(const nlohmann::json& activity, const std::string& sender_id)
{
    std::string object_uri = json_ld::getId(activity, "object");
    if (object_uri.empty()) return {};

    auto target_user = db->getUserByUri(object_uri);
    if (!target_user || !target_user.value())
    {
        // Target is not us (or not found), ignore
        return {};
    }

    ASSIGN_OR_RETURN(auto follower_id, ensureRemoteUser(sender_id));

    Follow f;
    f.follower_id = follower_id;
    f.target_id = target_user.value()->id;
    f.status = 1; // Auto-accept
    f.uri = json_ld::getId(activity, "id");
    
    DO_OR_RETURN(db->createFollow(f));

    // TODO: Enqueue Accept activity (Phase 6)
    
    return {};
}

mw::E<void> App::handleAccept(const nlohmann::json& activity, const std::string& sender_id)
{
    auto object = activity["object"];
    if (object.is_object() && object.value("type", "") == "Follow")
    {
        std::string actor_uri = json_ld::getId(object, "actor");
        std::string target_uri = json_ld::getId(object, "object");

        // Verify sender matches target
        if (target_uri != sender_id) return {};

        auto local_user = db->getUserByUri(actor_uri);
        auto remote_user = db->getUserByUri(target_uri);

        if (local_user && local_user.value() && remote_user && remote_user.value())
        {
            return db->updateFollowStatus(local_user.value()->id, 
                                          remote_user.value()->id, 1);
        }
    }
    return {};
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

std::optional<Session> App::getCurrentSession(const mw::HTTPServer::Request& req)
{
    std::string token = getCookie(req, "session");
    if(token.empty()) return std::nullopt;
    
    auto sess = db->getSession(token);
    if(sess && sess.value())
    {
        if(sess.value()->expires_at > mw::timeToSeconds(mw::Clock::now()))
        {
            return sess.value();
        }
        else
        {
            db->deleteSession(token);
        }
    }
    return std::nullopt;
}

std::optional<User> App::getCurrentUser(const mw::HTTPServer::Request& req)
{
    auto sess = getCurrentSession(req);
    if(sess)
    {
        auto user = db->getUserById(sess->user_id);
        if(user && user.value()) return user.value();
    }
    return std::nullopt;
}

bool App::checkCSRF(const mw::HTTPServer::Request& req)
{
    auto sess = getCurrentSession(req);
    if(!sess) return false;

    if(!req.has_param("csrf_token")) return false;
    return req.get_param_value("csrf_token") == sess->csrf_token;
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
