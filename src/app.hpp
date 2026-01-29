#pragma once

#include <memory>
#include <mw/http_server.hpp>
#include <mw/auth.hpp>
#include <mw/crypto.hpp>
#include <inja/inja.hpp>
#include "database.hpp"
#include "signature_verifier.hpp"
#include "job_queue.hpp"

class App : public mw::HTTPServer
{
public:
    App(std::unique_ptr<Database> db, const mw::HTTPServer::ListenAddress& listen);
    
    mw::E<void> run();

protected:
    void setup() override;

private:
    void render(mw::HTTPServer::Response& res, const std::string& template_name,
                const nlohmann::json& data);
    
    std::optional<User> getCurrentUser(const mw::HTTPServer::Request& req);
    std::optional<Session> getCurrentSession(const mw::HTTPServer::Request& req);
    bool checkCSRF(const mw::HTTPServer::Request& req);
    std::string generateToken();
    mw::E<void> processActivity(const nlohmann::json& activity, const std::string& sender_id);
    mw::E<void> handleCreate(const nlohmann::json& activity, const std::string& sender_id);
    mw::E<void> handleFollow(const nlohmann::json& activity, const std::string& sender_id);
    mw::E<void> handleAccept(const nlohmann::json& activity, const std::string& sender_id);
    mw::E<int64_t> ensureRemoteUser(const std::string& uri);
    mw::E<void> createPost(const User& author, const std::string& content);
    mw::E<std::string> handleUpload(const mw::HTTPServer::Request& req, const User& uploader);
    mw::E<std::optional<User>> resolveRemoteUser(const std::string& username, const std::string& domain);
    mw::E<void> sendFollowActivity(const User& follower, const User& target);

    std::unique_ptr<Database> db;
    std::unique_ptr<mw::HTTPSessionInterface> http_client;
    std::unique_ptr<mw::CryptoInterface> crypto;
    std::unique_ptr<JobQueue> job_queue;
    inja::Environment inja_env;
    std::unique_ptr<mw::AuthOpenIDConnect> auth;
    std::unique_ptr<SignatureVerifier> sig_verifier;
};