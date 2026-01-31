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
    App(std::unique_ptr<DatabaseInterface> db, 
        const mw::HTTPServer::ListenAddress& listen,
        std::unique_ptr<mw::HTTPSessionInterface> http_client = nullptr,
        std::unique_ptr<mw::CryptoInterface> crypto = nullptr);
    
    mw::E<void> run();

    // HTTP Handlers

    /// Handles the home page request.
    /// Shows public timeline if not logged in, or user's timeline if logged in.
    void handleIndex(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Initiates the OIDC login flow.
    /// Redirects the user to the OIDC provider's authentication page.
    void handleAuthLogin(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Handles the OIDC callback.
    /// Exchanges the code for tokens, creates a session, or redirects to username setup.
    void handleAuthCallback(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Displays the username setup form.
    /// Required for first-time OIDC logins.
    void handleAuthSetupUsername(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Processes the username setup form submission.
    /// Creates the local user account and session.
    void handleAuthSetupUsernamePost(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Logs the user out.
    /// Destroys the current session and clears cookies.
    void handleAuthLogout(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Handles WebFinger discovery requests.
    /// Returns JRD JSON for local users.
    void handleWebFinger(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Handles NodeInfo discovery requests.
    /// Returns links to the supported NodeInfo versions.
    void handleNodeInfo(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Returns the NodeInfo 2.0 JSON.
    /// Provides server metadata and usage statistics.
    void handleNodeInfo2(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Handles incoming ActivityPub messages (Inbox).
    /// Verifies HTTP signatures and processes activities.
    void handleInbox(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Returns a user's outbox.
    /// Currently returns an OrderedCollection of the user's posts.
    void handleUserOutbox(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Handles creation of new posts.
    /// Accepts content, creates local post, and initiates federation.
    void handlePost(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Handles file uploads.
    /// Saves file, calculates hash, and returns the URL.
    void handleApiUpload(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Handles the search page and queries.
    /// Searches local users or resolves remote users via WebFinger.
    void handleSearch(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Displays a user's profile.
    /// Shows profile info and their recent posts.
    void handleUserProfile(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);

    /// Handles follow requests.
    /// Creates a local follow record and sends a Follow activity.
    void handleApiFollow(const mw::HTTPServer::Request& req, mw::HTTPServer::Response& res);
    
    static std::string generateToken();
    
    /// Initializes the secret key.
    /// Checks Config, then Database, then generates a new one.
    static void initSecretKey(DatabaseInterface& db);

protected:
    void setup() override;

private:
    void render(mw::HTTPServer::Response& res, const std::string& template_name,
                const nlohmann::json& data);
    
    std::optional<User> getCurrentUser(const mw::HTTPServer::Request& req);
    std::optional<Session> getCurrentSession(const mw::HTTPServer::Request& req);
    bool checkCSRF(const mw::HTTPServer::Request& req);
    mw::E<void> processActivity(const nlohmann::json& activity, const std::string& sender_id);
    mw::E<void> handleCreate(const nlohmann::json& activity, const std::string& sender_id);
    mw::E<void> handleFollow(const nlohmann::json& activity, const std::string& sender_id);
    mw::E<void> handleAccept(const nlohmann::json& activity, const std::string& sender_id);
    mw::E<int64_t> ensureRemoteUser(const std::string& uri);
    mw::E<void> createPost(const User& author, const std::string& content);
    mw::E<std::string> handleUpload(const mw::HTTPServer::Request& req, const User& uploader);
    mw::E<std::optional<User>> resolveRemoteUser(const std::string& username, const std::string& domain);
    mw::E<void> sendFollowActivity(const User& follower, const User& target);
    mw::E<void> ensureSystemActor();
    mw::E<nlohmann::json> fetchRemoteActor(const std::string& uri, const User& system_actor);
    User parseRemoteActor(const nlohmann::json& j, const std::string& uri);

    std::unique_ptr<DatabaseInterface> db;
    std::unique_ptr<mw::HTTPSessionInterface> http_client;
    std::unique_ptr<mw::CryptoInterface> crypto;
    std::unique_ptr<JobQueue> job_queue;
    inja::Environment inja_env;
    std::unique_ptr<mw::AuthOpenIDConnect> auth;
    std::unique_ptr<SignatureVerifier> sig_verifier;
};