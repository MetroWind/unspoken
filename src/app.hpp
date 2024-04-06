#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <format>

#include <httplib.h>
#include <spdlog/spdlog.h>
#include <inja.hpp>

#include "auth.hpp"
#include "config.hpp"
#include "data.hpp"
#include "error.hpp"
#include "federation.hpp"
#include "http_client.hpp"
#include "types.hpp"
#include "utils.hpp"
#include "url_manager.hpp"

void copyToHttplibReq(const HTTPRequest& src, httplib::Request& dest);

class App
{
public:
    App() = delete;
    explicit App(const Configuration& conf,
                 std::unique_ptr<AuthInterface> openid_auth,
                 std::unique_ptr<DataSourceInterface> data);

    std::string urlFor(const std::string& name, const std::string& arg) const;

    void handleIndex(const httplib::Request& req, httplib::Response& res) const;
    void handleLogin(httplib::Response& res) const;
    void handleOpenIDRedirect(const httplib::Request& req,
                              httplib::Response& res) const;

    // Federation APIs
    void handleWebFinger(const httplib::Request& req, httplib::Response& res);
    void handleUserInfo(httplib::Response& res, const std::string& username);

    void start();

private:
    struct SessionValidation
    {
        enum { VALID, REFRESHED, INVALID } status;
        UserInfo user;
        Tokens new_tokens;

        static SessionValidation valid(UserInfo&& user_info)
        {
            return {VALID, user_info, {}};
        }

        static SessionValidation refreshed(UserInfo&& user_info, Tokens&& tokens)
        {
            return {REFRESHED, user_info, tokens};
        }

        static SessionValidation invalid()
        {
            return {INVALID, {}, {}};
        }
    };
    E<SessionValidation> validateSession(const httplib::Request& req) const;
    E<std::string> httpSig(const std::string& username, const std::string& key,
                           const httplib::Request& req);
    inline bool verifyHTTPSig(const httplib::Request&)
    {
        // TODO: Implement
        return true;
    }

    const Configuration config;
    inja::Environment templates;
    std::unique_ptr<AuthInterface> auth;
    std::unique_ptr<DataSourceInterface> data_source;
    Crypto crypto;
    URLManager url_manager;
    Federation fed;
    std::string server_host;
};
