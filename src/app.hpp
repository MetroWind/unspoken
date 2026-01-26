#pragma once

#include <memory>
#include <mw/http_server.hpp>
#include <mw/auth.hpp>
#include <inja/inja.hpp>
#include "database.hpp"

class App : public mw::HTTPServer
{
public:
    App(std::shared_ptr<Database> db, const mw::HTTPServer::ListenAddress& listen);
    
    mw::E<void> run();

protected:
    void setup() override;

private:
    void render(mw::HTTPServer::Response& res, const std::string& template_name,
                const nlohmann::json& data);
    
    std::optional<User> getCurrentUser(const mw::HTTPServer::Request& req);
    std::string generateToken();

    std::shared_ptr<Database> db;
    inja::Environment inja_env;
    std::unique_ptr<mw::AuthOpenIDConnect> auth;
};