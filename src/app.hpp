#pragma once

#include <string>

#include <mw/error.hpp>
#include <mw/http_server.hpp>
#include <mw/url.hpp>

#include "config.hpp"

// The app module: the HTTP server, routing, and request handlers.
// Handlers are kept thin (design §1.2); business logic belongs in the
// service/federation/data layers. In Phase 0 this only serves a health
// route and static assets.
class App : public mw::HTTPServer
{
public:
    using Request = mw::HTTPServer::Request;
    using Response = mw::HTTPServer::Response;

    App() = delete;
    explicit App(const Config& conf);

    // Build a URL under the configured url_root.
    std::string urlFor(const std::string& path = "") const;

private:
    void setup() override;

    void handleHealth(const Request& req, Response& res) const;

    Config config;
    mw::URL base_url;
};
