#include <filesystem>
#include <string>

#include <spdlog/spdlog.h>
#include <mw/http_server.hpp>
#include <mw/url.hpp>

#include "app.hpp"
#include "commit.hpp"
#include "config.hpp"

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

} // namespace

App::App(const Config& conf)
        : mw::HTTPServer(listenAddrFromConfig(conf)),
          config(conf),
          base_url(baseUrlFromConfig(conf))
{}

std::string App::urlFor(const std::string& path) const
{
    if(path.empty())
    {
        return base_url.str();
    }
    return mw::URL(base_url).appendPath(path).str();
}

void App::handleHealth([[maybe_unused]] const Request& req,
                       Response& res) const
{
    res.status = 200;
    res.set_content(
        std::string("unspoken ") + unspoken::GIT_COMMIT_HASH + " ok",
        "text/plain");
}

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
}
