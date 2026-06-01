#include <iostream>
#include <string>

#include <cxxopts.hpp>
#include <spdlog/spdlog.h>
#include <mw/error.hpp>

#include "app.hpp"
#include "commit.hpp"
#include "config.hpp"

int main(int argc, char** argv)
{
    cxxopts::Options cmd_options(
        "unspoken", "A micro-blog server that federates over ActivityPub");
    cmd_options.add_options()
        ("c,config", "Config file",
         cxxopts::value<std::string>()->default_value("/etc/unspoken.yaml"))
        ("v,verbose", "Verbose (debug) logging")
        ("h,help", "Print this message.");
    auto opts = cmd_options.parse(argc, argv);

    if(opts.count("help"))
    {
        std::cout << cmd_options.help() << std::endl;
        return 0;
    }

    if(opts.count("verbose"))
    {
        spdlog::set_level(spdlog::level::debug);
    }

    spdlog::info("unspoken {} starting...", unspoken::GIT_COMMIT_HASH);

    const std::string config_file = opts["config"].as<std::string>();
    auto config = Config::fromYaml(config_file);
    if(!config.has_value())
    {
        // A malformed or incomplete config is a fatal startup error.
        spdlog::error("Failed to load config {}: {}", config_file,
                      mw::errorMsg(config.error()));
        return 1;
    }

    App app(*config);
    auto start = app.start();
    if(!start.has_value())
    {
        spdlog::error("Failed to start server: {}",
                      mw::errorMsg(start.error()));
        return 1;
    }

    spdlog::info("Listening at {}:{}...", config->listen_address,
                 config->listen_port);
    app.wait();
    return 0;
}
