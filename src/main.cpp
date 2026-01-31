#include "config.hpp"
#include "database.hpp"
#include "app.hpp"
#include <iostream>
#include <spdlog/spdlog.h>
#include <mw/error.hpp>
#include <cxxopts.hpp>
#include <filesystem>

int main(int argc, char* argv[])
{
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
    spdlog::info("Unspoken server starting...");

    cxxopts::Options options("unspoken", "ActivityPub Microblog Server");
    options.add_options()
        ("c,config", "Path to config file", cxxopts::value<std::string>()->default_value("config.yaml"))
        ("d,data-dir", "Data directory override", cxxopts::value<std::string>())
        ("h,help", "Print usage");

    auto result = options.parse(argc, argv);

    if (result.count("help"))
    {
        std::cout << options.help() << std::endl;
        return 0;
    }

    std::string config_path = result["config"].as<std::string>();

    try
    {
        Config::get().load(config_path);
    }
    catch(const std::exception& e)
    {
        spdlog::critical("Failed to load config from {}: {}", config_path, e.what());
        return 1;
    }

    if (result.count("data-dir"))
    {
        std::string data_dir = result["data-dir"].as<std::string>();
        Config::get().data_dir = data_dir;
        Config::get().db_path = (std::filesystem::path(data_dir) / "unspoken.db").string();
        spdlog::info("Data directory overridden by command line: {}", data_dir);
    }

    auto db = std::make_unique<Database>(Config::get().db_path);
    auto db_init = db->init();
    if(!db_init)
    {
        spdlog::critical("Failed to initialize database: {}",
                         mw::errorMsg(db_init.error()));
        return 1;
    }

    spdlog::info("Database initialized successfully at {}",
                 Config::get().db_path);

    App::initSecretKey(*db);

    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{
        "0.0.0.0", Config::get().port
    };

    App app(std::move(db), listen);
    auto app_run = app.run();
    if(!app_run)
    {
        spdlog::critical("App failed to run: {}",
                         mw::errorMsg(app_run.error()));
        return 1;
    }

    return 0;
}