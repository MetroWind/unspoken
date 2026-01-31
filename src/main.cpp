#include "config.hpp"
#include "database.hpp"
#include "app.hpp"
#include <iostream>
#include <spdlog/spdlog.h>
#include <mw/error.hpp>

int main()
{
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
    spdlog::info("Unspoken server starting...");

    try
    {
        Config::get().load("config.yaml");
    }
    catch(const std::exception& e)
    {
        spdlog::critical("Failed to load config: {}", e.what());
        return 1;
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