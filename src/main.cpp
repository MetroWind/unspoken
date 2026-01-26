#include "config.hpp"
#include "database.hpp"
#include <iostream>
#include <spdlog/spdlog.h>
#include <mw/error.hpp>

int main()
{
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
    spdlog::info("ActPub server starting...");

    try
    {
        Config::get().load("config.yaml");
    }
    catch (const std::exception& e)
    {
        spdlog::critical("Failed to load config: {}", e.what());
        return 1;
    }

    Database db(Config::get().db_path);
    auto db_init = db.init();
    if (!db_init)
    {
        spdlog::critical("Failed to initialize database: {}", mw::errorMsg(db_init.error()));
        return 1;
    }

    spdlog::info("Database initialized successfully at {}", Config::get().db_path);

    // More initialization will go here in further phases (HTTP server, etc.)

    return 0;
}
