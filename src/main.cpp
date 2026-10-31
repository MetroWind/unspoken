#include <iostream>
#include <fstream>
#include <string>

#include <cxxopts.hpp>
#include <spdlog/spdlog.h>
#include <mw/error.hpp>

#include "app.hpp"
#include "commit.hpp"
#include "config.hpp"
#include "data.hpp"
#include "federation.hpp"
#include "follow_import.hpp"

int main(int argc, char** argv)
{
    cxxopts::Options cmd_options(
        "unspoken", "A micro-blog server that federates over ActivityPub");
    cmd_options.add_options()
        ("c,config", "Config file",
         cxxopts::value<std::string>()->default_value("/etc/unspoken.yaml"))
        ("import-follows", "Import one account handle per line, then exit",
         cxxopts::value<std::string>())
        ("user", "Local username for --import-follows",
         cxxopts::value<std::string>())
        ("v,verbose", "Verbose (debug) logging")
        ("h,help", "Print this message.");
    auto opts = cmd_options.parse(argc, argv);

    if(opts.count("help"))
    {
        std::cout << cmd_options.help() << std::endl;
        return 0;
    }

    const bool importing = opts.count("import-follows") > 0;
    if(importing != (opts.count("user") > 0) ||
       (importing && opts["user"].as<std::string>().empty()))
    {
        std::cerr << "Use --import-follows FILE with --user USERNAME.\n";
        return 1;
    }
    std::ifstream follows;
    if(importing)
    {
        follows.open(opts["import-follows"].as<std::string>());
        if(!follows)
        {
            std::cerr << "Cannot open follow list: "
                      << opts["import-follows"].as<std::string>() << '\n';
            return 1;
        }
    }

    spdlog::set_pattern("[%l] %v");
    bool cli_verbose = opts.count("verbose") > 0;
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
    if(config->verbose || cli_verbose)
    {
        spdlog::set_level(spdlog::level::debug);
    }
    if(config->dev.allow_http_url_root)
    {
        spdlog::warn("HTTP url_root enabled for development");
    }
    if(config->dev.allow_http_url_root
       && !config->dev.outbound_allow_private_hosts.empty())
    {
        std::string hosts;
        for(const auto& host : config->dev.outbound_allow_private_hosts)
        {
            if(!hosts.empty()) hosts += ", ";
            hosts += host;
        }
        spdlog::warn("private outbound host allowlist enabled: {}", hosts);
    }

    // Initialize the database (create the schema at v1 if fresh) once at
    // startup so a misconfigured/unwritable DB is a clear fatal error
    // rather than surfacing later on a request thread. Each thread opens
    // its own connection afterward (design §7.2).
    auto db_init = unspoken::DataSourceSQLite::fromFile(
        config->database_path, config->sqlite_busy_timeout_ms);
    if(!db_init.has_value())
    {
        spdlog::error("Failed to open database {}: {}", config->database_path,
                      mw::errorMsg(db_init.error()));
        return 1;
    }
    std::optional<unspoken::User> import_user;
    if(importing)
    {
        auto user = (*db_init)->getUserByUsername(opts["user"].as<std::string>());
        if(!user || !*user)
        {
            spdlog::error("Cannot import for local user {}: {}",
                opts["user"].as<std::string>(),
                user ? "account not found" : mw::errorMsg(user.error()));
            return 1;
        }
        import_user = **user;
    }
    mw::Crypto federation_crypto;
    mw::HTTPSession federation_http;
    auto federation_init = unspoken::initializeFederationLibrary(
        *config, **db_init, federation_crypto, federation_http);
    if(!federation_init)
    {
        spdlog::error("Failed to initialize federation: {}",
                      mw::errorMsg(federation_init.error()));
        return 1;
    }
    if(importing)
    {
        auto result = unspoken::importFollows(*config,**db_init,
            federation_crypto,federation_http,*import_user,follows,std::cout);
        if(!result)
        {
            spdlog::error("Follow import stopped: {}",mw::errorMsg(result.error()));
            return 1;
        }
        std::cout << "Import complete: " << result->queued << " queued, "
                  << result->local << " local, " << result->skipped
                  << " skipped, " << result->failed << " failed.\n";
        return result->failed == 0 ? 0 : 1;
    }
    auto repaired = (*db_init)->repairMentionLinkPreviews(
        config->url_root,config->link_previews_enabled);
    if(!repaired)
    {
        spdlog::error("Failed to repair mention previews: {}",
                      mw::errorMsg(repaired.error()));
        return 1;
    }
    if(*repaired > 0)
        spdlog::info("Corrected {} mention preview association(s)",*repaired);
    int64_t maintenance_now = mw::timeToSeconds(mw::Clock::now());
    auto pruned = unspoken::runInboxMaintenanceOnce(
        *config, **db_init, maintenance_now);
    if(!pruned.has_value())
    {
        spdlog::warn("Startup inbox maintenance failed: {}",
                     mw::errorMsg(pruned.error()));
    }
    else if(*pruned > 0)
    {
        spdlog::info("Startup inbox maintenance pruned {} activity IDs",
                     *pruned);
    }
    auto collected = unspoken::runRemoteActorCollectionOnce(
        *config, **db_init, maintenance_now);
    if(!collected.has_value())
    {
        spdlog::warn("Startup remote actor collection failed: {}",
                     mw::errorMsg(collected.error()));
    }
    else if(*collected > 0)
    {
        spdlog::info("Startup remote actor collection removed {} actors",
                     *collected);
    }
    db_init->reset();

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
