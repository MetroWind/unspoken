#pragma once
#include <string>

struct NodeInfoConfig {
    std::string name;
    std::string description;
};

struct Config {
    std::string server_domain;
    std::string protocol;
    int port;
    std::string db_path;
    std::string oidc_client_id;
    std::string oidc_secret;
    std::string secret_key;
    NodeInfoConfig nodeinfo;

    static Config& get();
    void load(const std::string& path);
};
