#pragma once
#include <string>

struct NodeInfoConfig
{
    std::string name;
    std::string description;
};

struct Config
{
    std::string server_url_root;
    int port;
    std::string data_dir = ".";
    std::string db_path;
    std::string oidc_issuer_url;
    std::string oidc_client_id;
    std::string oidc_secret;
    std::string secret_key;
    int posts_per_page = 20;
    NodeInfoConfig nodeinfo;

    static Config& get();
    void load(const std::string& path);
};
