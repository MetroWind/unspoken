#include "config.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include <ryml.hpp>
#include <ryml_std.hpp>

std::string readFile(const std::string& path)
{
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if(!f)
    {
        throw std::runtime_error("Cannot open config file: " + path);
    }
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

Config& Config::get()
{
    static Config instance;
    return instance;
}

void Config::load(const std::string& path)
{
    std::string content = readFile(path);
    ryml::Tree tree = ryml::parse_in_arena(ryml::to_csubstr(content));
    ryml::NodeRef root = tree.rootref();

    if(root.has_child("server_url_root"))
    {
        root["server_url_root"] >> server_url_root;
    }
    if(root.has_child("port"))
    {
        root["port"] >> port;
    }

    if(root.has_child("data_dir"))
    {
        root["data_dir"] >> data_dir;
    }

    db_path = (std::filesystem::path(data_dir) / "unspoken.db").string();

    if(root.has_child("oidc_issuer_url"))
    {
        root["oidc_issuer_url"] >> oidc_issuer_url;
    }
    if(root.has_child("oidc_client_id"))
    {
        root["oidc_client_id"] >> oidc_client_id;
    }
    if(root.has_child("oidc_secret"))
    {
        root["oidc_secret"] >> oidc_secret;
    }
    if(root.has_child("secret_key"))
    {
        root["secret_key"] >> secret_key;
    }
    if(root.has_child("posts_per_page"))
    {
        root["posts_per_page"] >> posts_per_page;
    }

    if(root.has_child("nodeinfo"))
    {
        auto node = root["nodeinfo"];
        if(node.has_child("name"))
        {
            node["name"] >> nodeinfo.name;
        }
        if(node.has_child("description"))
        {
            node["description"] >> nodeinfo.description;
        }
    }
}
