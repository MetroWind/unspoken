#include "config.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <ryml.hpp>
#include <ryml_std.hpp> // For std::string support

std::string readFile(const std::string& path) {
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open config file: " + path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

Config& Config::get() {
    static Config instance;
    return instance;
}

void Config::load(const std::string& path) {
    std::string content = readFile(path);
    // rapidyaml requires the buffer to persist if we use parse_in_place, 
    // but parse_in_arena copies to arena.
    // However, to be safe and simple, we can keep the content if needed, 
    // or just copy values out immediately which we do.
    
    ryml::Tree tree = ryml::parse_in_arena(ryml::to_csubstr(content));
    ryml::NodeRef root = tree.rootref();

    if (root.has_child("server_domain")) root["server_domain"] >> server_domain;
    if (root.has_child("protocol")) root["protocol"] >> protocol;
    if (root.has_child("port")) root["port"] >> port;
    if (root.has_child("db_path")) root["db_path"] >> db_path;
    if (root.has_child("oidc_client_id")) root["oidc_client_id"] >> oidc_client_id;
    if (root.has_child("oidc_secret")) root["oidc_secret"] >> oidc_secret;
    if (root.has_child("secret_key")) root["secret_key"] >> secret_key;
    
    if (root.has_child("nodeinfo")) {
        auto node = root["nodeinfo"];
        if (node.has_child("name")) node["name"] >> nodeinfo.name;
        if (node.has_child("description")) node["description"] >> nodeinfo.description;
    }
}
