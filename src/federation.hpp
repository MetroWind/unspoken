#pragma once

#include <expected>
#include <string>
#include <string_view>
#include <format>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "config.hpp"
#include "crypto.hpp"
#include "data.hpp"
#include "error.hpp"
#include "url_manager.hpp"

constexpr char KEY_URL_SUFFIX[] = "#main-key";

struct WebFingerQuery
{
    enum Type { RESOURCE, };
    enum ResourceType { ACCOUNT, };

    static E<WebFingerQuery> fromRequest(const httplib::Request& req);

    Type type;
    ResourceType resource_type;
    std::string arg;
};

class Federation
{
public:
    Federation(const Configuration& conf, DataSourceInterface& data,
               Crypto& crypto, URLManager& url);
    bool good() const { return is_valid; }

    E<nlohmann::json> handleWebFinger(const httplib::Request& req);
    E<nlohmann::json> handleUserInfo(const std::string& username);

private:
    const Configuration& config;
    DataSourceInterface& data_source;
    Crypto& crypto;
    URLManager& url_manager;
    std::string server_host;
    bool is_valid;
};
