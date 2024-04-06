#include <format>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "config.hpp"
#include "crypto.hpp"
#include "data.hpp"
#include "error.hpp"
#include "federation.hpp"
#include "url.hpp"
#include "url_manager.hpp"
#include "utils.hpp"

Federation::Federation(const Configuration& conf, DataSourceInterface& data,
                       Crypto& cry, URLManager& url)
        : config(conf), data_source(data), crypto(cry), url_manager(url),
          is_valid(true)
{
    E<URL> prefix = URL::fromStr(config.url_prefix);
    if(!prefix.has_value())
    {
        spdlog::error("Invalid url_prefix. Program cannot continue.");
        is_valid = false;
        return;
    }
    if(prefix->port().empty())
    {
        server_host = prefix->host();
    }
    else
    {
        server_host = std::format("{}:{}", prefix->host(), prefix->port());
    }

}

E<nlohmann::json> Federation::handleWebFinger(const httplib::Request& req)
{
    ASSIGN_OR_RETURN(
        auto query, WebFingerQuery::fromRequest(req).transform_error(
            [](Error&& e) { return httpError(400, errorMsg(e)); }));
    if(query.type != WebFingerQuery::RESOURCE ||
       query.resource_type != WebFingerQuery::ACCOUNT)
    {
        return std::unexpected(httpError(400, "Invalid web finger params"));
    }

    ASSIGN_OR_RETURN(const FediUser user, FediUser::fromStr(query.arg)
                     .transform_error([](Error&& e)
                     {
                         return httpError(400, errorMsg(e));
                     }));
    ASSIGN_OR_RETURN(URL prefix, URL::fromStr(config.url_prefix));
    if(user.server != server_host)
    {
        return std::unexpected(httpError(400, "Invalid user server"));
    }

    ASSIGN_OR_RETURN(auto user_maybe, data_source.getUser(user.name));
    if(!user_maybe.has_value())
    {
        return std::unexpected(httpError(404, "User not found"));
    }

    nlohmann::json data = {{"subject", std::string("acct:") + user.idStr()},
                           {"links", {
                                   {{"rel", "self"},
                                    {"type", "application/activity+json"},
                                    {"href", prefix.appendPath(url_manager.urlFor(
                                        "user-info", user.name)).str()}},
                               }
                           }};
    return data;
}

E<nlohmann::json> Federation::handleUserInfo(const std::string& username)
{
    // TODO: Get user info from data source.

    ASSIGN_OR_RETURN(auto user_maybe, data_source.getUser(username));
    if(!user_maybe.has_value())
    {
        return std::unexpected(httpError(404, "User not found"));
    }

    ASSIGN_OR_RETURN(URL prefix, URL::fromStr(config.url_prefix));
    std::string user_url = URL(prefix).appendPath(
        url_manager.urlFor("user", username)).str();
    nlohmann::json data =
        {{"@context", {"https://www.w3.org/ns/activitystreams",
                       "https://w3id.org/security/v1" }},
         {"id", user_url},
         {"type", "Person"},
         {"preferredUsername", username},
         {"inbox", URL(prefix).appendPath(url_manager.urlFor("inbox", username))
          .str()},
         {"publicKey", {{"id", user_url + KEY_URL_SUFFIX},
                        {"owner", user_url},
                        {"publicKeyPem", user_maybe->keys.pemPublicKey()}}}};
    return data;
}
