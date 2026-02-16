#include "signature_verifier.hpp"

#include <sstream>

#include <mw/crypto.hpp>
#include <mw/url.hpp>
#include <mw/utils.hpp>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "database.hpp"
#include "http_utils.hpp"
#include "json_ld.hpp"

SignatureVerifier::SignatureVerifier(
    std::unique_ptr<mw::HTTPSessionInterface> http_client,
    std::unique_ptr<mw::CryptoInterface> crypto,
    std::unique_ptr<DatabaseInterface> db, const std::string& system_actor_uri)
    : http_client(std::move(http_client)), crypto(std::move(crypto)),
      db(std::move(db)), system_actor_uri(system_actor_uri)
{
}

static std::unordered_map<std::string, std::string>
parseSignatureHeader(const std::string& header)
{
    std::unordered_map<std::string, std::string> params;
    std::string key, val;
    bool in_quote = false;
    bool parsing_key = true;

    for(char c : header)
    {
        if(parsing_key)
        {
            if(c == '=')
            {
                parsing_key = false;
            }
            else if(c != ' ' && c != ',')
            {
                key += c;
            }
        }
        else
        {
            if(c == '"')
            {
                in_quote = !in_quote;
            }
            else if(c == ',' && !in_quote)
            {
                params[key] = val;
                key.clear();
                val.clear();
                parsing_key = true;
            }
            else
            {
                val += c;
            }
        }
    }
    if(!key.empty())
    {
        params[key] = val;
    }
    return params;
}

mw::E<std::string> SignatureVerifier::fetchAndCacheActor(const std::string& uri)
{
    // Use signed GET with System Actor
    auto system_actor_res = db->getUserByUri(system_actor_uri);
    if(!system_actor_res || !system_actor_res.value())
    {
        return std::unexpected(mw::runtimeError("System actor not found"));
    }
    auto sys_actor = *system_actor_res.value();
    if(!sys_actor.private_key)
    {
        return std::unexpected(
            mw::runtimeError("System actor has no private key"));
    }

    auto url_res = mw::URL::fromStr(uri);
    if(!url_res)
    {
        return std::unexpected(url_res.error());
    }
    auto url = *url_res;

    std::string path = url.path();
    if(path.empty())
    {
        path = "/";
    }
    if(!url.query().empty())
    {
        path += "?" + url.query();
    }

    std::string date = http_utils::getHttpDate();
    std::string host = url.host();
    if(url.port() != "80" && url.port() != "443" && !url.port().empty())
    {
        host += ":" + url.port();
    }

    std::string to_sign = "(request-target): get " + path + "\n" +
                          "host: " + host + "\n" + "date: " + date;

    auto sig_bytes = crypto->sign(mw::SignatureAlgorithm::RSA_V1_5_SHA256,
                                  *sys_actor.private_key, to_sign);
    if(!sig_bytes)
    {
        return std::unexpected(sig_bytes.error());
    }
    std::string signature = mw::base64Encode(*sig_bytes);

    auto sys_uri = mw::URL::fromStr(system_actor_uri);
    std::string key_id = system_actor_uri;
    if(sys_uri)
    {
        sys_uri->fragment("main-key");
        key_id = sys_uri->str();
    }
    else
    {
        key_id += "#main-key";
    }

    std::string sig_header = "keyId=\"" + key_id +
                             "\",algorithm=\"hs2019\",headers=\"(request-"
                             "target) host date\",signature=\"" +
                             signature + "\"";

    mw::HTTPRequest req(uri);
    req.addHeader("Host", host);
    req.addHeader("Date", date);
    req.addHeader("Signature", sig_header);
    req.addHeader("Accept", "application/activity+json");

    auto res_ptr = http_client->get(req);
    if(!res_ptr)
    {
        return std::unexpected(res_ptr.error());
    }

    if((*res_ptr)->status != 200)
    {
        return std::unexpected(
            mw::httpError(502, "Failed to fetch actor: " +
                                   std::to_string((*res_ptr)->status)));
    }

    try
    {
        auto j = nlohmann::json::parse((*res_ptr)->payloadAsStr());
        std::string public_key_pem;
        std::string owner_id = j["id"];

        if(j.contains("publicKey") && j["publicKey"].contains("publicKeyPem"))
        {
            public_key_pem = j["publicKey"]["publicKeyPem"];
        }
        else if(j.contains("publicKeyPem"))
        {
            public_key_pem = j["publicKeyPem"];
        }

        if(public_key_pem.empty())
        {
            return std::unexpected(mw::runtimeError("No public key in actor"));
        }

        auto existing = db->getUserByUri(owner_id);
        if(existing && existing.value())
        {
            auto user = *existing.value();
            user.public_key = public_key_pem;
            // Update other fields too?
            user.display_name = j.value("name", user.display_name);
            user.bio = j.value("summary", user.bio);
            user.inbox = json_ld::getId(j, "inbox");
            if(j.contains("endpoints") &&
               j["endpoints"].contains("sharedInbox"))
            {
                user.shared_inbox =
                    json_ld::getId(j["endpoints"], "sharedInbox");
            }
            DO_OR_RETURN(db->updateUser(user));
        }
        else
        {
            User u;
            u.uri = owner_id;
            u.username = j["preferredUsername"];
            u.display_name = j.value("name", "");
            u.bio = j.value("summary", "");
            u.public_key = public_key_pem;
            u.created_at = std::time(nullptr);
            u.inbox = json_ld::getId(j, "inbox");
            if(j.contains("endpoints") &&
               j["endpoints"].contains("sharedInbox"))
            {
                u.shared_inbox = json_ld::getId(j["endpoints"], "sharedInbox");
            }
            auto url = mw::URL::fromStr(owner_id);
            if(url)
            {
                u.host = url->host();
            }

            DO_OR_RETURN(db->createUser(u));
        }
        return public_key_pem;
    }
    catch(...)
    {
        return std::unexpected(mw::runtimeError("Failed to parse actor JSON"));
    }
}

mw::E<std::string> SignatureVerifier::verify(const mw::HTTPServer::Request& req,
                                             const std::string& method,
                                             const std::string& path)
{
    // 1. Date Validation
    if(!req.has_header("Date"))
    {
        return std::unexpected(mw::httpError(401, "Missing Date header"));
    }
    if(!http_utils::checkDateSkew(req.get_header_value("Date")))
    {
        return std::unexpected(mw::httpError(401, "Date header too skewed"));
    }

    // 2. Digest Verification
    if(method == "POST" || method == "PUT")
    {
        if(!req.has_header("Digest"))
        {
            return std::unexpected(mw::httpError(401, "Missing Digest header"));
        }
        std::string digest_header = req.get_header_value("Digest");
        if(digest_header.starts_with("SHA-256="))
        {
            std::string remote_digest = digest_header.substr(8);
            auto local_digest_bytes = mw::SHA256Hasher().hashToBytes(req.body);
            if(!local_digest_bytes)
            {
                return std::unexpected(mw::runtimeError("Hash failed"));
            }
            std::string local_digest = mw::base64Encode(*local_digest_bytes);
            if(remote_digest != local_digest)
            {
                return std::unexpected(mw::httpError(401, "Digest mismatch"));
            }
        }
    }

    if(!req.has_header("Signature"))
    {
        return std::unexpected(mw::httpError(401, "Missing Signature header"));
    }

    auto params = parseSignatureHeader(req.get_header_value("Signature"));
    if(params.find("keyId") == params.end() ||
       params.find("signature") == params.end() ||
       params.find("headers") == params.end())
    {
        return std::unexpected(
            mw::httpError(400, "Invalid Signature header format"));
    }

    std::string key_id = params["keyId"];
    std::string signature_base64 = params["signature"];
    std::string headers_str = params["headers"];

    auto sig_bytes = mw::base64Decode(signature_base64);
    if(!sig_bytes)
    {
        return std::unexpected(mw::httpError(400, "Invalid base64 signature"));
    }

    // Extract Actor URI from keyId (usually actor_uri#main-key)
    std::string actor_uri = key_id;
    auto k_url = mw::URL::fromStr(key_id);
    if(k_url)
    {
        k_url->fragment(nullptr); // Remove fragment
        actor_uri = k_url->str();
    }
    else
    {
        size_t hash_pos = actor_uri.find('#');
        if(hash_pos != std::string::npos)
        {
            actor_uri = actor_uri.substr(0, hash_pos);
        }
    }

    auto construct_comparison_string =
        [&](const std::string& headers) -> std::string
    {
        std::string comparison_string;
        std::stringstream ss(headers);
        std::string header_name;
        bool first = true;
        while(std::getline(ss, header_name, ' '))
        {
            if(header_name.empty())
            {
                continue;
            }
            if(!first)
            {
                comparison_string += "\n";
            }
            first = false;
            std::string val;
            if(header_name == "(request-target)")
            {
                std::string lower_method = method;
                mw::toLower(lower_method);
                val = lower_method + " " + path;
            }
            else
            {
                if(!req.has_header(header_name))
                {
                    return ""; // Error
                }
                val = req.get_header_value(header_name);
            }
            comparison_string += header_name + ": " + val;
        }
        return comparison_string;
    };

    std::string comparison_string = construct_comparison_string(headers_str);
    if(comparison_string.empty())
    {
        return std::unexpected(
            mw::httpError(400, "Failed to construct comparison string"));
    }

    auto verify_with_key = [&](const std::string& pem) -> bool
    {
        auto valid =
            crypto->verifySignature(mw::SignatureAlgorithm::RSA_V1_5_SHA256,
                                    pem, *sig_bytes, comparison_string);
        return valid && *valid;
    };

    auto user_res = db->getUserByUri(actor_uri);
    if(user_res && user_res.value())
    {
        if(verify_with_key(user_res.value()->public_key))
        {
            return actor_uri;
        }
        spdlog::info(
            "Verification failed with cached key for {}, re-fetching...",
            actor_uri);
    }

    // Fetch-on-failure or initial fetch
    auto fetch_res = fetchAndCacheActor(actor_uri);
    if(!fetch_res)
    {
        return std::unexpected(fetch_res.error());
    }

    if(verify_with_key(*fetch_res))
    {
        return actor_uri;
    }

    return std::unexpected(mw::httpError(401, "Invalid Signature"));
}
