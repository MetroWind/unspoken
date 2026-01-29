#include "signature_verifier.hpp"
#include "json_ld.hpp"
#include <mw/crypto.hpp>
#include <mw/utils.hpp>
#include <sstream>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

SignatureVerifier::SignatureVerifier(std::unique_ptr<mw::HTTPSessionInterface> http_client,
                                       std::unique_ptr<mw::CryptoInterface> crypto)
    : http_client(std::move(http_client)), crypto(std::move(crypto))
{
}
static std::unordered_map<std::string, std::string> parseSignatureHeader(const std::string& header)
{
    std::unordered_map<std::string, std::string> params;
    std::string key, val;
    bool in_quote = false;
    bool parsing_key = true;
    
    for (char c : header)
    {
        if (parsing_key)
        {
            if (c == '=') parsing_key = false;
            else if (c != ' ' && c != ',') key += c;
        }
        else
        {
            if (c == '"') in_quote = !in_quote;
            else if (c == ',' && !in_quote)
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
    if (!key.empty()) params[key] = val;
    return params;
}

mw::E<std::string> SignatureVerifier::verify(const mw::HTTPServer::Request& req,
                                             const std::string& method,
                                             const std::string& path)
{
    if (!req.has_header("Signature"))
    {
        return std::unexpected(mw::httpError(401, "Missing Signature header"));
    }

    auto params = parseSignatureHeader(req.get_header_value("Signature"));
    if (params.find("keyId") == params.end() || 
        params.find("signature") == params.end() ||
        params.find("headers") == params.end())
    {
        return std::unexpected(mw::httpError(400, "Invalid Signature header format"));
    }

    std::string key_id = params["keyId"];
    std::string signature_base64 = params["signature"];
    std::string headers_str = params["headers"];

    // Fetch Public Key
    auto res_ptr = http_client->get(key_id);
    if (!res_ptr)
    {
        return std::unexpected(res_ptr.error());
    }
    
    const auto& res = *res_ptr; // Unwrap E<const HTTPResponse*> 
    
    if (res->status != 200)
    {
        return std::unexpected(mw::httpError(502, "Failed to fetch public key"));
    }

    std::string public_key_pem;
    std::string owner_id;

    try
    {
        auto j = nlohmann::json::parse(res->payloadAsStr());
        // Handle if returned object is Actor or Key
        if (json_ld::hasType(j, "Person") || json_ld::hasType(j, "Service") || json_ld::hasType(j, "Application"))
        {
            if (j.contains("publicKey") && j["publicKey"].contains("publicKeyPem"))
            {
                public_key_pem = j["publicKey"]["publicKeyPem"];
                owner_id = j["id"];
            }
        }
        else if (j.contains("publicKeyPem"))
        {
             public_key_pem = j["publicKeyPem"];
             owner_id = j.contains("owner") ? j["owner"].get<std::string>() : j["id"].get<std::string>();
        }
    }
    catch (const std::exception& e)
    {
        return std::unexpected(mw::httpError(502, "Invalid JSON from remote"));
    }

    if (public_key_pem.empty())
    {
        return std::unexpected(mw::httpError(502, "Could not find public key PEM"));
    }

    // Construct Comparison String
    std::string comparison_string;
    std::stringstream ss(headers_str);
    std::string header_name;
    bool first = true;

    while (std::getline(ss, header_name, ' '))
    {
        if (header_name.empty()) continue;
        if (!first) comparison_string += "\n";
        first = false;

        std::string val;
        if (header_name == "(request-target)")
        {
            std::string lower_method = method;
            mw::toLower(lower_method);
            val = lower_method + " " + path;
        }
        else
        {
            if (!req.has_header(header_name))
            {
                return std::unexpected(mw::httpError(400, "Signed header missing: " + header_name));
            }
            val = req.get_header_value(header_name);
        }
        comparison_string += header_name + ": " + val;
    }

    // Verify
    auto sig_bytes = mw::base64Decode(signature_base64);
    if (!sig_bytes)
    {
        return std::unexpected(mw::httpError(400, "Invalid base64 signature"));
    }

    // Assume RSA-SHA256 for now as it's standard for AP
    auto valid = crypto->verifySignature(mw::SignatureAlgorithm::RSA_V1_5_SHA256, 
                                     public_key_pem, 
                                     *sig_bytes, 
                                     comparison_string);
    
    if (!valid || !*valid)
    {
        spdlog::warn("Signature verification failed for keyId: {}", key_id);
        spdlog::debug("Comparison string:\n{}", comparison_string);
        return std::unexpected(mw::httpError(401, "Invalid Signature"));
    }

    return owner_id;
}
