#include "federation.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <ctime>
#include <format>
#include <iomanip>
#include <locale>
#include <map>
#include <sstream>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>
#include <mw/crypto.hpp>
#include <mw/error.hpp>
#include <mw/http_client.hpp>
#include <mw/url.hpp>
#include <mw/utils.hpp>
#include <spdlog/spdlog.h>

#include "attachments.hpp"
#include "data.hpp"
#include "emoji.hpp"
#include "render.hpp"
#include "structs.hpp"

namespace unspoken
{

namespace
{

nlohmann::json activityContext()
{
    return nlohmann::json::array({
        "https://www.w3.org/ns/activitystreams",
        "https://w3id.org/security/v1",
    });
}

std::string isoTimestamp(int64_t unix_seconds)
{
    std::time_t t = static_cast<std::time_t>(unix_seconds);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

std::string localAttachmentUrl(const Config& config, const Attachment& a)
{
    std::string ext = a.extension.empty()
        ? extensionOf(a.original_name) : a.extension;
    std::string filename = ext.empty() ? a.sha256 : (a.sha256 + "." + ext);
    return std::format("{}media/{}/{}", config.url_root,
                       a.sha256.substr(0, 1), filename);
}

std::optional<nlohmann::json> actorImageJson(
    const Config& config, const std::optional<Attachment>& attachment)
{
    if(!attachment.has_value() || attachment->remote_url.has_value()
       || !attachment->is_image)
    {
        return std::nullopt;
    }
    return nlohmann::json{
        {"type", "Image"},
        {"mediaType", attachment->media_type},
        {"url", localAttachmentUrl(config, *attachment)},
        {"name", attachment->original_name},
    };
}

std::string httpDate()
{
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[40];
    std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    return std::string(buf);
}

std::string requestTarget(const mw::URL& url)
{
    std::string path = url.path();
    if(path.empty()) path = "/";
    std::string query = url.query();
    if(!query.empty()) path += "?" + query;
    return path;
}

std::string requestAuthority(const mw::URL& url)
{
    std::string host = url.host();
    std::string port = url.port();
    if(port.empty()) return host;
    if((url.scheme() == "https" && port == "443")
       || (url.scheme() == "http" && port == "80"))
    {
        return host;
    }
    return host + ":" + port;
}

nlohmann::json headersJson(
    const std::unordered_map<std::string, std::string>& headers)
{
    nlohmann::json out = nlohmann::json::object();
    for(const auto& [key, value] : headers) out[key] = value;
    return out;
}

void logOutgoingFederationRequest(std::string_view method,
                                  const mw::HTTPRequest& req)
{
    spdlog::info("Outgoing federation request: {} {} bytes={}",
                 method, req.url, req.request_data.size());
    spdlog::debug("Outgoing federation request headers: {}",
                  headersJson(req.header).dump());
    spdlog::debug("Outgoing federation request body: {}",
                  req.request_data);
}

void logOutgoingFederationResponse(std::string_view method,
                                   const mw::HTTPRequest& req,
                                   const mw::HTTPResponse& res)
{
    spdlog::info("Outgoing federation response: {} {} status={} bytes={}",
                 method, req.url, res.status, res.payload.size());
    spdlog::debug("Outgoing federation response headers: {}",
                  headersJson(res.header).dump());
    spdlog::debug("Outgoing federation response body: {}",
                  res.payloadAsStr());
}

bool ipv4In(const std::vector<uint8_t>& a, uint8_t b0)
{
    return a.size() == 4 && a[0] == b0;
}

bool ipv4In(const std::vector<uint8_t>& a, uint8_t b0, uint8_t b1)
{
    return a.size() == 4 && a[0] == b0 && a[1] == b1;
}

bool ipv6AllZeroUntilLast(const std::vector<uint8_t>& a, uint8_t last)
{
    if(a.size() != 16 || a[15] != last) return false;
    for(size_t i = 0; i < 15; ++i) if(a[i] != 0) return false;
    return true;
}

std::string lower(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    for(char c : s)
    {
        out.push_back(static_cast<char>(std::tolower(
            static_cast<unsigned char>(c))));
    }
    return out;
}

bool hostMatches(std::string_view host,
                 const std::vector<std::string>& allowed_hosts)
{
    std::string needle = lower(host);
    for(const auto& allowed : allowed_hosts)
    {
        if(needle == lower(allowed)) return true;
    }
    return false;
}

bool isMetadataAddress(const mw::SockAddr& addr)
{
    const auto& a = addr.address;
    return addr.family == mw::AddressFamily::IPV4 && a.size() == 4
        && a[0] == 169 && a[1] == 254 && a[2] == 169 && a[3] == 254;
}

std::string addressForLog(const mw::SockAddr& addr)
{
    const auto& a = addr.address;
    if(addr.family == mw::AddressFamily::IPV4 && a.size() == 4)
    {
        return std::format("{}.{}.{}.{}:{}", a[0], a[1], a[2], a[3],
                           addr.port);
    }
    std::ostringstream out;
    out << "[";
    for(size_t i = 0; i < a.size(); i += 2)
    {
        if(i > 0) out << ":";
        uint16_t part = static_cast<uint16_t>(a[i]) << 8;
        if(i + 1 < a.size()) part |= a[i + 1];
        out << std::hex << part;
    }
    out << "]:" << std::dec << addr.port;
    return out.str();
}

std::string percentEncode(std::string_view s)
{
    constexpr char HEX[] = "0123456789ABCDEF";
    std::string out;
    for(unsigned char c : s)
    {
        bool keep = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '-' || c == '_'
            || c == '.' || c == '~';
        if(keep)
        {
            out.push_back(static_cast<char>(c));
        }
        else
        {
            out.push_back('%');
            out.push_back(HEX[c >> 4]);
            out.push_back(HEX[c & 0x0f]);
        }
    }
    return out;
}

std::optional<std::pair<std::string, std::string>>
parseHandle(std::string_view handle)
{
    handle = mw::strip(handle);
    if(handle.starts_with('@')) handle.remove_prefix(1);
    size_t at = handle.find('@');
    if(at == std::string_view::npos || at == 0 || at + 1 >= handle.size())
        return std::nullopt;
    if(handle.find('@', at + 1) != std::string_view::npos)
        return std::nullopt;
    std::string username(handle.substr(0, at));
    std::string domain(handle.substr(at + 1));
    if(domain.find('/') != std::string::npos
       || domain.find(':') != std::string::npos)
    {
        return std::nullopt;
    }
    return std::make_pair(username, domain);
}

std::unordered_map<std::string, std::string>
lowerHeaders(const std::unordered_map<std::string, std::string>& headers)
{
    std::unordered_map<std::string, std::string> out;
    for(const auto& [k, v] : headers) out[lower(k)] = v;
    return out;
}

std::optional<std::string> header(
    const std::unordered_map<std::string, std::string>& headers,
    std::string_view name)
{
    auto it = headers.find(std::string(name));
    if(it == headers.end()) return std::nullopt;
    return it->second;
}

std::vector<std::string> splitWords(std::string_view s)
{
    std::istringstream in{std::string(s)};
    std::vector<std::string> out;
    std::string item;
    while(in >> item) out.push_back(item);
    return out;
}

std::unordered_map<std::string, std::string>
parseSignatureParams(std::string_view sig)
{
    std::unordered_map<std::string, std::string> out;
    size_t pos = 0;
    while(pos < sig.size())
    {
        while(pos < sig.size() && (sig[pos] == ' ' || sig[pos] == ','))
            ++pos;
        size_t eq = sig.find('=', pos);
        if(eq == std::string_view::npos) break;
        std::string key = lower(sig.substr(pos, eq - pos));
        pos = eq + 1;
        std::string value;
        if(pos < sig.size() && sig[pos] == '"')
        {
            ++pos;
            while(pos < sig.size())
            {
                if(sig[pos] == '\\' && pos + 1 < sig.size())
                {
                    value.push_back(sig[pos + 1]);
                    pos += 2;
                    continue;
                }
                if(sig[pos] == '"')
                {
                    ++pos;
                    break;
                }
                value.push_back(sig[pos++]);
            }
        }
        else
        {
            size_t comma = sig.find(',', pos);
            value = std::string(sig.substr(
                pos, comma == std::string_view::npos ? comma : comma - pos));
            pos = comma == std::string_view::npos ? sig.size() : comma + 1;
        }
        out[key] = value;
    }
    return out;
}

struct ParsedHttpSignature
{
    std::string key_id;
    std::string actor_uri;
    std::vector<std::string> signed_headers;
    std::vector<unsigned char> signature;
    std::string signing_input;
};

std::optional<int64_t> parseHttpDate(std::string_view date)
{
    std::tm tm{};
    std::istringstream in{std::string(date)};
    in.imbue(std::locale::classic());
    in >> std::get_time(&tm, "%a, %d %b %Y %H:%M:%S GMT");
    if(in.fail()) return std::nullopt;
#if defined(_WIN32)
    return static_cast<int64_t>(_mkgmtime(&tm));
#else
    return static_cast<int64_t>(timegm(&tm));
#endif
}

mw::E<std::string> digestHeaderFor(std::string_view body)
{
    mw::SHA256Hasher hasher;
    ASSIGN_OR_RETURN(auto digest, hasher.hashToBytes(std::string(body)));
    return "SHA-256=" + mw::base64Encode(
        std::span<unsigned char>(digest.data(), digest.size()), false, true);
}

mw::E<bool> verifyDigestHeader(std::string_view header_value,
                               std::string_view body)
{
    mw::SHA256Hasher hasher;
    ASSIGN_OR_RETURN(auto expected, hasher.hashToBytes(std::string(body)));

    size_t pos = 0;
    while(pos < header_value.size())
    {
        size_t comma = header_value.find(',', pos);
        std::string_view part = comma == std::string_view::npos
            ? header_value.substr(pos)
            : header_value.substr(pos, comma - pos);
        pos = comma == std::string_view::npos ? header_value.size()
                                              : comma + 1;

        size_t eq = part.find('=');
        if(eq == std::string_view::npos) continue;
        std::string algorithm(lower(mw::strip(part.substr(0, eq))));
        if(algorithm != "sha-256") continue;

        std::string encoded(mw::strip(part.substr(eq + 1)));
        ASSIGN_OR_RETURN(auto actual, mw::base64Decode(encoded));
        return actual.size() == expected.size()
            && std::equal(actual.begin(), actual.end(), expected.begin());
    }
    return false;
}

bool containsHeader(const std::vector<std::string>& headers,
                    std::string_view name)
{
    for(const auto& h : headers) if(lower(h) == name) return true;
    return false;
}

std::string firstForwardedValue(std::string_view value)
{
    size_t comma = value.find(',');
    return std::string(mw::strip(
        comma == std::string_view::npos ? value : value.substr(0, comma)));
}

std::unordered_map<std::string, std::string> signatureHeaders(
    const std::unordered_map<std::string, std::string>& raw_headers)
{
    auto headers = lowerHeaders(raw_headers);
    auto forwarded_host = header(headers, "x-forwarded-host");
    if(forwarded_host.has_value() && !forwarded_host->empty())
    {
        headers["host"] = firstForwardedValue(*forwarded_host);
    }
    return headers;
}

mw::E<std::string> signingString(
    const IncomingHttpRequest& req,
    const std::unordered_map<std::string, std::string>& headers,
    const std::vector<std::string>& signed_headers)
{
    std::vector<std::string> lines;
    for(const auto& raw_name : signed_headers)
    {
        std::string name = lower(raw_name);
        if(name == "(request-target)")
        {
            lines.push_back(std::format("(request-target): {} {}",
                                        lower(req.method), req.target));
            continue;
        }
        auto value = header(headers, name);
        if(!value.has_value())
        {
            return std::unexpected(mw::runtimeError(
                std::format("Signed header missing: {}", name)));
        }
        lines.push_back(std::format("{}: {}", name, *value));
    }

    std::string out;
    for(size_t i = 0; i < lines.size(); ++i)
    {
        if(i > 0) out.push_back('\n');
        out += lines[i];
    }
    return out;
}

mw::E<ParsedHttpSignature> parseHttpSignature(
    const Config& config, const IncomingHttpRequest& req,
    int64_t now_seconds)
{
    auto headers = signatureHeaders(req.headers);
    auto sig_header = header(headers, "signature");
    if(!sig_header.has_value())
    {
        return std::unexpected(mw::httpError(401, "Missing Signature"));
    }
    auto params = parseSignatureParams(*sig_header);
    if(!params.contains("keyid") || !params.contains("signature")
       || params["keyid"].empty() || params["signature"].empty())
    {
        return std::unexpected(mw::httpError(401, "Bad Signature header"));
    }

    std::string algorithm = lower(params.contains("algorithm")
        ? params["algorithm"] : "rsa-sha256");
    if(algorithm != "rsa-sha256" && algorithm != "hs2019")
    {
        return std::unexpected(mw::httpError(
            401, "Unsupported signature algorithm"));
    }

    std::vector<std::string> signed_headers = params.contains("headers")
        ? splitWords(params["headers"])
        : std::vector<std::string>{"date"};
    if(!containsHeader(signed_headers, "date"))
    {
        return std::unexpected(mw::httpError(401, "Date is not signed"));
    }
    if(!containsHeader(signed_headers, "(request-target)"))
    {
        return std::unexpected(mw::httpError(
            401, "Request target is not signed"));
    }

    auto date = header(headers, "date");
    if(!date.has_value())
    {
        return std::unexpected(mw::httpError(401, "Missing Date"));
    }
    auto request_time = parseHttpDate(*date);
    if(!request_time.has_value()
       || std::llabs(now_seconds - *request_time)
              > config.http_signature_skew_seconds)
    {
        return std::unexpected(mw::httpError(401, "Date skew too large"));
    }

    std::string method = lower(req.method);
    if(method == "post" || method == "put")
    {
        if(!containsHeader(signed_headers, "digest"))
        {
            return std::unexpected(mw::httpError(
                401, "Digest is not signed"));
        }
        auto digest = header(headers, "digest");
        if(!digest.has_value())
        {
            return std::unexpected(mw::httpError(401, "Missing Digest"));
        }
        auto digest_ok = verifyDigestHeader(*digest, req.body);
        if(!digest_ok.has_value() || !*digest_ok)
        {
            return std::unexpected(mw::httpError(401, "Digest mismatch"));
        }
    }

    auto signature = mw::base64Decode(params["signature"]);
    if(!signature.has_value())
    {
        return std::unexpected(mw::httpError(401, "Bad Signature header"));
    }
    auto signing_input = signingString(req, headers, signed_headers);
    if(!signing_input.has_value())
    {
        return std::unexpected(mw::httpError(401, "Bad Signature header"));
    }

    std::string actor_uri = params["keyid"];
    size_t hash = actor_uri.find('#');
    if(hash != std::string::npos) actor_uri.resize(hash);
    if(actor_uri.empty() || !isValidRemoteUrl(config.dev, actor_uri))
    {
        return std::unexpected(mw::httpError(401, "Invalid signature key"));
    }

    return ParsedHttpSignature{
        std::move(params["keyid"]),
        std::move(actor_uri),
        std::move(signed_headers),
        std::move(*signature),
        std::move(*signing_input),
    };
}

mw::E<bool> verifyParsedHttpSignature(
    mw::CryptoInterface& crypto, const ParsedHttpSignature& signature,
    const RemoteActor& actor)
{
    if(actor.uri != signature.actor_uri
       || actor.public_key_id != signature.key_id)
    {
        return false;
    }
    return crypto.verifySignature(mw::SignatureAlgorithm::RSA_V1_5_SHA256,
                                  actor.public_key_pem,
                                  signature.signature,
                                  signature.signing_input);
}

void appendAll(std::vector<std::string>& out,
               const std::vector<std::string>& in)
{
    out.insert(out.end(), in.begin(), in.end());
}

bool boolField(const nlohmann::json& object, std::string_view key)
{
    if(!object.is_object()) return false;
    auto it = object.find(std::string(key));
    return it != object.end() && it->is_boolean() && it->get<bool>();
}

mw::E<void> handleCreateActivity(const Config& config,
                                 const DataSourceInterface& data,
                                 const Activity& activity);
bool isLocalActorUri(const Config& config, std::string_view uri);

mw::E<SigningActor> signingActorForUri(const Config& config,
                                       const DataSourceInterface& data,
                                       std::string_view actor_uri)
{
    const std::string system_uri = config.url_root + "actor";
    if(actor_uri == system_uri)
    {
        ASSIGN_OR_RETURN(auto system, data.getSystemActor());
        if(!system.has_value())
        {
            return std::unexpected(mw::runtimeError(
                "Delivery signer is missing system actor"));
        }
        return signingActorForSystem(config, *system);
    }

    const std::string local_prefix = config.url_root + "u/";
    if(!actor_uri.starts_with(local_prefix))
    {
        return std::unexpected(mw::runtimeError(
            "Delivery signer must be a local actor"));
    }
    std::string_view username = actor_uri.substr(local_prefix.size());
    if(username.empty() || username.find('/') != std::string_view::npos)
    {
        return std::unexpected(mw::runtimeError(
            "Delivery signer actor URI is invalid"));
    }
    ASSIGN_OR_RETURN(auto user, data.getUserByUsername(username));
    if(!user.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Delivery signer local user not found"));
    }
    return signingActorFor(config, *user);
}

mw::E<void> performDeliveryJob(const Config& config,
                               const DataSourceInterface& data,
                               mw::CryptoInterface& crypto,
                               mw::HTTPSessionInterface& http,
                               const nlohmann::json& payload)
{
    if(!payload.is_object() || !payload.contains("target_inbox")
       || !payload["target_inbox"].is_string()
       || !payload.contains("signer_actor")
       || !payload["signer_actor"].is_string()
       || !payload.contains("activity"))
    {
        return std::unexpected(mw::runtimeError(
            "Delivery job payload is malformed"));
    }

    std::string inbox = payload["target_inbox"].get<std::string>();
    std::string signer_uri = payload["signer_actor"].get<std::string>();
    ASSIGN_OR_RETURN(auto signer, signingActorForUri(config, data,
                                                     signer_uri));
    std::string body = payload["activity"].dump();

    DO_OR_RETURN(hardenOutboundSession(config, http, inbox));
    ASSIGN_OR_RETURN(auto req, signedHttpRequest(
        config, crypto, signer, "POST", inbox, body,
        "application/activity+json"));
    logOutgoingFederationRequest("POST", req);
    auto res_e = http.post(req);
    if(!res_e.has_value())
    {
        spdlog::warn("Outgoing federation response: POST {} failed: {}",
                     req.url, mw::errorMsg(res_e.error()));
        return std::unexpected(res_e.error());
    }
    const mw::HTTPResponse* res = *res_e;
    logOutgoingFederationResponse("POST", req, *res);
    if(res->status < 200 || res->status >= 300)
    {
        return std::unexpected(mw::httpError(
            res->status, "Activity delivery failed"));
    }
    return {};
}

std::vector<std::string> objectRefsFromCollection(const nlohmann::json& doc)
{
    std::vector<std::string> out;
    auto add_refs = [&](const nlohmann::json& items)
    {
        if(items.is_array())
        {
            for(const auto& item : items)
                if(auto ref = normalizeRef(item); ref.has_value())
                    out.push_back(*ref);
        }
        else if(auto ref = normalizeRef(items); ref.has_value())
        {
            out.push_back(*ref);
        }
    };

    if(doc.is_array())
    {
        add_refs(doc);
        return out;
    }
    if(!doc.is_object()) return out;
    if(doc.contains("orderedItems")) add_refs(doc["orderedItems"]);
    if(doc.contains("items")) add_refs(doc["items"]);
    return out;
}

mw::E<nlohmann::json> signedGetJson(
    const Config& config, mw::CryptoInterface& crypto,
    mw::HTTPSessionInterface& http, const SystemActor& system_actor,
    std::string_view uri)
{
    DO_OR_RETURN(hardenOutboundSession(config, http, uri));
    ASSIGN_OR_RETURN(auto req, signedGetRequest(config, system_actor, crypto,
                                                uri));
    ASSIGN_OR_RETURN(const mw::HTTPResponse* res, http.get(req));
    if(res->status < 200 || res->status >= 300)
    {
        return std::unexpected(mw::httpError(res->status,
                                             "Remote object fetch failed"));
    }
    nlohmann::json doc = nlohmann::json::parse(res->payloadAsStr(),
                                               nullptr, false);
    if(!doc.is_object() && !doc.is_array())
    {
        return std::unexpected(mw::runtimeError(
            "Remote object response is not JSON"));
    }
    return doc;
}

mw::E<void> ensureRemoteActorForObject(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, const nlohmann::json& object,
    std::string_view fallback_actor)
{
    auto actor_uri = normalizeRef(object.contains("attributedTo")
        ? object["attributedTo"] : nlohmann::json());
    std::string uri = actor_uri.value_or(std::string(fallback_actor));
    if(uri.empty() || isLocalActorUri(config, uri)) return {};

    ASSIGN_OR_RETURN(auto actor, ensureRemoteActorRetained(
        config, data, crypto, http, system_actor, uri,
        mw::timeToSeconds(mw::Clock::now())));
    (void)actor;
    return {};
}

mw::E<void> fetchThreadObject(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view uri, int depth_left,
    std::set<std::string>& seen)
{
    if(depth_left <= 0 || uri.empty()) return {};
    std::string key(uri);
    if(!seen.insert(key).second) return {};

    ASSIGN_OR_RETURN(auto doc, signedGetJson(config, crypto, http,
                                             system_actor, uri));
    if(doc.is_array())
    {
        for(const auto& ref : objectRefsFromCollection(doc))
        {
            DO_OR_RETURN(fetchThreadObject(config, data, crypto, http,
                                           system_actor, ref, depth_left - 1,
                                           seen));
        }
        return {};
    }

    if(doc.value("type", std::string()) == "Note")
    {
        auto object_uri = normalizeRef(doc);
        if(!object_uri.has_value()) return {};
        auto actor = normalizeRef(doc.contains("attributedTo")
            ? doc["attributedTo"] : nlohmann::json());
        Activity synthetic;
        synthetic.id = *object_uri + "#fetch";
        synthetic.type = "Create";
        synthetic.actor = actor.value_or(std::string());
        synthetic.object = doc;
        synthetic.raw = {
            {"id", synthetic.id},
            {"type", "Create"},
            {"actor", synthetic.actor},
            {"object", doc},
        };
        if(!synthetic.actor.empty())
            DO_OR_RETURN(handleCreateActivity(config, data, synthetic));

        auto parent = normalizeRef(doc.contains("inReplyTo")
            ? doc["inReplyTo"] : nlohmann::json());
        if(parent.has_value())
        {
            ASSIGN_OR_RETURN(auto existing_parent,
                             data.getPostByUri(*parent));
            if(!existing_parent.has_value())
            {
                DO_OR_RETURN(fetchThreadObject(config, data, crypto, http,
                                               system_actor, *parent,
                                               depth_left - 1, seen));
            }
        }

        if(doc.contains("replies"))
        {
            std::vector<std::string> replies =
                objectRefsFromCollection(doc["replies"]);
            if(replies.empty())
            {
                auto first = normalizeRef(
                    doc["replies"].contains("first")
                        ? doc["replies"]["first"] : nlohmann::json());
                if(first.has_value())
                {
                    ASSIGN_OR_RETURN(auto page, signedGetJson(
                        config, crypto, http, system_actor, *first));
                    replies = objectRefsFromCollection(page);
                }
            }
            for(const auto& reply : replies)
            {
                ASSIGN_OR_RETURN(auto existing_reply,
                                 data.getPostByUri(reply));
                if(!existing_reply.has_value())
                {
                    DO_OR_RETURN(fetchThreadObject(config, data, crypto, http,
                                                   system_actor, reply,
                                                   depth_left - 1, seen));
                }
            }
        }
    }
    else
    {
        for(const auto& ref : objectRefsFromCollection(doc))
        {
            DO_OR_RETURN(fetchThreadObject(config, data, crypto, http,
                                           system_actor, ref, depth_left - 1,
                                           seen));
        }
    }
    return {};
}

mw::E<void> performFetchThreadJob(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const nlohmann::json& payload)
{
    if(!payload.is_object() || !payload.contains("root_uri")
       || !payload["root_uri"].is_string())
    {
        return std::unexpected(mw::runtimeError(
            "Fetch-thread job payload is malformed"));
    }
    ASSIGN_OR_RETURN(auto system_actor, data.getSystemActor());
    if(!system_actor.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Fetch-thread job requires a system actor"));
    }
    int depth = payload.value("depth", config.thread_fetch_max_depth);
    if(depth > config.thread_fetch_max_depth)
        depth = config.thread_fetch_max_depth;
    std::set<std::string> seen;
    return fetchThreadObject(config, data, crypto, http, *system_actor,
                             payload["root_uri"].get<std::string>(),
                             depth, seen);
}

bool isLocalActorUri(const Config& config, std::string_view uri)
{
    return uri.starts_with(config.url_root + "u/")
        || uri == config.url_root + "actor";
}

std::optional<std::string> localUsernameForActor(const Config& config,
                                                 std::string_view uri)
{
    const std::string prefix = config.url_root + "u/";
    if(!uri.starts_with(prefix)) return std::nullopt;
    std::string_view username = uri.substr(prefix.size());
    if(username.empty() || username.find('/') != std::string_view::npos)
        return std::nullopt;
    return std::string(username);
}

std::optional<std::string> followersCollectionOwner(const Config& config,
                                                    std::string_view uri)
{
    constexpr std::string_view SUFFIX = "/followers";
    if(!uri.starts_with(config.url_root + "u/")
       || !uri.ends_with(SUFFIX))
    {
        return std::nullopt;
    }
    return std::string(uri.substr(0, uri.size() - SUFFIX.size()));
}

bool isLocalPostUri(const Config& config, std::string_view uri)
{
    return uri.starts_with(config.url_root + "p/");
}

mw::E<bool> referencesKnownOwnedObject(
    const Config& config, const DataSourceInterface& data,
    std::string_view uri, int depth_left)
{
    if(depth_left <= 0 || uri.empty()) return false;
    if(isLocalPostUri(config, uri)) return true;

    ASSIGN_OR_RETURN(auto post, data.getPostByUri(uri));
    if(!post.has_value()) return false;
    if(post->local_author_id.has_value()) return true;
    if(post->in_reply_to_uri.has_value())
    {
        return referencesKnownOwnedObject(config, data,
                                          *post->in_reply_to_uri,
                                          depth_left - 1);
    }
    return false;
}

std::vector<std::string> forwardingReferenceUris(const Activity& activity)
{
    std::vector<std::string> out;
    if(auto ref = normalizeRef(activity.object); ref.has_value())
        out.push_back(*ref);
    if(activity.object.is_object())
    {
        if(auto ref = normalizeRef(activity.object.contains("inReplyTo")
                ? activity.object["inReplyTo"] : nlohmann::json());
           ref.has_value())
        {
            out.push_back(*ref);
        }
    }
    if(activity.raw.is_object())
    {
        if(auto ref = normalizeRef(activity.raw.contains("target")
                ? activity.raw["target"] : nlohmann::json());
           ref.has_value())
        {
            out.push_back(*ref);
        }
        nlohmann::json tags = activity.raw.value("tag",
                                                 nlohmann::json::array());
        if(tags.is_object()) tags = nlohmann::json::array({tags});
        if(tags.is_array())
        {
            for(const auto& tag : tags)
                if(auto ref = normalizeRef(tag); ref.has_value())
                    out.push_back(*ref);
        }
    }
    return out;
}

mw::E<bool> refetchedObjectReferencesOwnedObject(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view object_uri)
{
    if(isLocalPostUri(config, object_uri)) return true;
    ASSIGN_OR_RETURN(auto doc, signedGetJson(config, crypto, http,
                                             system_actor, object_uri));
    if(!doc.is_object()) return false;
    auto fetched_id = normalizeRef(doc);
    if(!fetched_id.has_value() || *fetched_id != object_uri) return false;
    if(auto parent = normalizeRef(doc.contains("inReplyTo")
            ? doc["inReplyTo"] : nlohmann::json());
       parent.has_value())
    {
        return referencesKnownOwnedObject(config, data, *parent,
                                          config.thread_fetch_max_depth);
    }
    return false;
}

mw::E<void> maybeForwardIncomingActivity(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface* crypto, mw::HTTPSessionInterface* http,
    const SystemActor* system_actor, const Activity& activity,
    int64_t now_seconds)
{
    if(crypto == nullptr || http == nullptr || system_actor == nullptr)
        return {};

    std::vector<std::string> addressed;
    appendAll(addressed, activity.to);
    appendAll(addressed, activity.cc);
    std::set<std::string> forwarded_collections;
    for(const auto& address : addressed)
    {
        auto owner = followersCollectionOwner(config, address);
        if(!owner.has_value() || !isLocalActorUri(config, *owner)) continue;

        bool references_owned = false;
        for(const auto& ref : forwardingReferenceUris(activity))
        {
            ASSIGN_OR_RETURN(bool ok, referencesKnownOwnedObject(
                config, data, ref, config.thread_fetch_max_depth));
            if(ok)
            {
                references_owned = true;
                break;
            }
        }
        if(!references_owned) continue;

        bool verified_by_refetch = false;
        for(const auto& ref : forwardingReferenceUris(activity))
        {
            ASSIGN_OR_RETURN(bool ok, refetchedObjectReferencesOwnedObject(
                config, data, *crypto, *http, *system_actor, ref));
            if(ok)
            {
                verified_by_refetch = true;
                break;
            }
        }
        if(!verified_by_refetch) continue;
        if(!forwarded_collections.insert(address).second) continue;

        std::vector<PostRecipient> recipients = {
            {0, address, "to"},
        };
        ASSIGN_OR_RETURN(auto jobs, enqueueOutboundDelivery(
            config, data, *owner, activity.raw, recipients, now_seconds));
        (void)jobs;
    }
    return {};
}

bool addressesContainPublic(const std::vector<std::string>& addresses)
{
    for(const auto& uri : addresses)
        if(isPublicAddress(uri)) return true;
    return false;
}

bool addressesContainFollowersCollection(
    const std::vector<std::string>& addresses)
{
    for(const auto& uri : addresses)
    {
        if(uri.ends_with("/followers")) return true;
    }
    return false;
}

Visibility visibilityForActivityObject(const nlohmann::json& object)
{
    std::vector<std::string> to = normalizeAddressing(
        object.value("to", nlohmann::json()));
    std::vector<std::string> cc = normalizeAddressing(
        object.value("cc", nlohmann::json()));
    if(addressesContainPublic(to)) return Visibility::PUBLIC;
    if(addressesContainPublic(cc)) return Visibility::UNLISTED;
    if(!addressesContainFollowersCollection(to)
       && !addressesContainFollowersCollection(cc))
    {
        return Visibility::DIRECT;
    }
    return Visibility::FOLLOWERS;
}

std::vector<PostRecipient> recipientsForObject(const nlohmann::json& object)
{
    std::vector<PostRecipient> out;
    for(const auto& uri : normalizeAddressing(
            object.value("to", nlohmann::json())))
    {
        out.push_back(PostRecipient{0, uri, "to"});
    }
    for(const auto& uri : normalizeAddressing(
            object.value("cc", nlohmann::json())))
    {
        out.push_back(PostRecipient{0, uri, "cc"});
    }
    return out;
}

std::map<std::string, EmojiInfo> emojiTagsForObject(
    const nlohmann::json& object)
{
    std::map<std::string, EmojiInfo> out;
    nlohmann::json tags = object.value("tag", nlohmann::json::array());
    if(tags.is_object()) tags = nlohmann::json::array({tags});
    if(!tags.is_array()) return out;

    for(const auto& tag : tags)
    {
        if(!tag.is_object() || tag.value("type", std::string()) != "Emoji")
            continue;
        std::string shortcode = tag.value("name", std::string());
        if(shortcode.size() >= 3 && shortcode.front() == ':'
           && shortcode.back() == ':')
        {
            shortcode = shortcode.substr(1, shortcode.size() - 2);
        }
        if(!isValidShortcode(shortcode)) continue;
        if(!tag.contains("icon") || !tag["icon"].is_object()) continue;
        const auto& icon = tag["icon"];
        if(!icon.contains("url") || !icon["url"].is_string()) continue;
        std::string url = icon["url"].get<std::string>();
        if(!url.starts_with("https://") && !url.starts_with("http://"))
            continue;

        EmojiInfo info;
        info.shortcode = shortcode;
        info.image_url = url;
        info.media_type = icon.value("mediaType", std::string("image/png"));
        out.emplace(shortcode, std::move(info));
    }
    return out;
}

std::string substituteRemoteEmoji(std::string_view html,
                                  const std::map<std::string, EmojiInfo>& emoji)
{
    std::string out;
    out.reserve(html.size());
    size_t pos = 0;
    while(pos < html.size())
    {
        size_t start = html.find(':', pos);
        if(start == std::string_view::npos)
        {
            out += html.substr(pos);
            break;
        }
        out += html.substr(pos, start - pos);
        size_t end = html.find(':', start + 1);
        if(end == std::string_view::npos)
        {
            out += html.substr(start);
            break;
        }
        std::string shortcode(html.substr(start + 1, end - start - 1));
        auto it = emoji.find(shortcode);
        if(isValidShortcode(shortcode) && it != emoji.end())
        {
            out += std::format(
                "<img class=\"emoji\" src=\"{}\" alt=\":{}:\" "
                "title=\":{}:\">",
                mw::escapeHTML(it->second.image_url), shortcode, shortcode);
        }
        else
        {
            out += html.substr(start, end - start + 1);
        }
        pos = end + 1;
    }
    return out;
}

std::string tagPageUrl(const Config& config, std::string_view tag)
{
    std::string out;
    out.reserve(tag.size());
    for(char c : tag)
    {
        out.push_back(static_cast<char>(std::tolower(
            static_cast<unsigned char>(c))));
    }
    return config.url_root + "tags/" + out;
}

nlohmann::json tagsForPostSource(const Config& config,
                                 const std::vector<PostRecipient>& recipients,
                                 std::string_view source,
                                 const EmojiRegistry* emoji)
{
    if(source.empty()) return nlohmann::json::array();

    std::set<std::string> addressed;
    for(const auto& recipient : recipients)
        addressed.insert(recipient.recipient_uri);

    EmojiRegistry empty_emoji;
    RenderedPostContent parsed = parsePostContent(std::string(source),
                                                  empty_emoji);
    nlohmann::json tags = nlohmann::json::array();
    for(const auto& mention : parsed.mentions)
    {
        std::string href;
        if(mention.domain.empty() || mention.domain == config.public_domain)
        {
            href = config.url_root + "u/" + mention.username;
        }
        else
        {
            std::optional<std::string> alias_href;
            bool alias_ambiguous = false;
            for(const auto& recipient : addressed)
            {
                auto url_e = mw::URL::fromStr(recipient);
                if(!url_e.has_value()) continue;
                const mw::URL& url = *url_e;
                std::string path = url.path();
                bool username_match = path.ends_with(
                    "/" + mention.username)
                    || path.ends_with("/@" + mention.username);
                if(!username_match) continue;
                if(url.host() == mention.domain)
                {
                    href = recipient;
                    break;
                }
                if(alias_href.has_value())
                {
                    alias_ambiguous = true;
                }
                else
                {
                    alias_href = recipient;
                }
            }
            if(href.empty() && alias_href.has_value() && !alias_ambiguous)
                href = *alias_href;
        }
        if(href.empty()) continue;
        if(!addressed.contains(href)) continue;
        tags.push_back({
            {"type", "Mention"},
            {"href", href},
            {"name", mention.name},
        });
    }
    for(const auto& hashtag : parsed.hashtags)
    {
        tags.push_back({
            {"type", "Hashtag"},
            {"href", tagPageUrl(config, hashtag.tag)},
            {"name", hashtag.name},
        });
    }
    if(emoji != nullptr)
    {
        size_t pos = 0;
        std::set<std::string> seen_emoji;
        while(pos < source.size())
        {
            size_t start = source.find(':', pos);
            if(start == std::string_view::npos) break;
            size_t end = source.find(':', start + 1);
            if(end == std::string_view::npos) break;
            std::string shortcode(source.substr(start + 1,
                                                end - start - 1));
            pos = end + 1;
            if(!isValidShortcode(shortcode)) continue;
            auto info = emoji->lookup(shortcode);
            if(!info.has_value()) continue;
            if(!seen_emoji.insert(shortcode).second) continue;
            tags.push_back({
                {"type", "Emoji"},
                {"id", config.url_root + "emoji/" + shortcode},
                {"name", ":" + shortcode + ":"},
                {"icon", {
                    {"type", "Image"},
                    {"mediaType", info->media_type},
                    {"url", info->image_url},
                }},
            });
        }
    }
    return tags;
}

mw::E<void> storeRemoteAttachments(const DataSourceInterface& data,
                                   const nlohmann::json& object,
                                   int64_t post_id)
{
    nlohmann::json attachments = object.value("attachment",
                                              nlohmann::json::array());
    if(attachments.is_object()) attachments = nlohmann::json::array(
        {attachments});
    if(!attachments.is_array()) return {};

    for(const auto& item : attachments)
    {
        if(!item.is_object()) continue;
        auto url = normalizeRef(item.contains("url") ? item["url"]
                                                     : nlohmann::json());
        if(!url.has_value()) continue;
        Attachment a;
        a.post_id = post_id;
        a.sha256 = "";
        a.media_type = item.value("mediaType", std::string());
        a.original_name = item.value("name", *url);
        a.sensitive = boolField(object, "sensitive")
            || boolField(item, "sensitive");
        a.remote_url = *url;
        std::string type = item.value("type", std::string());
        a.is_image = type == "Image" || a.media_type.starts_with("image/");
        DO_OR_RETURN(data.insertAttachment(a));
    }
    return {};
}

mw::E<NewPost> remoteNotePostFromActivity(
    const DataSourceInterface& data, const Activity& activity)
{
    auto uri = normalizeRef(activity.object);
    if(!uri.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Remote Note is missing id"));
    }

    auto attributed_to = normalizeRef(
        activity.object.contains("attributedTo")
            ? activity.object["attributedTo"] : nlohmann::json());
    std::string author_uri = attributed_to.value_or(activity.actor);
    std::optional<int64_t> remote_author_id;
    ASSIGN_OR_RETURN(auto remote_author, data.getRemoteActorByUri(author_uri));
    if(remote_author.has_value()) remote_author_id = remote_author->id;

    NewPost np;
    np.uri = *uri;
    np.remote_author_id = remote_author_id;
    auto remote_emoji = emojiTagsForObject(activity.object);
    np.content_html = substituteRemoteEmoji(
        sanitizeRemoteHtml(activity.object.value("content", std::string())),
        remote_emoji);
    np.summary = activity.object.contains("summary")
        && activity.object["summary"].is_string()
        ? std::optional<std::string>(sanitizeRemoteHtml(
              activity.object["summary"].get<std::string>()))
        : std::nullopt;
    np.sensitive = boolField(activity.object, "sensitive");
    np.visibility = visibilityForActivityObject(activity.object);
    np.in_reply_to_uri = normalizeRef(
        activity.object.contains("inReplyTo")
            ? activity.object["inReplyTo"] : nlohmann::json());
    if(activity.object.contains("published")
       && activity.object["published"].is_string())
    {
        np.published = activity.object["published"].get<std::string>();
    }
    return np;
}

mw::E<void> handleCreateActivity(const Config& config,
                                 const DataSourceInterface& data,
                                 const Activity& activity)
{
    if(!activity.object.is_object()
       || activity.object.value("type", std::string()) != "Note")
    {
        return {};
    }
    auto uri = normalizeRef(activity.object);
    if(!uri.has_value()) return {};
    ASSIGN_OR_RETURN(auto existing, data.getPostByUri(*uri));
    if(existing.has_value()) return {};
    ASSIGN_OR_RETURN(auto np, remoteNotePostFromActivity(data, activity));
    ASSIGN_OR_RETURN(auto post, data.insertPost(
        np, recipientsForObject(activity.object), config.url_root + "p/"));
    return storeRemoteAttachments(data, activity.object, post.id);
}

mw::E<void> handleFollowActivity(const Config& config,
                                 const DataSourceInterface& data,
                                 const Activity& activity,
                                 int64_t now_seconds)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return {};
    auto username = localUsernameForActor(config, *object_uri);
    if(!username.has_value()) return {};
    ASSIGN_OR_RETURN(auto local_user, data.getUserByUsername(*username));
    if(!local_user.has_value()) return {};

    Follow follow;
    follow.follower_uri = activity.actor;
    follow.followee_uri = *object_uri;
    follow.state = FollowState::ACCEPTED;
    follow.follow_activity_uri = activity.id;
    follow.created_at = now_seconds;
    DO_OR_RETURN(data.addFollow(follow));
    ASSIGN_OR_RETURN(auto stored_follow, data.getFollow(
        activity.actor, *object_uri));
    int64_t follow_id = stored_follow.has_value() ? stored_follow->id : 0;

    nlohmann::json accept = {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", std::format("{}activities/accept/{}/{}", config.url_root,
                           follow_id, now_seconds)},
        {"type", "Accept"},
        {"actor", *object_uri},
        {"object", activity.raw},
        {"to", nlohmann::json::array({activity.actor})},
    };
    std::vector<PostRecipient> recipients = {
        {0, activity.actor, "to"},
    };
    ASSIGN_OR_RETURN(auto jobs, enqueueOutboundDelivery(
        config, data, *object_uri, accept, recipients, now_seconds));
    (void)jobs;
    return {};
}

mw::E<void> handleAcceptActivity(const DataSourceInterface& data,
                                 const Activity& activity)
{
    if(!activity.object.is_object()) return {};
    auto follower = normalizeRef(
        activity.object.contains("actor") ? activity.object["actor"]
                                          : nlohmann::json());
    auto followee = normalizeRef(
        activity.object.contains("object") ? activity.object["object"]
                                           : nlohmann::json());
    if(!follower.has_value() || !followee.has_value()) return {};
    return data.setFollowState(*follower, *followee, FollowState::ACCEPTED);
}

mw::E<void> handleLikeActivity(const DataSourceInterface& data,
                               const Activity& activity,
                               int64_t now_seconds)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return {};
    ASSIGN_OR_RETURN(auto post, data.getPostByUri(*object_uri));
    if(!post.has_value()) return {};
    Like like;
    like.actor_uri = activity.actor;
    like.post_uri = *object_uri;
    like.activity_uri = activity.id;
    like.created_at = now_seconds;
    return data.addLike(like);
}

mw::E<void> handleAnnounceActivity(const DataSourceInterface& data,
                                   const Activity& activity,
                                   int64_t now_seconds)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return {};
    ASSIGN_OR_RETURN(auto post, data.getPostByUri(*object_uri));
    if(!post.has_value()) return {};
    if(post->visibility != Visibility::PUBLIC
       && post->visibility != Visibility::UNLISTED)
    {
        return {};
    }
    Boost boost;
    boost.actor_uri = activity.actor;
    boost.post_uri = *object_uri;
    boost.activity_uri = activity.id;
    boost.created_at = now_seconds;
    return data.addBoost(boost);
}

mw::E<void> handleEmojiReactActivity(const DataSourceInterface& data,
                                     const Activity& activity,
                                     int64_t now_seconds)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return {};
    ASSIGN_OR_RETURN(auto post, data.getPostByUri(*object_uri));
    if(!post.has_value()) return {};
    std::string emoji = activity.raw.value("content", std::string());
    if(emoji.empty()) emoji = activity.raw.value("name", std::string());
    if(emoji.empty()) return {};
    Reaction reaction;
    reaction.actor_uri = activity.actor;
    reaction.post_uri = *object_uri;
    reaction.emoji = emoji;
    if(emoji.size() >= 3 && emoji.front() == ':' && emoji.back() == ':')
    {
        std::string shortcode = emoji.substr(1, emoji.size() - 2);
        auto remote_emoji = emojiTagsForObject(activity.raw);
        auto it = remote_emoji.find(shortcode);
        if(it != remote_emoji.end())
        {
            reaction.remote_emoji_url = it->second.image_url;
            reaction.remote_emoji_media_type = it->second.media_type;
        }
    }
    reaction.activity_uri = activity.id;
    reaction.created_at = now_seconds;
    return data.addReaction(reaction);
}

mw::E<void> handleDeleteActivity(const DataSourceInterface& data,
                                 const Activity& activity)
{
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return {};
    ASSIGN_OR_RETURN(auto post, data.getPostByUri(*object_uri));
    if(!post.has_value()) return {};
    return data.deletePost(post->id);
}

mw::E<void> handleUpdateActivity(const DataSourceInterface& data,
                                 const Activity& activity,
                                 int64_t now_seconds)
{
    if(!activity.object.is_object())
    {
        return {};
    }
    std::string type = activity.object.value("type", std::string());
    if(type != "Note")
    {
        auto actor_uri = normalizeRef(activity.object);
        if(!actor_uri.has_value() || *actor_uri != activity.actor)
            return {};
        ASSIGN_OR_RETURN(auto existing, data.getRemoteActorByUri(*actor_uri));
        if(!existing.has_value()) return {};

        RemoteActor updated = *existing;
        updated.username = activity.object.value("preferredUsername",
                                                 updated.username);
        if(updated.username.empty()) updated.username = updated.domain;
        updated.display_name = activity.object.value("name",
                                                     updated.display_name);
        if(activity.object.contains("inbox")
           && activity.object["inbox"].is_string())
        {
            updated.inbox = activity.object["inbox"].get<std::string>();
        }
        if(activity.object.contains("endpoints")
           && activity.object["endpoints"].is_object()
           && activity.object["endpoints"].contains("sharedInbox")
           && activity.object["endpoints"]["sharedInbox"].is_string())
        {
            updated.shared_inbox =
                activity.object["endpoints"]["sharedInbox"].get<std::string>();
        }
        if(activity.object.contains("publicKey")
           && activity.object["publicKey"].is_object())
        {
            const auto& key = activity.object["publicKey"];
            if(key.contains("id") && key["id"].is_string())
                updated.public_key_id = key["id"].get<std::string>();
            if(key.contains("publicKeyPem")
               && key["publicKeyPem"].is_string())
            {
                updated.public_key_pem =
                    key["publicKeyPem"].get<std::string>();
            }
        }
        updated.actor_json = activity.object.dump();
        updated.fetched_at = now_seconds;
        ASSIGN_OR_RETURN(auto stored, data.upsertRemoteActor(updated));
        (void)stored;
        return {};
    }
    auto object_uri = normalizeRef(activity.object);
    if(!object_uri.has_value()) return {};
    ASSIGN_OR_RETURN(auto existing, data.getPostByUri(*object_uri));
    if(!existing.has_value()) return {};
    ASSIGN_OR_RETURN(auto np, remoteNotePostFromActivity(data, activity));
    DO_OR_RETURN(data.updatePost(
        existing->id, np, recipientsForObject(activity.object)));
    return storeRemoteAttachments(data, activity.object, existing->id);
}

mw::E<void> handleUndoActivity(const DataSourceInterface& data,
                               const Activity& activity)
{
    if(!activity.object.is_object()) return {};
    Activity wrapped;
    ASSIGN_OR_RETURN(wrapped, parseActivity(activity.object));
    auto object_uri = normalizeRef(wrapped.object);
    if(wrapped.type == "Follow" && object_uri.has_value())
    {
        return data.removeFollow(wrapped.actor, *object_uri);
    }
    if(wrapped.type == "Like" && object_uri.has_value())
    {
        return data.removeLike(wrapped.actor, *object_uri);
    }
    if(wrapped.type == "Announce" && object_uri.has_value())
    {
        return data.removeBoost(wrapped.actor, *object_uri);
    }
    if(wrapped.type == "EmojiReact" && object_uri.has_value())
    {
        std::string emoji = wrapped.raw.value("content", std::string());
        if(emoji.empty()) emoji = wrapped.raw.value("name", std::string());
        if(!emoji.empty())
            return data.removeReaction(wrapped.actor, *object_uri, emoji);
    }
    return {};
}

} // namespace

std::vector<std::string> normalizeAddressing(const nlohmann::json& field)
{
    std::vector<std::string> out;
    if(field.is_null()) return out;
    if(field.is_array())
    {
        for(const auto& item : field)
        {
            if(auto ref = normalizeRef(item); ref.has_value())
                out.push_back(*ref);
        }
        return out;
    }
    if(auto ref = normalizeRef(field); ref.has_value()) out.push_back(*ref);
    return out;
}

std::optional<std::string> normalizeRef(const nlohmann::json& field)
{
    if(field.is_string()) return field.get<std::string>();
    if(field.is_object() && field.contains("id") && field["id"].is_string())
    {
        return field["id"].get<std::string>();
    }
    return std::nullopt;
}

mw::E<Activity> parseActivity(const nlohmann::json& raw)
{
    if(!raw.is_object())
    {
        return std::unexpected(mw::httpError(
            400, "Activity must be an object"));
    }
    auto id = normalizeRef(raw.contains("id") ? raw["id"] : nlohmann::json());
    auto actor = normalizeRef(raw.contains("actor") ? raw["actor"]
                                                    : nlohmann::json());
    if(!id.has_value() || !raw.contains("type") || !raw["type"].is_string()
       || !actor.has_value())
    {
        return std::unexpected(mw::httpError(
            400,
            "Activity is missing id, type, or actor"));
    }

    Activity activity;
    activity.id = *id;
    activity.type = raw["type"].get<std::string>();
    activity.actor = *actor;
    activity.object = raw.contains("object") ? raw["object"] : nlohmann::json();
    appendAll(activity.to,
              normalizeAddressing(raw.value("to", nlohmann::json())));
    appendAll(activity.to,
              normalizeAddressing(raw.value("bto", nlohmann::json())));
    appendAll(activity.to,
              normalizeAddressing(raw.value("audience", nlohmann::json())));
    appendAll(activity.cc,
              normalizeAddressing(raw.value("cc", nlohmann::json())));
    appendAll(activity.cc,
              normalizeAddressing(raw.value("bcc", nlohmann::json())));
    activity.raw = raw;
    return activity;
}

bool isPublicAddress(std::string_view uri)
{
    return uri == AS_PUBLIC || uri == "as:Public" || uri == "Public";
}

bool wantsActivityJson(std::string_view accept)
{
    return accept.find("application/activity+json") != std::string_view::npos
        || accept.find("application/ld+json") != std::string_view::npos;
}

nlohmann::json actorJson(const Config& config, const User& user,
                         std::string_view summary_html)
{
    return actorJson(config, user, summary_html, std::nullopt, std::nullopt,
                     {});
}

nlohmann::json actorJson(
    const Config& config, const User& user, std::string_view summary_html,
    const std::optional<Attachment>& avatar,
    const std::optional<Attachment>& banner,
    const std::vector<RenderedProfileField>& fields)
{
    std::string actor = config.url_root + "u/" + user.username;
    nlohmann::json j;
    j["@context"] = activityContext();
    j["type"] = "Person";
    j["id"] = actor;
    j["preferredUsername"] = user.username;
    j["name"] = user.display_name.empty() ? user.username : user.display_name;
    j["summary"] = std::string(summary_html);
    j["inbox"] = actor + "/inbox";
    j["outbox"] = actor + "/outbox";
    j["followers"] = actor + "/followers";
    j["following"] = actor + "/following";
    j["endpoints"] = {{"sharedInbox", config.url_root + "inbox"}};
    j["publicKey"] = {
        {"id", actor + "#main-key"},
        {"owner", actor},
        {"publicKeyPem", user.public_key_pem},
    };
    if(auto image = actorImageJson(config, avatar); image.has_value())
    {
        j["icon"] = *image;
    }
    if(auto image = actorImageJson(config, banner); image.has_value())
    {
        j["image"] = *image;
    }
    nlohmann::json attachment = nlohmann::json::array();
    for(const auto& field : fields)
    {
        if(field.label.empty() || field.value_html.empty()) continue;
        attachment.push_back({
            {"type", "PropertyValue"},
            {"name", field.label},
            {"value", field.value_html},
        });
    }
    if(!attachment.empty()) j["attachment"] = std::move(attachment);
    return j;
}

nlohmann::json systemActorJson(const Config& config,
                               std::string_view public_key_pem)
{
    std::string actor = config.url_root + "actor";
    nlohmann::json j;
    j["@context"] = activityContext();
    j["type"] = "Application";
    j["id"] = actor;
    j["preferredUsername"] = "unspoken";
    j["name"] = "unspoken";
    j["inbox"] = config.url_root + "inbox";
    j["endpoints"] = {{"sharedInbox", config.url_root + "inbox"}};
    j["publicKey"] = {
        {"id", actor + "#main-key"},
        {"owner", actor},
        {"publicKeyPem", std::string(public_key_pem)},
    };
    return j;
}

nlohmann::json noteJson(const Config& config, const Post& post,
                        const User& author,
                        const std::vector<PostRecipient>& recipients,
                        const std::vector<Attachment>& attachments,
                        const EmojiRegistry* emoji)
{
    nlohmann::json to = nlohmann::json::array();
    nlohmann::json cc = nlohmann::json::array();
    for(const auto& r : recipients)
    {
        if(r.field == "to") to.push_back(r.recipient_uri);
        if(r.field == "cc") cc.push_back(r.recipient_uri);
    }

    nlohmann::json attachment_arr = nlohmann::json::array();
    for(const auto& a : attachments)
    {
        std::string url;
        if(a.remote_url.has_value())
        {
            url = *a.remote_url;
        }
        else
        {
            url = localAttachmentUrl(config, a);
        }
        attachment_arr.push_back({
            {"type", a.is_image ? "Image" : "Document"},
            {"mediaType", a.media_type},
            {"url", url},
            {"name", a.original_name},
        });
    }

    nlohmann::json j;
    j["@context"] = "https://www.w3.org/ns/activitystreams";
    j["type"] = "Note";
    j["id"] = post.uri;
    j["url"] = post.uri;
    j["attributedTo"] = config.url_root + "u/" + author.username;
    j["content"] = post.content_html;
    j["to"] = to;
    j["cc"] = cc;
    j["sensitive"] = post.sensitive;
    j["published"] = post.published.value_or(isoTimestamp(post.created_at));
    if(post.summary.has_value()) j["summary"] = *post.summary;
    if(post.in_reply_to_uri.has_value()) j["inReplyTo"] = *post.in_reply_to_uri;
    if(!attachment_arr.empty()) j["attachment"] = attachment_arr;
    if(post.content_source.has_value())
    {
        nlohmann::json tags = tagsForPostSource(config, recipients,
                                                *post.content_source, emoji);
        if(!tags.empty()) j["tag"] = tags;
    }
    return j;
}

nlohmann::json deleteActivityJson(
    std::string_view activity_id, std::string_view actor_uri,
    std::string_view object_uri, const std::vector<PostRecipient>& recipients)
{
    nlohmann::json to = nlohmann::json::array();
    nlohmann::json cc = nlohmann::json::array();
    for(const auto& r : recipients)
    {
        if(r.field == "to") to.push_back(r.recipient_uri);
        if(r.field == "cc") cc.push_back(r.recipient_uri);
    }
    return {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", std::string(activity_id)},
        {"type", "Delete"},
        {"actor", std::string(actor_uri)},
        {"object", std::string(object_uri)},
        {"to", to},
        {"cc", cc},
    };
}

nlohmann::json actorUpdateActivityJson(
    const Config& config, std::string_view activity_id, const User& user,
    std::string_view summary_html,
    const std::vector<PostRecipient>& recipients)
{
    return actorUpdateActivityJson(config, activity_id, user, summary_html,
                                   std::nullopt, std::nullopt, {},
                                   recipients);
}

nlohmann::json actorUpdateActivityJson(
    const Config& config, std::string_view activity_id, const User& user,
    std::string_view summary_html, const std::optional<Attachment>& avatar,
    const std::optional<Attachment>& banner,
    const std::vector<RenderedProfileField>& fields,
    const std::vector<PostRecipient>& recipients)
{
    nlohmann::json to = nlohmann::json::array();
    nlohmann::json cc = nlohmann::json::array();
    for(const auto& r : recipients)
    {
        if(r.field == "to") to.push_back(r.recipient_uri);
        if(r.field == "cc") cc.push_back(r.recipient_uri);
    }
    std::string actor_uri = config.url_root + "u/" + user.username;
    return {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", std::string(activity_id)},
        {"type", "Update"},
        {"actor", actor_uri},
        {"object", actorJson(config, user, summary_html, avatar, banner,
                             fields)},
        {"to", to},
        {"cc", cc},
    };
}

nlohmann::json emojiReactActivityJson(
    const Config& config, std::string_view activity_id,
    std::string_view actor_uri, std::string_view object_uri,
    std::string_view emoji_str, const std::vector<PostRecipient>& recipients,
    const EmojiRegistry& emoji_registry)
{
    nlohmann::json to = nlohmann::json::array();
    nlohmann::json cc = nlohmann::json::array();
    for(const auto& r : recipients)
    {
        if(r.field == "to") to.push_back(r.recipient_uri);
        if(r.field == "cc") cc.push_back(r.recipient_uri);
    }

    nlohmann::json j = {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", std::string(activity_id)},
        {"type", "EmojiReact"},
        {"actor", std::string(actor_uri)},
        {"object", std::string(object_uri)},
        {"content", std::string(emoji_str)},
        {"to", to},
        {"cc", cc},
    };

    if(emoji_str.size() >= 3 && emoji_str.front() == ':'
       && emoji_str.back() == ':')
    {
        std::string shortcode(emoji_str.substr(1, emoji_str.size() - 2));
        if(auto info = emoji_registry.lookup(shortcode); info.has_value())
        {
            j["tag"] = nlohmann::json::array({
                {
                    {"type", "Emoji"},
                    {"id", config.url_root + "emoji/" + shortcode},
                    {"name", std::string(emoji_str)},
                    {"icon", {
                        {"type", "Image"},
                        {"mediaType", info->media_type},
                        {"url", info->image_url},
                    }},
                },
            });
        }
    }
    return j;
}

nlohmann::json webFingerJson(const Config& config, const User& user)
{
    std::string actor = config.url_root + "u/" + user.username;
    return {
        {"subject", std::format("acct:{}@{}", user.username,
                                config.public_domain)},
        {"aliases", nlohmann::json::array({actor})},
        {"links", nlohmann::json::array({
            {
                {"rel", "self"},
                {"type", "application/activity+json"},
                {"href", actor},
            },
        })},
    };
}

std::string hostMetaXml(const Config& config)
{
    std::string webfinger = config.url_root
        + ".well-known/webfinger?resource={uri}";
    return std::format(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<XRD xmlns=\"http://docs.oasis-open.org/ns/xri/xrd-1.0\">\n"
        "  <Link rel=\"lrdd\" type=\"application/xrd+xml\" "
        "template=\"{}\" />\n"
        "</XRD>\n",
        webfinger);
}

nlohmann::json nodeInfoDiscoveryJson(const Config& config)
{
    return {
        {"links", nlohmann::json::array({
            {
                {"rel", "http://nodeinfo.diaspora.software/ns/schema/2.1"},
                {"href", config.url_root + "nodeinfo/2.1"},
            },
        })},
    };
}

nlohmann::json nodeInfoJson(const Config& config)
{
    return nodeInfoJson(config, 0, 0);
}

nlohmann::json nodeInfoJson(const Config& config, int64_t user_count,
                            int64_t local_post_count)
{
    return {
        {"version", "2.1"},
        {"software", {
            {"name", config.nodeinfo.software_name},
            {"version", "0.1.0"},
        }},
        {"protocols", nlohmann::json::array({"activitypub"})},
        {"services", {
            {"inbound", nlohmann::json::array()},
            {"outbound", nlohmann::json::array()},
        }},
        {"openRegistrations", config.nodeinfo.open_registrations},
        {"usage", {
            {"users", {
                {"total", user_count},
                {"activeHalfyear", 0},
                {"activeMonth", 0},
            }},
            {"localPosts", local_post_count},
        }},
        {"metadata", {
            {"nodeDescription", config.nodeinfo.description},
        }},
    };
}

mw::E<nlohmann::json> nodeInfoJson(const Config& config,
                                   const DataSourceInterface& data)
{
    ASSIGN_OR_RETURN(auto user_count, data.countUsers());
    ASSIGN_OR_RETURN(auto local_post_count, data.countLocalPosts());
    return nodeInfoJson(config, user_count, local_post_count);
}

bool isAllowedOutboundAddress(const mw::SockAddr& addr)
{
    const auto& a = addr.address;
    if(addr.family == mw::AddressFamily::IPV4)
    {
        if(a.size() != 4) return false;
        if(ipv4In(a, 10) || ipv4In(a, 127) || ipv4In(a, 169, 254)
           || ipv4In(a, 192, 168))
        {
            return false;
        }
        if(a[0] == 172 && a[1] >= 16 && a[1] <= 31) return false;
        // Carrier-grade NAT, localhost-ish zero net, multicast/reserved.
        if(a[0] == 100 && a[1] >= 64 && a[1] <= 127) return false;
        if(a[0] == 0 || a[0] >= 224) return false;
        return true;
    }

    if(addr.family == mw::AddressFamily::IPV6)
    {
        if(a.size() != 16) return false;
        if(ipv6AllZeroUntilLast(a, 1)) return false; // ::1
        if((a[0] & 0xfe) == 0xfc) return false;      // fc00::/7 ULA
        if(a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return false; // fe80::/10
        if(a[0] == 0xff) return false;               // multicast
        return true;
    }
    return false;
}

bool isValidRemoteUrl(const DevConfig& dev, std::string_view value)
{
    auto parsed = mw::URL::fromStr(std::string(value));
    if(!parsed.has_value() || parsed->host().empty()) return false;
    if(parsed->scheme() == "https") return true;
    return dev.allow_http_url_root && parsed->scheme() == "http"
        && hostMatches(parsed->host(), dev.outbound_allow_private_hosts);
}

mw::E<void> hardenOutboundSession(mw::HTTPSessionInterface& http)
{
    DO_OR_RETURN(http.allowedProtocols("https"));
    DO_OR_RETURN(http.allowedRedirectProtocols("https"));
    DO_OR_RETURN(http.maxRedirections(5));
    http.followRedirects(true);
    http.addressFilter([](const mw::SockAddr& addr)
    {
        return isAllowedOutboundAddress(addr);
    });
    return {};
}

mw::E<void> hardenOutboundSession(const Config& config,
                                  mw::HTTPSessionInterface& http,
                                  std::string_view target_url)
{
    auto parsed = mw::URL::fromStr(std::string(target_url));
    if(!parsed.has_value() || parsed->host().empty())
    {
        return std::unexpected(mw::runtimeError(
            "Outbound federation URL must be absolute"));
    }

    bool dev_private_host = config.dev.allow_http_url_root
        && hostMatches(parsed->host(),
                       config.dev.outbound_allow_private_hosts);
    if(dev_private_host)
    {
        DO_OR_RETURN(http.allowedProtocols("http,https"));
        DO_OR_RETURN(http.allowedRedirectProtocols("http,https"));
        DO_OR_RETURN(http.maxRedirections(0));
        http.followRedirects(false);
        std::string host = parsed->host();
        http.addressFilter([host](const mw::SockAddr& addr)
        {
            spdlog::warn("Development private outbound host {} resolved to {}",
                         host, addressForLog(addr));
            return !isMetadataAddress(addr);
        });
        return {};
    }

    return hardenOutboundSession(http);
}

mw::E<mw::HTTPRequest> signedGetRequest(const Config& config,
                                        const SystemActor& system_actor,
                                        mw::CryptoInterface& crypto,
                                        std::string_view uri)
{
    return signedHttpRequest(config, crypto,
                             signingActorForSystem(config, system_actor),
                             "GET", uri);
}

mw::E<mw::HTTPRequest> webFingerRequest(const Config& config,
                                        std::string_view uri)
{
    auto parsed = mw::URL::fromStr(std::string(uri));
    bool dev_http = config.dev.allow_http_url_root
        && parsed.has_value()
        && hostMatches(parsed->host(),
                       config.dev.outbound_allow_private_hosts);
    if(!parsed.has_value() || parsed->host().empty()
       || (parsed->scheme() != "https"
           && !(dev_http && parsed->scheme() == "http")))
    {
        return std::unexpected(mw::runtimeError(
            "Outbound WebFinger URL must be absolute https"));
    }

    mw::HTTPRequest req{std::string(uri)};
    req.addHeader("Accept", "application/jrd+json, application/json");
    return req;
}

SigningActor signingActorFor(const Config& config, const User& user)
{
    std::string actor = config.url_root + "u/" + user.username;
    return SigningActor{
        actor,
        actor + "#main-key",
        user.private_key_pem,
    };
}

SigningActor signingActorForSystem(const Config& config,
                                   const SystemActor& system_actor)
{
    return SigningActor{
        config.url_root + "actor",
        config.url_root + "actor#main-key",
        system_actor.private_key_pem,
    };
}

mw::E<mw::HTTPRequest> signedHttpRequest(
    const Config& config, mw::CryptoInterface& crypto,
    const SigningActor& actor,
    std::string_view method, std::string_view uri, std::string_view body,
    std::string_view content_type)
{
    auto parsed = mw::URL::fromStr(std::string(uri));
    bool dev_http = config.dev.allow_http_url_root
        && parsed.has_value()
        && hostMatches(parsed->host(),
                       config.dev.outbound_allow_private_hosts);
    if(!parsed.has_value() || parsed->host().empty()
       || (parsed->scheme() != "https"
           && !(dev_http && parsed->scheme() == "http")))
    {
        return std::unexpected(mw::runtimeError(
            "Outbound federation fetch URL must be absolute https"));
    }

    std::string date = httpDate();
    std::string target = requestTarget(*parsed);
    std::string host = requestAuthority(*parsed);
    std::string method_lower = lower(method);
    std::string signed_headers = "(request-target) host date";
    std::string signing_input = std::format(
        "(request-target): {} {}\nhost: {}\ndate: {}",
        method_lower, target, host, date);

    std::optional<std::string> digest;
    if(method_lower == "post" || method_lower == "put")
    {
        ASSIGN_OR_RETURN(auto d, digestHeaderFor(body));
        digest = d;
        signed_headers += " digest";
        signing_input += "\ndigest: " + *digest;
    }

    ASSIGN_OR_RETURN(auto sig, crypto.sign(
        mw::SignatureAlgorithm::RSA_V1_5_SHA256,
        actor.private_key_pem, signing_input));
    std::string sig64 = mw::base64Encode(
        std::span<unsigned char>(sig.data(), sig.size()), false, true);

    mw::HTTPRequest req{std::string(uri)};
    if(!body.empty()) req.setPayload(body);
    if(!content_type.empty()) req.setContentType(content_type);
    req.addHeader("Accept", "application/activity+json");
    req.addHeader("Host", host);
    req.addHeader("Date", date);
    if(digest.has_value()) req.addHeader("Digest", *digest);
    req.addHeader("Signature", std::format(
        R"(keyId="{}",algorithm="rsa-sha256",headers="{}",signature="{}")",
        actor.key_id, signed_headers, sig64));
    return req;
}

mw::E<RemoteActor> fetchRemoteActor(const Config& config,
                                    mw::CryptoInterface& crypto,
                                    mw::HTTPSessionInterface& http,
                                    const SystemActor& system_actor,
                                    std::string_view actor_uri)
{
    DO_OR_RETURN(hardenOutboundSession(config, http, actor_uri));
    ASSIGN_OR_RETURN(auto req, signedGetRequest(config, system_actor, crypto,
                                                actor_uri));
    ASSIGN_OR_RETURN(const mw::HTTPResponse* res, http.get(req));
    if(res->status < 200 || res->status >= 300)
    {
        return std::unexpected(mw::httpError(res->status,
                                             "Remote actor fetch failed"));
    }

    nlohmann::json doc = nlohmann::json::parse(res->payloadAsStr(),
                                               nullptr, false);
    if(!doc.is_object())
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor response is not JSON"));
    }
    if(doc.contains("id") && !doc["id"].is_string())
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor has invalid id"));
    }
    std::string id = doc.contains("id")
        ? doc["id"].get<std::string>() : std::string(actor_uri);
    if(id != actor_uri)
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor id does not match requested URI"));
    }
    if(!isValidRemoteUrl(config.dev, id))
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor has invalid id"));
    }
    if(!doc.contains("inbox") || !doc["inbox"].is_string()
       || !doc.contains("publicKey") || !doc["publicKey"].is_object())
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor is missing inbox or publicKey"));
    }
    std::string inbox = doc["inbox"].get<std::string>();
    if(!isValidRemoteUrl(config.dev, inbox))
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor has invalid inbox"));
    }
    const auto& public_key = doc["publicKey"];
    if(!public_key.contains("id") || !public_key["id"].is_string()
       || !public_key.contains("publicKeyPem")
       || !public_key["publicKeyPem"].is_string())
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor has incomplete publicKey"));
    }
    std::string public_key_id = public_key["id"].get<std::string>();
    std::string public_key_pem = public_key["publicKeyPem"].get<std::string>();
    if(public_key_id.empty() || public_key_pem.empty()
       || (public_key.contains("owner")
           && (!public_key["owner"].is_string()
               || public_key["owner"].get<std::string>() != id)))
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor has invalid publicKey"));
    }

    RemoteActor actor;
    actor.uri = id;
    if(doc.contains("preferredUsername")
       && !doc["preferredUsername"].is_string())
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor has invalid preferredUsername"));
    }
    if(doc.contains("name") && !doc["name"].is_string())
    {
        return std::unexpected(mw::runtimeError(
            "Remote actor has invalid name"));
    }
    actor.username = doc.contains("preferredUsername")
        ? doc["preferredUsername"].get<std::string>() : std::string();
    auto parsed_id = mw::URL::fromStr(id);
    if(actor.username.empty()) actor.username = parsed_id->host();
    actor.domain = parsed_id->host();
    actor.display_name = doc.contains("name")
        ? doc["name"].get<std::string>() : std::string();
    actor.inbox = std::move(inbox);
    if(doc.contains("endpoints") && doc["endpoints"].is_object()
       && doc["endpoints"].contains("sharedInbox"))
    {
        if(!doc["endpoints"]["sharedInbox"].is_string())
        {
            return std::unexpected(mw::runtimeError(
                "Remote actor has invalid sharedInbox"));
        }
        std::string shared_inbox = doc["endpoints"]["sharedInbox"]
            .get<std::string>();
        if(!isValidRemoteUrl(config.dev, shared_inbox))
        {
            return std::unexpected(mw::runtimeError(
                "Remote actor has invalid sharedInbox"));
        }
        actor.shared_inbox = std::move(shared_inbox);
    }
    actor.public_key_id = std::move(public_key_id);
    actor.public_key_pem = std::move(public_key_pem);
    actor.actor_json = doc.dump();
    actor.fetched_at = mw::timeToSeconds(mw::Clock::now());
    return actor;
}

mw::E<RemoteActorResolution> findOrFetchRemoteActor(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view actor_uri)
{
    ASSIGN_OR_RETURN(auto cached, data.getRemoteActorByUri(actor_uri));
    if(cached.has_value()) return RemoteActorResolution{*cached, true};

    ASSIGN_OR_RETURN(auto actor, fetchRemoteActor(
        config, crypto, http, system_actor, actor_uri));
    return RemoteActorResolution{std::move(actor), false};
}

mw::E<RemoteActor> ensureRemoteActorRetained(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view actor_uri,
    int64_t now_seconds)
{
    ASSIGN_OR_RETURN(auto resolution, findOrFetchRemoteActor(
        config, data, crypto, http, system_actor, actor_uri));
    if(resolution.retained) return resolution.actor;

    if(now_seconds > 0) resolution.actor.fetched_at = now_seconds;
    return data.upsertRemoteActor(resolution.actor);
}

mw::E<RemoteActor> resolveWebFingerActor(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view handle)
{
    auto parsed = parseHandle(handle);
    if(!parsed.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "WebFinger query must be a user@domain handle"));
    }
    const auto& [username, domain] = *parsed;
    if(domain == config.public_domain)
    {
        return std::unexpected(mw::runtimeError(
            "Local handles do not need WebFinger resolution"));
    }

    std::string acct = username + "@" + domain;
    std::string scheme = config.dev.allow_http_url_root
        && hostMatches(domain, config.dev.outbound_allow_private_hosts)
        ? "http" : "https";
    std::string uri = scheme + "://" + domain
        + "/.well-known/webfinger?resource="
        + percentEncode("acct:" + acct);

    DO_OR_RETURN(hardenOutboundSession(config, http, uri));
    ASSIGN_OR_RETURN(auto req, webFingerRequest(config, uri));
    ASSIGN_OR_RETURN(const mw::HTTPResponse* res, http.get(req));
    if(res->status < 200 || res->status >= 300)
    {
        return std::unexpected(mw::httpError(res->status,
                                             "WebFinger lookup failed"));
    }

    nlohmann::json doc = nlohmann::json::parse(res->payloadAsStr(),
                                               nullptr, false);
    if(!doc.is_object())
    {
        return std::unexpected(mw::runtimeError(
            "WebFinger response is not JSON"));
    }

    if(!doc.contains("links") || !doc["links"].is_array())
    {
        return std::unexpected(mw::runtimeError(
            "WebFinger response has no links"));
    }
    std::optional<std::string> actor_uri;
    for(const auto& link : doc["links"])
    {
        if(!link.is_object()) continue;
        if(link.value("rel", std::string()) != "self") continue;
        std::string type = link.value("type", std::string());
        if(type != "application/activity+json"
           && type != "application/ld+json")
        {
            continue;
        }
        if(link.contains("href") && link["href"].is_string())
        {
            actor_uri = link["href"].get<std::string>();
            break;
        }
    }
    if(!actor_uri.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "WebFinger response has no ActivityPub self link"));
    }
    ASSIGN_OR_RETURN(auto resolution, findOrFetchRemoteActor(
        config, data, crypto, http, system_actor, *actor_uri));
    return resolution.actor;
}

mw::E<Post> fetchRemotePostByUri(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view post_uri)
{
    ASSIGN_OR_RETURN(auto existing, data.getPostByUri(post_uri));
    if(existing.has_value()) return *existing;

    ASSIGN_OR_RETURN(auto doc, signedGetJson(config, crypto, http,
                                             system_actor, post_uri));
    Activity activity;
    std::string object_uri;

    if(doc.is_object() && doc.value("type", std::string()) == "Note")
    {
        auto id = normalizeRef(doc);
        if(!id.has_value())
        {
            return std::unexpected(mw::runtimeError(
                "Remote post is missing id"));
        }
        auto actor = normalizeRef(doc.contains("attributedTo")
            ? doc["attributedTo"] : nlohmann::json());
        object_uri = *id;
        activity.id = object_uri + "#fetch";
        activity.type = "Create";
        activity.actor = actor.value_or(std::string());
        activity.object = doc;
        activity.raw = {
            {"id", activity.id},
            {"type", "Create"},
            {"actor", activity.actor},
            {"object", doc},
        };
    }
    else if(doc.is_object() && doc.value("type", std::string()) == "Create"
            && doc.contains("object") && doc["object"].is_object()
            && doc["object"].value("type", std::string()) == "Note")
    {
        ASSIGN_OR_RETURN(activity, parseActivity(doc));
        auto id = normalizeRef(activity.object);
        if(!id.has_value())
        {
            return std::unexpected(mw::runtimeError(
                "Remote Create object is missing id"));
        }
        object_uri = *id;
    }
    else
    {
        return std::unexpected(mw::runtimeError(
            "Remote URL did not resolve to a post"));
    }

    if(activity.actor.empty())
    {
        return std::unexpected(mw::runtimeError(
            "Remote post is missing an actor"));
    }
    DO_OR_RETURN(ensureRemoteActorForObject(
        config, data, crypto, http, system_actor, activity.object,
        activity.actor));
    DO_OR_RETURN(handleCreateActivity(config, data, activity));

    ASSIGN_OR_RETURN(auto post, data.getPostByUri(object_uri));
    if(!post.has_value())
    {
        return std::unexpected(mw::runtimeError(
            "Remote post was not stored"));
    }
    return *post;
}

mw::E<VerifiedSignature> verifyHttpSignature(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, const IncomingHttpRequest& req,
    int64_t now_seconds)
{
    ASSIGN_OR_RETURN(auto signature, parseHttpSignature(
        config, req, now_seconds));
    ASSIGN_OR_RETURN(auto actor, data.getRemoteActorByUri(signature.actor_uri));
    if(!actor.has_value())
    {
        return std::unexpected(mw::httpError(401, "Unknown signature key"));
    }

    ASSIGN_OR_RETURN(bool ok, verifyParsedHttpSignature(
        crypto, signature, *actor));
    if(!ok)
    {
        return std::unexpected(mw::httpError(401, "Bad signature"));
    }
    return VerifiedSignature{
        signature.actor_uri,
        signature.key_id,
        *actor,
        true,
        false,
    };
}

mw::E<VerifiedSignature> verifyHttpSignatureWithKeyRefresh(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, const IncomingHttpRequest& req,
    int64_t now_seconds)
{
    ASSIGN_OR_RETURN(auto signature, parseHttpSignature(
        config, req, now_seconds));
    ASSIGN_OR_RETURN(auto cached, data.getRemoteActorByUri(
        signature.actor_uri));

    if(!cached.has_value())
    {
        auto fetched = fetchRemoteActor(config, crypto, http, system_actor,
                                        signature.actor_uri);
        if(!fetched.has_value() || fetched->public_key_id != signature.key_id)
        {
            return std::unexpected(mw::httpError(
                401, "Unknown signature key"));
        }
        ASSIGN_OR_RETURN(bool ok, verifyParsedHttpSignature(
            crypto, signature, *fetched));
        if(!ok)
        {
            return std::unexpected(mw::httpError(401, "Bad signature"));
        }
        return VerifiedSignature{
            signature.actor_uri,
            signature.key_id,
            std::move(*fetched),
            false,
            false,
        };
    }

    if(cached->public_key_id == signature.key_id)
    {
        ASSIGN_OR_RETURN(bool ok, verifyParsedHttpSignature(
            crypto, signature, *cached));
        if(ok)
        {
            return VerifiedSignature{
                signature.actor_uri,
                signature.key_id,
                *cached,
                true,
                false,
            };
        }
    }

    auto fetched = fetchRemoteActor(config, crypto, http, system_actor,
                                    signature.actor_uri);
    if(!fetched.has_value() || fetched->public_key_id != signature.key_id)
    {
        return std::unexpected(mw::httpError(401, "Bad signature"));
    }
    ASSIGN_OR_RETURN(bool ok, verifyParsedHttpSignature(
        crypto, signature, *fetched));
    if(!ok)
    {
        return std::unexpected(mw::httpError(401, "Bad signature"));
    }
    ASSIGN_OR_RETURN(auto retained, data.upsertRemoteActor(*fetched));
    return VerifiedSignature{
        signature.actor_uri,
        signature.key_id,
        std::move(retained),
        true,
        true,
    };
}

mw::E<int64_t> enqueueDeliveryJob(const DataSourceInterface& data,
                                  std::string_view target_inbox,
                                  std::string_view signer_actor_uri,
                                  const nlohmann::json& activity,
                                  int64_t now_seconds)
{
    if(target_inbox.empty() || signer_actor_uri.empty()
       || !activity.is_object())
    {
        return std::unexpected(mw::runtimeError(
            "Delivery job requires inbox, signer, and activity object"));
    }
    nlohmann::json payload = {
        {"target_inbox", std::string(target_inbox)},
        {"signer_actor", std::string(signer_actor_uri)},
        {"activity", activity},
    };
    return data.enqueueJob("deliver", payload.dump(), now_seconds,
                           now_seconds);
}

mw::E<std::vector<std::string>> deliveryInboxesForRecipients(
    const Config& config, const DataSourceInterface& data,
    const std::vector<PostRecipient>& recipients)
{
    std::set<std::string> inboxes;

    auto add_actor = [&](std::string_view actor_uri) -> mw::E<void> {
        if(actor_uri.empty() || isPublicAddress(actor_uri)
           || isLocalActorUri(config, actor_uri))
        {
            return {};
        }
        ASSIGN_OR_RETURN(auto actor, data.getRemoteActorByUri(actor_uri));
        if(!actor.has_value())
        {
            return std::unexpected(mw::runtimeError(std::format(
                "Remote delivery actor is not cached: {}", actor_uri)));
        }
        inboxes.insert(actor->shared_inbox.value_or(actor->inbox));
        return {};
    };

    for(const auto& r : recipients)
    {
        if(isPublicAddress(r.recipient_uri)) continue;
        if(auto owner = followersCollectionOwner(config, r.recipient_uri);
           owner.has_value())
        {
            ASSIGN_OR_RETURN(auto followers, data.followerUris(*owner));
            for(const auto& follower : followers)
            {
                DO_OR_RETURN(add_actor(follower));
            }
            continue;
        }
        DO_OR_RETURN(add_actor(r.recipient_uri));
    }

    return std::vector<std::string>(inboxes.begin(), inboxes.end());
}

mw::E<std::vector<int64_t>> enqueueOutboundDelivery(
    const Config& config, const DataSourceInterface& data,
    std::string_view signer_actor_uri, const nlohmann::json& activity,
    const std::vector<PostRecipient>& recipients, int64_t now_seconds)
{
    ASSIGN_OR_RETURN(auto inboxes, deliveryInboxesForRecipients(
        config, data, recipients));
    std::vector<int64_t> job_ids;
    job_ids.reserve(inboxes.size());
    for(const auto& inbox : inboxes)
    {
        ASSIGN_OR_RETURN(auto id, enqueueDeliveryJob(
            data, inbox, signer_actor_uri, activity, now_seconds));
        job_ids.push_back(id);
    }
    return job_ids;
}

mw::E<std::vector<int64_t>> enqueueActorUpdateDelivery(
    const Config& config, const DataSourceInterface& data, const User& user,
    std::string_view summary_html, int64_t now_seconds)
{
    return enqueueActorUpdateDelivery(config, data, user, summary_html,
                                      std::nullopt, std::nullopt, {},
                                      now_seconds);
}

mw::E<std::vector<int64_t>> enqueueActorUpdateDelivery(
    const Config& config, const DataSourceInterface& data, const User& user,
    std::string_view summary_html, const std::optional<Attachment>& avatar,
    const std::optional<Attachment>& banner,
    const std::vector<RenderedProfileField>& fields, int64_t now_seconds)
{
    std::string actor_uri = config.url_root + "u/" + user.username;
    std::vector<PostRecipient> recipients = {
        {0, actor_uri + "/followers", "to"},
    };
    nlohmann::json activity = actorUpdateActivityJson(
        config,
        std::format("{}activities/update/profile/{}/{}",
                    config.url_root, user.id, now_seconds),
        user, summary_html, avatar, banner, fields, recipients);
    return enqueueOutboundDelivery(
        config, data, actor_uri, activity, recipients, now_seconds);
}

mw::E<int64_t> enqueueFetchThreadJob(const DataSourceInterface& data,
                                     std::string_view root_uri,
                                     int64_t now_seconds)
{
    if(root_uri.empty())
    {
        return std::unexpected(mw::runtimeError(
            "Fetch-thread job requires a root URI"));
    }
    nlohmann::json payload = {
        {"root_uri", std::string(root_uri)},
    };
    return data.enqueueJob("fetch_thread", payload.dump(), now_seconds,
                           now_seconds);
}

mw::E<InboxDispatchResult> dispatchIncomingActivity(
    const Config& config, const DataSourceInterface& data,
    std::string_view verified_actor_uri, const Activity& activity,
    int64_t now_seconds, mw::CryptoInterface* crypto,
    mw::HTTPSessionInterface* http, const SystemActor* system_actor)
{
    if(activity.actor != verified_actor_uri)
    {
        return std::unexpected(mw::httpError(
            401, "Activity actor does not match signature actor"));
    }

    ASSIGN_OR_RETURN(bool first_seen, data.markActivitySeen(
        activity.id, now_seconds));
    if(!first_seen) return InboxDispatchResult{true};

    DO_OR_RETURN(maybeForwardIncomingActivity(config, data, crypto, http,
                                              system_actor, activity,
                                              now_seconds));

    if(activity.type == "Create")
    {
        if(activity.object.is_object())
        {
            DO_OR_RETURN(handleCreateActivity(config, data, activity));
        }
        else if(auto object_uri = normalizeRef(activity.object);
                object_uri.has_value() && !isLocalActorUri(config,
                                                           *object_uri))
        {
            if(crypto == nullptr || http == nullptr || system_actor == nullptr)
            {
                return std::unexpected(mw::runtimeError(
                    "Create object fetch requires federation clients"));
            }
            ASSIGN_OR_RETURN(auto post, fetchRemotePostByUri(
                config, data, *crypto, *http, *system_actor, *object_uri));
            (void)post;
        }
    }
    else if(activity.type == "Follow")
    {
        DO_OR_RETURN(handleFollowActivity(config, data, activity,
                                          now_seconds));
    }
    else if(activity.type == "Accept")
    {
        DO_OR_RETURN(handleAcceptActivity(data, activity));
    }
    else if(activity.type == "Like")
    {
        DO_OR_RETURN(handleLikeActivity(data, activity, now_seconds));
    }
    else if(activity.type == "Announce")
    {
        DO_OR_RETURN(handleAnnounceActivity(data, activity, now_seconds));
    }
    else if(activity.type == "EmojiReact")
    {
        DO_OR_RETURN(handleEmojiReactActivity(data, activity, now_seconds));
    }
    else if(activity.type == "Delete")
    {
        DO_OR_RETURN(handleDeleteActivity(data, activity));
    }
    else if(activity.type == "Undo")
    {
        DO_OR_RETURN(handleUndoActivity(data, activity));
    }
    else if(activity.type == "Update")
    {
        DO_OR_RETURN(handleUpdateActivity(data, activity, now_seconds));
    }

    return InboxDispatchResult{false};
}

mw::E<bool> runFederationJobOnce(const Config& config,
                                 const DataSourceInterface& data,
                                 mw::CryptoInterface& crypto,
                                 mw::HTTPSessionInterface& http,
                                 int64_t now_seconds)
{
    ASSIGN_OR_RETURN(auto claimed, data.claimJob(now_seconds));
    if(!claimed.has_value()) return false;

    mw::E<void> result;
    if(claimed->kind == "deliver")
    {
        nlohmann::json payload = nlohmann::json::parse(
            claimed->payload_json, nullptr, false);
        result = performDeliveryJob(config, data, crypto, http, payload);
    }
    else if(claimed->kind == "fetch_thread")
    {
        nlohmann::json payload = nlohmann::json::parse(
            claimed->payload_json, nullptr, false);
        result = performFetchThreadJob(config, data, crypto, http, payload);
    }
    else
    {
        result = std::unexpected(mw::runtimeError(
            std::format("Unknown job kind: {}", claimed->kind)));
    }

    if(result.has_value())
    {
        DO_OR_RETURN(data.completeJob(claimed->id));
    }
    else
    {
        DO_OR_RETURN(data.failJob(
            claimed->id, mw::errorMsg(result.error()), now_seconds,
            config.job_retry_base_delay_seconds, config.job_max_retries));
    }
    return true;
}

} // namespace unspoken
