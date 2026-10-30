#include <actpub/transport.hpp>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <ctime>
#include <format>
#include <iomanip>
#include <locale>
#include <span>
#include <sstream>
#include <mw/url.hpp>
#include <mw/utils.hpp>
#include <spdlog/spdlog.h>

namespace ap
{
namespace
{
std::string jsonString(const nlohmann::json& object, const char* key)
{
    auto field = object.find(key);
    return field != object.end() && field->is_string()
               ? field->get<std::string>()
               : "";
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
    if(path.empty())
        path = "/";
    std::string query = url.query();
    if(!query.empty())
        path += "?" + query;
    return path;
}

std::string requestAuthority(const mw::URL& url)
{
    std::string host = url.host();
    std::string port = url.port();
    if(port.empty())
        return host;
    if((url.scheme() == "https" && port == "443") ||
       (url.scheme() == "http" && port == "80"))
    {
        return host;
    }
    return host + ":" + port;
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
    if(a.size() != 16 || a[15] != last)
        return false;
    for(size_t i = 0; i < 15; ++i)
        if(a[i] != 0)
            return false;
    return true;
}

std::string lower(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    for(char c : s)
    {
        out.push_back(
            static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

bool hostMatches(std::string_view host,
                 const std::vector<std::string>& allowed_hosts)
{
    std::string needle = lower(host);
    for(const auto& allowed : allowed_hosts)
    {
        if(needle == lower(allowed))
            return true;
    }
    return false;
}

bool isMetadataAddress(const mw::SockAddr& addr)
{
    const auto& a = addr.address;
    return addr.family == mw::AddressFamily::IPV4 && a.size() == 4 &&
           a[0] == 169 && a[1] == 254 && a[2] == 169 && a[3] == 254;
}

std::string addressForLog(const mw::SockAddr& addr)
{
    const auto& a = addr.address;
    if(addr.family == mw::AddressFamily::IPV4 && a.size() == 4)
    {
        return std::format("{}.{}.{}.{}:{}", a[0], a[1], a[2], a[3], addr.port);
    }
    std::ostringstream out;
    out << "[";
    for(size_t i = 0; i < a.size(); i += 2)
    {
        if(i > 0)
            out << ":";
        uint16_t part = static_cast<uint16_t>(a[i]) << 8;
        if(i + 1 < a.size())
            part |= a[i + 1];
        out << std::hex << part;
    }
    out << "]:" << std::dec << addr.port;
    return out.str();
}

std::unordered_map<std::string, std::string>
lowerHeaders(const std::unordered_map<std::string, std::string>& headers)
{
    std::unordered_map<std::string, std::string> out;
    for(const auto& [k, v] : headers)
        out[lower(k)] = v;
    return out;
}

std::optional<std::string>
header(const std::unordered_map<std::string, std::string>& headers,
       std::string_view name)
{
    auto it = headers.find(std::string(name));
    if(it == headers.end())
        return std::nullopt;
    return it->second;
}

std::vector<std::string> splitWords(std::string_view s)
{
    std::istringstream in{std::string(s)};
    std::vector<std::string> out;
    std::string item;
    while(in >> item)
        out.push_back(item);
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
        if(eq == std::string_view::npos)
            break;
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

std::optional<int64_t> parseHttpDate(std::string_view date)
{
    std::tm tm{};
    std::istringstream in{std::string(date)};
    in.imbue(std::locale::classic());
    in >> std::get_time(&tm, "%a, %d %b %Y %H:%M:%S GMT");
    if(in.fail())
        return std::nullopt;
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
    return "SHA-256=" + mw::base64Encode(std::span<unsigned char>(
                                             digest.data(), digest.size()),
                                         false, true);
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
        pos = comma == std::string_view::npos ? header_value.size() : comma + 1;

        size_t eq = part.find('=');
        if(eq == std::string_view::npos)
            continue;
        std::string algorithm(lower(mw::strip(part.substr(0, eq))));
        if(algorithm != "sha-256")
            continue;

        std::string encoded(mw::strip(part.substr(eq + 1)));
        ASSIGN_OR_RETURN(auto actual, mw::base64Decode(encoded));
        return actual.size() == expected.size() &&
               std::equal(actual.begin(), actual.end(), expected.begin());
    }
    return false;
}

bool containsHeader(const std::vector<std::string>& headers,
                    std::string_view name)
{
    for(const auto& h : headers)
        if(lower(h) == name)
            return true;
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

mw::E<std::string>
signingString(const IncomingHttpRequest& req,
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
        if(i > 0)
            out.push_back('\n');
        out += lines[i];
    }
    return out;
}

void appendAll(std::vector<std::string>& out,
               const std::vector<std::string>& in)
{
    out.insert(out.end(), in.begin(), in.end());
}

std::string percentEncode(std::string_view s)
{
    constexpr char HEX[] = "0123456789ABCDEF";
    std::string out;
    for(unsigned char c : s)
    {
        bool keep = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                    c == '.' || c == '~';
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
    if(handle.starts_with('@'))
        handle.remove_prefix(1);
    size_t at = handle.find('@');
    if(at == std::string_view::npos || at == 0 || at + 1 >= handle.size())
        return std::nullopt;
    if(handle.find('@', at + 1) != std::string_view::npos)
        return std::nullopt;
    std::string username(handle.substr(0, at));
    std::string domain(handle.substr(at + 1));
    if(domain.find('/') != std::string::npos ||
       domain.find(':') != std::string::npos)
    {
        return std::nullopt;
    }
    return std::make_pair(username, domain);
}

} // namespace

mw::E<SignatureEnvelope> parseHttpSignature(const TransportConfig& config,
                                            const IncomingHttpRequest& req,
                                            int64_t now_seconds)
{
    auto headers = signatureHeaders(req.headers);
    auto sig_header = header(headers, "signature");
    if(!sig_header.has_value())
    {
        return std::unexpected(mw::httpError(401, "Missing Signature"));
    }
    auto params = parseSignatureParams(*sig_header);
    if(!params.contains("keyid") || !params.contains("signature") ||
       params["keyid"].empty() || params["signature"].empty())
    {
        return std::unexpected(mw::httpError(401, "Bad Signature header"));
    }

    std::string algorithm = lower(
        params.contains("algorithm") ? params["algorithm"] : "rsa-sha256");
    if(algorithm != "rsa-sha256" && algorithm != "hs2019")
    {
        return std::unexpected(
            mw::httpError(401, "Unsupported signature algorithm"));
    }

    std::vector<std::string> signed_headers =
        params.contains("headers") ? splitWords(params["headers"])
                                   : std::vector<std::string>{"date"};
    if(!containsHeader(signed_headers, "date"))
    {
        return std::unexpected(mw::httpError(401, "Date is not signed"));
    }
    if(!containsHeader(signed_headers, "(request-target)"))
    {
        return std::unexpected(
            mw::httpError(401, "Request target is not signed"));
    }

    auto date = header(headers, "date");
    if(!date.has_value())
    {
        return std::unexpected(mw::httpError(401, "Missing Date"));
    }
    auto request_time = parseHttpDate(*date);
    if(!request_time.has_value() || std::llabs(now_seconds - *request_time) >
                                        config.http_signature_skew_seconds)
    {
        return std::unexpected(mw::httpError(401, "Date skew too large"));
    }

    std::string method = lower(req.method);
    if(method == "post" || method == "put")
    {
        if(!containsHeader(signed_headers, "digest"))
        {
            return std::unexpected(mw::httpError(401, "Digest is not signed"));
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
    if(hash != std::string::npos)
        actor_uri.resize(hash);
    if(actor_uri.empty() || !isValidRemoteUrl(config.dev, actor_uri))
    {
        return std::unexpected(mw::httpError(401, "Invalid signature key"));
    }

    return SignatureEnvelope{
        std::move(params["keyid"]), std::move(actor_uri),
        std::move(signed_headers),  std::move(*signature),
        std::move(*signing_input),
    };
}

mw::E<bool> verifyParsedHttpSignature(mw::CryptoInterface& crypto,
                                      const SignatureEnvelope& signature,
                                      const RemoteActor& actor)
{
    if(actor.uri != signature.actor_uri ||
       actor.public_key_id != signature.key_id)
    {
        return false;
    }
    return crypto.verifySignature(mw::SignatureAlgorithm::RSA_V1_5_SHA256,
                                  actor.public_key_pem, signature.signature,
                                  signature.signing_input);
}

std::vector<std::string> normalizeAddressing(const nlohmann::json& field)
{
    std::vector<std::string> out;
    if(field.is_null())
        return out;
    if(field.is_array())
    {
        for(const auto& item : field)
        {
            if(auto ref = normalizeRef(item); ref.has_value())
                out.push_back(*ref);
        }
        return out;
    }
    if(auto ref = normalizeRef(field); ref.has_value())
        out.push_back(*ref);
    return out;
}

std::optional<std::string> normalizeRef(const nlohmann::json& field)
{
    if(field.is_string())
        return field.get<std::string>();
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
        return std::unexpected(
            mw::httpError(400, "Activity must be an object"));
    }
    auto id = normalizeRef(raw.contains("id") ? raw["id"] : nlohmann::json());
    auto actor =
        normalizeRef(raw.contains("actor") ? raw["actor"] : nlohmann::json());
    if(!id.has_value() || !raw.contains("type") || !raw["type"].is_string() ||
       !actor.has_value())
    {
        return std::unexpected(
            mw::httpError(400, "Activity is missing id, type, or actor"));
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
    return accept.find("application/activity+json") != std::string_view::npos ||
           accept.find("application/ld+json") != std::string_view::npos;
}

bool isAllowedOutboundAddress(const mw::SockAddr& addr)
{
    const auto& a = addr.address;
    if(addr.family == mw::AddressFamily::IPV4)
    {
        if(a.size() != 4)
            return false;
        if(ipv4In(a, 10) || ipv4In(a, 127) || ipv4In(a, 169, 254) ||
           ipv4In(a, 192, 168))
        {
            return false;
        }
        if(a[0] == 172 && a[1] >= 16 && a[1] <= 31)
            return false;
        // Carrier-grade NAT, localhost-ish zero net, multicast/reserved.
        if(a[0] == 100 && a[1] >= 64 && a[1] <= 127)
            return false;
        if(a[0] == 0 || a[0] >= 224)
            return false;
        return true;
    }

    if(addr.family == mw::AddressFamily::IPV6)
    {
        if(a.size() != 16)
            return false;
        if(ipv6AllZeroUntilLast(a, 1))
            return false; // ::1
        if((a[0] & 0xfe) == 0xfc)
            return false; // fc00::/7 ULA
        if(a[0] == 0xfe && (a[1] & 0xc0) == 0x80)
            return false; // fe80::/10
        if(a[0] == 0xff)
            return false; // multicast
        return true;
    }
    return false;
}

bool isValidRemoteUrl(const DevConfig& dev, std::string_view value)
{
    auto parsed = mw::URL::fromStr(std::string(value));
    if(!parsed.has_value() || parsed->host().empty())
        return false;
    if(parsed->scheme() == "https")
        return true;
    return dev.allow_http_url_root && parsed->scheme() == "http" &&
           hostMatches(parsed->host(), dev.outbound_allow_private_hosts);
}

mw::E<void> hardenOutboundSession(mw::HTTPSessionInterface& http)
{
    DO_OR_RETURN(http.allowedProtocols("https"));
    DO_OR_RETURN(http.allowedRedirectProtocols("https"));
    DO_OR_RETURN(http.maxRedirections(5));
    http.followRedirects(true);
    http.addressFilter([](const mw::SockAddr& addr)
                       { return isAllowedOutboundAddress(addr); });
    return {};
}

mw::E<void> hardenOutboundSession(const TransportConfig& config,
                                  mw::HTTPSessionInterface& http,
                                  std::string_view target_url)
{
    auto parsed = mw::URL::fromStr(std::string(target_url));
    if(!parsed.has_value() || parsed->host().empty())
    {
        return std::unexpected(
            mw::runtimeError("Outbound federation URL must be absolute"));
    }

    bool dev_private_host =
        config.dev.allow_http_url_root &&
        hostMatches(parsed->host(), config.dev.outbound_allow_private_hosts);
    if(dev_private_host)
    {
        DO_OR_RETURN(http.allowedProtocols("http,https"));
        DO_OR_RETURN(http.allowedRedirectProtocols("http,https"));
        DO_OR_RETURN(http.maxRedirections(0));
        http.followRedirects(false);
        std::string host = parsed->host();
        http.addressFilter(
            [host](const mw::SockAddr& addr)
            {
                spdlog::warn(
                    "Development private outbound host {} resolved to {}", host,
                    addressForLog(addr));
                return !isMetadataAddress(addr);
            });
        return {};
    }

    DO_OR_RETURN(hardenOutboundSession(http));
    http.followRedirects(false);
    return http.maxRedirections(0);
}

mw::E<mw::HTTPRequest>
signedHttpRequest(const TransportConfig& config, mw::CryptoInterface& crypto,
                  const SigningActor& actor, std::string_view method,
                  std::string_view uri, std::string_view body,
                  std::string_view content_type)
{
    auto parsed = mw::URL::fromStr(std::string(uri));
    bool dev_http =
        config.dev.allow_http_url_root && parsed.has_value() &&
        hostMatches(parsed->host(), config.dev.outbound_allow_private_hosts);
    if(!parsed.has_value() || parsed->host().empty() ||
       (parsed->scheme() != "https" &&
        !(dev_http && parsed->scheme() == "http")))
    {
        return std::unexpected(mw::runtimeError(
            "Outbound federation fetch URL must be absolute https"));
    }

    std::string date = httpDate();
    std::string target = requestTarget(*parsed);
    std::string host = requestAuthority(*parsed);
    std::string method_lower = lower(method);
    std::string signed_headers = "(request-target) host date";
    std::string signing_input =
        std::format("(request-target): {} {}\nhost: {}\ndate: {}", method_lower,
                    target, host, date);

    std::optional<std::string> digest;
    if(method_lower == "post" || method_lower == "put")
    {
        ASSIGN_OR_RETURN(auto d, digestHeaderFor(body));
        digest = d;
        signed_headers += " digest";
        signing_input += "\ndigest: " + *digest;
    }

    ASSIGN_OR_RETURN(auto sig,
                     crypto.sign(mw::SignatureAlgorithm::RSA_V1_5_SHA256,
                                 actor.private_key_pem, signing_input));
    std::string sig64 = mw::base64Encode(
        std::span<unsigned char>(sig.data(), sig.size()), false, true);

    mw::HTTPRequest req{std::string(uri)};
    if(!body.empty())
        req.setPayload(body);
    if(!content_type.empty())
        req.setContentType(content_type);
    req.addHeader("Accept", "application/activity+json");
    req.addHeader("Host", host);
    req.addHeader("Date", date);
    if(digest.has_value())
        req.addHeader("Digest", *digest);
    req.addHeader(
        "Signature",
        std::format(
            R"(keyId="{}",algorithm="rsa-sha256",headers="{}",signature="{}")",
            actor.key_id, signed_headers, sig64));
    return req;
}

mw::E<RemoteActor> fetchRemoteActor(const TransportConfig& config,
                                    mw::CryptoInterface& crypto,
                                    mw::HTTPSessionInterface& http,
                                    const SigningActor& signer,
                                    std::string_view actor_uri)
{
    DO_OR_RETURN(hardenOutboundSession(config, http, actor_uri));
    ASSIGN_OR_RETURN(
        auto req, signedHttpRequest(config, crypto, signer, "GET", actor_uri));
    ASSIGN_OR_RETURN(auto bounded, getBounded(http, req, 2 * 1024 * 1024));
    const auto* res = &bounded;
    if(res->status < 200 || res->status >= 300)
    {
        return std::unexpected(
            mw::httpError(res->status, "Remote actor fetch failed"));
    }

    nlohmann::json doc =
        nlohmann::json::parse(res->payloadAsStr(), nullptr, false);
    if(!doc.is_object())
    {
        return std::unexpected(
            mw::runtimeError("Remote actor response is not JSON"));
    }
    if(doc.contains("id") && !doc["id"].is_string())
    {
        return std::unexpected(mw::runtimeError("Remote actor has invalid id"));
    }
    std::string id = doc.contains("id") ? doc["id"].get<std::string>()
                                        : std::string(actor_uri);
    if(id != actor_uri)
    {
        return std::unexpected(
            mw::runtimeError("Remote actor id does not match requested URI"));
    }
    if(!isValidRemoteUrl(config.dev, id))
    {
        return std::unexpected(mw::runtimeError("Remote actor has invalid id"));
    }
    if(!doc.contains("inbox") || !doc["inbox"].is_string() ||
       !doc.contains("publicKey") || !doc["publicKey"].is_object())
    {
        return std::unexpected(
            mw::runtimeError("Remote actor is missing inbox or publicKey"));
    }
    std::string inbox = doc["inbox"].get<std::string>();
    if(!isValidRemoteUrl(config.dev, inbox))
    {
        return std::unexpected(
            mw::runtimeError("Remote actor has invalid inbox"));
    }
    const auto& public_key = doc["publicKey"];
    if(!public_key.contains("id") || !public_key["id"].is_string() ||
       !public_key.contains("publicKeyPem") ||
       !public_key["publicKeyPem"].is_string())
    {
        return std::unexpected(
            mw::runtimeError("Remote actor has incomplete publicKey"));
    }
    std::string public_key_id = public_key["id"].get<std::string>();
    std::string public_key_pem = public_key["publicKeyPem"].get<std::string>();
    if(public_key_id.empty() || public_key_pem.empty() ||
       (public_key.contains("owner") &&
        (!public_key["owner"].is_string() ||
         public_key["owner"].get<std::string>() != id)))
    {
        return std::unexpected(
            mw::runtimeError("Remote actor has invalid publicKey"));
    }

    RemoteActor actor;
    actor.uri = id;
    if(doc.contains("preferredUsername") &&
       !doc["preferredUsername"].is_string())
    {
        return std::unexpected(
            mw::runtimeError("Remote actor has invalid preferredUsername"));
    }
    if(doc.contains("name") && !doc["name"].is_string())
    {
        return std::unexpected(
            mw::runtimeError("Remote actor has invalid name"));
    }
    actor.username = doc.contains("preferredUsername")
                         ? doc["preferredUsername"].get<std::string>()
                         : std::string();
    auto parsed_id = mw::URL::fromStr(id);
    if(actor.username.empty())
        actor.username = parsed_id->host();
    actor.domain = parsed_id->host();
    actor.display_name =
        doc.contains("name") ? doc["name"].get<std::string>() : std::string();
    actor.inbox = std::move(inbox);
    if(doc.contains("endpoints") && doc["endpoints"].is_object() &&
       doc["endpoints"].contains("sharedInbox"))
    {
        if(!doc["endpoints"]["sharedInbox"].is_string())
        {
            return std::unexpected(
                mw::runtimeError("Remote actor has invalid sharedInbox"));
        }
        std::string shared_inbox =
            doc["endpoints"]["sharedInbox"].get<std::string>();
        if(!isValidRemoteUrl(config.dev, shared_inbox))
        {
            return std::unexpected(
                mw::runtimeError("Remote actor has invalid sharedInbox"));
        }
        actor.shared_inbox = std::move(shared_inbox);
    }
    actor.public_key_id = std::move(public_key_id);
    actor.public_key_pem = std::move(public_key_pem);
    actor.actor_json = doc.dump();
    actor.fetched_at = mw::timeToSeconds(mw::Clock::now());
    return actor;
}

mw::E<mw::HTTPRequest> webFingerRequest(const TransportConfig& config,
                                        std::string_view uri)
{
    auto parsed = mw::URL::fromStr(std::string(uri));
    bool dev_http =
        config.dev.allow_http_url_root && parsed.has_value() &&
        hostMatches(parsed->host(), config.dev.outbound_allow_private_hosts);
    if(!parsed.has_value() || parsed->host().empty() ||
       (parsed->scheme() != "https" &&
        !(dev_http && parsed->scheme() == "http")))
    {
        return std::unexpected(
            mw::runtimeError("Outbound WebFinger URL must be absolute https"));
    }

    mw::HTTPRequest req{std::string(uri)};
    req.addHeader("Accept", "application/jrd+json, application/json");
    return req;
}

mw::E<std::string> discoverActorUri(const TransportConfig& config,
                                    mw::HTTPSessionInterface& http,
                                    std::string_view handle)
{
    auto parsed = parseHandle(handle);
    if(!parsed)
        return std::unexpected(
            mw::runtimeError("Expected a user@domain handle"));
    const auto& [username, domain] = *parsed;
    std::string acct = username + "@" + domain;
    std::string scheme =
        config.dev.allow_http_url_root &&
                hostMatches(domain, config.dev.outbound_allow_private_hosts)
            ? "http"
            : "https";
    std::string uri =
        scheme + "://" + domain +
        "/.well-known/webfinger?resource=" + percentEncode("acct:" + acct);

    DO_OR_RETURN(hardenOutboundSession(config, http, uri));
    // WebFinger is unsigned and commonly delegated to another HTTPS host.
    // The address filter still checks every connection, including redirects.
    // Keep development private-host exceptions confined to their named host.
    const bool dev_private_host = config.dev.allow_http_url_root &&
        hostMatches(domain, config.dev.outbound_allow_private_hosts);
    if(!dev_private_host)
    {
        DO_OR_RETURN(http.maxRedirections(5));
        http.followRedirects(true);
    }
    ASSIGN_OR_RETURN(auto req, webFingerRequest(config, uri));
    ASSIGN_OR_RETURN(auto bounded, getBounded(http, req, 2 * 1024 * 1024));
    const auto* res = &bounded;
    if(res->status < 200 || res->status >= 300)
    {
        return std::unexpected(
            mw::httpError(res->status, "WebFinger lookup failed"));
    }

    nlohmann::json doc =
        nlohmann::json::parse(res->payloadAsStr(), nullptr, false);
    if(!doc.is_object())
    {
        return std::unexpected(
            mw::runtimeError("WebFinger response is not JSON"));
    }

    if(!doc.contains("links") || !doc["links"].is_array())
    {
        return std::unexpected(
            mw::runtimeError("WebFinger response has no links"));
    }
    std::optional<std::string> actor_uri;
    for(const auto& link : doc["links"])
    {
        if(!link.is_object())
            continue;
        if(jsonString(link, "rel") != "self")
            continue;
        std::string type = jsonString(link, "type");
        if(type != "application/activity+json" && type != "application/ld+json")
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
    if(!isValidRemoteUrl(config.dev, *actor_uri))
        return std::unexpected(mw::runtimeError("Unsafe WebFinger self link"));
    return *actor_uri;
}

mw::E<mw::HTTPResponse> getBounded(mw::HTTPSessionInterface& http,
                                   const mw::HTTPRequest& request,
                                   size_t max_bytes)
{
    std::vector<std::byte> body;
    bool exceeded = false;
    auto consume = [&](std::span<const std::byte> chunk)
    {
        if(chunk.size() > max_bytes - body.size())
        {
            exceeded = true;
            return false;
        }
        body.insert(body.end(), chunk.begin(), chunk.end());
        return true;
    };
    auto response = http.getStream(request, consume);
    if(exceeded)
        return std::unexpected(mw::httpError(413, "Remote document too large"));
    if(!response)
        return std::unexpected(response.error());
    response->payload = std::move(body);
    return std::move(*response);
}

mw::E<mw::HTTPResponse> postBounded(mw::HTTPSessionInterface& http,
                                    const mw::HTTPRequest& request,
                                    size_t max_bytes)
{
    size_t received = 0;
    bool exceeded = false;
    auto consume = [&](std::span<const std::byte> chunk)
    {
        if(chunk.size() > max_bytes - received)
        {
            exceeded = true;
            return false;
        }
        received += chunk.size();
        return true;
    };
    auto response = http.postStream(request, consume);
    if(exceeded)
        return std::unexpected(
            mw::httpError(413, "Delivery response too large"));
    return response;
}

} // namespace ap
