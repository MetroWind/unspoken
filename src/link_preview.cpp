#include "link_preview.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <set>
#include <arpa/inet.h>
#include <libxml/HTMLparser.h>
#include <mw/url.hpp>
#include <spdlog/spdlog.h>
#include <actpub/transport.hpp>

#include "commit.hpp"
#include "data.hpp"

namespace unspoken
{
namespace
{
constexpr size_t MAX_HTML_BYTES = 1024 * 1024;
using SteadyClock = std::chrono::steady_clock;

struct PreviewBody
{
    std::vector<std::byte> bytes;
    size_t received = 0;
    bool exceeded = false;

    bool consume(std::span<const std::byte> chunk)
    {
        received += chunk.size();
        if(chunk.size() > MAX_HTML_BYTES - bytes.size())
        {
            exceeded = true;
            return false;
        }
        bytes.insert(bytes.end(),chunk.begin(),chunk.end());
        return true;
    }
};

std::string lower(std::string value)
{
    for(char& c : value)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

std::string attribute(xmlNode* node, const char* name)
{
    for(auto* attr = node->properties; attr; attr = attr->next)
    {
        if(xmlStrcasecmp(attr->name, BAD_CAST name)) continue;
        xmlChar* value = xmlNodeListGetString(node->doc, attr->children, 1);
        std::string result = value ? reinterpret_cast<char*>(value) : "";
        xmlFree(value);
        return result;
    }
    return "";
}

bool named(xmlNode* node, const char* name)
{
    return node->type == XML_ELEMENT_NODE &&
           xmlStrcasecmp(node->name, BAD_CAST name) == 0;
}

bool token(std::string value, std::string_view sought)
{
    value = " " + lower(std::move(value)) + " ";
    for(char& c : value)
        if(std::isspace(static_cast<unsigned char>(c))) c = ' ';
    return value.find(" " + std::string(sought) + " ") != std::string::npos;
}

bool containsImage(xmlNode* node)
{
    for(auto* child = node->children; child; child = child->next)
        if(named(child, "img") || containsImage(child)) return true;
    return false;
}

// libxml emits UTF-8. Count code points and never split a multibyte sequence.
std::string cleanText(std::string_view text, size_t limit)
{
    std::string result;
    bool space = false;
    size_t count = 0;
    for(size_t i = 0; i < text.size() && count < limit;)
    {
        unsigned char first = text[i];
        size_t size = first < 0x80 ? 1 : first < 0xe0 ? 2 :
                      first < 0xf0 ? 3 : 4;
        if(i + size > text.size()) break;
        uint32_t code = first & (size == 1 ? 0x7f :
                                size == 2 ? 0x1f : size == 3 ? 0x0f : 0x07);
        for(size_t j = 1; j < size; ++j)
            code = (code << 6) | (static_cast<unsigned char>(text[i+j]) & 63);
        bool whitespace = code == 32 || (code >= 9 && code <= 13) ||
            code == 0x85 || code == 0xa0 || code == 0x1680 ||
            (code >= 0x2000 && code <= 0x200a) || code == 0x2028 ||
            code == 0x2029 || code == 0x202f || code == 0x205f || code == 0x3000;
        if(whitespace) space = !result.empty();
        else if(code >= 32 && !(code >= 0x7f && code <= 0x9f))
        {
            if(space)
            {
                result += ' ';
                space = false;
                if(++count == limit) break;
            }
            result.append(text.substr(i, size));
            ++count;
        }
        i += size;
    }
    return result;
}

std::string header(const mw::HTTPResponse& response, std::string_view key)
{
    for(const auto& [name, value] : response.header)
        if(lower(name) == key) return value;
    return "";
}

std::optional<std::string> selectAnchor(
    xmlNode* node, std::string_view origin, std::string_view canonical,
    const std::set<std::string>& excluded)
{
    for(; node; node = node->next)
    {
        if(named(node, "a") && !token(attribute(node,"rel"),"tag") &&
           !token(attribute(node,"class"),"mention") &&
           !token(attribute(node,"class"),"hashtag") && !containsImage(node))
        {
            auto url = normalizePreviewUrl(attribute(node,"href"),origin);
            if(url && *url != canonical && !excluded.contains(*url)) return url;
        }
        auto child = selectAnchor(node->children,origin,canonical,excluded);
        if(child) return child;
    }
    return {};
}

void readHead(xmlNode* node, LinkPreview& preview,
              std::string& fallback_title, std::string& fallback_description,
              std::string_view final_url, std::string_view origin)
{
    for(; node; node = node->next)
    {
        if(named(node,"meta"))
        {
            std::string key = lower(attribute(node,"property"));
            if(key.empty()) key = lower(attribute(node,"name"));
            std::string value = attribute(node,"content");
            if(key == "og:title" && preview.title.empty())
                preview.title = cleanText(value,300);
            else if(key == "og:description" && preview.description.empty())
                preview.description = cleanText(value,500);
            else if(key == "description" && fallback_description.empty())
                fallback_description = cleanText(value,500);
            else if((key == "og:image" || key == "og:image:url") &&
                    preview.image.empty() && !value.empty())
            {
                auto base = mw::URL::fromStr(std::string(final_url));
                if(base)
                {
                    auto resolved = base->resolve(value);
                    if(resolved)
                    {
                        auto image = validatePreviewImageUrl(
                            resolved->str(),origin);
                        if(image) preview.image = *image;
                    }
                }
            }
        }
        else if(named(node,"title") && fallback_title.empty())
        {
            xmlChar* value = xmlNodeGetContent(node);
            if(value) fallback_title = cleanText(
                reinterpret_cast<char*>(value),300);
            xmlFree(value);
        }
        readHead(node->children,preview,fallback_title,fallback_description,
                 final_url,origin);
    }
}

xmlNode* findHead(xmlNode* node)
{
    for(; node; node = node->next)
    {
        if(named(node,"head")) return node;
        auto found = findHead(node->children);
        if(found) return found;
    }
    return nullptr;
}
} // namespace

bool isAllowedPreviewAddress(const mw::SockAddr& address)
{
    const auto& bytes = address.address;
    if(address.family == mw::AddressFamily::IPV6)
    {
        if(bytes.size() != 16) return false;
        bool mapped = std::all_of(bytes.begin(),bytes.begin()+10,
                                 [](auto b) { return b == 0; }) &&
                      bytes[10] == 255 && bytes[11] == 255;
        if(mapped)
        {
            mw::SockAddr ipv4;
            ipv4.address.assign(bytes.begin()+12,bytes.end());
            return isAllowedPreviewAddress(ipv4);
        }
        // Only global unicast; excludes unspecified, local, multicast,
        // IPv4-compatible and translation ranges as well as scoped addresses.
        if((bytes[0] & 0xe0) != 0x20) return false;
        if(bytes[0] == 0x20 && bytes[1] == 1 &&
           (bytes[2] < 2 || (bytes[2] == 0x0d && bytes[3] == 0xb8)))
            return false;
    }
    if(!ap::isAllowedOutboundAddress(address)) return false;
    if(address.family == mw::AddressFamily::IPV4)
    {
        if(bytes[0] == 192 && (bytes[1] == 0 || bytes[1] == 2)) return false;
        if(bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19 ||
           (bytes[1] == 51 && bytes[2] == 100))) return false;
        if(bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113) return false;
    }
    return true;
}

std::optional<std::string> normalizePreviewUrl(
    std::string_view value, std::string_view origin)
{
    if(value.empty() || value.size() > 4096 ||
       std::any_of(value.begin(),value.end(),[](unsigned char c)
                   { return c <= 32 || c == 127 || c == '\\'; })) return {};
    auto url = mw::URL::fromStr(std::string(value));
    if(!url) return {};
    std::string scheme = lower(url->scheme());
    std::string host = lower(url->host());
    std::string port = url->port();
    auto authority_start = value.find("://");
    if(authority_start == std::string_view::npos) return {};
    auto authority = value.substr(authority_start+3);
    authority = authority.substr(0,authority.find_first_of("/?#"));
    if(host.empty() || (scheme != "http" && scheme != "https") ||
       !url->user().empty() || !url->password().empty() ||
       authority.find('@') != std::string_view::npos || !url->zoneid().empty() ||
       (!port.empty() && port != (scheme == "http" ? "80" : "443"))) return {};
    std::string dns_name = host;
    while(!dns_name.empty() && dns_name.back() == '.') dns_name.pop_back();
    url->scheme(scheme.c_str()).host(host.c_str()).port(nullptr).fragment(nullptr);
    if(!origin.empty())
    {
        auto local = mw::URL::fromStr(std::string(origin));
        std::string local_host = local ? lower(local->host()) : "";
        while(!local_host.empty() && local_host.back() == '.')
            local_host.pop_back();
        if(local && local_host == dns_name &&
           lower(local->scheme()) == scheme &&
           (local->port().empty() || local->port() ==
               (scheme == "http" ? "80" : "443"))) return {};
    }
    std::string normalized = url->str();
    if(normalized.size() > 4096) return {};
    return normalized;
}

std::optional<std::string> validatePreviewImageUrl(
    std::string_view value, std::string_view origin)
{
    auto normalized = normalizePreviewUrl(value,origin);
    if(!normalized) return {};
    auto url = mw::URL::fromStr(*normalized);
    std::string host = lower(url->host());
    std::string literal = host;
    if(literal.front() == '[' && literal.back() == ']')
        literal = literal.substr(1,literal.size()-2);
    std::string dns_name = host;
    while(!dns_name.empty() && dns_name.back() == '.') dns_name.pop_back();
    std::array<unsigned char,16> bytes{};
    mw::SockAddr address;
    if(inet_pton(AF_INET,literal.c_str(),bytes.data()) == 1)
        address.address.assign(bytes.begin(),bytes.begin()+4);
    else if(inet_pton(AF_INET6,literal.c_str(),bytes.data()) == 1)
    {
        address.family = mw::AddressFamily::IPV6;
        address.address.assign(bytes.begin(),bytes.end());
    }
    if(address.address.empty() &&
       (dns_name == "localhost" || dns_name.ends_with(".localhost") ||
        dns_name.ends_with(".local") ||
        dns_name.find('.') == std::string::npos))
        return {};
    if(!address.address.empty() && !isAllowedPreviewAddress(address)) return {};
    return normalized;
}

std::optional<std::string> selectPreviewUrl(
    std::string_view html, std::string_view origin, std::string_view canonical,
    const std::vector<std::string>& excluded_urls)
{
    if(html.empty() || html.size() > MAX_HTML_BYTES) return {};
    auto* document = htmlReadMemory(html.data(),static_cast<int>(html.size()),
        nullptr,"UTF-8",HTML_PARSE_NONET | HTML_PARSE_NOERROR |
        HTML_PARSE_NOWARNING | HTML_PARSE_COMPACT);
    if(!document) return {};
    std::set<std::string> excluded;
    for(const auto& value : excluded_urls)
        if(auto normalized = normalizePreviewUrl(value))
            excluded.insert(*normalized);
    auto own_url = normalizePreviewUrl(canonical);
    auto selected = selectAnchor(xmlDocGetRootElement(document),origin,
                                 own_url.value_or(""),excluded);
    xmlFreeDoc(document);
    return selected;
}

LinkPreview parsePreviewHtml(std::string_view html, std::string_view final_url,
                             std::string_view origin, const char* encoding)
{
    LinkPreview preview;
    preview.status = PreviewStatus::UNAVAILABLE;
    if(html.empty() || html.size() > MAX_HTML_BYTES) return preview;
    auto* document = htmlReadMemory(html.data(),static_cast<int>(html.size()),
        nullptr,encoding,HTML_PARSE_NONET | HTML_PARSE_NOERROR |
        HTML_PARSE_NOWARNING | HTML_PARSE_COMPACT);
    if(!document) return preview;
    auto* head = findHead(xmlDocGetRootElement(document));
    std::string title, description;
    if(head) readHead(head->children,preview,title,description,final_url,origin);
    xmlFreeDoc(document);
    if(preview.title.empty()) preview.title = title;
    if(preview.description.empty()) preview.description = description;
    if(!preview.title.empty()) preview.status = PreviewStatus::READY;
    return preview;
}

PreviewResult fetchLinkPreview(mw::HTTPSessionInterface& http,
                                std::string_view url, std::string_view origin)
{
    PreviewResult result;
    result.preview.status = PreviewStatus::UNAVAILABLE;
    auto target = validatePreviewImageUrl(url,origin);
    if(!target) return result;
    auto protocols = http.allowedProtocols("http,https");
    auto redirects = http.allowedRedirectProtocols("http,https");
    auto connect = http.connectionTimeout(std::chrono::seconds(5));
    auto maximum = http.maxSize(MAX_HTML_BYTES);
    if(!protocols || !redirects || !connect || !maximum) return result;
    http.followRedirects(false);
    http.addressFilter(isAllowedPreviewAddress);
    const auto deadline = SteadyClock::now() + std::chrono::seconds(30);
    for(int hop = 0; hop <= 5; ++hop)
    {
        auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
            deadline - SteadyClock::now());
        if(remaining.count() <= 0)
        {
            result.failure = PreviewFailure::TRANSIENT;
            return result;
        }
        if(!http.transferTimeout(remaining)) return result;
        mw::HTTPRequest request(*target);
        request.addHeader("Accept","text/html, application/xhtml+xml");
        request.addHeader("User-Agent",std::string("Unspoken/") + GIT_COMMIT_HASH);
        PreviewBody body;
        auto response = http.getStream(request,
            std::bind_front(&PreviewBody::consume,&body));
        result.html_bytes += body.received;
        if(body.exceeded) return result;
        if(!response)
        {
            const auto message = lower(mw::errorMsg(response.error()));
            if(message != mw::HTTP_BLOCKED_BY_POLICY &&
               message.find("too large") == std::string::npos &&
               message.find("maximum") == std::string::npos)
                result.failure = PreviewFailure::TRANSIENT;
            return result;
        }
        response->payload = std::move(body.bytes);
        int status = response->status;
        if(status == 408 || status == 429 || status >= 500)
        {
            result.failure = PreviewFailure::TRANSIENT;
            std::string delay = header(*response,"retry-after");
            int seconds = 0;
            bool integer = !delay.empty();
            for(unsigned char digit : delay)
            {
                if(digit < '0' || digit > '9')
                {
                    integer = false;
                    break;
                }
                seconds = std::min(3600,seconds*10 + digit-'0');
            }
            if(integer) result.retry_after_seconds = seconds;
            return result;
        }
        if(status == 301 || status == 302 || status == 303 ||
           status == 307 || status == 308)
        {
            if(hop == 5) return result;
            std::string location = header(*response,"location");
            auto base = mw::URL::fromStr(*target);
            if(location.empty() || !base) return result;
            auto resolved = base->resolve(location);
            if(!resolved) return result;
            target = validatePreviewImageUrl(resolved->str(),origin);
            if(!target) return result;
            continue;
        }
        if(status != 200) return result;
        std::string content_type = lower(header(*response,"content-type"));
        auto semicolon = content_type.find(';');
        std::string mime = content_type.substr(0,semicolon);
        while(!mime.empty() && std::isspace(mime.back())) mime.pop_back();
        if(mime != "text/html" && mime != "application/xhtml+xml") return result;
        std::string encoding;
        auto charset = content_type.find("charset=");
        if(charset != std::string::npos)
        {
            encoding = content_type.substr(charset+8);
            encoding = encoding.substr(0,encoding.find(';'));
            encoding.erase(std::remove(encoding.begin(),encoding.end(),'"'),
                           encoding.end());
        }
        result.preview = parsePreviewHtml(response->payloadAsStr(),*target,
            origin,encoding.empty() ? nullptr : encoding.c_str());
        result.preview.url = std::string(url);
        result.failure = result.preview.status == PreviewStatus::READY ?
            PreviewFailure::NONE : PreviewFailure::PERMANENT;
        return result;
    }
    return result;
}

LinkPreviewWorker::LinkPreviewWorker(const Config& value) : config(value) {}
LinkPreviewWorker::~LinkPreviewWorker() { stop(); }

void LinkPreviewWorker::start()
{
    std::lock_guard lock(mutex);
    if(!config.link_previews_enabled || thread.joinable()) return;
    stopping = false;
    thread = std::thread(&LinkPreviewWorker::run,this);
}

void LinkPreviewWorker::wake()
{
    std::lock_guard lock(mutex);
    notified = true;
    condition.notify_one();
}

void LinkPreviewWorker::stop()
{
    {
        std::lock_guard lock(mutex);
        stopping = true;
        condition.notify_all();
    }
    if(thread.joinable()) thread.join();
}

mw::E<void> LinkPreviewQueue::recover(const DataSourceSQLite& data)
{
    if(queue.size() >= 1000) return {};
    ASSIGN_OR_RETURN(auto ids,data.pendingLinkPreviewIds(scan_cursor,1000));
    for(auto id : ids)
    {
        if(queue.size() >= 1000) break;
        scan_cursor = id;
        queue.try_emplace(id);
    }
    if(ids.empty()) scan_cursor = 0;
    return {};
}

std::vector<int64_t> LinkPreviewQueue::activeIds() const
{
    std::vector<int64_t> ids;
    for(const auto& [id,work] : queue) ids.push_back(id);
    return ids;
}

SteadyClock::time_point LinkPreviewQueue::nextDeadline(
    SteadyClock::time_point scan_deadline) const
{
    for(const auto& [id, work] : queue)
        scan_deadline = std::min(scan_deadline,work.due);
    return scan_deadline;
}

mw::E<bool> LinkPreviewQueue::runOnce(
    const DataSourceSQLite& data, const PreviewFetcher& fetch,
    std::string_view origin, SteadyClock::time_point now)
{
    auto ready = std::find_if(queue.begin(),queue.end(),
        [now](const auto& entry) { return entry.second.due <= now; });
    if(ready == queue.end()) return false;
    auto id = ready->first;
    auto& work = ready->second;
    // Back off database failures too, retaining the ID and any fetched result.
    work.due = now + std::chrono::seconds(30);
    ASSIGN_OR_RETURN(auto referenced,data.pendingLinkPreviewIds(id-1,1));
    if(referenced.empty() || referenced.front() != id)
    {
        queue.erase(ready);
        return true;
    }
    if(!work.completed)
    {
        ASSIGN_OR_RETURN(auto rows,data.getLinkPreviews({id}));
        if(!rows.contains(id))
        {
            queue.erase(ready);
            return true;
        }
        auto started = SteadyClock::now();
        auto result = fetch(rows.at(id).url,origin);
        auto elapsed = SteadyClock::now() - started;
        work.due += elapsed;
        ++work.attempts;
        auto parsed = mw::URL::fromStr(rows.at(id).url);
        spdlog::info("Preview {} host={} attempt={} result={} "
                     "bytes={} elapsed_ms={}",id,
            parsed ? parsed->host() : "",work.attempts,
            static_cast<int>(result.failure),result.html_bytes,
            std::chrono::duration_cast<std::chrono::milliseconds>(
                SteadyClock::now()-started).count());
        if(result.failure == PreviewFailure::TRANSIENT && work.attempts < 3)
        {
            int delay = work.attempts == 1 ? 30 : 300;
            work.due = now + elapsed + std::chrono::seconds(
                std::max(delay,result.retry_after_seconds));
            return true;
        }
        if(result.failure == PreviewFailure::TRANSIENT)
            result.preview.status = PreviewStatus::FAILED;
        else if(result.failure == PreviewFailure::PERMANENT)
            result.preview.status = PreviewStatus::UNAVAILABLE;
        work.completed = std::move(result.preview);
    }
    DO_OR_RETURN(data.completeLinkPreview(id,*work.completed));
    queue.erase(id);
    return true;
}

namespace
{
PreviewResult fetchPreviewRequest(std::string_view url,std::string_view origin)
{
    mw::HTTPSession http;
    return fetchLinkPreview(http,url,origin);
}
} // namespace

void LinkPreviewWorker::run()
{
    auto opened = DataSourceSQLite::fromFile(config.database_path,
                                            config.sqlite_busy_timeout_ms);
    if(!opened)
    {
        spdlog::error("Preview worker cannot open database: {}",
                      mw::errorMsg(opened.error()));
        return;
    }
    auto& data = **opened;
    LinkPreviewQueue queue;
    auto next_scan = SteadyClock::now();
    auto next_collection = SteadyClock::now() + std::chrono::hours(1);
    std::unique_lock lock(mutex);
    while(!stopping)
    {
        auto now = SteadyClock::now();
        bool scan = now >= next_scan || notified;
        notified = false;
        lock.unlock();
        if(scan)
        {
            auto recovered = queue.recover(data);
            if(!recovered) spdlog::warn("Preview recovery failed");
            next_scan = now + std::chrono::seconds(30);
        }
        if(now >= next_collection)
        {
            auto collected = data.collectLinkPreviews(queue.activeIds());
            if(!collected) spdlog::warn("Preview collection failed");
            next_collection = now + std::chrono::hours(1);
        }
        auto ran = queue.runOnce(data,fetchPreviewRequest,config.url_root,now);
        if(!ran) spdlog::warn("Preview database operation failed");
        if(ran && *ran) next_scan = SteadyClock::now();
        auto deadline = queue.nextDeadline(next_scan);
        lock.lock();
        if(ran && *ran) continue;
        condition.wait_until(lock,deadline,[this] { return stopping || notified; });
    }
}
} // namespace unspoken
