#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <mw/http_client.hpp>

#include "config.hpp"

namespace unspoken
{
// Stable values stored in the application database; never renumber.
enum class PreviewStatus
{
    PENDING = 0,
    READY = 1,
    UNAVAILABLE = 2,
    FAILED = 3,
};

// Cached plain text and a browser-loaded image; no remote HTML is retained.
struct LinkPreview
{
    int64_t id = 0;
    std::string url;
    std::string title;
    std::string description;
    std::string image;
    PreviewStatus status = PreviewStatus::PENDING;
};

// Classify network outcomes separately from database errors.
enum class PreviewFailure { NONE, PERMANENT, TRANSIENT };

// One attempt's bounded outcome, with an optional server retry delay.
struct PreviewResult
{
    LinkPreview preview;
    PreviewFailure failure = PreviewFailure::PERMANENT;
    int retry_after_seconds = 0;
    size_t html_bytes = 0;
};

// Validate and normalize a web URL without DNS or other I/O.
std::optional<std::string> normalizePreviewUrl(
    std::string_view value, std::string_view origin = "");
// Validate browser image destinations, including literal-address restrictions.
std::optional<std::string> validatePreviewImageUrl(
    std::string_view value, std::string_view origin = "");
// Reject nonpublic addresses, including mapped IPv4 and unspecified IPv6.
bool isAllowedPreviewAddress(const mw::SockAddr& address);
// Select one article anchor in document order, ignoring structured exclusions.
std::optional<std::string> selectPreviewUrl(
    std::string_view html, std::string_view origin,
    std::string_view canonical,
    const std::vector<std::string>& excluded_urls = {});
// Keep semantic link exclusions before sanitization removes HTML markers.
std::vector<std::string> previewExcludedUrlsFromHtml(std::string_view html);
// Combine original HTML markers with structured mentions, tags, and media.
std::vector<std::string> previewExcludedUrlsForObject(
    const nlohmann::json& object);
// Extract head metadata; relative images resolve against the final page URL.
LinkPreview parsePreviewHtml(std::string_view html, std::string_view final_url,
                             std::string_view origin,
                             const char* encoding = nullptr);
// Fetch only HTML, with explicit redirects and resolved-address filtering.
PreviewResult fetchLinkPreview(mw::HTTPSessionInterface& http,
                                std::string_view url,
                                std::string_view origin);

// Application database used by the scheduler, independent of federation jobs.
class DataSourceSQLite;
// Injectable attempt function for deterministic worker tests.
using PreviewFetcher = std::function<PreviewResult(
    std::string_view, std::string_view)>;

// Single-thread-owned bounded scheduling state; no retry state is persisted.
class LinkPreviewQueue
{
public:
    // Scan committed work, preserving ownership of queued/running IDs.
    mw::E<void> recover(const DataSourceSQLite& data);
    // Perform at most one due attempt or database save; false means idle.
    mw::E<bool> runOnce(const DataSourceSQLite& data,
        const PreviewFetcher& fetch, std::string_view origin,
        std::chrono::steady_clock::time_point now);
    // IDs protected from collection, including delayed and unsaved results.
    std::vector<int64_t> activeIds() const;
    // Number of distinct queued/running rows.
    size_t size() const { return queue.size(); }
    // Earliest due work, bounded by the next recovery deadline.
    std::chrono::steady_clock::time_point nextDeadline(
        std::chrono::steady_clock::time_point scan_deadline) const;

private:
    struct Work
    {
        int attempts = 0;
        std::chrono::steady_clock::time_point due{};
        std::optional<LinkPreview> completed;
    };
    std::map<int64_t, Work> queue;
    int64_t scan_cursor = 0;
};

// One application worker with bounded, deduplicated in-memory retry state.
class LinkPreviewWorker
{
public:
    // Copy configuration; the worker owns its database connection.
    explicit LinkPreviewWorker(const Config& config);
    // Join before releasing worker-owned resources.
    ~LinkPreviewWorker();
    // Start once, independently of federation worker count.
    void start();
    // Wake recovery after committed application changes.
    void wake();
    // Stop accepting work and wait for the bounded active request.
    void stop();

private:
    void run();
    Config config;
    std::mutex mutex;
    std::condition_variable condition;
    bool stopping = false;
    bool notified = false;
    std::thread thread;
};
} // namespace unspoken
