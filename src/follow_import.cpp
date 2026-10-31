#include "follow_import.hpp"

#include <algorithm>
#include <cctype>
#include <istream>
#include <ostream>
#include <set>
#include <thread>

#include <actpub/identity.hpp>
#include <actpub/transaction.hpp>
#include <mw/url.hpp>
#include <mw/utils.hpp>

#include "service.hpp"

namespace unspoken
{
namespace
{
struct FollowHandle
{
    std::string username;
    std::string domain;
    std::string account;
};

enum class ImportOutcome { QUEUED, LOCAL, SKIPPED };

std::string lower(std::string value)
{
    for(char& c : value)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

std::string trim(std::string value)
{
    const auto first = value.find_first_not_of(" \t\r\n");
    if(first == std::string::npos) return "";
    return value.substr(first,value.find_last_not_of(" \t\r\n")-first+1);
}

std::optional<FollowHandle> parseImportHandle(std::string_view value)
{
    if(value.starts_with('@')) value.remove_prefix(1);
    if(value.empty() || value.size() > 4096 ||
       std::any_of(value.begin(),value.end(),[](unsigned char c)
                   { return c <= 32 || c == 127; })) return {};
    auto separator = value.find('@');
    if(separator == std::string_view::npos || separator == 0 ||
       separator+1 == value.size() ||
       value.find('@',separator+1) != std::string_view::npos) return {};
    FollowHandle handle;
    handle.username = value.substr(0,separator);
    handle.domain = lower(std::string(value.substr(separator+1)));
    if(handle.username.find_first_of("/:?#,\\\"<>") != std::string::npos ||
       handle.domain.find_first_of("/:?#,\\\"<>") != std::string::npos)
        return {};
    auto domain_url = mw::URL::fromStr("https://"+handle.domain+"/");
    if(!domain_url || domain_url->host() != handle.domain ||
       !domain_url->user().empty() || !domain_url->password().empty()) return {};
    handle.account = "@"+handle.username+"@"+handle.domain;
    return handle;
}

mw::E<ImportOutcome> followTarget(
    const Config& config, const DataSourceSQLite& data,
    const User& user, const std::string& target,
    const std::optional<RemoteActor>& remote)
{
    const std::string follower = config.url_root+"u/"+user.username;
    if(follower == target) return ImportOutcome::SKIPPED;
    ASSIGN_OR_RETURN(auto transaction,ap::Transaction::begin(data.connection()));
    ASSIGN_OR_RETURN(auto existing,data.getFollow(follower,target));
    if(existing) return ImportOutcome::SKIPPED;
    EmojiRegistry emoji;
    Service service(config,data,emoji);
    if(!remote)
    {
        DO_OR_RETURN(service.setFollowActor(user,target,true));
        DO_OR_RETURN(transaction.commit());
        return ImportOutcome::LOCAL;
    }
    // Retention, pending state, outbox activity, and delivery job commit together.
    ASSIGN_OR_RETURN(auto retained,data.upsertRemoteActor(*remote));
    ASSIGN_OR_RETURN(auto activity_id,
                     ap::newActivityUri(config.url_root+"activities/follow/"));
    DO_OR_RETURN(service.setFollowActor(user,retained.uri,true,
                                        FollowState::PENDING,activity_id));
    DO_OR_RETURN(enqueueFollowActivity(config,data,user,retained.uri,activity_id,
                                       mw::timeToSeconds(mw::Clock::now())));
    DO_OR_RETURN(transaction.commit());
    return ImportOutcome::QUEUED;
}

mw::E<ImportOutcome> importHandle(
    const Config& config, const DataSourceSQLite& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system, const User& user, const FollowHandle& handle)
{
    auto root = mw::URL::fromStr(config.url_root);
    if(handle.domain == lower(config.public_domain) ||
       (root && handle.domain == lower(root->host())))
    {
        ASSIGN_OR_RETURN(auto local,data.getUserByUsername(handle.username));
        if(!local)
            return std::unexpected(mw::runtimeError("Local account not found"));
        return followTarget(config,data,user,
                             config.url_root+"u/"+local->username,std::nullopt);
    }
    DO_OR_RETURN(http.connectionTimeout(std::chrono::seconds(5)));
    DO_OR_RETURN(http.transferTimeout(std::chrono::seconds(20)));
    DO_OR_RETURN(http.maxSize(2*1024*1024));
    ASSIGN_OR_RETURN(auto actor,resolveWebFingerActor(config,data,crypto,http,
                                                     system,handle.account));
    // A remote handle may resolve to an actor hosted locally.
    const std::string local_prefix = config.url_root+"u/";
    if(actor.uri.starts_with(local_prefix))
    {
        ASSIGN_OR_RETURN(auto local,data.getUserByUsername(
            actor.uri.substr(local_prefix.size())));
        if(!local)
            return std::unexpected(mw::runtimeError("Local actor not found"));
        return followTarget(config,data,user,actor.uri,std::nullopt);
    }
    return followTarget(config,data,user,actor.uri,actor);
}
} // namespace

mw::E<FollowImportResult> importFollows(
    const Config& config, const DataSourceSQLite& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const User& user, std::istream& input, std::ostream& output,
    std::chrono::milliseconds interval)
{
    ASSIGN_OR_RETURN(auto system,data.getSystemActor());
    if(!system)
        return std::unexpected(mw::runtimeError("System actor is not initialized"));
    FollowImportResult result;
    std::set<std::string> seen;
    std::string line;
    int line_number = 0;
    bool first_lookup = true;
    while(std::getline(input,line))
    {
        ++line_number;
        if(line_number == 1 && line.starts_with("\xef\xbb\xbf"))
            line.erase(0,3);
        line = trim(std::move(line));
        if(line.empty() || line.starts_with('#')) continue;
        auto handle = parseImportHandle(line);
        if(!handle)
        {
            ++result.failed;
            output << "Line " << line_number << ": invalid account handle\n";
            continue;
        }
        if(!seen.insert(handle->account).second)
        {
            ++result.skipped;
            output << handle->account << ": duplicate, skipped\n";
            continue;
        }
        if(!first_lookup) std::this_thread::sleep_for(interval);
        first_lookup = false;
        output << handle->account << ": resolving..." << std::endl;
        auto imported = importHandle(config,data,crypto,http,*system,user,*handle);
        if(!imported)
        {
            ++result.failed;
            output << handle->account << ": failed: "
                   << mw::errorMsg(imported.error()) << std::endl;
            continue;
        }
        switch(*imported)
        {
        case ImportOutcome::QUEUED:
            ++result.queued;
            output << handle->account << ": follow queued\n";
            break;
        case ImportOutcome::LOCAL:
            ++result.local;
            output << handle->account << ": local follow added\n";
            break;
        case ImportOutcome::SKIPPED:
            ++result.skipped;
            output << handle->account << ": already followed or self, skipped\n";
            break;
        }
        output.flush();
    }
    if(input.bad())
        return std::unexpected(mw::runtimeError("Failed to read follow list"));
    return result;
}
} // namespace unspoken
