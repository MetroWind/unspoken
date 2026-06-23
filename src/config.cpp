#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <utility>
#include <vector>

#include <ryml.hpp>
#include <ryml_std.hpp>
#include <mw/error.hpp>
#include <mw/url.hpp>

#include "config.hpp"

namespace
{

ryml::ConstNodeRef child(const ryml::ConstNodeRef& node, const char* name)
{
    if(!node.readable() || !node.is_map())
    {
        return {};
    }
    return node.find_child(ryml::to_csubstr(name));
}

mw::E<std::vector<char>> readFile(const std::filesystem::path& path)
{
    std::ifstream f(path, std::ios::binary);
    if(!f)
    {
        return std::unexpected(mw::runtimeError(
            std::format("Failed to open config file {}", path.string())));
    }
    std::vector<char> content;
    content.assign(std::istreambuf_iterator<char>(f),
                   std::istreambuf_iterator<char>());
    if(f.bad())
    {
        return std::unexpected(mw::runtimeError(
            std::format("Failed to read config file {}", path.string())));
    }
    return content;
}

// Read an integer YAML node into “out” if present.
void readInt(const ryml::ConstNodeRef& node, int& out)
{
    if(node.readable() && node.has_val())
    {
        node.load(&out);
    }
}

void readInt64(const ryml::ConstNodeRef& node, int64_t& out)
{
    if(node.readable() && node.has_val())
    {
        node.load(&out);
    }
}

void readStr(const ryml::ConstNodeRef& node, std::string& out)
{
    if(node.readable() && node.has_val())
    {
        node.load(&out);
    }
}

void readBool(const ryml::ConstNodeRef& node, bool& out)
{
    if(node.readable() && node.has_val())
    {
        node.load(&out);
    }
}

} // namespace

mw::E<void> Config::validateAndFinalize()
{
    // url_root is required and must be a valid absolute https URL.
    if(url_root.empty())
    {
        return std::unexpected(mw::runtimeError("url_root is required"));
    }
    auto parsed = mw::URL::fromStr(url_root);
    if(!parsed.has_value())
    {
        return std::unexpected(mw::runtimeError(
            std::format("url_root is not a valid URL: {}", url_root)));
    }
    if(parsed->scheme() != "https")
    {
        return std::unexpected(mw::runtimeError(
            std::format("url_root must be an https URL: {}", url_root)));
    }
    if(parsed->host().empty())
    {
        return std::unexpected(mw::runtimeError(
            std::format("url_root has no host: {}", url_root)));
    }
    // Normalize to exactly one trailing slash so URL construction
    // elsewhere (url_root + "u/" + name) never double-slashes.
    while(!url_root.empty() && url_root.back() == '/')
    {
        url_root.pop_back();
    }
    url_root.push_back('/');

    // public_domain defaults to the host of url_root.
    if(public_domain.empty())
    {
        public_domain = parsed->host();
    }

    // All numeric tuning params must be positive.
    struct { const char* name; int value; } positives[] = {
        {"listen_port", listen_port},
        {"posts_per_page", posts_per_page},
        {"http_signature_skew_seconds", http_signature_skew_seconds},
        {"thread_fetch_max_depth", thread_fetch_max_depth},
        {"sqlite_busy_timeout_ms", sqlite_busy_timeout_ms},
        {"job_workers", job_workers},
        {"job_max_retries", job_max_retries},
        {"job_retry_base_delay_seconds", job_retry_base_delay_seconds},
    };
    for(const auto& p : positives)
    {
        if(p.value <= 0)
        {
            return std::unexpected(mw::runtimeError(
                std::format("{} must be positive (got {})", p.name, p.value)));
        }
    }
    if(max_upload_bytes <= 0)
    {
        return std::unexpected(mw::runtimeError(
            "max_upload_bytes must be positive"));
    }

    // OIDC fields are required.
    if(oidc.issuer.empty() || oidc.client_id.empty() ||
       oidc.client_secret.empty())
    {
        return std::unexpected(mw::runtimeError(
            "oidc.issuer, oidc.client_id, and oidc.client_secret are "
            "required"));
    }

    // The database parent directory and attachment dir must exist and
    // be writable.
    std::error_code ec;
    std::filesystem::path db_parent =
        std::filesystem::path(database_path).parent_path();
    if(db_parent.empty())
    {
        db_parent = ".";
    }
    if(!std::filesystem::is_directory(db_parent, ec))
    {
        return std::unexpected(mw::runtimeError(std::format(
            "database_path parent directory does not exist: {}",
            db_parent.string())));
    }

    return {};
}

mw::E<Config> Config::fromYaml(const std::filesystem::path& path)
{
    auto buffer = readFile(path);
    if(!buffer.has_value())
    {
        return std::unexpected(buffer.error());
    }

    ryml::Tree tree = ryml::parse_in_place(ryml::to_substr(*buffer));
    ryml::ConstNodeRef root = tree.crootref();

    Config config;
    readStr(child(root, "url_root"), config.url_root);
    readStr(child(root, "public_domain"), config.public_domain);
    readStr(child(root, "listen_address"), config.listen_address);
    readInt(child(root, "listen_port"), config.listen_port);

    readStr(child(root, "database_path"), config.database_path);
    readStr(child(root, "attachment_dir"), config.attachment_dir);
    readStr(child(root, "emoji_dir"), config.emoji_dir);
    readStr(child(root, "template_dir"), config.template_dir);
    readStr(child(root, "static_dir"), config.static_dir);

    readInt(child(root, "posts_per_page"), config.posts_per_page);

    readInt(child(root, "http_signature_skew_seconds"),
            config.http_signature_skew_seconds);
    readInt(child(root, "thread_fetch_max_depth"),
            config.thread_fetch_max_depth);
    readInt(child(root, "sqlite_busy_timeout_ms"),
            config.sqlite_busy_timeout_ms);

    readInt(child(root, "job_workers"), config.job_workers);
    readInt(child(root, "job_max_retries"), config.job_max_retries);
    readInt(child(root, "job_retry_base_delay_seconds"),
            config.job_retry_base_delay_seconds);

    readInt64(child(root, "max_upload_bytes"), config.max_upload_bytes);

    ryml::ConstNodeRef oidc = child(root, "oidc");
    if(oidc.readable() && oidc.is_map())
    {
        readStr(child(oidc, "issuer"), config.oidc.issuer);
        readStr(child(oidc, "client_id"), config.oidc.client_id);
        readStr(child(oidc, "client_secret"), config.oidc.client_secret);
        readStr(child(oidc, "scopes"), config.oidc.scopes);
    }

    ryml::ConstNodeRef ni = child(root, "nodeinfo");
    if(ni.readable() && ni.is_map())
    {
        readStr(child(ni, "software_name"), config.nodeinfo.software_name);
        readBool(child(ni, "open_registrations"),
                 config.nodeinfo.open_registrations);
        readStr(child(ni, "description"), config.nodeinfo.description);
    }

    auto valid = config.validateAndFinalize();
    if(!valid.has_value())
    {
        return std::unexpected(valid.error());
    }
    return config;
}
