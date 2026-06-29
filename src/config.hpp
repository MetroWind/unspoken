#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

#include <mw/error.hpp>

#ifndef UNSPOKEN_DEFAULT_EMOJI_DATA_FILE
#define UNSPOKEN_DEFAULT_EMOJI_DATA_FILE "data/emoji_categories.json"
#endif

// Server configuration, loaded from a YAML file at startup (design §5).
//
// The defaults below match the documented schema defaults. Required
// fields (url_root, oidc.*) have no usable default and are validated in
// fromYaml().
struct OidcConfig
{
    std::string issuer;
    std::string client_id;
    std::string client_secret;
    std::string scopes = "openid profile";
};

struct NodeInfoConfig
{
    std::string software_name = "unspoken";
    bool open_registrations = true;
    std::string description = "";
};

struct Config
{
    // ─── Network / identity ──────────────────────────────────────
    // REQUIRED. Normalized to exactly one trailing slash. All actor
    // IDs and AP endpoints are sub-URLs of this.
    std::string url_root;
    // Bare domain for @handles. Defaults to the host of url_root.
    std::string public_domain;
    std::string listen_address = "127.0.0.1";
    int listen_port = 8080;
    // Enable debug logging, including full federation request/response
    // headers and bodies.
    bool verbose = false;

    // ─── Storage ─────────────────────────────────────────────────
    std::string database_path = "unspoken.db";
    std::string attachment_dir = "attachments";
    std::string emoji_dir = "emoji";
    std::string emoji_data_file = UNSPOKEN_DEFAULT_EMOJI_DATA_FILE;
    // Where Inja templates and static assets live. App-level dirs (not
    // in the PRD schema, but needed to serve the UI).
    std::string template_dir = "templates";
    std::string static_dir = "static";

    // ─── Pagination ──────────────────────────────────────────────
    int posts_per_page = 20;

    // ─── Federation tuning ───────────────────────────────────────
    int http_signature_skew_seconds = 300;
    int thread_fetch_max_depth = 20;
    int sqlite_busy_timeout_ms = 5000;

    // ─── Job queue ───────────────────────────────────────────────
    int job_workers = 4;
    int job_max_retries = 8;
    int job_retry_base_delay_seconds = 30;

    // ─── Uploads ─────────────────────────────────────────────────
    int64_t max_upload_bytes = 10485760; // 10 MiB

    // ─── OpenID Connect (Keycloak) ───────────────────────────────
    OidcConfig oidc;

    // ─── NodeInfo ────────────────────────────────────────────────
    NodeInfoConfig nodeinfo;

    // Parse and validate a config from a YAML file. A malformed or
    // incomplete config is a fatal error (returned, not thrown).
    static mw::E<Config> fromYaml(const std::filesystem::path& path);

    // Validate an already-populated config and apply derived defaults
    // (e.g. public_domain fallback, url_root normalization). Exposed
    // separately so tests can validate a hand-built Config.
    mw::E<void> validateAndFinalize();
};
