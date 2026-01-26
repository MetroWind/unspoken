#pragma once

#include <string>
#include <optional>
#include <vector>
#include <cstdint>

enum class Visibility : int
{
    Public = 0,
    Unlisted = 1,
    Followers = 2,
    Direct = 3
};

struct User
{
    int64_t id;
    std::string username;
    std::string display_name;
    std::string bio;
    std::optional<std::string> email;
    std::string uri;
    std::string public_key;
    std::optional<std::string> private_key;
    std::optional<std::string> host;
    int64_t created_at;
    std::optional<std::string> avatar_path;

    bool is_local() const { return !host.has_value(); }
};

struct Post
{
    int64_t id;
    std::string uri;
    int64_t author_id;
    std::string content_html;
    std::string content_source;
    std::optional<std::string> in_reply_to_uri;
    Visibility visibility;
    int64_t created_at;
    bool is_local;
};

struct Follow
{
    int64_t follower_id;
    int64_t target_id;
    int status; // 0=Pending, 1=Accepted
    std::string uri;
};

struct Like
{
    int64_t user_id;
    int64_t post_id;
    int64_t created_at;
};

struct Job
{
    int64_t id;
    std::string type;
    std::string payload; // JSON
    int attempts;
    int64_t next_try;
    int status; // 0=Pending, 1=Processing, 2=Failed
};

struct Media
{
    int64_t id;
    std::string hash;
    std::string filename;
    std::string mime_type;
    int64_t uploader_id;
};
