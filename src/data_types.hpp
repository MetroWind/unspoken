#pragma once

#include <vector>
#include <string>
#include <format>
#include <string_view>
#include <optional>

#include "crypto.hpp"
#include "utils.hpp"

struct Attachment
{
    std::string file;
};

struct FediUser
{
    std::string name;
    // If server is empty, it’s a local user.
    std::string server;

    // Parse a user ID from the fediverse. A user ID looks like
    // “name@server.com”, or “@name@server.com”.
    static E<FediUser> fromStr(std::string_view s);

    std::string idStr() const
    {
        if(server.empty())
        {
            return name;
        }
        else
        {
            return std::format("{}@{}", name, server);
        }
    }
};

struct LocalUser
{
    std::string name;
    std::string desc;
    Attachment avatar;
    Time time_join;
    KeyPair keys;
};

// Local posts use “id” as unique ID; remote posts use “remote_url”.
struct Post
{
    std::optional<int64_t> id;
    enum Visibility { PUBLIC, FOLLOWER_ONLY, PRIVATE };
    std::string author;
    Visibility visibility = PUBLIC;
    Time time_creation;
    // Initially this will equal time_creation.
    Time time_update;
    // For local posts this is markdown. For remote posts this is
    // HTML.
    std::string content;
    // Only local posts have this.
    std::vector<Attachment> attachments;
    // Only remote posts have this.
    std::vector<std::string> remote_attachments;
    // Only remote posts have this.
    std::string remote_url;

    bool remote() const
    {
        return !remote_url.empty();
    }
};

struct Like
{
    FediUser user;
    int64_t post_id;
};

struct Boost
{
    FediUser user;
    int64_t post_id;
};

struct Follow
{
    FediUser user;
    FediUser follower;
};

struct TimelineSpec
{
    enum TimelineType { USER_INDEX, USER };
    TimelineType type;
    // The local user this time line belongs to.
    std::string user;
    unsigned int begin = 0;
    unsigned int count;
};
