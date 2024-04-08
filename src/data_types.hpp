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

struct Post
{
    std::optional<int64_t> id;
    enum Visibility { PUBLIC, FOLLOWER_ONLY, PRIVATE };
    std::string author;
    Visibility visibility;
    Time time_creation;
    Time time_update;
    std::string content;
    std::vector<Attachment> attachments;
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
