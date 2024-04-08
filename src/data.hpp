#pragma once

#include <optional>
#include <string_view>

#include "data_types.hpp"
#include "error.hpp"

class DataSourceInterface
{
public:
    // Find a local user by name (no server part);
    virtual E<std::optional<LocalUser>> getUser(std::string_view name) = 0;
    // Create a post, or modify a post if “p” has an post ID.
    virtual E<void> post(Post&& p) = 0;
    // Remove a post.
    virtual E<void> deletePost(std::string_view post_url) = 0;
    // Retrieve a timeline of posts.
    virtual E<vector<Post>> getTimeline(const TimelineSpec& spec) = 0;
    // Execute a follow. “Follower” and “followee” are full user IDs.
    // This, along with like() and boost(), could happen in three
    // ways:
    //
    // - local to remote
    // - remote to local
    // - local to local
    virtual E<void> follow(std::string_view follower, std::string_view followee)
    = 0;
    // Execute a like. “User” is a full ID.
    virtual E<void> like(std::string_view user, std::string_view post_url) = 0;
    // Execute a boost (repost). “User” is a full ID.
    virtual E<void> boost(std::string_view user, std::string_view post_url) = 0;
};
