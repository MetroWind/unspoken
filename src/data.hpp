#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "data_types.hpp"
#include "database.hpp"
#include "error.hpp"

class DataSourceInterface
{
public:
    // Create a new local user.
    virtual E<void> createUser(std::string_view name) = 0;
    // Find a local user by name (no server part);
    virtual E<std::optional<LocalUser>> getUser(std::string_view name) = 0;
    // Create a post, or modify a post if “p” has an post ID.
    virtual E<void> post(Post&& p) = 0;
    // Remove a post. This does not delete attachment files.
    virtual E<void> deletePost(uint64_t id) = 0;
    // Retrieve a timeline of posts.
    virtual E<std::vector<Post>> getTimeline(const TimelineSpec& spec) = 0;
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

class DataSourceSQLite : public DataSourceInterface
{
public:
    static E<std::unique_ptr<DataSourceSQLite>> newFromMemory();
    static E<std::unique_ptr<DataSourceSQLite>>
    fromDBFile(const std::string& f);

    DataSourceSQLite(const DataSourceSQLite&) = delete;
    DataSourceSQLite& operator=(const DataSourceSQLite&) = delete;

    E<void> createUser(std::string_view name) override;
    E<std::optional<LocalUser>> getUser(std::string_view name) override;
    E<void> post(Post&& p) override;
    E<void> deletePost(uint64_t id) override;
    E<vector<Post>> getTimeline(const TimelineSpec& spec) override;
    E<void> follow(std::string_view follower, std::string_view followee) override;
    E<void> like(std::string_view user, std::string_view post_url) override;
    E<void> boost(std::string_view user, std::string_view post_url) override;

    // Do not use.
    DataSourceSQLite() = default;

private:
    E<void> setupTables() const;
    E<void> addRemotePost(const Post& p) const;
    E<void> addLocalPost(const Post& p) const;
    E<std::vector<int64_t>> findPostsByAttachment(const Attachment& att) const;
    E<void> addAttachment(int64_t post_id, const Attachment& att) const;
    E<void> updateAttachments(
        int64_t post_id, std::span<Attachment> attachments) const;

    std::unique_ptr<SQLite> db;
};
