#pragma once

#include <string>
#include <memory>
#include <vector>
#include <optional>
#include <mw/database.hpp>
#include <mw/error.hpp>
#include "types.hpp"

class DatabaseInterface
{
public:
    virtual ~DatabaseInterface() = default;
    virtual mw::E<void> init() = 0;

    // User DAO
    virtual mw::E<int64_t> createUser(const User& user) = 0;
    virtual mw::E<void> updateUser(const User& user) = 0;
    virtual mw::E<std::optional<User>> getUserById(int64_t id) = 0;
    virtual mw::E<std::optional<User>> getUserByUsername(const std::string& username) = 0;
    virtual mw::E<std::optional<User>> getUserByUri(const std::string& uri) = 0;
    virtual mw::E<std::optional<User>> getUserByOidcSubject(const std::string& sub) = 0;

    // Post DAO
    virtual mw::E<int64_t> createPost(const Post& post) = 0;
    virtual mw::E<std::optional<Post>> getPostById(int64_t id) = 0;
    virtual mw::E<std::optional<Post>> getPostByUri(const std::string& uri) = 0;
    virtual mw::E<std::vector<Post>> getTimeline(int64_t user_id, int limit,
                                                 int offset) = 0;
    virtual mw::E<std::vector<Post>> getUserPosts(int64_t author_id, int limit,
                                                  int offset) = 0;
    virtual mw::E<std::vector<Post>> getPublicTimeline(int limit, int offset) = 0;

    // Follow DAO
    virtual mw::E<void> createFollow(const Follow& follow) = 0;
    virtual mw::E<void> updateFollowStatus(int64_t follower_id, int64_t target_id,
                                           int status) = 0;
    virtual mw::E<std::optional<Follow>> getFollow(int64_t follower_id,
                                                   int64_t target_id) = 0;
    virtual mw::E<std::vector<User>> getFollowers(int64_t target_id) = 0;

    // Media DAO
    virtual mw::E<int64_t> createMedia(const Media& media) = 0;
    virtual mw::E<std::optional<Media>> getMediaByHash(const std::string& hash) = 0;

    // Job DAO
    virtual mw::E<int64_t> enqueueJob(const Job& job) = 0;
    virtual mw::E<std::vector<Job>> getPendingJobs(int limit) = 0;
    virtual mw::E<void> updateJob(int64_t id, int status, int attempts,
                                  int64_t next_try) = 0;
    virtual mw::E<void> deleteJob(int64_t id) = 0;

    // Session DAO
    virtual mw::E<void> createSession(const Session& session) = 0;
    virtual mw::E<std::optional<Session>> getSession(const std::string& token) = 0;
    virtual mw::E<void> deleteSession(const std::string& token) = 0;

    // System Config DAO
    virtual mw::E<std::optional<std::string>> getSystemConfig(const std::string& key) = 0;
    virtual mw::E<void> setSystemConfig(const std::string& key, const std::string& value) = 0;
};

class Database : public DatabaseInterface
{
public:
    explicit Database(const std::string& path);
    mw::E<void> init() override;

    // User DAO
    mw::E<int64_t> createUser(const User& user) override;
    mw::E<void> updateUser(const User& user) override;
    mw::E<std::optional<User>> getUserById(int64_t id) override;
    mw::E<std::optional<User>> getUserByUsername(const std::string& username) override;
    mw::E<std::optional<User>> getUserByUri(const std::string& uri) override;
    mw::E<std::optional<User>> getUserByOidcSubject(const std::string& sub) override;

    // Post DAO
    mw::E<int64_t> createPost(const Post& post) override;
    mw::E<std::optional<Post>> getPostById(int64_t id) override;
    mw::E<std::optional<Post>> getPostByUri(const std::string& uri) override;
    mw::E<std::vector<Post>> getTimeline(int64_t user_id, int limit,
                                         int offset) override;
    mw::E<std::vector<Post>> getUserPosts(int64_t author_id, int limit,
                                          int offset) override;
    mw::E<std::vector<Post>> getPublicTimeline(int limit, int offset) override;

    // Follow DAO
    mw::E<void> createFollow(const Follow& follow) override;
    mw::E<void> updateFollowStatus(int64_t follower_id, int64_t target_id,
                                   int status) override;
    mw::E<std::optional<Follow>> getFollow(int64_t follower_id,
                                           int64_t target_id) override;
    mw::E<std::vector<User>> getFollowers(int64_t target_id) override;

    // Media DAO
    mw::E<int64_t> createMedia(const Media& media) override;
    mw::E<std::optional<Media>> getMediaByHash(const std::string& hash) override;

    // Job DAO
    mw::E<int64_t> enqueueJob(const Job& job) override;
    mw::E<std::vector<Job>> getPendingJobs(int limit) override;
    mw::E<void> updateJob(int64_t id, int status, int attempts,
                          int64_t next_try) override;
    mw::E<void> deleteJob(int64_t id) override;

    // Session DAO
    mw::E<void> createSession(const Session& session) override;
    mw::E<std::optional<Session>> getSession(const std::string& token) override;
    mw::E<void> deleteSession(const std::string& token) override;

    // System Config DAO
    mw::E<std::optional<std::string>> getSystemConfig(const std::string& key) override;
    mw::E<void> setSystemConfig(const std::string& key, const std::string& value) override;

private:
    std::string db_path;
    std::unique_ptr<mw::SQLite> db;

    mw::E<void> migrate();
};
