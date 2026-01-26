#pragma once

#include <string>
#include <memory>
#include <vector>
#include <optional>
#include <mw/database.hpp>
#include <mw/error.hpp>
#include "types.hpp"

class Database
{
public:
    explicit Database(const std::string& path);
    mw::E<void> init();

    // User DAO
    mw::E<int64_t> createUser(const User& user);
    mw::E<std::optional<User>> getUserById(int64_t id);
    mw::E<std::optional<User>> getUserByUsername(const std::string& username);
    mw::E<std::optional<User>> getUserByUri(const std::string& uri);
    mw::E<std::optional<User>> getUserByOidcSubject(const std::string& sub);

    // Post DAO
    mw::E<int64_t> createPost(const Post& post);
    mw::E<std::optional<Post>> getPostById(int64_t id);
    mw::E<std::optional<Post>> getPostByUri(const std::string& uri);
    mw::E<std::vector<Post>> getTimeline(int64_t user_id, int limit,
                                         int offset);
    mw::E<std::vector<Post>> getPublicTimeline(int limit, int offset);

    // Follow DAO
    mw::E<void> createFollow(const Follow& follow);
    mw::E<void> updateFollowStatus(int64_t follower_id, int64_t target_id,
                                   int status);
    mw::E<std::optional<Follow>> getFollow(int64_t follower_id,
                                           int64_t target_id);

    // Job DAO
    mw::E<int64_t> enqueueJob(const Job& job);
    mw::E<std::vector<Job>> getPendingJobs(int limit);
    mw::E<void> updateJob(int64_t id, int status, int attempts,
                          int64_t next_try);
    mw::E<void> deleteJob(int64_t id);

    // Session DAO
    mw::E<void> createSession(const Session& session);
    mw::E<std::optional<Session>> getSession(const std::string& token);
    mw::E<void> deleteSession(const std::string& token);

private:
    std::string db_path;
    std::unique_ptr<mw::SQLite> db;

    mw::E<void> migrate();
};
