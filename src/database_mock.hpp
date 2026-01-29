#pragma once
#include <gmock/gmock.h>
#include "database.hpp"

class DatabaseMock : public DatabaseInterface {
public:
    MOCK_METHOD(mw::E<void>, init, (), (override));
    MOCK_METHOD(mw::E<int64_t>, createUser, (const User&), (override));
    MOCK_METHOD(mw::E<void>, updateUser, (const User&), (override));
    MOCK_METHOD(mw::E<std::optional<User>>, getUserById, (int64_t), (override));
    MOCK_METHOD(mw::E<std::optional<User>>, getUserByUsername, (const std::string&), (override));
    MOCK_METHOD(mw::E<std::optional<User>>, getUserByUri, (const std::string&), (override));
    MOCK_METHOD(mw::E<std::optional<User>>, getUserByOidcSubject, (const std::string&), (override));
    MOCK_METHOD(mw::E<int64_t>, createPost, (const Post&), (override));
    MOCK_METHOD(mw::E<std::optional<Post>>, getPostById, (int64_t), (override));
    MOCK_METHOD(mw::E<std::optional<Post>>, getPostByUri, (const std::string&), (override));
    MOCK_METHOD(mw::E<std::vector<Post>>, getTimeline, (int64_t, int, int), (override));
    MOCK_METHOD(mw::E<std::vector<Post>>, getUserPosts, (int64_t, int, int), (override));
    MOCK_METHOD(mw::E<std::vector<Post>>, getPublicTimeline, (int, int), (override));
    MOCK_METHOD(mw::E<void>, createFollow, (const Follow&), (override));
    MOCK_METHOD(mw::E<void>, updateFollowStatus, (int64_t, int64_t, int), (override));
    MOCK_METHOD(mw::E<std::optional<Follow>>, getFollow, (int64_t, int64_t), (override));
    MOCK_METHOD(mw::E<std::vector<User>>, getFollowers, (int64_t), (override));
    MOCK_METHOD(mw::E<int64_t>, createMedia, (const Media&), (override));
    MOCK_METHOD(mw::E<std::optional<Media>>, getMediaByHash, (const std::string&), (override));
    MOCK_METHOD(mw::E<int64_t>, enqueueJob, (const Job&), (override));
    MOCK_METHOD(mw::E<std::vector<Job>>, getPendingJobs, (int), (override));
    MOCK_METHOD(mw::E<void>, updateJob, (int64_t, int, int, int64_t), (override));
    MOCK_METHOD(mw::E<void>, deleteJob, (int64_t), (override));
    MOCK_METHOD(mw::E<void>, createSession, (const Session&), (override));
    MOCK_METHOD(mw::E<std::optional<Session>>, getSession, (const std::string&), (override));
    MOCK_METHOD(mw::E<void>, deleteSession, (const std::string&), (override));
};
