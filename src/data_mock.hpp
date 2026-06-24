#pragma once

// A gmock implementation of DataSourceInterface, so federation/app
// logic can be unit-tested without a real SQLite database (design §19,
// plan Phase 1).

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <gmock/gmock.h>
#include <mw/error.hpp>

#include "data.hpp"
#include "structs.hpp"

namespace unspoken
{

class DataSourceMock : public DataSourceInterface
{
public:
    MOCK_METHOD(mw::E<int64_t>, getSchemaVersion, (), (const, override));

    MOCK_METHOD(mw::E<User>, createUser, (const NewUser&), (const, override));
    MOCK_METHOD(mw::E<std::optional<User>>, getUserById, (int64_t),
                (const, override));
    MOCK_METHOD(mw::E<std::optional<User>>, getUserByUsername,
                (std::string_view), (const, override));
    MOCK_METHOD(mw::E<std::optional<User>>, getUserByOidcSub,
                (std::string_view, std::string_view), (const, override));
    MOCK_METHOD(mw::E<void>, updateUserProfile,
                (int64_t, std::string_view, std::string_view),
                (const, override));
    MOCK_METHOD(mw::E<std::vector<User>>, searchUsers,
                (std::string_view, int), (const, override));

    MOCK_METHOD(mw::E<std::optional<SystemActor>>, getSystemActor, (),
                (const, override));
    MOCK_METHOD(mw::E<void>, setSystemActor,
                (std::string_view, std::string_view), (const, override));

    MOCK_METHOD(mw::E<RemoteActor>, upsertRemoteActor, (const RemoteActor&),
                (const, override));
    MOCK_METHOD(mw::E<std::optional<RemoteActor>>, getRemoteActorById,
                (int64_t), (const, override));
    MOCK_METHOD(mw::E<std::optional<RemoteActor>>, getRemoteActorByUri,
                (std::string_view), (const, override));

    MOCK_METHOD(mw::E<Post>, insertPost,
                (const NewPost&, (const std::vector<PostRecipient>&),
                 std::string_view),
                (const, override));
    MOCK_METHOD(mw::E<std::optional<Post>>, getPostById, (int64_t),
                (const, override));
    MOCK_METHOD(mw::E<std::optional<Post>>, getPostByUri, (std::string_view),
                (const, override));
    MOCK_METHOD(mw::E<void>, deletePost, (int64_t), (const, override));
    MOCK_METHOD(mw::E<std::vector<PostRecipient>>, getPostRecipients,
                (int64_t), (const, override));
    MOCK_METHOD(mw::E<std::vector<Post>>, timelinePublic,
                (const Cursor&, int), (const, override));
    MOCK_METHOD(mw::E<std::vector<Post>>, timelineHome,
                (int64_t, const Cursor&, int), (const, override));
    MOCK_METHOD(mw::E<std::vector<Post>>, postsForAuthors,
                ((const std::vector<int64_t>&), const Cursor&, int),
                (const, override));
    MOCK_METHOD(mw::E<std::vector<Post>>, homeTimelinePosts,
                ((const std::vector<int64_t>&), int64_t, const Cursor&, int,
                 std::string_view),
                (const, override));
    MOCK_METHOD(mw::E<std::vector<Post>>, threadFor, (std::string_view),
                (const, override));

    MOCK_METHOD(mw::E<void>, addFollow, (const Follow&), (const, override));
    MOCK_METHOD(mw::E<std::optional<Follow>>, getFollow,
                (std::string_view, std::string_view), (const, override));
    MOCK_METHOD(mw::E<void>, setFollowState,
                (std::string_view, std::string_view, FollowState),
                (const, override));
    MOCK_METHOD(mw::E<void>, removeFollow,
                (std::string_view, std::string_view), (const, override));
    MOCK_METHOD(mw::E<std::vector<std::string>>, followerUris,
                (std::string_view), (const, override));
    MOCK_METHOD(mw::E<std::vector<std::string>>, followingUris,
                (std::string_view), (const, override));
    MOCK_METHOD(mw::E<std::vector<ActorCollectionItem>>, followerPage,
                (std::string_view, const Cursor&, int), (const, override));
    MOCK_METHOD(mw::E<std::vector<ActorCollectionItem>>, followingPage,
                (std::string_view, const Cursor&, int), (const, override));

    MOCK_METHOD(mw::E<void>, addLike, (const Like&), (const, override));
    MOCK_METHOD(mw::E<void>, removeLike,
                (std::string_view, std::string_view), (const, override));
    MOCK_METHOD(mw::E<std::vector<Like>>, likesForPost, (std::string_view),
                (const, override));

    MOCK_METHOD(mw::E<void>, addBoost, (const Boost&), (const, override));
    MOCK_METHOD(mw::E<void>, removeBoost,
                (std::string_view, std::string_view), (const, override));

    MOCK_METHOD(mw::E<void>, addReaction, (const Reaction&), (const, override));
    MOCK_METHOD(mw::E<void>, removeReaction,
                (std::string_view, std::string_view, std::string_view),
                (const, override));
    MOCK_METHOD(mw::E<std::vector<Reaction>>, reactionsForPost,
                (std::string_view), (const, override));

    MOCK_METHOD(mw::E<void>, addBookmark, (int64_t, int64_t),
                (const, override));
    MOCK_METHOD(mw::E<void>, removeBookmark, (int64_t, int64_t),
                (const, override));
    MOCK_METHOD(mw::E<bool>, isBookmarked, (int64_t, int64_t),
                (const, override));
    MOCK_METHOD(mw::E<std::vector<Post>>, bookmarksFor,
                (int64_t, const Cursor&, int), (const, override));

    MOCK_METHOD(mw::E<int64_t>, insertAttachment, (const Attachment&),
                (const, override));
    MOCK_METHOD(mw::E<void>, attachToPost, (int64_t, int64_t),
                (const, override));
    MOCK_METHOD(mw::E<std::vector<Attachment>>, attachmentsForPost,
                (int64_t), (const, override));

    MOCK_METHOD(mw::E<void>, createSession,
                (std::string_view, int64_t, int64_t), (const, override));
    MOCK_METHOD(mw::E<std::optional<int64_t>>, getSessionUser,
                (std::string_view, int64_t), (const, override));
    MOCK_METHOD(mw::E<void>, deleteSession, (std::string_view),
                (const, override));

    MOCK_METHOD(mw::E<void>, addPendingLogin,
                (std::string_view, std::string_view, int64_t),
                (const, override));
    MOCK_METHOD(mw::E<std::optional<std::string>>, takePendingLogin,
                (std::string_view), (const, override));

    MOCK_METHOD(mw::E<bool>, markActivitySeen, (std::string_view, int64_t),
                (const, override));

    MOCK_METHOD(mw::E<int64_t>, enqueueJob,
                (std::string_view, std::string_view, int64_t, int64_t),
                (const, override));
    MOCK_METHOD(mw::E<std::optional<Job>>, claimJob, (int64_t),
                (const, override));
    MOCK_METHOD(mw::E<void>, completeJob, (int64_t), (const, override));
    MOCK_METHOD(mw::E<void>, failJob,
                (int64_t, std::string_view, int64_t, int, int),
                (const, override));

protected:
    MOCK_METHOD(mw::E<void>, setSchemaVersion, (int64_t), (const, override));
};

} // namespace unspoken
