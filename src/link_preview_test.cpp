#include <gtest/gtest.h>
#include "link_preview.hpp"
#include "data.hpp"
#include "data_mock.hpp"
#include "emoji.hpp"
#include "service.hpp"
#include <filesystem>
#include <functional>
#include <inja.hpp>
#include <mw/test_utils.hpp>
#include <actpub/transaction.hpp>

namespace unspoken
{
TEST(LinkPreview, SelectFirstArticle)
{
    auto selected = selectPreviewUrl(
        "<a href='https://local.test/a'>self</a>"
        "<a class='mention' href='https://remote.test/u/a'>user</a>"
        "<a rel='tag' href='https://remote.test/t/a'>tag</a>"
        "<a href='https://remote.test/image'><img src='x'></a>"
        "<a href='HTTP://Example.COM:80/Path?a=1&amp;b=2#part'>@article</a>"
        "<a href='https://second.test/'>second</a>","https://local.test/","");
    ASSERT_TRUE(selected);
    EXPECT_EQ(*selected,"http://example.com/Path?a=1&b=2");
}

TEST(LinkPreview, NormalizeAndRejectUnsafeUrls)
{
    EXPECT_EQ(normalizePreviewUrl("https://EXAMPLE.com:443/A%2fb#x"),
              "https://example.com/A%2fb");
    for(const auto* value : {"/relative", "file:///etc/passwd",
        "https://user:pass@example.com/", "https://@example.com/",
        "http://127.0.0.1/", "http://0.0.0.0/", "http://[::]/",
        "http://[::ffff:127.0.0.1]/", "http://localhost/",
        "http://example.com:8080/", "http://169.254.169.254/"})
        EXPECT_FALSE(validatePreviewImageUrl(value)) << value;
    EXPECT_TRUE(normalizePreviewUrl("https://[2606:4700:4700::1111]/"));
}

TEST(LinkPreview, StructuredExclusions)
{
    EXPECT_EQ(selectPreviewUrl(
        "<a href='https://example.com/mention#x'>a</a>"
        "<a href='https://example.com/article'>#real title</a>","","",
        {"https://example.com/mention"}),"https://example.com/article");
}

TEST(LinkPreview, ExtractHeadOnlyAndResolveImage)
{
    auto preview = parsePreviewHtml(
        "<html><head><title>fallback</title>"
        "<META PROPERTY='OG:TITLE' content='  Fish &amp; Chips  '>"
        "<meta name='description' content='a   description'>"
        "<meta property='og:image' content='file:///tmp/no'>"
        "<meta property='og:image:url' content='../image.png'>"
        "<base href='https://evil.test/'></head>"
        "<body><meta property='og:title' content='body'></body></html>",
        "https://example.com/path/page","https://local.test/","UTF-8");
    EXPECT_EQ(preview.status,PreviewStatus::READY);
    EXPECT_EQ(preview.title,"Fish & Chips");
    EXPECT_EQ(preview.description,"a description");
    EXPECT_EQ(preview.image,"https://example.com/image.png");
    EXPECT_EQ(parsePreviewHtml("<body>body only</body>",
        "https://example.com/","").status,PreviewStatus::UNAVAILABLE);
}

TEST(LinkPreview, RejectUnspecifiedAndMappedPrivateIpv6)
{
    mw::SockAddr address;
    address.family = mw::AddressFamily::IPV6;
    address.address.resize(16);
    EXPECT_FALSE(isAllowedPreviewAddress(address));
    address.address[10] = 255;
    address.address[11] = 255;
    address.address[12] = 127;
    address.address[15] = 1;
    EXPECT_FALSE(isAllowedPreviewAddress(address));
    address.address[12] = 8;
    address.address[13] = 8;
    address.address[14] = 8;
    address.address[15] = 8;
    EXPECT_TRUE(isAllowedPreviewAddress(address));
}

namespace
{
// A real configured session whose transfer boundary is replaced by fixtures.
class PreviewHttpFake : public mw::HTTPSession
{
public:
    std::vector<mw::HTTPResponse> responses;
    std::vector<std::string> requested_urls;
    std::function<void()> during_request;
    bool blocked = false;

    mw::E<mw::HTTPResponse> getStream(
        const mw::HTTPRequest& request,mw::ChunkCallback consume) override
    {
        EXPECT_FALSE(followRedirects());
        EXPECT_EQ(connectionTimeout(),std::chrono::seconds(5));
        EXPECT_LE(transferTimeout(),std::chrono::seconds(30));
        EXPECT_EQ(request.header.size(),2u);
        EXPECT_TRUE(request.header.contains("User-Agent"));
        EXPECT_FALSE(request.header.contains("Authorization"));
        requested_urls.push_back(request.url);
        if(during_request) during_request();
        if(blocked)
            return std::unexpected(mw::runtimeError(mw::HTTP_BLOCKED_BY_POLICY));
        if(responses.empty())
            return std::unexpected(mw::runtimeError("connection failed"));
        auto response = responses.front();
        responses.erase(responses.begin());
        for(size_t offset = 0; offset < response.payload.size(); offset += 4096)
        {
            auto chunk = std::span<const std::byte>(response.payload).subspan(
                offset,std::min<size_t>(4096,response.payload.size()-offset));
            if(!consume(chunk))
                return std::unexpected(mw::runtimeError(mw::HTTP_ABORTED_BY_CALLER));
        }
        response.payload.clear();
        return response;
    }
};

mw::HTTPResponse htmlResponse(std::string_view html)
{
    mw::HTTPResponse response(200,html);
    response.header["Content-Type"] = "text/html; charset=UTF-8";
    return response;
}

NewPost previewPost(std::string_view url = "https://example.com/article")
{
    NewPost post;
    post.content_html = "<a href='" + std::string(url) + "'>article</a>";
    post.preview_origin = "https://local.test/";
    return post;
}

PreviewResult successfulPreview(std::string_view,std::string_view)
{
    PreviewResult result;
    result.failure = PreviewFailure::NONE;
    result.preview.title = "A title";
    result.preview.status = PreviewStatus::READY;
    return result;
}
} // namespace

TEST(LinkPreview, RedirectResolutionAndNoImageFetch)
{
    PreviewHttpFake http;
    mw::HTTPResponse redirect(302,"");
    redirect.header["Location"] = "http://other.test/path/page";
    http.responses = {redirect,htmlResponse(
        "<head><title>article</title>"
        "<meta property='og:image' content='../image'></head>")};
    auto result = fetchLinkPreview(http,"https://example.com/start","");
    EXPECT_EQ(result.failure,PreviewFailure::NONE);
    EXPECT_EQ(result.preview.url,"https://example.com/start");
    EXPECT_EQ(result.preview.image,"http://other.test/image");
    EXPECT_EQ(http.requested_urls.size(),2u);
}

TEST(LinkPreview, RejectRedirectToLocalAndAddressPolicyFailure)
{
    PreviewHttpFake http;
    mw::HTTPResponse redirect(302,"");
    redirect.header["location"] = "http://[::]/";
    http.responses = {redirect};
    EXPECT_EQ(fetchLinkPreview(http,"https://example.com/","").failure,
              PreviewFailure::PERMANENT);
    EXPECT_EQ(http.requested_urls.size(),1u);
    http.blocked = true;
    EXPECT_EQ(fetchLinkPreview(http,"https://example.com/","").failure,
              PreviewFailure::PERMANENT);
}

TEST(LinkPreview, BoundStreamingAndClassifyRetryAfter)
{
    PreviewHttpFake http;
    http.responses = {htmlResponse(std::string(1024*1024+1,'x'))};
    auto result = fetchLinkPreview(http,"https://example.com/","");
    EXPECT_EQ(result.failure,PreviewFailure::PERMANENT);
    mw::HTTPResponse retry(429,"");
    retry.header["Retry-After"] = "99999";
    http.responses = {retry};
    result = fetchLinkPreview(http,"https://example.com/","");
    EXPECT_EQ(result.failure,PreviewFailure::TRANSIENT);
    EXPECT_EQ(result.retry_after_seconds,3600);
    http.responses = {mw::HTTPResponse(404,"")};
    EXPECT_EQ(fetchLinkPreview(http,"https://example.com/","").failure,
              PreviewFailure::PERMANENT);
    EXPECT_EQ(fetchLinkPreview(http,"https://example.com/","").failure,
              PreviewFailure::TRANSIENT);
}

TEST(LinkPreview, EnforceRedirectLimitAndIgnoreNonHtml)
{
    PreviewHttpFake http;
    mw::HTTPResponse redirect(302,"");
    redirect.header["location"] = "/redirect";
    http.responses.assign(6,redirect);
    EXPECT_EQ(fetchLinkPreview(http,"https://example.com/","").failure,
              PreviewFailure::PERMANENT);
    EXPECT_EQ(http.requested_urls.size(),6u);
    auto response = htmlResponse("<title>pretend</title>");
    response.header["Content-Type"] = "image/svg+xml";
    http.responses = {response};
    EXPECT_EQ(fetchLinkPreview(http,"https://example.com/","").failure,
              PreviewFailure::PERMANENT);
}

TEST(LinkPreview, UnicodeTruncationAndEncoding)
{
    std::string title;
    for(int i = 0; i < 301; ++i) title += "猫";
    auto preview = parsePreviewHtml("<title>"+title+"</title>",
                                    "https://example.com/","","UTF-8");
    EXPECT_EQ(preview.title.size(),900u);
    auto latin = parsePreviewHtml("<title>caf\xe9</title>",
                                  "https://example.com/","","ISO-8859-1");
    EXPECT_EQ(latin.title,"caf\xc3\xa9");
}

TEST(LinkPreview, SharedAssociationEditRollbackAndCollection)
{
    ASSIGN_OR_FAIL(auto data,DataSourceSQLite::newFromMemory());
    auto input = previewPost();
    ASSIGN_OR_FAIL(auto first,data->insertPost(input,{},"https://local.test/p/"));
    ASSIGN_OR_FAIL(auto second,data->insertPost(input,{},"https://local.test/p/"));
    ASSERT_TRUE(first.link_preview_id);
    EXPECT_EQ(first.link_preview_id,second.link_preview_id);
    {
        ASSIGN_OR_FAIL(auto transaction,ap::Transaction::begin(data->connection()));
        ASSIGN_OR_FAIL(auto rolled_back,data->insertPost(
            previewPost("https://rollback.test/"),{},"https://local.test/p/"));
        EXPECT_TRUE(rolled_back.link_preview_id);
    }
    EXPECT_EQ(data->connection().evalToValue<int64_t>(
        "SELECT count(*) FROM link_previews").value(),1);
    input.uri = first.uri;
    input.content_html = "no link";
    ASSERT_TRUE(data->updatePost(first.id,input,{}));
    EXPECT_FALSE(data->getPostById(first.id).value()->link_preview_id);
    ASSERT_TRUE(data->collectLinkPreviews({}));
    EXPECT_EQ(data->getLinkPreviews({*second.link_preview_id}).value().size(),1u);
    ASSERT_TRUE(data->deletePost(second.id));
    ASSERT_TRUE(data->collectLinkPreviews({*second.link_preview_id}));
    EXPECT_EQ(data->getLinkPreviews({*second.link_preview_id}).value().size(),1u);
    ASSERT_TRUE(data->collectLinkPreviews({}));
    EXPECT_TRUE(data->getLinkPreviews({*second.link_preview_id}).value().empty());
}

TEST(LinkPreview, RetryDeduplicationRecoveryAndTerminalReuse)
{
    ASSIGN_OR_FAIL(auto data,DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto post,data->insertPost(previewPost(),{},"https://local.test/p/"));
    LinkPreviewQueue queue;
    ASSERT_TRUE(queue.recover(*data));
    ASSERT_TRUE(queue.recover(*data));
    EXPECT_EQ(queue.size(),1u);
    int calls = 0;
    PreviewFetcher fetch = [&calls](std::string_view,std::string_view)
    {
        ++calls;
        PreviewResult result;
        result.failure = PreviewFailure::TRANSIENT;
        return result;
    };
    auto now = std::chrono::steady_clock::now();
    EXPECT_TRUE(queue.runOnce(*data,fetch,"",now).value());
    EXPECT_FALSE(queue.runOnce(*data,fetch,"",now).value());
    EXPECT_TRUE(queue.runOnce(*data,fetch,"",now+std::chrono::seconds(31)).value());
    EXPECT_FALSE(queue.runOnce(*data,fetch,"",now+std::chrono::seconds(329)).value());
    EXPECT_TRUE(queue.runOnce(*data,fetch,"",now+std::chrono::seconds(332)).value());
    EXPECT_EQ(calls,3);
    EXPECT_EQ(queue.size(),0u);
    EXPECT_EQ(data->getLinkPreviews({*post.link_preview_id}).value().begin()->second.status,
              PreviewStatus::FAILED);
    ASSIGN_OR_FAIL(auto shared,data->insertPost(previewPost(),{},"https://local.test/p/"));
    EXPECT_EQ(shared.link_preview_id,post.link_preview_id);
    LinkPreviewQueue restarted;
    ASSERT_TRUE(restarted.recover(*data));
    EXPECT_EQ(restarted.size(),0u);
}

TEST(LinkPreview, RestartResetsRetryBudgetAndSaveFailureDoesNotRefetch)
{
    ASSIGN_OR_FAIL(auto data,DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto post,data->insertPost(previewPost(),{},"https://local.test/p/"));
    LinkPreviewQueue queue;
    ASSERT_TRUE(queue.recover(*data));
    int calls = 0;
    PreviewFetcher fetch = [&calls](std::string_view url,std::string_view origin)
    {
        ++calls;
        return successfulPreview(url,origin);
    };
    ASSERT_TRUE(data->connection().execute(
        "CREATE TRIGGER fail_preview BEFORE UPDATE ON link_previews "
        "BEGIN SELECT RAISE(ABORT,'injected save failure'); END;"));
    auto now = std::chrono::steady_clock::now();
    EXPECT_FALSE(queue.runOnce(*data,fetch,"",now));
    EXPECT_EQ(queue.size(),1u);
    EXPECT_EQ(calls,1);
    ASSERT_TRUE(data->connection().execute("DROP TRIGGER fail_preview;"));
    EXPECT_TRUE(queue.runOnce(*data,fetch,"",now+std::chrono::seconds(31)).value());
    EXPECT_EQ(calls,1);
    EXPECT_EQ(queue.size(),0u);
    ASSIGN_OR_FAIL(auto pending,data->insertPost(previewPost("https://pending.test/"),{},
                                                "https://local.test/p/"));
    {
        LinkPreviewQueue abandoned;
        ASSERT_TRUE(abandoned.recover(*data));
    }
    LinkPreviewQueue restarted;
    ASSERT_TRUE(restarted.recover(*data));
    EXPECT_EQ(restarted.size(),1u);
    EXPECT_TRUE(restarted.runOnce(*data,fetch,"",now).value());
    EXPECT_EQ(calls,2);
}

TEST(LinkPreview, EditsDuringFetchNeverReassociateOldResult)
{
    ASSIGN_OR_FAIL(auto data,DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto post,data->insertPost(previewPost(),{},"https://local.test/p/"));
    LinkPreviewQueue queue;
    ASSERT_TRUE(queue.recover(*data));
    PreviewFetcher fetch = [&](std::string_view url,std::string_view origin)
    {
        auto updated = previewPost("https://new.test/article");
        updated.uri = post.uri;
        EXPECT_TRUE(data->updatePost(post.id,updated,{}));
        return successfulPreview(url,origin);
    };
    EXPECT_TRUE(queue.runOnce(*data,fetch,"",std::chrono::steady_clock::now()).value());
    ASSIGN_OR_FAIL(auto updated,data->getPostById(post.id));
    EXPECT_NE(updated->link_preview_id,post.link_preview_id);
    EXPECT_EQ(data->getLinkPreviews({*post.link_preview_id}).value().begin()->second.status,
              PreviewStatus::PENDING);
}

TEST(LinkPreview, QueueOverflowAndMissedNotificationsRecoverByScanning)
{
    ASSIGN_OR_FAIL(auto data,DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto transaction,ap::Transaction::begin(data->connection()));
    for(int i = 0; i < 1002; ++i)
    {
        auto input = previewPost("https://example.com/"+std::to_string(i));
        ASSERT_TRUE(data->insertPost(input,{},"https://local.test/p/"));
    }
    ASSERT_TRUE(transaction.commit());
    LinkPreviewQueue queue;
    ASSERT_TRUE(queue.recover(*data));
    EXPECT_EQ(queue.size(),1000u);
    ASSERT_TRUE(queue.recover(*data));
    EXPECT_EQ(queue.size(),1000u);
    auto now = std::chrono::steady_clock::now();
    ASSERT_TRUE(queue.runOnce(*data,successfulPreview,"",now).value());
    ASSERT_TRUE(queue.recover(*data));
    EXPECT_EQ(queue.size(),1000u);
    EXPECT_EQ(queue.activeIds().back(),1001);
    ASSERT_TRUE(queue.runOnce(*data,successfulPreview,"",now).value());
    ASSERT_TRUE(queue.recover(*data));
    EXPECT_EQ(queue.activeIds().back(),1002);
}

TEST(LinkPreview, RejectUnknownStoredStatus)
{
    ASSIGN_OR_FAIL(auto data,DataSourceSQLite::newFromMemory());
    ASSIGN_OR_FAIL(auto post,data->insertPost(previewPost(),{},"https://local.test/p/"));
    ASSERT_TRUE(data->connection().execute("PRAGMA ignore_check_constraints=ON;"));
    ASSERT_TRUE(data->connection().execute("UPDATE link_previews SET status=99;"));
    EXPECT_FALSE(data->getLinkPreviews({*post.link_preview_id}));
}

TEST(LinkPreview, MigrationPreservesPostsWithoutBackfill)
{
    auto path = std::filesystem::temp_directory_path()/"unspoken_preview_migration.sqlite";
    std::filesystem::remove(path);
    {
        ASSIGN_OR_FAIL(auto data,DataSourceSQLite::fromFile(path.string()));
        ASSIGN_OR_FAIL(auto post,data->insertPost(previewPost(),{},"https://local.test/p/"));
        ASSERT_TRUE(data->connection().execute("DROP INDEX idx_posts_link_preview;"));
        ASSERT_TRUE(data->connection().execute("ALTER TABLE posts DROP COLUMN link_preview_id;"));
        ASSERT_TRUE(data->connection().execute("DROP TABLE link_previews;"));
        ASSERT_TRUE(data->connection().execute("PRAGMA user_version=4;"));
    }
    {
        ASSIGN_OR_FAIL(auto data,DataSourceSQLite::fromFile(path.string()));
        EXPECT_EQ(data->getSchemaVersion().value(),5);
        auto posts = data->timelinePublic({},20).value();
        ASSERT_EQ(posts.size(),1u);
        EXPECT_FALSE(posts.front().link_preview_id);
        EXPECT_EQ(posts.front().content_html,previewPost().content_html);
        EXPECT_EQ(data->connection().evalToValue<int64_t>(
            "SELECT count(*) FROM pragma_foreign_key_check").value(),0);
        EXPECT_TRUE(data->pendingLinkPreviewIds(0,10).value().empty());
    }
    {
        ASSIGN_OR_FAIL(auto reopened,DataSourceSQLite::fromFile(path.string()));
        EXPECT_EQ(reopened->getSchemaVersion().value(),5);
    }
    std::filesystem::remove(path);
}

TEST(LinkPreview, SaveToRenderEscapesAndRespectsPrivateAuthorization)
{
    ASSIGN_OR_FAIL(auto data,DataSourceSQLite::newFromMemory());
    Config config;
    config.url_root = "https://local.test/";
    config.public_domain = "local.test";
    EmojiRegistry emoji;
    Service service(config,*data,emoji);
    NewUser new_user;
    new_user.username = "author";
    new_user.oidc_iss = "https://issuer.test/";
    new_user.oidc_sub = "author";
    new_user.private_key_pem = "private";
    new_user.public_key_pem = "public";
    ASSIGN_OR_FAIL(auto author,data->createUser(new_user));
    ComposeParams params;
    params.source = "[Article](https://example.com/article)";
    params.visibility = Visibility::DIRECT;
    params.summary = "warning";
    ASSIGN_OR_FAIL(auto post,service.createPost(author,params));
    ASSERT_TRUE(post.link_preview_id);
    auto preview = successfulPreview("","").preview;
    preview.title = "<script>&title";
    preview.image = "https://images.test/p.png?a=1&b=2";
    ASSERT_TRUE(data->completeLinkPreview(*post.link_preview_id,preview));
    EXPECT_FALSE(service.postView(post,std::nullopt));
    ASSIGN_OR_FAIL(auto view,service.postView(post,author));
    EXPECT_TRUE(view["has_link_preview"].get<bool>());
    EXPECT_EQ(view["link_preview"]["title"],"&lt;script&gt;&amp;title");
    EXPECT_EQ(view["link_preview"]["image_url"],
              "https://images.test/p.png?a=1&amp;b=2");
    inja::Environment environment("templates/");
    auto html = environment.render_file("_post.html",{
        {"post",view},{"focus_id",0},{"logged_in",false},
        {"site",{{"root",config.url_root}}}});
    auto disclosure = html.find("<details class=\"cw\">");
    auto card = html.find("class=\"link-preview\"");
    EXPECT_LT(disclosure,card);
    EXPECT_LT(card,html.find("</details>",disclosure));
    EXPECT_NE(html.find("referrerpolicy=\"no-referrer\""),std::string::npos);
    EXPECT_NE(html.find("&lt;script&gt;&amp;title"),std::string::npos);
    EXPECT_EQ(html.find("<script>"),std::string::npos);
    params.source = "[Article](https://disabled.test/)";
    config.link_previews_enabled = false;
    Service disabled(config,*data,emoji);
    ASSIGN_OR_FAIL(auto without_preview,disabled.createPost(author,params));
    EXPECT_FALSE(without_preview.link_preview_id);
}

TEST(LinkPreview, BatchLoadsDistinctPreviewIdsOncePerPage)
{
    testing::NiceMock<DataSourceMock> data;
    Config config;
    config.url_root = "https://local.test/";
    EmojiRegistry emoji;
    Service service(config,data,emoji);
    Post post;
    post.uri = "https://remote.test/post";
    post.link_preview_id = 7;
    std::vector<Post> posts(20,post);
    Post private_post = post;
    private_post.visibility = Visibility::DIRECT;
    posts.push_back(private_post);
    LinkPreview preview;
    preview.url = "https://example.com/";
    preview.title = "Article";
    preview.status = PreviewStatus::READY;
    std::map<int64_t,LinkPreview> previews = {{7,preview}};
    EXPECT_CALL(data,getLinkPreviews(std::vector<int64_t>{7}))
        .Times(1).WillOnce(testing::Return(previews));
    ASSIGN_OR_FAIL(auto views,service.postViews(posts,std::nullopt));
    ASSERT_EQ(views.size(),20u);
    for(const auto& view : views)
        EXPECT_TRUE(view["has_link_preview"].get<bool>());
}

TEST(LinkPreview, RejectUnsafeStoredImageAndSensitiveDisclosure)
{
    testing::NiceMock<DataSourceMock> data;
    Config config;
    config.url_root = "https://local.test/";
    EmojiRegistry emoji;
    Service service(config,data,emoji);
    Post post;
    post.uri = "https://remote.test/post";
    post.link_preview_id = 7;
    post.sensitive = true;
    LinkPreview preview;
    preview.url = "https://example.com/";
    preview.title = "Article";
    preview.status = PreviewStatus::READY;
    preview.image = "javascript:alert(1)";
    std::map<int64_t,LinkPreview> previews = {{7,preview}};
    EXPECT_CALL(data,getLinkPreviews(std::vector<int64_t>{7}))
        .WillOnce(testing::Return(previews));
    ASSIGN_OR_FAIL(auto view,service.postView(post,std::nullopt));
    EXPECT_FALSE(view["link_preview"]["has_image"].get<bool>());
    inja::Environment environment("templates/");
    auto html = environment.render_file("_post.html",{
        {"post",view},{"focus_id",0},{"logged_in",false},
        {"site",{{"root",config.url_root}}}});
    auto disclosure = html.find("<details class=\"sensitive\">");
    auto card = html.find("class=\"link-preview\"");
    EXPECT_LT(disclosure,card);
    EXPECT_LT(card,html.find("</details>",disclosure));
    EXPECT_EQ(html.find("javascript:"),std::string::npos);
}
TEST(LinkPreview, DeniedFirstDestinationDoesNotSelectLaterArticle)
{
    EXPECT_EQ(selectPreviewUrl(
        "<a href='http://[::]/'>blocked</a>"
        "<a href='https://example.com/article'>later</a>","",""),
        "http://[::]/");
    PreviewHttpFake http;
    EXPECT_EQ(fetchLinkPreview(http,"http://[::]/","").failure,
              PreviewFailure::PERMANENT);
    EXPECT_TRUE(http.requested_urls.empty());
}

} // namespace unspoken
