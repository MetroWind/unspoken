#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mw/crypto_mock.hpp>
#include <mw/http_client_mock.hpp>

#include "database_mock.hpp"
#include "http_utils.hpp"
#include "signature_verifier.hpp"

using ::testing::_;
using ::testing::Field;
using ::testing::NiceMock;
using ::testing::Return;

class SignatureVerifierTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        auto h = std::make_unique<NiceMock<mw::HTTPSessionMock>>();
        http_mock = h.get();
        auto c = std::make_unique<NiceMock<mw::CryptoMock>>();
        crypto_mock = c.get();
        auto d = std::make_unique<NiceMock<DatabaseMock>>();
        db_mock = d.get();
        verifier = std::make_unique<SignatureVerifier>(
            std::move(h), std::move(c), std::move(d),
            "https://example.com/system");
    }

    mw::HTTPSessionMock* http_mock;
    mw::CryptoMock* crypto_mock;
    DatabaseMock* db_mock;
    std::unique_ptr<SignatureVerifier> verifier;
};

TEST_F(SignatureVerifierTest, VerifySuccess)
{
    mw::HTTPServer::Request req;
    req.headers.emplace("Signature", "keyId=\"https://example.com/"
                                     "alice#main-key\",headers=\"(request-"
                                     "target) host date\",signature=\"c2ln\"");
    req.headers.emplace("Host", "example.com");
    req.headers.emplace("Date", http_utils::getHttpDate());

    // System actor needed for fetch
    User system;
    system.uri = "https://example.com/system";
    system.private_key = "SYS_PRIVATE_KEY";
    EXPECT_CALL(*db_mock, getUserByUri("https://example.com/system"))
        .WillRepeatedly(Return(system));

    // Mock initial DB lookup failure and subsequent lookup in
    // fetchAndCacheActor
    EXPECT_CALL(*db_mock, getUserByUri("https://example.com/alice"))
        .Times(2)
        .WillRepeatedly(Return(std::nullopt));

    mw::HTTPResponse mock_res;
    mock_res.status = 200;
    std::string json = R"({
        "id": "https://example.com/alice",
        "type": "Person",
        "preferredUsername": "alice",
        "publicKey": {
            "id": "https://example.com/alice#main-key",
            "owner": "https://example.com/alice",
            "publicKeyPem": "PUBLIC_KEY"
        }
    })";
    for(char c : json)
    {
        mock_res.payload.push_back((std::byte)c);
    }

    EXPECT_CALL(*http_mock,
                get(Field(&mw::HTTPRequest::url, "https://example.com/alice")))
        .WillOnce(Return(&mock_res));

    EXPECT_CALL(*crypto_mock, sign(_, "SYS_PRIVATE_KEY", _))
        .WillOnce(Return(std::vector<unsigned char>{'s'}));

    EXPECT_CALL(*crypto_mock, verifySignature(_, "PUBLIC_KEY", _, _))
        .WillOnce(Return(true));

    auto res = verifier->verify(req, "GET", "/u/alice");
    ASSERT_TRUE(res.has_value()) << mw::errorMsg(res.error());
    EXPECT_EQ(*res, "https://example.com/alice");
}

TEST_F(SignatureVerifierTest, DateSkew)
{
    mw::HTTPServer::Request req;
    req.headers.emplace("Date", "Tue, 23 May 2023 10:00:00 GMT");
    auto res = verifier->verify(req, "GET", "/inbox");
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(std::get<mw::HTTPError>(res.error()).code, 401);
}
