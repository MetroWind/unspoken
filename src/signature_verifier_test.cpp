#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "signature_verifier.hpp"
#include <mw/http_client_mock.hpp>
#include <mw/crypto_mock.hpp>

using ::testing::_;
using ::testing::Return;
using ::testing::NiceMock;
using ::testing::Field;

class SignatureVerifierTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto h = std::make_unique<NiceMock<mw::HTTPSessionMock>>();
        http_mock = h.get();
        auto c = std::make_unique<NiceMock<mw::CryptoMock>>();
        crypto_mock = c.get();
        verifier = std::make_unique<SignatureVerifier>(std::move(h), std::move(c));
    }

    mw::HTTPSessionMock* http_mock;
    mw::CryptoMock* crypto_mock;
    std::unique_ptr<SignatureVerifier> verifier;
};

TEST_F(SignatureVerifierTest, VerifySuccess) {
    mw::HTTPServer::Request req;
    req.headers.emplace("Signature", "keyId=\"https://example.com/alice\",headers=\"(request-target) host date\",signature=\"c2ln\"");
    req.headers.emplace("Host", "example.com");
    req.headers.emplace("Date", "Tue, 23 May 2023 10:00:00 GMT");

    mw::HTTPResponse mock_res;
    mock_res.status = 200;
    std::string json = R"({
        "id": "https://example.com/alice",
        "type": "Person",
        "publicKey": {
            "id": "https://example.com/alice#main-key",
            "owner": "https://example.com/alice",
            "publicKeyPem": "PUBLIC_KEY"
        }
    })";
    for(char c : json) mock_res.payload.push_back((std::byte)c);

    EXPECT_CALL(*http_mock, get(Field(&mw::HTTPRequest::url, "https://example.com/alice")))
        .WillOnce(Return(&mock_res));

    EXPECT_CALL(*crypto_mock, verifySignature(_, "PUBLIC_KEY", _, _))
        .WillOnce(Return(true));

    auto res = verifier->verify(req, "POST", "/inbox");
    ASSERT_TRUE(res.has_value()) << mw::errorMsg(res.error());
    EXPECT_EQ(*res, "https://example.com/alice");
}

TEST_F(SignatureVerifierTest, MissingHeader) {
    mw::HTTPServer::Request req;
    auto res = verifier->verify(req, "POST", "/inbox");
    ASSERT_FALSE(res.has_value());
    ASSERT_TRUE(std::holds_alternative<mw::HTTPError>(res.error()));
    EXPECT_EQ(std::get<mw::HTTPError>(res.error()).code, 401);
}

TEST_F(SignatureVerifierTest, InvalidKeyId) {
    mw::HTTPServer::Request req;
    req.headers.emplace("Signature", "keyId=\"https://example.com/alice\",headers=\"(request-target)\",signature=\"sig\"");
    
    mw::HTTPResponse mock_res;
    mock_res.status = 404;

    EXPECT_CALL(*http_mock, get(_))
        .WillOnce(Return(&mock_res));

    auto res = verifier->verify(req, "POST", "/inbox");
    ASSERT_FALSE(res.has_value());
    ASSERT_TRUE(std::holds_alternative<mw::HTTPError>(res.error()));
    EXPECT_EQ(std::get<mw::HTTPError>(res.error()).code, 502);
}
