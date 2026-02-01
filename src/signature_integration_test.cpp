#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "signature_verifier.hpp"
#include "job_queue.hpp"
#include "database_mock.hpp"
#include "http_utils.hpp"
#include <mw/http_client_mock.hpp>
#include <mw/crypto.hpp>
#include <nlohmann/json.hpp>

using ::testing:: _;
using ::testing::Return;
using ::testing::NiceMock;
using ::testing::Invoke;

class SignatureIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        crypto = std::make_unique<mw::Crypto>();
        auto h = std::make_unique<NiceMock<mw::HTTPSessionMock>>();
        http_mock = h.get();
        auto d = std::make_unique<NiceMock<DatabaseMock>>();
        db_mock = d.get();
        
        system_actor_uri = "https://local.test/system";
        verifier = std::make_unique<SignatureVerifier>(std::move(h), std::make_unique<mw::Crypto>(), std::move(d), system_actor_uri);
    }

    std::unique_ptr<mw::Crypto> crypto;
    mw::HTTPSessionMock* http_mock;
    DatabaseMock* db_mock;
    std::string system_actor_uri;
    std::unique_ptr<SignatureVerifier> verifier;
};

TEST_F(SignatureIntegrationTest, IncomingSignatureVerification) {
    auto keys = crypto->generateKeyPair(mw::KeyType::RSA).value();
    std::string alice_uri = "https://remote.test/alice";
    
    User alice;
    alice.uri = alice_uri;
    alice.public_key = keys.public_key;
    EXPECT_CALL(*db_mock, getUserByUri(alice_uri)).WillRepeatedly(Return(alice));

    mw::HTTPServer::Request req;
    req.body = "{\"type\":\"Create\"}";
    std::string method = "POST";
    std::string path = "/inbox";
    std::string date = http_utils::getHttpDate();
    std::string host = "local.test";
    
    auto digest_bytes = mw::SHA256Hasher().hashToBytes(req.body).value();
    std::string digest = "SHA-256=" + mw::base64Encode(digest_bytes);
    
    std::string to_sign = "(request-target): post /inbox\nhost: local.test\ndate: " + date + "\ndigest: " + digest;
    auto sig_bytes = crypto->sign(mw::SignatureAlgorithm::RSA_V1_5_SHA256, keys.private_key, to_sign).value();
    std::string signature = mw::base64Encode(sig_bytes);
    
    std::string sig_header = "keyId=\"" + alice_uri + "#main-key\",algorithm=\"hs2019\",headers=\"(request-target) host date digest\",signature=\"" + signature + "\"";
    
    req.headers.emplace("Date", date);
    req.headers.emplace("Host", host);
    req.headers.emplace("Digest", digest);
    req.headers.emplace("Signature", sig_header);

    auto res = verifier->verify(req, method, path);
    ASSERT_TRUE(res.has_value()) << mw::errorMsg(res.error());
    EXPECT_EQ(*res, alice_uri);
}

TEST_F(SignatureIntegrationTest, OutgoingSignatureGeneration) {
    auto keys = crypto->generateKeyPair(mw::KeyType::RSA).value();
    std::string alice_uri = "https://local.test/u/alice";
    User alice;
    alice.uri = alice_uri;
    alice.private_key = keys.private_key;
    
    Job job;
    job.type = "deliver_activity";
    nlohmann::json payload_json;
    payload_json["inbox"] = "https://remote.test/inbox";
    payload_json["activity"] = {{"type", "Create"}};
    payload_json["sender_uri"] = alice_uri;
    job.payload = payload_json.dump();

    struct TestJobQueue : public JobQueue {
        using JobQueue::JobQueue;
        using JobQueue::deliverActivity;
    };
    
    auto h2 = std::make_unique<NiceMock<mw::HTTPSessionMock>>();
    auto d2 = std::make_unique<NiceMock<DatabaseMock>>();
    EXPECT_CALL(*d2, getUserByUri(alice_uri)).WillRepeatedly(Return(alice));
    
    mw::HTTPResponse mock_res;
    mock_res.status = 202;

    EXPECT_CALL(*h2, post(_)).WillOnce(Invoke([&](const mw::HTTPRequest& req) -> mw::E<const mw::HTTPResponse*> {
        EXPECT_EQ(req.url, "https://remote.test/inbox");
        EXPECT_TRUE(req.header.contains("Signature"));
        EXPECT_TRUE(req.header.contains("Date"));
        EXPECT_TRUE(req.header.contains("Host"));
        EXPECT_TRUE(req.header.contains("Digest"));
        
        std::string sig = req.header.at("Signature");
        EXPECT_TRUE(sig.find("keyId=\"" + alice_uri + "#main-key\"") != std::string::npos);
        EXPECT_TRUE(sig.find("algorithm=\"hs2019\"") != std::string::npos);
        
        size_t sig_start = sig.find("signature=\"") + 11;
        size_t sig_end = sig.find("\"", sig_start);
        std::string sig_b64 = sig.substr(sig_start, sig_end - sig_start);
        auto sig_bytes = mw::base64Decode(sig_b64).value();
        
        std::string date = req.header.at("Date");
        std::string digest = req.header.at("Digest");
        std::string to_verify = "(request-target): post /inbox\nhost: remote.test\ndate: " + date + "\ndigest: " + digest;
        
        auto valid = crypto->verifySignature(mw::SignatureAlgorithm::RSA_V1_5_SHA256, keys.public_key, sig_bytes, to_verify);
        EXPECT_TRUE(valid && *valid);

        return &mock_res;
    }));

    TestJobQueue tjq(*d2, std::move(h2), std::make_unique<mw::Crypto>());
    tjq.deliverActivity(job);
}