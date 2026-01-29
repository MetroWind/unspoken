#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "job_queue.hpp"
#include "database.hpp"
#include <mw/http_client_mock.hpp>
#include <mw/crypto_mock.hpp>
#include <filesystem>
#include <thread>
#include <chrono>

using ::testing::_;
using ::testing::Return;
using ::testing::NiceMock;

class JobQueueTest : public ::testing::Test {
protected:
    void SetUp() override {
        db_path = "test_jobqueue.db";
        if (std::filesystem::exists(db_path)) std::filesystem::remove(db_path);
        
        test_db = std::make_unique<Database>(db_path);
        test_db->init();

        auto jq_db = std::make_unique<Database>(db_path);
        jq_db->init();

        auto h = std::make_unique<NiceMock<mw::HTTPSessionMock>>();
        http_mock = h.get();
        auto c = std::make_unique<NiceMock<mw::CryptoMock>>();
        crypto_mock = c.get();

        jq = std::make_unique<JobQueue>(std::move(jq_db), std::move(h), std::move(c));
    }

    void TearDown() override {
        if(jq) jq->stop();
        jq.reset();
        test_db.reset();
        if (std::filesystem::exists(db_path)) std::filesystem::remove(db_path);
    }

    std::string db_path;
    std::unique_ptr<Database> test_db;
    std::unique_ptr<JobQueue> jq;
    mw::HTTPSessionMock* http_mock;
    mw::CryptoMock* crypto_mock;
};

TEST_F(JobQueueTest, StartStop) {
    jq->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    jq->stop();
}

TEST_F(JobQueueTest, ProcessJob) {
    Job j;
    j.type = "deliver_activity";
    j.payload = R"({
        "inbox": "https://example.com/inbox", 
        "activity": {"type": "Create"}, 
        "sender_uri": "https://local/u/alice"
    })";
    j.status = 0;
    j.attempts = 0;
    j.next_try = 0;
    auto jid = test_db->enqueueJob(j);
    ASSERT_TRUE(jid.has_value());

    User u;
    u.uri = "https://local/u/alice";
    u.username = "alice";
    u.private_key = "PRIVKEY";
    test_db->createUser(u);

    EXPECT_CALL(*crypto_mock, sign(_, _, _)).WillOnce(Return(std::vector<unsigned char>{'s','i','g'}));
    
    mw::HTTPResponse mock_res;
    mock_res.status = 202;
    EXPECT_CALL(*http_mock, post(_)).WillOnce(Return(&mock_res));

    jq->start();
    
    int retries = 0;
    while(retries++ < 20) {
        auto jobs = test_db->getPendingJobs(1);
        if (jobs && jobs->empty()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    jq->stop();

    auto jobs = test_db->getPendingJobs(1);
    EXPECT_TRUE(jobs && jobs->empty());
}
