#pragma once

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

#include <mw/crypto.hpp>
#include <mw/http_client.hpp>

#include "database.hpp"
#include "types.hpp"

class JobQueue
{
public:
    JobQueue(DatabaseInterface& db,
             std::unique_ptr<mw::HTTPSessionInterface> http_client,
             std::unique_ptr<mw::CryptoInterface> crypto);
    ~JobQueue();

    void start();
    void stop();

protected:
    void processJob(const Job& job);
    void deliverActivity(const Job& job);

private:
    void workerLoop();

    DatabaseInterface& db;
    std::unique_ptr<mw::HTTPSessionInterface> http_client;
    std::unique_ptr<mw::CryptoInterface> crypto;
    std::thread worker_thread;
    std::mutex cv_m;
    std::condition_variable cv;
    std::atomic<bool> running{false};
};
