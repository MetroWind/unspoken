#pragma once

#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "database.hpp"
#include <mw/http_client.hpp>
#include <mw/crypto.hpp>

class JobQueue
{
public:
    JobQueue(std::unique_ptr<Database> db, 
             std::unique_ptr<mw::HTTPSessionInterface> http_client,
             std::unique_ptr<mw::CryptoInterface> crypto);
    ~JobQueue();

    void start();
    void stop();

private:
    void workerLoop();
    void processJob(const Job& job);
    
    // Activity Delivery
    void deliverActivity(const Job& job);

    std::unique_ptr<Database> db;
    std::unique_ptr<mw::HTTPSessionInterface> http_client;
    std::unique_ptr<mw::CryptoInterface> crypto;
    
    std::atomic<bool> running{false};
    std::thread worker_thread;
    std::mutex cv_m;
    std::condition_variable cv;
};
