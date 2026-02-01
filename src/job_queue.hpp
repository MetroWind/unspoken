#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <vector>
#include <string>
#include <mw/http_client.hpp>
#include <mw/crypto.hpp>
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
