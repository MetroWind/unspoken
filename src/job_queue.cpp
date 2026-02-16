#include "job_queue.hpp"

#include <chrono>

#include <mw/crypto.hpp>
#include <mw/url.hpp>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "config.hpp"
#include "http_utils.hpp"

JobQueue::JobQueue(DatabaseInterface& db,
                   std::unique_ptr<mw::HTTPSessionInterface> http_client,
                   std::unique_ptr<mw::CryptoInterface> crypto)
    : db(db), http_client(std::move(http_client)), crypto(std::move(crypto))
{
}

JobQueue::~JobQueue()
{
    stop();
}

void JobQueue::start()
{
    if(running)
    {
        return;
    }
    running = true;
    worker_thread = std::thread(&JobQueue::workerLoop, this);
    spdlog::info("JobQueue started");
}

void JobQueue::stop()
{
    if(!running)
    {
        return;
    }
    running = false;
    cv.notify_all();
    if(worker_thread.joinable())
    {
        worker_thread.join();
    }
    spdlog::info("JobQueue stopped");
}

void JobQueue::workerLoop()
{
    while(running)
    {
        auto jobs_res = db.getPendingJobs(10);
        if(!jobs_res)
        {
            spdlog::error("Failed to fetch pending jobs: {}",
                          mw::errorMsg(jobs_res.error()));
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        auto jobs = *jobs_res;
        if(jobs.empty())
        {
            std::unique_lock<std::mutex> lk(cv_m);
            cv.wait_for(lk, std::chrono::seconds(5),
                        [this] { return !running; });
            continue;
        }

        for(const auto& job : jobs)
        {
            if(!running)
            {
                break;
            }
            processJob(job);
        }
    }
}

void JobQueue::processJob(const Job& job)
{
    // Mark as processing
    db.updateJob(job.id, 1, job.attempts, job.next_try);

    try
    {
        if(job.type == "deliver_activity")
        {
            deliverActivity(job);
        }
        else
        {
            spdlog::warn("Unknown job type: {}", job.type);
            // Mark as failed permanently? Or just delete.
            db.deleteJob(job.id);
            return;
        }

        // Success
        db.deleteJob(job.id);
    }
    catch(const std::exception& e)
    {
        spdlog::error("Job {} failed: {}", job.id, e.what());

        // Retry logic
        int attempts = job.attempts + 1;
        if(attempts >= 5)
        {
            db.updateJob(job.id, 2, attempts, job.next_try); // Failed
        }
        else
        {
            // Exponential backoff
            int64_t delay = 60 * (1 << (attempts - 1));
            int64_t next = mw::timeToSeconds(mw::Clock::now()) + delay;
            db.updateJob(job.id, 0, attempts, next);
        }
    }
}

void JobQueue::deliverActivity(const Job& job)
{
    auto payload = nlohmann::json::parse(job.payload);
    std::string inbox = payload["inbox"];
    std::string body = payload["activity"].dump();
    std::string sender_uri = payload["sender_uri"];

    // Retrieve sender keys
    auto user_res = db.getUserByUri(sender_uri);
    if(!user_res || !user_res.value())
    {
        throw std::runtime_error("Sender not found: " + sender_uri);
    }
    auto user = *user_res.value();
    if(!user.private_key)
    {
        throw std::runtime_error("Sender has no private key");
    }

    mw::URL url_obj = *mw::URL::fromStr(inbox);
    std::string target = "post " + url_obj.path();
    std::string date = http_utils::getHttpDate();

    // Digest
    auto digest_bytes = mw::SHA256Hasher().hashToBytes(body);
    if(!digest_bytes)
    {
        throw std::runtime_error("Failed to hash body");
    }
    std::string digest = "SHA-256=" + mw::base64Encode(*digest_bytes);

    std::string host = url_obj.host();
    if(url_obj.port() != "80" && url_obj.port() != "443" &&
       !url_obj.port().empty())
    {
        host += ":" + url_obj.port();
    }

    // Signing String
    // (request-target) host date digest
    std::string to_sign = "(request-target): " + target + "\n" +
                          "host: " + host + "\n" + "date: " + date + "\n" +
                          "digest: " + digest;

    auto sig_bytes = crypto->sign(mw::SignatureAlgorithm::RSA_V1_5_SHA256,
                                  *user.private_key, to_sign);
    if(!sig_bytes)
    {
        throw std::runtime_error("Failed to sign request: " +
                                 mw::errorMsg(sig_bytes.error()));
    }
    std::string signature = mw::base64Encode(*sig_bytes);

    std::string key_id = sender_uri + "#main-key";
    auto s_url = mw::URL::fromStr(sender_uri);
    if(s_url)
    {
        s_url->fragment("main-key");
        key_id = s_url->str();
    }
    std::string header =
        "keyId=\"" + key_id + "\",algorithm=\"hs2019\"," +
        "headers=\" (request-target) host date digest\",signature=\"" +
        signature + "\"";

    mw::HTTPRequest req(inbox);
    req.setPayload(body);
    req.setContentType("application/activity+json");
    req.addHeader("Host", host);
    req.addHeader("Date", date);
    req.addHeader("Digest", digest);
    req.addHeader("Signature", header);

    auto res = http_client->post(req);
    if(!res)
    {
        throw std::runtime_error("HTTP POST failed: " +
                                 mw::errorMsg(res.error()));
    }

    int status = (*res)->status;
    if(status < 200 || status >= 300)
    {
        throw std::runtime_error("HTTP POST returned status " +
                                 std::to_string(status));
    }
}
