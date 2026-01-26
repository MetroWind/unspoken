#pragma once

#include <mw/http_server.hpp>
#include <mw/http_client.hpp> // For HTTPSessionInterface to fetch keys
#include <mw/error.hpp>
#include <memory>
#include <string>
#include <vector>

class SignatureVerifier
{
public:
    explicit SignatureVerifier(std::shared_ptr<mw::HTTPSessionInterface> http_client);

    // Verifies the HTTP signature of the incoming request.
    // Returns the ID of the signer (Actor URI) on success.
    mw::E<std::string> verify(const mw::HTTPServer::Request& req, 
                              const std::string& method, 
                              const std::string& path);

private:
    std::shared_ptr<mw::HTTPSessionInterface> http_client;
};
