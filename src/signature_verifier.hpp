#pragma once

#include <mw/http_server.hpp>
#include <mw/http_client.hpp> // For HTTPSessionInterface to fetch keys
#include <mw/crypto.hpp> // For CryptoInterface
#include <mw/error.hpp>
#include <memory>
#include <string>
#include <vector>

class SignatureVerifier
{
public:
    SignatureVerifier(std::unique_ptr<mw::HTTPSessionInterface> http_client,
                      std::unique_ptr<mw::CryptoInterface> crypto);

    // Verifies the HTTP signature of the incoming request.
    // Returns the ID of the signer (Actor URI) on success.
    mw::E<std::string> verify(const mw::HTTPServer::Request& req, 
                              const std::string& method, 
                              const std::string& path);

private:
    std::unique_ptr<mw::HTTPSessionInterface> http_client;
    std::unique_ptr<mw::CryptoInterface> crypto;
};
