#include <iostream>
#include <memory>

#include <cxxopts.hpp>
#include <spdlog/spdlog.h>

#include "app.hpp"
#include "auth.hpp"
#include "config.hpp"
#include "crypto.hpp"
#include "error.hpp"
#include "http_client.hpp"
#include "utils.hpp"

int main()
{
    spdlog::set_level(spdlog::level::debug);

    Crypto c;
    KeyPair keys = c.createKeyPair();
    std::cout << keys.pemPublicKey() << std::endl;
    std::cout << keys.pemPrivateKey() << std::endl;

    Configuration config;
    config.listen_address = "0.0.0.0";
    config.listen_port = 8123;
    config.client_id = "test";
    config.client_secret = "7QHMYaQYj4UxpqlmYKUYYDiLoNRCSRSD";
    config.openid_url_prefix = "https://auth.xeno.darksair.org/realms/xeno";
    config.url_prefix = "https://fedi-test.xeno.darksair.org/";
    auto auth = AuthOpenIDConnect::create(
        config, "https://fedi-test.xeno.darksair.org/openid-redirect",
        std::make_unique<HTTPSession>());
    if(!auth.has_value())
    {
        spdlog::error(errorMsg(auth.error()));
        return 1;
    }
    // App app(config, *std::move(auth), std::make_unique<DataSourceHardCoded>());
    // app.start();
    return 0;
}
