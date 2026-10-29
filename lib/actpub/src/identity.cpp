#include <actpub/identity.hpp>

#include <cstddef>
#include <cstdint>
#include <format>
#include <mw/crypto.hpp>
#include <mw/utils.hpp>

namespace ap
{

mw::E<std::string> newActivityUri(std::string_view prefix)
{
    mw::Crypto crypto;
    ASSIGN_OR_RETURN(auto bytes, crypto.randomBytes(16));
    std::string uri(prefix);
    uri.reserve(uri.size() + bytes.size() * 2);
    for(auto byte : bytes)
        uri += std::format("{:02x}", std::to_integer<unsigned int>(byte));
    return uri;
}

} // namespace ap
