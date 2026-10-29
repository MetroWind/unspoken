#pragma once

#include <string>
#include <string_view>
#include <mw/error.hpp>

namespace ap
{

// Generate a fresh 128-bit activity identity using libmw secure randomness.
// Persist the result once and reuse it for retries of the same operation.
mw::E<std::string> newActivityUri(std::string_view prefix);

} // namespace ap
