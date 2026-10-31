#pragma once

#include <chrono>
#include <iosfwd>

#include "federation.hpp"

namespace unspoken
{
// Counts from an additive import; queued follows await remote acceptance.
struct FollowImportResult
{
    int queued = 0;
    int local = 0;
    int skipped = 0;
    int failed = 0;
};

// Import one @user@domain handle per line, preserving existing relationships.
// Resolve outside write transactions and atomically queue each new follow.
// The interval paces remote lookups; tests can supply zero without networking.
mw::E<FollowImportResult> importFollows(
    const Config& config, const DataSourceSQLite& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const User& user, std::istream& input, std::ostream& output,
    std::chrono::milliseconds interval = std::chrono::milliseconds(250));
} // namespace unspoken
