#include "database.hpp"
#include <mw/error.hpp>
#include <iostream>

Database::Database(const std::string& path)
    : db_path(path)
{
}

mw::E<void> Database::init()
{
    auto conn = mw::SQLite::connectFile(db_path);
    if (!conn)
    {
        return std::unexpected(conn.error());
    }
    db = std::move(*conn);

    // Enable WAL mode
    auto wal = db->execute("PRAGMA journal_mode=WAL;");
    if (!wal)
    {
        return std::unexpected(wal.error());
    }

    return migrate();
}

mw::E<void> Database::migrate()
{
    auto version_res = db->evalToValue<int>("PRAGMA user_version;");
    if (!version_res)
    {
        return std::unexpected(version_res.error());
    }

    int version = *version_res;

    if (version == 0)
    {
        // Initial schema creation will happen here in Phase 2.
        // For now, just set version to 1 as per PRD "starting from 1".
        // Actually, PRD says "schema version will remain 1, so we don’t need to worry about migration for now."
        // So we just set it to 1 if it's 0.
        auto res = db->execute("PRAGMA user_version = 1;");
        if (!res)
        {
            return std::unexpected(res.error());
        }
    }

    return {};
}