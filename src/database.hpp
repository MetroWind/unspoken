#pragma once

#include <string>
#include <memory>
#include <mw/database.hpp>
#include <mw/error.hpp>

class Database
{
public:
    explicit Database(const std::string& path);
    mw::E<void> init();

private:
    std::string db_path;
    std::unique_ptr<mw::SQLite> db;

    mw::E<void> migrate();
};