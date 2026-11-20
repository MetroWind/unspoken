#pragma once

#include "config.hpp"
#include <iosfwd>
#include <mw/error.hpp>
#include <string>

namespace unspoken
{
// Offline import identity and paths, explicitly selected by the operator.
struct NspicImportOptions
{
    std::string source_db;
    std::string image_dir;
    std::string source_key;
    std::string author;
    bool dry_run = true;
};

// Preflight all source records, then commit one mapped photo at a time.
// Dry runs open both databases read-only and never create destination files.
// Reports are JSON lines. Run with the application stopped and a source backup.
mw::E<void> importNspic(const Config &config, const NspicImportOptions &options,
                        std::ostream &report);
} // namespace unspoken
