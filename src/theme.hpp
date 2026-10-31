#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include <mw/error.hpp>

namespace unspoken
{

// A CSS theme with one optional parent and a human-readable label.
struct Theme
{
    std::string name;
    std::string parent;
    std::vector<std::string> stylesheets;
};

// Validated theme catalog; directory names are stable theme identifiers.
class ThemeManager
{
public:
    // Load and validate all manifests and inheritance chains atomically.
    mw::E<void> loadDir(const std::filesystem::path& dir);
    // Return themes in identifier order for a picker.
    const std::map<std::string, Theme>& all() const { return themes; }
    // Return ancestor-first stylesheets, or an empty list for an unknown ID.
    std::vector<std::string> stylesheets(const std::string& id) const;

private:
    std::map<std::string, Theme> themes;
};

}
