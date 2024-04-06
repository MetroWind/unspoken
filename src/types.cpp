#include <expected>
#include <format>
#include <string>
#include <string_view>

#include "types.hpp"
#include "error.hpp"
#include "utils.hpp"

E<FediUser> FediUser::fromStr(std::string_view s)
{
    s = strip(s);
    size_t name_begin = 0;
    if(s[0] == '@')
    {
        name_begin = 1;
    }
    size_t name_end = s.find('@', name_begin);
    if(name_end == std::string_view::npos)
    {
        return std::unexpected(runtimeError(
            std::format("Invalid account string: {}", s)));
    }
    FediUser u;
    u.name = strip(s.substr(name_begin, name_end - name_begin));
    if(u.name.empty())
    {
        return std::unexpected(runtimeError(
            std::format("Invalid account string: {}", s)));
    }
    // The account string should not contains a “@” in the domain
    // part.
    if(s.find('@', name_end + 1) != std::string_view::npos)
    {
        return std::unexpected(runtimeError(
            std::format("Invalid account string: {}", s)));
    }
    u.server = strip(s.substr(name_end + 1));
    if(u.server.empty())
    {
        return std::unexpected(runtimeError(
            std::format("Invalid account string: {}", s)));
    }
    return u;
}
