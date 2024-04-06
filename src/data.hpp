#pragma once

#include <optional>
#include <string_view>

#include "types.hpp"
#include "error.hpp"

class DataSourceInterface
{
public:
    virtual E<std::optional<LocalUser>> getUser(std::string_view name) = 0;
};
