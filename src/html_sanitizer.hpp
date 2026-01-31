#pragma once

#include <string>

class HtmlSanitizer {
public:
    static std::string sanitize(const std::string& input);
};
