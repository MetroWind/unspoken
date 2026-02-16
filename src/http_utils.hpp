#pragma once
#include <string>

namespace http_utils
{
std::string getHttpDate();
bool checkDateSkew(const std::string& date_str, int max_skew_seconds = 30);
} // namespace http_utils
