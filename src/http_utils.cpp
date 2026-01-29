#include "http_utils.hpp"
#include <ctime>
#include <iomanip>
#include <sstream>
#include <cmath>

namespace http_utils {

std::string getHttpDate() {
    std::time_t now = std::time(nullptr);
    std::tm tm = *std::gmtime(&now);
    std::stringstream ss;
    ss << std::put_time(&tm, "%a, %d %b %Y %H:%M:%S GMT");
    return ss.str();
}

bool checkDateSkew(const std::string& date_str, int max_skew_seconds) {
    std::tm tm = {};
    std::stringstream ss(date_str);
    ss >> std::get_time(&tm, "%a, %d %b %Y %H:%M:%S GMT");
    if(ss.fail()) return false;
    
    std::time_t time = timegm(&tm); 
    std::time_t now = std::time(nullptr);
    
    double diff = std::difftime(now, time);
    return std::abs(diff) <= max_skew_seconds;
}

}
