#pragma once

#include "config.hpp"

class URLManager
{
public:
    URLManager(const Configuration& conf) : config(conf) {}

    inline std::string urlFor(const std::string& name, const std::string& arg)
        const
    {
        if(name == "index")
        {
            return "/";
        }
        if(name == "openid-redirect")
        {
            return "/openid-redirect";
        }
        if(name == "login")
        {
            return "/login";
        }
        if(name == "user-info")
        {
            return std::string("/fed/user/") + arg;
        }
        if(name == "user")
        {
            return std::string("/u/") + arg;
        }
        if(name == "inbox")
        {
            return std::string("/fed/inbox/") + arg;
        }
        return "";
    }

private:
    const Configuration& config;
};
