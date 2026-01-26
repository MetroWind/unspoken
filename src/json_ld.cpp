#include "json_ld.hpp"

std::vector<std::string> JsonLD::asList(const nlohmann::json& j, 
                                        const std::string& key)
{
    std::vector<std::string> result;
    if(!j.contains(key))
    {
        return result;
    }

    const auto& val = j[key];
    if(val.is_array())
    {
        for(const auto& item : val)
        {
            if(item.is_string())
            {
                result.push_back(item.get<std::string>());
            }
        }
    }
    else if(val.is_string())
    {
        result.push_back(val.get<std::string>());
    }
    return result;
}

std::string JsonLD::getId(const nlohmann::json& j, const std::string& key)
{
    if(!j.contains(key))
    {
        return "";
    }

    const auto& val = j[key];
    if(val.is_string())
    {
        return val.get<std::string>();
    }
    else if(val.is_object() && val.contains("id") && val["id"].is_string())
    {
        return val["id"].get<std::string>();
    }
    else if(val.is_object() && val.contains("href") && val["href"].is_string())
    {
        return val["href"].get<std::string>();
    }
    return "";
}

bool JsonLD::hasType(const nlohmann::json& j, const std::string& type)
{
    auto types = asList(j, "type");
    for(const auto& t : types)
    {
        if(t == type)
        {
            return true;
        }
    }
    return false;
}
