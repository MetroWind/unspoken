#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

class JsonLD
{
public:
    // Normalizes a field that can be a single string or a list of strings
    // into a vector of strings.
    static std::vector<std::string> asList(const nlohmann::json& j, 
                                           const std::string& key);

    // Normalizes a field that can be a string (URI) or an object (Link/Object)
    // and returns the ID/URI.
    static std::string getId(const nlohmann::json& j, const std::string& key);
    
    // Check if a field exists and is of a certain type
    static bool hasType(const nlohmann::json& j, const std::string& type);
};
