#include <actpub/collection.hpp>
#include <format>

namespace ap
{
nlohmann::json collectionRootJson(const std::string& collection_uri)
{
    return {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", collection_uri},
        {"type", "OrderedCollection"},
        {"first", collection_uri + "?page=true"},
    };
}

std::string pageUrl(const std::string& collection_uri, std::string_view key,
                    int64_t value)
{
    return std::format("{}?page=true&{}={}", collection_uri, key, value);
}

nlohmann::json collectionPageJson(const std::string& collection_uri,
                                  const std::string& self_uri,
                                  const nlohmann::json& ordered_items,
                                  std::optional<int64_t> next_max_id,
                                  std::optional<int64_t> prev_min_id)
{
    nlohmann::json page = {
        {"@context", "https://www.w3.org/ns/activitystreams"},
        {"id", self_uri},
        {"type", "OrderedCollectionPage"},
        {"partOf", collection_uri},
        {"orderedItems", ordered_items},
    };
    if(next_max_id.has_value())
        page["next"] = pageUrl(collection_uri, "max_id", *next_max_id);
    if(prev_min_id.has_value())
        page["prev"] = pageUrl(collection_uri, "min_id", *prev_min_id);
    return page;
}

} // namespace ap
