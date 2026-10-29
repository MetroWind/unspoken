#pragma once

#include "types.hpp"

namespace ap
{

// Construct an ActivityStreams ordered collection with its first page link.
nlohmann::json collectionRootJson(const std::string& collection_uri);
// Construct one ordered collection page and opaque sequence cursor links.
nlohmann::json collectionPageJson(const std::string& collection_uri,
                                  const std::string& self_uri,
                                  const nlohmann::json& ordered_items,
                                  std::optional<int64_t> next_max_id,
                                  std::optional<int64_t> prev_min_id);

} // namespace ap
