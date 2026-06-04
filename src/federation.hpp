#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>
#include <mw/error.hpp>

#include "config.hpp"
#include "structs.hpp"

namespace unspoken
{

std::vector<std::string> normalizeAddressing(const nlohmann::json& field);
std::optional<std::string> normalizeRef(const nlohmann::json& field);
mw::E<Activity> parseActivity(const nlohmann::json& raw);
bool isPublicAddress(std::string_view uri);

bool wantsActivityJson(std::string_view accept);

nlohmann::json actorJson(const Config& config, const User& user,
                         std::string_view summary_html);
nlohmann::json systemActorJson(const Config& config,
                               std::string_view public_key_pem);
nlohmann::json noteJson(const Config& config, const Post& post,
                        const User& author,
                        const std::vector<PostRecipient>& recipients,
                        const std::vector<Attachment>& attachments);
nlohmann::json webFingerJson(const Config& config, const User& user);
nlohmann::json nodeInfoDiscoveryJson(const Config& config);
nlohmann::json nodeInfoJson(const Config& config);

} // namespace unspoken
