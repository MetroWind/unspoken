#include <actpub/engine.hpp>
#include <actpub/identity.hpp>
#include <actpub/collection.hpp>

#include <algorithm>
#include <chrono>
#include <format>
#include <set>
#include <mw/utils.hpp>
#include <mw/url.hpp>

namespace ap
{
namespace
{

int64_t timeNow()
{
    return mw::timeToSeconds(mw::Clock::now());
}

bool validFields(const nlohmann::json& value)
{
    if(!value.is_object())
        return false;
    for(const char* key :
        {"type", "content", "summary", "name", "preferredUsername", "mediaType",
         "publicKeyPem", "inbox", "sharedInbox"})
    {
        auto field = value.find(key);
        if(field != value.end() && !field->is_null() && !field->is_string())
            return false;
    }
    for(const char* key : {"icon", "image", "publicKey", "endpoints"})
    {
        auto child = value.find(key);
        if(child != value.end() && child->is_object() && !validFields(*child))
            return false;
    }
    for(const char* key : {"attachment", "tag"})
    {
        auto values = value.find(key);
        if(values == value.end())
            continue;
        if(values->is_object() && !validFields(*values))
            return false;
        if(values->is_array())
            for(const auto& item : *values)
                if(item.is_object() && !validFields(item))
                    return false;
    }
    return true;
}

bool publicDocument(const nlohmann::json& doc)
{
    for(const char* key : {"to", "cc"})
        for(const auto& uri :
            normalizeAddressing(doc.value(key, nlohmann::json())))
            if(isPublicAddress(uri))
                return true;
    return false;
}

bool validDepth(const nlohmann::json& doc, size_t limit)
{
    if(limit == 0)
        return false;
    if(doc.is_structured())
        for(const auto& value : doc)
            if(!validDepth(value, limit - 1))
                return false;
    return true;
}

std::string stringField(const nlohmann::json& value, const char* key)
{
    auto found = value.find(key);
    return found != value.end() && found->is_string()
               ? found->get<std::string>()
               : "";
}

mw::E<void> writeObject(mw::SQLite& db, const nlohmann::json& doc,
                        std::string_view owner, bool local,
                        bool deleted = false)
{
    auto uri = normalizeRef(doc);
    if(!uri)
        return std::unexpected(mw::runtimeError("Object needs an id"));
    ASSIGN_OR_RETURN(
        auto st,
        db.statementFromStr(
            "INSERT INTO ap_objects(uri,owner_uri,local,document_json,deleted) "
            "VALUES (?,?,?,?,?) ON CONFLICT(uri) DO UPDATE SET "
            "document_json=excluded.document_json,deleted=excluded.deleted"));
    DO_OR_RETURN(
        (st.bind<std::string, std::string, int64_t, std::string, int64_t>(
            *uri, std::string(owner), local ? 1 : 0, doc.dump(),
            deleted ? 1 : 0)));
    DO_OR_RETURN(db.execute(std::move(st)));
    if(!local && !deleted)
    {
        ASSIGN_OR_RETURN(
            auto pin,
            db.statementFromStr(
                "INSERT OR IGNORE INTO ap_actor_refs VALUES (?,'object',?)"));
        DO_OR_RETURN(
            (pin.bind<std::string, std::string>(std::string(owner), *uri)));
        DO_OR_RETURN(db.execute(std::move(pin)));
    }
    if(deleted)
    {
        ASSIGN_OR_RETURN(
            auto unpin,
            db.statementFromStr("DELETE FROM ap_actor_refs WHERE "
                                "owner_kind='object' AND owner_key=?"));
        DO_OR_RETURN(unpin.bind<std::string>(*uri));
        DO_OR_RETURN(db.execute(std::move(unpin)));
    }
    return {};
}

} // namespace

Session::Session(const FederationConfig& policy, mw::SQLite& connection,
                 mw::CryptoInterface& cryptography,
                 mw::HTTPSessionInterface& transport, Application& host)
    : config(policy), db(connection), crypto(cryptography), http(transport),
      application(host), store(connection)
{
}

mw::E<void> Session::migrate()
{
    return store.migrate();
}

mw::E<void> Session::checkTransaction(Transaction& tx) const
{
    if(!tx.active() || &tx.connection() != &db)
        return std::unexpected(
            mw::runtimeError("Wrong federation transaction"));
    return {};
}

mw::E<void> Session::registerActor(Transaction& tx, const LocalActor& actor)
{
    DO_OR_RETURN(checkTransaction(tx));
    if(!actor.document.is_object() ||
       stringField(actor.document, "id") != actor.uri || actor.key_id.empty() ||
       actor.private_key_pem.empty())
        return std::unexpected(mw::runtimeError("Invalid local actor"));
    ASSIGN_OR_RETURN(
        auto st,
        db.statementFromStr(
            "INSERT INTO ap_local_actors VALUES (?,?,?,?) ON CONFLICT(uri) "
            "DO UPDATE SET "
            "key_id=excluded.key_id,private_key_pem=excluded.private_key_pem,"
            "document_json=excluded.document_json"));
    DO_OR_RETURN((st.bind<std::string, std::string, std::string, std::string>(
        actor.uri, actor.key_id, actor.private_key_pem,
        actor.document.dump())));
    return db.execute(std::move(st));
}

mw::E<std::optional<LocalActor>> Session::localActor(std::string_view uri) const
{
    ASSIGN_OR_RETURN(auto st, db.statementFromStr(
                                  "SELECT key_id,private_key_pem,document_json "
                                  "FROM ap_local_actors WHERE uri=?"));
    DO_OR_RETURN(st.bind<std::string>(std::string(uri)));
    ASSIGN_OR_RETURN(auto rows, (db.eval<std::string, std::string, std::string>(
                                    std::move(st))));
    if(rows.empty())
        return std::nullopt;
    auto doc = nlohmann::json::parse(std::get<2>(rows.front()), nullptr, false);
    if(!doc.is_object())
        return std::unexpected(
            mw::runtimeError("Corrupt local actor document"));
    return LocalActor{std::string(uri), std::get<0>(rows.front()),
                      std::get<1>(rows.front()), std::move(doc)};
}

mw::E<SigningActor> Session::signer(std::string_view uri) const
{
    ASSIGN_OR_RETURN(auto actor, localActor(uri));
    if(!actor)
        return std::unexpected(mw::runtimeError("Unknown local signer"));
    return SigningActor{actor->uri, actor->key_id, actor->private_key_pem};
}

mw::E<std::optional<nlohmann::json>> Session::object(std::string_view uri) const
{
    ASSIGN_OR_RETURN(auto st,
                     db.statementFromStr(
                         "SELECT document_json FROM ap_objects WHERE uri=?"));
    DO_OR_RETURN(st.bind<std::string>(std::string(uri)));
    ASSIGN_OR_RETURN(auto rows, db.eval<std::string>(std::move(st)));
    if(rows.empty())
        return std::nullopt;
    auto doc = nlohmann::json::parse(std::get<0>(rows.front()), nullptr, false);
    if(!doc.is_object())
        return std::unexpected(mw::runtimeError("Corrupt object document"));
    return std::optional<nlohmann::json>{std::move(doc)};
}

mw::E<std::optional<nlohmann::json>>
Session::objectForActor(std::string_view uri, std::string_view actor_uri) const
{
    ASSIGN_OR_RETURN(auto doc, object(uri));
    if(!doc)
        return std::nullopt;
    if(publicDocument(*doc))
        return doc;
    if(actor_uri.empty())
        return std::nullopt;
    auto owner = stringField(*doc, "attributedTo");
    if(owner == actor_uri)
        return doc;
    ASSIGN_OR_RETURN(auto local_owner, localActor(owner));
    for(const char* key : {"to", "cc"})
        for(const auto& recipient :
            normalizeAddressing(doc->value(key, nlohmann::json())))
        {
            if(recipient == actor_uri)
                return doc;
            if(local_owner &&
               recipient == stringField(local_owner->document, "followers"))
            {
                ASSIGN_OR_RETURN(auto follow,
                                 store.getFollow(actor_uri, owner));
                if(follow && follow->state == FollowState::ACCEPTED)
                    return doc;
            }
        }
    return std::nullopt;
}

mw::E<VerifiedSignature>
Session::authenticate(const IncomingHttpRequest& request, int64_t now)
{
    ASSIGN_OR_RETURN(bool active, inTransaction(db));
    if(active)
        return std::unexpected(
            mw::runtimeError("Authentication requires no write transaction"));
    return verify(request, now);
}

mw::E<nlohmann::json> Session::outboxPage(std::string_view actor_uri,
                                          const Cursor& cursor, int limit,
                                          std::string_view self_uri) const
{
    if(limit <= 0 || limit > 1000)
        return std::unexpected(mw::httpError(400, "Invalid collection limit"));
    ASSIGN_OR_RETURN(auto local, localActor(actor_uri));
    if(!local)
        return std::unexpected(mw::httpError(404, "Unknown actor"));
    std::string collection = stringField(local->document, "outbox");
    std::string sql =
        "SELECT sequence,document_json FROM ap_outbox WHERE actor_uri=?";
    if(cursor.max_id)
        sql += " AND sequence<?";
    if(cursor.min_id)
        sql += " AND sequence>?";
    // json_each accepts both scalar and array addressing without reparsing
    // extracted strings. Only public activities are exposed by this endpoint.
    sql += " AND (EXISTS(SELECT 1 FROM json_each(document_json,'$.to') "
           "WHERE value IN ('https://www.w3.org/ns/activitystreams#Public',"
           "'Public','as:Public')) OR EXISTS(SELECT 1 FROM "
           "json_each(document_json,'$.cc') WHERE value IN "
           "('https://www.w3.org/ns/"
           "activitystreams#Public','Public','as:Public')))";
    sql += cursor.min_id ? " ORDER BY sequence ASC LIMIT ?"
                         : " ORDER BY sequence DESC LIMIT ?";
    ASSIGN_OR_RETURN(auto st, db.statementFromStr(sql));
    int index = 1;
    DO_OR_RETURN(mw::internal::bindOne(st, index++, std::string(actor_uri)));
    if(cursor.max_id)
    {
        DO_OR_RETURN(mw::internal::bindOne(st, index++, *cursor.max_id));
    }
    if(cursor.min_id)
    {
        DO_OR_RETURN(mw::internal::bindOne(st, index++, *cursor.min_id));
    }
    DO_OR_RETURN(mw::internal::bindOne(st, index, static_cast<int64_t>(limit)));
    ASSIGN_OR_RETURN(auto rows, (db.eval<int64_t, std::string>(std::move(st))));
    if(cursor.min_id)
        std::reverse(rows.begin(), rows.end());
    nlohmann::json items = nlohmann::json::array();
    for(const auto& row : rows)
    {
        auto doc = nlohmann::json::parse(std::get<1>(row), nullptr, false);
        if(!doc.is_object())
            return std::unexpected(mw::runtimeError("Corrupt outbox document"));
        items.push_back(std::move(doc));
    }
    std::optional<int64_t> next;
    std::optional<int64_t> previous;
    if(!rows.empty())
    {
        previous = std::get<0>(rows.front());
        if(rows.size() == static_cast<size_t>(limit))
            next = std::get<0>(rows.back());
    }
    return collectionPageJson(collection, std::string(self_uri), items, next,
                              previous);
}

mw::E<Publication> Session::enqueue(Transaction& tx,
                                    std::string_view signer_uri,
                                    const nlohmann::json& raw,
                                    const std::vector<std::string>& inboxes,
                                    int64_t now)
{
    DO_OR_RETURN(checkTransaction(tx));
    ASSIGN_OR_RETURN(auto scope, Savepoint::begin(tx));
    ASSIGN_OR_RETURN(auto activity, parseActivity(raw));
    if(!validFields(raw) ||
       (activity.object.is_object() && !validFields(activity.object)))
        return std::unexpected(
            mw::httpError(400, "Invalid protocol field types"));
    ASSIGN_OR_RETURN(auto local, signer(signer_uri));
    ASSIGN_OR_RETURN(
        auto old, db.statementFromStr("SELECT sequence,document_json,actor_uri "
                                      "FROM ap_outbox WHERE activity_uri=?"));
    DO_OR_RETURN(old.bind<std::string>(activity.id));
    ASSIGN_OR_RETURN(auto rows, (db.eval<int64_t, std::string, std::string>(
                                    std::move(old))));
    Publication result;
    result.activity_uri = activity.id;
    if(!rows.empty())
    {
        if(std::get<1>(rows.front()) != raw.dump())
            return std::unexpected(
                mw::runtimeError("Activity ID reused for different content"));
        result.sequence = std::get<0>(rows.front());
    }
    else
    {
        ASSIGN_OR_RETURN(
            auto insert,
            db.statementFromStr(
                "INSERT INTO ap_outbox(activity_uri,actor_uri,document_json) "
                "VALUES (?,?,?)"));
        DO_OR_RETURN((insert.bind<std::string, std::string, std::string>(
            activity.id, activity.actor, raw.dump())));
        DO_OR_RETURN(db.execute(std::move(insert)));
        result.sequence = db.lastInsertRowID();
    }
    std::set<std::string> targets(inboxes.begin(), inboxes.end());
    for(const auto& inbox : targets)
    {
        if(!isValidRemoteUrl(config.transport.dev, inbox))
            return std::unexpected(mw::runtimeError("Invalid delivery inbox"));
        ASSIGN_OR_RETURN(
            auto key,
            db.statementFromStr(
                "INSERT OR IGNORE INTO ap_delivery_keys VALUES (?,?,?)"));
        DO_OR_RETURN((key.bind<std::string, std::string, std::string>(
            activity.id, std::string(signer_uri), inbox)));
        DO_OR_RETURN(db.execute(std::move(key)));
        if(db.changedRowsCount() == 0)
            continue;
        nlohmann::json payload = {{"target_inbox", inbox},
                                  {"signer_actor", signer_uri},
                                  {"activity", raw}};
        ASSIGN_OR_RETURN(auto id, store.enqueueJob("deliver", payload.dump(),
                                                   now ? now : timeNow(),
                                                   now ? now : timeNow()));
        ++result.target_count;
        (void)id;
    }
    DO_OR_RETURN(scope.release());
    return result;
}

mw::E<Publication> Session::publish(Transaction& tx, const nlohmann::json& raw,
                                    int64_t now)
{
    DO_OR_RETURN(checkTransaction(tx));
    ASSIGN_OR_RETURN(auto scope, Savepoint::begin(tx));
    ASSIGN_OR_RETURN(auto activity, parseActivity(raw));
    if(!validFields(raw) ||
       (activity.object.is_object() && !validFields(activity.object)))
        return std::unexpected(
            mw::httpError(400, "Invalid protocol field types"));
    ASSIGN_OR_RETURN(auto actor, localActor(activity.actor));
    if(!actor)
        return std::unexpected(mw::runtimeError("Actor is not local"));
    if(raw.contains("bto") || raw.contains("bcc"))
        return std::unexpected(
            mw::runtimeError("Hidden recipients are unsupported"));
    std::set<std::string> targets;
    for(const auto& addresses : {activity.to, activity.cc})
    {
        for(const auto& uri : addresses)
        {
            if(isPublicAddress(uri))
                continue;
            if(uri == stringField(actor->document, "followers"))
            {
                ASSIGN_OR_RETURN(auto followers,
                                 store.followerUris(activity.actor));
                targets.insert(followers.begin(), followers.end());
            }
            else
                targets.insert(uri);
        }
    }
    if(targets.size() > 10000)
        return std::unexpected(
            mw::runtimeError("Expanded audience limit exceeded"));
    std::vector<std::string> inboxes;
    for(const auto& uri : targets)
    {
        ASSIGN_OR_RETURN(auto local, localActor(uri));
        if(local)
            continue;
        ASSIGN_OR_RETURN(auto remote, store.getRemoteActorByUri(uri));
        if(!remote)
            return std::unexpected(mw::runtimeError(
                "Recipient must be resolved before publication"));
        bool is_public = publicDocument(raw);
        inboxes.push_back(is_public
                              ? remote->shared_inbox.value_or(remote->inbox)
                              : remote->inbox);
    }
    bool actor_update = activity.type == "Update" &&
                        normalizeRef(activity.object) ==
                            std::optional<std::string>(activity.actor);
    if(actor_update)
    {
        actor->document = activity.object;
        DO_OR_RETURN(registerActor(tx, *actor));
    }
    else if(activity.type == "Create" || activity.type == "Update" ||
            activity.type == "Delete")
    {
        auto object_uri = normalizeRef(activity.object);
        if(!object_uri)
            return std::unexpected(mw::runtimeError("Object is missing id"));
        ASSIGN_OR_RETURN(auto existing, object(*object_uri));
        if(existing && stringField(*existing, "attributedTo") != activity.actor)
            return std::unexpected(mw::runtimeError("Object owner mismatch"));
        if(activity.type == "Delete")
        {
            nlohmann::json tombstone = {{"id", *object_uri},
                                        {"type", "Tombstone"},
                                        {"attributedTo", activity.actor}};
            DO_OR_RETURN(
                writeObject(db, tombstone, activity.actor, true, true));
        }
        else if(activity.object.is_object())
        {
            if(stringField(activity.object, "attributedTo") != activity.actor)
                return std::unexpected(
                    mw::runtimeError("Object owner mismatch"));
            DO_OR_RETURN(
                writeObject(db, activity.object, activity.actor, true));
        }
    }
    ASSIGN_OR_RETURN(auto result,
                     enqueue(tx, activity.actor, raw, inboxes, now));
    DO_OR_RETURN(scope.release());
    return result;
}

mw::E<nlohmann::json> Session::fetchObject(std::string_view uri)
{
    ASSIGN_OR_RETURN(auto active, inTransaction(db));
    if(active)
        return std::unexpected(
            mw::runtimeError("Network I/O inside a write transaction"));
    ASSIGN_OR_RETURN(auto signing_actor, signer(config.system_actor_uri));
    DO_OR_RETURN(hardenOutboundSession(config.transport, http, uri));
    ASSIGN_OR_RETURN(auto req, signedHttpRequest(config.transport, crypto,
                                                 signing_actor, "GET", uri));
    http.followRedirects(false);
    DO_OR_RETURN(http.maxRedirections(0));
    DO_OR_RETURN(http.connectionTimeout(std::chrono::seconds(10)));
    DO_OR_RETURN(http.transferTimeout(std::chrono::seconds(30)));
    DO_OR_RETURN(http.maxSize(static_cast<long>(config.max_document_bytes)));
    ASSIGN_OR_RETURN(auto response_value,
                     getBounded(http, req, config.max_document_bytes));
    const auto* response = &response_value;
    if(response->status < 200 || response->status >= 300)
        return std::unexpected(
            mw::httpError(response->status, "Object fetch failed"));
    if(response->payload.size() > config.max_document_bytes)
        return std::unexpected(mw::httpError(413, "Remote document too large"));
    auto doc = nlohmann::json::parse(response->payloadAsStr(), nullptr, false);
    if(!doc.is_object() || !validFields(doc) ||
       !validDepth(doc, config.max_json_depth) ||
       (normalizeRef(doc) &&
        normalizeRef(doc) != std::optional<std::string>(std::string(uri))))
        return std::unexpected(mw::runtimeError("Invalid remote object"));
    return doc;
}

mw::E<VerifiedSignature> Session::verify(const IncomingHttpRequest& request,
                                         int64_t now)
{
    ASSIGN_OR_RETURN(auto signature,
                     parseHttpSignature(config.transport, request, now));
    ASSIGN_OR_RETURN(auto cached,
                     store.getRemoteActorByUri(signature.actor_uri));
    if(cached && cached->public_key_id == signature.key_id)
    {
        ASSIGN_OR_RETURN(bool ok,
                         verifyParsedHttpSignature(crypto, signature, *cached));
        if(ok)
            return VerifiedSignature{signature.actor_uri, signature.key_id,
                                     *cached, true, false};
    }
    ASSIGN_OR_RETURN(auto signing_actor, signer(config.system_actor_uri));
    DO_OR_RETURN(http.connectionTimeout(std::chrono::seconds(10)));
    DO_OR_RETURN(http.transferTimeout(std::chrono::seconds(30)));
    DO_OR_RETURN(http.maxSize(static_cast<long>(config.max_document_bytes)));
    ASSIGN_OR_RETURN(auto fetched,
                     fetchRemoteActor(config.transport, crypto, http,
                                      signing_actor, signature.actor_uri));
    ASSIGN_OR_RETURN(bool ok,
                     verifyParsedHttpSignature(crypto, signature, fetched));
    if(!ok)
        return std::unexpected(mw::httpError(401, "Bad signature"));
    if(cached)
    {
        ASSIGN_OR_RETURN(auto refreshed, store.upsertRemoteActor(fetched));
        fetched = std::move(refreshed);
    }
    return VerifiedSignature{signature.actor_uri, signature.key_id,
                             std::move(fetched), cached.has_value(),
                             cached.has_value()};
}

mw::E<PreparedInbox> Session::prepareInbox(const IncomingHttpRequest& request,
                                           std::string_view endpoint_actor,
                                           int64_t now)
{
    ASSIGN_OR_RETURN(bool active, inTransaction(db));
    if(active)
        return std::unexpected(
            mw::runtimeError("Inbox preparation requires no transaction"));
    size_t header_bytes = 0;
    for(const auto& [key, value] : request.headers)
    {
        if(key.size() + value.size() > 65536 - header_bytes)
            return std::unexpected(
                mw::httpError(431, "Inbox headers too large"));
        header_bytes += key.size() + value.size();
    }
    if(request.body.size() > config.max_inbox_bytes)
        return std::unexpected(mw::httpError(413, "Inbox body too large"));
    PreparedInbox prepared;
    ASSIGN_OR_RETURN(prepared.verified, verify(request, now));
    auto raw = nlohmann::json::parse(request.body, nullptr, false);
    if(!raw.is_object() || !validDepth(raw, config.max_json_depth))
        return std::unexpected(mw::httpError(400, "Invalid activity document"));
    ASSIGN_OR_RETURN(prepared.activity, parseActivity(raw));
    if(!validFields(raw) || (prepared.activity.object.is_object() &&
                             !validFields(prepared.activity.object)))
        return std::unexpected(
            mw::httpError(400, "Invalid protocol field types"));
    if(prepared.activity.to.size() + prepared.activity.cc.size() >
       config.max_recipients)
        return std::unexpected(mw::httpError(413, "Too many recipients"));
    if(prepared.activity.type == "Create" &&
       !prepared.activity.object.is_object())
    {
        auto uri = normalizeRef(prepared.activity.object);
        if(!uri)
            return std::unexpected(mw::httpError(400, "Missing Create object"));
        ASSIGN_OR_RETURN(prepared.activity.object, fetchObject(*uri));
    }
    if(prepared.activity.type == "Create")
    {
        auto object_uri = normalizeRef(prepared.activity.object);
        std::set<std::string> claimed;
        for(const auto& address : prepared.activity.to)
            claimed.insert(address);
        for(const auto& address : prepared.activity.cc)
            claimed.insert(address);
        ASSIGN_OR_RETURN(auto locals,
                         (db.eval<std::string, std::string>(
                             "SELECT uri,document_json FROM ap_local_actors")));
        std::vector<std::pair<std::string, std::string>> candidates;
        for(const auto& row : locals)
        {
            auto actor_doc =
                nlohmann::json::parse(std::get<1>(row), nullptr, false);
            auto followers = stringField(actor_doc, "followers");
            if(!followers.empty() && claimed.contains(followers))
                candidates.emplace_back(std::get<0>(row), followers);
        }
        if(object_uri && !candidates.empty())
        {
            ASSIGN_OR_RETURN(auto authoritative, fetchObject(*object_uri));
            auto parent = normalizeRef(
                authoritative.value("inReplyTo", nlohmann::json()));
            bool owned = false;
            std::set<std::string> seen;
            for(int depth = 0; parent && depth < config.fetch_depth; ++depth)
            {
                if(!seen.insert(*parent).second)
                    break;
                ASSIGN_OR_RETURN(auto known, object(*parent));
                if(!known)
                    break;
                ASSIGN_OR_RETURN(auto owner, localActor(stringField(
                                                 *known, "attributedTo")));
                if(owner)
                {
                    owned = true;
                    break;
                }
                parent =
                    normalizeRef(known->value("inReplyTo", nlohmann::json()));
            }
            if(owned && stringField(authoritative, "attributedTo") ==
                            prepared.activity.actor)
            {
                std::set<std::string> addressed;
                for(const char* key : {"to", "cc"})
                    for(const auto& address : normalizeAddressing(
                            authoritative.value(key, nlohmann::json())))
                        addressed.insert(address);
                for(const auto& candidate : candidates)
                    if(addressed.contains(candidate.second))
                        prepared.forward_collections.push_back(candidate);
                prepared.forward_document = prepared.activity.raw;
                prepared.forward_document["object"] = authoritative;
                for(const char* key : {"to", "cc"})
                {
                    if(authoritative.contains(key))
                        prepared.forward_document[key] = authoritative[key];
                    else
                        prepared.forward_document.erase(key);
                }
            }
        }
    }
    prepared.endpoint_actor = std::string(endpoint_actor);
    prepared.prepared_at = now;
    prepared.session_identity = this;
    return prepared;
}

mw::E<std::vector<std::string>>
Session::recipients(const Activity& activity) const
{
    std::set<std::string> result;
    std::vector<std::string> addresses = activity.to;
    addresses.insert(addresses.end(), activity.cc.begin(), activity.cc.end());
    if(activity.object.is_object())
        for(const char* key : {"to", "cc"})
        {
            auto values = normalizeAddressing(
                activity.object.value(key, nlohmann::json()));
            addresses.insert(addresses.end(), values.begin(), values.end());
        }
    auto target = normalizeRef(activity.object);
    if(target && activity.type == "Follow")
        addresses.push_back(*target);
    if((activity.type == "Accept" || activity.type == "Reject") &&
       activity.object.is_object())
        addresses.push_back(stringField(activity.object, "actor"));
    if(target)
    {
        ASSIGN_OR_RETURN(auto doc, object(*target));
        if(doc)
            addresses.push_back(stringField(*doc, "attributedTo"));
    }
    if(activity.object.is_object())
    {
        auto parent =
            normalizeRef(activity.object.value("inReplyTo", nlohmann::json()));
        if(parent)
        {
            ASSIGN_OR_RETURN(auto doc, object(*parent));
            if(doc)
                addresses.push_back(stringField(*doc, "attributedTo"));
        }
    }
    ASSIGN_OR_RETURN(auto locals,
                     (db.eval<std::string, std::string>(
                         "SELECT uri,document_json FROM ap_local_actors")));
    for(const auto& row : locals)
    {
        const auto& uri = std::get<0>(row);
        auto doc = nlohmann::json::parse(std::get<1>(row), nullptr, false);
        if(!doc.is_object())
            continue;
        auto followers = stringField(doc, "followers");
        bool addressed =
            std::find(addresses.begin(), addresses.end(), uri) !=
                addresses.end() ||
            (!followers.empty() && std::find(addresses.begin(), addresses.end(),
                                             followers) != addresses.end());
        bool is_public =
            publicDocument(activity.raw) ||
            (activity.object.is_object() && publicDocument(activity.object));
        if(!addressed && is_public)
        {
            ASSIGN_OR_RETURN(auto follow, store.getFollow(uri, activity.actor));
            addressed = follow && follow->state == FollowState::ACCEPTED;
            if(activity.type == "Create")
                addressed = true;
        }
        if(addressed)
            result.insert(uri);
    }
    return std::vector<std::string>(result.begin(), result.end());
}

mw::E<bool> Session::applyProtocol(Transaction& tx,
                                   const PreparedInbox& prepared,
                                   std::string_view recipient,
                                   Decision decision, int64_t now)
{
    const auto& activity = prepared.activity;
    auto target = normalizeRef(activity.object);
    if(activity.type == "Create" || activity.type == "Update" ||
       activity.type == "Delete")
    {
        if(!target)
            return false;
        ASSIGN_OR_RETURN(auto existing, object(*target));
        if(activity.type == "Delete")
        {
            if(!existing ||
               stringField(*existing, "attributedTo") != activity.actor)
                return false;
            ASSIGN_OR_RETURN(auto local, localActor(activity.actor));
            if(local)
                return false;
            nlohmann::json tombstone = {{"id", *target},
                                        {"type", "Tombstone"},
                                        {"attributedTo", activity.actor}};
            DO_OR_RETURN(
                writeObject(db, tombstone, activity.actor, false, true));
            return true;
        }
        std::string type = stringField(activity.object, "type");
        if(type == "Person" || type == "Service" || type == "Application")
        {
            if(*target != activity.actor || activity.type != "Update")
                return false;
            ASSIGN_OR_RETURN(auto old,
                             store.getRemoteActorByUri(activity.actor));
            if(!old)
                return false;
            auto actor = *old;
            actor.actor_json = activity.object.dump();
            actor.display_name = stringField(activity.object, "name");
            auto inbox = stringField(activity.object, "inbox");
            if(!isValidRemoteUrl(config.transport.dev, inbox))
                return false;
            actor.inbox = inbox;
            actor.fetched_at = now;
            ASSIGN_OR_RETURN(auto saved, store.upsertRemoteActor(actor));
            (void)saved;
            return true;
        }
        if(type != "Note" && type != "Article" && type != "Image")
            return false;
        ASSIGN_OR_RETURN(
            auto actor_origins,
            db.eval<std::string>("SELECT uri FROM ap_local_actors"));
        auto target_url = mw::URL::fromStr(*target);
        for(const auto& row : actor_origins)
        {
            auto local_url = mw::URL::fromStr(std::get<0>(row));
            if(target_url && local_url &&
               target_url->scheme() == local_url->scheme() &&
               target_url->host() == local_url->host() &&
               target_url->port() == local_url->port())
                return false;
        }
        if(stringField(activity.object, "attributedTo") != activity.actor)
            return false;
        if(existing && stringField(*existing, "attributedTo") != activity.actor)
            return false;
        if(activity.type == "Create" && existing)
            return false;
        if(activity.type == "Update" && !existing)
            return false;
        ASSIGN_OR_RETURN(auto local, localActor(activity.actor));
        if(local)
            return false;
        DO_OR_RETURN(writeObject(db, activity.object, activity.actor, false));
        return true;
    }
    if(activity.type == "Follow")
    {
        if(!target || *target != recipient)
            return false;
        ASSIGN_OR_RETURN(auto local, localActor(*target));
        if(!local)
            return false;
        Follow follow;
        follow.follower_uri = activity.actor;
        follow.followee_uri = *target;
        follow.follow_activity_uri = activity.id;
        follow.state = decision == Decision::PENDING_APPROVAL
                           ? FollowState::PENDING
                           : FollowState::ACCEPTED;
        follow.created_at = now;
        if(decision != Decision::REJECT)
        {
            DO_OR_RETURN(store.addFollow(follow));
        }
        if(decision == Decision::PENDING_APPROVAL)
            return true;
        ASSIGN_OR_RETURN(auto id, newActivityUri(config.activity_uri_prefix));
        nlohmann::json response = {
            {"@context", "https://www.w3.org/ns/activitystreams"},
            {"id", id},
            {"type", decision == Decision::REJECT ? "Reject" : "Accept"},
            {"actor", *target},
            {"object", activity.raw},
            {"to", nlohmann::json::array({activity.actor})}};
        ASSIGN_OR_RETURN(auto queued, enqueue(tx, *target, response,
                                              {prepared.verified.actor.inbox}));
        (void)queued;
        return true;
    }
    if(activity.type == "Accept" || activity.type == "Reject")
    {
        if(!activity.object.is_object() ||
           stringField(activity.object, "type") != "Follow")
            return false;
        auto follower =
            normalizeRef(activity.object.value("actor", nlohmann::json()));
        auto followee =
            normalizeRef(activity.object.value("object", nlohmann::json()));
        auto follow_id = normalizeRef(activity.object);
        if(!follower || !followee || *followee != activity.actor)
            return false;
        ASSIGN_OR_RETURN(auto follow, store.getFollow(*follower, *followee));
        if(!follow || follow->follow_activity_uri != follow_id)
            return false;
        ASSIGN_OR_RETURN(auto local, localActor(*follower));
        if(!local)
            return false;
        if(activity.type == "Accept")
        {
            DO_OR_RETURN(store.setFollowState(*follower, *followee,
                                              FollowState::ACCEPTED));
        }
        else
        {
            DO_OR_RETURN(store.removeFollow(*follower, *followee));
        }
        return true;
    }
    if(activity.type == "Undo")
    {
        if(!activity.object.is_object())
            return false;
        ASSIGN_OR_RETURN(auto original, parseActivity(activity.object));
        if(original.actor != activity.actor)
            return false;
        auto object_uri = normalizeRef(original.object);
        if(!object_uri)
            return false;
        if(original.type == "Follow")
        {
            ASSIGN_OR_RETURN(auto follow,
                             store.getFollow(activity.actor, *object_uri));
            if(!follow || (follow->follow_activity_uri &&
                           *follow->follow_activity_uri != original.id))
                return false;
            DO_OR_RETURN(store.removeFollow(activity.actor, *object_uri));
            return true;
        }
        if(original.type == "Like")
        {
            ASSIGN_OR_RETURN(auto rows, store.likesForPost(*object_uri));
            for(const auto& row : rows)
                if(row.actor_uri == activity.actor &&
                   (!row.activity_uri || *row.activity_uri == original.id))
                {
                    DO_OR_RETURN(store.removeLike(activity.actor, *object_uri));
                    return true;
                }
        }
        if(original.type == "Announce")
        {
            ASSIGN_OR_RETURN(auto rows, store.boostsForPost(*object_uri));
            for(const auto& row : rows)
                if(row.actor_uri == activity.actor &&
                   (!row.activity_uri || *row.activity_uri == original.id))
                {
                    DO_OR_RETURN(
                        store.removeBoost(activity.actor, *object_uri));
                    return true;
                }
        }
        if(original.type == "EmojiReact")
        {
            ASSIGN_OR_RETURN(auto rows, store.reactionsForPost(*object_uri));
            for(const auto& row : rows)
                if(row.actor_uri == activity.actor &&
                   row.emoji == stringField(original.raw, "content") &&
                   (!row.activity_uri || *row.activity_uri == original.id))
                {
                    DO_OR_RETURN(store.removeReaction(activity.actor,
                                                      *object_uri, row.emoji));
                    return true;
                }
        }
        return false;
    }
    if(!target)
        return false;
    ASSIGN_OR_RETURN(auto doc, objectForActor(*target, activity.actor));
    if(!doc || stringField(*doc, "type") == "Tombstone")
        return false;
    if(activity.type == "Like")
    {
        Like like;
        like.actor_uri = activity.actor;
        like.post_uri = *target;
        like.activity_uri = activity.id;
        like.created_at = now;
        DO_OR_RETURN(store.addLike(like));
        return true;
    }
    if(activity.type == "Announce")
    {
        if(!publicDocument(*doc))
            return false;
        Boost boost;
        boost.actor_uri = activity.actor;
        boost.post_uri = *target;
        boost.activity_uri = activity.id;
        boost.created_at = now;
        DO_OR_RETURN(store.addBoost(boost));
        return true;
    }
    if(activity.type == "EmojiReact")
    {
        auto emoji = stringField(activity.raw, "content");
        if(emoji.empty())
            emoji = stringField(activity.raw, "name");
        if(emoji.empty() || emoji.size() > 256)
            return false;
        Reaction reaction;
        reaction.actor_uri = activity.actor;
        reaction.post_uri = *target;
        reaction.emoji = emoji;
        reaction.activity_uri = activity.id;
        reaction.created_at = now;
        auto tags = activity.raw.find("tag");
        if(tags != activity.raw.end() && tags->is_array())
            for(const auto& tag : *tags)
                if(tag.is_object() && stringField(tag, "type") == "Emoji" &&
                   (stringField(tag, "name") == emoji ||
                    ":" + stringField(tag, "name") + ":" == emoji) &&
                   tag.contains("icon") && tag["icon"].is_object())
                {
                    auto url = stringField(tag["icon"], "url");
                    if(isValidRemoteUrl(config.transport.dev, url))
                    {
                        reaction.remote_emoji_url = url;
                        reaction.remote_emoji_media_type =
                            stringField(tag["icon"], "mediaType");
                        if(reaction.remote_emoji_media_type->empty())
                            reaction.remote_emoji_media_type = "image/png";
                    }
                }
        DO_OR_RETURN(store.addReaction(reaction));
        return true;
    }
    return false;
}

mw::E<InboxResult> Session::acceptInbox(PreparedInbox&& prepared, int64_t now)
{
    if(prepared.session_identity != this || now - prepared.prepared_at > 300 ||
       now < prepared.prepared_at)
        return std::unexpected(
            mw::runtimeError("Expired or foreign prepared inbox"));
    prepared.session_identity = nullptr;
    // A forwarder can only trigger the separately verified forwarding path.
    bool direct = prepared.activity.actor == prepared.verified.actor_uri;
    if(!direct && prepared.forward_collections.empty())
        return InboxResult{};
    ASSIGN_OR_RETURN(auto tx, Transaction::begin(db));
    const auto& activity = prepared.activity;
    ASSIGN_OR_RETURN(auto legacy, db.statementFromStr(
                                      "SELECT 1 FROM ap_seen_activities WHERE "
                                      "activity_uri=? AND state='processed'"));
    DO_OR_RETURN(legacy.bind<std::string>(activity.id));
    ASSIGN_OR_RETURN(auto legacy_rows, db.eval<int64_t>(std::move(legacy)));
    if(!legacy_rows.empty())
    {
        DO_OR_RETURN(tx.commit());
        return InboxResult{true, false, false};
    }
    ASSIGN_OR_RETURN(
        auto prior,
        db.statementFromStr("SELECT actor_uri,document_json,applied FROM "
                            "ap_inbox_activities WHERE activity_uri=?"));
    DO_OR_RETURN(prior.bind<std::string>(activity.id));
    ASSIGN_OR_RETURN(auto rows, (db.eval<std::string, std::string, int64_t>(
                                    std::move(prior))));
    bool global_applied = !rows.empty() && std::get<2>(rows.front()) != 0;
    if(!rows.empty() && (std::get<0>(rows.front()) != activity.actor ||
                         std::get<1>(rows.front()) != activity.raw.dump()))
        return std::unexpected(mw::httpError(400, "Activity ID collision"));
    ASSIGN_OR_RETURN(auto targets, recipients(activity));
    if(!prepared.endpoint_actor.empty())
        std::erase_if(targets, [&](const auto& target)
                      { return target != prepared.endpoint_actor; });
    InboxResult result;
    bool new_recipient = false;
    for(const auto& target : targets)
    {
        ASSIGN_OR_RETURN(
            auto receipt,
            db.statementFromStr("SELECT 1 FROM ap_inbox_receipts WHERE "
                                "activity_uri=? AND recipient_uri=?"));
        DO_OR_RETURN(
            (receipt.bind<std::string, std::string>(activity.id, target)));
        ASSIGN_OR_RETURN(auto done, db.eval<int64_t>(std::move(receipt)));
        if(!done.empty())
            continue;
        new_recipient = true;
        ValidatedActivity validated(activity);
        ASSIGN_OR_RETURN(auto decision,
                         application.decide(tx, validated, {target}));
        bool applied = false;
        bool changed = false;
        if(direct &&
           (decision == Decision::ACCEPT ||
            decision == Decision::PENDING_APPROVAL ||
            (decision == Decision::REJECT && activity.type == "Follow")))
        {
            if(global_applied)
                applied = true;
            else
            {
                // Retention and effects are rolled back together on no-op.
                ASSIGN_OR_RETURN(auto effect_scope, Savepoint::begin(tx));
                ASSIGN_OR_RETURN(auto actor, store.upsertRemoteActor(
                                                 prepared.verified.actor));
                (void)actor;
                ASSIGN_OR_RETURN(applied, applyProtocol(tx, prepared, target,
                                                        decision, now));
                if(applied)
                {
                    DO_OR_RETURN(effect_scope.release());
                    global_applied = true;
                    changed = true;
                }
            }
            if(applied)
            {
                ASSIGN_OR_RETURN(auto actor,
                                 store.getRemoteActorByUri(activity.actor));
                if(!actor)
                    return std::unexpected(
                        mw::runtimeError("Applied actor missing"));
                DO_OR_RETURN(
                    application.apply(tx, {activity, target, *actor, changed}));
                result.applied = true;
            }
        }
        if(decision == Decision::ACCEPT)
        {
            for(const auto& collection : prepared.forward_collections)
            {
                if(collection.first != target)
                    continue;
                ASSIGN_OR_RETURN(auto followers, store.followerUris(target));
                std::vector<std::string> inboxes;
                for(const auto& follower : followers)
                {
                    ASSIGN_OR_RETURN(auto local, localActor(follower));
                    if(local)
                        continue;
                    ASSIGN_OR_RETURN(auto remote,
                                     store.getRemoteActorByUri(follower));
                    if(remote)
                        inboxes.push_back(
                            publicDocument(prepared.forward_document)
                                ? remote->shared_inbox.value_or(remote->inbox)
                                : remote->inbox);
                }
                ASSIGN_OR_RETURN(auto queued,
                                 enqueue(tx, target, prepared.forward_document,
                                         inboxes, now));
                result.forwarded = result.forwarded || queued.target_count != 0;
            }
        }
        ASSIGN_OR_RETURN(
            auto insert,
            db.statementFromStr("INSERT INTO ap_inbox_receipts VALUES (?,?)"));
        DO_OR_RETURN(
            (insert.bind<std::string, std::string>(activity.id, target)));
        DO_OR_RETURN(db.execute(std::move(insert)));
    }
    ASSIGN_OR_RETURN(
        auto insert,
        db.statementFromStr(
            "INSERT INTO ap_inbox_activities VALUES (?,?,?,?,?) "
            "ON CONFLICT(activity_uri) DO UPDATE SET applied=excluded.applied,"
            "processed_at=excluded.processed_at"));
    DO_OR_RETURN(
        (insert.bind<std::string, std::string, std::string, int64_t, int64_t>(
            activity.id, activity.actor, activity.raw.dump(),
            global_applied ? 1 : 0, now)));
    DO_OR_RETURN(db.execute(std::move(insert)));
    result.duplicate = !rows.empty() && !new_recipient;
    DO_OR_RETURN(tx.commit());
    return result;
}

mw::E<bool> Session::runOnce(int64_t now)
{
    ASSIGN_OR_RETURN(bool active, inTransaction(db));
    if(active)
        return std::unexpected(mw::runtimeError("Worker inside transaction"));
    if(config.max_fetch_requests > 32 || config.job_lease_seconds < 1100)
        return std::unexpected(
            mw::runtimeError("Unsafe worker lease/fetch limits"));
    ASSIGN_OR_RETURN(auto job, store.claimJob(now, config.job_lease_seconds));
    if(!job)
        return false;
    auto run = [&]() -> mw::E<void>
    {
        auto payload = nlohmann::json::parse(job->payload_json, nullptr, false);
        if(!payload.is_object())
            return std::unexpected(mw::runtimeError("Unsupported job payload"));
        if(job->kind == "fetch_thread")
        {
            std::set<std::string> seen;
            size_t budget = config.max_fetch_requests;
            return fetchThread(stringField(payload, "root_uri"),
                               config.fetch_depth, seen, budget);
        }
        if(job->kind != "deliver")
            return std::unexpected(mw::runtimeError("Unsupported job kind"));
        auto inbox = stringField(payload, "target_inbox");
        auto actor_uri = stringField(payload, "signer_actor");
        ASSIGN_OR_RETURN(auto local, signer(actor_uri));
        if(!payload.contains("activity") || !payload["activity"].is_object())
            return std::unexpected(
                mw::runtimeError("Missing delivery activity"));
        DO_OR_RETURN(hardenOutboundSession(config.transport, http, inbox));
        ASSIGN_OR_RETURN(
            auto req, signedHttpRequest(config.transport, crypto, local, "POST",
                                        inbox, payload["activity"].dump(),
                                        "application/activity+json"));
        http.followRedirects(false);
        DO_OR_RETURN(http.maxRedirections(0));
        DO_OR_RETURN(http.connectionTimeout(std::chrono::seconds(10)));
        DO_OR_RETURN(http.transferTimeout(std::chrono::seconds(30)));
        DO_OR_RETURN(
            http.maxSize(static_cast<long>(config.max_document_bytes)));
        ASSIGN_OR_RETURN(auto response_value,
                         postBounded(http, req, config.max_document_bytes));
        const auto* response = &response_value;
        if(response->status < 200 || response->status >= 300)
            return std::unexpected(
                mw::httpError(response->status, "Delivery failed"));
        return {};
    };
    auto result = run();
    if(result)
    {
        DO_OR_RETURN(store.completeJob(*job));
    }
    else
    {
        int retries = config.max_retries;
        if(const auto* error = result.error().as<mw::HTTPError>();
           error && error->code >= 400 && error->code < 500 &&
           error->code != 408 && error->code != 429)
            retries = 1;
        DO_OR_RETURN(store.failJob(*job, mw::errorMsg(result.error()), now,
                                   config.retry_base_seconds, retries));
    }
    return true;
}

mw::E<void> Session::importFetchedObject(const nlohmann::json& doc,
                                         size_t& budget)
{
    auto uri = normalizeRef(doc);
    auto actor_uri = stringField(doc, "attributedTo");
    if(!uri || actor_uri.empty())
        return std::unexpected(
            mw::runtimeError("Fetched object has no owner or ID"));
    ASSIGN_OR_RETURN(auto local, localActor(actor_uri));
    if(!local)
    {
        ASSIGN_OR_RETURN(auto actor, store.getRemoteActorByUri(actor_uri));
        if(!actor)
        {
            if(budget == 0)
                return {};
            --budget;
            ASSIGN_OR_RETURN(auto signing_actor,
                             signer(config.system_actor_uri));
            ASSIGN_OR_RETURN(auto fetched,
                             fetchRemoteActor(config.transport, crypto, http,
                                              signing_actor, actor_uri));
            actor = std::move(fetched);
        }
        PreparedInbox prepared;
        prepared.activity.id = *normalizeRef(doc) + "#fetch";
        prepared.activity.type = "Create";
        prepared.activity.actor = actor_uri;
        prepared.activity.object = doc;
        prepared.activity.raw = {{"id", prepared.activity.id},
                                 {"type", "Create"},
                                 {"actor", actor_uri},
                                 {"object", doc}};
        prepared.verified = {actor_uri, actor->public_key_id, *actor,
                             actor->id != 0, false};
        prepared.prepared_at = timeNow();
        prepared.session_identity = this;
        ASSIGN_OR_RETURN(auto result,
                         acceptInbox(std::move(prepared), timeNow()));
        (void)result;
    }

    return {};
}

mw::E<nlohmann::json> Session::fetchAndStoreObject(std::string_view uri)
{
    ASSIGN_OR_RETURN(auto old, object(uri));
    if(old)
        return *old;
    ASSIGN_OR_RETURN(auto doc, fetchObject(uri));
    if(stringField(doc, "type") == "Create" && doc.contains("object") &&
       doc["object"].is_object())
    {
        if(stringField(doc, "actor") !=
           stringField(doc["object"], "attributedTo"))
            return std::unexpected(
                mw::runtimeError("Fetched Create author mismatch"));
        doc = doc["object"];
    }
    auto id = normalizeRef(doc);
    if(!id)
        return std::unexpected(mw::runtimeError("Fetched object has no ID"));
    size_t budget = config.max_fetch_requests;
    DO_OR_RETURN(importFetchedObject(doc, budget));
    ASSIGN_OR_RETURN(auto stored, object(*id));
    if(!stored)
        return std::unexpected(mw::runtimeError("Fetched object was ignored"));
    return *stored;
}

mw::E<void> Session::fetchThread(std::string_view uri, int depth,
                                 std::set<std::string>& seen, size_t& budget)
{
    if(depth <= 0 || budget == 0 || uri.empty() ||
       !seen.insert(std::string(uri)).second)
        return {};
    --budget;
    ASSIGN_OR_RETURN(auto existing, object(uri));
    nlohmann::json doc;
    if(existing)
        doc = *existing;
    else
    {
        ASSIGN_OR_RETURN(doc, fetchObject(uri));
    }
    if(!doc.is_object())
        return {};
    auto type = stringField(doc, "type");
    if(type == "Note" || type == "Article" || type == "Image")
    {
        if(!existing)
        {
            DO_OR_RETURN(importFetchedObject(doc, budget));
        }
        auto parent = normalizeRef(doc.value("inReplyTo", nlohmann::json()));
        if(parent)
        {
            ASSIGN_OR_RETURN(auto stored, object(*parent));
            if(!stored)
            {
                DO_OR_RETURN(fetchThread(*parent, depth - 1, seen, budget));
            }
        }
    }
    for(const char* key : {"replies", "first", "next"})
    {
        auto value = doc.find(key);
        if(value == doc.end())
            continue;
        for(const char* items : {"orderedItems", "items"})
        {
            if(!value->is_object() || !value->contains(items) ||
               !(*value)[items].is_array())
                continue;
            for(const auto& item : (*value)[items])
            {
                auto target = normalizeRef(item);
                if(target)
                {
                    DO_OR_RETURN(fetchThread(*target, depth - 1, seen, budget));
                }
            }
        }
        auto target = normalizeRef(*value);
        if(target)
        {
            DO_OR_RETURN(fetchThread(*target, depth - 1, seen, budget));
        }
        else if(value->is_object() && value->contains("first"))
        {
            auto first = normalizeRef((*value)["first"]);
            if(first)
            {
                DO_OR_RETURN(fetchThread(*first, depth - 1, seen, budget));
            }
        }
    }
    for(const char* key : {"orderedItems", "items"})
    {
        auto items = doc.find(key);
        if(items == doc.end() || !items->is_array())
            continue;
        for(const auto& item : *items)
        {
            auto target = normalizeRef(item);
            if(target)
            {
                DO_OR_RETURN(fetchThread(*target, depth - 1, seen, budget));
            }
        }
    }
    return {};
}

} // namespace ap
