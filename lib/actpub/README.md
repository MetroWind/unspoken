# ActivityPub library

`ActPub::actpub` is an embedded C++23 federation library for applications
using libmw and SQLite. Unspoken is its first consumer. The target has no
Unspoken, OIDC, Markdown, Inja, or libxml2 dependency. HTML sanitization and
presentation remain application responsibilities.

The implementation is built with `add_subdirectory(lib/actpub)` by the
parent project. Its libmw, nlohmann/json, and spdlog dependencies are supplied
by that project. External package installation and a second application
are outside the current scope.

## Connection and lifetime

Create one SQLite connection and `ap::Session` for each request thread or
worker. Enable foreign keys and a bounded busy timeout on connections; the
host selects WAL and durability settings before starting workers. Pass the
same connection to application repositories and the federation session.
Sharing a database filename through different connections does not share
a transaction.

The session borrows its configuration, connection, crypto context, HTTP
session, and application hooks. Those objects must outlive it. Initialize
the schema with `session.migrate()` before accepting requests or starting
workers. Library tables have an `ap_` prefix and a separate `ap_schema`
version; application schema versioning remains under the application's
control.

## Application hooks

Implement `ap::Application`:

- `decide()` selects relevance/moderation policy after protocol checks.
  Return `ACCEPT`, `IGNORE`, `REJECT`, or `PENDING_APPROVAL`. Pending approval
  is for follows. For example, a blog can accept only replies to its own
  entries and ignore unrelated public content.
- `apply()` updates the application's own projections after an accepted
  protocol effect. Write comments, notifications, or timeline records using
  `tx.connection()`. A failure rolls back protocol effects, host changes,
  outgoing responses, and inbox receipts together.

Hooks may perform bounded in-memory transformations and SQLite work. They
must not perform network or filesystem I/O inside the write transaction.
Incoming content, including actor profiles and extensions, is untrusted for
rendering even after authentication. Apply the application's sanitizer or
plain-text policy before displaying it.

`AppliedEvent::global_effect` identifies the first global mutation of an
activity. On later delivery to another local recipient it is false. Avoid
reapplying an old Update to a shared application content row; recipient
notifications can still be inserted with an activity/recipient uniqueness
constraint.

There is no storage interface for the application to implement. `ap::Store`
provides the concrete actor, follow, interaction, receipt, and job SQL. Host
content tables remain host-owned. Explicit actor-reference pins through
`Store::pinActor()`/`unpinActor()` prevent collection of identities needed by
host-only data. Unspoken maintains these through its projection-table
triggers.

## Register actors

`Session::registerActor()` accepts an exact actor URI, key ID, private PEM,
and host-produced public actor document. It imposes no `/u/` or `/p/` URL
layout. Generate/import keys once and retain their identity across restarts.
Registration uses a caller-owned transaction.

The public document should contain `id`, `type`, `inbox`, `outbox`,
`followers`, `following`, and `publicKey` as appropriate. The host owns
profile rendering and media URLs. `localActor()` also returns signing
metadata for trusted application code: serialize only its `document`, never
the entire registration or private key fields.

## Publish atomically

Prepare content and media outside the write transaction. Then commit the
native record and its ActivityStreams representation together:

```cpp
// The session and host repository borrow the same connection.
ASSIGN_OR_RETURN(auto tx, ap::Transaction::begin(connection));
ASSIGN_OR_RETURN(auto entry, entries.insert(tx.connection(), params));
ASSIGN_OR_RETURN(auto activity_uri,
    ap::newActivityUri("https://example.org/activities/"));

nlohmann::json object = {
    {"id", entry.uri},
    {"type", "Article"},
    {"attributedTo", actor_uri},
    {"content", entry.html},
    {"to", nlohmann::json::array({ap::AS_PUBLIC})},
};
nlohmann::json activity = {
    {"@context", "https://www.w3.org/ns/activitystreams"},
    {"id", activity_uri},
    {"type", "Create"},
    {"actor", actor_uri},
    {"object", object},
    {"to", object["to"]},
    {"cc", nlohmann::json::array({followers_uri})},
};
ASSIGN_OR_RETURN(auto publication, session.publish(tx, activity));
DO_OR_RETURN(tx.commit());
```

The repository and entry above are illustrative application code, not
library classes. `publication` is provisional until commit succeeds.
Recipient identities must already be resolved/retained before publication;
network lookup must precede the transaction. Publication snapshots accepted
followers and stores immutable outgoing activity JSON. Retrying delivery
uses the stored ID/body. Recreating an interaction uses a new activity ID;
Undo identifies the original interaction.

Typed `Store` relationship operations compose with `Session::publish()` in
the same transaction. Unspoken's service/federation facade constructs its
activity documents and uses these operations; consumers do not implement
relationship SQL. Actor Update refreshes the registered public snapshot;
content Create/Update/Delete update the protocol object's snapshot.

## HTTP endpoints

The host registers its libmw routes and supplies exact actor/object URIs.

For inbox POST:

1. Copy the original HTTP method, target (including query), headers, and
   exact body bytes into `IncomingHttpRequest`.
2. Call `prepareInbox()` without a write transaction. It verifies signatures
   and performs bounded protected fetches as needed.
3. Call `acceptInbox()` on that same session. It owns the short transaction
   for protocol effects, host hooks, forwarding jobs, and scoped receipts.
4. Return success only after it commits. A duplicate/ignored request may
   return 200; accepted effects/forwarding may return 202.

Pass a registered actor URI for a personal inbox, or an empty endpoint
actor for the shared inbox. Do not pass a caller-supplied body actor as the
personal endpoint identity.

For object GET/HEAD, use `objectForActor()`, passing either a trusted local
identity from host authentication or the actor authenticated by
`authenticate()`. An empty actor means anonymous. Return 404 when absent
or unauthorized. `object()` is an unrestricted internal snapshot query for
trusted application logic; it is not an authorization API.

`outboxPage()` exposes only public/unlisted activities and uses library
sequence cursors. Collection JSON helpers provide roots and page links;
typed `Store` follower/following queries use preserved relationship
sequences. Set ActivityPub content types, `Vary: Accept` on negotiated
routes, and appropriate private cache controls in the host response.

WebFinger self-link resolution, request signing, remote actor fetching,
reference normalization, and outbound protections are available in
`transport.hpp`. Helpers do not implement arbitrary remote JSON-LD contexts.

## Workers and recovery

Call `runOnce(now)` from a host-managed loop; false means idle. The library
does not start threads or sleep on an empty queue. The worker handles
stored deliveries and bounded thread backfill. Each worker has its own
connection and libmw HTTP/crypto context.

Claims have random tokens and expiry. Only the current token may complete
or fail a job. An expired claim is recoverable; a stale worker cannot
finalize the replacement's work. Deliveries sharing a signer/destination
stream cannot overtake an earlier pending/running job. Delivery is
at-least-once: a crash after peer acceptance can cause a retry of the same
activity. Retryable errors use capped exponential backoff; Retry-After and
jitter are not currently implemented. A permanently failed job does not
block later work indefinitely.

Stop claiming jobs on shutdown and wait for bounded active requests. The
initial maximum fetch budget is 32 requests with 30-second HTTP deadlines;
worker leases have a validated minimum of 1,100 seconds. Call
`Store::pruneIncomingActivities()` and
`Store::collectUnreferencedRemoteActors()` periodically with bounded batches.
Retention checks include accepted protocol state, pending jobs, and host
reference pins.
