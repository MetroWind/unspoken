# Design Document: Remote Actor Lifecycle

**Status:** Draft
**Source requirements:** [`prd.md`](../prd.md), especially HTTP signature
verification, signed remote fetches, SSRF protection, remote post storage,
follows, interactions, deliveries, and activity deduplication.
**Source task:** [`todo.md`](../todo.md), "Avoid permanent actor-cache growth
from irrelevant inbox traffic."
**Related designs:**
[`design-0-architecture.md`](design-0-architecture.md),
[`design-2-interop.md`](design-2-interop.md), and
[`design-3-profile.md`](design-3-profile.md).
**Scope:** Separate remote actor acquisition, HTTP-signature verification,
and durable actor retention. Persist remote actors only while local state
needs their identity or delivery metadata. Bound activity-deduplication state
and close authorization gaps that affect the retention decision.

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Goals and Non-Goals](#2-goals-and-non-goals)
3. [External References](#3-external-references)
4. [Terminology and Invariants](#4-terminology-and-invariants)
5. [Current Behavior](#5-current-behavior)
6. [Architecture](#6-architecture)
7. [Actor Types and APIs](#7-actor-types-and-apis)
8. [HTTP-Signature Verification](#8-http-signature-verification)
9. [Inbox Processing](#9-inbox-processing)
10. [Authorization Rules](#10-authorization-rules)
11. [Activity Deduplication](#11-activity-deduplication)
12. [Actor Retention and Collection](#12-actor-retention-and-collection)
13. [Database Migration](#13-database-migration)
14. [Errors and Concurrency](#14-errors-transactions-and-concurrency)
15. [Implementation Plan](#15-implementation-plan)
16. [Testing Strategy](#16-testing-strategy)
17. [Observability](#17-observability)
18. [Deployment and Rollout](#18-deployment-and-rollout)
19. [Alternatives Considered](#19-alternatives-considered)
20. [Acceptance Criteria](#20-acceptance-criteria)

---

## 1. Problem Statement

The `remote_actors` table currently serves three different purposes:

1. It stores durable identity and profile data for remote accounts relevant
   to local users.
2. It maps stored remote posts to their authors through
   `posts.remote_author_id`.
3. It caches public keys used to verify inbound HTTP signatures.

These purposes have different lifetimes. A remote post author or follower can
remain relevant for months. A public key fetched only to verify one ignored
inbox activity may be useful for a few milliseconds. Treating both lifetimes
as permanent causes unbounded database growth.

The production-derived schema-v1 fixture exposed the failure mode. Before the
fixture was sanitized, it contained approximately 4,330 remote actor rows on
an instance with approximately ten local posts. Most actors came from
`mastodon.social`. The corresponding `seen_activities` population was of the
same order, and recent IDs were largely account `Delete` activities ending in
`#delete` that did not reference any locally stored object.

The current inbox sequence is:

1. Parse HTTP-signature metadata and validate the request envelope.
2. Derive an actor URI from the signature `keyId`.
3. Call `resolveRemoteActor()` when that actor is not cached.
4. Fetch the actor with a system-actor-signed, SSRF-protected GET.
5. Insert the fetched actor into `remote_actors`.
6. Verify the signature with the newly stored key.
7. Parse and dispatch the activity.
8. Ignore an irrelevant activity such as `Delete` for an unknown object.

Step 5 makes an actor durable before step 8 determines whether any durable
state needs that actor. The actor row remains indefinitely even though the
activity had no effect.

The generic name `resolveRemoteActor()` hides this policy. Some callers need
only a fetched document. Some callers may use an existing cached document but
do not need to retain a newly fetched one. Other callers require a durable row
because they are about to store a post, follow, interaction, or future
delivery relationship. A single function cannot make the correct lifetime
decision for all of these callers.

The same traffic reveals a related issue in `seen_activities`. Every unique,
verified activity ID is stored permanently before dispatch, including ignored
traffic. If dispatch subsequently fails, the activity nevertheless remains
marked as seen and a retry is discarded. The actor lifecycle can be fixed
without fixing deduplication, but doing so would leave the other unbounded
table and an existing retry correctness bug. This design therefore includes a
bounded claim-and-finalize deduplication lifecycle.

## 2. Goals and Non-Goals

### 2.1 Goals

- Make a network fetch of an unknown remote actor non-persistent by default.
- Make durable actor retention an explicit operation requested by the
  workflow that creates durable local state.
- Preserve cached actor reuse for normal reads and verification.
- Preserve one-time key refresh when a retained actor rotates its key.
- Update a retained actor only after the refreshed key verifies the request.
- Never parse or act on ActivityPub body contents before authenticating the
  HTTP request that carries them.
- Keep every remote actor fetch system-actor-signed.
- Keep scheme, address, redirect, and connected-IP SSRF protections on every
  remote fetch.
- Retain remote authors needed to render stored posts.
- Retain remote followers and followees needed for federation and delivery.
- Retain actors associated with stored interactions when their identity is
  part of the stored user-facing state.
- Avoid retaining actors for ignored, unsupported, unauthorized, or otherwise
  irrelevant inbox activities.
- Bound the lifetime of activity IDs used for deduplication.
- Ensure a dispatch failure can be retried rather than being permanently
  mistaken for a successful delivery.
- Define authorization before relevance, so an unauthorized activity cannot
  create state or justify retaining an actor.
- Provide focused unit, data, and interop coverage for the new lifecycle.
- Preserve thin HTTP handlers and keep policy in federation and data layers.

### 2.2 Non-Goals

- Do not add a general-purpose remote media proxy or profile media cache.
- Do not implement Linked Data Signatures.
- Do not replace Cavage HTTP signatures with HTTP Message Signatures.
- Do not add moderation, domain blocking, or federation allowlists.
- Do not guarantee that remote profile data is always fresh.
- Do not retain every actor returned by user search merely to accelerate a
  later search.
- Do not use activity contents to decide whether an unknown actor should be
  fetched before the HTTP signature is verified.
- Do not make `remote_actors` an audit log of every authenticated peer.
- Do not require a persistent verification-key row for unknown actors.
- Do not introduce an unbounded in-memory verification cache. A bounded
  in-memory cache can be added later if measurements show that repeated
  transient fetches are a problem.
- Do not redesign every federation data operation into one universal event
  transaction. This design adds transactional boundaries only where actor
  identity and the state write must succeed together.

## 3. External References

- [ActivityPub Recommendation](https://www.w3.org/TR/activitypub/), especially
  inbox delivery, forwarding, and activity side effects.
- [ActivityStreams 2.0](https://www.w3.org/TR/activitystreams-core/) for actor,
  object, and activity structures.
- [Cavage HTTP Signatures
  draft](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures)
  for the deployed `Signature` header format.
- [ActivityPub HTTP Signature
  profile](https://swicg.github.io/activitypub-http-signature/)
  for Fediverse-specific signing and verification guidance.
- [RFC 3230](https://www.rfc-editor.org/rfc/rfc3230) for the deployed
  `Digest` header syntax.
- <https://owasp.org/www-community/attacks/Server_Side_Request_Forgery>
  for outbound request threat modeling.
- [SQLite transaction
  documentation](https://www.sqlite.org/lang_transaction.html)
  for claim, finalize, and migration transactions.
- [SQLite partial indexes](https://www.sqlite.org/partialindex.html) for
  efficient maintenance queries when appropriate.

## 4. Terminology and Invariants

### 4.1 Actor Document

An **actor document** is the ActivityPub JSON object fetched from a remote
actor URI. It includes the actor ID, inbox, optional shared inbox, profile
fields, and public key. Fetching and validating a document does not imply
that the document must be stored.

### 4.2 Transient Actor

A **transient actor** is a parsed and validated remote actor document held in
memory for the duration of one operation. It has no database identity and
must not be referenced through `posts.remote_author_id`.

A transient actor can be used to:

- Verify an HTTP signature.
- Render the immediate result of a WebFinger or actor-URL search.
- Determine an inbox for a one-time operation whose job payload already
  stores the final inbox URL.
- Decide whether a later stateful operation should retain the actor.

### 4.3 Retained Actor

A **retained actor** has a row in `remote_actors`. It has an integer database
ID and can be referenced by stored posts and durable federation state.

Retention is justified by a local relationship, not merely by successful
authentication. Examples include:

- The actor authors a stored remote post.
- A local user follows the actor.
- The actor follows a local user.
- A stored interaction needs the actor's identity.
- A stored post audience requires the actor's inbox for later updates or
  deletion delivery.

### 4.4 Relevant Activity

An activity is **relevant** when it is authorized and its handler creates,
updates, deletes, or forwards state owned by this server. Merely targeting the
shared inbox does not make an activity relevant.

An activity can be relevant without requiring retention of its HTTP signer.
For example, a forwarding server can sign an activity authored by a different
actor. Forwarding may be relevant, but the forwarder need not become a durable
profile row.

### 4.5 Core Invariants

The implementation must maintain these invariants:

1. **Verification precedes body trust.** Activity type, actor, object, and
   addressing are not used for dispatch or retention before the HTTP
   signature and digest are valid.
2. **Acquisition is non-persistent.** Fetching and parsing an actor document
   never writes the database by itself.
3. **Retention is explicit.** Only a stateful workflow requests an actor row.
4. **Unknown verification is transient.** A valid signature from an unknown
   actor does not create a row unless dispatch establishes a retention reason.
5. **Cached refresh is conditional.** A fetched replacement key is persisted
   only if the actor was retained before the request and the replacement key
   successfully verifies it.
6. **Failed verification does not mutate actor state.** Invalid signatures
   cannot update profile, key, inbox, or fetch timestamps.
7. **Authorization precedes mutation.** A known object is not sufficient;
   the authenticated logical actor must own or be permitted to mutate it.
8. **Ignored traffic is bounded.** Deduplication state for ignored traffic
   expires under a configured retention policy.
9. **Failed dispatch is retryable.** A failed handler does not permanently
   finalize its activity ID as processed.
10. **Stored post authors are retained.** A remote post with a known author
    has a valid `remote_author_id` referring to a retained actor.
11. **Outbound fetches remain protected.** Actor acquisition uses the existing
    signed GET and connected-IP SSRF policy on every redirect hop.

## 5. Current Behavior

### 5.1 Actor Resolution

`resolveRemoteActor()` currently performs all of the following:

1. Look up `remote_actors.uri`.
2. Return the cached row unless `force_refresh` is set.
3. Harden the HTTP session against SSRF.
4. Construct a system-actor-signed GET.
5. Fetch and parse the remote actor document.
6. Validate a minimum set of actor fields.
7. Call `upsertRemoteActor()` unconditionally.

The first six operations are resolution. The seventh is retention. Combining
them makes retention an accidental side effect of every network miss.

### 5.2 Current Call-Site Requirements

Existing callers need different policies:

| Caller | Needs fetched data | Needs durable row |
|---|---:|---:|
| Unknown HTTP signer | Yes | No, unless dispatch is relevant |
| Retained signer key refresh | Yes | Yes, after verification |
| WebFinger search result | Yes | No |
| Direct actor-URL search result | Yes | No |
| User follows remote actor | Yes | Yes |
| Fetch and store remote post | Yes | Yes, for the author |
| Fetch a thread object that is stored | Yes | Yes, for stored authors |
| Deliver to a retained follower/followee | Usually no | Already retained |
| Ignored unknown `Delete` | Yes, for signature | No |

The table demonstrates why one generic resolver cannot choose correctly.

### 5.3 Current Key Refresh

`verifyHttpSignatureWithKeyRefresh()` first calls the cached-only verifier.
On any error for which a `keyId` can still be parsed, it force-resolves the
actor and retries. This has three undesirable properties:

- A malformed digest or stale date can cause an unnecessary outbound fetch.
- The fetched actor is persisted before the new key proves the request valid.
- An unknown signer is indistinguishable from a retained actor rotating its
  key.

The replacement design separates request-envelope failures from
cryptographic key failures and carries explicit retained/transient state.

### 5.4 Current Dispatch and Deduplication

`dispatchIncomingActivity()` inserts the activity ID into
`seen_activities` before forwarding or dispatch. That prevents concurrent
duplicate application, but it also means:

- Ignored traffic grows the table forever.
- A handler error leaves the ID marked as processed.
- A later legitimate redelivery returns as a duplicate and cannot repair the
  missing state.
- The dispatch result records only `duplicate`, so the app cannot distinguish
  ignored, applied, and forwarded activities.

### 5.5 Current Authorization Gaps

Retention decisions depend on whether an activity is allowed to modify state.
The current handlers do not consistently establish ownership:

- A remote `Delete` can reference any known post without checking its author.
- A remote `Update` of a `Note` can update a known post without checking its
  stored author.
- An `Undo` can wrap an activity whose actor differs from the outer actor.
- An embedded `Create` can name an `attributedTo` actor different from the
  authenticated activity actor without entering the forwarding flow.

These gaps must be closed as part of this design. Otherwise an unauthorized
activity could be classified as relevant, retained, and applied.

## 6. Architecture

### 6.1 Separation of Responsibilities

Remote actor handling is divided into four operations:

```text
Acquire document       Validate document       Verify request
      |                       |                       |
      +-----------------------+-----------------------+
                              |
                              v
                       transient actor
                              |
                  authorized relevant state?
                       /              \
                     no                yes
                     |                  |
                  discard          retain actor
                                        |
                                        v
                                  durable state
```

The operations are:

1. **Acquire:** Perform the protected HTTP GET and return JSON.
2. **Validate:** Convert JSON to a complete transient actor value.
3. **Verify:** Use the transient or retained key to authenticate a request.
4. **Retain:** Upsert the actor only when a stateful caller explicitly asks.

No operation earlier in the sequence can silently perform a later operation.

### 6.2 Module Ownership

The struct module owns plain actor and verification result types.

The data module owns:

- Reading retained actors.
- Upserting actors when explicitly requested.
- Atomic actor-plus-post insertion.
- Deduplication claims, finalization, release, and pruning.
- Unreferenced actor discovery and deletion.

The federation module owns:

- Protected actor fetches.
- Actor document validation.
- HTTP-signature parsing and verification.
- Key refresh policy.
- Activity authorization and dispatch policy.
- The decision to request actor retention.

The app module owns only HTTP adaptation:

- Construct `IncomingHttpRequest`.
- Call verification and dispatch.
- Map the dispatch disposition to `200`, `202`, `400`, or `401`.

### 6.3 Dependency Direction

The existing dependency direction remains unchanged:

```text
app -> federation -> data -> structs
```

The data layer does not fetch actors. The app layer does not choose whether an
actor should be retained. This keeps federation policy reusable by a future
client API and prevents request handlers from becoming lifecycle owners.

## 7. Actor Types and APIs

### 7.1 Remote Actor Value

Keep `RemoteActor` as the common value type to limit churn. A value returned
from a network-only fetch has `id == 0`. A value read from or returned by the
data layer has `id > 0`.

The zero-ID convention already matches the existing construction pattern, but
the public APIs make the lifecycle explicit so callers do not infer retention
from the type alone.

Add a wrapper for lookup results:

```c++
// A validated remote actor and whether it existed durably before this
// operation.
struct RemoteActorResolution
{
    // The retained or transient actor document selected by lookup.
    RemoteActor actor;
    // True only when the actor had a durable row before this operation.
    bool retained = false;
};
```

`retained` describes database state at acquisition time. It is not inferred
only from `actor.id`, because a caller can retain the actor later during the
same operation.

### 7.2 Federation Acquisition APIs

Replace the ambiguous resolver with explicit functions:

```c++
// Fetch and validate one remote actor without reading or writing the actor
// cache. The returned actor has id == 0.
mw::E<RemoteActor> fetchRemoteActor(
    const Config& config, mw::CryptoInterface& crypto,
    mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view actor_uri);

// Return a retained actor when present; otherwise fetch a transient actor.
// This function never inserts a previously unknown actor.
mw::E<RemoteActorResolution> findOrFetchRemoteActor(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view actor_uri);

// Return a retained actor, fetching and explicitly retaining it when absent.
// Callers use this only after establishing a durable retention reason.
mw::E<RemoteActor> ensureRemoteActorRetained(
    const Config& config, const DataSourceInterface& data,
    mw::CryptoInterface& crypto, mw::HTTPSessionInterface& http,
    const SystemActor& system_actor, std::string_view actor_uri,
    int64_t now_seconds);
```

`fetchRemoteActor()` always performs a network request. It is used for key
refresh even when a cached actor exists.

`findOrFetchRemoteActor()` reads the cache first. It provides the behavior
needed by search and unknown-signature verification.

`ensureRemoteActorRetained()` is deliberately verbose. The name forces a
call-site reviewer to notice that a database lifetime decision is being made.

### 7.3 Actor Document Validation

`fetchRemoteActor()` must validate all fields before returning:

1. The requested URI passes outbound URL policy.
2. The final response is a 2xx ActivityPub JSON response.
3. The response is a JSON object.
4. Its `id`, when present, exactly equals the requested actor URI after the
   repository's existing URL normalization policy.
5. Its ID parses as an allowed remote URL.
6. `inbox` is a string containing an allowed remote URL.
7. `endpoints.sharedInbox`, when present, is a string containing an allowed
   remote URL.
8. `publicKey` is an object.
9. `publicKey.id` and `publicKey.publicKeyPem` are non-empty strings.
10. `publicKey.id` exactly matches the key selected for verification when the
    fetch was initiated for a specific `keyId`.
11. `publicKey.owner`, when present, equals the actor ID.
12. The PEM parses as a supported RSA public key before it is used.

The inbox and shared-inbox URLs are validated syntactically at actor parse
time and again through connected-IP SSRF checks when a request is actually
made. Parse-time validation prevents obviously invalid data from entering the
cache. Connect-time validation prevents DNS rebinding.

### 7.4 Search Behavior

WebFinger and direct actor-URL search call `findOrFetchRemoteActor()` and
render the returned value directly. A search miss does not create a row.

If the user clicks Follow, the follow workflow calls
`ensureRemoteActorRetained()` independently. This can issue a second request
if the actor was transient during search. The extra request is acceptable
because:

- It makes the durable decision explicit at the state-changing boundary.
- It avoids server-wide growth from crawlers and anonymous searches.
- It refreshes the inbox immediately before creating a delivery relationship.

A future short-lived, bounded in-memory cache may avoid the second request,
but it must not change the persistence contract.

### 7.5 Stored Remote Posts

A stored remote post needs a retained author because rendering reads the
author through `remote_author_id`. The post storage path therefore uses an
atomic data operation:

```c++
// Retain the remote author and insert its post in one write transaction.
// Existing posts are returned without creating duplicate rows.
virtual mw::E<Post> insertRemotePost(
    const RemoteActor& author, const NewPost& post,
    const std::vector<PostRecipient>& recipients,
    std::string_view local_uri_prefix) const = 0;
```

The data implementation:

1. Begins a write transaction through the existing busy-retry mechanism.
2. Looks up the post URI.
3. Returns the existing post if found.
4. Upserts the actor and obtains its database ID.
5. Copies the actor ID into `NewPost.remote_author_id`.
6. Inserts the post and recipients.
7. Commits.

If post insertion fails, the transaction rolls back the actor insertion. This
prevents an invalid or conflicting `Create` from leaving an otherwise
unreferenced actor row.

When a local post explicitly addresses or mentions a remote actor, recipient
resolution must call `ensureRemoteActorRetained()` before the post and its
delivery jobs commit. The retained inbox supports the initial delivery and
later Update or Delete delivery to the stored audience. Merely parsing a
remote-looking mention string is not enough; the actor must first be resolved
through WebFinger or its actor URI and validated through the protected actor
fetch path.

### 7.6 Explicit Retention Reasons

The implementation does not need to store a reason enum in the database, but
federation call sites should describe the reason in their function names and
logs. The allowed reasons are:

- `post_author`: a stored post references the actor ID.
- `local_followee`: a local user follows the actor.
- `local_follower`: the actor follows a local user.
- `interaction_actor`: a stored like, boost, or reaction exposes the actor.
- `addressed_recipient`: stored audience data requires later delivery.

An actor `Update` is not itself a reason to retain a previously unknown actor.
It updates an actor that already has one of the reasons above. Otherwise an
attacker could recreate the original growth problem using self-update traffic.

## 8. HTTP-Signature Verification

### 8.1 Verification Result

Expand the result returned to dispatch:

```c++
// An authenticated HTTP signer and the actor material used to verify it.
struct VerifiedSignature
{
    // The actor URI authenticated by the selected public key.
    std::string actor_uri;
    // The exact key identifier from the Signature header.
    std::string key_id;
    // The retained or transient actor document used for verification.
    RemoteActor actor;
    // True when the actor had a durable row before verification.
    bool actor_was_retained = false;
    // True when a fetched replacement key verified the request.
    bool key_was_refreshed = false;
};
```

The actor value lets dispatch retain the exact verified document without
performing another fetch. `actor_was_retained` controls key-refresh policy and
observability. `key_was_refreshed` is useful for tests and logs.

### 8.2 Parsed Signature Envelope

Introduce a private federation type:

```c++
struct ParsedHttpSignature
{
    std::string key_id;
    std::string actor_uri;
    std::vector<std::string> signed_headers;
    std::vector<unsigned char> signature;
    std::string signing_input;
};
```

Parsing the envelope performs every check that does not need a public key:

1. Require `Signature`.
2. Parse quoted parameters.
3. Require `keyId` and `signature`.
4. Accept only `rsa-sha256` and compatible `hs2019` labels.
5. Require signed `date` and `(request-target)`.
6. Check clock skew.
7. For `POST` and `PUT`, require signed `digest`.
8. Verify the SHA-256 body digest.
9. Decode the signature bytes.
10. Reconstruct the signing input.
11. Derive and validate the actor URI from `keyId`.

No actor fetch occurs if any of these steps fails. This prevents stale dates,
bad digests, and malformed headers from causing outbound traffic.

### 8.3 Unknown Actor Algorithm

For an actor absent from `remote_actors`:

1. Parse and validate the signature envelope.
2. Call `fetchRemoteActor()` for the derived actor URI.
3. Require the fetched public-key ID to equal the request `keyId`.
4. Verify the cryptographic signature using the transient public key.
5. On failure, return `401` and discard the actor.
6. On success, return `VerifiedSignature` with
   `actor_was_retained == false`.
7. Do not write `remote_actors`.

The activity body remains unparsed until step 6 succeeds.

### 8.4 Retained Actor Algorithm

For an actor present in `remote_actors`:

1. Parse and validate the signature envelope.
2. If cached `public_key_id` equals the request `keyId`, verify with the
   cached key.
3. If verification succeeds, return the retained actor without a fetch.
4. If the key ID differs or cryptographic verification fails, fetch a fresh
   transient document exactly once.
5. Require the fresh document's actor and key IDs to match the request.
6. Verify using the fresh key.
7. If verification fails, return `401` and leave the cached row unchanged.
8. If verification succeeds, upsert the fresh document while preserving its
   retained identity and retention timestamp.
9. Return `VerifiedSignature` with both flags set appropriately.

This preserves key rotation while preventing an invalid request from changing
cached actor data.

### 8.5 Failure Classification

Key refresh is permitted only for these initial failures:

- The retained actor's cached `public_key_id` differs from the request
  `keyId`.
- RSA verification returns `false` using the cached key.

Key refresh is not permitted for:

- Missing or malformed signature parameters.
- Unsupported algorithms.
- Missing signed headers.
- Clock-skew failure.
- Missing, malformed, unsigned, or mismatched digest.
- Invalid base64.
- An invalid or disallowed actor URI.
- A signing-input reconstruction failure.

This distinction is represented by control flow, not by inspecting error
message strings.

### 8.6 Signed GET and SSRF Requirements

Every call to `fetchRemoteActor()` must:

- Use `signedGetRequest()` with the system actor.
- Allow HTTPS only in production.
- Reuse `hardenOutboundSession(config, http, actor_uri)`.
- Reject private, loopback, link-local, ULA, and metadata addresses.
- Validate the actual connected IP.
- Revalidate every redirect destination and connected IP.
- Enforce the configured redirect limit.
- Never fall back to an unsigned GET.

Tests must exercise the same HTTP session abstraction as existing SSRF tests.
The transient lifecycle must not introduce a simpler, unprotected fetch path.

## 9. Inbox Processing

### 9.1 End-to-End Sequence

The new inbox sequence is:

1. Build `IncomingHttpRequest` from the HTTP server request.
2. Parse and validate the HTTP-signature envelope.
3. Read a retained actor or fetch a transient actor.
4. Verify the cryptographic signature.
5. Parse and normalize the ActivityPub body.
6. Establish whether this is direct delivery or valid forwarded delivery.
7. Claim the activity ID for deduplication.
8. Authorize the activity against its target state.
9. Dispatch the activity, retaining the logical actor inside the handler only
   at the point durable identity becomes necessary.
10. Record whether the handler retained the actor.
11. Finalize the activity claim.
12. Return a status based on dispatch disposition.

Steps 5 through 10 never run for an unauthenticated request.

### 9.2 Dispatch Result

Replace the single duplicate flag with an explicit result:

```c++
// The durable effect of a successfully authenticated inbox activity.
enum class InboxDisposition
{
    DUPLICATE,             // The activity completed previously.
    PROCESSING,            // Another request owns a live claim.
    IGNORED,               // The valid activity required no action.
    APPLIED,               // The activity changed local state.
    FORWARDED,             // Forwarding jobs were accepted.
    APPLIED_AND_FORWARDED, // Both local and forwarding effects occurred.
};

// The result used by the HTTP handler and lifecycle tests.
struct InboxDispatchResult
{
    // The final processing outcome exposed to the HTTP handler.
    InboxDisposition disposition = InboxDisposition::IGNORED;
    // True when processing created or refreshed a durable actor row.
    bool actor_retained = false;
};
```

The app maps results as follows:

| Disposition | HTTP status | Meaning |
|---|---:|---|
| `DUPLICATE` | 200 | Already processed successfully |
| `PROCESSING` | 202 | Another request currently owns the claim |
| `IGNORED` | 200 | Valid but unsupported, irrelevant, or idempotently absent |
| `APPLIED` | 202 | Local state changed or a job was accepted |
| `FORWARDED` | 202 | Forwarding delivery jobs were accepted |
| `APPLIED_AND_FORWARDED` | 202 | Both effects occurred |

`DUPLICATE` means processing finished previously. `PROCESSING` means another
request owns a live claim and has accepted responsibility for processing.
This distinction prevents a concurrent request from implying that processing
already completed. It also restores the architecture design's promised `200`
for ignored unknown `Delete` and `Undo` activities.

### 9.3 Persistence Matrix

The dispatcher applies this matrix after verification and authorization:

| Activity | Relevant condition | Retain logical actor? |
|---|---|---:|
| `Create` `Note` | New, valid, addressed post is stored | Yes, as author |
| `Create` URI | Fetch produces a storable remote post | Yes, as author |
| `Follow` | Target is an existing local actor | Yes, as follower |
| `Accept` | Matches an outgoing local follow | Ensure retained |
| `Like` | Target post exists and interaction is stored | Yes |
| `Announce` | Target exists, is public/unlisted, boost stored | Yes |
| `EmojiReact` | Target exists, emoji valid, reaction stored | Yes |
| `Delete` post | Known remote post owned by actor | Do not add unknown actor |
| `Delete` unknown | No local target | No |
| `Delete` actor | Known self-delete | No new actor |
| `Update` post | Known actor-owned post | Refresh if needed |
| `Update` actor | Actor already retained and updates itself | Keep retained |
| `Update` unknown | No locally relevant target | No |
| `Undo` | Matching actor-owned state | Only if referenced |
| Unsupported type | None | No |
| Forward only | Forwarding conditions hold | Do not retain forwarder |

"Usually already retained" is not used as an assumption in code. The handler
still obtains the actor explicitly when the resulting state requires it.

### 9.4 Handler Structure

Each handler follows this order:

1. Normalize required references.
2. Reject or ignore unsupported object shapes.
3. Load the target local state.
4. Authorize the logical actor.
5. Determine whether the operation is already idempotently complete.
6. Perform the state mutation.
7. Retain the actor as part of the same transaction when an integer actor ID
   is required, or immediately after the URI-keyed mutation otherwise.
8. Return whether state changed and whether retention occurred.

Handlers must not retain an actor at entry. At that point they have not yet
established relevance.

### 9.5 Direct and Forwarded Delivery

For direct delivery, the authenticated HTTP signer must equal
`activity.actor`. The verified actor material is therefore also the logical
actor material available for retention.

For forwarded delivery, the HTTP signer is the forwarder and can differ from
`activity.actor`. The forwarding verifier follows the architecture design:

1. Verify the forwarder's HTTP signature.
2. Detect that the signer differs from `activity.actor`.
3. Require the activity to meet inbox-forwarding addressing conditions.
4. Re-fetch the referenced object from its origin with a protected signed GET.
5. Verify that the refetched object supports the claimed author and reference.
6. Use the origin copy, not the forwarded embedded copy, for state mutation.

The forwarder is not retained merely because it signed the transport request.
If the origin author must be retained, use the actor document obtained for the
origin author through the normal protected acquisition path.

## 10. Authorization Rules

### 10.1 General Rule

Authentication answers "who signed this transport request?" Authorization
answers "may the logical actor perform this mutation?" Both are required.

No handler may treat the existence of a target URI as sufficient permission.

### 10.2 Create

For direct `Create` delivery:

- `activity.actor` must equal the authenticated signer.
- Embedded `Note.attributedTo`, when present, must equal `activity.actor`.
- If `attributedTo` is absent, the activity actor is the author.
- The object ID must be remote and must not collide with a local object URI.
- The activity or object must be addressed to a local actor, a local followers
  collection, or a supported public/shared-inbox path under existing policy.

An author mismatch is rejected with `401` or ignored as unauthorized according
to the existing handler-boundary error policy. It must never store the post or
either actor.

### 10.3 Delete

For a post `Delete`:

- Load the post by object URI.
- Unknown posts are ignored with `200`.
- Local posts cannot be deleted by inbound remote activities.
- Remote posts must have `remote_author_id`.
- Load the retained author and require its URI to equal `activity.actor`.
- Only then delete the post.

For actor deletion, support can remain limited. If implemented, the actor must
delete itself and must already be retained. A self-delete from an unknown actor
is irrelevant and does not create then delete a row.

### 10.4 Update

For a `Note` update:

- The target post must exist and be remote.
- Its retained author URI must equal `activity.actor`.
- The updated object's `attributedTo`, when present, must equal the same actor.
- The object ID must equal the stored post URI.

For an actor update:

- Object ID must equal `activity.actor`.
- The actor must already be retained for another reason.
- Key material in the activity body is profile update data, not proof of the
  current request. The HTTP signature has already been verified separately.

An unknown actor update is ignored without persistence.

### 10.5 Undo

For every `Undo`:

- Parse the wrapped activity.
- Require `wrapped.actor == activity.actor`.
- Require the outer activity actor to be authenticated through the direct or
  forwarding path.
- Remove only state keyed by that actor and the wrapped target.
- Treat absent state as an idempotent ignored result.

This prevents one actor from wrapping and undoing another actor's interaction.

### 10.6 Interactions and Follow

`Like`, `Announce`, and `EmojiReact` require a known target post before
retention. `Announce` additionally requires public or unlisted visibility.

An inbound `Follow` requires an existing local target actor before retention.
The verified follower document supplies the inbox used to enqueue `Accept`.

An inbound `Accept` must correspond to an existing outgoing follow whose
follower is local and whose followee equals `activity.actor`.

## 11. Activity Deduplication

### 11.1 Why Deduplication Is Included

The same irrelevant traffic that grows `remote_actors` also grows
`seen_activities`. Leaving it permanent would solve only half of the observed
storage problem. The current insert-before-dispatch behavior also loses retries
after handler failures. Both issues require a lifecycle rather than a simple
set membership row.

### 11.2 Claim State

Replace `markActivitySeen()` with claim/finalize operations:

```c++
// The result of attempting to claim an inbound activity ID.
enum class ActivityClaimResult
{
    CLAIMED,           // This request owns the processing lease.
    ALREADY_PROCESSED, // A previous request finalized the activity.
    IN_PROGRESS,       // Another request owns an unexpired lease.
};

// Claim an activity ID or reclaim an expired processing lease.
virtual mw::E<ActivityClaimResult> claimIncomingActivity(
    std::string_view activity_uri, int64_t now_seconds,
    int64_t lease_seconds) const = 0;

// Mark a successfully dispatched activity as processed.
virtual mw::E<void> finalizeIncomingActivity(
    std::string_view activity_uri, int64_t now_seconds) const = 0;

// Release a claim after dispatch failure so redelivery can retry.
virtual mw::E<void> releaseIncomingActivity(
    std::string_view activity_uri) const = 0;

// Delete processed activity IDs older than the retention cutoff.
virtual mw::E<int64_t> pruneIncomingActivities(
    int64_t cutoff_seconds) const = 0;
```

### 11.3 Claim Algorithm

Within one write transaction:

1. Insert the ID with state `processing`, `claimed_at = now`, and
   `processed_at = NULL` if absent.
2. If the row is `processed`, return `ALREADY_PROCESSED`.
3. If the row is `processing` and its lease is unexpired, return
   `IN_PROGRESS`.
4. If the row is `processing` and expired, update `claimed_at = now` and
   return `CLAIMED`.

Both non-claim results prevent concurrent state application. The HTTP handler
returns `200` for `ALREADY_PROCESSED`. It returns `202` for `IN_PROGRESS`
because another request currently owns processing responsibility.

### 11.4 Finalize and Release

After successful dispatch, including an intentionally ignored activity,
finalize the row as `processed` and set `processed_at`.

If forwarding, authorization lookup, retention, or the state mutation returns
an error:

1. Attempt `releaseIncomingActivity()`.
2. Return the original error to the HTTP handler.
3. Log a secondary release failure without replacing the original error.

If the process crashes before release, the processing lease eventually allows
redelivery to reclaim the ID.

### 11.5 Retention Window

Add configuration:

```yaml
seen_activity_retention_seconds: 2592000 # 30 days
inbox_processing_lease_seconds: 300      # 5 minutes
```

Thirty days is long enough to suppress normal delayed redelivery while
bounding hostile or irrelevant traffic. The exact default is operational
policy and can be changed without a schema change.

Both settings are positive integer fields in the existing flat federation
tuning section of `Config`. Configuration validation rejects zero and negative
values.

After expiry, an old activity can be processed again. State handlers must
therefore remain idempotent through existing unique constraints and target
checks. A repeated follow may enqueue another `Accept`; that is harmless and
preferable to retaining every activity ID forever.

### 11.6 Maintenance Schedule

Pruning runs:

- Once after startup migration completes.
- At most once per hour from the existing background worker infrastructure.
- In a bounded delete batch, for example 1,000 rows per transaction, so a
  large historical table does not monopolize the SQLite writer.

The prune query uses the `processed_at` index. Active processing claims are
never pruned by the retention query.

## 12. Actor Retention and Collection

### 12.1 Initial Retention

An actor is inserted only through one of the explicit retention paths in
section 9.3. Search, verification, and ignored traffic never insert rows.

### 12.2 Retention Timestamp

Add `retained_at` to distinguish local relevance from remote fetch freshness:

- `fetched_at` records when the actor document was last fetched.
- `retained_at` records when local durable state last established or renewed
  a reason to retain the actor.

Key refresh updates `fetched_at` but must not extend `retained_at` by itself.
Otherwise irrelevant signed traffic from a historically retained actor could
prevent collection forever.

Every operation that adds or removes a durable reference touches
`retained_at`. Touching it on removal is important: if a five-year-old actor
loses its final follow today, its grace period begins today rather than five
years ago. The relevant data operation updates the timestamp in the same write
transaction as the reference change.

For URI-keyed references, add this data helper:

```c++
// Record that local durable state added or removed a reference to an actor.
virtual mw::E<void> touchRemoteActorRetention(
    std::string_view actor_uri, int64_t now_seconds) const = 0;
```

Post deletion can touch by the stored `remote_author_id` before deleting the
post. Follow and interaction operations touch by actor URI. A touch of an
actor that is not retained is a no-op; insertion paths set `retained_at`
directly.

### 12.3 Reference Rules

An actor is referenced while any of these conditions holds:

- A post has `remote_author_id = remote_actors.id`.
- A follow has `follower_uri = remote_actors.uri`.
- A follow has `followee_uri = remote_actors.uri`.
- A like has `actor_uri = remote_actors.uri`.
- A boost has `actor_uri = remote_actors.uri`.
- A reaction has `actor_uri = remote_actors.uri`.
- A stored post recipient equals the actor URI.

Queued delivery jobs do not need to keep the actor row if their payload
already contains the final target inbox. The job must never defer recipient
URI to inbox resolution until execution time unless the actor is otherwise
retained.

### 12.4 Garbage Collection

Add a configurable grace period:

```yaml
remote_actor_gc_grace_seconds: 2592000 # 30 days
```

An actor is eligible when:

1. `retained_at` is older than the cutoff.
2. None of the reference rules in section 12.3 matches.
3. The actor is rechecked inside the deletion transaction.

Deletion happens in bounded batches. The grace period prevents churn after a
user briefly follows and unfollows an actor and gives concurrent jobs time to
finish.

This setting is also a positive integer in the existing flat federation
tuning section. Configuration validation rejects zero and negative values.

Because reference-removal operations touch `retained_at`, the cutoff measures
time since the most recent reference transition, including removal of the
final reference. Garbage collection never has to infer that transition from a
periodic scan.

### 12.5 Why Retention Is Not Limited to Followees

Followees are only one durable relationship. A remote actor can instead be:

- The author of a reply stored in a local thread.
- A remote follower who must receive future local posts.
- The actor behind a like shown to a local post author.
- A mentioned recipient of a local post that may later receive an update or
  delete.

The correct rule is "referenced by locally relevant state," not "currently
followed by a local user."

## 13. Database Migration

### 13.1 Version

The current implemented schema version is 2. This design introduces schema
version 3. Fresh databases are created directly at version 3; existing version
2 databases run `migrate2To3()` transactionally.

### 13.2 Remote Actor Change

Add the retention timestamp:

```sql
ALTER TABLE remote_actors
ADD COLUMN retained_at INTEGER NOT NULL DEFAULT 0;

UPDATE remote_actors
SET retained_at = fetched_at
WHERE retained_at = 0;

CREATE INDEX idx_remote_actors_retained
ON remote_actors(retained_at, id);
```

Existing rows receive `fetched_at` as a conservative approximation. They are
not deleted during migration. Normal garbage collection applies only after
the configured grace period and reference checks.

### 13.3 Seen Activities Change

Rebuild `seen_activities` because its state model changes:

```sql
CREATE TABLE seen_activities_new (
    activity_uri TEXT PRIMARY KEY,
    state         TEXT NOT NULL,
    claimed_at    INTEGER,
    processed_at  INTEGER,
    CHECK (state IN ('processing', 'processed')),
    CHECK (
        (state = 'processing' AND claimed_at IS NOT NULL)
        OR
        (state = 'processed' AND processed_at IS NOT NULL)
    )
);

INSERT INTO seen_activities_new (
    activity_uri,
    state,
    claimed_at,
    processed_at
)
SELECT
    activity_uri,
    'processed',
    NULL,
    seen_at
FROM seen_activities;

DROP TABLE seen_activities;
ALTER TABLE seen_activities_new RENAME TO seen_activities;

CREATE INDEX idx_seen_activities_processed
ON seen_activities(processed_at)
WHERE state = 'processed';

CREATE INDEX idx_seen_activities_processing
ON seen_activities(claimed_at)
WHERE state = 'processing';
```

Historical rows are treated as successfully processed because the migration
cannot reconstruct which handlers failed. The retention job later prunes old
rows.

### 13.4 Migration Transaction

`migrate2To3()` follows the existing migration pattern:

1. Begin a write transaction.
2. Add `retained_at` and its index.
3. Rebuild `seen_activities`.
4. Set `PRAGMA user_version = 3`.
5. Commit.
6. Roll back every earlier step on error.

The migration runs under `withWriteRetry()`. Tests use a copied version-2
fixture or construct a minimal version-2 database and verify data survival.

## 14. Errors, Transactions, and Concurrency

### 14.1 Error Mapping

- Missing or invalid signatures return `401`.
- Actor fetch HTTP failures retain their upstream status only internally;
  inbox verification maps failure to `401` without exposing remote details.
- Invalid ActivityPub JSON returns `400` only after signature verification.
- Unauthorized actor/object relationships return `401` or an ignored `200`
  according to whether revealing target existence would leak private state.
- Unexpected database and job errors return `500` and release the activity
  claim.
- Background maintenance errors are logged and retried later; they do not stop
  inbox processing.

### 14.2 Actor Refresh Concurrency

Two requests can concurrently refresh one retained actor:

1. Both read the old key.
2. Both fetch the same new document.
3. Both verify successfully.
4. Both upsert the same URI.

This is safe because URI uniqueness makes the upsert idempotent. The final
document is one that successfully verified a request. If the remote document
changes between the two fetches, last writer wins as it does today.

An optional optimistic `fetched_at` comparison is not required for v1 of this
change.

### 14.3 Actor Retention Concurrency

Concurrent relevant activities for one new actor can both request retention.
`upsertRemoteActor()` must return the single row selected by unique URI.

Remote post insertion uses one transaction so the returned actor ID and post
reference agree. URI-keyed follows and interactions can be retried safely
under their unique indexes.

### 14.4 Claim Concurrency

`claimIncomingActivity()` must determine insertion or lease takeover inside
one write transaction. It must not perform a read in one transaction and an
insert in another. SQLite's single-writer behavior plus the primary key then
ensures only one request obtains `CLAIMED`.

### 14.5 Partial Failure

The desired order for URI-keyed state is:

1. Apply the idempotent state mutation.
2. Retain the actor if the state remains present.
3. Finalize the activity ID.

If step 2 fails, release the claim and return an error. Redelivery repeats the
idempotent state mutation and retries retention. The activity is not finalized
until both are successful.

For post storage, actor retention and post insertion are one transaction, so
there is no intermediate post without an author or actor without a post.

### 14.6 Collection Concurrency

Garbage collection selects candidates, then rechecks references in the delete
transaction. A new reference inserted before the check prevents deletion.

Code that creates a new reference must retain/upsert the actor in the same
logical operation. If collection deletes an unreferenced actor immediately
before that operation, the upsert recreates it with the same URI and the new
reference uses the new ID.

## 15. Implementation Plan

### 15.1 Phase 1: Types and Acquisition

Files:

- `src/structs.hpp`
- `src/federation.hpp`
- `src/federation.cpp`
- `src/federation_test.cpp`

Steps:

1. Add `RemoteActorResolution`.
2. Extract actor JSON validation from `resolveRemoteActor()`.
3. Implement `fetchRemoteActor()` with no data-source argument.
4. Implement `findOrFetchRemoteActor()`.
5. Implement `ensureRemoteActorRetained()`.
6. Convert search callers to non-persistent lookup.
7. Convert explicit follow and stored-post paths to explicit retention.
8. Remove `resolveRemoteActor()` after every caller has selected a policy.

### 15.2 Phase 2: Signature Verification

Steps:

1. Extract `ParsedHttpSignature` parsing.
2. Add a helper that verifies parsed input against one actor value.
3. Implement unknown transient verification.
4. Implement retained cached verification.
5. Implement verified-before-persisted key refresh.
6. Expand `VerifiedSignature`.
7. Remove refresh-on-envelope-error behavior.

### 15.3 Phase 3: Dispatch and Authorization

Steps:

1. Pass `VerifiedSignature` to dispatch instead of only an actor URI.
2. Add `InboxDisposition`.
3. Apply the persistence matrix to each handler.
4. Add actor ownership checks for Create, Delete, Update, and Undo.
5. Add the atomic remote actor plus post data operation.
6. Correct HTTP statuses for ignored activities.
7. Preserve and test forwarded-delivery behavior separately from direct
   signer/actor equality.

### 15.4 Phase 4: Deduplication and Schema

Files:

- `src/config.hpp`
- `src/config.cpp`
- `src/data.hpp`
- `src/data.cpp`
- `src/data_mock.hpp`
- `src/data_test.cpp`
- `src/config_test.cpp`

Steps:

1. Add schema version 3 and `migrate2To3()`.
2. Add deduplication configuration.
3. Implement claim, finalize, release, and prune.
4. Update mock interfaces.
5. Integrate claim lifecycle into dispatch.
6. Add periodic maintenance.

### 15.5 Phase 5: Actor Collection

Steps:

1. Add the actor grace-period configuration.
2. Touch `retained_at` when references are added or removed.
3. Implement reference queries and bounded deletion.
4. Ensure queued jobs contain final inbox URLs.
5. Schedule collection with deduplication maintenance.
6. Add migration-fixture and reference-preservation tests.

### 15.6 Documentation Cleanup

After implementation:

- Update design 0 section 10.1 so it no longer says an unknown signer is
  immediately cached.
- Update design 0 section 12.6 with claim/finalize terminology and explicit
  dispositions.
- Update operator documentation with new retention settings.
- Remove the completed item from `todo.md` or mark it resolved according to
  repository convention.

## 16. Testing Strategy

### 16.1 Actor Acquisition Unit Tests

- Fetching a valid unknown actor returns `id == 0` and writes no row.
- A retained actor is returned without network access.
- Search for an unknown actor renders a result and leaves no row.
- Following the same actor creates one row and queues delivery to its inbox.
- Fetch rejects a mismatched actor ID.
- Fetch rejects missing inbox or key data.
- Fetch rejects a mismatched key ID when a key was requested.
- Fetch rejects a conflicting `publicKey.owner`.
- Fetch uses a system-actor-signed GET.
- Fetch preserves redirect and connected-IP SSRF checks.

### 16.2 Signature Tests

- Unknown valid signer verifies without persistence.
- Unknown bad signature verifies unsuccessfully without persistence.
- Unknown malformed digest causes no actor fetch.
- Unknown stale date causes no actor fetch.
- Unknown unsupported algorithm causes no actor fetch.
- Retained actor verifies using its cached key without a fetch.
- Retained rotated key fetches once, verifies, then updates the row.
- Retained fetched key that fails verification leaves the old row unchanged.
- A different `keyId` triggers one retained refresh.
- A fetched actor/key mismatch is rejected without an upsert.
- Both `rsa-sha256` and supported `hs2019` labels remain accepted.

### 16.3 Dispatch Persistence Tests

For every test, begin with no actor row unless the scenario requires a
retained target author:

- Unknown-object `Delete` returns ignored and creates no actor row.
- Unsupported activity returns ignored and creates no actor row.
- Like of unknown post creates no actor row.
- Announce of a private post creates no actor row.
- Reaction with missing emoji creates no actor row.
- Follow of an unknown local actor creates no actor row.
- Relevant Follow retains the follower and queues `Accept`.
- Relevant Like retains the actor and stores one like.
- Relevant Announce retains the actor and stores one boost.
- Relevant reaction retains the actor and stores one reaction.
- Relevant Create atomically stores actor and post.
- Duplicate Create stores neither a second actor nor a second post.
- Unknown actor Update does not create a row.
- Update of a retained actor changes the retained row.

### 16.4 Authorization Tests

- One remote actor cannot delete another actor's post.
- A remote actor cannot delete a local post.
- One remote actor cannot update another actor's post.
- A Create with mismatched `attributedTo` is not stored.
- An Undo whose wrapped actor differs from the outer actor changes no state.
- A valid owner can Delete, Update, and Undo its own state.
- A forwarder/signature mismatch enters only the verified forwarding path.

### 16.5 Deduplication Data Tests

- First claim returns `CLAIMED`.
- Concurrent second claim returns `IN_PROGRESS`.
- Finalized claim returns `ALREADY_PROCESSED`.
- Released claim can be claimed again.
- Expired processing lease can be reclaimed.
- Unexpired processing lease cannot be stolen.
- Pruning deletes only old processed rows.
- Pruning does not delete active processing rows.
- A dispatch failure releases its claim.
- A process-crash simulation is recoverable after lease expiry.

### 16.6 Migration Tests

- Version 2 migrates to version 3.
- Existing actor fields survive unchanged.
- Existing actors receive `retained_at` copied from `fetched_at`.
- Existing seen activity IDs become processed rows with their original
  timestamps.
- Sessions, jobs, posts, attachments, and profile data remain unchanged.
- Migration rollback leaves version 2 intact after an injected failure.
- A fresh database creates the version-3 schema directly.

### 16.7 Garbage Collection Tests

- An unreferenced actor older than the grace period is deleted.
- A recent unreferenced actor is retained.
- A post author is retained.
- A follower is retained.
- A followee is retained.
- A like, boost, or reaction actor is retained.
- An addressed post recipient is retained.
- Removing the final reference makes the actor eligible after the grace
  period.
- Removing the final reference starts a new grace period at removal time.
- Batch size limits one collection transaction.

### 16.8 Production-Derived Regression Test

Add a focused regression that simulates many unique signed unknown-object
deletes:

1. Generate or reuse a small set of remote keys and unique actor documents.
2. Deliver valid, uniquely identified Delete activities for unknown objects.
3. Assert every request verifies and returns ignored.
4. Assert `remote_actors` remains unchanged.
5. Assert dedup rows are created as processed.
6. Advance time beyond retention and run prune.
7. Assert the dedup rows are removed.

The test need not generate 4,330 RSA keys. A table-driven smaller sample proves
the lifecycle; the production fixture remains evidence of the original scale.

### 16.9 Interop Tests

Extend the Docker interop harness with:

- A real peer key rotation followed by a signed activity.
- An inbound relevant Follow that remains deliverable after restart.
- An inbound unknown-object Delete that leaves no actor row.
- A stored remote post whose author still renders after restart.

## 17. Observability

### 17.1 Metrics or Structured Counters

Expose or log counters for:

- Actor fetches by purpose: search, verification, post, follow, refresh.
- Transient actor verifications.
- Actor retentions by reason.
- Cached-key verification successes.
- Key refresh attempts, successes, and failures.
- Inbox dispositions.
- Dedup claim results.
- Dedup rows pruned.
- Remote actors garbage-collected.

If the project has no metrics backend, emit structured debug or info logs
with stable field names. Do not log PEM keys, signature bytes, full private
activity bodies, or authentication secrets.

### 17.2 Diagnostic Logging

Useful fields include:

- `actor_uri`
- `key_id`
- `actor_retained_before`
- `actor_retained_after`
- `key_refreshed`
- `activity_id`
- `activity_type`
- `inbox_disposition`
- `retention_reason`

Actor and activity URIs can contain user-controlled text. Pass them as log
arguments rather than using them as format strings.

### 17.3 Operational Queries

Document read-only queries for operators:

```sql
SELECT COUNT(*) FROM remote_actors;

SELECT domain, COUNT(*)
FROM remote_actors
GROUP BY domain
ORDER BY COUNT(*) DESC
LIMIT 20;

SELECT state, COUNT(*)
FROM seen_activities
GROUP BY state;
```

These queries make regression detection possible without inspecting private
activity bodies.

## 18. Deployment and Rollout

### 18.1 Pre-Deployment

- Back up the SQLite database.
- Confirm the current schema version is 1 or 2 and that sequential migrations
  are available.
- Measure current `remote_actors` and `seen_activities` counts.
- Confirm the system actor exists, because transient verification still uses
  signed GET.

### 18.2 Deployment Sequence

1. Stop the old process so it cannot write the database during migration.
2. Start the new binary.
3. Apply all sequential migrations through version 3.
4. Run startup dedup pruning in bounded batches.
5. Start HTTP and background workers.
6. Observe signature failures, actor fetches, and inbox dispositions.

### 18.3 Rollback

The binary cannot safely run against a schema newer than it supports. Rollback
therefore restores the pre-deployment database backup together with the old
binary. Do not attempt to decrement `user_version` without reversing the
schema.

### 18.4 Existing Irrelevant Actors

The migration does not delete existing actors immediately. Immediate deletion
would risk removing a row referenced through a URI column that the migration
failed to anticipate. Normal garbage collection performs complete reference
checks after the grace period.

Operators who need immediate space recovery can run the same audited
collection operation through an administrative maintenance command added in a
later change. Raw ad hoc `DELETE` instructions are not part of this design.

## 19. Alternatives Considered

### 19.1 Keep Persisting Every Verified Actor

Rejected because authentication traffic is attacker-controlled in volume.
Successful verification proves control of a key, not local relevance. A table
that records every valid signer is an unbounded audit log, contrary to the
small-instance storage goal.

### 19.2 Add a Persistent Verification-Key Table

A separate `remote_actor_keys` table with TTL would decouple profiles from
keys, but it still writes one row per irrelevant signer and requires pruning,
migration, and consistency rules. Transient verification is simpler and meets
the requirement directly.

A bounded key table can be reconsidered if network measurements show repeated
fetches from the same irrelevant actors are expensive.

### 19.3 Add an Unbounded In-Memory Cache

Rejected because it moves the growth problem from SQLite to process memory and
loses predictable resource bounds. Any future in-memory cache must have an
entry limit, TTL, thread-safe eviction, and tests.

### 19.4 Parse Activity Before Fetching the Key

This could cheaply ignore obvious unknown deletes, but it would use untrusted
body contents before signature verification and create parser work for
unauthenticated traffic. It violates the core security invariant and the PRD.

### 19.5 Persist, Dispatch, Then Delete If Irrelevant

Rejected because it creates unnecessary writes, consumes autoincrement IDs,
introduces races with concurrent relevant requests, and can delete an actor
that another transaction just began referencing. It also makes failed cleanup
equivalent to permanent growth.

### 19.6 Persist Only Followees

Rejected because stored post authors, remote followers, interaction actors,
and addressed recipients can be required even when no local user follows
them. Reference-based relevance is the correct model.

### 19.7 Never Garbage-Collect Retained Actors

Preventing new irrelevant inserts solves the immediate incident, but actors
can become unreferenced after post deletion, unfollow, or interaction undo.
Grace-period, reference-checked collection gives the table an intentional
lifecycle without deleting live identity data.

### 19.8 Keep Permanent Activity Deduplication

Rejected because the table grows with every unique activity forever. Permanent
deduplication is unnecessary when state operations are idempotent and HTTP
signatures already enforce a narrow replay window for a captured transport
request. A long finite retention window handles ordinary redelivery.

## 20. Acceptance Criteria

The design is implemented only when all of the following are true:

1. No public federation function named `resolveRemoteActor()` remains with an
   implicit upsert side effect.
2. Actor network acquisition can complete successfully without a database
   write.
3. Unknown valid HTTP signers verify transiently.
4. Unknown invalid signers create no actor rows.
5. Bad date, digest, algorithm, and signature-envelope failures cause no actor
   fetch.
6. Retained actors continue to verify from cached keys.
7. A retained rotated key is fetched once and stored only after successful
   verification.
8. Failed refreshed-key verification leaves the cached actor unchanged.
9. Search alone does not retain a remote actor.
10. Following a remote actor retains it and can deliver the Follow.
11. Storing a remote post atomically retains its author.
12. Relevant inbound follows and interactions retain their actors.
13. Unknown-object Delete, Undo, Update, unsupported activities, and
    irrelevant interactions retain no actors.
14. Delete, Update, Create, and Undo enforce actor ownership.
15. Forwarded delivery does not confuse the transport signer with the logical
    actor.
16. Inbox dispatch distinguishes duplicate, processing, ignored, applied, and
    forwarded results.
17. Ignored unknown Delete and Undo return `200`.
18. A failed dispatch releases or eventually expires its processing claim.
19. Processed activity IDs are pruned after the configured retention window.
20. Unreferenced actors are collected only after the configured grace period.
21. Referenced post authors, followers, followees, interaction actors, and
    addressed recipients survive collection.
22. Removing the final actor reference starts the configured grace period.
23. All actor fetches remain signed and SSRF-protected across redirects.
24. Version-2 databases migrate transactionally to version 3 without losing
    unrelated data.
25. Unit, data, migration, and interop regression tests cover the lifecycle.
