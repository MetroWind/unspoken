# Design Document: Unspoken — Micro-blog with ActivityPub (Fediverse) in C++23

**Server name:** `unspoken` (the executable, package, and NodeInfo
software name). The repository directory is `actpub`.
**Status:** Draft
**Source requirements:** [`prd.md`](../prd.md) and resolved decisions in [`prd_gaps.md`](../prd_gaps.md)
**Audience:** The engineer(s) implementing this server from scratch.

This document is intentionally exhaustive. Every component, data
structure, algorithm, and error path is spelled out so that the
implementer never has to guess what "the right thing" is. Where a
concept relies on an external standard, the relevant specification is
linked inline for further reading. Read this top-to-bottom once before
writing any code; the early sections (architecture, configuration,
data model) are prerequisites for understanding the later ones
(federation, handlers, jobs).

---

## Table of contents

1. [Overview and scope](#1-overview-and-scope)
2. [Glossary](#2-glossary)
3. [High-level architecture](#3-high-level-architecture)
4. [Technology stack and build system](#4-technology-stack-and-build-system)
5. [Configuration](#5-configuration)
6. [Domain model: URL root, public domain, handles, IDs](#6-domain-model-url-root-public-domain-handles-ids)
7. [Database schema and the data module](#7-database-schema-and-the-data-module)
8. [The struct module (core types)](#8-the-struct-module-core-types)
9. [JSON-LD normalization layer](#9-json-ld-normalization-layer)
10. [HTTP signatures (sign and verify)](#10-http-signatures-sign-and-verify)
11. [SSRF-safe outbound HTTP](#11-ssrf-safe-outbound-http)
12. [The federation module](#12-the-federation-module)
13. [Markdown rendering, mentions, and HTML sanitization](#13-markdown-rendering-mentions-and-html-sanitization)
14. [The job queue and background workers](#14-the-job-queue-and-background-workers)
15. [Authentication: OpenID Connect and sessions](#15-authentication-openid-connect-and-sessions)
16. [The app module: routes, handlers, templates](#16-the-app-module-routes-handlers-templates)
17. [Attachments](#17-attachments)
18. [Error handling conventions](#18-error-handling-conventions)
19. [Testing strategy](#19-testing-strategy)
20. [Future work (explicitly out of scope for v1)](#20-future-work-explicitly-out-of-scope-for-v1)

---

## 1. Overview and scope

We are building a **single-server micro-blogging application** (think a
small Mastodon/Pleroma instance) that participates in the **Fediverse**
by implementing the [ActivityPub protocol](https://www.w3.org/TR/activitypub/).
"Federation" means our server exchanges messages with other independent
servers (Mastodon, Pleroma, Akkoma, Misskey, etc.) so that a user on our
server can follow, reply to, like, and boost users on those other
servers, and vice versa.

The product has two faces:

- **A human-facing web UI** rendered server-side (HTML), where logged-in
  users read timelines, write posts, follow people, etc.
- **A machine-facing ActivityPub API**, where remote servers POST
  activities to our users' inboxes and GET our users' actor documents
  and collections as `application/activity+json`.

Both faces are served by **the same C++ HTTP server process**. The same
URL (`/u/<username>`, `/p/<id>`) returns HTML or ActivityPub JSON
depending on the request's `Accept` header (this is called *content
negotiation*).

### 1.1 What v1 must deliver

The complete user-facing and technical feature list lives in
[`prd.md`](../prd.md). At a glance, v1 includes: timelines (paginated),
posting with four visibility scopes, content warnings / sensitive
media, replies, boosts, likes, bookmarks, emoji reactions, custom
server emoji, user/post search (local + remote via WebFinger),
following (local + remote), file attachments, post deletion, OIDC
login, profile editing, and threaded post views with recursive remote
fetch.

On the federation side: full HTTP-signature signing and verification,
SSRF protection, a system actor, inbox/outbox/followers/following
collections, sharedInbox, WebFinger and NodeInfo, inbox forwarding
(§8.1.2), incoming `Create`/`Follow`/`Accept`/`Like`/`Announce`/
`Delete`/`Update`/`Undo` handling with deduplication, a persisted job
queue with retries for outbound delivery, and JSON-LD polymorphism
normalization.

### 1.2 What v1 must *not* preclude

A future client-to-server (C2S) API (Pleroma-flavored Mastodon API for
mobile clients) is **out of scope** but must remain *architecturally
reachable*. Concretely (PRD lines 127–135):

- **Request handlers stay thin.** All business logic lives in the
  service / federation / data layers, never in the HTTP handler bodies,
  so the future API can call the same functions.
- **Current-user resolution goes through one abstraction.** v1
  implements it with cookie sessions; the future API will add OAuth
  bearer tokens behind the same interface.
- **IDs and pagination already align with Mastodon.** Integer primary
  keys map to Mastodon's string IDs, and id-keyed cursor pagination maps
  to Mastodon's `max_id`/`min_id` cursoring.

Keep these three constraints in mind throughout; they shape the layering
decisions below.

---

## 2. Glossary

| Term | Meaning |
|------|---------|
| **Actor** | An ActivityPub entity that can act (a user, or our system actor). Identified by a globally unique URI (its `id`). |
| **Activity** | A JSON-LD object describing an action (`Create`, `Follow`, `Like`, …). Delivered to inboxes. |
| **Object** | The thing an activity acts on (e.g. a `Note` = a post). |
| **Inbox** | A per-actor URL that receives `POST`ed activities from other servers. |
| **Outbox** | A per-actor URL listing activities the actor has published. |
| **sharedInbox** | A single server-wide inbox; lets a remote server deliver one copy for many local recipients. |
| **Local** | Belonging to our server (a user or post we host). |
| **Remote** | Belonging to another server. |
| **URL root** | The base URL where our service actually runs; all actor IDs and endpoints are sub-URLs of it. |
| **Public domain** | The bare domain that appears in user handles (`@user@public_domain`), possibly different from the URL root's host. |
| **Handle** | The human-readable address of a user: `@username@public_domain`. |
| **WebFinger** | A discovery protocol ([RFC 7033](https://www.rfc-editor.org/rfc/rfc7033)) that maps a handle to an actor URI. |
| **`mw::E<T>`** | libmw's expected/error result type, `E<T> = std::expected<T, Error>`-style. Our primary error-propagation mechanism. |

---

## 3. High-level architecture

### 3.1 Module layering

The PRD (lines 119–126) mandates four backend modules. We implement them
as distinct layers with a strict dependency direction (each layer may
call the layer below it, never above):

```
        ┌───────────────────────────────────────────────┐
        │                 app module                    │  HTTP server, routing, handlers,
        │  (handlers are THIN — no business logic)      │  template rendering, OIDC, sessions, CSRF
        └───────────────┬───────────────────┬───────────┘
                        │                   │
                        ▼                   ▼
        ┌───────────────────────┐   ┌────────────────────────┐
        │   federation module   │   │   service helpers      │  ActivityPub logic: signing,
        │  (ActivityPub logic)  │   │  (markdown, sanitize,  │  verification, delivery, JSON-LD,
        │                       │   │   attachments, search) │  inbox handling, WebFinger
        └───────────┬───────────┘   └────────────┬───────────┘
                    │                            │
                    └──────────────┬─────────────┘
                                   ▼
                    ┌───────────────────────────────┐
                    │         data module           │  All SQL. Connection-per-thread.
                    │  (the ONLY code touching SQL) │  Busy-timeout + retry. Returns structs.
                    └───────────────┬───────────────┘
                                    ▼
                    ┌───────────────────────────────┐
                    │        struct module          │  Plain data definitions (User, Post,
                    │  (pure data, no logic)        │  Activity, …). Depended on by everyone.
                    └───────────────────────────────┘
```

**Why this layering?** It is the concrete mechanism that satisfies
§1.2's "handlers stay thin." If a handler contained, say, the logic for
constructing a `Create` activity, the future C2S API would have to
duplicate it. By forcing that logic into the federation module, both the
HTML handler and the future API handler call one function.

The example to follow for the data module shape is shrt's
[`data.hpp`](https://github.com/MetroWind/shrt/blob/master/src/data.hpp);
for config, shrt's
[`config.cpp`](https://github.com/MetroWind/shrt/blob/master/src/config.cpp);
for the overall CMake/libmw wiring, shrt's
[`CMakeLists.txt`](https://github.com/MetroWind/shrt/blob/master/CMakeLists.txt).

### 3.2 Process and threading model

A single process runs:

- **N HTTP worker threads** (provided by libmw's HTTP server). Each
  handles one request at a time, synchronously. Handlers must not block
  on slow network I/O to *remote* servers — that work is deferred to the
  job queue (see §14).
- **M background worker threads** draining the persisted job queue.
  These perform the slow outbound work (signing + delivering activities,
  resolving remote actors, recursive thread fetches).

Both pools touch SQLite. The concurrency rules (§7.2) are therefore
critical: **one SQLite connection per thread**, WAL mode, a configurable
`busy_timeout`, and bounded retry on `SQLITE_BUSY`/`SQLITE_LOCKED`.

### 3.3 The two request lifecycles

**Inbound HTML request** (a browser):
1. libmw routes the request to a handler.
2. Handler resolves the current user from the session cookie (§15.4).
3. Handler validates CSRF if it is a state-changing POST (§16.4).
4. Handler calls service/federation/data functions to do the work.
5. Handler renders an Inja template to HTML and returns it.

**Inbound ActivityPub request** (a remote server POSTing to an inbox):
1. libmw routes to the inbox handler.
2. The HTTP signature is verified (§10), including `Digest` and clock
   skew. On failure → `401`.
3. The body is parsed and normalized through the JSON-LD layer (§9).
4. The activity is deduplicated by `id` (§12.6). A duplicate → `200`
   immediately, no processing.
5. The activity is dispatched to its handler (`Create`, `Follow`, …).
   Anything slow (e.g. fetching a referenced object) is enqueued.
6. Return `202 Accepted` (we accept responsibility; processing may be
   async).

**Outbound delivery** (we publish something):
1. A handler/service creates the local object + activity in the DB.
2. It computes the recipient inbox set (sharedInbox-preferred, §12.8).
3. It enqueues one delivery job per target inbox (§14).
4. The HTTP handler returns immediately to the user.
5. Background workers sign and POST each activity, retrying on failure.

---

## 4. Technology stack and build system

### 4.1 Language and standard

C++23. Use modern facilities: `std::expected` (or libmw's `E<>` wrapper
over it), `std::optional`, `std::string_view`, ranges where they
clarify, `std::format`. Avoid exceptions for control flow — see §18.

### 4.2 Dependencies

| Dependency | Purpose | How obtained |
|-----------|---------|--------------|
| [libmw](https://github.com/MetroWind/libmw) | HTTP server, HTTP client, HTTP signing/verification, SQLite wrapper, `E<>`/`Error` | FetchContent. Headers: [includes/mw](https://github.com/MetroWind/libmw/tree/master/includes/mw) |
| [nlohmann/json](https://github.com/nlohmann/json) | JSON parsing/serialization | FetchContent |
| [Inja](https://github.com/pantor/inja) | Server-side HTML templating | FetchContent |
| [Rapid YAML (ryml)](https://github.com/biojppm/rapidyaml) | Parse the config file | FetchContent |
| [MacroDown](https://git.xeno.darksair.org/macrodown/tree/master) | Markdown → HTML, plus custom mention/hashtag markup | FetchContent |
| OpenSSL | RSA keygen, signing, SHA-256, JWT/JWKS verification | System package (do **not** FetchContent) |
| SQLite3 | Database | System package (do **not** FetchContent) |

The rule (PRD line 93): **FetchContent for everything except widely
available system libraries (OpenSSL, SQLite).** Model the `CMakeLists.txt`
on
[shrt's](https://github.com/MetroWind/shrt/blob/master/CMakeLists.txt).

### 4.2.1 We own libmw and MacroDown

**[libmw](https://github.com/MetroWind/libmw) and
[MacroDown](https://git.xeno.darksair.org/macrodown/tree/master) are our
own libraries.** They are not third-party constraints — we control their
source. The practical consequence: **if this design needs a capability
that libmw or MacroDown does not yet expose, that is not a blocker.** We
add the capability to the library rather than working around its absence
in the app.

**Workflow for a library feature need.** When implementation reveals
that we need a new or changed feature in libmw or MacroDown:

1. **Do not** hack around it at the app layer, and **do not** silently
   assume the API exists.
2. **Write a separate feature-request document** describing the needed
   capability — what it does, the proposed API surface, why the app
   needs it, and any constraints. Place it in the **project root** (not
   under `designs/`), e.g. `libmw-feature-<topic>.md`. These docs are
   **temporary** — they are removed once the feature is implemented.
3. That feature-request doc is handed to a **separate implementation
   session** that works on the library itself. The app-side design here
   may then assume the capability exists once the request is filed.

This keeps the app design clean (it states the app-level requirement,
assuming the libraries are capable) while capturing library gaps as
first-class, separately-implementable work items.

### 4.3 Build targets

- `unspoken` — the server executable (entry point `main.cpp`).
- `unspoken_test` — **a single test executable containing all unit
  tests** (PRD line 256). Use whatever test framework shrt uses (likely
  GoogleTest via FetchContent). One executable means `ctest` runs the
  whole suite in one invocation and shared test fixtures are trivial.

### 4.4 Generated version header

Follow shrt's pattern of a `commit.hpp.in` configured by CMake into a
`commit.hpp` carrying the git commit hash, surfaced in NodeInfo and
optionally a footer.

---

## 5. Configuration

Configuration is a YAML file parsed with ryml at startup into a
`Config` struct. Parsing returns `E<Config>`; a malformed or
incomplete config is a fatal startup error (print the error, exit
non-zero). Model the loader on shrt's
[`config.cpp`](https://github.com/MetroWind/shrt/blob/master/src/config.cpp).

### 5.1 The complete config schema

```yaml
# ─── Network / identity ───────────────────────────────────────────
url_root: "https://f.mws.rocks/"   # REQUIRED. Trailing slash normalized.
                                    # All actor IDs/endpoints are sub-URLs of this.
public_domain: "mws.rocks"          # OPTIONAL. Bare domain for @handles.
                                    # Defaults to the HOST of url_root.
listen_address: "127.0.0.1"         # Where the HTTP server binds.
listen_port: 8080

# ─── Storage ──────────────────────────────────────────────────────
database_path: "/var/lib/unspoken/db.sqlite"
attachment_dir: "/var/lib/unspoken/attachments"
emoji_dir: "/var/lib/unspoken/emoji"   # Server-wide custom emoji images,
                                        # scanned at startup (§13.4).

# ─── Pagination ───────────────────────────────────────────────────
posts_per_page: 20                  # Timeline + collection page size.

# ─── Federation tuning ────────────────────────────────────────────
http_signature_skew_seconds: 300    # Max |now - Date| on incoming reqs.
thread_fetch_max_depth: 20          # Recursion cap for thread/forwarding.
sqlite_busy_timeout_ms: 5000        # PRAGMA busy_timeout.

# ─── Job queue ────────────────────────────────────────────────────
job_workers: 4                      # Background worker thread count.
job_max_retries: 8                  # Per-job delivery retry cap.
job_retry_base_delay_seconds: 30    # Backoff base (see §14.4).

# ─── Uploads ──────────────────────────────────────────────────────
max_upload_bytes: 10485760          # 10 MiB. Reject larger uploads.

# ─── OpenID Connect (Keycloak) ────────────────────────────────────
oidc:
  issuer: "https://keycloak.example/realms/main"
  client_id: "unspoken"
  client_secret: "..."
  scopes: "openid profile"          # OPTIONAL, default shown.

# ─── NodeInfo (advertised server metadata) ────────────────────────
nodeinfo:
  software_name: "unspoken"
  open_registrations: true          # Any OIDC-authenticated user may register.
  description: "A small fedi instance."
  # Other free-form fields surfaced in the nodeinfo document.
```

### 5.2 Validation rules

- `url_root` must be a valid absolute `https://` URL. Normalize it to a
  canonical form with exactly one trailing slash so URL construction
  elsewhere is `url_root + "u/" + username` style without double
  slashes.
- If `public_domain` is empty, set it to the host component of
  `url_root` (e.g. `f.mws.rocks`).
- All numeric tuning params must be positive; provide the defaults shown.
- `oidc.issuer`, `client_id`, `client_secret` are required.
- The `attachment_dir` and `database_path` parent directories must
  exist and be writable; check at startup.

---

## 6. Domain model: URL root, public domain, handles, IDs

This section resolves the trickiest source of interoperability bugs.
Read it carefully; getting it wrong causes "split identities" on remote
servers (decision **C3** in `prd_gaps.md`).

### 6.1 Two domains, two roles

- **URL root (internal domain).** Where the service runs. The **actor
  `id` URI and every ActivityPub endpoint live here**, *including any
  path*. With `url_root = https://mws.rocks/fedi/`:
  - Actor id: `https://mws.rocks/fedi/u/alice`
  - Inbox: `https://mws.rocks/fedi/u/alice/inbox`
  - Outbox/followers/following analogously.
  Remote servers *do* see this domain (and path) in the actor id. **Do
  not strip the path** from actor URLs.

- **Public domain.** Appears **only in the handle**: `@alice@mws.rocks`
  / `acct:alice@mws.rocks`. A handle is a bare `user@domain` and **can
  never contain a path** — this is why we need a separate domain concept
  when `url_root` has a path. The UI displays handles using the public
  domain everywhere (profiles, mentions, timelines). Defaults to the
  host of `url_root` when unset.

### 6.2 URL patterns (PRD lines 187–193)

| Resource | URL |
|----------|-----|
| User actor | `<url_root>/u/<username>` |
| Post object | `<url_root>/p/<id>` |
| Inbox | `<url_root>/u/<username>/inbox` |
| Outbox | `<url_root>/u/<username>/outbox` |
| Followers | `<url_root>/u/<username>/followers` |
| Following | `<url_root>/u/<username>/following` |
| sharedInbox | `<url_root>/inbox` (server-wide) |
| System actor | `<url_root>/actor` (or similar; see §12.2) |

### 6.3 Identifiers

- **Local users** and **local posts** have integer primary keys
  (`AUTOINCREMENT`). These integers appear directly in `/u/<username>`
  (via username) and `/p/<id>` (via id).
- **Every post** (local and remote) lives in **one shared table** with a
  `uri` column that is **unique and indexed**. For local posts the URI
  is `<url_root>/p/<id>`; for remote posts it is the origin server's URI.
- The integer IDs are deliberately sequential and enumerable. That is an
  accepted trade-off (decision **B3**): public-post existence is
  discoverable, which is fine; **private-post safety relies on returning
  `404` (not `403`) for unauthorized fetches** (§16.6, decision **B2**),
  so an enumerator cannot tell a private post from a nonexistent one.

---

## 7. Database schema and the data module

### 7.1 Schema versioning

The schema version is an integer stored in SQLite's
[`PRAGMA user_version`](https://www.sqlite.org/pragma.html#pragma_user_version),
starting at `1`. On startup the data module reads `user_version`; if it
is `0` (fresh DB) it creates all tables and sets `user_version = 1`.
**No migration logic is needed for v1** — the version stays `1` until
the first stable release (PRD line 270). Still, write the dispatch as a
`switch` on version so migrations slot in later.

### 7.2 Concurrency model (decision C5)

SQLite allows **one writer at a time** but, in
[WAL mode](https://www.sqlite.org/wal.html), **concurrent readers
alongside the single writer**. Our two thread pools (HTTP + job workers)
will contend on writes. The rules:

1. **Enable WAL** at startup: `PRAGMA journal_mode=WAL;`.
2. **One connection per thread.** Never share a `sqlite3*` across
   threads. The data module hands each thread its own connection (e.g.
   `thread_local`, or a small pool keyed by thread). This way WAL's
   "many readers + one writer" actually applies.
3. **Set `PRAGMA busy_timeout = sqlite_busy_timeout_ms;`** on every
   connection so a blocked write *waits* for the lock instead of
   immediately failing.
4. **Bounded retry-with-backoff** wrapping each write that can still see
   `SQLITE_BUSY`/`SQLITE_LOCKED` after the busy_timeout (e.g. during a
   checkpoint). Retry a few times with small sleeps, then surface the
   error as `E<>`. This makes contended writes reliable rather than
   spuriously failing.

The data module exposes a helper like
`E<void> withWriteRetry(std::function<E<void>()> txn)` that all writers
use.

### 7.3 Table definitions

Below is the complete schema. Types are SQLite type-affinity hints.
Every foreign key references an integer PK. Indices are listed after
each table; create them explicitly.

```sql
-- Local accounts. One row per OIDC subject that finished username setup.
CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,       -- immutable once set
    display_name    TEXT NOT NULL DEFAULT '',   -- editable
    bio             TEXT NOT NULL DEFAULT '',    -- editable, markdown source
    oidc_iss        TEXT NOT NULL,
    oidc_sub        TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,              -- RSA private key (local users)
    public_key_pem  TEXT NOT NULL,
    created_at      INTEGER NOT NULL            -- unix seconds
);
CREATE UNIQUE INDEX idx_users_oidc ON users(oidc_iss, oidc_sub);

-- Remote actors we have encountered. Cached on first contact.
CREATE TABLE remote_actors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    uri             TEXT NOT NULL UNIQUE,       -- the actor id
    username        TEXT NOT NULL,              -- preferredUsername
    domain          TEXT NOT NULL,              -- for @user@domain handle
    display_name    TEXT NOT NULL DEFAULT '',
    inbox           TEXT NOT NULL,
    shared_inbox    TEXT,                       -- nullable
    public_key_pem  TEXT NOT NULL,
    public_key_id   TEXT NOT NULL,              -- the keyId in signatures
    actor_json      TEXT NOT NULL,              -- raw cached actor doc
    fetched_at      INTEGER NOT NULL
);
CREATE INDEX idx_remote_actors_domain ON remote_actors(domain);

-- Posts: BOTH local and remote live here (PRD line 207).
CREATE TABLE posts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    uri             TEXT NOT NULL UNIQUE,       -- local: url_root/p/<id>; remote: origin URI
    local_author_id INTEGER,                    -- FK users.id, NULL if remote
    remote_author_id INTEGER,                   -- FK remote_actors.id, NULL if local
    content_html    TEXT NOT NULL,              -- rendered, sanitized HTML
    content_source  TEXT,                       -- markdown source (local only)
    summary         TEXT,                       -- content warning text, nullable
    sensitive       INTEGER NOT NULL DEFAULT 0, -- boolean
    visibility      TEXT NOT NULL,              -- 'public'|'unlisted'|'followers'|'direct'
    in_reply_to_uri TEXT,                        -- parent post URI, nullable
    created_at      INTEGER NOT NULL,
    published       TEXT                        -- original published timestamp (remote)
);
CREATE INDEX idx_posts_created ON posts(created_at);
CREATE INDEX idx_posts_inreplyto ON posts(in_reply_to_uri);
CREATE INDEX idx_posts_local_author ON posts(local_author_id);

-- Explicit per-post recipients (the addressing audience), used for
-- private-post authorization and delivery. One row per (post, recipient).
CREATE TABLE post_recipients (
    post_id         INTEGER NOT NULL,           -- FK posts.id
    recipient_uri   TEXT NOT NULL,              -- actor URI or Public/Followers collection
    field           TEXT NOT NULL               -- 'to' | 'cc'
);
CREATE INDEX idx_post_recipients_post ON post_recipients(post_id);

-- Attachments on posts.
CREATE TABLE attachments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id         INTEGER,                    -- FK posts.id (NULL while draft)
    sha256          TEXT NOT NULL,              -- lowercase hex
    media_type      TEXT NOT NULL,              -- MIME
    original_name   TEXT NOT NULL,
    is_image        INTEGER NOT NULL DEFAULT 0,
    sensitive       INTEGER NOT NULL DEFAULT 0,
    remote_url      TEXT                        -- set for remote attachments (not stored locally)
);
CREATE INDEX idx_attachments_post ON attachments(post_id);

-- Follow relationships (local->anyone, anyone->local). Stores actor URIs
-- so it uniformly covers local and remote on both sides.
CREATE TABLE follows (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    follower_uri    TEXT NOT NULL,
    followee_uri    TEXT NOT NULL,
    state           TEXT NOT NULL,              -- 'pending' | 'accepted'
    follow_activity_uri TEXT,                    -- the Follow activity id (for Undo/Accept)
    created_at      INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_follows_pair ON follows(follower_uri, followee_uri);

-- Likes. Author of post sees who liked (PRD line 27).
CREATE TABLE likes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_uri       TEXT NOT NULL,
    post_uri        TEXT NOT NULL,
    activity_uri    TEXT,                        -- the Like activity id (for Undo)
    created_at      INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_likes_pair ON likes(actor_uri, post_uri);

-- Boosts (Announce).
CREATE TABLE boosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_uri       TEXT NOT NULL,
    post_uri        TEXT NOT NULL,
    activity_uri    TEXT,
    created_at      INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_boosts_pair ON boosts(actor_uri, post_uri);

-- Emoji reactions (Pleroma EmojiReact).
CREATE TABLE reactions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_uri       TEXT NOT NULL,
    post_uri        TEXT NOT NULL,
    emoji           TEXT NOT NULL,              -- unicode emoji or :shortcode:
    activity_uri    TEXT,
    created_at      INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_reactions_triple ON reactions(actor_uri, post_uri, emoji);

-- Bookmarks (purely local, no federation — PRD line 28).
CREATE TABLE bookmarks (
    user_id         INTEGER NOT NULL,           -- FK users.id
    post_id         INTEGER NOT NULL,           -- FK posts.id
    created_at      INTEGER NOT NULL,
    PRIMARY KEY (user_id, post_id)
);

-- NOTE: server-wide custom emoji are NOT stored in the DB. They are an
-- in-memory registry built by scanning config.emoji_dir at startup
-- (§13.4) — the directory is the single source of truth.

-- Stateful sessions (PRD line 211).
CREATE TABLE sessions (
    token           TEXT PRIMARY KEY,           -- random opaque token
    user_id         INTEGER NOT NULL,           -- FK users.id
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
);

-- Transient pending-login state for the OIDC flow (state+nonce).
CREATE TABLE pending_logins (
    state           TEXT PRIMARY KEY,
    nonce           TEXT NOT NULL,
    created_at      INTEGER NOT NULL
);

-- Dedup of processed incoming activities (decision C2).
CREATE TABLE seen_activities (
    activity_uri    TEXT PRIMARY KEY,
    seen_at         INTEGER NOT NULL
);

-- Persisted job queue (PRD line 146).
CREATE TABLE jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT NOT NULL,              -- 'deliver' | 'resolve_actor' | 'fetch_thread' | ...
    payload_json    TEXT NOT NULL,             -- kind-specific parameters
    state           TEXT NOT NULL,             -- 'pending' | 'running' | 'done' | 'failed'
    attempts        INTEGER NOT NULL DEFAULT 0,
    run_after       INTEGER NOT NULL,          -- earliest unix time to run (for backoff)
    last_error      TEXT,
    created_at      INTEGER NOT NULL
);
CREATE INDEX idx_jobs_runnable ON jobs(state, run_after);
```

A `Note`'s exact `published` time from a remote server is kept verbatim
in `published` so we can re-emit it; `created_at` is our local insertion
time, used for stable cursor ordering.

### 7.4 The data module surface

The data module is the **only** code that issues SQL. It exposes typed
functions returning `E<T>`, e.g.:

```cpp
E<std::optional<User>> getUserByUsername(std::string_view username);
E<std::optional<User>> getUserByOidcSub(std::string_view iss, std::string_view sub);
E<User>                createUser(const NewUser& nu);
E<void>                updateUserProfile(int64_t id, std::string_view display, std::string_view bio);

E<int64_t>             insertPost(const NewPost& np);          // returns new id
E<std::optional<Post>> getPostByUri(std::string_view uri);
E<std::optional<Post>> getPostById(int64_t id);
E<std::vector<Post>>   timelinePublic(Cursor c, int limit);    // §16.2
E<std::vector<Post>>   timelineHome(int64_t user_id, Cursor c, int limit);
E<std::vector<Post>>   threadFor(std::string_view root_uri);

E<RemoteActor>         upsertRemoteActor(const RemoteActor& a);
E<std::optional<RemoteActor>> getRemoteActorByUri(std::string_view uri);

E<void>                addFollow(const Follow& f);
E<void>                setFollowState(std::string_view follower, std::string_view followee, FollowState s);
E<std::vector<std::string>> followerInboxes(std::string_view local_actor_uri); // for delivery

E<bool>                markActivitySeen(std::string_view uri);  // false if already seen
// ... likes/boosts/reactions/bookmarks/emoji/sessions/pending_logins/jobs analogously
```

Each function uses the calling thread's connection and the write-retry
wrapper for mutations. **Never** leak a `sqlite3_stmt*` or connection
above this layer; callers see only structs from the struct module.

---

## 8. The struct module (core types)

Pure data, no behavior beyond trivial constructors/serializers. Header
only. Examples (illustrative, not exhaustive):

```cpp
enum class Visibility { PUBLIC, UNLISTED, FOLLOWERS, DIRECT };

struct User {
    int64_t id;
    std::string username;
    std::string display_name;
    std::string bio;
    std::string oidc_iss, oidc_sub;
    std::string private_key_pem, public_key_pem;
    int64_t created_at;
};

struct RemoteActor {
    int64_t id;
    std::string uri, username, domain, display_name;
    std::string inbox;
    std::optional<std::string> shared_inbox;
    std::string public_key_pem, public_key_id;
    std::string actor_json;
    int64_t fetched_at;
};

struct Post {
    int64_t id;
    std::string uri;
    std::optional<int64_t> local_author_id;
    std::optional<int64_t> remote_author_id;
    std::string content_html;
    std::optional<std::string> content_source;
    std::optional<std::string> summary;     // content warning
    bool sensitive;
    Visibility visibility;
    std::optional<std::string> in_reply_to_uri;
    int64_t created_at;
    std::optional<std::string> published;
};

struct Attachment { /* ... mirrors attachments table ... */ };

// A normalized, parser-friendly view of an incoming activity (see §9).
struct Activity {
    std::string id;                 // canonical URI
    std::string type;               // "Create", "Follow", ...
    std::string actor;              // canonical actor URI
    nlohmann::json object;          // embedded object or {"id": "..."}
    std::vector<std::string> to;    // normalized to a list
    std::vector<std::string> cc;
    nlohmann::json raw;             // the original, for forwarding verbatim
};

// Pagination cursor (decision C4).
struct Cursor {
    std::optional<int64_t> max_id;  // return items with id < max_id (older)
    std::optional<int64_t> min_id;  // return items with id > min_id (newer)
};
```

The `as:Public` sentinel is defined **once** here as a named constant
(decision D3):

```cpp
inline constexpr std::string_view AS_PUBLIC =
    "https://www.w3.org/ns/activitystreams#Public";
```

Reference `AS_PUBLIC` everywhere — both when emitting addressing and
detecting public visibility — so a typo can never silently break
public-visibility detection.

---

## 9. JSON-LD normalization layer

ActivityPub messages are JSON-LD, and different implementations encode
the same information in different shapes. **Before any business logic
touches an incoming document, normalize it.** This is a dedicated module
(PRD lines 246–255).

### 9.1 The polymorphism we must absorb

1. **Addressing fields (`to`, `cc`, `bto`, `bcc`, `audience`)** may be a
   single string *or* an array of strings. Normalize **always to a
   `std::vector<std::string>`** (an absent field → empty vector).

2. **ID-reference fields (`actor`, `object`, `attributedTo`, `inReplyTo`,
   `target`)** may be a bare URI string *or* an embedded object with an
   `id`. Normalize to the **canonical URI string**. (Keep the embedded
   object too when present — e.g. a `Create` usually embeds its `Note`,
   which we want without a second fetch.)

3. **The public-addressing marker** must be recognized in **all three
   legal input forms**:
   - full IRI `https://www.w3.org/ns/activitystreams#Public`
   - compact `as:Public`
   - bare `Public`

   A helper `bool isPublicAddress(std::string_view)` matches all three.
   **On output we always emit the full IRI** (`AS_PUBLIC`).

### 9.2 API

```cpp
// Normalize a to/cc-style field.
std::vector<std::string> normalizeAddressing(const nlohmann::json& field);

// Extract a canonical URI from a string-or-object reference.
std::optional<std::string> normalizeRef(const nlohmann::json& field);

// Parse a raw incoming activity into our Activity struct.
E<Activity> parseActivity(const nlohmann::json& raw);

bool isPublicAddress(std::string_view uri);
```

`parseActivity` rejects (`E` error) only on structurally impossible
input (e.g. missing `type` or `id`). It is liberal otherwise — Postel's
law — because the live Fediverse is messy. See the ActivityStreams 2.0
spec ([core](https://www.w3.org/TR/activitystreams-core/),
[vocabulary](https://www.w3.org/TR/activitystreams-vocabulary/)) for the
field meanings.

---

## 10. HTTP signatures (sign and verify)

This is the heart of federation security. We follow the
[draft-cavage HTTP signatures](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures)
spec as deployed across the Fediverse (see also the
[ActivityPub HTTP signatures CG note](https://swicg.github.io/activitypub-http-signature/)).
libmw provides the signing/verification primitives (PRD line 74); this
module wires them to our policy.

### 10.1 Verification (incoming) — decisions A1, A2, A3, A4

**Every** incoming request that carries a `Signature` header is verified.
Inbox POSTs without a valid signature are rejected `401`.

The signature `headers` parameter lists which pseudo-headers/headers are
covered; we reconstruct the *signing string* from them in order and
verify against the actor's public key.

Algorithm:

1. **Parse the `Signature` header** into `keyId`, `algorithm` (optional),
   `headers`, `signature`.
2. **Accept both `rsa-sha256` and `hs2019`** algorithm labels. Treat
   `hs2019` carrying the legacy header set as `rsa-sha256` (decision A1).
   Most of the live Fediverse signs `rsa-sha256`; this is non-negotiable.
3. **Clock-skew check (A3).** Parse the `Date` header; if
   `|now − Date| > http_signature_skew_seconds` (default 300) → reject
   `401`. This blocks replay of old signed requests.
4. **Digest check on POST/PUT (A2).** This has two non-negotiable
   sub-rules:
   - **Bind digest to the signature:** `digest` **must** be in the signed
     `headers` list. If it isn't, reject — otherwise a MITM could swap
     the body, recompute `Digest`, and replay a signature that only
     covered `(request-target) host date`.
   - **No silent bypass on format:** parse the `Digest` header value
     case-insensitively, handle the comma-separated multi-value form
     ([RFC 3230](https://www.rfc-editor.org/rfc/rfc3230)), select the
     **SHA-256** entry, recompute SHA-256 of the raw body, and compare.
     If there is no usable SHA-256 digest, reject `401`. Never skip the
     check just because the literal prefix wasn't exactly `SHA-256=`.
5. **Resolve the signer's key.** `keyId` is a URL like
   `https://remote/u/bob#main-key`. Look up the cached `remote_actors`
   row by the actor URI (strip the fragment). If we have no cached key,
   resolve the actor via the **system-actor-signed GET** (§11, §12.2,
   decision C1) and cache it.
6. **Verify the signature** over the reconstructed signing string with
   the cached public key.
7. **Key-rotation retry (A4).** If verification fails with a cached key,
   **re-fetch the actor once**, update the stored key, and retry. If it
   still fails → reject. This stops a single key rotation from
   permanently breaking a peer.

A successful verification yields the authenticated **actor URI**, which
downstream logic uses for authorization (e.g. private-post fetch, §16.6).

### 10.2 Signing (outgoing) — decision A1

All outbound requests to remote servers are signed (PRD line 79). We
sign **`rsa-sha256` cavage** — the construction every peer verifies — for
maximum deliverability. **No per-peer "try hs2019 then fall back"
machinery.**

- **Signed headers for GET:** `(request-target)`, `host`, `date`.
- **Signed headers for POST:** `(request-target)`, `host`, `date`,
  `digest` (and we send `Content-Type: application/activity+json`).
  Compute `Digest: SHA-256=<base64(sha256(body))>` and include it.
- **`keyId`** is the signing actor's key id (`<actor>#main-key`).
- For user-initiated deliveries the signing key is the **local user's**
  key; for actor resolution / WebFinger / object fetches with no
  associated user, the **system actor's** key (§12.2).

[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) (the modern
successor) stays in Future Work (§20); it can be added later without ever
blocking deliverability.

---

## 11. SSRF-safe outbound HTTP

Decision **B1**. Actor resolution, recursive thread fetch, and WebFinger
all take **remote-controlled URLs**. Without filtering, a hostile peer
could make us fetch `http://169.254.169.254/…` (cloud metadata) or
`http://localhost:…` (internal services). Every outbound request to a
remote-controlled URL goes through an SSRF guard.

Rules:

1. **`https`-only.** Reject any non-`https` scheme, for both the initial
   URL and every redirect target.
2. **Validate the resolved destination IP, not the hostname.** A
   hostname can resolve to an internal address, so the blocklist applies
   to the **actual resolved IP(s)**. Reject if the IP is in any of:
   - loopback `127.0.0.0/8`, `::1`
   - private `10/8`, `172.16/12`, `192.168/16`
   - link-local `169.254/16` (this includes the cloud-metadata address
     `169.254.169.254`)
   - unique-local IPv6 `fd00::/8`
   - and **normalize IPv4-mapped IPv6** (`::ffff:127.0.0.1`) to its IPv4
     form *before* checking, so it can't bypass the IPv4 blocklist.
3. **Rebinding-proof connect.** Validate the **exact address the socket
   will connect to**, at connect time — no separate "resolve then
   connect" window (that TOCTOU gap is the DNS-rebinding attack). In
   practice: resolve, pick an address, validate *that* address, and
   connect to *that* address (pin it), rather than re-resolving.
4. **Cap redirects** to a small number and **re-validate the destination
   on every hop** (re-apply rules 1–3 to each `Location`).

Implement this as a wrapper around libmw's HTTP client. Background on the
attack class: [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery).

---

## 12. The federation module

This module contains all ActivityPub logic. It depends on the JSON-LD
layer (§9), signatures (§10), SSRF-safe fetch (§11), and the data module.

### 12.1 Actor documents (serving our actors)

For a local user, the Actor JSON is **computed from the user row**, not
stored (per recent project direction). It is served at
`<url_root>/u/<username>` when `Accept: application/activity+json`. Shape:

```json
{
  "@context": ["https://www.w3.org/ns/activitystreams",
               "https://w3id.org/security/v1"],
  "type": "Person",
  "id": "https://f.mws.rocks/u/alice",
  "preferredUsername": "alice",
  "name": "Alice Display",
  "summary": "<bio rendered to HTML>",
  "inbox": "https://f.mws.rocks/u/alice/inbox",
  "outbox": "https://f.mws.rocks/u/alice/outbox",
  "followers": "https://f.mws.rocks/u/alice/followers",
  "following": "https://f.mws.rocks/u/alice/following",
  "endpoints": { "sharedInbox": "https://f.mws.rocks/inbox" },
  "publicKey": {
    "id": "https://f.mws.rocks/u/alice#main-key",
    "owner": "https://f.mws.rocks/u/alice",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
  }
}
```

Each local user gets an **RSA keypair generated at account creation**
(2048-bit), stored in `users.private_key_pem` / `public_key_pem`. The
public key is served as above; the private key signs that user's
outbound activities.

### 12.2 The system actor (decision C1)

A single server-wide actor (e.g. `Application` type at `<url_root>/actor`)
exists to **sign requests not associated with any user**: actor
resolution, WebFinger probes, object/thread fetches, and verifying
forwarded activities. Its keypair is generated once at first startup and
stored (a dedicated row, e.g. a reserved username like `__system__`, or a
small singleton table — either is fine; keep it out of the human
username space). When we must fetch a remote resource and have no user
context, we sign the GET with the system actor so it works against peers
in "secure mode" (authorized fetch).

### 12.3 Resolving a remote actor

On first encounter with a remote actor URI:
1. **SSRF-checked, system-actor-signed GET** of the actor URI with
   `Accept: application/activity+json`.
2. Parse `inbox`, `endpoints.sharedInbox`, `preferredUsername`,
   `publicKey.publicKeyPem`, `publicKey.id`, `name`.
3. Derive the `domain` for the handle (the host of the actor `id`, unless
   the actor advertises a different WebFinger-canonical handle — for v1,
   host of the id is acceptable).
4. `upsertRemoteActor` into the DB cache.

Re-fetch on the key-rotation path (§10.1 step 7) updates this row.

### 12.4 WebFinger and NodeInfo (decision C3)

**WebFinger** ([RFC 7033](https://www.rfc-editor.org/rfc/rfc7033)) at
`/.well-known/webfinger?resource=acct:alice@<domain>`:

- Must resolve on **both** the public domain **and** the URL-root host.
- In **both** cases returns the **canonical subject**
  `acct:alice@<public_domain>` and a `self` link
  (`rel="self"`, `type="application/activity+json"`) pointing to the
  actor id on the **URL root** (`<url_root>/u/alice`).
- The URL-root-host resolution is required for *reverse* discovery: when
  a remote server sees the actor id first, its default would be to derive
  `@alice@<internal_host>`. Answering WebFinger there with the
  public-domain subject forces `@alice@<public_domain>` as canonical,
  preventing split identities. (Mastodon enforces this.)

**NodeInfo** ([nodeinfo spec](https://nodeinfo.diaspora.software/)) at
`/.well-known/nodeinfo` returns a discovery document pointing to the
schema endpoint; the schema doc's fields come from `config.nodeinfo`.

**Deployment caveat (document for the operator):** when `public_domain`
differs from the URL-root host, the operator must reverse-proxy
**specifically** `/.well-known/webfinger` and `/.well-known/nodeinfo`
from the public-domain apex to the service, **without** disturbing the
rest of that apex (e.g. another app, or its `/.well-known/acme-challenge`).
Note the proxy-ordering gotcha in the README.

### 12.5 Visibility and addressing (PRD lines 237–245, decision D3)

Define each visibility's addressing exactly:

| Visibility | `to` | `cc` |
|-----------|------|------|
| Public | `[AS_PUBLIC]` | `[followers]` |
| Unlisted | `[followers]` | `[AS_PUBLIC]` |
| Followers-only | `[followers]` | `[]` |
| Direct | `[mentioned actor URIs]` | `[]` |

Detection on **incoming** activities uses `isPublicAddress` (§9.1):
`AS_PUBLIC` in `to` → public; in `cc` only → unlisted; absent → private
(triggers authorization, §16.6). Mentioned actors are always added to
addressing (§13.2).

### 12.6 Incoming activity handling (decision C2)

The inbox handler (HTML-irrelevant; pure AP):

1. **Verify signature** (§10). Fail → `401`.
2. **Parse + normalize** (§9).
3. **Dedup:** `markActivitySeen(activity.id)`. If it returns "already
   seen", return `200` immediately without processing (idempotent
   redelivery).
4. **Inbox forwarding check** (§12.7) — may forward.
5. **Dispatch by `type`:**

| Type | Action |
|------|--------|
| `Create` | Store the embedded `Note` as a remote post (resolve author, save addressing, attachments-as-remote-URLs). Respect visibility. |
| `Follow` | Auto-accept (PRD line 43): record follow as `accepted`, **send an `Accept` activity** back (enqueue delivery). |
| `Accept` | Mark our outgoing `Follow` as `accepted`. |
| `Like` | Record like on the target local post (author can see likers). |
| `Announce` | Record boost — **but ignore if the target object is non-public** (decision E2). |
| `EmojiReact` | Record an emoji reaction (Pleroma-style). |
| `Delete` | Delete the referenced object if we know it; **silently `200` if unknown** (decision C2). |
| `Update` | Update the referenced object/actor if known. |
| `Undo` | Reverse the wrapped activity (unfollow, unlike, unboost, unreact). Unknown target → silently `200`. |

Anything requiring a slow remote fetch (e.g. resolving an unknown author,
fetching a missing parent) is enqueued as a job; the inbox returns
`202 Accepted` promptly.

### 12.7 Inbox forwarding, AP §8.1.2 (decision E3)

Implemented in v1. Forward an inbound activity to a local followers
collection **only when all three hold**:

1. **First time** we've seen this activity (reuse the §12.6 dedup).
2. **Addressed to a collection we own** — `to`/`cc`/`audience` contains a
   local user's `followers` URI.
3. **References an object we own** — `inReplyTo`/`object`/`target`/`tag`
   resolves (recursively, bounded by `thread_fetch_max_depth`) to an
   object we host.

When all hold, deliver the **original activity verbatim** to that
followers collection (sharedInbox-preferred).

**Verifying forwarded activities:** the HTTP signature on a forwarded
activity belongs to the *forwarder*, not the original author, so it can't
prove authorship. **Verify by re-fetching the referenced object from its
origin server** (the §12.3 system-actor-signed GET) and trusting that
copy. **No LD-Signatures in v1.** This is the documented reason a
forwarded activity is trusted despite a "foreign" signature.

### 12.8 Outbound delivery (PRD lines 203–206)

To publish an activity:
1. Compute the **recipient set** from addressing: expand `followers` to
   the set of remote followers' inboxes; add explicitly mentioned/`to`
   actors' inboxes.
2. **Prefer sharedInbox:** group recipients by server; if a server
   advertises a `sharedInbox`, deliver **one** copy there instead of one
   per follower on that server. Otherwise deliver to each personal inbox.
3. **Enqueue one delivery job per target inbox** (§14). The job signs
   (with the author's key, or the system actor for keyless server
   activities) and POSTs.

Local `Delete` and `Update` are federated the same way (PRD line 109):
build the activity, address it to the original audience, enqueue
deliveries.

### 12.9 Recursive thread fetch (PRD lines 232–236)

When a user views a thread and some ancestor/descendant posts are not in
our DB, fetch them from remote servers **recursively, bounded by
`thread_fetch_max_depth`**. Walk `inReplyTo` upward and `replies`
downward (where available), SSRF-checked and system-actor-signed, saving
each fetched post into `posts`. This work is slow → do it via a job
(`fetch_thread`) and render what we have, or block briefly with a depth
cap — prefer the job for deep threads.

---

## 13. Markdown rendering, mentions, and HTML sanitization

### 13.1 Rendering outgoing posts

Local posts are authored in **Markdown** and rendered to **HTML before
federating** (PRD lines 95–98), using
[MacroDown](https://git.xeno.darksair.org/macrodown/tree/master). Store
both the markdown source (`content_source`) and rendered HTML
(`content_html`).

### 13.2 Mentions and hashtags (decision D2)

Mentions/hashtags are parsed by **defining custom MacroDown markups** and
**iterating the resulting syntax tree** (PRD lines 99–104). The extracted
mentions feed **two** places from the same data:

1. **The activity `tag` array** — one object per item:
   - Mention: `{"type": "Mention", "href": "<actor URI>", "name": "@user@domain"}`
   - Hashtag: `{"type": "Hashtag", "href": "<tag page URL>", "name": "#tag"}`
2. **Recipient addressing** — mentioned actors are added to the delivery
   audience: for **Direct** visibility the recipients are **exactly** the
   mentioned actors (`to`); for other visibilities, mentioned actors are
   added to `to`/`cc` so they actually receive the post.

Resolving a mention `@user@domain` to an actor URI uses WebFinger
(§12.4), then actor resolution (§12.3).

### 13.3 Sanitizing incoming HTML

HTML content from remote servers is **untrusted** and must be
**sanitized** before storage/display (PRD line 223) to prevent stored
XSS. Use an allowlist sanitizer: permit a safe subset of tags/attributes
(`p`, `br`, `a[href]`, `span`, `code`, `pre`, `blockquote`, emphasis,
mention/hashtag classes) and strip everything else (`script`, `style`,
event handlers, `javascript:` URLs, etc.). Sanitize the **rendered HTML**
stored in `posts.content_html` for remote posts, and remote actors'
`summary`/`name`.

### 13.4 Custom emoji (server-wide)

PRD line 31. Custom emoji are **server-wide and operator-managed via a
seed directory** — there is no admin UI in v1 (admin/moderation is future
work).

**Wire representation.** A custom emoji is not a dedicated field; it
rides in a post's `tag` array as an `Emoji` object (the Mastodon
`toot:Emoji` convention,
[docs](https://docs.joinmastodon.org/spec/activitypub/#Emoji)), exactly
alongside the `Mention`/`Hashtag` tags built in §13.2. The post
`content` keeps the literal shortcode text `:blobcat:`:

```json
"tag": [{
  "type": "Emoji",
  "id": "https://f.mws.rocks/emoji/blobcat",
  "name": ":blobcat:",
  "icon": { "type": "Image", "mediaType": "image/png",
            "url": "https://f.mws.rocks/emoji/blobcat.png" }
}]
```

**In-memory registry (no DB table).** The emoji directory is the **single
source of truth**; the emoji set is small, static after startup, and
read-only, so it is **not** persisted to the database. At startup, scan
`config.emoji_dir` for image files and build an in-memory map
`shortcode → EmojiInfo{ image_url, media_type }`:
- The **shortcode is the filename stem** (`blobcat.png` → `blobcat`).
- Validate the stem against the shortcode charset `[a-z0-9_]+`; **skip
  invalid names with a logged warning**.
- `image_url = <url_root>/emoji/<filename>`; `media_type` is derived from
  the file extension (needed for the `Emoji` tag's `icon.mediaType`).
- **Shortcode collision** (e.g. `emoji.png` and `emoji.svg` both yield
  `:emoji:`): **first wins** — keep the first file encountered in the
  directory listing, ignore the rest, and **log a warning** naming the
  shortcode and the winning file. This is a misconfiguration the operator
  is expected to avoid; we do not impose a deterministic ordering, so
  which file wins follows the raw filesystem order.

The map is built once and shared read-only across all threads (no
locking). Adding/removing an emoji is: drop/remove a file and re-scan —
on restart, or via an optional re-scan trigger that atomically swaps the
map. No DB editing, no auth model.

**Serving.** Emoji images are served by our own server at
`<url_root>/emoji/<filename>` (a static route over `emoji_dir`, image
content types only, like the image branch of attachment serving in §17.2).

**Authoring (local).** The post form offers shortcode autocomplete from
the registry. The markdown source keeps the literal `:blobcat:`. During
the render/extract pass (the same MacroDown syntax-tree walk as mentions,
§13.2), each `:shortcode:` token is looked up in the registry; a match
(a) emits an `Emoji` tag into the outgoing activity and (b) is substituted
inline in the stored HTML (below). Unknown shortcodes are left as literal
text — no tag, rendered verbatim.

**Rendering = substitute when producing stored HTML** (a deliberate
simplification, consistent with §13.3's "store sanitized HTML"):
- **Local posts:** at compose time, replace each known `:shortcode:` with
  `<img class="emoji" src="<image_url>" alt=":shortcode:">` using the
  in-memory registry.
- **Remote posts:** during sanitization at ingest, replace `:shortcode:`
  using **that post's own incoming `Emoji` tag mapping** (the
  `icon.url`). We render remote emoji straight from the remote URL and
  **do not store remote emoji images** — consistent with the
  "remote attachments aren't cached" rule (§17.3).

Because substitution happens when the stored HTML is produced, **no
per-post emoji side table is needed**; `image_url`s are stable.

**Reactions.** Pleroma-style emoji reactions (§12.6 `EmojiReact`) reuse
the same registry for the picker; the `reactions.emoji` column holds
either a Unicode emoji or a `:shortcode:`, and a custom reaction federates
with an accompanying `Emoji` tag and renders the same way.

---

## 14. The job queue and background workers

PRD lines 146–150. Expensive/slow work is deferred to background workers
so HTTP handlers return promptly.

### 14.1 Persistence

The queue is the `jobs` table (§7.3) — **persisted in the DB** so jobs
survive a restart. A job has a `kind`, a JSON `payload`, a `state`, an
`attempts` counter, and a `run_after` timestamp for backoff.

### 14.2 Job kinds (v1)

| Kind | Payload | Work |
|------|---------|------|
| `deliver` | `{inbox, activity_json, signing_actor}` | Sign + POST one activity to one inbox. |
| `resolve_actor` | `{actor_uri}` | System-signed GET + cache. |
| `fetch_thread` | `{root_uri, depth}` | Recursive thread fetch (§12.9). |
| `accept_follow` | `{follow_activity_uri}` | Build + deliver an `Accept`. |

### 14.3 Worker loop

Each of `job_workers` threads:
1. In a write transaction, claim the oldest runnable job
   (`state='pending' AND run_after <= now`), set `state='running'`.
   (Claiming in a transaction prevents two workers grabbing the same
   job.)
2. Execute by `kind`.
3. On success → `state='done'` (or delete).
4. On failure → see retry policy below.

### 14.4 Retry policy (PRD line 147)

`job_max_retries` and the backoff base `job_retry_base_delay_seconds`
are configurable. On failure:
- Increment `attempts`, store `last_error`.
- If `attempts >= job_max_retries` → `state='failed'` (give up).
- Else → `state='pending'`, `run_after = now + base * 2^attempts`
  (exponential backoff, optionally jittered). This way a temporarily
  unreachable peer is retried later without hammering it.

Failed deliveries are common in the Fediverse (peers go down); the retry
+ backoff is what makes delivery eventually-consistent.

---

## 15. Authentication: OpenID Connect and sessions

Decision **D1**. We do **not** manage passwords; identity comes from the
operator's Keycloak via the OpenID Connect
[Authorization Code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth).

### 15.1 Configuration & discovery

From `config.oidc`: `issuer`, `client_id`, `client_secret`, optional
`scopes` (default `openid profile`). **Discover endpoints** from
`<issuer>/.well-known/openid-configuration` (the
[discovery document](https://openid.net/specs/openid-connect-discovery-1_0.html))
rather than hardcoding the authorization/token/JWKS URLs.

### 15.2 Login

1. Generate random `state` (CSRF) and `nonce`.
2. Persist them in `pending_logins` (and/or a short-lived secure cookie).
3. Redirect the browser to Keycloak's authorization endpoint with
   `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`,
   `nonce`.

### 15.3 Callback

Registered in Keycloak as `<url_root>/.../callback` on the internal
domain:
1. **Validate `state`** against `pending_logins` (CSRF). Mismatch → reject.
2. **Exchange `code` for tokens** at the token endpoint using
   `client_secret`.
3. **Validate the ID token** (a JWT): verify the **signature via JWKS**
   (fetch the issuer's keys), and check `iss == issuer`,
   `aud == client_id`, `exp` not passed, and `nonce` matches the one we
   stored. All of these must pass.
4. **Identity = the `sub` claim** (stable), not email/username. Look up
   `users` by `(oidc_iss, oidc_sub)`.
   - **Existing user** → create a session (§15.4), redirect home.
   - **New `sub`** → the user is authenticated but has no fedi account →
     redirect to **username setup** (§16.5). Username is validated,
     unique, reserved-name-checked, and **immutable once set** (it's
     embedded in the actor URI/handle). On submit, generate the user's
     RSA keypair, create the `users` row keyed to the `sub`, then create
     the session.

Any user who can authenticate with the provider may register (PRD line
222; `open_registrations` advertised in NodeInfo).

### 15.4 Sessions (PRD line 211)

Keycloak's access/refresh tokens are **not persisted** — OIDC only
establishes identity once. After login the user rides our **own
stateful, DB-backed session**:
- A random opaque token in `sessions` (with `expires_at`), set as a
  cookie that is **`Secure`, `HttpOnly`, `SameSite=Lax`**. The cookie is
  named with the project prefix (`unspoken-session`) per the naming
  convention in §16.10.
- **Current-user resolution goes through a single abstraction** (§1.2):
  one function `E<std::optional<User>> currentUser(const Request&)` reads
  the cookie, looks up the session, returns the user. The future C2S API
  will add an OAuth-bearer branch behind this same function.
- **Logout** clears the local session only (no RP-initiated logout to
  Keycloak).

Out of scope: centralized revocation / propagating Keycloak user deletion
(no Admin-API reconciliation, no back-channel logout). Deleting a user in
Keycloak just blocks future logins; existing local sessions persist until
expiry.

---

## 16. The app module: routes, handlers, templates

Handlers are **thin** (§1.2): parse request → resolve user → check CSRF →
call service/federation/data → render template or JSON. **No business
logic in handler bodies.**

### 16.1 Route table

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Timeline (logged-out: global public; logged-in: home) |
| GET | `/u/<username>` | Profile HTML *or* Actor JSON (content negotiation) |
| GET | `/u/<username>/outbox` | `OrderedCollection`/`...Page` |
| GET | `/u/<username>/followers` | paginated collection |
| GET | `/u/<username>/following` | paginated collection |
| POST | `/u/<username>/inbox` | AP inbox (signature-verified) |
| POST | `/inbox` | sharedInbox |
| GET | `/p/<id>` | Post HTML (in-thread) *or* Object JSON (content negotiation) |
| GET | `/actor` | System actor JSON |
| GET | `/.well-known/webfinger` | WebFinger |
| GET | `/.well-known/nodeinfo` | NodeInfo discovery |
| GET | `/login`, `/callback`, `POST /logout` | OIDC flow |
| GET/POST | `/setup-username` | First-login username setup |
| GET/POST | `/profile` | Edit display name + bio |
| POST | `/post` | Create a post |
| POST | `/post/<id>/delete` | Delete own post |
| POST | `/post/<id>/reply` | Reply |
| POST | `/post/<id>/boost`, `/like`, `/react`, `/bookmark` | Interactions |
| POST | `/follow`, `/unfollow` | Follow/unfollow (local or remote) |
| GET | `/search` | Search users (local + remote via WebFinger) |
| GET | `/static/*`, `/media/<a>/<hash>.<ext>` | Static assets / attachments |
| GET | `/emoji/<filename>` | Server-wide custom emoji image (§13.4) |

### 16.2 Content negotiation

For `/u/<username>` and `/p/<id>`, inspect the `Accept` header: if it
prefers `application/activity+json` (or `application/ld+json`), return the
AP JSON; otherwise return HTML. This is how the same URL serves browsers
and servers (PRD line 194).

### 16.3 Pagination (decision C4)

**Cursor-based, keyed on `id`**, never `LIMIT/OFFSET` (offset
double-serves/skips items as the collection mutates). The page size is
`posts_per_page`.

- **HTML timeline:** `?max_id=<id>` returns the next-older page (items
  with `id < max_id`); `?min_id=<id>` the newer direction. Render
  next/prev links carrying the cursor.
- **AP `OrderedCollectionPage`:** `next`/`prev` links carry the same
  cursor. The collection root (`outbox`, `followers`, `following`)
  returns an `OrderedCollection` with `first`/`last` page links;
  each page is an `OrderedCollectionPage`.
- Where ordering isn't id-monotonic, key on `(created_at, id)`.

This `max_id`/`min_id` design deliberately matches the Mastodon API so
the future C2S API needs no rework.

### 16.4 CSRF protection (PRD line 230)

**Every state-changing form** (login initiation, post, follow, like,
boost, react, bookmark, delete, profile edit, username setup) carries a
CSRF token. Generate a per-session token, embed it as a hidden field in
every form, and verify it on POST. Reject mismatches. (The OIDC `state`
parameter is the CSRF defense specifically for the login redirect, §15.)

### 16.5 First-login username setup

Reached when a freshly authenticated `sub` has no `users` row (§15.3).
Validate: allowed charset, length, **not a reserved name** (e.g.
`inbox`, `actor`, `__system__`, `.well-known`), **unique**. On success,
generate the keypair, create the user, redirect home. The username is
**immutable** thereafter.

### 16.6 Private-post authorization (decision B2)

Followers-Only and Direct posts at `/p/<id>` must only be served to
authorized requesters:
- **AP JSON fetch:** the requester is the **HTTP-signature actor** (so an
  unsigned/anonymous request **cannot** be authorized → treat as `404`).
- **HTML page:** the requester is the **logged-in session user**.
- Authorization = the requester is the author, a follower (for
  Followers-Only), or an addressee (for Direct), checked against
  `post_recipients`/`follows`.
- **Unauthorized → return `404`, never `403`** (decision B2/B3), so the
  existence of a private post is not revealed.

### 16.7 Content warnings & sensitive media (decision E1)

- **Authoring:** the post form lets a user set a content warning (→
  `summary`) and mark the post/media `sensitive`.
- **Display (local + remote):** CW'd content is **collapsed behind the
  warning**; sensitive media is **hidden/blurred until revealed**. Remote
  posts' `summary`/`sensitive` are stored and rendered identically — never
  dump CW'd content raw.

### 16.8 Templates (PRD line 167)

Server-side rendering with [Inja](https://github.com/pantor/inja).
Templates live in `templates/` (e.g. `base.html`, `index.html`,
`profile.html`, `search.html`, `setup_username.html`, plus post/thread
partials). Static assets (CSS, JS) in `static/`, served by the same C++
server (PRD line 168). **No Bootstrap** (global style rule); hand-written
CSS in `static/style.css`.

**Design aesthetic.** The look-and-feel is intentionally **compact,
technical, and functional** — information-dense, with minimal chrome and
tight spacing. It is explicitly **not** a "modern", whitespace-heavy
layout: prefer small margins/padding, dense lists, and plain functional
controls over large hero areas and generous negative space.

**Readability and clarity come first, though.** Compact is the means, not
the goal: the density must never compromise legibility or make the
interface hard to parse. Maintain clear visual hierarchy, adequate line
spacing and contrast for comfortable reading, and unambiguous grouping
and labeling of controls. The target is *dense but clear* — like a
well-designed technical/reference interface — not cramped or cluttered.

The detailed page/component layout is **left loosely defined for now**
(to be fleshed out in a later UI pass); these principles are the binding
constraint on it.

### 16.9 Search (PRD lines 30, 224)

Search both local and remote users. A query that looks like a handle
(`@user@domain` or `user@domain`) triggers a **WebFinger lookup** →
actor resolution → display/follow. Local username/display-name matches
come from the DB. (Full-text post search is future work, §20.)

### 16.10 Client-side storage naming

**Every cookie and every `localStorage`/`sessionStorage` key set by the
frontend is prefixed with `unspoken-`.** This namespaces our state so it
cannot collide with another app sharing the origin — relevant because the
service may be hosted under a path on a shared host (e.g.
`https://mws.rocks/fedi/`, §6.1), where cookies set at the host apex are
visible to sibling apps. Examples: `unspoken-session` (the session
cookie, §15.4), `unspoken-csrf` if a token is ever mirrored client-side
(the canonical CSRF token is the per-session value in §16.4). Pick a
single constant for the prefix and reference it everywhere rather than
hard-coding the literal string at each call site.

PRD lines 151–166.

### 17.1 Upload and storage (content-addressed)

On upload:
1. **Enforce `max_upload_bytes`** — reject larger uploads.
2. Compute the file's **SHA-256**, lowercase hex.
3. Rename to `<hash>.<original-ext>` (e.g. `test.jpg`, hash `a1b2c3…` →
   `a1b2c3….jpg`).
4. Store under a **one-character shard dir** = first hash char:
   `<attachment_dir>/a/a1b2c3….jpg`.
5. **Deduplicate:** if that path already exists, reuse it (identical
   bytes → identical hash → same file).

### 17.2 Serving (decision B4)

- **Images, including SVG:** displayed inline via `<img>` (scripts don't
  execute in an `<img>` context).
- **Non-image types (e.g. HTML):** served **download-only** with
  `Content-Disposition: attachment` **and** `X-Content-Type-Options:
  nosniff`, so they never render inline.
- **Accepted risk:** navigating directly to a `.svg` URL renders it as a
  document and any embedded script runs in our origin (stored XSS). We
  accept this — **no SVG sanitization, no separate media origin** in v1.
- No decompression-bomb / image-dimension limits in v1 (out of scope).

### 17.3 Remote attachments

Remote attachments are **never stored** on our server. We keep only the
remote URL (`attachments.remote_url`); the frontend downloads/displays
them directly. **No media cache or proxy** (PRD lines 164–166).

---

## 18. Error handling conventions

Per PRD line 89, **prefer `mw::E<>` over exceptions**. Conventions:

- Functions that can fail return `E<T>` (`= std::expected<T, mw::Error>`
  in libmw). Propagate with early returns; do not throw across module
  boundaries.
- Map errors to HTTP status at the **handler boundary only**: validation
  → `400`; auth/signature failure → `401`; private/not-found → `404`;
  rate/parse issues as appropriate; unexpected internal → `500` with a
  generic body (never leak internals).
- Inbox endpoints return `202 Accepted` once an activity is accepted for
  (possibly async) processing; `200` for idempotent duplicates and for
  silently-ignored Delete/Undo of unknown objects; `401` for signature
  failures.
- Background jobs convert errors into retry/backoff (§14.4), not crashes.

---

## 19. Testing strategy

**All unit tests compile into the single `unspoken_test` executable** (PRD
line 256). Coverage targets, mirroring the modules:

- **JSON-LD normalization (§9):** addressing string-vs-array; ref
  string-vs-embedded-object; all three public-marker forms on input; full
  IRI on output. Table-driven tests.
- **HTTP signatures (§10):** verify a known-good `rsa-sha256` request;
  reject missing `digest` in signed headers on POST; reject bad digest;
  reject out-of-skew `Date`; key-rotation re-fetch path (mock the
  fetcher); accept `hs2019`-labeled legacy requests.
- **SSRF guard (§11):** reject `http`; reject hostnames resolving to
  loopback/private/link-local/ULA/metadata; reject IPv4-mapped IPv6
  bypass; redirect re-validation.
- **Visibility/addressing (§12.5):** each visibility produces the correct
  `to`/`cc`; incoming detection classifies correctly.
- **Data module (§7):** CRUD round-trips against an in-memory SQLite;
  cursor pagination stability under insertion/deletion; busy-timeout
  retry under simulated contention. Use a **database mock/interface**
  (à la `database_mock.hpp`) so higher layers are testable without real
  SQL.
- **Inbox dispatch (§12.6):** dedup returns 200; Delete/Undo of unknown →
  200; `Announce` of non-public ignored; `Follow` auto-accept enqueues an
  `Accept`.
- **Inbox forwarding (§12.7):** forwards only when all three conditions
  hold; re-fetches object to verify.
- **Job queue (§14):** claim-once under concurrency; backoff schedule;
  give-up at `job_max_retries`.
- **OIDC (§15):** state mismatch rejected; ID-token validation (iss/aud/
  exp/nonce/signature) — mock JWKS.
- **WebFinger (§12.4):** resolves on both domains; canonical subject;
  self link to URL-root actor id.

Prefer dependency injection (pass interfaces for the DB and the HTTP
fetcher) so each layer is unit-testable in isolation; add a few
end-to-end integration tests for the signature + inbox happy path (cf.
`signature_integration_test.cpp` in the prior tree).

---

## 20. Future work (explicitly out of scope for v1)

From PRD lines 258–277. v1 must not *preclude* these but must not
*implement* them:

- **C2S client API** (Pleroma-flavored Mastodon API) for mobile clients —
  reuses the v1 service layer, adds OAuth token issuance with Keycloak as
  the login backend. (§1.2 keeps the door open.)
- **Moderation and server-blocking.**
- **Full-text post search.**
- **Notifications.**
- **Schema migrations** — version stays `1` until first stable release.
- **RFC 9421 + full multi-standard/algorithm signature fallback**
  (cavage-12 *and* RFC 9421; RSA *and* ED25519). v1 signs `rsa-sha256`
  cavage and verifies `rsa-sha256`/`hs2019`.

---

*End of design document.*
