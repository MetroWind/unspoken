# Implementation Plan: Unspoken

Phased build plan for the `unspoken` ActivityPub server. Companion to the
design doc [`designs/design-0-architecture.md`](designs/design-0-architecture.md)
and the requirements in [`prd.md`](prd.md) / [`prd_gaps.md`](prd_gaps.md).

## Principles

- **Build bottom-up, respecting the layering** (struct → data →
  federation/service → app). Each phase ends at something runnable and
  testable; never build a top layer against an untested bottom layer.
- **Security-critical pieces get their own tests and a review pass
  before dependent logic is layered on** — signatures, SSRF, private
  authz, OIDC token validation.
- **Federation is validated incrementally against a real peer** (a local
  Mastodon/Pleroma test instance), not all at once at the end.
- **All tests go in the single `unspoken_test` executable.**
- If a phase needs a libmw/MacroDown capability we don't have, stop and
  write a feature-request doc in the project root (per the design doc
  §4.2.1 workflow); don't work around it in the app.

## Phase overview

| Phase | Scope | Exit criteria |
|-------|-------|---------------|
| 0 | Skeleton | Builds; loads config; serves a health route. |
| 1 | Data + structs | CRUD round-trips pass on in-memory SQLite. |
| 2 | Auth + sessions | Log in via Keycloak, create user, hold session. |
| 3 | Local-only app | Post/reply/like/bookmark/browse, all local. |
| 4 | Federation read | Remote can fetch our actors/posts; we resolve+show a remote actor. |
| 5 | Federation write | Follow/post/like federates both directions vs. a real peer. |
| 6 | Advanced federation | Forwarding, thread backfill, mentions, reactions, emoji, search. |
| 7 | Hardening | Security review clean; interop verified against multiple peers. |

Phases 4–5 hold most of the risk and iteration.

---

## Phase 0 — Skeleton

**Goal:** a buildable project that loads config and answers one route.

- [x] `CMakeLists.txt` modeled on shrt: C++23, FetchContent for
      libmw/nlohmann-json/Inja/ryml/MacroDown. (OpenSSL/SQLite3 come in
      transitively via `mw::crypto`/`mw::sqlite`, which find_package them
      internally, so no explicit find_package is needed here.)
- [x] `unspoken` and `unspoken_test` targets; wire in the test framework
      (GoogleTest via FetchContent, `gtest_discover_tests`).
- [x] `commit.hpp.in` → `commit.hpp` (git hash).
- [x] Config struct + ryml loader (§5), full schema, validation, defaults,
      `public_domain` fallback to `url_root` host.
- [x] libmw HTTP server boot; bind to `listen_address`/`listen_port`.
- [x] A trivial health/static route to prove the server answers.
- [x] Logging.

**Exit:** `cmake --build` succeeds; server starts; config errors are
fatal with a clear message; a GET returns 200.

---

## Phase 1 — Data + structs

**Goal:** the persistence layer, fully tested in isolation.

- [x] struct module: `User`, `RemoteActor`, `Post`, `Attachment`,
      `Follow`, `Like`, `Boost`, `Reaction`, `Cursor`, `Activity`,
      `Visibility`, the `AS_PUBLIC` constant. (`src/structs.hpp`)
- [x] DB init: open, `PRAGMA journal_mode=WAL`, `busy_timeout`,
      `user_version` dispatch (create schema at v1). (busy_timeout is set
      via `PRAGMA` since the fetched libmw's `connectFile` takes no
      timeout arg.)
- [x] All tables + indices from design §7.3.
- [x] Connection-per-thread strategy + `withWriteRetry` wrapper. (Each
      thread constructs its own `DataSourceSQLite` over the same file;
      `withWriteRetry` retries transient busy/locked errors.)
- [x] Data-module functions (design §7.4) with `E<>` returns.
- [x] DB interface + mock (`data_mock.hpp`) so upper layers are
      testable without real SQL.

**Tests:** CRUD round-trips on in-memory SQLite; **cursor pagination
stable under insertion/deletion**; write-retry under simulated
contention.

**Exit:** data tests green.

---

## Phase 2 — Auth + sessions

**Goal:** real login, the single current-user abstraction, CSRF.

- [x] OIDC discovery from `<issuer>/.well-known/openid-configuration`.
      (Implemented in-app in `src/auth.cpp`, **not** via
      `mw::AuthOpenIDConnect`: that helper exposes neither the ID token
      nor JWKS validation, so it cannot satisfy the design's §15.3
      requirement. See the note below.)
- [x] `/login`: generate `state`+`nonce`, persist (`pending_logins`),
      redirect to authorization endpoint.
- [x] `/callback`: validate `state`; exchange code; **validate ID token**
      (JWKS signature, `iss`, `aud`, `exp`, `nonce`). Full RS256 + JWKS
      verification done in-app (`validateIdToken`); JWK→PEM via OpenSSL 3.
- [x] Identity keyed on `(iss, sub)`; lookup-or-route-to-setup.
- [x] `/setup-username`: validate (charset/length/reserved/unique),
      generate RSA keypair, create user, immutable username. (Pre-auth
      identity is carried across the redirect in an AES-256-GCM-sealed
      `unspoken-setup` cookie — no schema change needed.)
- [x] Sessions table; `Secure`/`HttpOnly`/`SameSite=Lax` cookie.
- [x] `currentUser(Request)` single abstraction (design §15.4) — the seam
      the future C2S API extends.
- [x] CSRF: per-session token, hidden form field, verify on POST.
      (Token is a server-key-keyed digest of the session token; a separate
      family guards the pre-session `/setup-username` POST.)
- [x] `/logout` clears local session.

**Tests:** state mismatch rejected; ID-token validation (signature/iss/
aud/exp/nonce, all from a generated keypair); session lifecycle; CSRF
accept/reject; base64url round-trip; JWK↔PEM. All in `auth_test.cpp`.

**Exit:** can log into Keycloak, create an account, ride a session.
✅ Builds green; 50 tests pass; server boots and serves `/`, `/login`,
`/callback`, `/setup-username`, `/logout`.

> Review checkpoint: OIDC token validation.

> **Decision (Phase 2):** the OIDC flow is implemented directly in
> `src/auth.cpp` rather than through `mw::AuthOpenIDConnect`. The libmw
> helper does discovery + code exchange + userinfo but does not expose the
> `id_token`, omits `state`/`nonce` from the auth URL, and has no
> JWKS/ID-token validation — so it cannot meet design §15.3. Implementing
> in-app lets us validate the ID token fully (signature via JWKS, `iss`,
> `aud`, `exp`, `nonce`).
>
> **libmw `base64Decode` bug (fixed):** it rejected empty input and
> dropped the final byte(s) on the unpadded 3-char tail. Reported via a
> feature-request doc, fixed in libmw, and the temporary in-app codec was
> removed — `auth.cpp`'s `base64Url*` now delegate to `mw::base64*`.

---

## Phase 3 — Local-only app (no federation yet)

**Goal:** a usable single-user-server experience, entirely local.

- [ ] MacroDown integration: render markdown → HTML; store source + HTML.
- [ ] Inja templates + `static/style.css` (no Bootstrap): `base`,
      `index`, `profile`, `search`, `setup_username`, post/thread partials.
      Follow the UI aesthetic in §16.8: compact/technical/functional, but
      readability and clarity first (dense but clear, not cramped).
- [ ] `POST /post`: visibility, CW (`summary`), `sensitive`; persist post
      + `post_recipients` addressing.
- [ ] Timelines (design §16.2–16.3): logged-out global public, logged-in
      home; cursor pagination (`max_id`/`min_id`).
- [ ] Reply, like, boost, bookmark, react — **local-only** semantics.
- [ ] Custom emoji seed scan at startup (§13.4): scan `emoji_dir`,
      shortcode = filename stem, build the in-memory registry (no DB
      table), serve at `/emoji/<file>`. Local authoring picker +
      `:shortcode:` → `<img>` substitution into stored HTML.
- [ ] `/profile` edit (display name + bio).
- [ ] Attachments (design §17): size limit, SHA-256 content-addressed
      storage with shard dir, dedup; image-inline vs download-only
      (`Content-Disposition: attachment` + `nosniff`).
- [ ] Thread view (local posts only for now).
- [ ] Post deletion (local).

**Tests:** posting/visibility addressing table (§12.5); pagination;
attachment hashing/dedup/serving rules.

**Exit:** a logged-in user posts, replies, likes, bookmarks, edits
profile, uploads files — all browsable. No network egress yet.

---

## Phase 4 — Federation read

**Goal:** remote servers can read us; we can read them. Inbound trust.

- [ ] JSON-LD normalization layer (§9): addressing string/array, ref
      string/object, all three public-marker input forms.
- [ ] SSRF-safe outbound fetch (§11): https-only, resolved-IP blocklist,
      IPv4-mapped normalization, rebinding-proof connect, redirect cap +
      re-validate.
- [ ] HTTP signature **verification** (§10.1): rsa-sha256 + hs2019,
      clock-skew, digest-bound-to-signature on POST, no silent bypass.
- [ ] System actor (§12.2): keypair, served JSON, signs keyless GETs.
- [ ] Remote actor resolution (§12.3): system-signed GET, cache.
- [ ] Serve Actor JSON (computed) and Object JSON via content negotiation
      (§12.1, §16.2).
- [ ] WebFinger on both domains + canonical subject; NodeInfo (§12.4).
- [ ] Private-post authz (§16.6): signature-actor (AP) / session (HTML);
      **404 not 403**; unsigned private fetch → 404.

**Tests:** signature verify suite (good/bad digest/skew/missing-digest/
hs2019); SSRF guard suite; WebFinger both-domains/canonical-subject;
private-fetch 404 matrix.

**Exit:** a real peer can fetch our actor + a public post; we can resolve
and display a remote actor's profile.

> Review checkpoint: signature verify, SSRF, private authz.

---

## Phase 5 — Federation write

**Goal:** activities flow both directions, reliably.

- [ ] HTTP signature **signing** (§10.2): rsa-sha256 cavage; digest on
      POST; user key vs system key.
- [ ] Job queue + workers (§14): claim-once transaction, backoff/retry,
      give-up at `job_max_retries`.
- [ ] Outbound delivery (§12.8): recipient expansion, **sharedInbox
      preferred**, one job per inbox.
- [ ] Inbox dispatch (§12.6): `Create`, `Follow` (auto-accept + send
      `Accept`), `Accept`, `Like`, `Announce` (ignore non-public),
      `EmojiReact`, `Delete`/`Update`/`Undo` (silent 200 for unknown).
- [ ] Dedup by activity `id` (`seen_activities`); 200 on redelivery.
- [ ] Key-rotation retry (§10.1 step 7): re-fetch once, update, retry.
- [ ] Federate local `Delete`/`Update` outbound.
- [ ] Outbox/followers/following as paginated `OrderedCollectionPage`.

**Tests:** sign round-trips; job claim-once under concurrency; backoff
schedule; inbox dispatch matrix; dedup; Announce-of-private ignored.

**Exit:** follow, post, and like federate both ways against a live test
instance.

---

## Phase 6 — Advanced federation

**Goal:** the interop niceties that make threads and mentions feel right.

- [ ] Mentions/hashtags via MacroDown custom markup → syntax-tree
      iteration → `tag` array + addressing wiring (§13.2, decision D2).
- [ ] Recursive thread fetch (§12.9), bounded by `thread_fetch_max_depth`;
      save fetched posts; `fetch_thread` job.
- [ ] Inbox forwarding §8.1.2 (§12.7): three-condition gate; verify by
      re-fetching the referenced object from origin.
- [ ] Emoji reactions end-to-end. Custom emoji **federation**: emit
      `Emoji` tags on outgoing posts; parse incoming `Emoji` tags and
      substitute remote `:shortcode:` from the per-post tag mapping at
      ingest (§13.4). (Local seed/authoring landed in Phase 3.)
- [ ] Remote user search via WebFinger (§16.9).
- [ ] CW/sensitive rendering for remote posts (collapsed/blurred).
- [ ] HTML sanitization of remote content (§13.3).

**Tests:** mentions→addressing; forwarding three-condition gate +
re-fetch verification; thread backfill depth cap; sanitizer allowlist.

**Exit:** threads backfill, mentions deliver, forwarding works,
reactions/emoji/search functional.

---

## Phase 7 — Hardening

**Goal:** production-ready, interop-verified.

- [ ] Security review: signatures, SSRF, private authz, OIDC, CSRF,
      upload handling, session cookie flags.
- [ ] Interop testing against **multiple** peer implementations
      (Mastodon, Pleroma/Akkoma, Misskey); fix quirks.
- [ ] Edge cases: malformed activities, partial actor docs, redelivery
      storms, peer downtime/backoff behavior.
- [ ] Operator docs: the reverse-proxy caveat for `/.well-known/*` from
      the public domain (design §12.4), config reference, deployment
      (the `packages/arch/unspoken.*` units).
- [ ] Error-status mapping audit (§18); no internal leakage on 500.

**Exit:** clean review; verified against several peers; documented.

---

## Cross-cutting, every phase

- Keep handlers thin; business logic in service/federation/data layers
  (the C2S-readiness constraint, design §1.2).
- Prefer `mw::E<>` over exceptions; map to HTTP status only at the
  handler boundary.
- Add tests to `unspoken_test` as each unit lands — don't defer testing
  to Phase 7.
- File a feature-request doc (project root) the moment a libmw/MacroDown
  gap appears; don't work around it.
