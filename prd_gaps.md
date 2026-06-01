# PRD Gaps & Open Issues

Tracking doc for gaps found reviewing `prd.md`. We'll work through these one
by one. Ordered roughly by severity.

Status legend: `[ ]` open · `[~]` in progress · `[x]` resolved

---

## A. Federation-breaking

### A1. `hs2019` as the signing algorithm is a trap — RESOLVED
- [x] PRD says "use hs2019 to sign" and "assume incoming requests are signed
      with this standard." In practice almost the entire live Fediverse
      (Mastodon, Pleroma, Akkoma, Misskey) signs draft-cavage with
      **`rsa-sha256`**, not `hs2019`. An hs2019-only implementation will fail
      to talk to nearly everyone. hs2019 is itself a dead/abandoned draft (its
      `(created)`/`(expires)` pseudo-headers were never interoperably deployed,
      RSA digest left underspecified, sender-driven algorithm-agility is a
      downgrade footgun). The genuine successor is RFC 9421.
- **Decision (separate signing from verifying):**
  - **Incoming verification:** accept *both* `rsa-sha256` and `hs2019` labels
    (treat hs2019-with-legacy-headers as rsa-sha256). We verify whatever
    arrives — there is no preference here, just a parser that handles both.
    rsa-sha256 working is non-negotiable. Includes digest verification (A2)
    and clock-skew checks (A3).
  - **Outgoing signing:** sign `rsa-sha256` cavage over
    `(request-target)`, `host`, `date`, and `digest` (for POSTs) — the
    construction every peer verifies — for maximum deliverability. No
    per-peer "try hs2019, fall back to rsa" machinery.
  - **RFC 9421** stays in Future Works (see prd.md). It is the real
    "advance the standard" play and can be added later without ever blocking
    deliverability. We do **not** promote it to near-term.

### A2. Digest header verification on incoming POSTs — AGREED
- [x] Recompute SHA-256 of the request body and compare against the `Digest`
      header before accepting an inbox POST.
- **Decision:** Required. Two points the spec must call out explicitly so the
  check actually has teeth:
  1. **Bind the digest to the signature.** Require `digest` to appear in the
     signature's signed `headers` list for POST/PUT. Otherwise a MITM can swap
     the body and recompute the `Digest` header while replaying a valid
     signature over `(request-target) host date` — body forgery would pass.
  2. **No silent bypass on unrecognized Digest format.** Parse the algorithm
     token case-insensitively, handle comma-separated values (RFC 3230), select
     the SHA-256 entry, and reject (401) when no usable SHA-256 digest is
     present. Never skip the check just because the format wasn't the exact
     literal `SHA-256=`.

### A3. Clock-skew tolerance on the `Date` header — AGREED
- [x] Reject signatures whose `Date` is outside a tolerance window.
- **Decision:** Allow **±5 minutes** of skew. Make the window a config
  parameter, defaulting to 300 seconds.

### A4. Re-fetch remote key on verification failure — AGREED
- [x] Stored remote public keys go stale when the peer rotates keys. PRD says
      "retrieve first and store" but never says "invalidate and re-fetch."
      Without this, a key rotation permanently breaks that peer.
- **Decision:** On signature verification failure with a cached key, re-fetch
  the actor's key **once** and retry verification. If it still fails, reject.
  Update the stored key on a successful re-fetch.

---

## B. Security

### B1. SSRF protection on all outbound fetches — AGREED
- [x] Actor resolution, recursive thread fetch, and webfinger all take
      remote-controlled URLs. Without filtering, a hostile server can make us
      fetch `http://169.254.169.254/…`, `http://localhost:…`, etc.
- **Decision:** Do all of the following:
  - **https-only** scheme allowlist for outbound requests and redirects.
  - **Validate the resolved destination IP, not the hostname.** A hostname can
    resolve to an internal address, so blocklisting must apply to the actual
    resolved IP(s): reject private, loopback, link-local, ULA, and
    cloud-metadata ranges (e.g. `127.0.0.0/8`, `::1`, `10/8`, `172.16/12`,
    `192.168/16`, `169.254/16`, `fd00::/8`, `169.254.169.254`). Normalize
    IPv4-mapped IPv6 (`::ffff:127.0.0.1`) before checking so it can't bypass
    the IPv4 blocklist.
  - **Rebinding-proof connection.** Validate the exact address the connection
    will use at connect time (no separate resolve-then-connect TOCTOU window).
  - **Cap redirects** and re-validate the destination on every redirect hop.

### B2. Authorization on private object fetch — AGREED
- [x] A Followers-Only or Direct post served at `/p/<id>` must check that the
      requester is a follower / addressee — for both AP JSON and HTML
      representations. PRD defines visibility addressing but never says who is
      allowed to *read* `/p/<id>`. Mostly obvious; three points to pin down:
  1. **Identity source differs by representation.** AP JSON fetch → the
     requester is the HTTP-signature actor. HTML page → the logged-in session.
     Both paths must enforce authorization.
  2. **Return 404, not 403, for unauthorized** requests, so we don't leak the
     existence of private posts (especially given enumerable IDs, B3).
  3. **Private fetch requires a signed GET.** An unsigned/anonymous AP request
     to a Followers-Only or Direct post cannot be authorized → treat as 404.
     (Read-side of the authorized-fetch flow, C1.)

### B3. Sequential integer IDs in post URLs — RESOLVED (keep sequential)
- [x] `AUTOINCREMENT` PKs exposed as `/p/<id>` let anyone enumerate every post
      and infer posting volume.
- **Decision:** Keep sequential integer IDs in URLs (as the PRD already
  specifies). Accepted trade-off: post existence and volume are enumerable for
  *public* posts, which is fine. Private-post safety relies on B2 returning
  **404 (not 403)** for unauthorized fetches, so enumeration cannot distinguish
  a private post from a nonexistent one. B2 must hold for this to be safe.

### B4. Uploaded SVG/HTML handling — RESOLVED (minimal, accept SVG risk)
- [x] Serving user uploads from our origin can be a stored-XSS vector.
- **Decision:** Same origin, minimal handling:
  - **Images (incl. SVG):** displayed inline like a regular image (via `<img>`,
    where scripts don't execute).
  - **Non-image types (e.g. HTML):** treated as opaque blobs, **download only**
    — served with `Content-Disposition: attachment` (+ `X-Content-Type-Options:
    nosniff`) so they never render inline.
  - **Accepted risk:** SVGs remain reachable at their own media URL; navigating
    directly to a `.svg` renders it as a document and any embedded script runs
    in our origin (stored XSS). We accept this — no SVG sanitization, no
    separate media origin.
  - **Upload size limit:** enforce a global maximum upload size, configurable
    in the config file. Reject uploads exceeding it.
- **Note:** No decompression-bomb / image-dimension limits specified; out of
  scope for this decision.

---

## C. Correctness / interop

### C1. Authorized-fetch bootstrapping — AGREED
- [x] To verify a remote actor we fetch their key — but if they run secure
      mode, that GET must itself be signed by our system actor.
- **Decision:** Make the flow explicit: when resolving a remote actor (to get
  its public key / endpoints), issue a **GET signed by the system actor** so it
  works against peers that require signed fetches (secure mode). Cache the
  fetched actor and key in the DB. This is the read-side counterpart to B2's
  signed-GET requirement.

### C2. Idempotency / dedup of incoming activities — AGREED
- [x] Activities get delivered multiple times, and Deletes are broadcast for
      objects we've never seen.
- **Decision:**
  - **Dedupe by activity `id`.** Track processed activity IDs; a redelivered
    activity is acknowledged (200) without being processed again.
  - **Silently ignore Delete/Undo for unknown objects** — return 200 OK rather
    than erroring when we have no record of the target.

### C3. WebFinger host, URL subpath, and public vs. internal domain — AGREED
- [x] With a root like `https://mws.rocks/fedi/`, WebFinger still lives at the
      apex `https://mws.rocks/.well-known/webfinger`, and the `acct:` domain is
      `mws.rocks`, not `mws.rocks/fedi` (a handle can't contain a path).
      Additionally, we support hosting the service on a different domain from
      the one in the user handle (the Mastodon `WEB_DOMAIN` / `LOCAL_DOMAIN`
      split), so an operator can run on a long internal domain but expose clean
      handles.
- **Decision:**
  - **Two domain concepts:**
    - **Internal domain (`url_root`):** where the service actually runs. The
      actor `id` and *all* ActivityPub endpoints live here
      (`<url_root>/u/<user>`, `…/inbox`, `…/outbox`, …). Remote servers do see
      this domain in the actor id.
    - **Public domain:** appears only in the **handle** —
      `@user@public_domain` / `acct:user@public_domain`. This is what "the
      domain in the user ID" refers to (the @handle, not the actor id URI).
      Configurable; when unset it defaults to the host of `url_root`.
  - **Handles never contain a path.** The handle host is a bare domain
    (`public_domain`), independent of any path in `url_root`.
  - **WebFinger must resolve on BOTH domains and always return the canonical
    subject** `acct:user@public_domain`, with a `self` link
    (`application/activity+json`) pointing to the actor id on `url_root`:
    - Public domain: discovery path; operator's reverse proxy fronts
      `/.well-known/*` and forwards to the service.
    - Internal domain (the actor-id host): required for *reverse* discovery —
      when a remote server sees the actor id first, its default is to derive
      `@user@<internal_host>` (wrong, and a duplicate/spoofable identity).
      Answering WebFinger on the internal host with the same public subject
      forces `@user@public_domain` as canonical. (Mastodon enforces this; not
      doing it causes split identities.)
  - **`/.well-known/nodeinfo`** is fronted the same way as WebFinger.
  - **Actor URLs / aliases keep the full `url_root`** (including any path):
    e.g. `https://internal/fedi/u/alice`. Only the *lookup location* and the
    *acct host* are pathless/public — do not strip the path from actor URLs.
  - **Profile page display:** our own HTML UI must display each user's handle
    using the **public domain** (`@user@public_domain`), never the internal
    host. (This is a correctness bug Pleroma has gotten wrong.)
- **Operator/deployment caveat:** the operator must reverse-proxy specifically
  `/.well-known/webfinger` and `/.well-known/nodeinfo` from the public domain
  apex to the service, without disturbing the rest of that apex (e.g. another
  app there, or its `/.well-known/acme-challenge`). Documented requirement with
  a proxy-ordering gotcha.

### C4. Pagination cursors instead of offset — AGREED
- [x] "N per page" implies offset pagination, which double-serves/skips items
      as the collection mutates.
- **Decision:** Use **stable cursor-based pagination** keyed on `id` (or
  `(created_at, id)` where ordering isn't id-monotonic), not `LIMIT/OFFSET`.
  Applies to both the HTML timeline and the ActivityPub `OrderedCollectionPage`
  endpoints (outbox, followers, following, …); `next`/`prev` links carry the
  cursor.

### C5. SQLite single-writer contention — AGREED
- [x] WAL helps reads, but background workers + web handlers collide on writes.
- **Decision:**
  - WAL on (already specified), with a configurable `busy_timeout` (default
    ~5s) and bounded retry-with-backoff on `SQLITE_BUSY`/`SQLITE_LOCKED` so
    contended writes wait/retry rather than failing spuriously.
  - **Connection-per-thread:** background workers and web handlers each use
    their own connection, so WAL gives concurrent readers + a single writer,
    with the busy_timeout/retry absorbing contention.

---

## D. Underspecified

### D1. OIDC auth-code flow — AGREED
- [x] "Use an already-setup OIDC server" (operator's Keycloak) needs the flow
      spelled out.
- **Decision — Authorization Code flow:**
  - **Config:** `issuer` URL, `client_id`, `client_secret` (and optional
    `scopes`, default `openid profile`). Discover endpoints via
    `<issuer>/.well-known/openid-configuration` rather than hardcoding them.
  - **Login:** generate random `state` + `nonce`, stash browser-side
    (short-lived secure cookie or transient pending-login row), redirect to the
    Keycloak authorization endpoint.
  - **Callback** (on the internal domain, `<url_root>/…/callback`, registered
    in Keycloak): validate `state` (CSRF), exchange `code` for tokens using
    `client_secret`, and **validate the ID token** (signature via JWKS, `iss`,
    `aud == client_id`, `exp`, `nonce`).
  - **Identity:** key the local account on the **`sub`** claim (stable), not
    email/username; store `iss`+`sub` on the user record.
  - **First login (new `sub`):** user is authenticated but has no fedi account
    → redirect to username setup. Username is validated, unique, reserved-names
    checked, and **immutable** once set (it's in the actor URI/handle). Pre-fill
    suggestions from `preferred_username`/`name` claims is a nice-to-have. On
    submit, create the `User` row keyed to the `sub`, then create the session.
  - **Sessions managed locally:** OIDC is used only to establish identity once;
    Keycloak's access/refresh tokens are **not persisted**. After login the
    user rides our own stateful DB-backed session (per PRD), set as a secure,
    httpOnly, SameSite cookie. Decouples us from Keycloak availability;
    revocation is a local DB delete.
  - **Logout:** local session only (no RP-initiated logout).
- **Out of scope for now:** centralized revocation / propagating Keycloak user
  deletion to the fedi server (no Admin-API reconciliation, no back-channel
  logout). Deleting a user in Keycloak just prevents future logins; existing
  local sessions persist until expiry.

### D2. Mentions → addressing wiring — AGREED
- [x] Mentions extracted from the MacroDown syntax tree must feed **two**
      places from the same data:
  1. The **`tag` array** — one `Mention` object per mentioned actor
     (`{type: "Mention", href: <actor URI>, name: "@user@domain"}`).
  2. **Recipient addressing** — mentioned actors are added to the delivery
     audience: `to` for **Direct** visibility, and added to `to`/`cc` for other
     visibilities so the mentioned actors actually receive the post.

### D3. `as:Public` constant — AGREED
- [x] "Public_Collection" in the visibility table is the ActivityPub magic
      "everyone" sentinel URI `https://www.w3.org/ns/activitystreams#Public`
      (a.k.a. `as:Public`) — not a real, dereferenceable collection. Its
      presence in addressing is *the* mechanism for public visibility:
      in `to` → public (global timeline); in `cc` only → unlisted; absent →
      private (triggers B2 authz).
- **Decision:** Define this exact string **once** as a named constant and
  reference it everywhere — both when populating `to`/`cc` on outgoing posts
  and when detecting public visibility on incoming activities. Avoids
  typo-driven silent breakage of public-visibility detection.

---

## E. Smaller / product calls

### E1. Content warnings + `sensitive` — AGREED (full support)
- [x] Mastodon uses the `summary` field as the content-warning text and a
      `sensitive` boolean (typically for media).
- **Decision:** Full support, both directions:
  - **Authoring:** local users can set a content warning (→ `summary`) and mark
    a post/media as sensitive (→ `sensitive: true`) when posting. CW'd content
    is collapsed behind the warning in our UI; sensitive media is hidden until
    revealed.
  - **Preserve + display incoming:** remote posts' `summary`/`sensitive` are
    stored and rendered the same way (collapsed behind the CW / blurred media),
    so federated CW'd content isn't dumped raw.
### E2. Boost (`Announce`) of private posts — AGREED
- [x] Boosting a Followers-Only or Direct post would leak it past its intended
      audience.
- **Decision:** Only **Public/Unlisted** posts are boostable.
  - **Outgoing:** hide/disable the boost action on Followers-Only and Direct
    posts; reject attempts to boost them.
  - **Incoming:** ignore `Announce` activities targeting non-public objects.
### E3. Inbox forwarding (AP §8.1.2) — AGREED (implement in v1)
- [x] Without inbox forwarding, "ghost reply" threads look broken to our
      followers (their servers never saw a reply because they don't follow the
      replier).
- **Decision:** Implement §8.1.2 forwarding in v1.
  - **Forward an inbound activity to a local followers collection only when all
    three hold:**
    1. First time we've seen this activity (reuse C2 dedup).
    2. `to`/`cc`/`audience` contains a collection **we** own (a local user's
       followers).
    3. `inReplyTo`/`object`/`target`/`tag` references an object **we** own —
       recurse with a max depth (reuse the PRD's configurable thread-recursion
       limit).
  - When all hold, deliver the original activity to that followers collection
    (sharedInbox-preferred).
  - **Verifying forwarded activities:** the HTTP signature on a forwarded
    activity is the *forwarder's*, not the original author's, so it can't prove
    authorship. **Verify by re-fetching the object from its origin server**
    (the C1 signed-GET flow) and trust that copy. **No LD-Signatures in v1.**
