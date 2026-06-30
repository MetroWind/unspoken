# Design Document: Docker Federation Interop Test Harness

**Status:** Draft
**Source requirements:** [`prd.md`](../prd.md), especially the
ActivityPub federation, custom emoji, interaction, thread-fetching, and
job-queue requirements.
**Related designs:** [`design-0-architecture.md`](design-0-architecture.md),
[`design-1-emoji.md`](design-1-emoji.md)
**Scope:** Add a temporary Docker-based local federation lab that can run
repeatable end-to-end tests between `unspoken` and real Fediverse peer
software, starting with Akkoma/Pleroma-compatible behavior. The harness
must test all federation surfaces that are practical to automate, not
only emoji reactions.

---

## 1. Problem Statement

Unit tests and service-layer tests prove that individual code paths work,
but they do not prove that a real Fediverse implementation can interoperate
with `unspoken` over HTTP. Federation bugs often live at boundaries that
unit tests mock away:

- Actor URLs must be resolvable by another server.
- WebFinger must return exactly the actor URL a peer expects.
- HTTP signatures must be accepted by software we do not control.
- Inbound activities must survive real queueing, retries, and duplicate
  delivery.
- Outbound activities must be addressed to the right inbox or shared
  inbox.
- Extension activities such as `EmojiReact` must match the vocabulary and
  JSON shape used by Pleroma-compatible software.

Manual testing against public instances is useful, but it is not enough
for regression coverage. Public instances can change configuration, reject
test accounts, rate-limit, defederate, or disappear. Manual tests also
make it hard to identify whether a failure came from our code, peer state,
network state, or operator error.

The goal is a local, disposable test environment that can be created,
used, and destroyed without permanently installing PostgreSQL, Redis, or
any peer server on the developer's host machine.

---

## 2. Goals

### 2.1 User Goals

- Run one command to start a complete local federation lab.
- Run one command to execute the interop test suite.
- Destroy all test data with one command.
- Avoid permanent host-level PostgreSQL or Redis installation.
- Avoid public DNS, public TLS certificates, and public tunnels for the
  default local path.
- Make failures diagnosable by preserving container logs and activity IDs.

### 2.2 Engineering Goals

- Test `unspoken` against at least one real Fediverse server.
- Start with Akkoma because it is Pleroma-compatible and supports
  `EmojiReact`, custom emoji, Mastodon-compatible APIs, and quote-related
  extension behavior.
- Keep the peer database inside Docker volumes so the environment is
  temporary.
- Use the normal `unspoken` login, session, CSRF, and form handlers
  instead of bypassing them with a parallel write API.
- Drive peer actions through public peer APIs where possible.
- Verify `unspoken` behavior through a mix of rendered HTML,
  ActivityPub JSON, and read-only database inspection.
- Keep interop tests separate from the normal unit-test suite because
  they require Docker and are slower.

### 2.3 Non-Goals

- Do not replace unit tests. The Docker harness complements them.
- Do not require public internet access for local peer-to-peer tests.
- Do not require real TLS in the default local harness.
- Do not make HTTP/private-address federation available in production.
- Do not fully automate every peer implementation in the first version.
  Misskey-family coverage is a later phase.
- Do not use browser automation as the primary test mechanism. Browser
  tests can be added later for UI smoke coverage, but federation interop
  should be driven through HTTP APIs and ActivityPub documents.

---

## 3. External References

- [ActivityPub Recommendation](https://www.w3.org/TR/activitypub/)
- [ActivityStreams Vocabulary](https://www.w3.org/TR/activitystreams-vocabulary/)
- [ActivityPub HTTP Signatures community
  report](https://swicg.github.io/activitypub-http-signature/)
- [Akkoma Docker installation guide](https://docs.akkoma.dev/stable/installation/docker_en/)
- [Akkoma configuration cheatsheet](https://docs.akkoma.dev/stable/configuration/cheatsheet/)
- [Mastodon API reference](https://docs.joinmastodon.org/methods/statuses/)
- [OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [WebFinger RFC 7033](https://www.rfc-editor.org/rfc/rfc7033)

These references matter because the harness tests real protocol behavior,
not just internal C++ functions. When a test fails, the expected behavior
should be traceable to a standard, a peer implementation's documented API,
or an explicit extension contract.

---

## 4. High-Level Approach

The harness runs `unspoken`, Akkoma, and Akkoma's PostgreSQL database in a
single Docker Compose project. Docker's internal DNS provides stable names
for each service. For example:

```text
http://unspoken.test:8080/
http://akkoma.test:4000/
```

These names do not need to exist in public DNS. They are Compose network
aliases. Inside the Docker network, the alias resolves to the correct
container IP. This solves the common local-federation problem where
`localhost` means a different process depending on which container makes
the request.

The harness has three layers:

1. **Infrastructure layer:** Compose files, config files, container
   images, volumes, and readiness checks.
2. **Control layer:** scripts that create users, create posts, follow
   accounts, react, like, boost, delete, update, and fetch state through
   fake OIDC, browser-form submissions, and peer APIs.
3. **Assertion layer:** tests that verify state on both sides through
   HTML, ActivityPub documents, peer JSON APIs, and read-only SQLite
   inspection.

This separation is intentional. Infrastructure can change without
rewriting assertions; assertions can grow without changing how containers
start.

---

## 5. Docker Topology

### 5.1 Services

The first version should define these services:

```text
postgres
  Akkoma database. Data lives in a disposable Docker volume.

akkoma
  Real Pleroma-compatible peer server.

unspoken
  The local server under test, built from this repository.

fake-oidc
  Minimal OpenID Connect provider used only by the harness.

interop-runner
  A small test runner image with curl, jq, and helper scripts.
```

The runner is a separate container so tests execute from inside the same
network namespace as both servers. That means the runner can use the same
Docker DNS names as the servers:

```text
http://unspoken.test:8080
http://akkoma.test:4000
```

Running tests from the host is possible, but it complicates name
resolution. The host does not automatically know Docker network aliases.
The runner avoids host `/etc/hosts` edits.

### 5.2 Network

Use one user-defined Compose network:

```yaml
networks:
  feditest:
```

Attach aliases explicitly:

```yaml
services:
  unspoken:
    networks:
      feditest:
        aliases:
          - unspoken.test

  akkoma:
    networks:
      feditest:
        aliases:
          - akkoma.test

  fake-oidc:
    networks:
      feditest:
        aliases:
          - fake-oidc.test
```

Use names with a dot, such as `unspoken.test`, rather than bare names
such as `unspoken`. Some Fediverse software and URL validators treat
single-label hosts as unusual or invalid. The `.test` top-level domain is
reserved for testing by [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761).

### 5.3 Ports

Expose ports to the host for debugging:

```text
unspoken: host 18080 -> container 8080
akkoma:   host 14000 -> container 4000
```

The tests should not depend on those host ports. They exist so a developer
can open a browser or run `curl` from the host while debugging.

### 5.4 Volumes

Use named volumes:

```text
unspoken-data
akkoma-db
akkoma-uploads
```

The teardown command must support removing them:

```sh
docker compose -f tests/interop/docker-compose.akkoma.yml down -v
```

Removing volumes is important because federation state is sticky. A test
run that reuses old activities can pass or fail for the wrong reason due
to deduplication, existing follows, or cached remote actors.

---

## 6. Required Test-Mode Changes

### 6.1 Test-Only HTTP URL Roots

Production `unspoken` requires `url_root` to be HTTPS. That is correct
for production because the PRD requires SSRF-safe outbound fetches and
Fediverse deployments generally use HTTPS actor IDs.

The Docker harness needs HTTP because local TLS would add certificate
management noise that does not test ActivityPub logic. Add a config flag:

```yaml
dev:
  allow_http_url_root: true
```

Rules:

- Default is `false`.
- If `false`, current HTTPS validation remains unchanged.
- If `true`, `url_root` may use `http`.
- This flag must be documented as test-only.
- The server should log a warning at startup when it is enabled.

The validation should still reject missing hosts, invalid URLs, and
non-HTTP(S) schemes.

### 6.2 Test-Only Outbound Local Address Allowlist

Production outbound fetches reject private, loopback, link-local, ULA,
and cloud-metadata destinations. That is a necessary SSRF protection.

The Docker harness needs `unspoken` to fetch `http://akkoma.test:4000`,
which resolves to a private Docker network IP. Add a config section:

```yaml
dev:
  outbound_allow_private_hosts:
    - akkoma.test
```

Rules:

- Default list is empty.
- The allowlist is ignored unless a separate dev mode is enabled.
- Matching is by URL host before the connection.
- The connected IP should still be logged.
- The allowlist must never be wildcard-based.
- Cloud metadata IPs must remain blocked even in dev mode unless a test
  explicitly changes code under a separate compile-time test flag. The
  harness does not need metadata IPs.

This design keeps the production SSRF posture intact while permitting a
known local peer in a controlled environment.

### 6.3 Fake OpenID Connect Provider

The harness should authenticate `unspoken` users through the same OIDC
flow used in production. This avoids adding a parallel write API whose
bugs could hide bugs in the real application path.

Add a `fake-oidc` service to the Compose project. It should implement the
small subset of OpenID Connect needed by `unspoken`:

```text
GET  /.well-known/openid-configuration
GET  /authorize
POST /token
GET  /jwks
GET  /select-user
POST /select-user
```

The provider should be implemented as a small C++ executable in
`tests/interop/fake_oidc/`, built by CMake as `fake_oidc`. It should
reuse the same libraries as `unspoken`: libmw for HTTP serving and crypto,
and nlohmann/json for JSON. This avoids pulling in Python JWT/crypto
dependencies and keeps the fake provider's signing behavior close to the
validation behavior already tested in `auth.cpp`.

The provider does not need user passwords because the interop runner
controls the network and uses predetermined test users. It does need to
behave like a real OIDC provider from `unspoken`'s point of view:
discovery, authorization redirect, code exchange, JWT signing, JWKS
publication, nonce echoing, and audience/issuer validation must all work.

#### 6.3.1 Configuration

The fake provider should be configured with environment variables:

```text
OIDC_ISSUER=http://fake-oidc.test:9000
OIDC_LISTEN_HOST=0.0.0.0
OIDC_LISTEN_PORT=9000
OIDC_CLIENT_ID=unspoken-interop
OIDC_CLIENT_SECRET=unspoken-interop-secret
OIDC_DEFAULT_USER=alice
OIDC_TOKEN_TTL_SECONDS=3600
```

The provider should also have a static user table. The first version can
hard-code it in `fake_oidc.cpp`:

```json
{
  "alice": {
    "sub": "alice-sub",
    "name": "Alice",
    "preferred_username": "alice"
  },
  "carol": {
    "sub": "carol-sub",
    "name": "Carol",
    "preferred_username": "carol"
  }
}
```

The user table is not authentication. It is fixture data used to generate
stable ID-token claims. More users can be added when tests need them.

#### 6.3.2 Signing Key

The fake provider must sign ID tokens with `RS256`.

Use one stable RSA keypair checked into `tests/interop/fake_oidc/`:

```text
tests/interop/fake_oidc/jwt_private.pem
tests/interop/fake_oidc/jwt_public.jwk
```

The private key is test-only and must never be reused outside the
harness. Keeping it stable makes token signatures and JWKS behavior
repeatable.

The JWK must include:

```json
{
  "kty": "RSA",
  "kid": "interop-rsa-1",
  "use": "sig",
  "alg": "RS256",
  "n": "...",
  "e": "AQAB"
}
```

All ID tokens must include this header:

```json
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "interop-rsa-1"
}
```

#### 6.3.3 Discovery Endpoint

`GET /.well-known/openid-configuration`

Response content type:

```text
application/json
```

Response:

```json
{
  "issuer": "http://fake-oidc.test:9000",
  "authorization_endpoint": "http://fake-oidc.test:9000/authorize",
  "token_endpoint": "http://fake-oidc.test:9000/token",
  "jwks_uri": "http://fake-oidc.test:9000/jwks",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile"],
  "claims_supported": [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nonce",
    "preferred_username",
    "name"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_post",
    "client_secret_basic"
  ]
}
```

The `issuer` value must exactly match the `oidc.issuer` configured in
`unspoken`.

#### 6.3.4 JWKS Endpoint

`GET /jwks`

Response:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "interop-rsa-1",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

The endpoint should set:

```text
Cache-Control: no-store
```

Caching is not needed in tests, and disabling it avoids confusing key
rotation experiments later.

#### 6.3.5 User Selection

The fake provider needs a way for the runner to say which user should be
logged in on the next authorization request.

`POST /select-user`

Request:

```json
{
  "username": "alice"
}
```

Response:

```json
{
  "username": "alice",
  "sub": "alice-sub"
}
```

Behavior:

1. Validate that `username` exists in the static user table.
2. Store the selected username in provider process memory.
3. Return `404` for unknown users.

`GET /select-user`

Response:

```json
{
  "username": "alice"
}
```

This endpoint is a test-control endpoint on the fake provider, not on
`unspoken`. It is acceptable because it only changes identity-provider
fixture state.

#### 6.3.6 Authorization Endpoint

`GET /authorize`

Required query parameters:

```text
client_id
redirect_uri
response_type
scope
state
nonce
```

Rules:

- `response_type` must be `code`.
- `client_id` must equal `OIDC_CLIENT_ID`.
- `redirect_uri` must start with `http://unspoken.test:8080/callback`
  in the default harness.
- `scope` must contain `openid`.
- `state` and `nonce` must be non-empty.

Behavior:

1. Pick the currently selected user. If no user was selected, use
   `OIDC_DEFAULT_USER`.
2. Generate an authorization code. Use at least 128 bits of randomness
   encoded in URL-safe base64.
3. Store an in-memory record:

   ```json
   {
     "code": "generated-code",
     "username": "alice",
     "client_id": "unspoken-interop",
     "redirect_uri": "http://unspoken.test:8080/callback",
     "nonce": "nonce-from-request",
     "issued_at": 1779999700,
     "used": false
   }
   ```

4. Redirect to:

   ```text
   <redirect_uri>?code=<code>&state=<state>
   ```

Error behavior:

- Invalid request parameters return `400 text/plain`.
- Unknown client returns `400 text/plain`.
- Invalid redirect URI returns `400 text/plain`.

The endpoint does not need to render a login page. The fake provider is
already controlled by the runner.

#### 6.3.7 Token Endpoint

`POST /token`

Accepted content type:

```text
application/x-www-form-urlencoded
```

Required form fields:

```text
grant_type=authorization_code
code=<authorization-code>
redirect_uri=<same redirect URI used at /authorize>
client_id=<client id>
client_secret=<client secret>
```

The provider should also accept HTTP Basic client authentication:

```text
Authorization: Basic base64(client_id:client_secret)
```

Rules:

- `grant_type` must be `authorization_code`.
- The code must exist, be unused, and be younger than 300 seconds.
- `client_id` and `client_secret` must match the configured values.
- `redirect_uri` must match the value stored with the code.
- A successful exchange marks the code as used.
- Reusing a code returns `400`.

Successful response:

```json
{
  "access_token": "fake-access-token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile",
  "id_token": "<signed-jwt>"
}
```

`access_token` can be an opaque random string. `unspoken` should not need
to call a userinfo endpoint if it validates and consumes the ID token.

ID-token payload:

```json
{
  "iss": "http://fake-oidc.test:9000",
  "sub": "alice-sub",
  "aud": "unspoken-interop",
  "exp": 1780000000,
  "iat": 1779999700,
  "nonce": "nonce-from-auth-request",
  "preferred_username": "alice",
  "name": "Alice"
}
```

Claim rules:

- `iss` equals `OIDC_ISSUER`.
- `sub`, `name`, and `preferred_username` come from the selected user.
- `aud` equals `OIDC_CLIENT_ID`.
- `iat` is the current unix time.
- `exp` is `iat + OIDC_TOKEN_TTL_SECONDS`.
- `nonce` equals the nonce stored with the authorization code.

Error response:

```json
{
  "error": "invalid_grant",
  "error_description": "authorization code is invalid"
}
```

Use HTTP `400` for invalid token requests.

#### 6.3.8 Runner Login Flow

The runner should log in a local user with these steps:

1. `POST http://fake-oidc.test:9000/select-user` with the desired
   username.
2. Start a cookie jar for that username.
3. `GET http://unspoken.test:8080/login` with redirects enabled.
4. The redirect chain goes:

   ```text
   unspoken /login
   -> fake-oidc /authorize
   -> unspoken /callback
   -> /setup-username or /
   ```

5. If the final page is `/setup-username`, parse the setup CSRF token and
   submit the normal setup form.
6. Keep the resulting session cookie for future form submissions.

This proves that `unspoken` can complete its real OIDC flow against an
external issuer. It also means local users in the interop harness are
created through the real first-login setup path, not through database
seeding or a custom write API.

This fake OIDC server is not a mock of `unspoken`; it is a real external
identity provider from `unspoken`'s point of view. That means the test
exercises discovery, callback validation, nonce validation, subject
mapping, session creation, first-login username setup, and cookies.

### 6.4 Form Driver for Unspoken Actions

The runner should drive `unspoken` through its normal HTML routes. It
must keep a cookie jar for each local test user.

The runner needs helpers:

```text
unspoken_login(username)
unspoken_setup_username(username)
unspoken_create_post(username, fields)
unspoken_reply(username, post_id, fields)
unspoken_follow(username, actor_uri)
unspoken_like(username, post_id)
unspoken_boost(username, post_id)
unspoken_react(username, post_id, emoji)
unspoken_delete(username, post_id)
unspoken_search(username, query)
```

Each helper should do the same steps a browser does:

1. Issue the relevant `GET` request when a CSRF token is needed.
2. Parse the CSRF token from the returned HTML.
3. Submit `application/x-www-form-urlencoded` form data.
4. Follow redirects when appropriate.
5. Return the final URL and response body for assertions.

The harness may parse HTML, but only for stable form contracts:

- hidden `csrf` inputs,
- post permalinks,
- reaction/count display,
- content warning and sensitive-media markers.

The harness should not depend on decorative CSS classes unless the class
is already part of the semantic template contract.

### 6.5 Assertions Without a Write API

The harness should not add write-capable `/dev/*` endpoints to
`unspoken`. Assertions can use three read paths:

1. **ActivityPub JSON:** fetch `/u/<username>` and `/p/<id>` with
   `Accept: application/activity+json`.
2. **Rendered HTML:** fetch timelines, profiles, search results, and post
   pages as a logged-in or anonymous browser.
3. **Read-only SQLite inspection:** mount the `unspoken` data volume into
   the runner read-only and query tables directly.

Read-only SQLite inspection is acceptable because it cannot create
federation behavior. It only observes final state. It also gives precise
assertions for state that the UI intentionally summarizes, such as raw
activity IDs, recipients, remote emoji URLs, and job states.

The runner should provide read helpers rather than open-coding SQL in
each test:

```text
db_post_by_uri(uri)
db_reactions_for_post(uri)
db_likes_for_post(uri)
db_boosts_for_post(uri)
db_follow(follower_uri, followee_uri)
db_jobs(kind, state)
```

If the schema changes, only these helpers need to change.

### 6.6 Job Progress

Prefer running `unspoken` with normal background workers enabled:

```yaml
job_workers: 2
job_retry_base_delay_seconds: 1
job_max_retries: 3
```

Tests should wait by polling visible effects instead of forcing jobs
through a dev endpoint. For example, after creating a post, poll Akkoma
until the post appears or until a timeout expires.

For retry-specific tests, inspect the `jobs` table read-only to confirm
pending, failed, and completed states. This keeps queue behavior real.

---

## 7. Akkoma Automation

### 7.1 Account Provisioning

The runner needs an Akkoma user, for example `bob`. There are two
possible provisioning strategies:

1. **Admin/API provisioning:** use Akkoma's admin API or CLI tasks to
   create users.
2. **Pre-seeded database/config:** initialize the Akkoma data volume with
   a known user.

Prefer admin/API provisioning because it uses the peer's supported
interfaces. If that proves unstable, use a container exec helper that runs
the Akkoma-provided user creation command inside the Akkoma container.

The harness should create:

```text
@bob@akkoma.test
password: test-password
```

### 7.2 API Authentication

To ask Akkoma to create posts, follow accounts, like posts, and react, the
runner needs an access token. Use Akkoma's Mastodon-compatible OAuth/API
flow where possible.

If OAuth setup is too heavy for the first version, a bootstrap script may
create an application and token through Akkoma CLI or admin API. The token
must be stored only inside the temporary test directory or container
environment.

The runner should expose helper functions:

```sh
akkoma_login bob test-password
akkoma_create_status "$token" "hello"
akkoma_follow "$token" "$actor_uri"
akkoma_like "$token" "$status_id"
akkoma_react "$token" "$status_id" ":blobcat:"
```

### 7.3 Custom Emoji Setup

The reaction tests require one known custom emoji on Akkoma. The setup
should install a tiny PNG under Akkoma's emoji/static directory and
refresh the emoji pack if Akkoma requires it.

Use one deterministic shortcode:

```text
:interop_blob:
```

Assertions should not rely on a particular generated CDN URL path unless
Akkoma makes it stable. Instead, assert:

- The stored reaction emoji is `:interop_blob:`.
- `remote_emoji_url` is present.
- `remote_emoji_media_type` is `image/png` or another expected image
  type.
- Rendering includes an `<img class="emoji">`.

---

## 8. Test Runner

### 8.1 Language

Use Python for the runner. Shell is acceptable for orchestration, but the
actual assertions should be in Python because JSON parsing, retries, and
error reporting are clearer.

Recommended files:

```text
tests/interop/
  docker-compose.akkoma.yml
  run.sh
  fake_oidc/
    Dockerfile
    fake_oidc.cpp
    jwt_private.pem
    jwt_public.jwk
  runner/
    Dockerfile
    interop.py
    http.py
    akkoma.py
    unspoken.py
    assertions.py
  config/
    unspoken.yaml
    akkoma.exs
  fixtures/
    interop_blob.png
```

### 8.2 Runner Commands

`run.sh` should support:

```sh
tests/interop/run.sh build
tests/interop/run.sh up
tests/interop/run.sh test
tests/interop/run.sh down
tests/interop/run.sh reset
tests/interop/run.sh logs
```

Meanings:

- `build`: run CMake builds for `unspoken` and `fake_oidc`, then build
  the `unspoken`, `fake-oidc`, and `interop-runner` images without
  starting the stack.
- `up`: build and start the stack.
- `test`: run the Python test suite against an already running stack.
- `down`: stop containers, keep volumes.
- `reset`: stop containers and remove volumes.
- `logs`: print relevant service logs.

`tests/interop/run.sh all` may perform `reset`, `up`, `test`, and `down`.
On failure it should keep containers running unless `--cleanup` is passed,
so logs and live state remain available.

### 8.3 Readiness

Readiness must be explicit:

- `unspoken`: `GET /health` returns `200`.
- Akkoma: `GET /api/v1/instance` or another stable public endpoint
  returns `200`.
- PostgreSQL: Compose healthcheck uses `pg_isready`.

The runner should use bounded retries:

```text
timeout: 120 seconds
interval: 1 second
```

If a service is not ready in time, the runner prints the last 100 log
lines for that service.

---

## 9. Test Cases

Each test should start from a clean or explicitly known state. If tests
share setup, they must use unique usernames and content strings so a
failure can be traced.

### 9.1 Actor and Discovery Tests

#### 9.1.1 Akkoma Fetches Unspoken Actor

Steps:

1. Create `alice` on `unspoken`.
2. From the runner, fetch `http://unspoken.test:8080/u/alice` with
   `Accept: application/activity+json`.
3. Ask Akkoma to resolve `@alice@unspoken.test` or the actor URL.
4. Assert Akkoma can identify the actor.

Verifies:

- Actor JSON shape.
- Public key publication.
- WebFinger.
- Docker DNS URL roots.

#### 9.1.2 Unspoken Fetches Akkoma Actor

Steps:

1. Create `bob` on Akkoma.
2. Log in to `unspoken` as Alice through fake OIDC.
3. Submit the normal `POST /follow` form with Bob's actor URI.
4. Assert `unspoken` stores a `RemoteActor` by read-only SQLite
   inspection.

Verifies:

- Signed system-actor GET.
- Remote actor parsing.
- Public key caching.
- Dev outbound private-host allowlist.

### 9.2 Follow Tests

#### 9.2.1 Akkoma Follows Unspoken

Steps:

1. Create `alice` on `unspoken`.
2. Create `bob` on Akkoma.
3. Ask Akkoma to follow Alice.
4. Poll until Bob appears in Alice's followers in the read-only SQLite
   view.
5. Assert Akkoma reports the follow as accepted.

Verifies:

- Inbound `Follow`.
- Signature verification.
- Remote actor resolution.
- Local follow storage.
- Outbound `Accept` delivery.

#### 9.2.2 Unspoken Follows Akkoma

Steps:

1. Log in to `unspoken` as Alice.
2. Submit the normal `POST /follow` form for Bob's actor URI.
3. Wait for Akkoma to accept.
4. Assert Bob appears in Alice's following list by read-only SQLite
   inspection.

Verifies:

- Outbound `Follow`.
- Delivery inbox calculation.
- Inbound `Accept`.
- Follow state transition.

### 9.3 Post Delivery Tests

#### 9.3.1 Unspoken Public Post Appears on Akkoma

Steps:

1. Ensure Bob follows Alice.
2. Create a public post as Alice through the normal `POST /post` form.
3. Poll Akkoma timelines or statuses API.
5. Assert the post content appears.

Verifies:

- Local post creation.
- ActivityPub `Create` construction.
- Recipients and shared inbox delivery.
- Remote server accepts our HTTP signature.

#### 9.3.2 Akkoma Public Post Appears on Unspoken

Steps:

1. Ensure Alice follows Bob.
2. Create a public post as Bob through Akkoma API.
3. Wait for delivery.
4. Query unspoken timeline HTML and read-only SQLite state.
5. Assert the post exists and content is sanitized.

Verifies:

- Inbound `Create`.
- Remote `Note` parsing.
- HTML sanitization.
- Remote author association.

### 9.4 Reply and Thread Tests

#### 9.4.1 Akkoma Replies to Unspoken Post

Steps:

1. Create Alice post.
2. Ask Bob to reply to Alice's post.
3. Wait for delivery.
4. Query Alice post's thread HTML and read-only SQLite state.
5. Assert the reply is stored with `in_reply_to_uri`.

Verifies:

- Inbound reply addressing.
- Thread storage.
- Mention/address parsing from peer.

#### 9.4.2 Unspoken Replies to Akkoma Post

Steps:

1. Create Bob post.
2. Fetch or receive it in unspoken.
3. Create Alice reply through the normal `POST /post/:id/reply` form.
4. Poll Akkoma for the reply.
5. Assert Akkoma sees the reply in the thread.

Verifies:

- Outbound replies.
- `inReplyTo`.
- Mention tags and recipient calculation.

#### 9.4.3 Remote Thread Backfill

Steps:

1. Create a Bob post with one Akkoma-side reply.
2. Log in to `unspoken` and search for the root post URL through the
   normal `/search` route.
3. Wait for fetch-thread background jobs to run.
4. Assert known replies are imported when exposed by Akkoma collections.

Verifies:

- `fetchRemotePostByUri()`.
- Fetch-thread job queue.
- Collection traversal.
- Depth limit behavior.

### 9.5 Like, Boost, and Undo Tests

#### 9.5.1 Akkoma Likes Unspoken Post

Steps:

1. Alice creates a post.
2. Bob likes it from Akkoma.
3. Wait for delivery.
4. Inspect read-only SQLite and post HTML.
5. Assert `like_count == 1`.

Verifies inbound `Like`.

#### 9.5.2 Akkoma Unlikes Unspoken Post

Steps:

1. Continue from liked state.
2. Bob unlikes it.
3. Assert `like_count == 0`.

Verifies inbound `Undo` for `Like`.

#### 9.5.3 Akkoma Boosts and Unboosts Unspoken Post

Same shape as like/unlike, but with `Announce` and `Undo`.

Verifies:

- Inbound `Announce`.
- Visibility restriction for boosts.
- Inbound `Undo` for `Announce`.

#### 9.5.4 Unspoken Likes and Boosts Akkoma Post

Steps:

1. Bob creates a post.
2. Alice likes and boosts through the normal form routes.
3. Poll Akkoma for those interactions.
4. Assert Akkoma displays or reports those interactions.

Verifies outbound `Like`, `Announce`, and undo behavior.

### 9.6 Emoji Reaction Tests

#### 9.6.1 Akkoma Custom Emoji Reacts to Unspoken Post

Steps:

1. Install `:interop_blob:` on Akkoma.
2. Alice creates a post.
3. Bob reacts with `:interop_blob:`.
4. Wait for delivery.
5. Inspect read-only SQLite reaction state.
6. Assert reaction exists with:
   - `emoji == ":interop_blob:"`
   - remote emoji URL present
   - media type present
7. Fetch normal post HTML and assert the reaction renders as an emoji
   image.

Verifies:

- Inbound `EmojiReact`.
- Custom emoji `tag` parsing.
- Reaction grouping and rendering.

#### 9.6.2 Akkoma Unicode Emoji Reacts to Unspoken Post

Same as above, but use a Unicode emoji such as `👍`.

Verifies Unicode reaction storage without custom emoji metadata.

#### 9.6.3 Unspoken Reacts to Akkoma Post

Steps:

1. Bob creates a post.
2. Alice reacts through the normal `POST /post/:id/react` form.
3. Poll Akkoma for the reaction.
4. Assert Akkoma records or displays the reaction.

Verifies outbound `EmojiReact`.

### 9.7 Delete and Update Tests

#### 9.7.1 Akkoma Deletes a Post Known to Unspoken

Steps:

1. Bob creates a post.
2. Unspoken receives or fetches it.
3. Bob deletes it.
4. Assert unspoken no longer shows the post.

Verifies inbound `Delete`.

#### 9.7.2 Unspoken Deletes a Post Known to Akkoma

Steps:

1. Alice creates a post.
2. Akkoma receives it.
3. Alice deletes through the normal `POST /post/:id/delete` form.
4. Poll Akkoma for the delete.
5. Assert Akkoma marks it deleted or removes it.

Verifies outbound `Delete`.

#### 9.7.3 Akkoma Updates a Post Known to Unspoken

Steps:

1. Bob creates a post.
2. Unspoken receives it.
3. Bob edits it.
4. Assert unspoken content changes.

Verifies inbound `Update`.

### 9.8 Content Warning and Sensitive Media Tests

Steps:

1. Create posts on each side with content warnings.
2. Create posts with sensitive media.
3. Assert remote objects preserve `summary` and `sensitive`.
4. Assert local rendered state marks media/content as collapsed or hidden.

Verifies:

- `summary`.
- `sensitive`.
- Attachment parsing.
- Template state for hidden content.

### 9.9 Attachment Tests

#### 9.9.1 Akkoma Image Attachment Inbound

Steps:

1. Bob posts an image.
2. Unspoken receives it.
3. Assert attachment row has `remote_url`, `media_type`, and `is_image`.

Verifies remote attachment storage without media caching.

#### 9.9.2 Unspoken Image Attachment Outbound

Steps:

1. Alice creates a post with an uploaded image through a dev endpoint or
   existing upload flow.
2. Akkoma receives it.
3. Assert Akkoma sees an `Image` attachment.

This may require a later dev endpoint for fixture uploads.

### 9.10 Privacy and Authorization Tests

#### 9.10.1 Followers-Only Post Delivery

Steps:

1. Bob follows Alice.
2. Alice creates a followers-only post.
3. Assert Akkoma receives it.
4. Attempt unsigned fetch from runner.
5. Assert unspoken returns `404`.

Verifies:

- Private delivery.
- ActivityPub authorized fetch behavior.
- HTML/API existence hiding.

#### 9.10.2 Direct Post Delivery

Steps:

1. Alice creates a direct post mentioning Bob.
2. Assert Bob receives it.
3. Assert unrelated actors cannot fetch it.

This test may require Akkoma API support for direct messages and should be
marked optional until stable.

### 9.11 Duplicate and Idempotency Tests

Steps:

1. Capture an inbound activity body and signature, or use peer API to
   perform an action twice when it redelivers the same activity.
2. Deliver the same activity twice to unspoken if signature timestamps are
   still valid.
3. Assert state changes once.

Verifies:

- `markActivitySeen()`.
- Unique reaction/like/boost constraints.
- Idempotent `Delete` and `Undo`.

For exact redelivery, a helper signed sender may be easier than forcing
Akkoma to resend the same activity. That helper can be added as a later
runner component.

### 9.12 Failure and Retry Tests

Steps:

1. Stop Akkoma.
2. Create an Alice post.
3. Run delivery jobs.
4. Assert jobs fail and reschedule.
5. Start Akkoma.
6. Run jobs again.
7. Assert delivery eventually succeeds.

Verifies:

- Persisted job queue.
- Retry backoff.
- Max retry behavior.
- Recovery after peer downtime.

---

## 10. Test Result Reporting

Each test case should print:

- Test name.
- Local user and peer user.
- Important object URIs.
- Important activity IDs.
- Final assertion summary.

On failure, print:

- Last HTTP request and response from the runner.
- Relevant rendered HTML, ActivityPub JSON, and read-only SQLite rows.
- Last 200 lines of `unspoken` logs.
- Last 200 lines of Akkoma logs.

The runner should write a machine-readable result file:

```text
tests/interop/.artifacts/results.json
```

Shape:

```json
{
  "started_at": "2026-06-29T00:00:00Z",
  "unspoken_commit": "abc1234",
  "peer": {
    "name": "akkoma",
    "version": "..."
  },
  "tests": [
    {
      "name": "akkoma_custom_emoji_reacts_to_unspoken_post",
      "status": "passed",
      "objects": {
        "post_uri": "http://unspoken.test:8080/p/1"
      }
    }
  ]
}
```

This file lets CI or a developer compare runs without scraping logs.

---

## 11. CI Strategy

The interop harness is a Docker-based test suite. It depends on Docker or
Podman Compose and should be run explicitly.

There is no separate C++ interop test binary in the first design. The
interop test executable is the runner script/container. The build
artifacts are:

- the normal `unspoken` server binary, built into an `unspoken` Docker
  image;
- the `fake_oidc` helper binary, built by CMake and then copied into the
  fake OIDC Docker image;
- the fake OIDC provider image, built from `tests/interop/fake_oidc/`;
- the interop runner image, built from `tests/interop/runner/`;
- third-party peer images and volumes managed by Compose.

The script should build these Docker images before running tests:

```sh
tests/interop/run.sh build
tests/interop/run.sh all
```

Run the interop suite through its own script:

```sh
tests/interop/run.sh all
```

If the harness is also exposed through CMake, that target should only be
a wrapper around `tests/interop/run.sh all`. It should be named
`interop_test` or `federation_interop_test`, not `test`, so it is clear
that Docker images and peer services are involved.

Future CI can run the interop suite:

- nightly,
- before releases,
- manually from a workflow dispatch,
- or on PRs that touch federation code.

The first implementation should optimize for local developer use. CI can
be added after the harness is stable.

---

## 12. Security Model

This design intentionally weakens some production rules inside the test
environment. Those weakenings must be explicit and contained.

### 12.1 Production Defaults Stay Secure

Defaults:

```yaml
dev:
  allow_http_url_root: false
  outbound_allow_private_hosts: []
```

If no dev config is present, `unspoken` behaves as it does today.

### 12.2 No Write-Capable Test API

The harness must not add write-capable `/dev/*` endpoints to `unspoken`.
All local state changes should use one of the real application paths:

- OIDC login and username setup,
- existing HTML form routes,
- existing ActivityPub inbox routes,
- normal background job processing.

This rule keeps the harness honest. A separate write API could contain
bugs or skip checks that the real UI path performs. Using fake OIDC and
forms means the harness covers authentication, session cookies, CSRF, form
parsing, service calls, and federation side effects together.

Read-only SQLite inspection is allowed because it does not create
application behavior. It only observes final state.

### 12.3 Fake OIDC Scope

The fake OIDC provider is test infrastructure, not production code. It
must live under `tests/interop/` and should not be linked into the
`unspoken` executable.

The fake provider should only be reachable inside the Compose network by
default. Exposing it to the host is optional for debugging.

### 12.4 Logs Must Identify Unsafe Mode

Startup logs should include warnings:

```text
HTTP url_root enabled for development
private outbound host allowlist enabled: akkoma.test
```

This makes accidental misuse visible.

---

## 13. Implementation Plan

### Phase 1: Test Config and Fake OIDC

1. Add `DevConfig` to `Config`.
2. Parse `dev.*` keys from YAML.
3. Allow HTTP `url_root` only when configured.
4. Add private-host outbound allowlisting for named test peers.
5. Add `tests/interop/fake_oidc/fake_oidc.cpp`.
6. Add a CMake target named `fake_oidc` that links libmw HTTP server,
   libmw crypto, nlohmann/json, and the existing auth/JWT helper code it
   needs.
7. Implement discovery, JWKS, authorization-code, token, and user
   selection endpoints.
8. Add the stable test RSA key and public JWK fixture.
9. Configure `unspoken` to use fake OIDC as its normal issuer in the
   interop config.
10. Add unit tests for config validation and focused fake-OIDC helper
    logic where it is factored out of the executable.

### Phase 2: Docker Compose Skeleton

1. Add `tests/interop/docker-compose.akkoma.yml`.
2. Add an `unspoken` Dockerfile or test-specific build target if the
   project does not already have one.
3. Add a fake OIDC Dockerfile that copies the CMake-built `fake_oidc`
   binary and its key/JWK fixtures into a minimal runtime image.
4. Add Akkoma config with:
   - `host: "akkoma.test"`
   - `scheme: "http"`
   - `port: 4000`
   - federation enabled
5. Add unspoken config with:
   - `url_root: "http://unspoken.test:8080/"`
   - `public_domain: "unspoken.test"`
   - fake OIDC issuer/client settings
   - private host allowlist containing `akkoma.test`
6. Add readiness checks.

### Phase 3: Control Helpers

1. Create Akkoma user.
2. Obtain Akkoma API token.
3. Log in to `unspoken` through fake OIDC.
4. Complete `unspoken` username setup through the real form.
5. Parse CSRF tokens from `unspoken` HTML.
6. Submit `unspoken` post, reply, follow, like, boost, react, and delete
   forms.
7. Create Akkoma statuses and interactions through Akkoma APIs.
8. Upload or install custom emoji fixture.

### Phase 4: Core Federation Tests

Implement tests for:

- actor fetch both directions,
- WebFinger,
- follow both directions,
- public post delivery both directions,
- reply both directions,
- like/undo,
- boost/undo,
- custom emoji reaction inbound,
- Unicode reaction inbound,
- delete inbound.

### Phase 5: Extended Federation Tests

Implement tests for:

- update,
- attachments,
- content warnings,
- sensitive media,
- private posts,
- duplicate delivery,
- job retry and recovery,
- outbound custom emoji reactions.

### Phase 6: Documentation and Operator Notes

1. Document `tests/interop/run.sh`.
2. Document expected runtime and dependencies.
3. Document how to inspect logs.
4. Update `docs/operator.md` interop section to mention the harness.

---

## 14. Open Questions

1. **Akkoma image source:** Which Akkoma image/tag should the harness pin?
   The answer affects reproducibility and setup speed.

2. **Akkoma provisioning interface:** Should we use Akkoma CLI tasks,
   admin API, or registration APIs to create users and tokens? The best
   answer is the most stable interface available in the chosen image.

3. **Outbound private allowlist implementation:** Should the allowlist live
   in `hardenOutboundSession()` or one layer above it? Keeping it near
   `hardenOutboundSession()` reduces the chance of missing a fetch path.

4. **Read-only assertion method:** Should assertions use SQLite directly,
   rendered HTML, ActivityPub JSON, or all three? The recommended answer is
   all three: SQLite for exact state, ActivityPub JSON for protocol shape,
   and HTML for user-visible behavior.

5. **CI runtime budget:** How long can the full interop suite take before
   it becomes too slow for routine use? The first target should be under
   five minutes after images are built.

---

## 15. Acceptance Criteria

The first complete version is accepted when:

- `tests/interop/run.sh all` starts from no containers and exits with
  success on a developer machine with Docker or Podman Compose.
- The command does not require host PostgreSQL, Redis, public DNS, public
  TLS, or host `/etc/hosts` changes.
- Local `unspoken` actions are driven through fake OIDC login and the
  existing HTML form routes, not through a write-capable test API.
- The suite proves at least:
  - WebFinger from Akkoma to unspoken,
  - actor fetch both directions,
  - follow/accept both directions,
  - public post delivery both directions,
  - reply delivery in at least one direction,
  - inbound like and undo,
  - inbound boost and undo,
  - inbound custom emoji `EmojiReact`,
  - inbound delete.
- On failure, logs and state dumps are available.
- Production config without `dev.*` remains secure and rejects HTTP
  `url_root` and private outbound federation targets.
