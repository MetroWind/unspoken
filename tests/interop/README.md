# Docker Federation Interop Harness

This directory contains the disposable Akkoma interop lab for `unspoken`.
It starts `unspoken`, a fake OpenID Connect provider, Akkoma, PostgreSQL,
a controllable ActivityPub lifecycle peer, and a Python runner in one Docker
Compose project. The runner talks to both servers from inside the Compose
network, so no public DNS, public TLS, host PostgreSQL, host Redis, or
`/etc/hosts` edits are required.

The harness is development and release-test infrastructure. It is not part
of the production deployment path.

## Requirements

- Docker with Compose v2, or the legacy `docker-compose` command.
- CMake and the normal C++ build toolchain for this repository.
- Python 3 on the host. `run.sh` uses it only to read retry artifacts.
- Network access when images or CMake dependencies are not already cached.
- Enough local disk for Docker images and the disposable named volumes.

The first run is dominated by CMake dependency downloads and Docker image
builds. A warm run is still slower than unit tests because it boots Akkoma,
PostgreSQL, `unspoken`, and the fake OIDC provider. Expect several minutes
on a typical development machine.

## Commands

Run commands from the repository root:

```sh
tests/interop/run.sh build
tests/interop/run.sh up
tests/interop/run.sh test
tests/interop/run.sh down
tests/interop/run.sh reset
tests/interop/run.sh logs
tests/interop/run.sh all
tests/interop/run.sh all --cleanup
```

`build` configures CMake, builds the `unspoken` and `fake_oidc` binaries,
and builds the Akkoma, `unspoken`, fake-OIDC, and runner images.

`up` builds what is needed and starts PostgreSQL, Akkoma, fake OIDC, and
`unspoken`. It leaves the stack running for debugging.

`test` runs the Python interop suite against an already running stack. It
also runs the retry/recovery check by stopping Akkoma, creating an outbound
delivery, restarting Akkoma, and confirming the queued delivery recovers.
It also restarts Unspoken after a lifecycle-peer delivery to verify that an
inbound follower remains deliverable and a remote post still renders.

`down` stops containers but keeps Docker volumes. This preserves federation
state for inspection.

`reset` stops containers, removes the named volumes, removes orphan
containers, and recreates the local artifact directory. Use this before a
clean run because ActivityPub state is sticky and duplicate activity IDs,
cached remote actors, or existing follows can change test behavior.

`logs` prints the last 200 lines from PostgreSQL, Akkoma, fake OIDC, and
`unspoken`.

`all` runs `reset`, `up`, and `test`. It intentionally leaves containers
running after success or failure so logs and live state can be inspected.
Use `all --cleanup` to stop the stack after a successful run.

## Network And URLs

The Compose network provides stable test hostnames:

- `http://unspoken.test:8080`
- `http://akkoma.test:4000`
- `http://fake-oidc.test:9000`
- `http://lifecycle-peer.test:8090`

Host ports are exposed only for debugging:

- `http://127.0.0.1:18080` maps to `unspoken`.
- `http://127.0.0.1:14000` maps to Akkoma.

Tests use the internal `.test` names, not the host ports.

## Test-Only Configuration

`tests/interop/config/unspoken.yaml` enables the dev-only federation
relaxations required by the local lab:

```yaml
dev:
  allow_http_url_root: true
  outbound_allow_private_hosts:
    - akkoma.test
```

These settings allow an HTTP `url_root` and outbound fetches to the named
Akkoma test host on Docker's private network. Production configs must keep
the defaults:

```yaml
dev:
  allow_http_url_root: false
  outbound_allow_private_hosts: []
```

The allowlist is host-based and explicit. It is not a wildcard and does
not make cloud metadata addresses valid test targets.

## Actor Lifecycle Coverage

The lifecycle peer serves actor documents and can rotate its RSA key between
signed deliveries. The test stages verify a real retained-key rotation, an
unknown-object `Delete` from a transient signer, and restart persistence for
an inbound follow and a stored remote post author. It is intentionally a
small purpose-built peer: Akkoma remains the compatibility peer for normal
federation behavior, while the lifecycle peer makes those timing-sensitive
security cases deterministic.

## Artifacts

The runner writes machine-readable results under:

```text
tests/interop/.artifacts/
```

The main run writes `results.json`. The retry check also writes
`retry_prepare.json` and `retry_recover.json`. Each file records test
names, pass/fail status, and important object IDs such as post URIs,
activity URIs, status IDs, and job IDs.

## Inspecting State

Print service logs:

```sh
tests/interop/run.sh logs
```

For a specific container, use Compose directly:

```sh
docker compose -f tests/interop/docker-compose.akkoma.yml logs --tail=200 \
    unspoken
docker compose -f tests/interop/docker-compose.akkoma.yml logs --tail=200 \
    akkoma
```

Inspect `unspoken` SQLite state without mutating it:

```sh
docker compose -f tests/interop/docker-compose.akkoma.yml run --rm \
    interop-runner sqlite3 /unspoken-data/unspoken.db \
    'select id, uri, author_uri, visibility from posts order by id desc;'
```

Open the web UIs from the host while the stack is running:

```text
http://127.0.0.1:18080/
http://127.0.0.1:14000/
```

The fake OIDC provider has no login UI. The runner selects fixture users
through its test-control endpoint and then drives `unspoken` through the
normal `/login`, `/callback`, and `/setup-username` flow.

## Failure Handling

On runner failure, `run.sh test` prints recent service logs and keeps the
stack running. Check `tests/interop/.artifacts/results.json` first for the
failed test name and object IDs, then inspect service logs and SQLite
state.

Use `reset` before re-running unless you are intentionally debugging the
preserved state. Existing follows, cached remote actors, and seen activity
IDs can otherwise mask or create failures.

## Peer-Specific Notes

The rich profile checks use Akkoma's Mastodon-compatible
`/api/v1/accounts/update_credentials` endpoint. Akkoma exposes profile
metadata as account `fields`, and actor `icon`/`image` as account avatar
and header URLs. Actor/profile refresh is eventually consistent, so the
runner polls account search and Unspoken's cached actor JSON before
asserting rendered profile fields.
