# Unspoken Operator Guide

This guide covers the production deployment details that are easy to get
wrong when running `unspoken` behind a reverse proxy.

## Reverse Proxy

`url_root` is the HTTPS origin where ActivityPub actor IDs and object IDs
live. `public_domain` is the bare domain shown in handles, for example
`@alice@example.org`. If those hosts differ, the reverse proxy for
`public_domain` must forward only these paths to `unspoken`:

- `/.well-known/webfinger`
- `/.well-known/nodeinfo`

Do not proxy the entire public-domain apex unless `unspoken` owns that
site. Keep ACME paths such as `/.well-known/acme-challenge/*` before the
Unspoken rules so certificate renewal still works.

The service must see normal `Host`, `Date`, `Digest`, and `Signature`
headers on ActivityPub requests. Do not strip or rewrite those headers.

## Config Reference

Required keys:

- `url_root`: HTTPS base URL for the service. It is normalized to one
  trailing slash.
- `oidc.issuer`: OpenID Connect issuer URL.
- `oidc.client_id`: OIDC client ID.
- `oidc.client_secret`: OIDC client secret.

Common optional keys and defaults:

- `public_domain`: handle domain. Defaults to the host of `url_root`.
- `listen_address`: `127.0.0.1`.
- `listen_port`: `8080`.
- `verbose`: `false`. Enables debug logging, including full federation
  request/response headers and bodies.
- `database_path`: `unspoken.db`.
- `attachment_dir`: `attachments`.
- `emoji_dir`: `emoji`.
- `emoji_data_file`: generated Unicode emoji picker data file.
- `template_dir`: `templates`.
- `static_dir`: `static`.
- `posts_per_page`: `20`.
- `http_signature_skew_seconds`: `300`.
- `thread_fetch_max_depth`: `20`.
- `sqlite_busy_timeout_ms`: `5000`.
- `seen_activity_retention_seconds`: `2592000` (30 days). Completed inbox
  activity IDs older than this are eligible for pruning.
- `inbox_processing_lease_seconds`: `300` (5 minutes). Retained for legacy
  receipt APIs. The migrated HTTP inbox commits effects and receipts in one
  transaction and does not use a separate processing lease.
- `maintenance_batch_size`: `1000`. The maximum completed activity IDs
  removed in one SQLite maintenance transaction.
- `remote_actor_gc_grace_seconds`: `2592000` (30 days). Unreferenced remote
  actors remain available for this grace period before collection.
- `job_workers`: `4`.
- `job_max_retries`: `8`.
- `job_retry_base_delay_seconds`: `30`.
- `max_upload_bytes`: `10485760`.
- `oidc.scopes`: `openid profile`.
- `nodeinfo.software_name`: `unspoken`.
- `nodeinfo.open_registrations`: `true`.
- `nodeinfo.description`: empty.

Example:

```yaml
url_root: https://fedi.internal.example.org/
public_domain: example.org
listen_address: 127.0.0.1
listen_port: 8080
verbose: false
database_path: /var/lib/unspoken/unspoken.db
attachment_dir: /var/lib/unspoken/attachments
emoji_dir: /var/lib/unspoken/emoji
emoji_data_file: /usr/share/unspoken/data/emoji_categories.json
template_dir: /usr/share/unspoken/templates
static_dir: /usr/share/unspoken/static

seen_activity_retention_seconds: 2592000
inbox_processing_lease_seconds: 300
maintenance_batch_size: 1000
remote_actor_gc_grace_seconds: 2592000

oidc:
  issuer: https://sso.example.org/realms/main
  client_id: unspoken
  client_secret: change-me

nodeinfo:
  open_registrations: true
  description: Small private Fediverse server
```

## Arch/systemd Deployment

The `packages/arch/unspoken.*` files provide the service account,
runtime directories, and systemd unit:

- `unspoken.sysusers`: creates the `unspoken` system user.
- `unspoken.tmpfiles`: creates `/var/lib/unspoken`.
- `unspoken.service`: starts `/usr/bin/unspoken --config
  /etc/unspoken/config.yaml`.

Install templates and static files under `/usr/share/unspoken/`, place
the config at `/etc/unspoken/config.yaml`, then run:

```sh
systemd-sysusers packages/arch/unspoken.sysusers
systemd-tmpfiles --create packages/arch/unspoken.tmpfiles
systemctl enable --now unspoken.service
```

## Security Review Checklist

Before exposing the service to the internet, confirm:

- HTTP signatures reject missing `Signature`, stale `Date`, unsigned or
  mismatched `Digest`, unsupported algorithms, and bad keys.
- Outbound ActivityPub/WebFinger fetches allow only HTTPS and reject
  private, loopback, link-local, ULA, and cloud-metadata addresses after
  connection address resolution.
- Followers-only and direct posts return `404` to unauthorized HTML and
  ActivityPub fetches.
- OIDC callback validates `state`, ID-token signature, issuer, audience,
  expiry, and nonce.
- All state-changing forms include a CSRF token.
- Session cookies are `Secure`, `HttpOnly`, and `SameSite=Lax`.
- Upload limits are enforced and non-image files are served as downloads
  with `nosniff`.
- Unexpected server errors return a generic `500` body; details stay in
  logs.

## Interop Notes

The repository includes a disposable Docker-based Akkoma interop harness
under `tests/interop/`. It is intended for development and release checks,
not for production deployment. See
[tests/interop/README.md](../tests/interop/README.md) for commands,
runtime expectations, logs, artifacts, and state-inspection examples.

The main local command is:

```sh
tests/interop/run.sh all
```

This starts PostgreSQL, Akkoma, fake OIDC, and `unspoken` in Docker,
drives local actions through the real OIDC and HTML form paths, and writes
machine-readable results under `tests/interop/.artifacts/`. On failure the
stack is left running so service logs and SQLite state can be inspected.
Use `tests/interop/run.sh reset` to remove all interop volumes before a
clean rerun.

The harness config enables test-only development settings:

```yaml
dev:
  allow_http_url_root: true
  outbound_allow_private_hosts:
    - akkoma.test
```

Do not copy those settings into production configs. Production deployments
must keep HTTPS `url_root` enforcement and the default empty private-host
outbound allowlist.

Verify federation against at least Mastodon, Akkoma or Pleroma, and
Misskey before declaring a deployment production ready. Exercise actor
fetch, WebFinger, follow/accept, public post delivery, replies, likes,
boosts, delete/update, custom emoji tags, and duplicate activity
redelivery.

Use this checklist for each peer implementation:

- WebFinger from the peer resolves `acct:<user>@<public_domain>` to the
  actor ID under `url_root`.
- The peer can fetch `/u/<username>` as ActivityPub JSON with authorized
  fetch enabled on the peer.
- The peer can fetch a public `/p/<id>` as ActivityPub JSON.
- A follow from the peer is accepted automatically, and the peer shows
  the follow as accepted.
- A local public post is delivered to the peer and appears in the peer's
  home timeline.
- A local reply to a peer post is delivered and threads correctly on the
  peer.
- A peer reply to a local post is received, stored, sanitized, and shown
  in the local thread.
- Like, boost, and undo from both directions update state once and stay
  idempotent when the activity is redelivered.
- Delete and Update from both directions update or remove the known
  object, while Delete or Undo for an unknown object returns success.
- Content warnings and `sensitive` media remain hidden/collapsed on both
  sides until revealed.
- A post containing a mention addresses and delivers to the mentioned
  actor.
- Custom emoji tags on a local post render on the peer, and remote
  custom emoji tags render locally.
- Shared inbox delivery is used when the peer advertises
  `endpoints.sharedInbox`; individual inbox delivery is used otherwise.
- Peer downtime causes delivery jobs to retry with backoff and eventually
  stop at `job_max_retries`.
- Private posts are not fetchable by unsigned or unauthorized peer
  requests and return `404`.

Record the peer name/version, the local commit, the test account handles,
and any quirk or failed activity ID. Check the phase 7 interop item in
`plan.md` only after Mastodon, Akkoma or Pleroma, and Misskey all pass
or have documented fixes committed.

## Federation library migration

Unspoken's application schema version 4 moves federation persistence into
library-owned `ap_*` tables. Startup migrates older databases before serving
requests or starting workers. Actor keys, actor/object/activity URIs,
relationship IDs, and queued delivery payloads are preserved. Previously
running jobs are requeued because the old workers must be stopped before
upgrade. New claims use lease expiry and claimant tokens for crash recovery. Older v3
databases without the system-actor table or optional remote-emoji columns
are supported; missing optional fields receive their library defaults.

Stop Unspoken and take a consistent SQLite backup before upgrading. For the
standard package paths, for example:

```sh
sudo systemctl stop unspoken
sudo -u unspoken sqlite3 /var/lib/unspoken/unspoken.db \
    ".backup '/var/lib/unspoken/pre_library.db'"
```

Start the new binary only after the backup succeeds. The application schema
version and the library's `ap_schema` version are independent. Old federation
table names remain read-only compatibility views for application queries
and inspection; new SQL writes belong to the library. Do not run the old
binary against the migrated database. Downgrade requires restoring the
pre-upgrade backup, which discards writes received after the upgrade.

Unspoken retains responsibility for HTML sanitization and media serving.
The library stores protocol snapshots independently of display projections.
Private outbox activities are not publicly enumerable, and deleted public
objects retain protocol tombstones after their application post is removed.

## Stored link previews

`link_previews.enabled` defaults to `true`. One application worker fetches
at most one article link from each new local or retained remote post. This
includes followers-only and direct posts: fetching reveals the URL and
server IP to the destination, without sending post content, author identity,
recipients, credentials, or federation signatures. Disable it with:

```yaml
link_previews:
  enabled: false
```

Disabling stops the worker and new associations; saved cards remain usable.
Re-enabling recovers referenced pending rows at startup and every 30 seconds.
The queue holds at most 1000 distinct IDs, including active and delayed work;
overflow remains pending in SQLite. Three attempts use delays of 30 seconds
and five minutes, with integer Retry-After up to one hour. Retry budgets and
deadlines live in memory and reset after a restart. Ready, unavailable, and
failed rows are never automatically refreshed or retried. Old posts with no
preview association are not backfilled.

Fetching permits HTTP/HTTPS on default ports, explicitly validates redirects
and resolved addresses, disables environment proxies, and limits each HTML
attempt to 30 seconds and 1 MiB of decoded data. Development federation
private-host exceptions do not apply. Logs contain row IDs, hosts, attempt
counts, result classes, byte counts, and durations, without full query URLs
or downloaded metadata. Inspect status totals with:

```sql
SELECT status, count(*) FROM link_previews GROUP BY status;
-- 0 pending, 1 ready, 2 unavailable, 3 failed
```

Images load directly in the browser with no Referer header. Their hosts can
observe viewer IPs, timing, and cookies permitted by the browser. A content
warning controls display, and does not guarantee that a browser postpones
image loading. HTTP images may be upgraded or blocked on HTTPS pages. Cards
remain usable without an image. If adding a Content Security Policy, allow
HTTP(S) image sources while retaining existing script/frame restrictions.

Unused preview rows are collected hourly in batches of 100, excluding queued
and running rows. There are no preview image files to back up. Take a
consistent SQLite backup before upgrading to schema 6. Reverting the binary
requires a compatible database backup; disabling previews is the reversible
way to stop fetching while retaining cached metadata. Only one Unspoken
process per database is supported for preview workers.


At startup, Unspoken corrects preview associations that point to mention,
hashtag, or inline-media links identified in retained original remote HTML
or structured tags. This repairs older cards whose profile URL differed from
an actor's canonical URL. It reselects the first eligible article link or
clears the association, without changing the shared cached metadata. Posts
without a preview remain untouched. This repair needs no schema change and
makes no network requests; corrected pending article previews use the normal
worker after startup.


## Home timeline boosts and replies

The home timeline includes replies from followed accounts even when their
parent posts or authors are unknown. It also includes public and unlisted
posts boosted by accepted follows, with attribution to the boosting account.
A newly received boost of an older post appears at the top. Multiple eligible
events for the same post collapse to its newest entry. Undoing a boost or
unfollowing its author removes that boost from the timeline; the original
post can remain if it is independently eligible.

Schema 6 adds application timeline event IDs so post and boost ordering share
a stable cursor. Existing posts and retained boosts are migrated in creation
time order. Home timeline cursor values from before this upgrade should be
replaced by opening the home page again. Other post URLs and collection
cursors continue to use their existing IDs.

For a followed account's boost of an unfamiliar post, the inbox preparation
fetches the original object and its author before opening a write transaction.
Only public or unlisted targets are retained. The fetched post, author, boost,
and timeline entry commit atomically. Replies do not require fetching an
unknown parent to appear in the home timeline. Take a consistent database
backup before this migration; older binaries require a compatible backup.

## Interface icons

UI icons use the symbol-only Nerd Fonts webfont, loaded from the official
[Nerd Fonts stylesheet](https://www.nerdfonts.com/assets/css/webfont.css),
with named `nf` classes as listed in its
[cheat sheet](https://www.nerdfonts.com/cheat-sheet). No font installation is
needed on the server or viewer's device. The stylesheet and font are loaded
from Nerd Fonts; a custom Content Security Policy needs to permit that
origin for styles and fonts.

## Importing follows

Import a plain-text list containing one `@user@domain` (or `user@domain`)
per line for an existing local account:

```sh
unspoken --config /etc/unspoken/config.yaml \
    --import-follows follows.txt --user YOUR_USERNAME
```

The command resolves accounts sequentially, pauses 250 ms between unique
entries, and exits after saving the follows. New remote follows are pending
until their servers accept them. Delivery uses the normal persisted job queue
and retry policy; keep the server running to deliver requests and receive
acceptances, or start it afterward to drain the queue. Local follows are
accepted immediately.

Existing accepted or pending follows, duplicate entries, and self-follows
are skipped. The import adds relationships without removing existing ones.
Blank lines and lines starting with `#` are ignored. Resolution or per-account
write failures are reported and do not stop later entries. The summary counts
queued, local, skipped, and failed entries; any failed entry produces a
nonzero exit status. Rerun the same file to retry failures without duplicating
successful follows. WebFinger resolution may still contact remote servers
when rerunning. Each new remote actor, pending follow, and delivery job is
committed together. Network resolution happens outside write transactions.

This command starts no HTTP server or workers, offers no dry-run mode, and
requires no additional database migration. Keep personal follow-list files
out of source control.
