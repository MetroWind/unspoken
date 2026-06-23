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
- `template_dir`: `templates`.
- `static_dir`: `static`.
- `posts_per_page`: `20`.
- `http_signature_skew_seconds`: `300`.
- `thread_fetch_max_depth`: `20`.
- `sqlite_busy_timeout_ms`: `5000`.
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
template_dir: /usr/share/unspoken/templates
static_dir: /usr/share/unspoken/static

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
