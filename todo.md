# TODO

## Avoid permanent actor-cache growth from irrelevant inbox traffic

The production-derived v1 migration fixture showed 4,330 cached
`remote_actors` rows on a small test instance with about 10 local posts.
Most cached actors were from `mastodon.social`, and the `seen_activities`
table had a similar row count. Recent activity IDs were mostly unrelated
`#delete` activities.

Root cause: incoming HTTP signatures are verified before activity
dispatch. If the signer actor is unknown,
`verifyHttpSignatureWithKeyRefresh()` resolves and persists that actor so
the signature can be checked. Dispatch can later ignore a `Delete` for an
unknown object, but the signer actor has already been permanently cached.

Investigate a non-persistent verification path for irrelevant inbound
activities:

- Fetch enough actor/key material to verify the HTTP signature without
  necessarily writing `remote_actors`.
- Dispatch the activity.
- Persist the actor only when the activity creates or updates local state
  that needs the actor later, such as known posts, follows, interactions,
  deliveries, or actor updates.
- Preserve key-refresh behavior for actors that are already cached.
- Keep security properties intact: do not trust activity contents before
  signature verification, and keep signed GET / SSRF protections.

This should be designed carefully because `remote_actors` currently acts
as both the actor profile cache and the HTTP-signature key cache.
