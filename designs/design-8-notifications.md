# Design Document: Notification Timeline

**Status:** Implemented
**Scope:** A private, paginated list of recent interactions below the home
page's sidebar composer.
**Related designs:** [Architecture](design-0-architecture.md),
[Actors](design-4-actors.md), and
[Library integration](design-6-library.md).

## 1. Product decisions

Each local user receives notifications when another account replies to one
of their posts, likes it, boosts it, adds an emoji reaction, or follows
them. Both local and remote accounts can cause notifications. An action
on somebody else's post does not notify the viewer, even if the viewer
participated elsewhere in its thread. Self-interactions never notify.

The home page shows ten notifications at a time, newest first, below the
composer. Names link to profiles. Post references use short excerpts and
link to the corresponding post. A reply entry links to both the user's
original post and the reply. A follow entry has no post link.

Keep at most the newest 100 notifications per user, and show only entries
received within the last 30 days. These limits apply together: an entry
is removed when either limit excludes it. Removing a notification does
not remove the interaction that caused it.

Undoing an interaction removes its notification. Doing it again after
undo creates a new notification. Removing newer entries does not restore
older entries discarded by retention. Notifications describe recent,
currently existing interactions rather than an immutable audit log.

Initial exclusions:

- Mentions outside replies, direct-message alerts, follow requests, and
  follow acceptance alerts.
- Read/unread state, badges, grouping, email, browser push, and live polling.
- A separate notifications page or public ActivityPub collection.
- Backfilling existing posts and interactions when upgrading.

The page refreshes through ordinary server-rendered navigation. The list
is available only to its logged-in owner. Existing interaction permissions
and federation validation continue to determine which actions are accepted.

## 2. Existing code and architectural boundaries

The feature upgrades application schema **6 to 7**, building on stored
home timeline events. The protocol
schema's version is independent.

| Area | Current behavior | Change |
| --- | --- | --- |
| `src/data.cpp` | Owns application SQL and delegates protocol interactions to `ap::Store` | Persist notifications in shared write transactions; add queries and retention |
| `src/service.cpp` | Creates local posts and interactions; renders authorized post and actor views | Record local notifications; assemble notification views |
| `lib/actpub/src/engine.cpp` | Applies remote interactions before calling the host application | Identify inbox, fetch, and repair callbacks |
| `src/federation.cpp` | `UnspokenApplication::apply()` projects accepted remote posts | Also record remote notifications |
| `src/app.cpp` | `handleIndex()` loads the main timeline | Load the viewer's independent notification page |
| `templates/index.html` | Includes the composer directly in `main` | Wrap composer and notifications in a sidebar |
| `themes/light/style.css` | Places the direct child composer in a desktop grid | Place the sidebar wrapper instead |
| `static/style.css`, `themes/plain/1-style.css` | Supply other presentation paths | Style the same semantic markup |

Local `DataSourceSQLite::addLike()`, `addBoost()`, `addReaction()`, and
`addFollow()` delegate to `ap::Store`. Remote inbox processing calls that
store directly. Adding notifications only to application data wrappers
would therefore miss remote interactions.

Keep notification policy in the application. Rely on existing inbox
receipt handling and interaction deduplication. The notification table's
source uniqueness constraints prevent duplicate entries while they are
retained. No additional interaction transition tracking or replay handling
is required for this feature.

## 3. Event semantics

| Kind | Recipient | Source identity | Removal |
| --- | --- | --- | --- |
| `REPLY` | Local author of the immediate parent post | Reply post ID | Reply or parent is deleted |
| `LIKE` | Local author of the liked post | `ap_likes.id` | Like or target post is deleted |
| `BOOST` | Local author of the boosted post | `ap_boosts.id` | Boost or target post is deleted |
| `REACTION` | Local author of the reacted-to post | `ap_reactions.id` | Reaction or target post is deleted |
| `FOLLOW` | Local followee | `ap_follows.id` | Follow is removed or becomes pending |

Reply notifications require a parent already retained in `posts`, with a
local author. Notify only the immediate parent author, once. A reply to a
remote post does not notify unrelated local participants. An unknown
parent produces no notification and no deferred backfill.

Only accepted follows notify. Recording an accepted follow uses its
existing source ID, with the notification table enforcing uniqueness. Following a remote
account cannot notify a local recipient. Importing a user's follow list
does not manufacture notifications. Its local import path writes the
restored relationship directly through the data layer, while remote
imports create pending follows with no local notification recipient.

Different emoji from the same actor produce separate reaction entries.
Repeating the same emoji while that reaction exists does not. For custom
emoji, display the existing shortcode as text in this first version.
This avoids adding image fetches or persisting a second copy of emoji
metadata. Unicode emoji display as text too.

A reply edit does not create a notification or refresh its order. If an
edit changes its parent URI, remove the old reply notification and do not
create one for the new parent. Visibility changes are checked again at
render time. Other post edits may change the displayed excerpt.

## 4. Application database model

Create `notifications` after the protocol tables exist:

```sql
CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    kind INTEGER NOT NULL CHECK(kind IN (0, 1, 2, 3, 4)),
    actor_uri TEXT NOT NULL,
    post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
    reply_post_id INTEGER UNIQUE
        REFERENCES posts(id) ON DELETE CASCADE,
    like_id INTEGER UNIQUE
        REFERENCES ap_likes(id) ON DELETE CASCADE,
    boost_id INTEGER UNIQUE
        REFERENCES ap_boosts(id) ON DELETE CASCADE,
    reaction_id INTEGER UNIQUE
        REFERENCES ap_reactions(id) ON DELETE CASCADE,
    follow_id INTEGER UNIQUE
        REFERENCES ap_follows(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    CHECK (
        (kind = 0 AND post_id IS NOT NULL
            AND reply_post_id IS NOT NULL AND like_id IS NULL
            AND boost_id IS NULL AND reaction_id IS NULL
            AND follow_id IS NULL)
        OR
        (kind = 1 AND post_id IS NOT NULL
            AND reply_post_id IS NULL AND like_id IS NOT NULL
            AND boost_id IS NULL AND reaction_id IS NULL
            AND follow_id IS NULL)
        OR
        (kind = 2 AND post_id IS NOT NULL
            AND reply_post_id IS NULL AND like_id IS NULL
            AND boost_id IS NOT NULL AND reaction_id IS NULL
            AND follow_id IS NULL)
        OR
        (kind = 3 AND post_id IS NOT NULL
            AND reply_post_id IS NULL AND like_id IS NULL
            AND boost_id IS NULL AND reaction_id IS NOT NULL
            AND follow_id IS NULL)
        OR
        (kind = 4 AND post_id IS NULL
            AND reply_post_id IS NULL AND like_id IS NULL
            AND boost_id IS NULL AND reaction_id IS NULL
            AND follow_id IS NOT NULL)
    )
);

CREATE INDEX idx_notifications_recipient
    ON notifications(recipient_user_id, id DESC);
CREATE INDEX idx_notifications_expiry
    ON notifications(created_at, id);
CREATE INDEX idx_notifications_post ON notifications(post_id);
```

Assign stable C++ values `REPLY = 0`, `LIKE = 1`, `BOOST = 2`,
`REACTION = 3`, and `FOLLOW = 4` in `NotificationKind`. Reject unknown
integers when decoding rows. SQL constraints ensure exactly the source
reference appropriate to that kind is present.

`post_id` is the recipient's original post. `reply_post_id` identifies the
incoming reply. Other source IDs identify the durable protocol row that
caused the entry. Unique constraints prevent two entries for one source.
Foreign keys remove notifications in the transaction that removes a
source or referenced post. Their implicit unique indexes also cover
source deletion lookups.

`actor_uri` stores identity, not a rendered name or profile URL. Resolve
current actor metadata at read time. Do not copy post content into this
table. That avoids stale text surviving deletion or a permissions change.
The reaction text comes from its referenced `ap_reactions` row.

`created_at` is server receipt/creation time in Unix seconds, never a
remote `published` value. Ordering uses `id`, including when multiple
entries have the same timestamp. SQLite's
[AUTOINCREMENT behavior](https://www.sqlite.org/autoinc.html) prevents a
deleted committed ID from being assigned to a later entry, preserving
cursor meaning after pruning.

The source rows already retain remote actors: follows, likes, boosts,
and reactions are considered by `Store::collectUnreferencedRemoteActors()`;
remote replies are retained by their application posts. Notifications
therefore need no additional actor pins. Actor metadata can still be
missing after unusual repairs; rendering has a fallback.

Add a cleanup trigger for accepted-to-pending follow transitions:

```sql
CREATE TRIGGER notification_follow_pending
AFTER UPDATE OF state ON ap_follows
WHEN NEW.state <> 'accepted'
BEGIN
    DELETE FROM notifications WHERE follow_id = NEW.id;
END;
```

The persisted state spelling matches `followStateToStr()`. Add an
`AFTER UPDATE OF in_reply_to_uri` trigger
on `posts` that deletes entries whose `reply_post_id = NEW.id` when
`OLD.in_reply_to_uri IS NOT NEW.in_reply_to_uri`. These triggers only
invalidate existing entries; notification creation remains explicit.

## 5. Recording notifications

### 5.1 Shared write boundary

Expose a documented application `DataSourceInterface::withWrite()` method
taking `const std::function<mw::E<void>()>&`. Its SQLite implementation
uses the existing `withDataWrite()` helper: start a retried IMMEDIATE
transaction when none exists, otherwise use a savepoint. SQL stays in the
data module. Callers never own a raw database handle.

A source mutation, its notification, and that recipient's pruning are one
operation. Any failure returns `mw::E<>` and rolls back all three. Do not
emit notifications after an independently committed interaction.

Retry callbacks must reread state on each attempt and keep output values
local until success. They must perform no network I/O. Notifications do
not change the existing transaction boundary between a local interaction
and scheduling its outbound delivery; that broader issue is separate.

### 5.2 Local interactions

Wrap `Service::setLike()`, `setBoost()`, `setReaction()`, and
`setFollowActor()` in `data.withWrite()`:

1. Apply the existing mutation.
2. For an enable operation, read the resulting source row to obtain its
   stable ID, using the existing relationship lookup methods.
3. Resolve the local recipient and record the notification, using the
   source-specific uniqueness constraint. Compare the actor URI with the
   recipient's exact canonical actor URI; skip equality. Only accepted
   follows qualify.
4. Prune that recipient before releasing the write boundary.

Disable operations delete the source as today. Cascades remove its
notification. A subsequent enable inserts a new source ID and may notify.

Wrap local `Service::createPost()` in the same write boundary, including
attachment association and reply notification creation. After inserting
a reply, load its parent and determine its local author. Use the current
permission helper to verify that the recipient can view the reply before
recording it. The data recording method rechecks parent ownership; foreign keys validate
source references inside the transaction.

### 5.3 Callback origin

Add an `AppliedOrigin` enum to `ap::AppliedEvent`, distinguishing `INBOX`,
`FETCH`, and `REPAIR`. This lets the application avoid notifications for
historical data loaded by background work. Existing synthetic Create
events for fetched objects use `FETCH`; historical reaction repair
callbacks use `REPAIR`.

Set origin explicitly at every `application.apply()` call site. The
existing `global_effect` guard continues to identify callbacks that apply
the activity's global effects. Leave protocol interaction application,
receipt handling, and automatic Follow responses unchanged.

### 5.4 Remote application projection

In `UnspokenApplication::apply()`:

1. Preserve the existing `global_effect` guard.
2. Handle Like, Announce, EmojiReact, and Follow activities before the
   current post-only Create/Update/Delete branch.
3. For origin `INBOX`, resolve the saved source row and its recipient.
   Only accepted follows qualify. Never trust an arbitrary recipient in
   JSON to choose the local notification owner.
4. Use the same self-interaction and visibility checks as local creation.
   Record and prune within the transaction passed by the library.
5. For a real inbox Create that inserts a new application reply, record
   its reply notification after recipients and attachments are saved.
6. Fetch and repair origins may update application state but do not
   generate notifications. Updates never generate reply notifications.

Use shared `Service::notifyInteraction()` and `notifyReply()` helpers for
recipient selection and recording. Federation callbacks construct a Service
with an empty in-memory emoji registry; recording does not use emoji data
or perform a filesystem scan. This reuses existing authorization without
a second notification-specific permissions system.

The callback's notification failure must propagate. The library then
rolls back protocol state, application projection, and receipt together,
allowing normal retry. Do not swallow that failure and acknowledge a
partially applied activity.

### 5.5 Undo and deletion

Source foreign keys perform ordinary undo cleanup. Keep the library's
existing actor and original-activity matching checks: a stale Undo must
not remove a replacement interaction's notification. The application must
not issue a broad delete merely because raw input contains an Undo.

Deletion of a reply removes its entry. Deletion of the original local
post removes all notifications referring to that post. Repeated deletion
is harmless. User deletion cascades through recipient ownership.

## 6. Data and service interfaces

Add the following application types in `src/structs.hpp`:

- `NotificationKind`: the stable values from section 4.
- `Notification`: all persisted fields, with optional source references.
Reuse the existing `Cursor` type for optional `max_id` or `min_id`, never
both. `Service::notificationPage()` returns render-ready JSON containing
entries, `has_older`, `has_newer`, and outgoing cursor IDs. Its implementation
lives in `src/notifications.cpp` alongside the shared recording helpers.

Keep proposed public interfaces intention-commented, for example:

```cpp
// Record an interaction after checking recipient and references.
virtual mw::E<void> recordNotification(
    const Notification& notification) const = 0;

// Read one owner's bounded unexpired history, newest first.
virtual mw::E<std::vector<Notification>> notificationsFor(
    int64_t user_id, int64_t now_seconds) const = 0;

// Remove at most batch_size expired entries across all recipients.
virtual mw::E<int64_t> pruneExpiredNotifications(
    int64_t now_seconds, int batch_size) const = 0;
```

`recordNotification()` joins the surrounding write boundary, verifies
local post ownership, and enforces source references through foreign keys.
The service resolves the matching source and recipient before recording.
Insertion uses a source-specific conflict target with `DO NOTHING`, then
prunes.
Other constraint errors must propagate. Do not use `INSERT OR REPLACE`,
which would replace IDs and change pagination order.

Add `Service::notificationPage(viewer, cursor, now_seconds)` to authorize,
resolve actors/posts, and build the final page. Keep fixed initial defaults
as application constants: `NOTIFICATIONS_PER_PAGE = 10`,
`MAX_NOTIFICATIONS_PER_USER = 100`, and
`NOTIFICATION_RETENTION_SECONDS = 2592000`. No new config keys are needed.

## 7. Retention and maintenance

On recording a notification, use one captured server time and perform:

```sql
DELETE FROM notifications
WHERE recipient_user_id = ? AND created_at < ?;

DELETE FROM notifications
WHERE recipient_user_id = ? AND id IN (
    SELECT id FROM notifications
    WHERE recipient_user_id = ?
    ORDER BY id DESC LIMIT -1 OFFSET 100
);
```

Bind the cutoff as `now_seconds - 2592000`. An entry exactly at the cutoff
is retained. The second statement keeps the highest 100 IDs, which are
the newest locally recorded events. The per-user index bounds the normal
work to roughly 101 rows. Reads apply the same age cutoff independently,
so a quiet user's expired notifications disappear immediately from the UI.

Add bounded global expiry cleanup to worker zero's existing hourly
maintenance block, before remote actor collection. Select expired IDs
using `ORDER BY created_at, id LIMIT ?` and delete that batch. Use
`config.maintenance_batch_size`. Run one startup batch too. Remaining
batches are removed on
subsequent maintenance passes; physical age cleanup can lag under a large
backlog, but read filtering and per-user count bounds remain effective.

Log the number removed at info level only when positive. Log maintenance
failures and retry on the next pass; a cleanup failure must not terminate
request handling. No separate worker or federation job type is necessary.

Rows deleted from SQLite may leave reusable database pages. Retention
bounds live rows; it does not promise immediate reduction of the database
file or erase historical backups. Do not run VACUUM in a request.

## 8. Authorization and view construction

Load only rows where `recipient_user_id == viewer.id`. User identity comes
from the authenticated session, never a query parameter. For each entry:

1. Resolve the actor locally or from cached remote actor metadata, reusing
   the identity rules in `followViews()` and caching within the response.
2. For post-related entries, load the target and call `canViewPost()`.
3. For replies, authorize the reply too. Omit the whole entry if either
   post is missing or unreadable. Other kinds need only the target check.
4. Resolve reaction text from its source row. Missing sources are omitted
   defensively even though normal foreign keys prevent them.
5. Build excerpts only after authorization. Extract plain text from
   sanitized HTML, decode entities, collapse whitespace, and truncate at
   80 Unicode code points with an ellipsis. Never slice UTF-8 bytes.
6. Use a plain-text content warning instead of body text when present.
   For a sensitive post without a warning, use “sensitive post”. Empty or
   media-only content uses “your post” or “reply”.
7. Escape all resulting text and link attributes according to the
   existing Inja view-model convention, exactly once. Do not insert raw
   actor names, summaries, emoji, or excerpts as trusted HTML.

Use local application `/p/<id>` links for retained posts, including remote
replies, so existing authorization and thread rendering apply. Local
profiles use `/u/<username>`. Cached remote profiles use their validated
HTTP(S) actor URI; a missing cache falls back to the validated URI as the
label and destination. If no safe destination exists, render plain text.
Rendering must perform no server-side fetching.

A notification view contains `id`, `kind`, `actor` (name and profile URL),
optional `post` and `reply` (excerpt and local URL), optional `emoji`,
`created_at`, and a formatted timestamp. Choose verb text in the template
from a fixed kind mapping. For example:

- “[Ada] liked your post [A walk by the river…]”
- “[Ada] boosted your post [A walk by the river…]”
- “[Ada] reacted with ❤️ to your post [A walk by the river…]”
- “[Ada] replied to your post [A walk by the river…]: [I was there too…]”
- “[Ada] followed you”

Brackets here identify links, not literal output. Use semantic list items
and a `time` element with a machine-readable UTC datetime. Screen readers
should hear the whole sentence in its natural reading order.

## 9. Independent cursor pagination

Add `notifications_max_id` and `notifications_min_id` to the existing home
page query. IDs must parse completely as positive signed 64-bit integers;
reject overflow, malformed values, repeated notification cursor keys, or
both directions together with HTTP 400. An absent cursor requests latest.
A valid cursor need not identify a currently retained row.

The database reads at most 100 unexpired entries for the owner in descending
ID order. The service applies cursor bounds after visibility filtering:
older entries have `id < max_id`; newer entries have `id > min_id`.
For newer navigation, take the nearest ten matching entries rather than
jumping to the newest page. Display every page newest first.

Authorization may omit rows. Since an owner has at most 100 saved entries,
loading the complete bounded history lets the service filter first and
then take the nearest ten visible entries. Use the same
bounded visible set to determine whether any older/newer entries exist;
raw row count is not enough. Outgoing older cursors use the last displayed
ID; newer cursors use the first displayed ID.

For an empty cursor page after deletion or expiry, show “No notifications
on this page” and a latest link. The default empty page says “No recent
notifications.” Expiration and undo can create gaps, so this is a moving
list rather than a historical snapshot. Never reuse IDs or fall back to
SQL OFFSET pagination.

Notification pager URLs preserve the validated main timeline `max_id` or
`min_id`; main timeline pager URLs preserve the validated notification
cursor. Build links with an encoded query builder and the configured site
root, without copying arbitrary query parameters. Use a sidebar fragment
such as `#notifications` for its links, with `#timeline` for main paging.
“Latest notifications” clears only notification cursors.

Anonymous home requests render no notification section. Do not load
notification data for them. Authenticated home responses containing this
list must send `Cache-Control: private, no-store`.

## 10. Template and theme layout

In `templates/index.html`, replace the direct composer include with:

```html
<aside class="sidebar" aria-label="Posting and notifications">
  {% include "_composer.html" %}
  {% include "_notifications.html" %}
</aside>
```

Place the notifications section at `id="notifications"` with its own
heading, semantic list, empty state, and Older / Newer / Latest links.
Keep its context under `notifications` rather than reusing the main
`posts`, `has_more`, or `next_max_id` variables.

Update the light theme's `main:has(> .composer:not(.reply))` grid selectors
to target `main:has(> .sidebar)`, placing that wrapper in column one.
Keep the page title and a wrapper containing the timeline plus its pager in
column two. Keeping that pager inside the wrapper prevents the sidebar's
height from separating it from the posts. Update child input width
rules for the new nesting. The wrapper stacks composer then notifications.

Do not make the whole sidebar sticky: ten notifications plus a composer
can exceed viewport height. Use ordinary document scrolling so every
entry and pager remains reachable. On narrow screens, put composer and
notifications before the timeline in document flow. Use the same flow in
the plain and fallback themes. Do not change thread reply composers, which
use `.composer.reply` and are outside this initial home-page feature.

Keep names and excerpts wrappable, including long unbroken strings. Links
must have visible keyboard focus. The list requires no JavaScript and no
new external font, image, or styling framework.

## 11. Migration and rollout

Implement `migrate6To7()` using the existing data write helper. Create the
table, indexes, and cleanup triggers, then advance `PRAGMA user_version`
in the same transaction. Failure leaves the database at version 6.

Update `CURRENT_SCHEMA_VERSION`, version dispatch, and the fresh-database
path. Fresh initialization currently builds an application schema, imports
the library tables, and applies later application migrations inside an
outer write boundary. Run this migration after `migrate5To6()` and after
`ap_*` tables exist; do not accidentally start a nested IMMEDIATE
transaction. Existing version 1 fixtures must still migrate through every
step successfully.

Start with an empty notification table. Existing likes and follows remain
active and are not scanned for backfill. Normal interaction handling and
incoming replies start populating the list.
No network backfill or schema changes to protocol tables are needed.

The callback origin addition changes the library source API, not its schema.
Update all aggregate initializers, mocks, engine tests, and application
implementations together. Keep event types documented in
`lib/actpub/include/actpub/engine.hpp`.

## 12. Verification

Add meaningful cases to the existing suites rather than testing only that
view-model fields mirror database columns.

### Database and transaction tests

- Fresh creation and upgrades from versions 1 and 6 reach version 7;
  existing users, sources, posts, and home timeline events are preserved.
- Invalid kind/source combinations fail. Duplicate source IDs do not
  replace a notification or change its cursor.
- An injected notification or pruning failure rolls back the local
  source mutation. An outer inbox rollback removes both source and entry.
- Every source FK removes only its matching notification. Reply and parent
  deletion, follow pending transition, and reply reparenting clean up.
- Inserting 101 entries leaves the newest 100 for that user and preserves
  another user's rows. Removing a newer entry does not restore discarded
  entries. Test the exact 30-day boundary and bounded global expiry.

### Library and federation tests

- Like, Announce, EmojiReact, and accepted Follow callbacks record the
  correct source and recipient without changing existing protocol behavior.
- A valid activity delivered to multiple local inboxes notifies only its
  actual local target owner once.
- Undo removes the notification; a later new interaction can notify again.
- A stale Undo for an older activity cannot remove a replacement entry.
- Real inbox replies notify; synthetic fetches and reaction repair do not.
  A failed notification write rolls back its inbox receipt and retries.

### Service, route, and rendering tests

- Each kind produces the correct recipient and links. Self-actions and
  replies to remote or unknown parents do not notify a local bystander.
- Two users cannot see each other's entries through cursor manipulation.
- A direct reply unreadable by the parent author produces no entry;
  later access loss hides an existing entry and all of its excerpts.
- Content warnings, sensitive and media-only posts, Unicode truncation,
  malicious actor text, and unsafe profile URLs render safely.
- Notification creation and rendering require no network requests.
- Older and newer pagination remains correct with equal timestamps,
  deleted IDs, expired entries, invisible replies, and concurrent inserts.
  Main and notification cursor links preserve each other independently.
- Anonymous requests omit the list; authenticated responses disable shared
  caching. Empty stale pages retain a working latest link.

Manually inspect light, plain, and fallback themes at desktop and narrow
widths. Verify long names, keyboard access, full sidebar reachability, and
that thread reply composers retain their layout.

For implementation, build with `cmake --build build -j24` and run the
relevant `unspoken_test` cases through CTest, followed by the complete
existing suite once the focused checks pass. This document itself does
not require a compilation.

## 13. Implementation sequence and acceptance

1. Add callback origin metadata and regression tests, preserving
   receipt, replay, and Follow response behavior.
2. Add schema migration, typed recording/query methods, shared application
   write boundaries, and retention tests.
3. Connect local service mutations and remote application projections.
   Verify transaction rollback before adding presentation.
4. Add authorized view construction and independent index-page cursors.
5. Add the notification partial, sidebar wrapper, and theme adjustments.
6. Connect startup/hourly expiry maintenance and run integration checks.

The feature is ready when another account's new accepted interaction
appears once below the composer with working identity/post links, paging
leaves the main timeline position intact, undo and deletion remove the
entry, privacy checks prevent hidden content from appearing, and each
user's visible history satisfies both retention limits.

The protocol's expected Undo identity checks are described in the
[ActivityPub inbox Undo section](https://www.w3.org/TR/activitypub/#undo-activity-inbox).
The SQL cleanup behavior depends on enabled
[SQLite foreign keys](https://www.sqlite.org/foreignkeys.html); all current
application and worker connections must continue enabling them.

The default theme is `light`, which inherits both `plain` stylesheets.
The compatibility stylesheet uses the `plain` theme. The desktop grid
gives the main timeline its content height
so a tall notification sidebar does not push its pager downward.
