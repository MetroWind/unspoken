# Design Document: Stored Link Previews

**Status:** Draft
**Scope:** Fetch and store at most one link preview for each locally
created or retained remote post, then render that preview in the web UI.
**Related designs:** [Architecture](design-0-architecture.md),
[Library integration](design-6-library.md), and
[Timeline avatars](design-5-avatars.md).

## 1. Decisions and requirements

A post has zero or one preview. A preview contains a destination URL,
plain-text title, optional description, and an optional
remote image URL that the browser loads directly. Multiple posts can reference the same cached
preview. The schema therefore adds one `link_previews` table and one
nullable `posts.link_preview_id` foreign key. There is no association table.

Both local publication and remote post persistence schedule previews.
Fetching runs after commit, outside request handling and inbox processing.
Rendering reads saved metadata without server-side fetching. The browser
may contact the remote image host to display the card image.
Failure to fetch a preview leaves an ordinary clickable link in the post.

This design includes followers-only and direct posts. Fetching their links
reveals the requested URL and the server's network address to the
website, even if nobody clicks the link. Requests carry no post body,
author identity, recipient list, viewer credentials, or federation
signature. Card metadata is rendered only where the viewer can read its
post. Images are third-party resources, not access-controlled copies held
by Unspoken. Their hosts receive viewer IP addresses and request timing;
this is an accepted product tradeoff.

The initial feature is a static card. It does not execute JavaScript,
embed players, use oEmbed HTML, expand shortened links in post content,
or modify outgoing ActivityPub documents. Existing posts do not trigger
automatic backfill on deployment. A deliberate backfill can be added
later using the same selection and scheduling functions.

Values below are proposed implementation defaults, rather than existing
configuration or behavior. They make the draft implementable without
requiring further policy decisions during coding.

## 2. Current code and integration boundaries

The application owns posts and presentation. The ActivityPub library owns
protocol persistence and its worker queue. The feature belongs to the
application, with these integration points:

| Area | Existing code | Required change |
| --- | --- | --- |
| Local creation | `Service::createPost()` in `src/service.cpp` | Associate a selected URL as part of post persistence |
| Remote retention | `UnspokenApplication::apply()` in `src/federation.cpp` | Associate previews when an accepted activity creates or updates a post |
| Other retention paths | `DataSourceSQLite::insertPost()` and `updatePost()` | Centralize association so fetched thread/search posts also work |
| Database | `src/data.cpp`, schema version 4 | Add application migration 4 to 5 |
| Workers | `App::jobWorker()` in `src/app.cpp` | Add a separate application preview worker lifecycle |
| View models | `Service::postView()` and `postViews()` | Resolve saved preview data after post authorization |
| Templates | `templates/_post.html` | Include a shared preview partial |

`runFederationJobOnce()` delegates SQLite work to `ap::Session::runOnce()`.
That library worker recognizes `deliver` and `fetch_thread`; unknown kinds
fail. Enqueuing a `fetch_preview` job in `ap_jobs` alone would therefore
break. Do not extend the protocol library merely to fetch HTML cards.

Use an application-owned in-memory queue and one dedicated preview worker.
The preview table records only cached data and whether fetching is pending
or finished. Startup and periodic recovery scans enqueue referenced pending
rows. Do not change the federation queue or persist preview job tracking.

`insertPost()` already participates in transaction handling. Association
must join its active transaction, including an inbox transaction managed
by `ap::Session`; it must never commit that outer transaction itself.

## 3. Selecting the one URL

Selection operates on the final rendered and sanitized `content_html`,
not on raw Markdown, ActivityPub JSON, or a regular expression over HTML.
This gives local and remote posts the same interpretation of links.

Use libxml2, already linked by the application, to parse the fragment
without external resource loading. Walk anchor elements in document
order. Choose the first eligible `href` and stop. A failed preview does
not advance selection to a later link: otherwise availability and timing
would change which destination a post appears to endorse.

An eligible link must meet all of these conditions:

1. It is an absolute HTTP or HTTPS URL with a host and without URL
   credentials.
2. Its port is absent or the default for its scheme (80 for HTTP, 443 for
   HTTPS). Other ports are unsupported in this version.
3. Its serialized length is at most 4096 bytes.
4. It is not on the Unspoken origin, and is not the post's own canonical
   URI. This avoids turning navigation links into cards or fetching self.
5. The anchor is not marked as a mention or hashtag. Inspect `rel="tag"`,
   `mention`, and `hashtag` class tokens when present. Also exclude URLs
   identified by the post's structured mention and hashtag data before
   sanitization discards those markers. Keep this selection context with
   the insertion/update call; it is transient, not another database table.
6. It is not one of the post's attachment URLs or an anchor wrapping an
   inline image. A remote media file is handled as an attachment instead.

Do not reject a normal article merely because its visible text starts
with `@` or `#`. Classify structured mentions and tags by their URLs and
HTML markers, rather than guessing from display text.

Normalize using `mw::URL`: lowercase scheme and DNS host, remove an
explicit scheme-default port (80 for HTTP, 443 for HTTPS), and discard
the fragment. HTTP and HTTPS URLs remain distinct cache keys. Preserve
path case,
query order, query parameters, trailing slashes, and percent-encoded path
semantics. Do not remove tracking parameters in this feature. They may be
significant to the destination. Fragment-only distinctions do not create
separate cache entries because fragments are not sent in HTTP requests.

The normalized selected URL is the cache key and card destination. Neither
`og:url` nor an HTML canonical link replaces it. Redirect targets are
kept only during fetching for relative URL resolution; they do not merge
otherwise different cache keys or add stored fields.

An ineligible or malformed link is skipped. No eligible link means a NULL
preview reference and no worker job. Bound traversal to the post's
already enforced content-size limit. URL selection performs no network I/O.

## 4. Database model and migration

Create the following application-owned table. Store status as an integer
with an explicit, stable mapping to the C++ `PreviewStatus` enum.

```sql
CREATE TABLE link_previews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    title TEXT,
    description TEXT,
    image TEXT,
    status INTEGER NOT NULL DEFAULT 0
        CHECK(status IN (0, 1, 2, 3))
);

ALTER TABLE posts ADD COLUMN link_preview_id INTEGER
    REFERENCES link_previews(id) ON DELETE SET NULL;

CREATE INDEX idx_posts_link_preview ON posts(link_preview_id);
CREATE INDEX idx_link_previews_status ON link_previews(status, id);
```

These are the five preview data columns plus one status column. `title`
and `description` are plain UTF-8 text, not escaped HTML. `image` is an
optional absolute HTTP(S) URL selected from the page metadata. It is never
a local filename or downloaded image. Site/domain display is derived from
`url`; image dimensions and alternative text are not persisted. Use empty
image alternative text because the card already provides its title.
Image URLs are web UI data and are not added to ActivityPub objects.

Status mapping and meanings:

- `0` / `PreviewStatus::PENDING`: fetching has not completed. This includes queued work,
  currently running work, and retries waiting in memory.
- `1` / `PreviewStatus::READY`: usable metadata was saved, optionally with an image.
- `2` / `PreviewStatus::UNAVAILABLE`: fetching completed but the URL is unsuitable or has no
  useful metadata. Startup must not retry it.
- `3` / `PreviewStatus::FAILED`: transient retries were exhausted. Startup must not retry it.

Assign these numeric values explicitly in the enum declaration. Do not
renumber or reuse persisted values when adding statuses. Validate database
integers when decoding; an unknown value returns an error rather than
being silently cast to an enum. Names such as pending and ready below
refer to these integer values.

There is no persisted fetching state, lease, ownership token, attempt
counter, retry deadline, error text, or cache timestamp. In-memory worker
coordination handles ownership within the single Unspoken process.

NULL `link_preview_id` means the post has no selected preview URL. A
reference to a pending or unsuccessful preview renders no card. The
association also records the selected URL, so the post needs no second
selected-URL column.

On a fresh database, create the table before creating `posts` with the new
column. On an existing database, execute migration 4 to 5 transactionally.
Old rows retain NULL, making the upgrade fast and avoiding a fetch storm.
Update `Post`, `NewPost` where appropriate, explicit SQL column lists,
`rowToPost()`, insert/update bindings, mocks, and fixtures together. Inspect
all fixed-order tuple decoders; adding a SQL column without changing the
matching decoder can silently misassign fields.

Foreign keys are already enabled on application connections. Keep that
behavior for worker connections too. SQLite documents enforcement and
nullable references in its [foreign key guide](https://www.sqlite.org/foreignkeys.html).
Only the application schema version changes; `ap_schema` does not.

## 5. Transactional scheduling and lifecycle

### 5.1 New posts

Before writing, extract the selected URL from the final content and the
transient mention/attachment exclusion context. Within the post write
transaction:

1. If there is no selected URL, insert the post with a NULL reference.
2. Otherwise insert the preview row with `ON CONFLICT(url) DO NOTHING`.
3. Read its ID and status. Reuse existing completed results, including
   unsuccessful results, without scheduling another fetch.
4. Set `posts.link_preview_id` to that ID.
5. Commit together with the post and other host-side effects.
6. After the outermost transaction commits, wake the preview worker.
   The worker scans committed pending rows rather than accepting
   uncommitted post data. A periodic scan covers a missed wakeup or a
   crash between commit and notification. Never enqueue from an inbox
   apply callback as though its surrounding transaction had committed.

Database failures propagate through `mw::E<>` and roll back the transaction.
A network failure cannot roll it back because fetching has not started.
A duplicate inbox delivery that creates no post schedules no extra work.
All remote retention paths, including thread fetches and explicitly fetched
posts, use the same association helper.

### 5.2 Edits and deletion

An edit repeats selection. If the normalized URL is unchanged, retain the
association and cached result. If changed, associate the new row in the
same transaction that updates content. If removed, clear the foreign key.
Do not mutate the old shared preview just because one post changed links.

Deleting a post removes only its reference. Workers recheck references
before fetching and before committing results. If a URL becomes
unreferenced during a fetch, the worker may discard the result. Fetched
metadata is discarded, and unused cache rows become eligible for collection.
A worker updates a preview row, never a post ID from a stale job payload,
so an edit cannot receive the wrong card when an older fetch finishes.

### 5.3 Cache reuse

There is no automatic expiry or refresh in this version. A URL reuses its
saved result for as long as its preview row exists. New posts sharing a
failed or unavailable URL do not repeatedly contact that website. Changing
a post to a different normalized URL selects a different cache entry.
A future explicit refresh feature can reset a row to pending, but is not
part of the initial implementation. Stale website metadata is an accepted
tradeoff of this simpler cache.

## 6. In-memory queue, retries, and restart recovery

Add `src/link_preview.hpp` and `src/link_preview.cpp`. Start one dedicated
preview worker alongside federation workers, with its own SQLite
connection and HTTP session. Keep its queue bounded at 1000 distinct IDs.
A mutex-protected set covers both queued and running IDs, preventing the
same preview from being fetched twice in this process. Delayed retries
stay in that set until completion. Use a condition variable to wake on new
work, the earliest retry deadline, or shutdown; do not block publication.

For each queued ID:

1. Read the committed row and confirm it is still pending and referenced
   by a post. Discard missing, terminal, or unreferenced work.
2. Fetch outside a database transaction. Keep attempt counts and retry
   times only in memory.
3. Save metadata, remote image URL, and terminal status together in a short
   transaction, checking that the row still exists, is pending, and is
   referenced. Do not update a post's association from a queued ID.
4. Remove the ID from the queued/running set only after a successful
   terminal database write or confirmation that the work is obsolete.
   If saving fails, retain/reschedule the work; do not lose its wakeup.

At startup, after migrations and before ordinary queue processing, scan
referenced pending rows in ID order and enqueue up to available capacity.
Repeat the scan every 30 seconds and whenever capacity becomes available.
This bounds startup memory, recovers work missed by a notification, and
avoids starving a large backlog. Do not scan ready, unavailable, or failed
rows into the queue. Pending rows already queued, running, or delayed for
retry are excluded through the in-memory set.

A crash loses queue contents, retry deadlines, and attempt counts. The
row remains pending until the result is committed, so a later startup
retries it. It may refetch a URL that succeeded over the network just
before the crash. Repeated crashes can restart the retry budget. These
are intentional tradeoffs; previews do not require exactly-once fetching.
No browser visit or new federation delivery is needed to recover pending
rows. Existing pre-feature posts with NULL associations are not backfilled.

Choose at most three attempts during one process lifetime, with retry
delays of 30 seconds then five minutes. Retry connection failures,
timeouts, HTTP 408, 429, and 5xx. Honor an integer `Retry-After` within a
maximum one-hour delay. Exhaustion writes failed. Other 4xx, invalid
metadata, denied addresses, excessive redirects, and unsupported formats
write unavailable. Neither terminal result is retried on restart.

Each attempt has a 30-second total deadline for fetching the HTML page,
a five-second connect timeout per request, and no more than five redirects
per fetch. Enforce decoded byte limits while streaming, including when
compression is enabled or Content-Length is absent. Shutdown stops
accepting work, interrupts or waits for the bounded active request, and
joins the worker before closing its database connection. Unfinished work
stays pending. This design supports one Unspoken process per database;
it does not coordinate preview fetches between multiple processes.

Queue capacity limits memory, not the number of saved pending rows. If
the queue is full, leave the committed row pending for a later scan.
Do not leave a post's association NULL merely because the queue is full.
With previews disabled, start no worker and schedule no new associations;
existing pending rows resume when the feature is enabled again.

## 7. Fetch policy

Use `mw::HTTPSession` and the existing resolved-address filtering mechanism.
Preview requests are unsigned website requests with an HTML-oriented
`Accept` header and a descriptive `Unspoken/<version>` user agent.
Use a fresh session for each attempt, with no cookie jar, authorization,
referer, or inherited federation headers. Disable environment-configured
proxies for these requests unless the address filtering contract is
explicitly preserved by a future proxy implementation.

Allow HTTP on port 80 and HTTPS on port 443 for page fetches and every
page redirect. Permit redirects in either direction between HTTP
and HTTPS, including HTTPS-to-HTTP redirects. An HTTPS page may also use
an HTTP image URL in its metadata. Every server-fetched destination still
undergoes URL and resolved-address validation; allowing HTTP does not
permit other URL schemes. Browser image loading follows the separate
policy in section 9.
Reject URL credentials, local origins, loopback, private, link-local,
multicast, unspecified, and metadata service destinations. Audit the
existing address helper for IPv4 unspecified addresses and IPv6-mapped
IPv4 handling before reuse. The new feature must not inherit development
private-host exceptions from federation configuration.

Follow redirects explicitly, validating the next resolved absolute URL
before opening its connection. This also gives a trustworthy final URL
for relative metadata links. Keep redirects disabled in libcurl while
following them at this layer. Validate actual resolved peer addresses on
every connection, not only hostnames before DNS resolution. For the
mechanism, see libcurl's [socket callback documentation](https://curl.se/libcurl/c/CURLOPT_OPENSOCKETFUNCTION.html)
and [protocol restrictions](https://curl.se/libcurl/c/CURLOPT_PROTOCOLS_STR.html).
The parser never fetches DTDs, stylesheet URLs, scripts, frames, or other
page assets, including preview images. Only the HTML document and its
redirects are fetched by the server.

## 8. HTML metadata extraction

Accept HTTP 200 HTML responses (`text/html` or
`application/xhtml+xml`) up to 1 MiB after decompression. Parse both using
libxml2's non-networking HTML parser rather than an XML parser that could
expand entities or load external subsets. Do not run page scripts or use a
headless browser. Handle HTTP charset declarations and HTML encoding hints
when supported by libxml2, and normalize the resulting text to UTF-8.

Read metadata from the head, with the following precedence:

| Field | First choice | Fallback |
| --- | --- | --- |
| Title | First nonempty `og:title` | HTML `title` text |
| Description | First nonempty `og:description` | `meta[name=description]` |
| Image | First usable `og:image` or `og:image:url` | None |

Attribute names and metadata keys match case-insensitively. Decode HTML
entities, collapse whitespace, remove control characters, and truncate at
UTF-8 boundaries: title 300 characters and description 500 characters.
An absent title means unavailable; an absent description or image still
allows a useful text card. Do not fall back to a page's full body text.

The [Open Graph specification](https://ogp.me/) defines the source fields
and structured image properties. The initial schema stores only title,
description, and image; ignore site-name and image-description metadata.
Use empty image alternative text because the card title identifies it.

Resolve relative image references against the final fetched page URL.
Ignore HTML `base` and alternate canonical URLs in this version. Choose
at most one valid image URL; missing or invalid URLs leave a text card. Never use
`og:video`, `og:audio`, script-generated data, or externally supplied HTML.
A browser image-loading failure does not trigger another metadata fetch.

## 9. Browser-loaded images

Store the selected image URL rather than fetching or processing its bytes.
There is no image decoder dependency, thumbnail directory, file cleanup,
or Unspoken image-serving route. The metadata worker does not perform
HEAD or GET requests to check whether the image exists.

Before storage, resolve relative references against the final page URL and
validate the URL structurally: absolute HTTP or HTTPS, a host, no URL
credentials, at most 4096 bytes, and default port for its scheme. Reject
literal local/private/reserved IP addresses, localhost names, and the
Unspoken origin. Do not accept data, file, javascript, or blob URLs.
Revalidate stored values when building the view model so malformed legacy
or manually edited data cannot become an unsafe attribute.

These checks do not provide the server fetcher's address guarantees for
browser-loaded images. DNS resolution, image redirects, final resource
type, download size, and decoding happen in the viewer's browser. A
remote host can change these later. Do not describe remote images as
validated raster bytes or claim that CSS limits their download size.

Render images with `loading="lazy"`, `decoding="async"`, empty `alt`, and
`referrerpolicy="no-referrer"`. No-referrer suppresses the referring page
URL; it does not hide the viewer's IP, request timing, or cookies the
browser permits for that image host. Do not preconnect or preload image
hosts. A lazy image hidden by a content warning may still be requested
according to browser behavior; the disclosure is a display control, not
a guarantee that no third-party request happens before expansion.

Use a bounded image box with preserved aspect ratio and `object-fit:
contain`. Broken, blocked, or slow images must leave the title, host, and
link usable. Prefer a fixed neutral image area over adding script solely
to detect image errors. Image hosts may change or remove content after
metadata is cached; this is accepted in the initial design.

HTTP image URLs remain HTTP in storage. On HTTPS Unspoken pages, browsers
may upgrade or block them under mixed-content rules. Do not promise that
every HTTP image will display, silently rewrite stored URLs to HTTPS, or
introduce a proxy fallback. The card remains useful without its image.

Ensure any Content Security Policy permits the intended HTTP(S) image
sources; do not loosen script or frame policy. The post's existing
visibility checks still control who receives the card metadata, but the
image host may observe authorized viewers loading it. An image URL is
not a private media URL issued or protected by Unspoken.

## 10. Rendering

After existing post visibility filtering, batch-load previews for the
current page's distinct preview IDs. Add an optional cache argument to
`postViewWithAuthorCache()` or introduce a page view context containing
both author and preview maps. A timeline of twenty posts must not require
twenty extra preview queries.

The view model exposes `has_link_preview`, `href`, `title`, `description`,
`display_host`, `image_url`, and `has_image`. Escape every text
and URL attribute exactly once using the existing explicit escaping
convention; Inja interpolation alone must not be assumed to escape values.
Use the selected validated HTTP or HTTPS URL as `href`. Derive
`display_host` from that URL to show the actual destination.
`image_url` is the validated remote URL stored in `image`.

Create `templates/_link_preview.html` and include it from `_post.html`
after content and before attachments. Include the card inside the same
closed content-warning details as the content it summarizes. Sensitive
posts without a summary get a collapsed preview disclosure as well.
Refactor the duplicated content branches if necessary so a card is
included only once. Parent thread cards, bookmarks, profiles, search
results, public timelines, and home timelines share this partial.

Use an accessible anchor with visible title and destination host, optional
text, and a lazy-loaded, asynchronously decoded thumbnail. Keep a visible
keyboard focus outline. Use a responsive stacked layout on narrow
screens and a thumbnail beside text on wide screens. Avoid nested anchors,
external styles, embedded iframes, JavaScript polling, and Bootstrap.
Do not hide cards just because a post has ordinary attachments.

Pending, unavailable, failed, and absent previews render
nothing. Rendering never schedules work. A page refresh shows completed
results without requiring a new post or a federation redelivery.

## 11. API and module responsibilities

The following names are proposed interfaces, not existing functions.
Public declarations require intention comments and use `mw::E<>` for
fallible operations.

- `selectPreviewUrl(...)`: pure HTML/context selection returning an
  optional normalized URL. No network or database access.
- `associateLinkPreview(...)`: join the caller's transaction, deduplicate
  a URL, schedule if necessary, and set a post's one preview reference.
- `pendingLinkPreviewIds(after_id, limit)`: scan referenced pending rows
  in batches for queue recovery; wrap to the beginning after each pass.
- `fetchLinkPreview(http, url, limits)`: return bounded metadata and an
  optional remote image URL, or a classified retry/permanent failure.
- `completeLinkPreview(id, result)` and
  `failLinkPreview(id, status)`: save terminal outcomes for pending rows.
- `getLinkPreviews(ids)`: batch access for authorized post rendering.
- `runLinkPreviewOnce(...)`: dequeue an ID, fetch outside a transaction,
  and save; retry timing remains in the application worker.
- `collectLinkPreviews(limit)`: delete unreferenced cached metadata.

Keep `LinkPreview`, `PreviewStatus`, and `PreviewFailure` in application
headers. Put HTML parser/HTTP logic in `link_preview.cpp`, database SQL in
`data.cpp`, view composition in `service.cpp`, and handlers/thread lifecycle
in `app.cpp`. Keep `ap::Session` and raw protocol documents independent of
preview state. Use named functions rather than temporary closures where
practical, four-space indentation, and the established brace style.

## 12. Configuration and maintenance

Add the validated setting `link_previews.enabled` (true).
Use one worker and a fixed 1000-ID queue initially. Keep network, size,
and retry bounds fixed constants. Document startup recovery and the
absence of automatic refresh or persistent retry budgets in
`docs/operator.md`, along with fetching links from private posts.

Hourly maintenance removes unreferenced preview rows in batches of 100.
Check `NOT EXISTS (SELECT 1 FROM posts WHERE link_preview_id=...)` inside
the write transaction. Coordinate collection with the in-memory running
set; never remove a row while it is being fetched. A pending orphan may
be removed without fetching. No age-based row retention requires extra
timestamp columns. AUTOINCREMENT prevents a deleted queued row's ID from
being reused for a different URL.

There are no image files to collect or include in backups. The database
contains all preview data owned by Unspoken. The remote host remains
responsible for the actual image bytes.

Log row ID, normalized destination host, elapsed time, result class,
in-memory attempt count, and fetched HTML byte counts. Avoid full URLs:
query strings can contain private tokens. Do not log downloaded HTML or
metadata from private posts. Useful operator counts are pending, ready,
unavailable, and failed rows, plus in-memory queue/running counts.

## 13. Verification and rollout

Tests must cover the complete save-to-render path as well as helpers.

1. **Selection:** two article links choose the first; mentions, hashtags,
   attachments, self links, invalid schemes, credentials, and oversized
   URLs are skipped. Query and path semantics survive normalization.
2. **Metadata:** Open Graph precedence, HTML fallbacks, entities, Unicode,
   empty fields, duplicates, relative images after redirects, malformed
   HTML, and non-HTML responses.
3. **Network:** successful HTTP and HTTPS page fetches; redirects
   in both directions; distinct scheme cache keys; redirect loops and
   limits; rejected non-HTTP(S) schemes; denied initial and redirect
   addresses; mapped IPv4;
   decompression limits; timeout; 429 and retry exhaustion. Use local
   fixtures/fake sessions with explicit test injection, not a production
   configuration that permits private targets.
4. **Images:** relative URLs, invalid schemes, credentials, disallowed
   literal hosts, attribute escaping, no server image requests, direct
   remote `src`, no-referrer, lazy loading, broken-image layout, and
   mixed-content behavior. Tests must not require image downloads to
   complete before marking valid metadata ready.
5. **Persistence:** two posts share one row; rollback leaves no orphan
   association; duplicate inbox delivery queues no second fetch; queued
   and running IDs are deduplicated; restart recovers pending rows but
   never retries terminal rows; attempts and deadlines reset on restart;
   queue overflow and missed commit notifications recover by scanning;
   edits during fetch retain the correct reference; deletion and garbage
   collection cannot remove a referenced preview row.
6. **Authorization:** private post cards appear only to authorized
   viewers. Shared public/private URLs do not expose private post
   associations. Verify that no new image-serving endpoint or public
   metadata API bypasses post authorization.
7. **Integration:** local create, accepted remote Create, remote Update,
   thread fetch, and search retention all schedule; ignored inbox events
   do not. Federation workers never claim a preview. Preview failure does
   not change delivery success or timeline availability.
8. **UI:** one card maximum, escaped title/attributes, validated remote image source,
   warning/sensitive disclosure, keyboard navigation, narrow-screen layout,
   and constant-count batch loading.
9. **Migration:** upgrade a version-4 database with posts, verify NULL
   references and unchanged existing content, reopen successfully, and run
   `PRAGMA foreign_key_check`. Fresh databases match migrated databases.

Implementation order:

1. Schema, types, transactional association, and selection tests.
2. In-memory queue/retries, pending-row recovery, and worker lifecycle.
3. HTTP/HTML extraction and validation of metadata image URLs.
4. Batched view-model integration behind existing post authorization.
5. Shared template/CSS, operator/package changes, and end-to-end tests.

Run compilation with `-j24`, focused tests after each meaningful change,
and the existing federation/inbox/transaction tests before release. Verify
with fixture pages whose responses and images are controlled; a live
website is a manual smoke test, not an automated test dependency.

Deploy after a consistent database backup. Startup recovers existing
pending preview rows but does not backfill posts with NULL references.
Verify a new local post and a newly retained remote post acquire one card after the worker completes, and that private post metadata is
not rendered anonymously. Confirm image requests go directly from the
browser to the remote host with no Referer header. Rolling back the
binary requires restoring a compatible database backup; disabling previews
is the reversible way to stop fetching while retaining stored data.
