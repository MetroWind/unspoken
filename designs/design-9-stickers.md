# Design Document: Stickers and Sticker Packs

**Status:** Proposed
**Related designs:** [Architecture](design-0-architecture.md),
[emoji picker](design-1-emoji.md), and
[federation library](design-6-library.md).
**Scope:** Operator-managed static sticker files, filename-based packs,
a composer picker, and ordinary image attachment federation.

## 1. Intended Behavior

Operators create packs by copying directories of image files into a
configured sticker directory, using `scp` or other filesystem tools.
Directory names are pack names. Filenames without their final extension
are sticker names and image descriptions. There are no manifests.

The application scans the directory at startup to build a read-only
picker registry, similarly to custom emoji. All local users can use all
packs. Refreshing the picker catalog requires restarting the application.
There is no web management UI, user ownership, database pack catalog,
startup database import, or copy into the attachment directory.

The application serves the original image at a public static URL:

```text
https://example.org/stickers/cats/happy_cat.webp
```

A post or reply can have zero or one sticker alongside optional text and
ordinary attachments. Selecting another sticker replaces the selection.
Sticker-only posts and replies are valid. A sticker renders as a separate
image below post text, preserving transparency and aspect ratio.

When a user publishes a sticker, the post stores a reference to its
static URL and a name snapshot. Federation includes that URL as an
ordinary image attachment. No image bytes are copied or fetched during
posting, and federation does not require the image to reside in the
application's attachment directory.

The operator maintains published files at permanent paths. Replacing a
file in place changes what old posts point to. Deleting or renaming a
file breaks its old URL. The application deliberately does not maintain
a historical image archive. Use new filenames for revised artwork and
keep old published files available.

## 2. Goals and Boundaries

The feature provides:

- Filesystem-only creation and maintenance of packs.
- One persistent copy of each source image, served directly.
- Pack and sticker labels derived from directory and file names.
- A shared pack-tabbed composer picker.
- At most one sticker relationship per post, enforced in SQLite.
- Ordinary image attachment federation with public static URLs.
- Snapshotted descriptions unaffected by later picker changes.
- Existing audience, content warning, and sensitive-media behavior.
- No configured import size limit: `max_upload_bytes` is for HTTP uploads.

Outside scope: web uploads, user-owned packs, manifests, subscriptions,
remote pack installation, pack federation, sticker reactions, inline
sticker syntax, image conversion, automatic file watching, immutable
content-addressed sticker URLs, and preservation of removed image bytes.
Existing custom emoji and ordinary attachment uploads retain their
current storage behavior.

## 3. Filesystem Contract

### 3.1 Configuration and layout

Add `Config::sticker_dir`, YAML key `sticker_dir`, default `stickers`.
Relative paths resolve the same way as `emoji_dir`. Production examples
use an absolute path. The process needs read access, not write access.

```yaml
sticker_dir: /var/lib/unspoken/stickers
attachment_dir: /var/lib/unspoken/attachments
```

The two directories are independent:

```text
stickers/
    cats/
        happy_cat.webp
        sleepy_cat.webp
    birds/
        hello.png
        waving.gif
```

The picker contains packs `birds` and `cats`; `happy_cat.webp` has the
name and description `happy_cat`. Preserve underscores, punctuation,
case, and spaces. `happy.cat.webp` becomes `happy.cat`. A filename such
as `A sleepy cat.webp` supplies a prose description without metadata.

Only immediate child directories define packs, and only immediate regular
image files inside them define stickers. No recursion, root-level
stickers, archives, or sidecars. Omit empty packs. Ignore hidden names
beginning with `.`, symlink entries, and special files.

Names must be valid UTF-8, have nonempty stems, and contain no ASCII
control characters. Do not normalize Unicode or case. Sort packs by
exact names and files by exact filenames using lexicographic unsigned
UTF-8 byte order. Identical stems with different extensions are separate
entries. Duplicate labels across packs are allowed.

### 3.2 Supported media

Initially accept PNG, JPEG, GIF, WebP, and AVIF extensions, matched
case-insensitively and mapped through existing attachment MIME helpers.
Preserve original bytes and animation. Exclude SVG, video, and arbitrary
documents from this initial sticker format set.

The registry reads directory metadata rather than image contents. Do not
hash, decode, copy, resize, or insert an attachment row during discovery.
There is no per-file import limit because there is no import operation.
The operator is responsible for valid images and sensible file sizes.
Zero-byte files are skipped with a warning. As with current custom emoji,
extension mapping does not claim full image-format validation.

### 3.3 Publication workflow

Upload complete images and restart to refresh the catalog. To avoid
serving partially transferred files, upload to a hidden temporary filename
in the destination directory, then rename it to its final name. For pack
updates, finish publishing the complete desired set before restarting.
The catalog is not a transactional snapshot of concurrent operator edits.

Published paths should be append-only. For new artwork, upload
`happy_cat_v2.webp` while retaining `happy_cat.webp`. The first version
has no independent unlisting mechanism: retained eligible files also
remain in the picker. Removing an entry from discovery by renaming it
also changes its URL and is not a way to preserve old posts.

A missing sticker root yields an empty registry and an informational log.
An existing unreadable root or pack is a startup error. Invalid names,
unsupported entries, symlinks, and empty files are skipped with warnings.
Log discovered pack/sticker counts without printing file contents.

## 4. Static Serving and URL Construction

### 4.1 Public endpoint

Add `GET /stickers/:pack/:filename`, relative to `url_root`, with an
optional HEAD equivalent through the HTTP server's normal behavior.
The endpoint is public and requires neither login nor an attachment row.
Remote servers must be able to fetch the image independently of the
HTML post. All configured sticker images are public media.

Construct absolute URLs from normalized `url_root` plus `stickers/` and
two separately percent-encoded path components. Encode UTF-8 bytes and
reserved characters with the project's URL facilities. Do not concatenate
raw filenames, encode the whole path as one component, or interpret a
filename's `?`, `#`, or `%` as URL syntax.

### 4.2 Path validation

Treat router values according to the HTTP library's actual decoding
behavior and decode no more than once. Reject empty components, exact
`.`/`..` segments, embedded slash or backslash, NUL, ASCII controls,
invalid UTF-8, and hidden names. Resolve beneath the canonical configured
root and verify containment by path components rather than a string
prefix. Require an immediate pack directory and regular image file;
reject symlinks in either component. Do not create a general filesystem
browser or expose directory listings.

Apply the same eligible-name and supported-extension rules as discovery.
Return HTTP 404 for invalid paths, unsupported formats, directories, and
missing files. An I/O failure reading an existing valid image returns a
server error. Serve the derived image MIME type and
`X-Content-Type-Options: nosniff`.

Serve based on the requested path and current filesystem, not membership
in the startup registry. This makes image retrieval independent of picker
state, including between a file upload and the next restart. Operators
should restrict filesystem writes to their deployment account; the app
has read-only access to this tree.

### 4.3 Caching and memory

Do not mark these name-based URLs immutable. Initially use
`Cache-Control: public, no-cache` so caches can store responses but must
revalidate. Optional conditional responses can use the HTTP server's
existing file metadata support; no content hash is required. Remote
implementations may cache images under their own policy, so in-place
replacement can still yield different images at different receivers.

Use file-backed or streaming response support where available rather
than reading an unbounded image into a response string. Verify libmw's
actual file-serving facility before choosing the implementation. Do not
reuse `max_upload_bytes` to impose a static-file size restriction.

The documented application route works without a reverse-proxy static
mapping. An operator may serve the same path directly from a proxy, but
its access, MIME, and path restrictions must match this contract. Hosting
on a separate configurable origin is outside this initial version.

## 5. Registry and Selection

Add `src/stickers.hpp` and `src/stickers.cpp`. Model discovery on
`EmojiRegistry`, with fallible scanning returned through `mw::E<>`.
Use libmw facilities where available. Public declarations need comments
and repository naming and brace conventions.

| Type or method | Purpose |
| --- | --- |
| `StickerInfo` | Selection key, name, absolute URL, media type |
| `StickerPack` | Exact directory name and ordered stickers |
| `StickerRegistry::scan()` | Discover eligible pack paths at startup |
| `StickerRegistry::lookup()` | Resolve an exact selection key |
| `StickerRegistry::all()` | Ordered packs for the picker |
| `StickerRegistry::empty()` | Hide picker when no choices exist |

The selection key can be the canonical absolute static URL, built only
by discovery. It is an identifier, not authorization to fetch arbitrary
URLs. Browser input must exactly match a registry entry. Never accept a
client URL as a new arbitrary attachment or interpret it as a filesystem
path. No hash or content-version token is needed: permanence of URL
contents is an operator contract, not an application guarantee.

Build the registry once at startup and share it read-only across request
threads. No database writes or attachment insertion happen at startup.
A missing root must not create a directory or require write permissions.
Inject the registry into `App` and `Service`; unrelated tests can use an
empty registry.

An unknown key returns HTTP 400 with a refresh-picker message. Check
file existence and regular-file eligibility when selecting a known entry
to catch source deletion since startup; perform this check before post
mutation. It cannot guarantee continued availability after commit, and
the UI/docs must not claim otherwise.

Keeping an existing post sticker never consults the registry or source
file. Text edits must work even if the operator has removed its image.
Replacing or deleting source bytes does not automatically modify posts
or enqueue federated Updates.

## 6. Persistence: References Only

### 6.1 Existing URL-backed attachments

The `attachments` table already supports URL-backed records through its
nullable `remote_url` field, with uniqueness by URL and no local hash or
extension. Use that representation for a selected static sticker:

```text
sha256       = NULL
extension    = NULL
media_type   = image/webp
original_name = happy_cat
is_image     = true
remote_url   = https://example.org/stickers/cats/happy_cat.webp
```

The historical name `remote_url` means a directly referenced URL for this
purpose, including one hosted by this server. Update comments and helper
names to describe URL-backed storage. A broad database column rename is
not required for this feature. Audit all branches on `remote_url` to
ensure they test storage representation rather than assuming a foreign
origin or requiring a download.

Only actual posting inserts or reuses an attachment row, inside the
post's transaction. No image is fetched, hashed, copied, or registered
for an unused picker item. Reuse `insertAttachment()`'s URL-backed branch;
rename its internal helper from `insertOrGetRemoteAttachment()` to
`insertOrGetUrlAttachment()` and adjust its errors/comments accordingly.

The same URL can have many post references. Deleting an unreferenced
attachment row must never delete a file in `sticker_dir`; source files
are exclusively operator-managed. There are no catalog pins because
unposted stickers need no attachment row.

### 6.2 Relationship metadata

Extend `post_attachments`:

```sql
ALTER TABLE post_attachments
    ADD COLUMN role TEXT NOT NULL DEFAULT 'ATTACHMENT'
    CHECK (role IN ('ATTACHMENT', 'STICKER'));

ALTER TABLE post_attachments ADD COLUMN sticker_name TEXT;

CREATE UNIQUE INDEX idx_post_attachments_one_sticker
    ON post_attachments(post_id) WHERE role = 'STICKER';
```

Require a nonempty `sticker_name` for sticker relationships and null for
ordinary relationships. Enforce through data validation and equivalent
insert/update triggers in migrated and fresh schemas. Snapshot the
filename-derived name when posting; do not depend on the asset-wide
`original_name`, which URL deduplication may have populated earlier.

Add `AttachmentRole` with `ATTACHMENT` and `STICKER` cases, plus role and
optional sticker name on post attachment views. A bare asset lookup has
no intrinsic sticker role. Update `attachmentsForPost()` to read the
relationship fields.

Keep the primary key `(post_id, attachment_id)`. If the same URL is
already an ordinary attachment on a post, promote that relation to the
sticker role rather than inserting a duplicate. Do not rely on existing
`ON CONFLICT DO NOTHING`, which could silently lose the requested role.
Preserve the order of other ordinary attachments.

Add a focused `setPostSticker()` data operation taking an optional
resolved attachment ID and name. It changes only sticker relationships,
sets sensitivity from the post, and appends new relations after ordinary
media in wire order. Generic incoming attachment writers continue to
create ordinary roles. Text edits preserving attachments preserve their
role and name.

### 6.3 Migration

At drafting time the schema version is 8. Implement migration 8 to 9,
fresh-schema equivalents, and advance the version after successful
transaction completion. Use the next available version if another
change lands first. Existing relationships default to ordinary roles.

Do not create pack tables, ownership tables, a `sticker_catalog`, or any
startup reconciliation. Those were earlier design alternatives, not
released schemas requiring migration. This migration reads no files.

## 7. Creating and Editing Posts

### 7.1 Form contract

Reuse existing create, reply, and edit POST routes:

| Field | Values | Meaning |
| --- | --- | --- |
| `sticker_action` | `keep`, `clear`, `set` | Requested change |
| `sticker` | Exact registry selection key | Required for set |

Missing action means keep on edit and no sticker on creation. Keep and
clear on creation both mean no selection. Reject unknown actions,
duplicate fields, missing selection for set, and a nonempty selection
for keep/clear. An empty selection control is valid for keep/clear.
Inspect field cardinality before using single-value parameter helpers.

Add a typed sticker intent to `ComposeParams`; existing callers default
to keep. The service resolves selection keys through the shared registry
rather than trusting the handler to pass arbitrary attachment metadata.

### 7.2 Create and reply

1. Apply existing login, CSRF, audience, and reply-target checks.
2. Parse and validate sticker intent and resolve any selected registry
   entry. Check source availability before handling uploaded attachments.
3. Reject whitespace-only content only if ordinary attachments and the
   resolved sticker are both absent. Enforce this in the service too.
4. Inside the existing post write transaction, insert or reuse the
   URL-backed attachment, create the post, and write ordinary and sticker
   relationships with the selected description snapshot.
5. Create notifications and enqueue the outbound activity within the
   existing outer transaction. An enqueue failure rolls back all DB
   mutations, including any newly created URL-backed attachment row.
6. Commit and redirect as normal.

Update early emptiness checks in `handlePostCreate()` and `handleReply()`
to account for sticker intent. Sticker-only replies retain ordinary
reply audience and notification behavior. Exclude selected sticker URLs
from link preview generation just as other attachment URLs are excluded.

### 7.3 Edit

Authorize post ownership first. Keep retains its saved URL and name
without a current catalog entry. Clear removes only the sticker. Set
resolves an active selection and replaces the sticker relation. Preserve
ordinary attachments, object identity, and audience.

Evaluate emptiness against the final relationship set. Clearing the only
sticker from a textless post without ordinary attachments returns HTTP
400 and leaves the old post intact. Content updates, relationship changes,
and outbound Update enqueueing share the existing outer transaction.
Reload the full attachment list before serialization. Failed edits must
not partially remove or replace an existing sticker.

## 8. Picker and Rendering

### 8.1 Enhanced picker

Place a sticker button beside the emoji button. Use pack tabs labeled by
directory name, an image grid, and one selected preview per invoking form.
Selecting an entry sets action to set and records its key. Selecting a
second replaces it. Remove clears the key and sets clear. Selection does
not insert text or submit the form.

Expose the read-only catalog through `GET /stickers/catalog`, requiring
login, with pack names and entry keys, names, media types, and URLs.
Serialize it once per process from the registry and load it once per page
when the picker first opens. Do not embed the full catalog in every post.
The one-component `catalog` route cannot collide with the two-component
public image route. No database query is needed for the catalog response.

Support tab roles, arrow-key navigation, selected states, Escape, focus
return, and keyboard activation. Use delegated listeners for fetched
edit forms and scope state to each form. An empty registry hides the
picker trigger; existing post stickers can still be previewed and cleared.

### 8.2 Native fallback and editor behavior

For basic no-JavaScript selection, provide standalone server-rendered
forms at `GET /compose` and `GET /post/:id/edit`. The former accepts an
optional local `reply_to` ID with existing access checks; the latter
requires ownership. Submit to existing create/reply/edit POST routes.
Keep native links to these forms available beside enhanced inline forms.

Each standalone form renders one native select grouped by pack, with
exact registry keys as option values and sticker names as labels. An
explicit action select provides keep, clear, and set. The default edit
action is keep; an unavailable old sticker remains visible in the preview
without needing a current catalog option. Do not submit duplicate native
and enhanced selection fields.

Extend `static/post_editor.js` to disable selects while saving, restore
preview/action/selection on cancellation, retain draft state after failed
saves, and reset enhanced state when `updateCopy()` replaces edit forms.
Use delegated handlers so replaced forms continue to work.

### 8.3 Display

The HTML view separates ordinary attachments and an optional sticker.
Render the sticker once after text and before the ordinary gallery, using
its saved name as alt text. Bound image width and height to 192 CSS pixels
and container width; preserve aspect ratio and transparency, avoid
cropping, and do not enlarge small images. Link to its original static URL.
Keep it outside ordinary gallery/lightbox selectors unless extended.

Content warnings enclose stickers and sensitive posts conceal them with
the existing reveal behavior. Use the shared post partial across feeds,
threads, boosts, bookmarks, and fetched fragments. Escape filenames and
pack names in HTML, attributes, and JSON. Use text properties instead of
`innerHTML` for client-side labels.

## 9. Federation

The standard ActivityStreams
[`attachment`](https://www.w3.org/TR/activitystreams-vocabulary/#dfn-attachment)
property accepts an
[`Image`](https://www.w3.org/TR/activitystreams-vocabulary/#dfn-image)
object whose URL refers directly to the static file. Use the saved
sticker description as its
[`name`](https://www.w3.org/TR/activitystreams-vocabulary/#dfn-name).
For example:

```json
{
    "type": "Note",
    "content": "<p>Hello!</p>",
    "attachment": [
        {
            "type": "Image",
            "mediaType": "image/webp",
            "url": "https://example.org/stickers/cats/happy_cat.webp",
            "name": "happy_cat"
        }
    ]
}
```

No new object type, context, or pack reference is emitted. Other servers,
including another Unspoken instance, receive an ordinary image attachment.
Do not infer incoming sticker roles from matching URLs or bytes. Exact
presentation on receiving servers is implementation-dependent.

`noteJson()` uses the complete relationship list even though HTML splits
stickers from ordinary media. Queued Create, queued Update, and direct
object GET must agree on URL, MIME type, and saved name. Existing URL-backed
serialization already emits the referenced URL without downloading it.
Retain post audience rules, while recognizing that the static images
are publicly retrievable independently of post visibility.

## 10. Operator Changes, Retention, and Backups

| Operator action | Effect |
| --- | --- |
| Add image, then restart | New picker entry |
| Add pack, then restart | New picker tab |
| Replace image at same path | Old and new posts reference changed bytes |
| Rename/delete image | Old URL stops working |
| Rename/delete pack directory | Every affected old URL stops working |
| Restart with missing root | Empty picker; old references remain in DB |

The application preserves saved URLs and descriptions, not historical
bytes. Remote caches may retain removed or replaced images, but they
are not a retention mechanism under our control. In-place changes do
not emit federated Updates; different receivers may show different cached
versions. Publish new versions at new filenames instead.

Do not delete old files based on current local post counts: remote posts
and caches may still reference their public URLs. Operator maintenance
is responsible for file retention. Attachment garbage collection must
never walk or delete from `sticker_dir`.

Back up the database, ordinary attachment directory, and sticker
directory. The sticker tree is the only persistent copy of these image
bytes. Preserve public `url_root` and relative pack/file paths when
restoring or moving deployments.

## 11. Errors and Guarantees

| Condition | Result |
| --- | --- |
| Missing source root at startup | Empty registry |
| Existing root/pack cannot be enumerated | Startup error |
| Unsupported/invalid/empty source entry | Skip with warning |
| Invalid or missing static image path | HTTP 404 |
| Valid static image cannot be read | Server error |
| Unknown selection key | HTTP 400; refresh picker |
| Known selection whose file was removed | HTTP 400; refresh picker |
| Unauthorized edit | Existing authentication/not-found behavior |
| Clearing the only post content | HTTP 400; preserve old post |
| DB or enqueue failure | Roll back post mutation |

The registry is a startup snapshot of selectable paths, not a guarantee
of future availability. Files can disappear after validation. Do not
add copying, hashing, historical archives, or database catalog pinning
to try to make the operator's permanence contract automatic.

## 12. Implementation Sequence

1. Add `sticker_dir` config parsing, documentation, and configuration tests.
2. Add registry discovery, encoded URL construction, public static serving,
   and focused scanner/path/serving tests. No startup DB writes.
3. Add role/name persistence, migration, data APIs, and mock support.
   Clarify URL-backed attachment semantics and audit `remote_url` uses.
4. Inject the registry into application/service construction. Add typed
   compose intent, create/reply/edit handling, and transaction tests.
5. Update federation name selection and shared post rendering. Ensure
   outbound serializers continue receiving all attachment relationships.
6. Add catalog route, picker, native standalone forms, styling, and editor
   integration. Keep current custom emoji behavior unchanged.
7. Update `config.yaml`, `packages/arch/config.yaml`, and
   `docs/operator.md` with layout, `scp` publication, restart, permanent
   paths, backups, and read-only service access. Package restrictions
   must allow reads without requiring writes to the sticker tree.
8. Add sources/tests to CMake and complete verification.

Keep sticker management, filesystem serving, and local rendering in the
application. Generic `lib/actpub` needs no sticker-specific model.

## 13. Verification and Acceptance Criteria

### 13.1 Discovery and public files

Test missing and empty roots, multiple packs, deterministic ordering,
uppercase extensions, duplicate stems/extensions, Unicode and spaced
names, control characters, hidden files, unsupported formats, nested
directories, symlinks, and enumeration failures. Verify discovery reads
no image bytes, writes no files, and performs no database operations.

Test URL round trips for spaces, Unicode, percent signs, question marks,
and hash characters. Test traversal, encoded separators, double encoding,
NUL, hidden components, sibling-prefix containment, and symlinks at both
path levels. Public image requests work without a session or attachment
row. Verify MIME, nosniff, cache policy, missing-file behavior, and read
failures. A valid image larger than `max_upload_bytes` must remain usable.

### 13.2 Database and posting

Test fresh schema and migration from version 8, existing ordinary roles,
name/role constraints, and unique sticker enforcement. Posting the same
sticker twice reuses one URL-backed asset with independent post relations.
No files appear in `attachment_dir`. Cleanup may remove unreferenced
URL rows but never modifies the sticker tree.

Test sticker-only posts/replies, mixed ordinary media, identical URL
relations, malformed fields, arbitrary unregistered URLs, source deletion,
and duplicate form fields. Test keep/clear/replace and retention of a
saved description without a live registry entry. Inject database and
activity enqueue failures to verify atomicity. Clearing the only content
must preserve the old post on failure.

### 13.3 UI and federation

Test keyboard navigation, per-form picker isolation, empty registries,
standalone native create/reply/edit forms, reply access checks, and
replacement of fetched edit markup. Extend editor tests for selects,
cancellation, failed-save preservation, and updated state. Manually check
mobile layout, transparent/animated images, warnings, and sensitivity.

Assert direct static URL output and saved names in Create, Update, and
object GET responses. Confirm incoming ordinary images do not become
stickers. Run a two-instance interop scenario in which the receiver
fetches the static image without authentication and displays it through
ordinary attachment handling.

Compile with `cmake --build build -j24` and run the relevant C++ and
JavaScript tests. Documentation changes alone require no build.

Final operator walkthrough: copy a pack into `sticker_dir`, restart,
publish a sticker-only post, and verify its federated static URL. Confirm
no copied sticker file appears in `attachment_dir`. Add revised artwork
at a new filename and restart: the old post continues using the old file.
Separately verify the documented consequence that deleting that old file
breaks its URL rather than causing an automatic restore or archive copy.
