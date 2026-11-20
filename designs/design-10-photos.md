# Design Document: Photo Posts and the nspic Merge

**Status:** Proposed
**Date:** 2026-11-12
**Related designs:** [Architecture](design-0-architecture.md),
[federation library](design-6-library.md),
[notifications](design-8-notifications.md), and
[stickers](design-9-stickers.md).
**Source application:** `~/programs/nspic`.

## 1. Intended Behavior

Unspoken gains a photo stream alongside its social stream. Both streams
contain ordinary posts from the same accounts. A photo post has a caption
and one or more ordered photo attachments; it uses the existing identity,
visibility, delivery, interaction, notification, and thread systems.

Every post has exactly one kind: `SOCIAL` or `PHOTO`. The kind is an
explicit classification of the post, independent of its attachment MIME
types, caption, hashtags, or author's server software. A social post can
contain photos and remains a social post.

**All incoming posts without a post kind are `SOCIAL`.** No image-based
heuristic, server allowlist, actor preference, or optional feed setting
overrides this rule. Only a recognized explicit photo kind can place an
incoming post in the photo stream.

The Social and Photos tabs are mutually exclusive views. A post is stored
once and has one canonical URL, even when it appears in a home timeline,
a public timeline, a profile, a search result, or a thread. Replies can
cross kinds: a social comment on a photo remains a social post and is
visible beneath the photo in its thread.

The merge brings nspic's photo publishing and gallery experience into
Unspoken. It does not embed the Rust server or maintain a second account
or post database.

### 1.1 Decisions and proposed defaults

The shared post model, explicit label, separate timelines, and missing
incoming kind default are requirements established in the discussion.
The wire identifier, invalid-value fallback, immutable local kind,
gallery details, and import procedure below are proposed implementation
choices. They make the design implementable without treating those
details as previously approved product requirements.

## 2. Scope

The initial release includes:

- A persisted post kind for local and remote posts.
- A Photos composer mode and ordered, described image uploads.
- Separate social and photo views for home, public, and profiles.
- A photo gallery on timelines and canonical post pages.
- Federation of the kind on normal ActivityStreams `Note` objects.
- An offline, repeatable import of existing nspic posts and image files.
- Migration of every existing Unspoken post to `SOCIAL`.

Albums, new follow relationships for individual streams, ranking,
automatic photo classification, video publishing, nspic password/session
import, and nspic webhook compatibility are outside this release. nspic
has an album column and table, but its upload handler does not currently
assign albums; the importer records any actual album data in its report
for a later album feature.

Image resizing and thumbnail generation are a separate implementation
phase in this document. The first usable release can use Unspoken's
existing attachment URLs. The phase is specified in section 10 so that
porting the photo experience does not silently imply retaining nspic's
old storage pipeline or discarding original uploads.

## 3. Existing Implementation and Integration Points

### 3.1 Unspoken

`src/structs.hpp` defines `Post`, `NewPost`, `Attachment`, and
`AttachmentRole`. Local and remote posts already share `posts`.
`post_attachments` stores ordering, sensitivity, role, and description;
the shared asset row stores file identity or a remote URL. A sticker is a
separate attachment role and is not a photo for validation purposes.

`src/service.cpp` creates posts in `Service::createPost()` and edits them
in `Service::editPost()`. The current edit path retains ordinary
attachments. It already permits attachment-only posts. The photo feature
adds kind validation here rather than in templates alone.

`src/data.cpp` owns application schema migrations; the current application
schema version is 9. It also implements `timelinePublic()`,
`postsForAuthors()`, and `homeTimelinePosts()`. The latter uses
`home_timeline_entries` and boost events, selects the newest eligible
event per post, and paginates by event ID. Photo filtering must preserve
that behavior.

`src/federation.cpp` renders local `Note` documents in `noteJson()` and
normalizes remote objects in `remoteNotePostFromActivity()`. Create,
Update, and remote object fetch paths must use the same kind parser.
The embedded `lib/actpub` library carries raw object JSON; the post kind
belongs to the application and does not require a library schema change.

`src/app.cpp` exposes `/post`, `/post/:id/reply`,
`/post/:id/edit`, `/p/:id`, `/compose`, `/u/:username`, and `/remote`.
Uploads are multipart fields named `attachments`. Stored media uses
`/media/:shard/:filename`. These routes remain the basis of the feature.

### 3.2 nspic

The Rust `Post` in `nspic/src/post.rs` contains an ID, image list,
description, upload timestamp, and optional album ID. Each image contains
a relative path and dimensions. `nspic/src/data.rs` persists these in
`posts`, `images`, and `albums`.

`nspic/src/post_pipeline.rs` resizes uploads, creates thumbnails, hashes
source bytes, and stores processed files. It removes the uploaded
original after processing. Port those image operations through linked
Magick++ rather than nspic's ImageMagick command invocations. Copying its
file naming and deletion logic would conflict with Unspoken's existing
content-addressed asset model.

The gallery templates and `static/gallery.js` provide a behavioral
reference for browsing multiple images. Port the behavior to Unspoken's
templates, themes, and existing lightbox. Do not copy authentication,
the Rust data layer, or dependencies into the C++ application.

## 4. Classification Contract

### 4.1 Domain model

Add this public application type to `src/structs.hpp`:

```cpp
// Author-selected stream classification, independent of attachments.
enum class PostKind
{
    SOCIAL = 0,
    PHOTO = 1,
};
```

Add `PostKind post_kind = PostKind::SOCIAL` to `Post`, `NewPost`, and
`ComposeParams`. Default initialization protects existing callers and
legacy form submissions. Database values are the integers above; form
and federation values are lowercase strings `social` and `photo`.

Provide documented conversion functions `postKindToStr()` and
`postKindFromStr()`. The latter returns `std::optional<PostKind>` so the
caller explicitly chooses whether an invalid input is a form error or a
remote compatibility fallback. Never cast untrusted integers to the enum.

### 4.2 Rules by input source

| Input | Result |
| --- | --- |
| Existing Unspoken database row | `SOCIAL` after migration |
| New local form with omitted kind | `SOCIAL` |
| Local form with `social` | `SOCIAL`, with existing content rules |
| Local form with `photo` | `PHOTO`, after photo validation |
| Local form with another value | HTTP 400 |
| Incoming object with no recognized kind property | `SOCIAL` |
| Incoming kind explicitly `social` | `SOCIAL` |
| Incoming kind explicitly `photo` | `PHOTO` |
| Incoming null, unknown, or non-string kind | `SOCIAL` |
| Imported nspic post | `PHOTO`, after import validation |

String comparisons are exact and case-sensitive. An unnamespaced
`post_kind`, `postKind`, or hashtag does not count as the recognized wire
property defined in section 7.

For remote objects, attachment presence does not affect classification.
An explicitly marked remote photo with missing or broken media remains
`PHOTO`; render an unavailable-media message if necessary. Local
validation is stronger because Unspoken controls its own publishing UI.

### 4.3 Creation and editing

A local photo post requires at least one ordinary uploaded raster image.
All ordinary attachments on that post must be raster images. Allow JPEG,
PNG, WebP, GIF, and AVIF when supported by the photo validator; determine
the format from bytes, not only the supplied filename or Content-Type.
Initially animated GIF/WebP can remain animated at the original URL;
derivatives in section 10 use the first frame. Other formats can be added
explicitly later. SVG, videos, and documents remain social attachments.

A selected sticker does not satisfy the photo requirement. A photo post
may also have one sticker, rendered through the existing sticker path.
Captions and alt text may be empty. Continue to expose alt-text inputs
and encourage descriptions without fabricating them from filenames.

Link ImageMagick 7's Magick++ library for initial photo probing and decode
validation, using the shared wrapper and limits in section 10.2. A
successful header probe alone is insufficient: perform a bounded full
decode to detect truncated or corrupt content. Use the detected format to
supply the canonical MIME type and extension to the attachment store; do
not retain an uploaded `.svg` suffix for bytes detected as JPEG. Add the
Magick++ development dependency, runtime libraries, and restrictive policy
to packaging and the operator guide in the first release. Missing decoder
support is a clear photo validation error; social posting remains
available. The follow-up phase adds output generation through the same
library wrapper. No photo operation invokes the `magick` command.

Keep the local post kind immutable after creation in this release.
The edit form displays the saved mode, and `editPost()` copies the saved
kind into `NewPost`. Omitted edit kind means preserve; an explicitly
different kind returns HTTP 400. This prevents older edit clients from
resetting photos to social and avoids adding a new kind-change workflow.
Existing caption, warning, sensitivity, and sticker edits still work.

Future removal of ordinary attachments must reject removal of the last
photo from a local `PHOTO` post. The current edit path retains them, so
attachment replacement is not required for this release.

## 5. Persistence

### 5.1 Schema migration

Introduce application schema 10, or the next free version if another
migration lands first. In the version-9-to-10 transaction:

```sql
ALTER TABLE posts ADD COLUMN post_kind INTEGER NOT NULL DEFAULT 0
    CHECK(post_kind IN (0, 1));

CREATE INDEX idx_posts_kind_id ON posts(post_kind, id);
CREATE INDEX idx_posts_local_author_kind_id
    ON posts(local_author_id, post_kind, id);
CREATE INDEX idx_posts_remote_author_kind_id
    ON posts(remote_author_id, post_kind, id);
```

Fresh initialization creates the same column, constraints, and indexes.
Use the existing migration dispatcher and transaction support. Advance
`user_version` only after all migration statements succeed. The default
assigns `SOCIAL` to historical rows without scanning their attachments.
SQLite documents the applicable
[ADD COLUMN rules](https://www.sqlite.org/lang_altertable.html#altertabaddcol).

Extend the shared post column list, every row tuple and mapper, insert
and update bindings, joined timeline projections, and mock signatures.
Search, bookmarks, threads, and notifications must load the saved kind
even though they are not exclusively photo or social views.

The kind CHECK belongs in SQL. The requirement that a local photo has
image relationships belongs in the service transaction: attachments are
inserted after the parent post, so an immediate row CHECK cannot express
that cross-table invariant correctly.

### 5.2 No duplicate feed state

Do not add photo posts, photo likes, photo recipients, or photo timeline
tables. Use existing rows and event IDs. Both views see the same saved
boost state; a boost of a photo enters the Photos view by inspecting the
boosted post's kind.

Add the import bookkeeping table from section 11 in this migration.
Derivative tables from section 10 belong to a later migration when that
phase is implemented, rather than creating unused storage now.

## 6. Timelines and Query Semantics

### 6.1 View membership

| Surface | Social view | Photos view |
| --- | --- | --- |
| Home | Eligible `SOCIAL` entries | Eligible `PHOTO` entries |
| Public | Public `SOCIAL` posts | Public `PHOTO` posts |
| Local profile | Authored `SOCIAL` posts | Authored `PHOTO` posts |
| Remote profile | Retained `SOCIAL` posts | Retained `PHOTO` posts |

All audience and follow rules remain predicates in addition to the kind.
The tabs do not broaden public visibility or cause remote profile visits
to fetch an entire photo history. Profiles display authored posts, not
the account's boosts, consistent with the existing authored-post model.

Preserve current social reply inclusion. The Photos view excludes posts
with `in_reply_to_uri` set, so it presents original photo entries and
their boosts. Photo replies remain in their threads, search, bookmarks,
and notifications. This exclusion is a view rule; it does not rewrite a
reply's kind. Local reply forms create `SOCIAL` by default even when their
parent is `PHOTO`; a photo attached to a comment does not change that.

Threads, notifications, bookmarks, and search can contain both kinds.
Opening a thread does not hide replies because they have a different kind
from the root. Actor outboxes also contain both kinds and retain their
existing canonical collection identity and pagination.

### 6.2 Data APIs

Add a required `PostKind post_kind` argument to public and authored-stream
query methods, `homeTimelinePosts()`, and `Service::homeTimeline()`.
Update the legacy `timelineHome()` primitive and its tests as well.
Prefer required arguments to hidden defaults on timeline APIs: each
caller must consciously select a stream. Keep unrestricted thread,
bookmark, search, and outbox queries distinct from these stream APIs;
an outbox must not become Social-only through a shared helper's default.

For ordinary post pagination, add `posts.post_kind = ?` and, for Photos,
`posts.in_reply_to_uri IS NULL` to the WHERE clause before ORDER BY and
LIMIT. Bind the enum's validated integer representation. Retain the
current ascending selection and final reversal for `min_id` requests.

For the home CTE, group its original/boost alternatives before applying
the common kind predicate:

```sql
WHERE ((original_event_eligibility) OR (boost_event_eligibility))
  AND posts.post_kind = ?
  -- Photos only:
  AND posts.in_reply_to_uri IS NULL
```

The parenthesized placeholders above describe existing SQL expressions,
not SQL parameters. Keep the existing `row_number()` selection of the
latest eligible event per post, then apply the event cursor and LIMIT.
An unparenthesized `OR` could let one branch bypass the photo filter.

Never fetch one mixed page and filter it in C++ or JavaScript: that can
produce short or empty pages despite later matching entries. A stream
page is a page of matching posts, not a page of candidates.

### 6.3 Ordering and switching tabs

Home continues to use `timeline_id`; public and profiles continue to use
post ID. Each tab starts from its latest page when selected. Preserve
the stream path (`/` or `/photos`) in pagination URLs and form return
destinations. Profile views retain their `kind` query parameter instead.
Discard `max_id` and `min_id` when switching tabs. Do not carry a social
cursor into a photo query merely because both use numeric IDs.

No new timeline event is emitted for caption edits or remote kind
updates. A reclassified remote post moves between views at its existing
position; it may require refreshing the destination tab to see it.

## 7. Federation Contract

### 7.1 Wire representation

Continue sending `Create` and `Update` activities with ordinary `Note`
objects. Photos are normal ordered image attachments, not a new object
type, actor, or collection. The vocabulary defines
[`Note` and `attachment`](https://www.w3.org/TR/activitystreams-vocabulary/).

Use this proposed stable application property IRI:

```text
https://f.mws.rocks/#postKind
```

It identifies this extension independently of the instance's hostname.
Treat it as a vocabulary identifier; processing does not dereference the
URL. Document it in the repository before shipping. Use the full IRI as
the JSON key so this feature needs neither remote context retrieval nor
a general JSON-LD processor. ActivityStreams explicitly permits extension
properties and instructs consumers to ignore unrecognized extensions.
See [Extensibility](https://www.w3.org/TR/activitystreams-core/#extensibility).

A shortened photo object example is:

```json
{
  "@context": "https://www.w3.org/ns/activitystreams",
  "type": "Note",
  "id": "https://example.org/p/42",
  "attributedTo": "https://example.org/u/alice",
  "https://f.mws.rocks/#postKind": "photo",
  "content": "<p>Evening at the coast.</p>",
  "published": "2026-11-12T18:00:00Z",
  "to": ["https://www.w3.org/ns/activitystreams#Public"],
  "cc": ["https://example.org/u/alice/followers"],
  "attachment": [
    {
      "type": "Image",
      "mediaType": "image/jpeg",
      "url": "https://example.org/media/a/abc.jpg",
      "name": "Waves beneath an orange sky"
    }
  ]
}
```

Emit the property for both kinds, including `"social"`, on object fetch,
outbox serialization, and embedded Create/Update objects. Define a single
constant for the key and use the same conversion code in every path.
The enclosing activity's kind is irrelevant; read the Note's property.

The initial parser accepts the exact full IRI key only. A server adopting
this extension must emit that key. Supporting equivalent compact aliases
through JSON-LD context expansion is a separate interoperability change;
do not opportunistically trust arbitrary `@context` definitions or fetch
remote contexts during inbox processing.

Other servers may ignore or discard the property and show photos in
their ordinary timelines. This extension guarantees separation within
Unspoken and compatible consumers, not a separate feed on every server.

### 7.2 Inbound normalization and updates

Implement one application helper that reads the recognized property:

1. Start with `SOCIAL`.
2. If the property is the string `photo`, return `PHOTO`.
3. If it is `social`, return `SOCIAL`.
4. For absence, null, unknown strings, arrays, objects, booleans, or
   numbers, return `SOCIAL` without rejecting an otherwise valid post.

Call it from `remoteNotePostFromActivity()` so inbox delivery and remote
resolution use the same rule. Preserve the raw remote document through
the existing storage mechanisms; normalization need not modify it.
An ActivityStreams `Image` type, image attachment, or photo software name
does not substitute for the property in any accepted fetch path.

Treat accepted server-to-server Update objects as complete snapshots,
including the kind. An Update without the property changes a previously
marked photo to `SOCIAL`. Keeping the old kind would violate the missing
kind rule. This follows ActivityPub's full replacement semantics for
[server-to-server Update][ap-update].
Existing authenticity, ownership, addressing, replay, and update-ordering
policies still apply before normalization is persisted.

Apply kind, content, recipients, and attachment changes in one existing
application write transaction. Audit Create, Update, and fetched-object
paths: some currently insert or update the post before storing its
attachments. A successful operation must expose the complete new state;
an attachment persistence failure must roll back the state change.

An Announce references the original post and never sets or overrides its
kind. Resolve an unknown target through the existing fetch path and use
the resolved object's kind. Replaying an already accepted Create must not
reclassify or duplicate the saved post.

## 8. HTTP and Composer Behavior

### 8.1 Route contract

All paths below are relative to the configured application URL root.

| Request | Kind handling |
| --- | --- |
| `GET /` | Social home when logged in; Social public otherwise |
| `GET /photos` | Photos home when logged in; Photos public otherwise |
| `GET /u/:username?kind=photo` | Local profile's authored photo stream |
| `GET /remote?...&kind=photo` | Cached remote profile's photo stream |
| `GET /compose?kind=photo` | Photo composer mode |
| `POST /post` | Multipart `post_kind`, optional source, attachments |
| `POST /post/:id/reply` | Omitted kind defaults to `social` |
| `GET /post/:id/edit` | Saved kind determines mode |
| `POST /post/:id/edit` | Preserve saved kind; reject explicit change |
| `GET /p/:id` | Render saved kind and full thread |

The main timeline's path selects its kind: `/` always selects Social and
`/photos` always selects Photos. A `kind` query parameter does not override
either path. Both routes use the same handler logic with an explicit
`PostKind` selected by the route registration.

Profiles and the composer retain the `kind` query parameter shown above.
For those routes, an omitted kind defaults to `social`; an invalid kind
returns 400. An invalid submitted kind also returns 400. Form field
`post_kind` selects a new post's classification. Route and form selections
do not change authorization or the post's canonical URI. ActivityPub
outbox and object representations ignore HTML tab selection.

Use Social and Photos labels in navigation and profile tabs, with an
accessible selected state. The photo tab's compose button selects Photos.
The general compose button defaults to Social. A mode switch preserves
unsent text and selected files; the UI explains incompatible files before
publishing instead of silently dropping them.

### 8.2 Upload and validation sequence

1. Authenticate and run existing request protections and size limits.
2. Parse `post_kind` before writing uploaded files. Reject unknown values.
3. Resolve the sticker selection through the existing service helper.
4. For Photos, validate the supplied image bytes and image dimensions.
   Reject malformed data or unsupported formats with 400 and oversized
   uploads with the existing 413 behavior. Enforce a decoded image limit
   of 100 million pixels per image to bound pathological inputs.
5. Store validated uploads through the shared attachment store. Retain
   multipart file order and reject duplicate attachment selections for
   one post, since the relation primary key cannot represent duplicates.
6. Build `ComposeParams`, including ordered IDs and descriptions. The
   browser must submit files in selected order; the handler must preserve
   that order. Do not depend on filename sorting or map iteration.
7. In `Service::createPost()`, verify the selected assets exist and meet
   the final kind requirements. Validation must apply to non-HTML callers
   too. Create the post, recipients, ordered relationships, sticker, and
   reply notification in the write transaction.
8. Use the existing delivery enqueue path after successful creation.
   A photo has the same delivery reliability semantics as a social post.
9. Redirect successful top-level photo composition to its canonical post
   or the Photos view according to the current post-create convention.
   Keep reply redirects anchored to the thread.

Use `mw::E<>` errors with existing HTTP error translation. Preserve draft
text, mode, descriptions, and ordering on recoverable form errors where
possible. Browsers may require selecting files again after a full-page
error; tell the user when that is necessary. Clean newly created,
unreferenced assets after a failed submission without removing files
shared by another post or profile. Never delete a deduplicated asset just
because the current request failed.

### 8.3 Ordering and alt text

Add per-file description and move-left/move-right controls to the photo
composer; support keyboard use as well as pointer input. Associate each
description with a stable client file token, then translate to the saved
attachment ID after upload. Filenames alone are not stable keys because
two distinct files can have the same name.

`post_attachments.sort_order` remains the source of image order. Save
descriptions on the relation, not the shared asset. Selecting the same
file in another post can use different alt text and order. An explicitly
empty description stays empty and does not fall back to the filename.
Adjust upload defaults accordingly; the current handler prepopulates
descriptions from filenames.

## 9. Gallery Rendering

Add `post_kind` and an ordered `photos` array to the shared post view.
Each photo has an attachment ID, URL, description, sensitivity, and
optional width/height. Keep ordinary attachments and stickers available
to their existing render paths; avoid displaying photo attachments twice.

Photo cards display author and timestamp, a large image area, the
caption, and shared interaction controls. Preserve the entire image's
aspect ratio with contained scaling. Multiple images form a horizontally
scrollable gallery with visible position indicators and previous/next
buttons. The first image is the default cover; a separate cover selector
is unnecessary initially.

The gallery works with CSS overflow and links without JavaScript.
Enhance it with keyboard navigation and the existing attachment lightbox.
Give buttons explicit names and associate indicators with their images.
Lazy-load offscreen images. When dimensions are known, reserve their
aspect ratio to reduce layout shifts; tolerate unknown remote dimensions.

Caption Markdown follows the same render/sanitization path as social
content. Alt text is a separate image description, not the caption. Honor
content warnings and sensitive-media hiding before loading gallery media,
including cover images and future thumbnails. Do not reveal a hidden
photo through a background image, eagerly loaded thumbnail, or preview.

Do not render automatic link preview cards inside photo cards initially;
the caption's links still work. Existing preview storage and federation
content are unaffected. Stickers retain their separate placement.

An explicitly marked remote photo with no renderable image shows its
caption and an unavailable-media placeholder. Other remote attachments
remain accessible as ordinary attachment links after existing URL safety
checks. Do not download remote files to inspect them or generate local
derivatives as a side effect of viewing a feed.

All bundled themes must support the gallery. Search, bookmarks,
notifications, and thread roots select rendering by saved post kind.
Existing anonymous-readability checks remain the gate for Open Graph
metadata; a private photo must not appear in public sharing metadata.

## 10. Follow-up Phase: Photo Derivatives

### 10.1 Storage and output contract

The initial stream uses existing attachment bytes. To regain nspic's
bandwidth savings, add derived display and thumbnail images in a later
phase, without changing post identity, kind, or attachment relationships.
Preserve the original uploaded asset under its existing URL. Unlike
nspic, never replace or delete it merely to create a smaller image.

Add optional decoded width and height to local attachment metadata and a
table `attachment_variants` with:

- `attachment_id`, a cascading foreign key to the source asset.
- `variant_kind`, `DISPLAY` or `THUMBNAIL`, persisted as 0 or 1.
- `generator_version`, an integer identifying processing rules.
- `relative_path`, a unique application-generated storage path.
- `media_type`, decoded width, height, and byte size.
- A primary key on `(attachment_id, variant_kind, generator_version)`.

Variants belong to the asset so duplicate uploads share their processing
cost. Descriptions and sensitivity remain on each post relation. Store
files beneath a reserved media subtree keyed by source hash, extension,
variant kind, and generator version. Serve them through a distinct
`/media/variants/:shard/:filename` route registered before general media
routes. Accept generated basenames only, never arbitrary client paths.

Default display output fits inside 2048 by 2048 pixels; thumbnails fit
inside 480 by 480. Do not upscale or crop. Use WebP at quality 85, preserve
transparency, apply orientation before removing metadata, convert to
sRGB, and omit camera/GPS metadata from derivatives. The original remains
available and may retain its original metadata; the UI must not describe
the overall upload as metadata-free.

### 10.2 Magick++ integration and failures

Link Magick++ directly into the application and test target. Discover the
installed ImageMagick 7 Magick++ package through pkg-config in CMake and
link its imported target, carrying the package's include paths, compiler
definitions, and transitive libraries. Do not hardcode quantum-depth or
HDRI flags; they must match the installed library build. Update Arch
packaging and the documented build dependencies accordingly. See the
official [Magick++ documentation](https://imagemagick.org/magick++/).

Keep `<Magick++.h>` and library-specific operations inside a shared
`photo_processing.cpp` implementation with a small `photo_processing.hpp`
interface. Expose documented functions returning `mw::E<>` for image
inspection, validation, and variant generation. Return plain application
metadata structures rather than Magick++ objects from that interface.
Uploads, import, and derivative jobs must reuse this wrapper.

Initialize Magick++ once at application or importer startup, before
starting request or job threads. Configure resource limits and policy
once at startup too; do not mutate process-wide limits for individual
requests. Use local `Magick::Image` objects for each operation, with no
shared mutable image objects between workers. Decode uploaded bytes
through `Magick::Blob`; filenames supplied by users must not become
ImageMagick filename expressions. Stored input and output paths are
application-generated and validated.

At this library boundary, catch `Magick::Exception` and translate it to
`mw::E<>` errors. Keep these necessary try/catch blocks inside the wrapper;
Magick++ exceptions must not escape into HTTP handlers or job workers.
Reject corrupt-image warnings during validation rather than accepting a
partial decode. Use the library API for orientation, colorspace conversion,
resizing, metadata removal, and encoding.

Permit at most two concurrent photo operations across upload validation,
import processing, and derivative workers in each application process.
Use a shared admission limit so synchronous validation cannot bypass the
worker limit. Permit only the selected raster decoders and WebP encoder;
disable network, document, SVG, and delegate processing. Apply memory,
pixel-cache disk, dimension, frame-count, thread, and processing-time
limits through the supplied policy and supported library resource APIs.
See ImageMagick's [security policy](https://imagemagick.org/security-policy/).

These are in-process library limits, not an isolated subprocess timeout.
Do not implement a 30-second deadline by abandoning or forcibly stopping
a thread that may still be inside Magick++. Library time-limit failures
follow the same error path as other resource failures. Do not promise a
hard per-image wall-clock deadline or crash isolation for this design.

Use an application-owned pending-job queue rather than ActivityPub
delivery jobs: this processing has local filesystem inputs and does not
belong to the federation library. Persist source attachment ID,
generator version, attempts, next-run time, state, and last error. A
unique active job per source/version prevents duplicate work. Retry up to
three times; preserve a visible operator error after the final failure.

Generate both variants into temporary files in the target filesystem,
validate dimensions and formats, then atomically rename them to final
paths and persist their metadata. A crash after rename but before commit
leaves recoverable orphan files; a retry can verify and reuse them. Never
commit a variant row pointing at an unfinished temporary file.

Publishing does not wait for variants. Before completion or after failure,
gallery views fall back to the original URL. Keep federation attachment
URLs pointing to the original in this phase; changing delivery format is
a separate compatibility decision. Remote URL-backed assets and stickers
are excluded from generation. Backfill local photo assets with a resumable
operator command. Deleting an unreferenced source removes its variants
and pending jobs through the same reference-aware cleanup path.

## 11. nspic Import

### 11.1 Command and preconditions

Provide an operator CLI using existing C++ application data helpers and
libmw. Proposed command shape, to be integrated with the current argument
parser:

```text
unspoken import-nspic --config /etc/unspoken/config.yaml \
    --source-db /backup/nspic/db.sqlite \
    --image-dir /backup/nspic/images \
    --source-key personal-nspic --author alice --dry-run
```

Running without `--dry-run` performs the import. This is an operator
action, not an HTTP endpoint. Read a consistent SQLite backup and a
matching image directory; open the source database read-only. Stop nspic
writes while taking the backup. Run the import with Unspoken stopped so
the importer is the sole application writer and a rollback backup is
well-defined.

The source has no per-post Unspoken actor identity. Require an explicit
existing local author; never infer one from the old site title or display
name. Require a stable `source-key` supplied by the operator; moving the
backup directory must not turn it into a different import source.

### 11.2 Durable mapping

Add this application table in the initial schema migration:

```sql
CREATE TABLE nspic_imports (
    source_key TEXT NOT NULL,
    source_post_id INTEGER NOT NULL,
    author_id INTEGER NOT NULL REFERENCES users(id),
    post_id INTEGER REFERENCES posts(id) ON DELETE SET NULL,
    source_digest TEXT NOT NULL,
    imported_at INTEGER NOT NULL,
    PRIMARY KEY(source_key, source_post_id)
);
```

The source digest covers caption, timestamp, ordered source image bytes,
and recorded album data using an unambiguous length-prefixed encoding
and SHA-256. Store an algorithm/version prefix with the digest. It detects
changes on rerun; it is not the post's identity. Existing mapping with the
same digest and author is skipped. A different digest or author is an
error requiring explicit operator reconciliation, not an automatic edit.
If a previously imported post was deleted, the null mapping prevents a
rerun from resurrecting it.

### 11.3 Per-post algorithm

1. Read source posts in `(upload_time ASC, id ASC)` order. This preserves
   relative historical order among imported posts when IDs are assigned.
2. Read each post's images in `images.id ASC` order. nspic has no explicit
   sort-order column and its current reader does not ORDER BY images;
   insertion ID is the deterministic recoverable approximation. Report
   this limitation instead of claiming to recover an independent order.
3. Resolve every image path beneath the configured source image root.
   Reject absolute paths, traversal, symlink escapes, missing files, and
   non-regular files. Import the actual stored image, not its `_t`
   thumbnail, as the canonical attachment. nspic may already have removed
   the camera original, so that original cannot be reconstructed.
4. Verify each image is supported raster content, nonempty, and within
   `max_upload_bytes` and the photo pixel limit. Reject zero-image posts
   with a report entry.
   Do not silently downgrade a failed import to Social or omit an image.
5. Compute the source digest and check the durable mapping. In dry-run,
   report the intended mapping, file count, bytes, and validation errors
   without writing files or opening a destination write transaction.
6. Copy bytes into Unspoken's content-addressed attachment store. Preserve
   source files. Deduplicate through the destination's existing asset key,
   rather than relying on nspic's truncated source hash filenames.
7. Treat the source description as plain text: HTML-escape it and preserve
   line breaks for `content_html`; generate escaped Markdown source that
   round-trips to the same text. Do not interpret old descriptions as raw
   HTML or newly introduce mentions through Markdown parsing.
8. In one destination transaction, create a `PHOTO` post by the selected
   author with `PUBLIC` visibility, no reply parent, no sticker, empty
   per-image descriptions, original publication timestamp, and ordered
   attachment relations. nspic's image rows have no alt text; do not invent
   it from captions or filenames. Record the import mapping in the same
   transaction. Bypass ordinary compose delivery and mention processing.
9. Do not enqueue Create/Update deliveries, notifications, or webhooks.
   Imported public posts can still appear in the author's outbox and be
   fetched or boosted afterward; silent import means no proactive history
   broadcast, not hidden federation objects.
10. Emit a machine-readable report mapping old source IDs to new post
    URLs, including skipped mappings, failures, and any source album data.

Set `published` from nspic's UTC epoch seconds. Keep `created_at` as local
insertion time, matching Unspoken's model. IDs and home event IDs are
assigned during import, so imported history appears near import time
relative to existing Unspoken posts, while displayed dates are historical.
Do not backdate or renumber existing timeline cursors. Fixing global
historical interleaving would require a separate timeline-order redesign.

Preflight the entire source before performing a non-dry import; if it
contains invalid records, fail without importing anything. During the
write pass, commit one complete source post at a time. On an unexpected
failure, stop, retain prior committed mappings, and report the failing ID.
Rerunning resumes without duplication. Clean unreferenced copied assets
with the shared reference-aware cleanup mechanism.

The importer does not take over nspic's old origin or guess redirect
routes. Use its ID-to-URL report to configure redirects on the old site
when desired. Keep the original backup until counts, media, and links
have been reviewed.

## 12. Verification

### 12.1 Classification and service tests

- Existing and fresh databases both default posts to `SOCIAL`; invalid
  persisted enum integers fail the CHECK constraint.
- Text-only social, social with photos, sticker-only social, photo with
  caption, and captionless photo have the intended classification.
- Local Photos reject zero photos, sticker-only content, invalid image
  bytes, documents, SVG, duplicate selections, and excessive dimensions.
- Local edits retain kind when omitted and reject an explicit change;
  caption edits retain attachments, identity, audience, and ordering.
- Identical assets on two posts retain independent descriptions and order.

### 12.2 Federation tests

- A Note with image attachments and no kind is always `SOCIAL`.
- A Note with `photo` under an unrelated key is `SOCIAL`.
- The recognized `photo` value works on inbox Create and resolved objects.
- Unknown, null, uppercase, and non-string kinds safely become `SOCIAL`.
- Explicit remote photos remain photos with absent or broken attachments.
- Full Update without kind resets a photo to Social; explicit Update can
  move it back. Unauthorized updates cannot change either classification.
- Announce follows the original's kind; duplicate Create and Announce
  operations preserve existing idempotency behavior.
- Local fetch, Create, Update, and outbox documents emit the same kind.
- A failed attachment write rolls back an inbound classification update.

### 12.3 Timeline and UI tests

- Interleave more than one page of social posts, photos, replies, and
  boost events. Both tabs paginate in each direction without leaking the
  other kind, duplicating boosts, or stopping at a filtered mixed page.
- Verify home uses event cursors and public/profiles use post cursors.
- Verify `/` selects Social and `/photos` selects Photos for authenticated
  and anonymous visitors. Pagination retains the selected path, query
  parameters cannot override its kind, and switching tabs resets cursors.
- Test private, direct, followers-only, unlisted, and public cases in both
  kinds using the existing visibility expectations.
- Photo replies stay out of the photo stream but appear in full threads;
  social replies to photos retain current social timeline eligibility.
- Outboxes, search, bookmarks, and notifications retain both kinds.
- Forms preserve kind, upload order, and description association; edit
  forms cannot reset the kind through a missing field.
- Test keyboard gallery navigation, no-JavaScript scrolling, all themes,
  sensitive-media reveal behavior, and the no-photo remote placeholder.

### 12.4 Import and derivative tests

Use small temporary SQLite sources and real fixture image bytes. Cover
caption escaping, equal timestamps, deterministic image order, asset
deduplication, missing files, path escapes, invalid formats, dry-run
without writes, interrupted imports, changed source digests, deleted
mapped posts, and reruns. Assert no delivery job, notification, or webhook
is generated. Verify existing source bytes remain unchanged.

When implementing derivatives, test orientation, alpha, small images
without upscaling, first-frame behavior, Magick++ exception translation,
resource-limit failure, retry after a crash, missing-variant fallback,
and cleanup of shared sources. Verify removed metadata separately from
the intentionally retained original bytes.

Use the repository's existing C++ test target and JavaScript test style.
Compile with `cmake --build build -j24`, then run appropriate CTest and
HTTP checks. The documentation-only change that introduces this design
does not require compiling the application.

## 13. Implementation Sequence and Rollout

1. Add `PostKind`, conversion helpers, migration, row mappings, and
   persistence tests. Include import bookkeeping, but no derivative
   storage yet. Existing rows remain Social.
2. Add canonical wire serialization and shared inbound normalization.
   Cover complete Update behavior and atomic post/attachment persistence.
3. Add required kind arguments to stream queries and update all callers,
   mocks, profiles, and home pagination. Audit outbox callers separately.
4. Add Magick++ linking, startup initialization, the shared processing
   wrapper, composer mode, image validation, ordering, alt-text controls,
   and immutable-kind edit handling. Retain ordinary social uploads.
5. Add tabs and photo gallery rendering, reusing interaction controls,
   lightbox, warnings, authorization, and themes. Complete mixed-stream
   pagination and HTTP checks before exposing Photos navigation.
6. Implement the offline importer, report format, and dry-run. Validate
   against a backup of the actual nspic data before the operator import.
7. Document the wire extension, route parameters, import command, backup
   procedure, and format limits in the operator guide. Run the import
   during a maintenance window and compare report counts with the source.
8. Implement derivatives as the follow-up media phase in section 10.

Before schema migration and import, back up the destination database and
attachment directory together. A rollback restores that matching snapshot
with the prior binary; do not start an old binary against the new schema.
Leave the nspic backup intact. No old post should change classification
merely because it contained an image, and no incoming unlabeled post
should enter Photos after rollout.

[ap-update]: https://www.w3.org/TR/activitypub/#update-activity-inbox
