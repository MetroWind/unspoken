# Design Document: Rich Actor Profiles

**Status:** Draft
**Source requirements:** [`prd.md`](../prd.md), especially profile
editing, ActivityPub actor documents, attachments, remote actor
resolution, HTML sanitization, and local actor `Update` delivery.
**Related designs:**
[`design-0-architecture.md`](design-0-architecture.md),
[`design-1-emoji.md`](design-1-emoji.md), and
[`design-2-interop.md`](design-2-interop.md)
**Scope:** Add Fediverse-compatible rich user profiles with avatar,
banner image, and profile metadata fields. The design covers local
profile editing, local ActivityPub actor output, remote actor parsing,
HTML rendering, database schema changes, and tests.

---

## 1. Problem Statement

The current local profile model is intentionally small. A local user has
a username, display name, and Markdown bio. This satisfies the initial
PRD requirement that a user can edit their display name and bio, but it
does not match the profile surface used by common Fediverse software.

Pleroma, Akkoma, Mastodon, and related servers commonly expose richer
actor documents. A profile usually has:

- An avatar, represented in ActivityPub as actor `icon`.
- A banner or header image, represented in ActivityPub as actor `image`.
- Profile metadata rows, represented as actor `attachment` entries whose
  type is `PropertyValue`.
- A rich HTML bio, represented as actor `summary`.

For example, the Pleroma actor at
<https://pleroma.xeno.darksair.org/users/mw> exposes `icon`, `image`,
and multiple `attachment` `PropertyValue` items. The exact values belong
to that remote actor, but the structure is the important contract.

The current implementation already stores raw remote actor JSON in the
`remote_actors.actor_json` column. That means we can display richer
remote profile data without refetching or widening the remote actor table
first. Local profiles need more work because local profile data must be
editable, stored in SQLite, rendered in HTML, and serialized into our own
actor documents.

This design treats the feature as an ActivityPub actor-profile feature,
not merely a template change. The local HTML UI and the ActivityPub JSON
must describe the same account state.

---

## 2. Goals

### 2.1 User Goals

- Let a local user upload or replace an avatar.
- Let a local user upload or replace a banner image.
- Let a local user add ordered profile metadata rows, such as `Blog`,
  `Matrix`, or `XMPP`.
- Render avatar, banner, bio, and metadata on local profile pages.
- Render the same richer fields for remote actors where the remote actor
  document provides them.
- Keep the edit-profile page simple and server-rendered.
- Preserve existing display name and bio behavior.
- Federate local profile changes through an actor `Update` activity so
  remote followers can refresh the account profile.

### 2.2 Engineering Goals

- Use standard ActivityStreams actor fields:
  - `icon` for avatar.
  - `image` for banner.
  - `attachment` with `PropertyValue` entries for metadata.
  - `summary` for bio HTML.
- Reuse the existing local file storage rules for uploaded files:
  content hash filenames, first-hash-character subdirectories, and
  duplicate file reuse.
- Keep request handlers thin. Profile validation, storage decisions, and
  view-model construction should live in service/data helpers, not inside
  HTTP handler bodies.
- Keep remote media remote. Do not proxy or cache remote avatars and
  banners in v1 of this feature.
- Sanitize all remote profile HTML before rendering.
- Store local profile metadata in normalized rows, not a single JSON
  blob. Metadata values use Markdown source, like the profile bio.
- Design the data model so a future Mastodon-compatible API can expose
  the same state without scraping rendered HTML.

### 2.3 Non-Goals

- Do not implement verified profile links in this design. Pleroma and
  Mastodon can include verification state, but link verification requires
  outbound fetching and rel-me style checks. That is separate work.
- Do not implement account migration or aliases beyond preserving
  existing remote `alsoKnownAs` data in raw actor JSON.
- Do not implement profile discoverability settings, locked accounts, or
  manual follow approval.
- Do not add client-side cropping or image editing.
- Do not proxy remote avatar or banner media.
- Do not expose a Mastodon client API yet. This design keeps the model
  compatible with that future work.

---

## 3. External References

- [ActivityPub Recommendation](https://www.w3.org/TR/activitypub/)
- [ActivityStreams Vocabulary][activitystreams-vocabulary]
- [ActivityStreams Core](https://www.w3.org/TR/activitystreams-core/)
- [Schema.org PropertyValue](https://schema.org/PropertyValue)
- [Mastodon profile fields API](https://docs.joinmastodon.org/entities/Field/)
- [Mastodon Account entity](https://docs.joinmastodon.org/entities/Account/)
- [Pleroma/Akkoma actor example](https://pleroma.xeno.darksair.org/users/mw)

[activitystreams-vocabulary]:
  https://www.w3.org/TR/activitystreams-vocabulary/

These references matter because profile interoperability is mostly a
convention layered on top of ActivityStreams. ActivityStreams defines the
generic object model and image properties, while real Fediverse servers
have converged on `PropertyValue` entries inside actor `attachment` for
profile metadata rows.

---

## 4. Existing System

### 4.1 Local User State

Local accounts are represented by `User` and `NewUser` in
`src/structs.hpp`. The current profile-related fields are:

```text
username
display_name
bio
```

`username` is immutable because it is part of the local actor URI and
Fediverse handle. `display_name` and `bio` are editable.

The SQLite `users` table mirrors these fields. The current profile edit
route updates only `display_name` and `bio`.

### 4.2 Local Actor JSON

The local actor JSON is built by `actorJson()`. It currently emits:

```json
{
  "type": "Person",
  "id": "https://example.test/u/alice",
  "preferredUsername": "alice",
  "name": "Alice",
  "summary": "<p>bio</p>",
  "inbox": "...",
  "outbox": "...",
  "followers": "...",
  "following": "...",
  "endpoints": {"sharedInbox": "..."},
  "publicKey": {"...": "..."}
}
```

This is valid but minimal. It has no avatar, banner, or metadata rows.

### 4.3 Remote Actor State

Remote actors are stored in `remote_actors`. The table extracts fields
needed for federation, such as actor URI, inbox, shared inbox, public
key, and display name. It also stores the complete remote actor document
in `actor_json`.

This raw JSON is important. It lets us display richer remote profile
fields without changing remote fetch semantics. If a remote actor has
`icon`, `image`, or `attachment`, the renderer can parse them from the
cached document.

### 4.4 Existing Attachment Storage

Uploaded files are stored by SHA-256 hash under the configured
attachment directory. The `attachments` table has a nullable `post_id`.
The architecture document describes `post_id = NULL` as a draft state.

Profile media should reuse the file storage layer, but profile ownership
must be explicit. Otherwise an unattached avatar can be mistaken for a
post draft.

This design normalizes attachments into two concepts:

- `attachments`: one row for one stored local file or one remote media
  URL.
- `post_attachments`: one row for each attachment shown on a post.
- `users`: account rows also carry avatar and banner attachment
  references.

That model matches the product rule that duplicate uploads reuse an
existing server file. If the same stored file is used by two posts, or by
a post and a profile avatar, it is still one attachment. The referencing
tables describe where that attachment appears.

---

## 5. ActivityPub Representation

### 5.1 Actor Avatar

Use the actor `icon` property.

Local output shape:

```json
{
  "icon": {
    "type": "Image",
    "mediaType": "image/png",
    "url": "https://example.test/media/a/abcdef.png",
    "name": "avatar.png"
  }
}
```

Rules:

- Omit `icon` when the user has no avatar.
- `type` is always `Image`.
- `mediaType` is the stored attachment media type.
- `url` is the public media URL for the stored attachment.
- `name` is optional but should use the original filename when present.

### 5.2 Actor Banner

Use the actor `image` property.

Local output shape:

```json
{
  "image": {
    "type": "Image",
    "mediaType": "image/jpeg",
    "url": "https://example.test/media/b/bcdef0.jpg",
    "name": "banner.jpg"
  }
}
```

Rules are the same as `icon`. The difference is semantic: `icon` is a
small identity image, while `image` is the larger profile header image.

### 5.3 Profile Metadata

Use actor `attachment` with `PropertyValue` objects.

Local output shape:

```json
{
  "attachment": [
    {
      "type": "PropertyValue",
      "name": "Blog",
      "value": "<a href=\"https://example.test\">https://example.test</a>"
    },
    {
      "type": "PropertyValue",
      "name": "Matrix",
      "value": "@alice:example.test"
    }
  ]
}
```

Rules:

- Omit `attachment` when there are no metadata rows.
- Preserve row order.
- `name` is a short plain-text label.
- `value` is sanitized HTML.
- Empty labels or empty values are not serialized.
- Unknown non-`PropertyValue` attachments from remote actors are ignored
  by the profile metadata renderer.

### 5.4 Actor Summary

Continue using actor `summary` for the rendered bio HTML.

Local users write Markdown. The server renders that Markdown to HTML
before serializing `summary`. Remote actor summaries are already HTML and
must be sanitized before rendering in our UI.

### 5.5 Actor Update Activities

When a local profile changes, send an ActivityPub `Update` activity to
followers. The object is the full updated actor document.

Shape:

```json
{
  "@context": "...",
  "type": "Update",
  "id": "https://example.test/activities/...",
  "actor": "https://example.test/u/alice",
  "to": ["https://www.w3.org/ns/activitystreams#Public"],
  "cc": ["https://example.test/u/alice/followers"],
  "object": {
    "type": "Person",
    "id": "https://example.test/u/alice",
    "preferredUsername": "alice",
    "name": "Alice",
    "summary": "<p>bio</p>",
    "icon": {"type": "Image", "url": "..."},
    "image": {"type": "Image", "url": "..."},
    "attachment": [{"type": "PropertyValue", "name": "...", "value": "..."}]
  }
}
```

This is an extension of the existing actor-update delivery path. The
important behavior is that every profile edit produces one complete actor
object, not a partial patch. Remote servers generally replace cached
profile fields from the received actor object.

---

## 6. Data Model

### 6.1 Schema Version

The current architecture uses `PRAGMA user_version` and schema version
`1`. This feature should be introduced as the next schema version
available at implementation time. If the current version is still `1`,
this migration becomes version `2`.

Migrations are part of the data-source contract. The
`DataSourceInterface` already abstracts over the database backend for
normal reads and writes; schema migration belongs behind the same
abstraction.

If this is the first migration, add interface methods similar to:

```c++
virtual mw::E<void> migrate1To2() const = 0;
```

Later migrations follow the same naming pattern:

```c++
virtual mw::E<void> migrate2To3() const = 0;
virtual mw::E<void> migrate3To4() const = 0;
```

`DataSourceSQLite` implements those methods with SQLite-specific SQL.
A future data-source implementation would implement the same version
transitions using that backend's DDL and transaction rules.

Startup migration dispatch should apply every missing migration in
order:

```text
version = PRAGMA user_version
if version == 0:
    create current schema
    set user_version = CURRENT_SCHEMA_VERSION
else:
    while version < CURRENT_SCHEMA_VERSION:
        if version == 1: migrate1To2()
        if version == 2: migrate2To3()
        ...
        version += 1
        set user_version = version
```

Rules:

- Each migration function runs in one backend write transaction.
- The migration sets `user_version` only after all schema and data
  changes for that step succeed.
- If any step fails, roll back the transaction and keep the old
  `user_version`.
- A fresh database should be created directly at
  `CURRENT_SCHEMA_VERSION`, not by creating v1 and replaying all
  migrations.
- Startup must reject databases whose `user_version` is newer than the
  compiled `CURRENT_SCHEMA_VERSION`.

For this feature, `DataSourceInterface::migrate1To2()` should:

1. Create the normalized attachment table shape and preserve existing
   attachment data.
2. Create `post_attachments`.
3. Backfill `post_attachments` from existing `attachments.post_id`.
4. Copy existing attachment sensitivity into `post_attachments`.
5. Add `users.avatar_attachment_id` and `users.banner_attachment_id`.
6. Add indexes for avatar, banner, and post attachment reference checks.
7. Create `user_profile_fields`.
8. Leave existing display names and bios unchanged.
9. Set `user_version = 2` only after the data migration succeeds.

The SQLite implementation has limited `ALTER TABLE` support. If the
attachment table cannot be transformed in place cleanly, use the
standard rebuild pattern:

1. Create `attachments_new`.
2. Copy and deduplicate rows from `attachments` into `attachments_new`.
3. Create a temporary mapping from old attachment IDs to new attachment
   IDs.
4. Backfill `post_attachments` through that mapping.
5. Drop the old table.
6. Rename `attachments_new` to `attachments`.
7. Create the final indexes.

This design is the first concrete use of the migration dispatch that
the architecture document reserved for post-v1 schema changes.
### 6.2 Attachment Table Normalization

The existing `attachments` table stores both file identity and per-use
state. For richer profiles and reliable file deletion, split those
responsibilities.

The normalized `attachments` row represents the media resource:

```sql
CREATE TABLE attachments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256        TEXT,
    extension     TEXT,
    media_type    TEXT NOT NULL,
    original_name TEXT NOT NULL DEFAULT '',
    is_image      INTEGER NOT NULL DEFAULT 0,
    remote_url    TEXT,
    created_at    INTEGER NOT NULL,
    CHECK (
        (remote_url IS NULL AND sha256 IS NOT NULL
         AND extension IS NOT NULL)
        OR
        (remote_url IS NOT NULL AND sha256 IS NULL
         AND extension IS NULL)
    )
);

CREATE UNIQUE INDEX idx_attachments_local_file
ON attachments(sha256, extension)
WHERE remote_url IS NULL;

CREATE UNIQUE INDEX idx_attachments_remote_url
ON attachments(remote_url)
WHERE remote_url IS NOT NULL;
```

Rules:

- A local attachment has `sha256` and `extension`.
- A remote attachment has `remote_url`.
- `media_type` and `is_image` describe the media resource.
- `original_name` is stored as simple display metadata on the
  attachment. If duplicate uploads use different filenames, the first
  stored name can win; the exact original filename is not important for
  social-media image display.
- `sensitive` is not file identity. It moves to `post_attachments`.
- `post_id` is not file identity. It moves to `post_attachments`.
- Duplicate local uploads resolve to the existing row for
  `(sha256, extension)`.
- Duplicate remote imports resolve to the existing row for `remote_url`.

Why include `extension` in the local uniqueness key:

- The current storage path is based on hash plus extension.
- Two uploads with the same bytes but different extensions resolve to
  different stored filenames under the current storage rule.
- If storage is later changed to key only by hash, the uniqueness rule
  can be simplified in that later migration.

### 6.3 Post Attachments Table

Add an explicit relation table for attachments shown on posts:

```sql
CREATE TABLE post_attachments (
    post_id       INTEGER NOT NULL
                  REFERENCES posts(id) ON DELETE CASCADE,
    attachment_id INTEGER NOT NULL
                  REFERENCES attachments(id) ON DELETE CASCADE,
    sensitive     INTEGER NOT NULL DEFAULT 0,
    sort_order    INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    PRIMARY KEY (post_id, attachment_id)
);

CREATE INDEX idx_post_attachments_attachment
ON post_attachments(attachment_id);

CREATE INDEX idx_post_attachments_post
ON post_attachments(post_id, sort_order, attachment_id);
```

Rules:

- `post_id` identifies the post.
- `attachment_id` identifies the media resource.
- `sensitive` controls whether this post hides the media behind a
  sensitive-media disclosure.
- `sort_order` preserves display order within the post.
- Deleting a post removes its post attachment rows automatically.

Why this table exists:

- A post can have many attachments.
- The same attachment can appear in more than one post.
- Per-post state belongs here, not on `attachments`.
- Cleanup can quickly test post references through
  `idx_post_attachments_attachment`.

### 6.4 Users Table Changes

Add avatar and banner attachment references to the existing `users`
table:

```sql
ALTER TABLE users ADD COLUMN avatar_attachment_id INTEGER
    REFERENCES attachments(id) ON DELETE SET NULL;

ALTER TABLE users ADD COLUMN banner_attachment_id INTEGER
    REFERENCES attachments(id) ON DELETE SET NULL;

CREATE INDEX idx_users_avatar_attachment
ON users(avatar_attachment_id);

CREATE INDEX idx_users_banner_attachment
ON users(banner_attachment_id);
```

Rules:

- `avatar_attachment_id` identifies the profile avatar.
- `banner_attachment_id` identifies the profile banner.
- Profile media attachments must be local, must be images, and must not
  have `remote_url` set.
- The service layer enforces profile media rules.
- The avatar and banner indexes make cleanup reference checks cheap.

The existing `attachments.post_id` and `attachments.sensitive` columns
should become legacy state. During migration:

1. Create one normalized attachment row for each unique local stored file
   or remote URL.
2. Create one `post_attachments` row for every existing post attachment.
3. Copy the old `sensitive` value into the post attachment row.
4. Make new code read and write `post_attachments` instead of treating
   `attachments.post_id` as the source of truth.

Whenever code removes an attachment reference, it should immediately
check whether the attachment is still referenced by `post_attachments`,
`users.avatar_attachment_id`, or `users.banner_attachment_id`. If no
references remain, delete the local stored file for local attachments,
then delete the attachment row. For remote attachments, delete only the
database row.

### 6.5 Profile Metadata Table

Add a normalized table:

```sql
CREATE TABLE user_profile_fields (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL
                REFERENCES users(id) ON DELETE CASCADE,
    label       TEXT NOT NULL,
    value       TEXT NOT NULL,
    sort_order  INTEGER NOT NULL
);

CREATE INDEX idx_user_profile_fields_user
ON user_profile_fields(user_id, sort_order, id);
```

The table intentionally stores Markdown source text, not pre-rendered
HTML.

Rules:

- `label` is plain text.
- `value` is Markdown source.
- `sort_order` controls display and ActivityPub serialization order.
- The service layer renders `value` from Markdown into sanitized HTML
  for local actor JSON and HTML views.
- Deleting a field removes the row.
- Reordering fields updates `sort_order`.
- `user_id` is a foreign key to `users(id)` with `ON DELETE CASCADE`
  because a profile field has no meaning without its owning user.

Why not JSON:

- Rows are easier to reorder.
- Rows are easier to validate individually.
- Rows map naturally to future Mastodon-compatible API field objects.
- Rows avoid rewriting an entire JSON blob for one field edit.
- SQL tests can assert exact row state without parsing JSON.

### 6.6 Struct Additions

Add these plain structs to the struct module:

```c++
// One local profile metadata row owned by a user.
struct UserProfileField
{
    int64_t id = 0;
    int64_t user_id = 0;
    std::string label;
    std::string value;
    int sort_order = 0;
};

// Editable profile data submitted by the profile form.
struct UserProfileUpdate
{
    std::string display_name;
    std::string bio;
    std::optional<int64_t> avatar_attachment_id;
    std::optional<int64_t> banner_attachment_id;
    std::vector<UserProfileField> fields;
};

```

The exact edit DTO can differ during implementation, but it should carry
the complete desired profile state. Complete-state updates are easier to
reason about than many small patch operations because the edit form
submits the whole profile.

### 6.7 Data Module API

Add data-layer operations similar to:

```c++
mw::E<std::vector<UserProfileField>>
profileFieldsForUser(int64_t user_id) const;

mw::E<void>
replaceProfileFields(
    int64_t user_id,
    const std::vector<UserProfileField>& fields) const;

mw::E<void>
updateUserProfile(
    int64_t id,
    std::string_view display_name,
    std::string_view bio) const;

mw::E<std::vector<Attachment>>
attachmentsForPost(int64_t post_id) const;

mw::E<void>
replacePostAttachments(
    int64_t post_id,
    const std::vector<int64_t>& attachment_ids) const;

mw::E<void>
updateProfileMedia(
    int64_t user_id,
    std::optional<int64_t> avatar_attachment_id,
    std::optional<int64_t> banner_attachment_id) const;

mw::E<void>
deleteUnreferencedAttachments(
    const std::vector<int64_t>& detached_attachment_ids) const;
```

The implementation should wrap profile changes in one write transaction:

1. Validate referenced attachment IDs.
2. Update `users.display_name` and `users.bio`.
3. Update the user's profile avatar and banner references.
4. Delete existing `user_profile_fields` rows for the user.
5. Insert the submitted fields with stable `sort_order`.
6. Commit.

This transaction prevents a profile page from seeing a new avatar with
old metadata rows, or new metadata rows with an old display name.

After the transaction commits, run the unreferenced-attachment cleanup
helper for any attachment IDs that lost post or profile references. The
helper must not run inside the database transaction if filesystem
deletion failure would make database rollback ambiguous. If file deletion
fails, log the failure and leave the database state correct.

---

## 7. Validation Rules

### 7.1 Display Name

Keep existing behavior unless implementation already has stricter
limits. Add a soft UI limit and a hard server limit.

Recommended hard limit:

```text
display_name: 0 to 120 UTF-8 bytes
```

Empty display name is allowed. Rendering falls back to username.

### 7.2 Bio

Recommended hard limit:

```text
bio: 0 to 5000 UTF-8 bytes
```

The bio remains Markdown source for local users. It is rendered through
the existing Markdown and sanitization path before display or federation.

### 7.3 Avatar

Validation:

- File must be uploaded through the existing upload pipeline.
- File must be an image media type accepted by the server.
- SVG may be allowed only if the existing image attachment policy allows
  SVG inline display. If SVG is allowed, it must use the same safety
  policy as normal attachments.
- File size must obey the global upload size limit.
- The stored attachment must be local.

Recommended UI guidance:

```text
avatar: square image recommended
```

Do not enforce dimensions in the first implementation because the PRD
explicitly keeps decompression-bomb and dimension limits out of v1
attachment scope.

### 7.4 Banner

Validation is the same as avatar.

Recommended UI guidance:

```text
banner: wide image recommended
```

The renderer should crop with CSS rather than modifying the uploaded
file.

### 7.5 Metadata Fields

Recommended hard limits:

```text
maximum rows: 8
label: 1 to 40 UTF-8 bytes after trimming
value: 1 to 250 UTF-8 bytes after trimming
```

Rules:

- Trim leading and trailing whitespace.
- Drop rows where both label and value are empty.
- Reject rows where only one side is empty.
- Reject rows over the byte limits.
- Preserve row order after dropping fully empty rows.
- Escape labels as plain text.
- Render values from Markdown to sanitized HTML.

### 7.6 Metadata Value Rendering

Local metadata values use the same Markdown rendering and sanitization
pipeline as the local bio.

Rules:

- Store the submitted value as Markdown source.
- Render it to HTML before local profile display.
- Render it to HTML before ActivityPub actor serialization.
- Sanitize the rendered HTML before inserting it into templates or JSON.
- Keep metadata labels plain text. Only metadata values support
  Markdown.

Why use Markdown:

- It matches the existing profile bio behavior.
- It lets users express links consistently between the bio and metadata
  fields.
- It avoids inventing a second mini-format for profile values.

Metadata values are still short fields. The byte limits in §7.5 remain
in force even though the value is Markdown source.

---

## 8. Service Layer Design

### 8.1 Profile View Model

Create one reusable profile view model for both local and remote actors.

Suggested JSON shape passed to templates:

```json
{
  "id": 1,
  "username": "alice",
  "display_name": "Alice",
  "handle": "@alice@example.test",
  "profile_url": "https://example.test/u/alice",
  "bio_source": "local edit source only",
  "bio_html": "<p>bio</p>",
  "avatar_url": "https://example.test/media/a/abcdef.png",
  "avatar_alt": "Alice avatar",
  "banner_url": "https://example.test/media/b/bcdef0.jpg",
  "banner_alt": "Alice banner",
  "fields": [
    {"label": "Blog", "value_html": "<a ...>...</a>"}
  ],
  "is_local": true
}
```

Rules:

- `bio_source` exists only for local edit views.
- `avatar_url` and `banner_url` may be empty strings.
- `fields` is always an array.
- Plain text fields are already escaped because Inja does not
  auto-escape.
- HTML fields are already sanitized or locally generated safe HTML.

### 8.2 Local User View Construction

`Service::userView()` should expand from user-only fields to full profile
state.

Steps:

1. Start with username, display name, handle, and profile URL.
2. Render bio Markdown to `bio_html`.
3. Load `users.avatar_attachment_id`, if present.
4. Convert the avatar attachment to a public media URL.
5. Load `users.banner_attachment_id`, if present.
6. Convert the banner attachment to a public media URL.
7. Load `user_profile_fields` rows ordered by `sort_order, id`.
8. Render each field value from Markdown to sanitized HTML.
9. Return the JSON view model.

If a referenced attachment is missing, the service should omit the image
and log a warning. A missing profile image should not break profile page
rendering.

### 8.3 Remote Actor View Construction

Move the current `remoteActorView()` helper out of `app.cpp` and into the
service or federation/service boundary so search, post author cards, and
future remote-profile pages can reuse it.

Steps:

1. Parse `RemoteActor.actor_json`.
2. Use extracted `display_name`, `username`, `domain`, and `uri` as the
   base identity fields.
3. Sanitize `summary` into `bio_html` if it is a string.
4. Extract `icon.url` if `icon` is an object.
5. Extract `image.url` if `image` is an object.
6. Extract `attachment` entries where `type` is `PropertyValue`.
7. For each `PropertyValue`:
   - Read string `name` as the label.
   - Read string `value` as HTML.
   - Escape the label.
   - Sanitize the value HTML.
8. Ignore malformed profile fields.
9. Return the same template JSON shape used for local profiles.

Remote actor parsing must be permissive. A malformed avatar or one bad
metadata row should not hide the whole actor.

### 8.4 Actor JSON Construction

Update `actorJson()` to take a richer profile input than just `User` and
`summary_html`.

One possible function shape:

```c++
nlohmann::json actorJson(
    const Config& config,
    const User& user,
    std::string_view summary_html,
    const std::optional<Attachment>& avatar,
    const std::optional<Attachment>& banner,
    const std::vector<RenderedProfileField>& fields);
```

The implementation should:

1. Build the existing actor JSON.
2. Add `icon` when avatar exists.
3. Add `image` when banner exists.
4. Add `attachment` when at least one rendered field exists.
5. Keep public key, inbox, outbox, followers, following, and endpoints
   unchanged.

This keeps the federation representation centralized. HTML handlers
should not hand-build actor profile fragments.

---

## 9. HTTP and Template Design

### 9.1 Profile Page

Update `templates/profile.html` to render:

1. Banner image if present.
2. Avatar image if present.
3. Display name.
4. Handle.
5. Bio.
6. Metadata fields.
7. Existing edit or follow controls.
8. Existing timeline.

The top of the page should still work when no images are present. The
fallback is the current compact text profile header.

Recommended structure:

```html
<section class="profile-head">
  <div class="profile-banner">...</div>
  <div class="profile-main">
    <img class="profile-avatar" ...>
    <h1>...</h1>
    <p class="handle">...</p>
    <div class="bio">...</div>
    <dl class="profile-fields">...</dl>
  </div>
</section>
```

Do not use a nested card layout. This should remain a full profile
header section followed by the timeline.

### 9.2 Profile Edit Page

Update `templates/profile_edit.html` to include:

- Display name input.
- Bio textarea.
- Avatar upload input.
- Current avatar preview and remove checkbox when set.
- Banner upload input.
- Current banner preview and remove checkbox when set.
- Metadata field rows.
- Empty extra metadata row for adding a new field.

The form must use `enctype="multipart/form-data"` once image uploads are
added.

Suggested field names:

```text
display_name
bio
avatar
remove_avatar
banner
remove_banner
field_label[]
field_value[]
```

The exact array syntax depends on libmw form parsing. If repeated names
are not ergonomic, use numbered names:

```text
field_0_label
field_0_value
field_1_label
field_1_value
...
field_count
```

Prefer the format that matches existing request parsing helpers.

### 9.3 Profile POST Flow

The profile update handler should stay thin.

Step-by-step:

1. Validate CSRF.
2. Resolve current user.
3. Parse normal text fields.
4. Pass uploaded profile files to the attachment service.
5. Build a `UserProfileUpdate` command object.
6. Call a service-layer `updateProfile()` function.
7. The service validates fields and persists all profile changes in one
   transaction.
8. Reload the updated user/profile.
9. Build the new actor JSON.
10. Enqueue actor `Update` delivery.
11. Redirect to the local profile page.

The handler should not validate metadata row limits directly. Those
limits belong in the service layer so a future API can reuse them.

### 9.4 ActivityPub GET Flow

When `/u/<username>` is requested with an ActivityPub `Accept` header:

1. Load the local user.
2. Load avatar attachment if present.
3. Load banner attachment if present.
4. Load profile fields.
5. Render bio and metadata field values.
6. Call the richer `actorJson()`.
7. Return `application/activity+json`.

The HTML and JSON paths should use the same profile-loading helper so
they cannot drift.

---

## 10. Remote Actor Updates

Incoming `Update` activities for remote actors already update basic
actor fields and replace `actor_json`. This should remain the primary
remote profile refresh mechanism.

When a remote actor sends an `Update` whose object is the actor:

1. Verify the activity actor matches the object actor.
2. Update username, display name, inbox, shared inbox, and public key as
   the existing logic does.
3. Replace `actor_json` with the full updated object.
4. Let renderers pick up new `icon`, `image`, and `attachment` values
   from the new raw JSON.

No separate remote avatar or metadata columns are required for the first
implementation. If profile rendering becomes a hot path later, generated
columns or extracted cache columns can be added as an optimization.

---

## 11. CSS and Frontend Behavior

### 11.1 Profile Header Layout

CSS should support these states:

- No avatar and no banner.
- Avatar only.
- Banner only.
- Both avatar and banner.
- Very long display name.
- Very long metadata values.
- Mobile narrow viewport.

Rules:

- Use `object-fit: cover` for banner and avatar images.
- Give avatar a fixed visual size.
- Do not let the banner create horizontal overflow.
- Wrap metadata values.
- Keep the edit/follow controls below the identity block.

### 11.2 Metadata Layout

Use a definition list:

```html
<dl class="profile-fields">
  <div class="profile-field">
    <dt>Blog</dt>
    <dd><a href="...">...</a></dd>
  </div>
</dl>
```

This is semantically appropriate because each metadata row is a label and
value pair.

### 11.3 JavaScript

No JavaScript is required for the first implementation.

Optional later enhancement:

- Add client-side buttons to add/remove metadata rows without reloading.
- Keep the server capable of handling the no-JavaScript form.

---

## 12. Security and Privacy

### 12.1 Remote HTML Sanitization

Remote `summary` and remote `PropertyValue.value` are HTML controlled by
another server. They must pass through `sanitizeRemoteHtml()` before
rendering.

Never render these raw:

- `actor.summary`
- `actor.attachment[].value`
- Any remote actor field whose content type is HTML

### 12.2 Local HTML Generation

Local bio HTML comes from Markdown rendering. Continue to use the
existing Markdown and sanitization pipeline.

Local metadata values also come from Markdown rendering. They must use
the same sanitizer before display or federation. This keeps the user
model simple: profile text fields use Markdown, profile labels use plain
text.

### 12.3 Remote Media

Remote avatar and banner URLs are displayed directly in `img` tags.
This is consistent with the existing PRD rule that remote attachments
are not cached or proxied.

Implications:

- The user's browser contacts the remote media host.
- Remote media can disappear or change.
- Broken remote images should degrade visually without breaking layout.

Do not server-side fetch remote profile images for display.

### 12.4 Local Media

Local avatar and banner files are served through the existing media
serving route. Non-image files must never be accepted as profile media.

Profile image upload errors should be normal validation errors, not
server crashes.

### 12.5 HTML Escaping

Inja does not auto-escape. Therefore every text field in the profile view
model must be escaped before it reaches the template.

Escaped fields include:

- Username.
- Display name.
- Handle.
- Profile URL.
- Image alt text.
- Metadata labels.

Fields intentionally containing HTML include:

- `bio_html`.
- `fields[].value_html`.

Those fields must be generated or sanitized before insertion.

---

## 13. Error Handling

### 13.1 Edit Form Validation Errors

If profile submission fails validation:

1. Return HTTP `400`.
2. Render the edit form again.
3. Preserve submitted text fields where practical.
4. Show a short error message.

Examples:

- `Profile field label is too long.`
- `Profile field value is required when label is set.`
- `Avatar must be an image.`
- `Too many profile fields.`

### 13.2 Upload Errors

Upload errors should follow existing attachment upload behavior.

Examples:

- File exceeds global upload size.
- File type is not accepted as an image.
- Filesystem write fails.

If avatar upload succeeds but banner upload fails in the same form
submission, the profile update should fail as a whole. This avoids a
partial profile update that is difficult for the user to understand.

### 13.3 Federation Delivery Errors

Profile save should succeed even if outbound actor `Update` delivery jobs
later fail. This matches existing asynchronous delivery behavior for
posts and profile updates.

Delivery failures are retried by the job queue.

---

## 14. Testing Strategy

### 14.1 Data Tests

Add tests for:

- Migrating from the previous schema version.
- Migrating existing post attachments into `post_attachments`.
- Reusing one normalized attachment row for duplicate local uploads.
- Replacing avatar and banner attachment references in `users`.
- Removing avatar and banner attachment references from `users`.
- Cascading post deletion to `post_attachments` rows.
- Clearing or deleting profile attachment references on user deletion.
- Rejecting remote attachments as profile media.
- Replacing profile metadata rows atomically.
- Returning metadata rows ordered by `sort_order, id`.
- Preserving existing display name and bio updates.

### 14.2 Service Tests

Add tests for:

- Local profile view without avatar/banner/fields.
- Local profile view with avatar.
- Local profile view with banner.
- Local profile view with metadata fields.
- Metadata value Markdown rendering.
- Metadata label escaping.
- Missing referenced attachment degrades to no image.
- Remote actor view extracts `icon.url`.
- Remote actor view extracts `image.url`.
- Remote actor view extracts and sanitizes `PropertyValue` rows.
- Malformed remote actor JSON does not crash view construction.

### 14.3 Federation Tests

Add tests for:

- Local actor JSON omits `icon`, `image`, and `attachment` when unset.
- Local actor JSON includes `icon` when avatar is set.
- Local actor JSON includes `image` when banner is set.
- Local actor JSON includes ordered `PropertyValue` attachments.
- Actor `Update` object includes the rich profile fields.
- Incoming remote actor `Update` replaces `actor_json`, and a later view
  reads the new rich fields.

### 14.4 App Tests

Add tests for:

- GET profile edit renders current avatar/banner previews.
- POST profile edit updates display name, bio, images, and fields.
- POST profile edit with invalid metadata returns `400`.
- POST profile edit with non-image avatar returns `400`.
- ActivityPub GET `/u/<username>` includes rich fields.
- HTML GET `/u/<username>` renders profile metadata.

### 14.5 Interop Tests

Extend the Docker federation harness after the core feature lands.

Test against Akkoma/Pleroma-compatible behavior:

1. Create or update a local user with avatar, banner, and metadata.
2. Have Akkoma fetch the local actor.
3. Assert Akkoma receives `icon`, `image`, and `attachment`.
4. Create or use an Akkoma account with profile fields.
5. Resolve that actor from `unspoken`.
6. Assert `unspoken` renders remote avatar, banner, and metadata.

The interop tests should not depend on public network access.

---

## 15. Implementation Plan

### 15.1 Phase 1: Attachment and Profile Model

1. Add `DataSourceInterface::migrate1To2()` for normalized
   `attachments`, `post_attachments`, `users.avatar_attachment_id`,
   `users.banner_attachment_id`, and `user_profile_fields`.
2. Migrate existing post attachment rows into `post_attachments`.
3. Add indexes used by attachment cleanup checks.
4. Add data APIs for normalized attachment lookup, post attachment
   replacement, profile media update, and profile metadata replacement.
5. Add the unreferenced-attachment cleanup helper.
6. Add data tests for migration, duplicate upload reuse, reference
   checks, and cleanup behavior.

This phase creates the storage foundation. It should land before actor
JSON or template changes because later phases depend on stable attachment
lookup and cleanup semantics.

### 15.2 Phase 2: Profile Service and Actor JSON

1. Add structs and service-layer view models for local rich profiles.
2. Add service validation for avatar, banner, and metadata fields.
3. Render metadata values from Markdown to sanitized HTML.
4. Update local actor JSON generation to emit `icon`, `image`, and
   `attachment`.
5. Update actor `Update` generation to include the rich actor object.
6. Add service and federation tests.

This phase proves the backend profile behavior and federation shape
before changing the edit UI.

### 15.3 Phase 3: HTML Rendering

1. Update `profile.html` to render avatar, banner, and metadata.
2. Update author-card or search-result rendering if the same profile
   fields are shown there.
3. Add CSS for profile header states.
4. Add HTML rendering tests where available.

This phase makes existing stored data visible.

### 15.4 Phase 4: Local Editing

1. Change profile edit form to multipart.
2. Add avatar upload handling.
3. Add banner upload handling.
4. Add metadata field parsing.
5. Wire form submission to service-layer profile update.
6. Enqueue actor `Update` delivery with rich actor JSON.
7. Add app tests.

This phase completes local user functionality.

### 15.5 Phase 5: Remote Rich Profile Rendering

1. Move remote actor view construction into a reusable service helper.
2. Parse `icon`, `image`, and `PropertyValue` fields from `actor_json`.
3. Render rich remote profile data in search results or remote profile
   cards.
4. Add remote actor parsing tests.

This phase improves remote display without adding remote schema columns.

### 15.6 Phase 6: Interop Coverage

1. Add Akkoma/Pleroma profile tests to the Docker harness.
2. Verify local actor profile fields from the peer side.
3. Verify remote actor profile fields from the `unspoken` side.
4. Document any peer-specific differences.

---

## 16. Edge Cases

### 16.1 Actor Has Multiple Icons

Some ActivityStreams properties can be arrays. For remote actors:

- If `icon` is an object, use it.
- If `icon` is an array, use the first object with a string `url`.
- Ignore all other entries.

The same rule applies to `image`.

### 16.2 Image Object Uses `href`

Some JSON-LD producers may use link-shaped objects. For remote display:

1. Prefer `url` when it is a string.
2. Fall back to `href` when it is a string.
3. Ignore the image if neither exists.

Local actor JSON should emit `url`.

### 16.3 Metadata Attachment Is Not an Array

For remote actors:

- If `attachment` is an object, treat it like a one-item array.
- If `attachment` is an array, iterate it.
- Ignore all other types.

Local actor JSON should emit an array.

### 16.4 Remote Metadata Value Is Plain Text

Remote `PropertyValue.value` is usually HTML, but some servers may send
plain text. Sanitizing plain text as HTML should still produce safe
output. If the sanitizer returns an empty string for plain text, fall
back to escaped text.

### 16.5 Deleted Avatar or Banner

If a user checks remove-avatar or remove-banner:

- Set the corresponding `users` attachment reference to `NULL`.
- Check whether that attachment is still referenced by
  `post_attachments` or `users`.
- Delete the stored file and attachment row only when no references
  remain.

Deleting without checking references is risky because the same attachment
may still be referenced by another post or profile.

### 16.6 Duplicate Metadata Labels

Allow duplicate labels. Some users may intentionally have multiple link
rows with similar names. The order is what makes the rows meaningful.

### 16.7 Remote Dangerous Links

The sanitizer should strip dangerous protocols such as `javascript:`.
If the existing sanitizer does not already do this, profile metadata
rendering must not ship until that behavior is added and tested.

---

## 17. Future Work

- Verified profile links using `rel="me"` or peer-specific verification
  metadata.
- Account discoverability and locked-account profile fields.
- Client-side metadata row add/remove controls.
- Image dimension validation and optional thumbnail generation.
- Mastodon-compatible account API endpoints.
- Profile field import/export for account migration.

---

## 18. Acceptance Criteria

The feature is complete when:

- A local user can set, replace, and remove an avatar.
- A local user can set, replace, and remove a banner.
- A local user can create, edit, reorder, and delete profile metadata
  rows.
- Local profile HTML renders avatar, banner, bio, and metadata.
- Local actor JSON emits `icon`, `image`, and `attachment` when set.
- Local actor JSON omits unset optional profile fields.
- Saving a local profile enqueues a federated actor `Update`.
- Remote actor `icon`, `image`, and `PropertyValue` rows render when
  present in cached actor JSON.
- Remote profile HTML is sanitized.
- Tests cover schema, service view models, actor JSON, and app profile
  editing.
