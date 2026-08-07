# Design Document: Timeline Avatars

**Status:** Draft
**Source requirements:** [`prd.md`](../prd.md), especially timelines,
profile editing, attachments, remote actor handling, and server-rendered
HTML.
**Related designs:**
[`design-0-architecture.md`](design-0-architecture.md),
[`design-3-profile.md`](design-3-profile.md), and
[`design-4-actors.md`](design-4-actors.md)
**Scope:** Display a square avatar beside every post author in the HTML
timeline, including a static placeholder for users without an avatar.

This design is intentionally narrower than the rich profile design. The
profile design defines how avatars are uploaded, stored, and represented in
ActivityPub. This document defines how the already available avatar data is
resolved into timeline view models and rendered in post headers.

---

## 1. Problem Statement

The HTML timeline currently displays an author's display name and handle,
but it does not display an image identifying the author. This makes a dense
timeline harder to scan, especially when several posts have similar names or
when the user is reading a home timeline containing both local and remote
accounts.

The server already has the data required to display avatars:

- Local users have an optional `avatar_attachment_id` in `users` and in the
  [`User`](../src/structs.hpp) domain object.
- Local profile media is already stored through the content-hash attachment
  system described in [`design-3-profile.md`](design-3-profile.md).
- Remote actors retain their raw ActivityPub actor document in
  `remote_actors.actor_json`.
- The existing remote profile parser already understands the ActivityStreams
  `icon` property and can read both `url` and `href` image forms.
- The shared [`_post.html`](../templates/_post.html) template is used by the
  home timeline, public timeline, profile timelines, threads, and bookmarks.

The missing behavior is the connection between the author data and the post
view model. `Service::postView()` currently reconstructs a small author JSON
object containing only identity fields. It does not include the local
attachment URL or the remote actor's `icon` URL. The template consequently
has no avatar value to render.

The feature also needs a defined appearance for accounts that have no
avatar. An empty space or a broken image would make the author column change
shape from post to post. Every post header should therefore contain an
avatar image URL. The URL will point either to the author's selected image or
to one server-owned, static placeholder SVG.

The avatar must be square. It must not be rendered with a circular mask or a
rounded border. This is a deliberate product requirement, not an incidental
CSS choice.

---

## 2. Goals and Non-Goals

### 2.1 Goals

- Display an avatar beside every post author in the shared post template.
- Display local avatars from the existing local attachment store.
- Display remote avatars from a remote actor's ActivityPub `icon` property.
- Use a server-owned placeholder SVG when an avatar is absent, malformed, or
  unavailable to the view-model builder.
- Keep the image's rendered width and height equal at all supported viewport
  sizes.
- Do not apply a circular or rounded mask to the avatar image.
- Make the avatar part of the author link so clicking it follows the same
  profile navigation as clicking the author's name.
- Keep the existing display name, handle, timestamp, and visibility marker
  behavior unchanged.
- Reuse the existing attachment and remote-actor rules instead of creating a
  second avatar storage system.
- Keep request handlers thin. Avatar resolution belongs in the service/view
  layer, not in `App::handleIndex()` or individual route handlers.
- Keep missing or malformed avatar data from making a timeline request fail.
- Make the placeholder a static asset that requires no JavaScript, database
  row, upload, or network request to another server.
- Preserve the existing no-proxy rule for remote media.

### 2.2 Non-Goals

- Do not add avatar upload or profile editing in this feature. Those concerns
  are covered by [`design-3-profile.md`](design-3-profile.md) and are already
  represented in the current profile implementation.
- Do not add a database migration or new avatar table.
- Do not add a media proxy or remote avatar cache.
- Do not download remote avatars on the server.
- Do not implement client-side image cropping, resizing, or editing.
- Do not generate a personalized identicon or initials avatar.
- Do not change ActivityPub actor serialization. Local actor `icon` output
  is already specified by the profile design.
- Do not change the avatar shown on the profile header unless a later task
  explicitly extends the shared placeholder policy to profile pages.
- Do not change post attachment sensitivity behavior. An actor avatar is
  profile media, not post media, and is not hidden behind a post content
  warning.
- Do not add a frontend framework or JavaScript for this feature.
- Do not change the ActivityPub `icon` field into a new custom field.

---

## 3. Existing System

### 3.1 Local Avatar Data

The local profile model already contains:

```text
User.avatar_attachment_id: optional integer attachment ID
```

The referenced attachment is expected to satisfy all of these conditions:

1. The attachment row exists.
2. The attachment is local, meaning `remote_url` is not set.
3. The attachment is an image, meaning `is_image` is true.
4. The attachment has a content hash and an extension suitable for the
   existing `/media/<shard>/<filename>` route.

The service already converts a valid local profile attachment into a public
URL using the same content-hash path used by post attachments. The URL shape
is:

```text
<url_root>media/<first-hash-character>/<hash>.<extension>
```

The timeline feature must call the same URL-construction logic. It must not
reconstruct filenames from the original upload name, because original names
are not the storage identity and may contain unsafe characters.

### 3.2 Remote Avatar Data

Remote actor documents are stored as raw JSON in `RemoteActor.actor_json`.
ActivityStreams actors commonly represent an avatar using `icon`:

```json
{
  "icon": {
    "type": "Image",
    "mediaType": "image/png",
    "url": "https://remote.example/avatar.png"
  }
}
```

Interoperability requires accepting a few common variations:

- `icon` can be an object or an array of objects.
- An image object can use `url` or `href`.
- Some remote documents may omit `icon` entirely.
- Some remote documents may contain malformed or unexpected values.

The parser must remain permissive. A malformed icon means that the
placeholder is used; it does not mean that the post or timeline request is
invalid.

Remote images remain remote. The browser loads a valid remote avatar URL
directly, in accordance with the PRD rule that remote attachments are not
stored or proxied by this server.

### 3.3 Current Post View Model

The current `postView()` author object has this effective shape:

```json
{
  "username": "alice",
  "display_name": "Alice",
  "handle": "@alice@example.test",
  "profile_url": "https://example.test/u/alice",
  "is_local": true
}
```

The avatar change adds these fields:

```json
{
  "avatar_url": "https://example.test/media/a/abcdef.png",
  "avatar_is_placeholder": false
}
```

`avatar_url` is always non-empty for a valid post view. The boolean is
included so templates, tests, and future clients can distinguish a real
avatar from the fallback without parsing the URL. The template does not
need to branch on this boolean for the first implementation; it is still a
useful explicit contract.

### 3.4 Current Template Reuse

The `_post.html` partial is included by:

- `templates/index.html` for public and home timelines;
- `templates/profile.html` for a user's posts;
- `templates/thread.html` for a thread;
- `templates/bookmarks.html` for saved posts.

Changing this one partial makes avatars appear consistently in all of these
views. No route-specific avatar rendering should be added.

### 3.5 Static Asset Serving

The application mounts the configured static directory at `/static`. A file
stored as:

```text
static/default_avatar.svg
```

is therefore available at:

```text
<url_root>static/default_avatar.svg
```

The placeholder must be part of the repository's static assets. It must not
be written into the attachment directory, because it is not a user upload,
does not have a content hash, and must not be collected as an unreferenced
attachment.

---

## 4. User-Facing Contract

### 4.1 Timeline Appearance

Each post header contains, from left to right:

1. A square avatar image.
2. The display name.
3. The account handle.
4. The existing permalink/timestamp.
5. The existing visibility marker.

The avatar is inside the same anchor element as the display name and handle.
The whole author identity therefore has one navigation target.

The avatar is visually square in both dimensions. The rendered image has no
`border-radius`, `clip-path`, mask, or other rule that turns the square into a
circle. Source images with non-square dimensions are cropped into the square
box using `object-fit: cover`; this preserves the square layout while
avoiding distortion.

### 4.2 Missing Avatar Appearance

If the author has no usable avatar, the timeline still displays an image at
the same size. Its source is the local static placeholder:

```text
<url_root>static/default_avatar.svg
```

This keeps all post headers aligned and avoids a broken-image icon. The
placeholder is deliberately neutral and contains no account-specific text,
initials, or network request.

### 4.3 Broken Remote Image Behavior

The server cannot determine whether a remote image will remain reachable
after the HTML response is sent. If a remote URL is syntactically valid but
the remote host later returns an error, the browser may show a broken image.
That is an inherent consequence of the no-proxy policy.

The view-model builder must still use the placeholder for values that are
invalid before rendering, including:

- a non-string `url` or `href`;
- an empty URL;
- a URL with an unsupported scheme;
- an `icon` value with no usable image object;
- invalid actor JSON.

The server is not required to make a network request to verify the remote
image before returning the timeline.

### 4.4 Accessibility

The display name and handle already identify the author in the same link as
the image. The avatar image therefore uses an empty alt attribute:

```html
alt=""
```

This makes the image decorative to screen readers while keeping the author
link's text as its accessible name. Repeating `Alice avatar` before `Alice`
would create unnecessary duplicate speech.

The link remains usable without the image. If images are disabled, the
display name and handle continue to provide the author identity.

The HTML follows the semantics described by the MDN [`img` element
documentation](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/img).

---

## 5. Placeholder Asset

### 5.1 Asset Identity

Add this repository file:

```text
static/default_avatar.svg
```

The filename uses the repository's `snake_case` convention. The application
serves it with the MIME type `image/svg+xml` through the existing static
mount.

The asset is a square 64 by 64 SVG. The file has no external references,
embedded raster data, JavaScript, animation, font dependency, or user data.
This makes it deterministic, cheap to load, and safe to serve as a shared
fallback.

### 5.2 Required SVG Content

The implementation should add the following content verbatim unless the
application's color palette changes. The SVG itself is square; the person
silhouette inside it may contain a circular head shape, but the image is not
masked into a circle.

```svg
<svg xmlns="http://www.w3.org/2000/svg"
     viewBox="0 0 64 64"
     width="64"
     height="64"
     role="img"
     aria-labelledby="title desc">
  <title id="title">Default avatar</title>
  <desc id="desc">A neutral placeholder profile avatar</desc>
  <rect width="64" height="64" fill="#23272e"/>
  <circle cx="32" cy="23" r="11" fill="#8b93a1"/>
  <path d="M12 57c1-13 9-21 20-21s19 8 20 21H12Z"
        fill="#8b93a1"/>
</svg>
```

The design uses the existing dark theme colors:

- `#23272e` is the existing secondary panel color.
- `#8b93a1` is the existing dim foreground color.

The placeholder must not use a gradient or a remote image. It should remain
legible against the timeline panel background and look neutral for both
local and remote accounts.

The standalone SVG has a title and description so that opening the asset
directly remains understandable. When the asset is loaded through the
timeline's `<img alt="">`, the surrounding HTML accessibility contract
treats it as decorative, as described above.

The SVG follows the standard SVG document model described by the [W3C SVG
specification](https://www.w3.org/TR/SVG2/). It does not require a new image
generation tool or a binary asset pipeline.

### 5.3 Cache and Versioning

The placeholder is a static asset and may be cached by browsers. If the
visual design changes later, the implementation should either:

1. retain the same asset with a cache-busting static asset policy; or
2. change the filename and update the service constant.

The first implementation does not need a query-string version because the
asset is new and is served through the existing static mount.

---

## 6. View-Model Design

### 6.1 Author View Contract

The author object embedded in every post view should have this shape:

```json
{
  "username": "alice",
  "display_name": "Alice",
  "handle": "@alice@example.test",
  "profile_url": "https://example.test/u/alice",
  "avatar_url": "https://example.test/media/a/abcdef.png",
  "avatar_is_placeholder": false,
  "is_local": true
}
```

For an account without a usable avatar:

```json
{
  "username": "bob",
  "display_name": "Bob",
  "handle": "@bob@example.test",
  "profile_url": "https://example.test/u/bob",
  "avatar_url": "https://example.test/static/default_avatar.svg",
  "avatar_is_placeholder": true,
  "is_local": true
}
```

The following invariants apply:

- `avatar_url` is always present.
- `avatar_url` is always a non-empty string.
- `avatar_is_placeholder` is always present and is a boolean.
- `profile_url` remains the author profile URL.
- `is_local` continues to indicate whether the post author is local.
- All text and URL values passed to Inja are HTML-escaped in the service
  layer, because Inja does not auto-escape.
- No raw remote actor JSON is passed to a template.

The view model should not expose the original avatar filename. The filename
is useful when editing a profile or serializing ActivityPub, but it is not
needed to render a timeline identity and could expose unnecessary metadata.

### 6.2 Placeholder URL Construction

Define one service-level helper for the placeholder URL, conceptually:

```text
defaultAvatarUrl(config):
    return config.url_root + "static/default_avatar.svg"
```

The helper should use the configured URL root rather than a hard-coded
origin. This matters when the server is deployed below a path, such as:

```text
https://example.test/fedi/
```

In that case, the correct URL is:

```text
https://example.test/fedi/static/default_avatar.svg
```

The helper should return the same URL for all authors in a given server
configuration. It does not need to query the database.

### 6.3 Local Avatar Resolution

When building an author view for a local user, use this algorithm:

1. Initialize `avatar_url` to `defaultAvatarUrl(config)`.
2. Initialize `avatar_is_placeholder` to `true`.
3. Check `user.avatar_attachment_id`.
4. If it is not set, return the placeholder values.
5. Fetch the attachment using the existing data-layer lookup.
6. If the attachment does not exist, return the placeholder values.
7. If `remote_url` is set, reject the attachment for local profile use and
   return the placeholder. A local user's avatar must use local storage.
8. If `is_image` is false, return the placeholder.
9. If the content hash is empty or cannot produce a valid local media path,
   return the placeholder.
10. Build the URL with the existing local attachment URL helper.
11. HTML-escape the URL.
12. Set `avatar_is_placeholder` to `false`.
13. Return the completed author view.

The service should not return an error merely because an old or missing
profile attachment is encountered. Profile data can outlive a file after an
operator cleanup or a failed migration. A degraded avatar is preferable to
an unavailable timeline.

The service may log a warning for a referenced attachment that is missing or
invalid. The warning should identify the local user ID and attachment ID,
but should not include private upload contents.

### 6.4 Remote Avatar Resolution

When building an author view for a remote actor, use this algorithm:

1. Initialize the avatar to the server placeholder.
2. Parse `RemoteActor.actor_json` as JSON with non-throwing error handling.
3. If parsing fails or the root is not an object, keep the placeholder.
4. Look up the `icon` property.
5. If `icon` is an object, inspect that object as one image candidate.
6. If `icon` is an array, inspect each item in order.
7. For each candidate, prefer a string `url`.
8. If `url` is absent, use a string `href`.
9. Ignore candidates whose selected value is empty after trimming.
10. Ignore candidates whose URL scheme is not `http` or `https`.
11. Use the first remaining candidate.
12. HTML-escape the selected URL.
13. Set `avatar_is_placeholder` to `false`.
14. Return the completed author view.

The parser must not fetch the selected URL. The purpose of this step is only
to turn already cached actor data into HTML view data.

The URL scheme check is required even though the value is placed in an
`img` `src` attribute. It gives the application one consistent policy for
remote media and prevents unsupported schemes from being propagated into
browser-facing HTML.

### 6.5 Unknown Author Resolution

The normal data invariants should ensure that a stored post has either a
valid local author or a retained remote author. If both references are
missing or the referenced author row cannot be loaded, the existing
`unknown` author fallback remains in place.

The unknown author fallback must also receive:

```json
"avatar_url": "<default avatar URL>",
"avatar_is_placeholder": true
```

This keeps the post header layout stable even when historical or partially
corrupt data is encountered.

### 6.6 Shared Helper Structure

The implementation should avoid duplicating avatar-resolution logic in the
HTML handler, template, federation code, and search code. A reasonable
internal structure is:

```text
Service::postView()
    -> localAuthorView(user) or remoteAuthorView(actor)
        -> resolve local attachment or remote icon
        -> return escaped identity fields plus avatar fields
```

The existing full `userView()` and `remoteActorView()` functions include
profile-only fields such as bio, banner, and metadata. They should not be
called wholesale for every timeline post. Instead, extract or share a
lightweight identity/avatar helper so the timeline does not render unused
profile HTML.

The exact helper may remain private to `Service` if no other caller needs
it. If it becomes part of a public service interface, it must have a comment
describing that it builds a render-ready author identity for post cards.

---

## 7. Template Design

### 7.1 Author Header Markup

Update the author portion of `templates/_post.html` from the current
name-and-handle-only structure to the following shape:

```html
<a class="author" href="{{ post.author.profile_url }}">
  <img class="post-avatar"
       src="{{ post.author.avatar_url }}"
       alt=""
       width="40"
       height="40"
       loading="lazy"
       decoding="async">
  <span class="author-copy">
    <span class="dname">{{ post.author.display_name }}</span>
    <span class="handle">{{ post.author.handle }}</span>
  </span>
</a>
```

The current author link contains the display name and handle directly. The
`author-copy` wrapper is added so that the image can be vertically centered
without changing the baseline relationship between the display name and
handle.

The explicit `width` and `height` attributes reserve layout space before the
image loads. This prevents the post header from shifting as avatars arrive.
The CSS must use the same 40px dimensions, with a smaller responsive value
only if the design explicitly chooses one for narrow screens.

`loading="lazy"` and `decoding="async"` are appropriate for a paginated
timeline because avatars below the initial viewport do not need to delay the
first text paint. The browser still loads visible images promptly. If
interop testing shows that a target browser handles lazy loading poorly,
`loading` may be removed without changing the view-model contract.

### 7.2 Template Safety

The template must not:

- construct media URLs from `sha256` or filenames;
- inspect raw `actor_json`;
- decide whether a remote URL is safe;
- add a fallback using JavaScript;
- use a CSS class that applies a circular mask;
- render user-controlled values outside the escaped view model.

The service is responsible for producing the complete safe URL and the
template is responsible only for displaying it.

### 7.3 Fallback Markup

The first implementation should always render an `<img>` because the service
always provides either a real URL or the placeholder URL. There should be no
empty-image branch in the template.

This is preferable to a conditional image because:

- all author headers have identical geometry;
- there is no broken-image state caused by missing template data;
- the placeholder policy remains centralized;
- future clients can rely on a stable `avatar_url` field.

If a future design wants to distinguish placeholder styling, it can use
`post.author.avatar_is_placeholder` to add a class. The first implementation
does not need a separate visual treatment.

---

## 8. CSS Design

### 8.1 Required Rules

Add timeline avatar rules to `static/style.css`:

```css
.author {
    display: inline-flex;
    gap: 8px;
    align-items: center;
}

.post-avatar {
    display: block;
    width: 40px;
    height: 40px;
    flex: 0 0 40px;
    object-fit: cover;
    background: var(--panel-2);
}

.author-copy {
    display: inline-flex;
    flex-direction: column;
    min-width: 0;
    align-items: flex-start;
}
```

The existing `.author` rule should be updated rather than duplicated. The
important behavior is:

- `width` and `height` are equal;
- `flex-basis` prevents flexbox from shrinking the image;
- `object-fit: cover` crops rather than distorts source images;
- there is no `border-radius`;
- there is no `clip-path` or CSS mask;
- `min-width: 0` allows long handles to wrap instead of forcing horizontal
  overflow.

The image is square because its width and height are equal, and it remains
visually square because no rounded or circular clipping is applied.

### 8.2 Header Alignment

The existing `.post-head` uses `align-items: baseline`. Once the author
contains a 40px image, the post header should use `align-items: center` or
retain baseline alignment only for its outer siblings after the author has
its own internal alignment.

The implementer should verify the following relationships:

- The timestamp remains aligned with the author block and does not overlap
  the avatar.
- The visibility marker remains readable when the handle wraps.
- The permalink continues to use `margin-left: auto` where space permits.
- Long display names and handles wrap inside the available width.
- The post body does not move horizontally because of the avatar.

If a very narrow viewport needs a smaller avatar, use an explicit media
query, for example 32px at the narrow breakpoint, and update all three
dimensions consistently:

```css
@media (max-width: 560px) {
    .post-avatar {
        width: 32px;
        height: 32px;
        flex-basis: 32px;
    }
}
```

The default should remain 40px unless visual testing demonstrates that the
existing 720px content width cannot accommodate the author block.

### 8.3 No Circular Mask Requirement

The implementation must not copy common social-media avatar CSS such as:

```css
border-radius: 50%;
```

It must also avoid equivalent effects implemented with:

- `border-radius` values other than zero;
- `clip-path: circle(...)`;
- `mask-image` or `mask`;
- a circular parent with `overflow: hidden`;
- a rounded placeholder SVG used as the image itself.

An avatar source may itself contain rounded artwork, but the server's
presentation box must remain square.

---

## 9. Performance and Caching

### 9.1 Existing Query Pattern

`postViews()` currently builds one post view at a time. Each `postView()` may
load the post author, attachments, interaction state, and other related
data. Avatar support should fit this architecture without introducing a
large database redesign.

However, a timeline often contains multiple posts by the same author. A
naive implementation would fetch the same local avatar attachment once for
each of those posts. It could also parse the same remote actor JSON once for
each post.

### 9.2 Per-Page Author Cache

The preferred first implementation adds an in-memory cache scoped to one
`postViews()` call. It must not be a global unbounded cache.

Conceptually:

```text
postViews(posts, viewer):
    author_cache = empty map keyed by author identity

    for post in posts:
        postView(post, viewer, author_cache)
```

The cache key should distinguish local and remote IDs. For example:

```text
local user ID:   (LOCAL, user_id)
remote actor ID: (REMOTE, actor_id)
```

The cache value is the completed escaped author JSON object. If a page has
five posts by one author, the author and avatar resolution happens once and
the same view object is copied into each post view.

If changing the `postView()` signature would unnecessarily expand the public
service API, the implementation may instead resolve author views in
`postViews()` and use a private helper that accepts the cache. The existing
single-post `postView()` API should remain correct without requiring a
caller-created cache.

### 9.3 Cache Lifetime

The cache exists only while assembling one HTML response. It must not outlive
the request because:

- a local user can change an avatar between requests;
- a remote actor's cached JSON can be refreshed;
- no cache invalidation protocol is needed for a request-local cache;
- memory usage is bounded by the number of distinct authors on one page.

The placeholder URL itself is constant and does not need caching.

### 9.4 Future Batch Query

If profiling later shows that author lookups dominate timeline latency, a
future optimization may add a data-layer batch lookup for local users and
attachments. That is not part of this feature because the current timeline
already performs per-post related-data lookups and the page size is
configurable.

The feature must not add a SQL join that changes timeline pagination,
visibility filtering, or post ordering. Avatar enrichment happens after the
post page has been selected.

---

## 10. Security and Privacy

### 10.1 Local URL Construction

Local avatar URLs must be generated from the trusted attachment record and
the configured URL root. The implementation must continue to use the
existing media route's path validation.

Do not use the original upload filename as a URL path component. Do not pass
an attachment ID directly as a filename. Do not accept a user-provided URL
as a local avatar URL.

### 10.2 Remote URL Validation

Remote avatar URLs come from remote actor JSON and are untrusted input. The
service must:

1. Require a JSON string.
2. Trim surrounding whitespace.
3. Reject an empty value.
4. Parse enough of the URL to confirm that its scheme is `http` or
   `https`.
5. HTML-escape the final value before it reaches Inja.

The server does not fetch remote avatars, so SSRF protection for outbound
server requests is not triggered by timeline rendering. The browser's direct
request is an intentional consequence of the PRD's remote-media policy.

The existing remote actor acquisition path remains responsible for SSRF
protection when the actor document itself is fetched. This design does not
weaken or bypass that path.

### 10.3 Escaping

Inja does not auto-escape. The service must escape:

- `avatar_url`;
- display name;
- handle;
- profile URL;
- username;
- any other plain-text author field.

The placeholder URL is trusted but should still pass through the same output
escaping path so the view-model contract is uniform.

The template must not use an unescaped/raw rendering operator for the
avatar URL.

### 10.4 SVG Safety

The placeholder SVG is repository-controlled and must remain a static,
constant file. It must not contain:

- `<script>`;
- event-handler attributes such as `onload`;
- external `<image>` or `<use>` references;
- external stylesheets;
- user-controlled text;
- data loaded from the database.

The SVG uses only a rectangle, circle, path, title, and description. This
keeps the asset easy to audit.

### 10.5 Privacy

Local avatars are already public profile media under the existing profile
design. They are not post content and do not inherit post visibility.

For remote avatars, the browser contacts the remote media host. This may
reveal the viewer's network address to that host. That behavior is already
specified for remote attachments and remote profile media; this feature does
not introduce a server-side proxy intended to hide it.

If the project later adds a content-security policy, it must account for
remote avatar origins without allowing arbitrary script execution.

---

## 11. Error Handling

### 11.1 View Construction Errors

Avatar data errors should degrade to the placeholder wherever possible.
Examples include:

- missing local attachment row;
- local attachment marked as remote;
- local attachment marked as non-image;
- malformed local hash or extension;
- invalid remote actor JSON;
- remote icon with the wrong JSON type;
- remote image without a URL;
- remote URL with an unsupported scheme.

These conditions should not produce a `500` response and should not hide the
post. They are profile-media problems, not timeline-data problems.

### 11.2 Database Errors

A genuine database failure while loading the author or attachment is
different from a missing/invalid avatar value. The service should preserve
the existing error propagation policy for database failures. In particular:

- If the author row cannot be loaded because SQLite returns an operational
  error, propagate the error as the existing `postView()` code does.
- If the author row loads and its optional attachment is missing, use the
  placeholder.
- If an attachment lookup returns a database error, follow the existing
  `mw::E<>` propagation behavior unless the data layer explicitly classifies
  the condition as a missing row.

This distinction prevents silent corruption of database failures while still
making stale profile references harmless.

### 11.3 Static Asset Missing

The repository and packaging process must include
`static/default_avatar.svg`. If an operator accidentally deploys without the
file, the browser will show a broken placeholder image for accounts without
avatars. The server does not need to synthesize SVG content dynamically.

Packaging tests should verify that the static asset is installed alongside
the other static files. A missing asset is a deployment/package failure, not
a reason to add a database fallback.

---

## 12. Implementation Plan

### 12.1 Phase 1: Static Asset

1. Add `static/default_avatar.svg` with the exact SVG from section 5.2.
2. Confirm the existing static mount serves it at
   `/static/default_avatar.svg`.
3. Confirm package manifests include the static directory recursively.
4. Confirm the SVG has no external references or executable content.

This phase creates the stable fallback URL before any template can refer to
it.

### 12.2 Phase 2: Service View Model

1. Add a service helper for the default avatar URL.
2. Add a lightweight local author/avatar resolver.
3. Add a lightweight remote author/avatar resolver.
4. Add `avatar_url` and `avatar_is_placeholder` to every author object
   returned by `postView()`.
5. Preserve the existing unknown-author fallback and add the placeholder to
   it.
6. Ensure all plain-text values remain escaped before entering the template.
7. Add the request-local author cache in `postViews()` if it can be done
   without changing the public API unnecessarily.

The service should not call the full profile view builder for every post.
Profile bio, banner, and metadata are not required for an author header.

### 12.3 Phase 3: Template and CSS

1. Update `_post.html` to render the avatar inside the author link.
2. Add explicit `alt`, `width`, `height`, `loading`, and `decoding`
   attributes.
3. Update `.author` layout rules.
4. Add `.post-avatar` rules with equal width and height.
5. Add `.author-copy` rules for display name and handle alignment.
6. Verify that no circular or rounded mask is present.
7. Add a narrow-screen rule only if visual testing requires it.

Because the partial is shared, do not add duplicate markup to index, profile,
thread, or bookmark templates.

### 12.4 Phase 4: Tests and Manual Review

1. Add service tests for local real avatar URLs.
2. Add service tests for local missing and invalid avatars.
3. Add service tests for remote `icon.url`.
4. Add service tests for remote `icon.href`.
5. Add service tests for remote icon arrays.
6. Add service tests for invalid remote schemes and malformed JSON.
7. Add tests for the unknown-author placeholder.
8. Add template or app tests verifying the avatar `<img>` is rendered.
9. Run the existing unit test suite.
10. Manually inspect public, home, profile, thread, and bookmark views.
11. Inspect a timeline containing both local and remote authors.
12. Inspect a timeline where every author uses the placeholder.
13. Inspect long handles and narrow viewport widths.

---

## 13. API and Data Changes

### 13.1 Database Schema

No schema change is required.

The existing fields remain the source of truth:

```text
users.avatar_attachment_id
attachments.sha256
attachments.extension
attachments.media_type
attachments.is_image
remote_actors.actor_json
```

The static placeholder is not represented in the database. It is a view-layer
fallback and must never be stored as an attachment row.

### 13.2 C++ Domain Types

No new persistent struct is required. The existing `User`, `RemoteActor`,
and `Attachment` types are sufficient.

If the implementation introduces a named transient author view type instead
of building JSON directly, it should contain at least:

```cpp
struct AuthorView
{
    std::string username;
    std::string display_name;
    std::string handle;
    std::string profile_url;
    std::string avatar_url;
    bool avatar_is_placeholder = true;
    bool is_local = false;
};
```

This type would be a render-only value object, not a database entity. Every
public field should have a comment explaining its rendering purpose if this
type is made public. Keeping the existing nlohmann/json view-model approach
is also acceptable and avoids widening the service API.

### 13.3 ActivityPub

No ActivityPub payload changes are required by this timeline feature.

Local actor documents already use `icon` for the selected avatar. Remote
actor documents already use `icon` as their source. The timeline merely
consumes those existing representations.

The ActivityPub meaning of `icon` is described by the [ActivityStreams
Vocabulary](https://www.w3.org/TR/activitystreams-vocabulary/#dfn-icon).

---

## 14. Testing Strategy

### 14.1 Service Tests

Add tests in `src/service_test.cpp` for the following cases.

#### Local avatar present

1. Create a local user.
2. Insert a local image attachment with a known hash and extension.
3. Associate the attachment with the user's avatar field.
4. Create a post authored by that user.
5. Build the post view.
6. Assert that `post.author.avatar_url` is the expected local media URL.
7. Assert that `post.author.avatar_is_placeholder` is false.

#### Local avatar absent

1. Create a local user without an avatar attachment.
2. Create a post by that user.
3. Build the post view.
4. Assert that `avatar_url` is the configured static placeholder URL.
5. Assert that `avatar_is_placeholder` is true.

#### Local attachment is missing

1. Create a user whose avatar ID references a nonexistent attachment.
2. Build a post view.
3. Assert that the view succeeds.
4. Assert that the placeholder is used.

#### Local attachment is invalid

Test at least these invalid states:

- `remote_url` is set;
- `is_image` is false;
- the local storage identity is incomplete.

Each case should use the placeholder and should not fail the post view.

#### Remote `icon.url`

Create a retained remote actor whose actor JSON contains an image object with
an HTTPS `url`. Build a remote-authored post view and assert that the URL is
used and the placeholder flag is false.

#### Remote `icon.href`

Repeat the test with `href` instead of `url`. This covers link-shaped actor
documents used by some implementations.

#### Remote icon array

Provide an array containing an invalid item followed by a valid image object.
Assert that the first usable URL is selected.

#### Remote icon failure

Test malformed JSON, a scalar `icon`, an empty object, an empty URL, and an
unsupported URL scheme. Each case should use the placeholder.

#### Unknown author

Create a post whose author references cannot be resolved. Assert that the
existing unknown identity remains available and that the placeholder fields
are present.

### 14.2 Template Tests

If the current test harness has a direct template-rendering facility, add
tests asserting:

- the author link contains an `<img class="post-avatar">`;
- the image uses `post.author.avatar_url`;
- `alt=""` is present;
- `width="40"` and `height="40"` are present;
- the display name and handle remain in the author link;
- no placeholder-specific branch is required in the template.

If templates are only covered through app tests, render a public timeline
response and assert the same properties in the returned HTML.

### 14.3 CSS Review

Automated CSS testing may not be available. The implementation review must
nevertheless verify:

- `.post-avatar` has equal width and height;
- `object-fit: cover` is present;
- no `border-radius` is applied to the avatar or its parent;
- no CSS mask or circular clip is applied;
- long handles do not cause horizontal overflow;
- the avatar does not cause layout shift before loading;
- narrow screens retain a square image.

### 14.4 Regression Tests

Run the existing tests for:

- profile media and profile views;
- remote actor parsing;
- local actor JSON;
- attachment URL generation;
- timeline and post views;
- ActivityPub interop where available.

The feature must not change local actor `icon` serialization, post attachment
rendering, sensitive-media disclosure, or private-post authorization.

---

## 15. Acceptance Criteria

The feature is complete when all of the following are true:

1. Every rendered post author has an avatar image in the post header.
2. A local user's selected avatar resolves to the existing local media URL.
3. A remote actor's valid `icon` URL or `href` resolves to a direct image URL.
4. A user without an avatar receives the server-owned placeholder SVG.
5. Missing or malformed avatar data falls back to the placeholder.
6. The placeholder asset is present at `static/default_avatar.svg`.
7. The placeholder SVG contains no external references or executable content.
8. All rendered avatar boxes are square.
9. No circular or rounded avatar mask is applied.
10. The avatar is inside the existing author profile link.
11. Avatar images use an empty alt attribute because the author text is
    already present.
12. Local and remote avatar URLs are escaped before reaching Inja.
13. Remote avatars are not downloaded, proxied, or cached by the server.
14. No database migration is introduced.
15. Public timelines, home timelines, profile timelines, threads, and
    bookmarks all display avatars through the shared post partial.
16. Existing author text, post content, attachments, interactions, and
    visibility behavior remain unchanged.
17. Unit or app tests cover local, remote, missing, malformed, and unknown
    author avatar states.
18. The implementation does not introduce a per-request failure when an
    optional profile attachment is stale.

---

## 16. Future Extensions

The following extensions are intentionally left for later work:

- Reuse the same placeholder policy in profile headers.
- Reuse the same author identity view in search results.
- Add a user-configurable avatar background or theme variant.
- Add responsive avatar sizing based on a broader mobile design pass.
- Add batch data-layer queries if profiling shows timeline author resolution
  is expensive.
- Add a bounded shared cache for remote actor profile parsing if request-local
  caching is insufficient.
- Add an explicit content-security policy for remote profile media.

None of these extensions should require changing the basic contract that an
author view has a square `avatar_url`, with the server placeholder as the
fallback.
