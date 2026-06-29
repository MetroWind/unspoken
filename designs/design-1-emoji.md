# Design Document: Tabbed Emoji Picker

**Status:** Draft
**Source requirements:** [`prd.md`](../prd.md), especially emoji
reactions and server-wide custom emoji.
**Related design:** [`design-0-architecture.md`](design-0-architecture.md)
**Scope:** Replace the current free-text reaction input with a tabbed
emoji picker, and make the same picker available in the post composer.
For reactions, selecting an emoji immediately sends the reaction. For
composition, selecting an emoji inserts it into the post textarea.

---

## 1. Problem Statement

The current reaction UI is technically functional but not ergonomic. A
logged-in user reacts to a post by manually typing an emoji value into a
small text input and then clicking a separate `react` button. This has
several problems:

- The user must already know how to enter the exact emoji character.
- Custom emoji require knowing and typing the shortcode syntax, such as
  `:blobcat:`.
- The extra submit button makes reaction selection slower than common
  mobile and social-network interfaces.
- The UI does not expose the server-wide custom emoji feature that the
  backend already supports.

The post composer has a related problem. A user writing a post may want
to insert Unicode emoji or server custom emoji. The server already
supports custom emoji shortcodes in post content, but the current
composer only displays custom emoji as passive reference material. It
does not insert the shortcode for the user. This means the user must
remember or manually copy values such as `:blobcat:`. Some users also do
not have a convenient operating-system emoji picker, especially on Linux
desktop environments.

The desired behavior is similar to a phone emoji keyboard, with two
usage modes:

Reaction mode:

1. The user opens a picker from the post action bar.
2. The picker shows tabs, where each tab is an emoji category.
3. The first tab is custom emoji, if the server has any custom emoji.
4. Unicode emoji categories follow after the custom emoji tab.
5. Clicking an emoji submits the reaction immediately.
6. There is no separate `react` button.

Composer mode:

1. The user opens a picker from the post composer.
2. The picker uses the same custom-first tabs and Unicode categories.
3. Clicking a Unicode emoji inserts the actual emoji character.
4. Clicking a custom emoji inserts its shortcode, such as `:blobcat:`.
5. The insertion happens at the textarea cursor position.
6. The textarea keeps focus and the cursor moves after the inserted
   value.

This is primarily a presentation-layer feature. The existing backend
already accepts a posted `emoji` field at `/post/:id/react`, stores the
reaction, and federates it as an `EmojiReact` activity. The existing
post renderer already substitutes custom emoji shortcodes when rendering
post content.

---

## 2. Goals

### 2.1 User Experience Goals

- Replace manual emoji typing with a selectable emoji grid.
- Let users insert emoji and custom emoji shortcodes while composing a
  post.
- Preserve the compact post action bar.
- Show server custom emoji first because they are instance-specific and
  cannot be typed from a normal operating-system emoji keyboard.
- Keep Unicode emoji grouped by familiar categories.
- Submit a reaction immediately when an emoji is selected.
- Insert composer emoji at the current cursor position.
- Keep the interaction usable without a frontend framework.
- Provide a basic non-JavaScript fallback.

### 2.2 Engineering Goals

- Reuse the existing `/post/:id/react` route and form handling.
- Reuse the existing post creation route and Markdown/custom-emoji
  rendering pipeline.
- Keep request handlers thin, consistent with the architecture design.
- Store Unicode emoji data as generated static data, not as handwritten
  template markup.
- Pin the Unicode source version so generated data is reproducible.
- Avoid adding an npm, bundler, or frontend framework dependency.
- Keep the generator and generated data shape reviewable in the
  repository, and keep the generated build artifact easy to inspect.
- Implement one shared picker presentation component with mode-specific
  click behavior.

### 2.3 Non-Goals

- Do not implement emoji search in this design. Search can be added
  later using the same generated names and keywords.
- Do not implement skin-tone or hair-style variant selectors in the
  first version. The Unicode source already contains fully-qualified
  variants; this design displays them as ordinary emoji entries.
- Do not implement a custom client-side ActivityPub API. The picker
  submits the existing HTML form.
- Do not change the federation representation of reactions.
- Do not change how reactions are stored in SQLite.
- Do not change the Markdown syntax for custom emoji in posts.

---

## 3. Existing System

### 3.1 Current Reaction Form

The current post partial renders this form:

```html
<form class="inline react-form" method="post" action="{{ site.root }}post/{{ post.id }}/react">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <input type="text" name="emoji" maxlength="40" placeholder="emoji" class="react-input">
  <button type="submit" class="linkbtn">react</button>
</form>
```

The important contract is the submitted field:

```text
emoji=<unicode emoji or :shortcode:>
```

This contract is already enough for an emoji picker. Each picker item can
be a submit button with `name="emoji"` and `value="<emoji value>"`.

### 3.2 Current Backend Handler

`App::handleReact()` performs these steps:

1. Validate CSRF.
2. Resolve the current logged-in user.
3. Load the target post by ID.
4. Confirm the user may view the post.
5. Read `emoji` from form parameters.
6. Add or remove the local reaction through `Service::setReaction()`.
7. If needed, enqueue outbound ActivityPub delivery.
8. Redirect back to the referring page.

The picker should not duplicate any of that logic. It should only submit
the same form field that the handler already expects.

### 3.3 Current Custom Emoji Registry

The app already scans server-wide custom emoji at startup through
`EmojiRegistry`. `App::baseContext()` exposes custom emoji to templates
as `ctx["emoji"]`, where each item includes:

```json
{
  "shortcode": "blobcat",
  "image_url": "/emoji/blobcat.png"
}
```

This existing data should become the first picker tab.

### 3.4 Current Composer

The current composer in `_composer.html` renders a textarea for post
content and a passive custom emoji list:

```html
<textarea name="content" rows="4" placeholder="Write a post (Markdown)…"></textarea>
```

When custom emoji exist, the template renders each custom emoji with its
shortcode as visible text. That helps discovery but still requires the
user to manually type or copy the shortcode.

The composer picker should use the same emoji data as the reaction
picker, but its click behavior is different:

```text
Unicode emoji click -> insert "😀" into textarea
Custom emoji click -> insert ":blobcat:" into textarea
```

No backend route change is needed because the submitted post content is
still normal Markdown source.

---

## 4. Unicode Emoji Data Source

### 4.1 Official Source

Use Unicode's official emoji test data file:

[`emoji-test.txt`](https://www.unicode.org/Public/emoji/latest/emoji-test.txt)

The file is part of the Unicode Emoji data described by
[Unicode Technical Standard #51](https://www.unicode.org/reports/tr51/).
For implementation stability, the generator must use a pinned version by
default, for example:

```text
https://www.unicode.org/Public/17.0.0/emoji/emoji-test.txt
```

The script may support `latest` as an explicit option for maintainers,
but generated data should record an exact Unicode version.

### 4.2 Why `emoji-test.txt`

`emoji-test.txt` is the correct input for this feature because it already
contains the information a picker needs:

- Group comments, such as `Smileys & Emotion`.
- Subgroup comments, such as `face-smiling`.
- Emoji display order.
- Qualification status.
- The rendered emoji string.
- The emoji version, such as `E1.0`.
- The CLDR short name, such as `grinning face`.

Other Unicode files are useful for lower-level validation and property
analysis, but they are less convenient for a picker:

- `emoji-data.txt` contains emoji-related properties.
- `emoji-sequences.txt` contains non-ZWJ valid sequences.
- `emoji-zwj-sequences.txt` contains valid ZWJ sequences.
- `emoji-variation-sequences.txt` contains emoji/text presentation
  variation sequences.

The picker is a presentation feature, so the ordered, grouped test file
is the right primary source.

---

## 5. Generated Data File

### 5.1 File Location

Generate this file in the build directory:

```text
<build_dir>/data/emoji_categories.json
```

The source tree may also contain a checked-in copy later if offline
source distribution becomes important, but the primary workflow is that
CMake runs the generator during build configuration. The generated
`data/` directory is for static application data that is neither source
code nor user-uploaded runtime data. It should be installed with the
application package in the same way templates and static assets are
installed.

### 5.2 JSON Shape

Use this top-level structure:

```json
{
  "source": {
    "unicode_version": "17.0.0",
    "url": "https://www.unicode.org/Public/17.0.0/emoji/emoji-test.txt",
    "generated_at": "2026-06-29"
  },
  "categories": [
    {
      "id": "smileys_emotion",
      "label": "Smileys & Emotion",
      "subgroups": [
        {
          "id": "face_smiling",
          "label": "face-smiling",
          "emoji": [
            {
              "emoji": "😀",
              "name": "grinning face",
              "version": "E1.0"
            }
          ]
        }
      ]
    }
  ]
}
```

### 5.3 Field Definitions

`source.unicode_version`
: The Unicode version used to generate the file. This makes diffs and
  package contents auditable.

`source.url`
: The exact source URL downloaded by the generator.

`source.generated_at`
: The generation date in `YYYY-MM-DD` format. This is informational.

`categories`
: Ordered category list. Order must match the source file so the picker
  behaves like Unicode's recommended order.

`categories[].id`
: A stable ASCII identifier derived from the group label. It is used for
  HTML IDs, tab state, and CSS selectors.

`categories[].label`
: Human-readable category label from the source file.

`categories[].subgroups`
: Ordered subgroup list. Keeping subgroup information allows the UI to
  add subgroup headings now or later without regenerating data.

`categories[].subgroups[].id`
: A stable ASCII identifier derived from the subgroup label.

`categories[].subgroups[].label`
: Human-readable subgroup label from the source file.

`categories[].subgroups[].emoji`
: Ordered emoji entries.

`emoji`
: The actual emoji string to submit to the backend.

`name`
: CLDR short name from the source comment. It should be used for
  `title` and `aria-label`.

`version`
: Emoji version from the source comment.

### 5.4 Why JSON Instead of a C++ Header

The generated artifact should be JSON, not a generated C++ header:

- Emoji categories are data, not behavior.
- JSON can be inspected and reviewed without compiling.
- JSON can be reused by server-side rendering and future client-side
  enhancements.
- Updating emoji data does not require changing C++ source files.
- The application can load the data once at startup, which is cheap.
- A C++ header would increase compile time and make large data diffs
  harder to review.

---

## 6. Generator Script

### 6.1 File Location

Add a generator script:

```text
tools/generate_emoji_data.py
```

Python is acceptable for this repository tool because it is a developer
utility, not application runtime logic. The script must only use the
Python standard library.

### 6.2 Command Line Interface

The script should support:

```text
tools/generate_emoji_data.py \
    --unicode-version 17.0.0 \
    --output build/data/emoji_categories.json
```

Optional arguments:

```text
--unicode-version VERSION
```

The Unicode version to download. This argument is required when the
script needs to download from Unicode and `--source-url` is not supplied.
The script does not define its own pinned default version. CMake owns the
pinned version and passes it explicitly.

```text
--source-url URL
```

An explicit URL override. This is useful for testing against a local
file server or a future Unicode URL shape.

```text
--input PATH
```

Read an already-downloaded `emoji-test.txt` file instead of downloading.
This is useful for offline tests and reproducible CI fixtures.

```text
--output PATH
```

Destination JSON path.

The script must fail with a clear usage error unless `--output` is
provided and at least one of these input sources is provided:

- `--input`
- `--source-url`
- `--unicode-version`

### 6.3 Download Behavior

When `--input` is not provided, the script constructs the source URL:

```text
https://www.unicode.org/Public/<version>/emoji/emoji-test.txt
```

If `--unicode-version latest` is explicitly passed, use:

```text
https://www.unicode.org/Public/emoji/latest/emoji-test.txt
```

The script should fail with a clear error if the download fails. It
should not silently write a partial output file.

### 6.4 CMake Integration

CMake should run the generator at configure time. This means the emoji
JSON is refreshed whenever the developer reconfigures the build tree.
The generated file lives under the build directory, not the source
directory:

```text
${CMAKE_BINARY_DIR}/data/emoji_categories.json
```

The CMake configuration should:

1. Find a Python 3 interpreter.
2. Define the pinned Unicode version in one CMake variable.
3. Run `tools/generate_emoji_data.py` with that version and the build
   directory output path.
4. Fail configuration if generation fails.
5. Pass the generated file path into the application config defaults or
   arrange for the runtime package to install the generated file at the
   configured default location.

Suggested CMake shape:

```cmake
find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(UNSPOKEN_UNICODE_EMOJI_VERSION "17.0.0"
    CACHE STRING "Unicode emoji data version")

set(UNSPOKEN_EMOJI_DATA_FILE
    "${CMAKE_BINARY_DIR}/data/emoji_categories.json")

execute_process(
    COMMAND
        "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/tools/generate_emoji_data.py"
        --unicode-version "${UNSPOKEN_UNICODE_EMOJI_VERSION}"
        --output "${UNSPOKEN_EMOJI_DATA_FILE}"
    RESULT_VARIABLE emoji_data_result
)

if(NOT emoji_data_result EQUAL 0)
    message(FATAL_ERROR "Failed to generate emoji data")
endif()
```

This deliberately uses `execute_process()` rather than a build target
because the desired behavior is configure-time generation. Re-running
the normal build should not unexpectedly contact Unicode. Re-running
CMake configuration may contact Unicode.

For offline or distribution builds, CMake should provide an option to
use an already-downloaded input file:

```cmake
set(UNSPOKEN_EMOJI_TEST_INPUT "" CACHE FILEPATH
    "Optional local emoji-test.txt input")
```

When this variable is non-empty, CMake passes:

```text
--input <path>
```

to the generator instead of requiring a network download.

### 6.5 Parsing Algorithm

Process the file line by line:

1. Start with an empty category list.
2. If a line starts with `# group: `:
   - Extract the group label.
   - Create a new category.
   - Derive `id` by lowercasing, replacing non-alphanumeric runs with
     `_`, and trimming leading/trailing `_`.
3. If a line starts with `# subgroup: `:
   - Extract the subgroup label.
   - Create a new subgroup inside the current category.
   - Derive `id` using the same slug rule.
4. If a line is blank or starts with `#`, ignore it.
5. For data lines, parse the shape:

   ```text
   <codepoints> ; <status> # <emoji> <version> <name>
   ```

6. Keep only lines where `<status>` is `fully-qualified`.
7. Extract the rendered emoji, version, and name from the comment.
8. Append the emoji entry to the current subgroup.
9. After parsing, remove empty subgroups and empty categories.
10. Write formatted UTF-8 JSON with stable indentation.

### 6.6 Error Handling

The generator should fail if:

- No categories are produced.
- An emoji data line appears before any group.
- An emoji data line appears before any subgroup.
- The output directory cannot be created.
- The downloaded file is empty.
- The source file format cannot be parsed for a data line that otherwise
  appears valid.

The generator should skip:

- Non-fully-qualified emoji.
- Pure comments.
- Blank lines.

This fail/skip split is important. Expected source content should be
handled quietly, but structural surprises should be visible to the
maintainer.

---

## 7. Runtime Loading

### 7.1 Configuration

Add a config field:

```yaml
emoji_data_file: data/emoji_categories.json
```

Default value:

```text
data/emoji_categories.json
```

This mirrors the existing `emoji_dir` configuration. The custom emoji
directory is operator-managed runtime content, while `emoji_data_file` is
generated static data. In a development build, the default may point at
the generated file under `${CMAKE_BINARY_DIR}`. In an installed package,
the default should point at the installed generated JSON file.

### 7.2 Data Types

Add plain structs in the emoji module or a small adjacent module:

```c++
struct UnicodeEmoji
{
    std::string emoji;
    std::string name;
    std::string version;
};

struct UnicodeEmojiSubgroup
{
    std::string id;
    std::string label;
    std::vector<UnicodeEmoji> emoji;
};

struct UnicodeEmojiCategory
{
    std::string id;
    std::string label;
    std::vector<UnicodeEmojiSubgroup> subgroups;
};
```

Public structs and public loader functions need comments, following the
project's style requirements.

### 7.3 Loader Function

Add a loader function:

```c++
mw::E<std::vector<UnicodeEmojiCategory>>
loadUnicodeEmojiCategories(const std::string& path);
```

Responsibilities:

1. Read the JSON file.
2. Parse it with `nlohmann::json`.
3. Validate required fields and expected types.
4. Return ordered categories.

If the file is missing or invalid, startup should not fail. The app
should log a warning and continue with only custom emoji. This keeps a
bad packaged data file from disabling the whole server.

### 7.4 App Lifetime

`App` should load Unicode emoji categories once during construction,
next to the existing custom emoji registry scan:

```c++
emoji(unspoken::EmojiRegistry::scan(conf.emoji_dir, conf.url_root)),
unicode_emoji(unspoken::loadUnicodeEmojiCategories(conf.emoji_data_file))
```

The exact code should follow the repository's current `mw::E<>` and
logging conventions.

### 7.5 Template Context

Extend `App::baseContext()` with:

```json
{
  "unicode_emoji": [
    {
      "id": "smileys_emotion",
      "label": "Smileys & Emotion",
      "subgroups": [
        {
          "id": "face_smiling",
          "label": "face-smiling",
          "emoji": [
            {
              "emoji": "😀",
              "name": "grinning face"
            }
          ]
        }
      ]
    }
  ]
}
```

All string fields inserted into the context should be HTML-escaped where
appropriate. The emoji character value itself must remain the original
Unicode string because it is submitted as the form value.

---

## 8. Shared Picker UI

The picker is one shared visual component used in two places:

- Reaction picker in `_post.html`.
- Composer picker in `_composer.html`.

The two pickers share category data, tab layout, styling, and tab
JavaScript. They differ only in what happens when a user clicks an emoji.

### 8.1 Reaction Placement

Replace the current reaction text input form in `_post.html` with a
picker form. The form action remains:

```text
{{ site.root }}post/{{ post.id }}/react
```

The form still contains:

```html
<input type="hidden" name="csrf" value="{{ csrf }}">
```

### 8.2 Composer Placement

Add the picker near the composer textarea or composer controls. The
picker should be visually connected to text entry, not buried below
attachments or visibility controls.

Suggested structure:

```html
<div class="composer-text">
  <textarea id="composer-content"
            name="content"
            rows="4"
            placeholder="Write a post (Markdown)…"></textarea>
  <div class="composer-tools">
    <!-- composer emoji picker trigger goes here -->
  </div>
</div>
```

The picker must know which textarea it targets. The simplest approach is
to place the picker inside the same composer form and let JavaScript find
the nearest textarea:

```javascript
const form = picker.closest("form");
const textarea = form.querySelector("textarea[name='content']");
```

This avoids global IDs and works if a page later contains multiple
composer forms.

### 8.3 Picker Modes

Use a mode marker on the picker root:

```html
<details class="emoji-picker" data-emoji-mode="react">
```

or:

```html
<details class="emoji-picker" data-emoji-mode="insert">
```

Reaction mode submits a form. Composer insert mode updates a textarea.

### 8.4 Reaction Submit Buttons

In reaction mode, each emoji item is a submit button.

Unicode emoji:

```html
<button class="emoji-choice"
        type="submit"
        name="emoji"
        value="😀"
        title="grinning face"
        aria-label="React with grinning face">😀</button>
```

Custom emoji:

```html
<button class="emoji-choice"
        type="submit"
        name="emoji"
        value=":blobcat:"
        title=":blobcat:"
        aria-label="React with :blobcat:">
  <img class="emoji" src="/emoji/blobcat.png" alt=":blobcat:">
</button>
```

This is the core design decision. The browser already knows how to
submit only the clicked submit button's name/value pair, so no custom
JavaScript is needed to send the selected emoji.

### 8.5 Composer Insert Buttons

In composer mode, each emoji item is a normal button with an insertion
value. It must use `type="button"` so it does not submit the post form.

Unicode emoji:

```html
<button class="emoji-choice"
        type="button"
        data-emoji-insert="😀"
        title="grinning face"
        aria-label="Insert grinning face">😀</button>
```

Custom emoji:

```html
<button class="emoji-choice"
        type="button"
        data-emoji-insert=":blobcat:"
        title=":blobcat:"
        aria-label="Insert :blobcat:">
  <img class="emoji" src="/emoji/blobcat.png" alt=":blobcat:">
</button>
```

The inserted string is deliberately different by emoji type:

- Unicode emoji insert their actual character.
- Custom emoji insert their shortcode, because that is what the post
  renderer recognizes in Markdown source.

### 8.6 Picker Shell

Use a compact picker trigger in the action bar:

```html
<details class="emoji-picker">
  <summary class="linkbtn emoji-picker-trigger">☺</summary>
  <div class="emoji-picker-panel">
    ...
  </div>
</details>
```

The summary text can be an emoji-like glyph or a short label. If the UI
later adopts an icon library, it can be replaced with an icon button.

The composer can use the same shell. Its trigger should sit near the
textarea controls and can use the same visual class as the reaction
picker trigger.

### 8.7 Tabs

Render tabs inside the panel:

```html
<div class="emoji-tabs" role="tablist">
  <button type="button" class="emoji-tab active" data-tab="custom">
    custom
  </button>
  <button type="button" class="emoji-tab" data-tab="smileys_emotion">
    Smileys
  </button>
</div>
```

Render each category panel:

```html
<div class="emoji-tab-panel active" data-tab-panel="custom">
  ...
</div>
```

JavaScript toggles which tab and panel have the `active` class. The
buttons that switch tabs must use `type="button"` so they do not submit
the reaction form.

### 8.8 First Tab Rule

If custom emoji exist, the first tab is:

```text
custom
```

If there are no custom emoji, do not render an empty custom tab. The
first tab should be the first Unicode category.

This avoids making the user open a tab that has no choices.

### 8.9 Category Labels

Unicode group labels from `emoji-test.txt` are descriptive but sometimes
long. The generated JSON should keep the official labels. The template
may display shorter labels if needed, but it must preserve the full
label in `title` or `aria-label`.

Suggested visible labels:

| Unicode label | Suggested tab label |
|---------------|---------------------|
| Smileys & Emotion | Smileys |
| People & Body | People |
| Animals & Nature | Nature |
| Food & Drink | Food |
| Travel & Places | Places |
| Activities | Activities |
| Objects | Objects |
| Symbols | Symbols |
| Flags | Flags |

This short-label mapping can be implemented in C++ when building the
template context or in the template if Inja support is sufficient.

### 8.10 Subgroups

The first version may render subgroup headings inside the active panel:

```html
<div class="emoji-subgroup">
  <div class="emoji-subgroup-label">face-smiling</div>
  <div class="emoji-grid">...</div>
</div>
```

Subgroup headings make large categories easier to scan. If they make the
panel too visually noisy, the data model still supports hiding them with
CSS or omitting the label markup while preserving ordering.

### 8.11 Existing Reaction Chips

Existing reaction chips should remain above the action bar. This design
does not require changing them.

A later improvement can make existing reaction chips clickable. That
would let a user quickly add the same reaction someone else already
used. If implemented later, each chip should submit the same `/react`
form with the chip's emoji value.

---

## 9. JavaScript Behavior

### 9.1 File Location

Add a small script:

```text
static/emoji_picker.js
```

The script should be loaded by the footer or the pages that render
posts. It must not depend on external libraries.

### 9.2 Responsibilities

The script has presentation responsibilities and composer-local text
insertion responsibilities:

1. Find every `.emoji-picker`.
2. Find its `.emoji-tab` buttons.
3. Find its `.emoji-tab-panel` elements.
4. On tab click:
   - Remove `active` from all tabs and panels in this picker.
   - Add `active` to the clicked tab.
   - Add `active` to the matching panel.
   - Update `aria-selected`.
   - Update `hidden` on inactive panels if used.
5. For `data-emoji-mode="insert"` pickers, handle `.emoji-choice`
   clicks by inserting `data-emoji-insert` into the nearest composer
   textarea.

The script must not build ActivityPub payloads, call `fetch()`, or
duplicate backend behavior.

### 9.3 Multiple Posts on One Page

Timeline pages render many posts. The script must scope tab switching to
the nearest picker container so selecting a tab on one post does not
change the picker state on another post.

Use DOM traversal like:

```javascript
const picker = tab.closest(".emoji-picker");
```

Then query only inside `picker`.

The same scoping rule applies to composer insertion. The script must
find the textarea in the nearest composer form, not by querying the
whole document.

### 9.4 Composer Insertion Algorithm

When an insert-mode emoji button is clicked:

1. Read the button's `data-emoji-insert` value.
2. Find the nearest `.emoji-picker`.
3. Find the nearest containing `form`.
4. Find `textarea[name="content"]` inside that form.
5. Read `selectionStart` and `selectionEnd`.
6. Replace the selected text with the insertion value.
7. Set both selection positions after the inserted value.
8. Focus the textarea.
9. Dispatch an `input` event so future autosize or draft-saving code can
   observe the change.

Example logic:

```javascript
const before = textarea.value.slice(0, start);
const after = textarea.value.slice(end);
textarea.value = before + value + after;
const cursor = before.length + value.length;
textarea.setSelectionRange(cursor, cursor);
textarea.focus();
textarea.dispatchEvent(new Event("input", { bubbles: true }));
```

If the browser does not expose `selectionStart`, append the value to the
end of the textarea as a fallback.

### 9.5 No-JavaScript Fallback

Without JavaScript, the reaction picker should still be usable. There
are two acceptable fallback approaches:

1. Show all category panels stacked.
2. Use native `<details>` for each category instead of JS-only tabs.

The first version should prefer stacked panels because it is simpler.
CSS can hide inactive panels only when JavaScript adds a marker class to
`document.documentElement`, for example:

```javascript
document.documentElement.classList.add("js");
```

Then CSS can do:

```css
.js .emoji-tab-panel { display: none; }
.js .emoji-tab-panel.active { display: block; }
```

Without JavaScript, `.js` is absent and all panels remain visible.

The composer insert picker cannot fully work without JavaScript because
HTML alone cannot insert text at the textarea cursor. For no-JavaScript
composer fallback, render custom emoji and Unicode emoji with visible
copyable values. That is no worse than the current custom emoji list and
still exposes the available emoji.

---

## 10. Styling

### 10.1 Design Constraints

The existing UI is compact and server-rendered. The picker should match
that style:

- Use existing color variables.
- Keep borders and spacing consistent with existing action buttons.
- Avoid Bootstrap or any external CSS framework.
- Avoid large decorative surfaces.
- Keep the picker usable on narrow screens.
- Fit both the compact post action bar and the composer controls.

### 10.2 Layout

Suggested CSS structure:

```css
.emoji-picker {
    position: relative;
}

.emoji-picker-panel {
    position: absolute;
    z-index: 20;
    width: min(360px, calc(100vw - 24px));
    max-height: 320px;
    overflow: auto;
}

.emoji-tabs {
    display: flex;
    overflow-x: auto;
}

.emoji-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(34px, 1fr));
    gap: 4px;
}
```

Exact colors and border values should reuse `static/style.css` variables.

### 10.3 Button Sizing

Emoji choice buttons need stable dimensions so the grid does not shift:

```css
.emoji-choice {
    width: 34px;
    height: 34px;
}
```

Custom emoji images should fit inside that button:

```css
.emoji-choice img.emoji {
    max-width: 24px;
    max-height: 24px;
}
```

### 10.4 Mobile Behavior

On narrow screens:

- The panel width should not exceed the viewport.
- The panel should remain scrollable.
- Tabs should scroll horizontally.
- Emoji buttons should remain at least 32px by 32px.

If absolute positioning causes clipping inside the timeline layout, the
mobile CSS can make the panel `position: fixed` with left/right margins.

### 10.5 Composer Layout

The composer picker should not make the textarea jump or resize when a
tab is changed. The picker panel should open over or below the composer
controls, and its panel should have a fixed max height with internal
scrolling.

The composer's passive custom emoji list should be removed or replaced
by the interactive picker. Keeping both would duplicate the same data and
make the composer visually noisy.

---

## 11. Accessibility

### 11.1 Buttons

Every emoji choice button must have:

- `title`
- `aria-label`
- visible emoji or an image with meaningful `alt`

The accessible label should describe the action, not only the symbol:

```text
React with grinning face
```

For composer insertion, use:

```text
Insert grinning face
```

### 11.2 Tabs

The tab list should use:

```html
role="tablist"
```

Each tab should use:

```html
role="tab"
aria-selected="true|false"
```

Each panel should use:

```html
role="tabpanel"
```

This is enough for the first version. Full keyboard arrow-key tab
navigation can be added later if needed.

### 11.3 Reduced Motion

Do not require animation. If hover/focus transitions are added, they
should be small and should not be necessary to understand the UI.

---

## 12. Backend Changes

### 12.1 Reaction Handler

No route change is required. `App::handleReact()` should continue to
read `emoji` from the submitted form.

### 12.2 Validation

The existing handler rejects empty emoji. This remains correct.

The handler currently allows arbitrary non-empty strings. That is
consistent with the current manual input UI and with remote custom emoji
shortcodes. This design does not tighten validation because stricter
rules could accidentally reject valid custom emoji or future Unicode
sequences.

### 12.3 Redirect Behavior

The handler should continue redirecting to the referring page. The
picker submits a normal form, so the current redirect behavior provides
the post-reaction refresh.

### 12.4 Composer Backend

No post creation route change is required. Composer insertion modifies
the `content` textarea before submission. The backend receives ordinary
Markdown source exactly as it does today.

Custom emoji continue to use shortcode syntax in source text:

```text
:blobcat:
```

The existing render path resolves the shortcode through the custom emoji
registry and emits the corresponding `<img class="emoji">` markup.

---

## 13. Packaging and Installation

The generated JSON file must be included wherever runtime assets are
installed. The package should install the generated build artifact:

```text
data/emoji_categories.json
```

alongside:

```text
templates/
static/
```

If the system package has a read-only application directory and a
separate writable state directory, `emoji_categories.json` belongs in the
read-only application data directory. It should not be stored beside
uploaded media or custom emoji.

Because CMake generates the file during configuration, package builders
need network access during configure unless they provide
`UNSPOKEN_EMOJI_TEST_INPUT` or an equivalent local source file option.
This tradeoff is intentional for this design because the requested
developer workflow is that reconfiguring the build refreshes emoji data.

---

## 14. Testing Strategy

### 14.1 Generator Tests

Use a small fixture containing:

```text
# group: Smileys & Emotion
# subgroup: face-smiling
1F600 ; fully-qualified # 😀 E1.0 grinning face
263A FE0F ; fully-qualified # ☺️ E0.6 smiling face
263A ; unqualified # ☺ E0.6 smiling face
```

Expected results:

- One category is produced.
- One subgroup is produced.
- The two `fully-qualified` entries are included.
- The `unqualified` entry is skipped.
- Order is preserved.

### 14.2 Loader Tests

Add C++ tests for:

- Loading a valid JSON file.
- Preserving category order.
- Preserving subgroup order.
- Preserving emoji order.
- Rejecting malformed JSON through `mw::E<>`.
- Rejecting missing required fields.

### 14.3 Template Behavior Tests

If the project has template rendering tests, add assertions that:

- The old text input is gone.
- The reaction form still posts to `/post/:id/react`.
- The CSRF input is present.
- Unicode emoji choices render as submit buttons.
- Custom emoji choices render as submit buttons with shortcode values.
- No separate `react` submit button is rendered.
- The composer renders an insert-mode picker.
- Composer custom emoji choices contain `data-emoji-insert=":name:"`.
- Composer Unicode emoji choices contain `data-emoji-insert` with the
  actual Unicode emoji.
- The old passive composer-only custom emoji reference list is removed
  or replaced by the interactive picker.

### 14.4 Handler Regression Tests

Existing handler behavior should remain valid. Add or keep tests that
submit:

```text
emoji=😀
```

and:

```text
emoji=:blobcat:
```

Both should create reactions through the same endpoint.

### 14.5 JavaScript Tests

If the project adds frontend tests, cover:

- Tab switching affects only the current picker.
- Insert-mode clicking inserts at the textarea cursor.
- Insert-mode clicking replaces selected text.
- The textarea remains focused after insertion.
- An `input` event fires after insertion.

If no frontend test harness exists yet, keep the insertion code small and
verify it manually in browser checks.

### 14.6 Manual Browser Checks

Verify in a browser:

- Timeline page with multiple posts.
- Thread page with a focused post.
- Composer on the home page.
- Picker with custom emoji configured.
- Picker with no custom emoji configured.
- Narrow mobile viewport.
- JavaScript disabled.
- Unicode emoji insertion into the composer.
- Custom emoji shortcode insertion into the composer.
- Insertion at the beginning, middle, and end of textarea content.
- Replacement of selected textarea text.

For the JavaScript-disabled case, the user must still be able to submit
a reaction by clicking an emoji button. Composer insertion may degrade to
visible copyable emoji values.

---

## 15. Implementation Plan

1. Add `tools/generate_emoji_data.py`.
2. Add CMake configure-time generation of
   `${CMAKE_BINARY_DIR}/data/emoji_categories.json`.
3. Add `emoji_data_file` to config defaults and YAML parsing.
4. Wire development defaults to the generated build-directory JSON.
5. Add Unicode emoji data structs and loader.
6. Load Unicode emoji categories during app construction.
7. Add Unicode emoji categories to `baseContext()`.
8. Create shared picker template markup or a template partial if Inja
   reuse is practical.
9. Replace the reaction text input in `_post.html` with the reaction
   picker form.
10. Replace the passive custom emoji composer list in `_composer.html`
   with the insert-mode picker.
11. Add `static/emoji_picker.js` for tab switching and composer
    insertion.
12. Add picker styles to `static/style.css`.
13. Ensure packaged installs include the generated
    `data/emoji_categories.json`.
14. Add generator, loader, rendering, and insertion tests where
    practical.
15. Run the existing test suite.
16. Manually verify the picker in desktop and mobile layouts.

---

## 16. Risks and Mitigations

### 16.1 Large Generated File

Unicode emoji data is larger than the rest of the current UI data. This
can make templates heavier.

Mitigation:

- Load once at startup.
- Render only compact fields needed by the picker.
- Keep images out of the Unicode data; Unicode emoji render as text.

### 16.2 Picker Repeated for Every Post

Timeline pages may render many posts, and each post may include the full
picker markup.

Mitigation:

- The first implementation can accept this for simplicity.
- If markup size becomes a problem, move to one shared picker component
  controlled by JavaScript while preserving form-submit behavior.

### 16.3 Unicode Source Format Changes

Unicode may change comments or formatting in a future version.

Mitigation:

- Pin the version used by default.
- Keep the generator strict enough to fail loudly on unexpected format.
- Use `--input` fixtures for tests.

### 16.4 Network Dependency During CMake Configure

Generating the emoji JSON during CMake configuration means a fresh build
tree may need network access to Unicode's website.

Mitigation:

- Keep the Unicode version pinned so the URL is stable.
- Provide a CMake option for a local `emoji-test.txt` input file.
- Fail configuration with a clear error if the download fails.
- Do not contact Unicode during ordinary incremental builds.

### 16.5 Custom Emoji Count

Some servers may have many custom emoji. A single custom tab could
become large.

Mitigation:

- Make the picker panel scrollable.
- Add custom emoji search later if needed.
- Preserve custom emoji ordering from `EmojiRegistry::all()`.

### 16.6 Composer Requires JavaScript For Insertion

Textarea insertion at cursor position cannot be implemented with plain
HTML alone.

Mitigation:

- Keep the reaction picker fully functional without JavaScript.
- In no-JavaScript composer mode, show copyable emoji values.
- Keep insertion JavaScript small, local, and independent of network
  calls.

---

## 17. Future Enhancements

- Emoji search using generated `name` fields.
- Keyword search using Unicode CLDR annotations.
- Recently used emoji stored per session or per user.
- Clickable existing reaction chips.
- Keyboard navigation for tabs and emoji grid.
- Skin-tone variant grouping.
- One shared picker instance per page to reduce repeated markup.
- Emoji insertion in profile bio editing, using the same insert-mode
  picker.
