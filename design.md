# Technical Design Document: ActivityPub Micro-blog Server

## 1. System Architecture

The application is a monolithic C++23 server utilizing `libmw` for networking and database interactions. It follows a modular design with clear separation of concerns between data persistence, federation logic, and the web interface.

### High-Level Components
*   **App Module**: The HTTP entry point, routing requests to appropriate handlers (UI or API).
*   **Federation Module**: Handles ActivityPub specific logic (Inbox/Outbox processing, JSON parsing/serialization, Signing).
*   **Data Module**: Abstracts SQLite database access.
*   **Job Queue**: Asynchronous task processor for outgoing federation.
*   **Templates**: Server-side rendering using `Inja`.

## 2. Dependencies & Technology Stack

*   **Language**: C++23
*   **Web Server / Utils**: `libmw` (Async HTTP, SQLite wrapper, Crypto utils).
*   **Database**: SQLite (WAL mode enabled).
*   **JSON**: `nlohmann/json`.
*   **Config**: `rapidyaml` (YAML parsing).
*   **Markdown**: `MacroDown` (with custom extensions for Mentions/Tags).
*   **Templates**: `Inja`.
*   **Auth**: OpenID Connect (integration with external provider like Keycloak).
*   **Build**: CMake.

## 3. Data Models (Schema)

The database schema uses integer IDs for local foreign keys but stores ActivityPub URIs for federation.

### Core Tables

#### `users`
*   `id`: INTEGER PK AUTOINCREMENT
*   `username`: TEXT UNIQUE (e.g., "alice")
*   `display_name`: TEXT
*   `bio`: TEXT
*   `email`: TEXT (from OIDC)
*   `uri`: TEXT UNIQUE (AP Actor ID)
*   `public_key`: TEXT (PEM)
*   `private_key`: TEXT (PEM, NULL for remote users)
*   `host`: TEXT (NULL for local, domain for remote)
*   `created_at`: INTEGER
*   `avatar_path`: TEXT

#### `posts`
*   `id`: INTEGER PK AUTOINCREMENT
*   `uri`: TEXT UNIQUE (AP Object ID)
*   `author_id`: INTEGER FK(users)
*   `content_html`: TEXT
*   `content_source`: TEXT (Markdown)
*   `in_reply_to_uri`: TEXT
*   `visibility`: INTEGER (0=Public, 1=Unlisted, 2=Followers, 3=Direct)
*   `created_at`: INTEGER
*   `is_local`: BOOLEAN

#### `follows`
*   `follower_id`: INTEGER FK(users)
*   `target_id`: INTEGER FK(users)
*   `status`: INTEGER (0=Pending, 1=Accepted)
*   `uri`: TEXT (AP Activity ID)

#### `likes` / `announces`
*   `user_id`: INTEGER FK(users)
*   `post_id`: INTEGER FK(posts)
*   `created_at`: INTEGER

#### `jobs`
*   `id`: INTEGER PK AUTOINCREMENT
*   `type`: TEXT (e.g., "deliver_activity")
*   `payload`: TEXT (JSON)
*   `attempts`: INTEGER
*   `next_try`: INTEGER (Timestamp)
*   `status`: INTEGER (0=Pending, 1=Processing, 2=Failed)

#### `media`
*   `id`: INTEGER PK AUTOINCREMENT
*   `hash`: TEXT UNIQUE (SHA256)
*   `filename`: TEXT
*   `mime_type`: TEXT
*   `uploader_id`: INTEGER FK(users)

## 4. Modules Detail

### 4.1. Struct Module
Defines C++ structs representing the domain objects. These structs should implement `toJson` and `fromJson` for easy serialization where applicable, or conversion methods for DB rows.

### 4.2. Data Module
Encapsulates all SQL queries.
*   Uses `libmw`'s SQLite wrapper.
*   **Key Functions**:
    *   `getUserByUri(string)`
    *   `createLocalPost(Post)`
    *   `getTimeline(user_id, page, limit)`
    *   `enqueueJob(Job)`

### 4.3. Federation Module
*   **JSON Normalization**: A wrapper around `nlohmann/json` to handle AP quirks (e.g., `object` field being a URI string OR a full JSON object).
*   **Signature Verifier**: Middleware to verify HTTP signatures on incoming requests to `/inbox`.
*   **Activity Dispatcher**:
    *   `handleCreate`: Parsing Note -> Inserting into `posts`.
    *   `handleFollow`: Auto-accept -> Create `follows` record -> Enqueue `Accept` activity.
    *   `handleUndo`: Generic undo handler.
*   **Delivery**:
    *   Resolves followers.
    *   Deduplicates shared inboxes.
    *   Signs requests using `libmw`.

### 4.4. App Module (HTTP)
*   **Router**:
    *   `GET /`: Home timeline (Public or User's).
    *   `GET /u/{username}`: Profile (HTML or JSON based on Accept header).
    *   `GET /p/{id}`: Post detail (HTML or JSON).
    *   `POST /u/{username}/inbox`: AP Inbox.
    *   `POST /auth/login`: Start OIDC flow.
    *   `GET /auth/callback`: OIDC callback.
*   **Controllers**:
    *   `WebController`: Renders Inja templates.
    *   `ActivityPubController`: Returns JSON-LD.

### 4.5. Job Queue
A polling loop or conditioned variable in a separate thread.
1.  Query `jobs` table for `status=0 AND next_try <= now`.
2.  Lock job (set `status=1`).
3.  Execute (e.g., HTTP POST to remote).
4.  On Success: Delete job.
5.  On Failure: Increment `attempts`, calculate exponential backoff, update `next_try`, set `status=0`.

## 5. Security & Privacy

*   **HTTP Signatures**: Strict verification for all incoming federation traffic.
*   **CSRF**: Token generation and validation for all local POST forms.
*   **Sanitization**: Input sanitization for all HTML content to prevent XSS.
*   **Visibility Logic**:
    *   *Public*: Served to everyone.
    *   *Followers-Only*: Served only if request is signed by a follower (for AP) or viewer is logged-in follower (Web).
    *   *Direct*: Filtered strictly by audience.

## 6. File Handling
*   **Uploads**:
    *   Calculate SHA256.
    *   Path: `uploads/{first_char}/{hash}.{ext}`.
    *   Deduplication: Check if hash exists in DB/Filesystem before saving.
*   **Serving**: Static file handler in `libmw`.

## 7. Configuration
*   Format: YAML.
*   Fields: `server_domain`, `port`, `db_path`, `oidc_client_id`, `oidc_secret`, `secret_key` (for sessions).