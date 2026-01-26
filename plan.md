# Implementation Plan: C++23 ActivityPub Micro-blog Server

## Phase 1: Infrastructure & Core Setup
**Goal:** Initialize the project, set up the build system, and integrate core libraries.
1.  **Project Skeleton:**
    *   Initialize Git repository (if not already done).
    *   Set up `CMakeLists.txt` with C++23 standard.
2.  **Dependency Integration:**
    *   Add `libmw` (HTTP, utils), `nlohmann/json` (JSON), `rapidyaml` (Config), `inja` (Templates), `MacroDown` (Markdown) via CMake (FetchContent or find_package).
    *   Add `sqlite3` and `openssl`.
3.  **Configuration & Logging:**
    *   Implement `Config` class using `rapidyaml` to load settings from a YAML file.
    *   Set up logging using `libmw` or a simple logger.
4.  **Database Connection:**
    *   Initialize SQLite connection with WAL mode enabled.
    *   Implement schema versioning and basic migration support (starting at v1).

## Phase 2: Data Layer & Core Structures
**Goal:** Define the data models and persistence layer.
1.  **Struct Module:**
    *   Define C++ structs/classes for `User` (Local/Remote), `Post`, `Activity`, `Follow`, `Notification`.
2.  **Database Schema (v1):**
    *   Create tables: `users`, `posts`, `follows`, `likes`, `bookmarks`, `jobs`, `media`.
3.  **Data Module:**
    *   Implement DAO (Data Access Object) patterns.
    *   Methods: `CreateUser`, `GetUser`, `CreatePost`, `GetTimeline`, `SaveRemoteActor`, etc.

## Phase 3: Application Logic & HTTP Server
**Goal:** Get the web server running and serving basic content.
1.  **App Module Skeleton:**
    *   Setup `libmw` HTTP server instance.
    *   Define route handlers structure.
2.  **Authentication (OIDC):**
    *   Implement OIDC login flow (Redirect to Keycloak -> Callback -> Create Session).
    *   Implement session management (cookies, persistence in DB).
    *   Profile setup for first-time login (Username selection).
3.  **Web UI (Read-Only):**
    *   Integrate Inja templates.
    *   Implement public timeline rendering.
    *   Implement User profile page rendering.
    *   Implement Thread/Post view.

## Phase 4: Federation - Foundation
**Goal:** Enable the server to "speak" ActivityPub.
1.  **Cryptography:**
    *   Implement RSA/Ed25519 key generation for users.
    *   Implement HTTP Message Signatures (Draft-04 compatible) verification and signing using `libmw`.
2.  **Discovery:**
    *   Implement `.well-known/webfinger` endpoint.
    *   Implement `.well-known/nodeinfo` endpoint.
    *   Implement Remote Actor lookup (WebFinger + Fetch JSON + Verify).
3.  **JSON Normalization:**
    *   Create a parser to handle AP polymorphism (Array vs Object, String vs Object).

## Phase 5: Federation - Incoming (Inbox)
**Goal:** Receive messages from other servers.
1.  **Inbox Endpoint:**
    *   Create `/u/<user>/inbox` and `/sharedInbox`.
    *   Validate HTTP Signatures on incoming requests.
2.  **Activity Handlers:**
    *   `Create` (Post): Parse and save to DB.
    *   `Delete`: Handle post deletion.
    *   `Follow`: Handle follow requests (Auto-accept logic).
    *   `Undo`: Handle unfollows.
    *   `Like/Announce`: Store interactions.
3.  **Spam/Safety:**
    *   Basic sender verification (fetch public key if unknown).

## Phase 6: Federation - Outgoing (Outbox)
**Goal:** Send messages to other servers.
1.  **Job Queue System:**
    *   Implement database-backed job queue for async delivery.
    *   Implement background worker(s) to process jobs.
    *   Retry logic (configurable counts/delays).
2.  **Outbox Logic:**
    *   Construct ActivityPub JSON for local activities.
    *   Resolve recipients (SharedInbox optimization).
    *   Sign and send HTTP requests to remote inboxes.

## Phase 7: Interactive Features & UI
**Goal:** Allow users to interact via the Web UI.
1.  **Posting:**
    *   Markdown editor.
    *   File upload handling (Hash-based renaming, storage).
    *   Post creation logic (DB insert + Federation job enqueue).
2.  **Interactions:**
    *   Reply, Boost (Announce), Like, Bookmark.
    *   Follow/Unfollow buttons.
    *   Search UI (Local + Remote WebFinger).
3.  **CSRF Protection:**
    *   Add CSRF tokens to all state-changing forms.

## Phase 8: Polish & Refinement
**Goal:** Production readiness.
1.  **Sanitization:** Ensure all HTML rendered from markdown or remote content is sanitized.
2.  **Pagination:** Refine pagination for API and Web UI.
3.  **Testing:**
    *   Unit tests for parsers and logic.
    *   Integration tests for federation flows.
4.  **Deployment Prep:**
    *   Finalize `config.yaml` template.
    *   Documentation.
