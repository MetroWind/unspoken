# Micro-blog with ActivityPub (Fediverse) in C++23

## User-facing features

Basically just standard micro blog features.

* Web UI
* When not logged in, home page shows timeline of all posts of users
  on the server
* Timeline is paginated. The number of posts per page is a
  configurable parameter.
* When logged in, home page shows timeline of posts from all the
  account that the current user follows, as well as the posts from the
  current user.
* User can write new posts
* User can choose post visibility (scope) when writing new posts.
  Valid visibilities are Public, Unlisted, Followers-Only, and Direct
  messaging.
* User can replay to posts
* User can repost (“boost”) posts
* User can like posts (post author sees who liked their posts)
* User can bookmark posts (Doesn’t involve federation)
* User can react to posts with emoji (pleroma-like reactions)
* User can search for both remote and local users.
* Server-wide custom emojis
* Authentication: use a already-setup OpenID Connect server (I have a
  keycloak server).
* User can attach files to their posts, and see attachment in others’
  posts.
* User can delete their own posts.
* When the user login for the first time, they should be asked to
  setup a username.
* User can go to their profile page to change their display name and
  bio.
* User can follow other users, both remote users and local users (on
  the same server)
* Follow request are accepted automatically (and `Accept` activities
  should be sent automatically).
* When user is viewing a single post, it’s display in its thread.

## Tech features

* Use sqlite for database. WAL should be turned on.
* Implement the (ActivityPub
  protocol)[https://www.w3.org/TR/activitypub/] to federate with other
  servers. Public key should be retrieved first when encountering a
  remote actor, and stored in the database. Locally-generated keys are
  stored in the database. Local user’s public keys are served as part
  of the Actor JSON object. All incoming requests should be verified.
  See
  https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-04.html
  for details. Also follow
  https://swicg.github.io/activitypub-http-signature/.
* Use [libmw](https://github.com/MetroWind/libmw) for HTTP server,
  HTTP queries, HTTP signing and verification, sqlite interfacing, and
  error handling. See example of usage in
  https://github.com/MetroWind/shrt . libmw headers are at
  https://github.com/MetroWind/libmw/tree/master/includes/mw . All
  queries to remote servers are signed.
* There should be a “system actor” to sign the queries that are not
  associated with a user.
* Prefer to use `mw::E<>` vs exceptions.
* Use cmake as the build system. An example cmakelist file which uses
  libmw can be found at
  https://github.com/MetroWind/shrt/blob/master/CMakeLists.txt
* External libraries should be imported with Cmake’s FetchContent,
  except for the widely used ones like openssl and sqlite.
* All outgoing posts will be composed in markdown, and rendered to
  HTML before sending to remote servers. Use the
  [MacroDown](https://git.xeno.darksair.org/macrodown/tree/master)
  library for markdown rendering.
  * Mention and tag parsing in posts. This is done by defining custom
    markups in MacroDown. Mentions and tags can be extracted by
    iterating the syntax tree.
* Incoming Delete, Update and Undo activities should be handled
  accordingly.
* Local operations like Delete and Update should be federated to
  remote servers.
* The backend will have a number of modules:
  * A struct module that contains class/struct definition of notable
    objects (users, activities, etc.)
  * A data module that interface with the database. See
    https://github.com/MetroWind/shrt/blob/master/src/data.hpp for an
    example
  * A federation module that contains the ActivityPub logic.
  * An app module that has the HTTP server and request handlers.
* `.well-known/webfinger` and `.well-known/nodeinfo` endpoints. Fields
  in nodeinfo are configured in the config file.
* Use nlohmann/json for JSON manipulation
* Use a job queue / background workers system to make expensive
  requests async (for example when creating a new post). Failed
  deliveries should be retried. And the number of retries as well as
  the time delay between retries are configurable parameters. The job
  queue is persisted in the database.
* When the user uploads an attachment, a SHA256 hash should be
  calculated. On the server, the attechment file will be renamed to
  the hash (lowercased hex) followed by the original extension name.
  The file will be stored in an attachment directory, and in a
  subdirectory whose name is the first character of the hash. For
  example, if the user uploads an image named “test.jpg”, and its hash
  is `a1b2c3`, it will be renamed to `a1b2c3.jpg`, and stored as a
  file at `<attachment_dir>/a/a1b2c3.jpg`. Duplicated uploads with
  reuse existing files in the server.
* Remote attachment will not be stored in the server. It is up to the
  frontend to download and display the attachment. There will be not
  media cache or proxy on the server.
* Use server-side rendering with the Inja template engine.
* Static asset will be served with the same C++ server.
* Server configuration will be loaded from a YAML file. Use [Rapid
  YAML](https://github.com/biojppm/rapidyaml) to parse YAML file. See
  https://github.com/MetroWind/shrt/blob/master/src/config.cpp for an
  example.
* Database schema will be versioned (integer, starting from 1). The
  schema version is stored with `PRAGMA user_version`.
* The server URL root will be configured in the YAML file. All URLs
  are “sub URLs” of the URL root. Examples of server URL root:
  * `https://f.mws.rocks/`
  * `https://mws.rocks/fedi/`
* URL pattern:
  * Users: `<url_root>/u/<username>`
  * Posts: `<url_root>/p/<id>`
  * inbox: `<url_root>/u/<username>/inbox`
  * outbox: `<url_root>/u/<username>/outbox`
  * followers: `<url_root>/u/<username>/followers`
  * following: `<url_root>/u/<username>/following`
* The Users and Posts URL will serve HTML to browser, and
  `application/activity+json` to other servers, based on the `Accept`
  header.
* For efficiency, delivering to a remote instance's sharedInbox is
  preferred over delivering to every individual follower on that
  instance.
* The server should expose a sharedInbox for incoming messages.
* Local posts and remote posts are in the same table. Local user IDs
  and local post IDs are just integer primary keys in the sqlite
  database with `AUTOINCREMENT`. The URI of the posts is also a column
  in the post table, which is indexed and unique.
* User sessions are stateful, with tokens persisted in the database.
* The HTML content from other servers should be sanitized.
* Searching for remote users will involve WebFinger lookup.
* The ActivityPub endpoints for outbox, followers, and following (and
  others if nessesary) should be paginated (`OrderedCollectionPage`).
* All state-changing forms (Login, Post, Follow, Like, etc.) must have
  CSRF (Cross-Site Request Forgery) protection
* When the user is viewing a thread, and if some of the posts are not
  in the database, they should be fetch from remote servers,
  recursively, with a limit. The limit should be a configurable
  parameter.
* Fetched remote posts will be saved in the database.
* Definition of visibilities:
   * Public: `to: [Public_Collection]`, `cc: [Followers]`
   * Unlisted: `to: [Followers]`, `cc: [Public_Collection]` (This effectively hides it from the global
     timeline on Mastodon but keeps it public accessible).
   * Followers-Only: `to: [Followers]`, `cc: []`
   * Direct: `to: [Mentioned_Users]`, `cc: []`
* JSON Normalization: Implement a dedicated parsing layer to handle
  ActivityPub polymorphism. This must transparently normalize fields
  such as addressing (to/cc) from either strings or arrays into lists,
  and ID references (e.g., actor, object, attributedTo) from either
  URI strings or embedded objects into canonical URIs, ensuring
  interoperability across different Fediverse implementations.
* All unit tests should be in the same executable.

## Future works (we don’t need these right now)

* For client API (C2S), we will go the pleroma route:
  mastodon-compatible API with extensions. See
  https://docs-develop.pleroma.social/backend/development/API/differences_in_mastoapi_responses/
* Moderation and server-blocking
* Full text search
* Notifications
* Database schema migration: Until the first stable release, the
  schema version will remain 1, so we don’t need to worry about
  migration for now.
