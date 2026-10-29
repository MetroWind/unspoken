# Unspoken

An ActivityPub server. See the [operator guide](docs/operator.md) for
configuration and deployment instructions.

## Build dependencies

Building requires CMake, a C++23 compiler, Python 3, libxml2 2.14 or newer
(with development headers), and the libraries required by libmw.

## ActivityPub library

Unspoken uses the embedded [ActivityPub library](lib/actpub/README.md) for
federation. See the [operator guide](docs/operator.md#federation-library-migration)
for the SQLite migration and backup procedure.

## SVG uploads

Uploaded SVG attachments are served inline from the application's origin
without sanitization. Opening an SVG attachment directly can execute its
scripts in the visitor's browser with the application's origin. Those
scripts can read authenticated pages and perform actions as the visitor,
even though session cookies are HttpOnly. SVGs embedded through an `img`
element generally have scripting disabled; opening the attachment itself
is the relevant risk.

Only allow uploads from users you trust to serve active content on the
application's origin. SVG sanitization and media origin isolation are not
currently implemented.
