# ActPub Microblog Server

A lightweight, high-performance ActivityPub microblogging server written in C++23.

## Features

- **ActivityPub Federation**: Compatible with Mastodon, Pleroma, and other Fediverse software.
- **Web Interface**: Clean, responsive UI for posting, reading, and interacting.
- **Microblogging**: Posts, replies, boosts, likes, and mentions.
- **Markdown Support**: Rich text formatting using Markdown.
- **Security**: HTTP Signatures, OpenID Connect authentication, CSRF protection, HTML sanitization.
- **Performance**: Built with C++23, uses SQLite with WAL mode.

## Prerequisites

- CMake 3.24+
- C++23 compatible compiler (GCC 13+, Clang 16+)
- OpenSSL
- SQLite3

## Build

```bash
mkdir build
cd build
cmake ..
make
```

## Configuration

Copy `config.yaml.example` to `config.yaml` and edit it:

```bash
cp config.yaml.example config.yaml
nano config.yaml
```

Make sure to set `oidc_issuer_url`, `oidc_client_id`, and `oidc_secret` to valid values from your OpenID Connect provider (e.g., Keycloak).

## Run

```bash
./build/actpub
```

The server will start on the configured port (default 8080).

## Testing

To run unit tests:

```bash
./build/unit_tests
```

## License

MIT
