#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
TLS_DIR="$SCRIPT_DIR/.artifacts/mastodon"

compose()
{
    docker compose -f "$SCRIPT_DIR/docker-compose.mastodon.yml" "$@"
}

up()
{
    mkdir -p "$TLS_DIR"
    if [ ! -f "$TLS_DIR/tls.key" ] ||
        ! openssl x509 -in "$TLS_DIR/tls.crt" -checkend 86400 -noout \
            >/dev/null 2>&1; then
        openssl req -x509 -newkey rsa:2048 -noenc -days 30 \
            -subj /CN=unspoken.test -addext subjectAltName=DNS:unspoken.test \
            -keyout "$TLS_DIR/tls.key" -out "$TLS_DIR/tls.crt"
    fi
    if [ ! -f "$REPO_ROOT/build/CMakeCache.txt" ]; then
        cmake -S "$REPO_ROOT" -B "$REPO_ROOT/build"
    fi
    cmake --build "$REPO_ROOT/build" --target unspoken fake_oidc -j24
    compose --profile test build unspoken fake-oidc photo-runner
    compose up -d --wait postgres redis fake-oidc unspoken-tls
    compose run --rm -T --no-deps mastodon bundle exec rails db:prepare
    compose up -d --wait mastodon
}

test_photo()
{
    post_uri=$(compose run --rm -T --no-deps photo-runner publish)
    echo "Published $post_uri"
    if ! import_result=$(compose exec -T -e POST_URI="$post_uri" \
        -e RAILS_LOG_LEVEL=debug mastodon \
        bundle exec rails runner '
        uri = ENV.fetch("POST_URI")
        status = ActivityPub::FetchRemoteStatusService.new.call(uri)
        abort "Mastodon failed to import #{uri}" unless status
        puts "INTEROP_STATUS_ID=#{status.id}"
    '); then
        printf '%s\n' "$import_result" >&2
        return 1
    fi
    status_id=$(printf '%s\n' "$import_result" |
        sed -n 's/^INTEROP_STATUS_ID=\([0-9][0-9]*\)$/\1/p')
    if [ -z "$status_id" ]; then
        printf '%s\n' "$import_result" >&2
        return 1
    fi
    if ! compose run --rm -T --no-deps photo-runner \
        verify "$status_id" "$post_uri"; then
        printf '%s\n' "$import_result" |
            sed -n '/Error fetching remote file/p' >&2
        return 1
    fi
}

case "${1:-}" in
    up) up ;;
    test) test_photo ;;
    all)
        up
        test_photo
        ;;
    logs) compose logs --tail=200 ;;
    down) compose down ;;
    *)
        echo "Usage: $0 up|test|all|logs|down" >&2
        exit 2
        ;;
esac
