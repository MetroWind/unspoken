#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.akkoma.yml"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"

compose()
{
    if docker compose version >/dev/null 2>&1; then
        docker compose -f "$COMPOSE_FILE" "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose -f "$COMPOSE_FILE" "$@"
    else
        echo "Docker Compose is required for interop tests." >&2
        exit 127
    fi
}

build_cmake()
{
    cmake -S "$REPO_ROOT" -B "$BUILD_DIR"
    cmake --build "$BUILD_DIR" --target unspoken fake_oidc -j
}

print_logs()
{
    compose logs --tail=200 postgres akkoma fake-oidc unspoken
}

cmd="${1:-}"
case "$cmd" in
    build)
        build_cmake
        compose build akkoma unspoken fake-oidc interop-runner
        ;;
    up)
        build_cmake
        compose up -d --build postgres akkoma fake-oidc unspoken
        ;;
    test)
        if ! compose run --rm interop-runner; then
            print_logs
            exit 1
        fi
        ;;
    down)
        compose down
        ;;
    reset)
        compose down -v --remove-orphans
        rm -rf "$SCRIPT_DIR/.artifacts"
        mkdir -p "$SCRIPT_DIR/.artifacts"
        ;;
    logs)
        print_logs
        ;;
    all)
        cleanup=0
        if [ "${2:-}" = "--cleanup" ]; then
            cleanup=1
        fi
        "$0" reset
        "$0" up
        if "$0" test; then
            if [ "$cleanup" -eq 1 ]; then
                "$0" down
            fi
        else
            exit 1
        fi
        ;;
    *)
        cat >&2 <<EOF
Usage: $0 build|up|test|down|reset|logs|all [--cleanup]
EOF
        exit 2
        ;;
esac
