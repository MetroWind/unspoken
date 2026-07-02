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

retry_post_uri()
{
    retry_artifact post_uri
}

retry_job_id()
{
    retry_artifact retried_job_id
}

retry_artifact()
{
    RESULT_FILE="$SCRIPT_DIR/.artifacts/retry_prepare.json" \
        FIELD="$1" python3 - <<'PY'
import json
import os
with open(os.environ["RESULT_FILE"], encoding="utf-8") as f:
    result = json.load(f)
print(result["tests"][-1]["objects"][os.environ["FIELD"]])
PY
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
        compose build interop-runner
        if ! compose run --rm interop-runner; then
            print_logs
            exit 1
        fi
        compose stop akkoma
        if ! compose run --no-deps --rm \
            -e INTEROP_ONLY=retry_prepare \
            -e RESULTS_PATH=/artifacts/retry_prepare.json \
            interop-runner; then
            compose start akkoma
            print_logs
            exit 1
        fi
        post_uri=$(retry_post_uri)
        retry_job=$(retry_job_id)
        compose start akkoma
        if ! compose run --no-deps --rm \
            -e INTEROP_ONLY=retry_recover \
            -e RETRY_POST_URI="$post_uri" \
            -e RETRY_JOB_ID="$retry_job" \
            -e RESULTS_PATH=/artifacts/retry_recover.json \
            interop-runner; then
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
