#!/bin/sh
set -eu

mkdir -p /opt/akkoma/priv/static/emoji/custom
base64 -d /opt/interop/interop_blob.png.b64 \
    > /opt/akkoma/priv/static/emoji/custom/interop_blob.png

exec /opt/akkoma/docker-entrypoint.sh
