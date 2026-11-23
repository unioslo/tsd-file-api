#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 OLD_RPM NEW_RPM" >&2
    exit 2
fi

old_rpm=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
new_rpm=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")

engine=${CONTAINER_ENGINE:-podman}
el_version=${EL_VERSION:-8}
base_image=${BASE_IMAGE:-docker.io/rockylinux/rockylinux}
platform=${PLATFORM:-}
if [ -n "${PYTHON_PKG:-}" ]; then
    python_pkg=$PYTHON_PKG
elif [ "$el_version" = "10" ]; then
    python_pkg=python3
else
    python_pkg=python3.12
fi

exec "$engine" run --rm \
    ${platform:+--platform "$platform"} \
    --volume "$old_rpm":/tmp/old.rpm:ro \
    --volume "$new_rpm":/tmp/new.rpm:ro \
    --env TEST_PYTHON_PKG="$python_pkg" \
    "$base_image:$el_version" sh -c '
set -eu

dnf install -y epel-release >/dev/null 2>&1 || true
dnf install -y "$TEST_PYTHON_PKG" libsodium sudo findutils libpq file-libs >/dev/null 2>&1

rpm -i /tmp/old.rpm
old_psycopg=$(/opt/tsd-file-api/bin/python -c "from importlib import metadata; print(metadata.version(\"psycopg\"))")
/opt/tsd-file-api/bin/python -c "import psycopg_pool"

rpm -Uvh /tmp/new.rpm
new_psycopg=$(/opt/tsd-file-api/bin/python -c "from importlib import metadata; print(metadata.version(\"psycopg\"))")
/opt/tsd-file-api/bin/python -c "import psycopg, psycopg_pool"

stale=$(find /opt/tsd-file-api -type d -name "*.dist-info" \
    -exec sh -c "test -e \"\$1/METADATA\" || echo \"\$1\"" sh {} \; | wc -l)
if [ "$stale" -ne 0 ]; then
    echo "stale metadata directories remain after upgrade:" >&2
    find /opt/tsd-file-api -type d -name "*.dist-info" \
        -exec sh -c "test -e \"\$1/METADATA\" || echo \"\$1\"" sh {} \; >&2
    exit 1
fi

echo "OK: psycopg ${old_psycopg} -> ${new_psycopg}; psycopg_pool imports cleanly"
'
