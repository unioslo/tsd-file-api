#!/bin/sh
# Remove stale Python metadata directories left behind when an upgrade changes
# a distribution's version, and therefore the name of its *.dist-info
# directory. fpm only packages leaf files, so the old directory is left empty;
# importlib.metadata then resolves distributions such as psycopg to that empty
# directory and reports a None version.

[ -d /opt/tsd-file-api ] || exit 0

find /opt/tsd-file-api -type d \( -name '*.dist-info' -o -name '*.egg-info' \) -empty -delete 2>/dev/null || true
