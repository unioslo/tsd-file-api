# Installation

## Synopsis

Notes on installing `tsd-file-api` on various platforms.

## RHEL/CentOS 8

Besides

* git
* python3-dev

the following packages are required:

* postgresql-server
* libpq-dev
* libpq-devel.x86_64
* a NaCl-derivative, like `libsodium`
* optionally `sqlite-amalgamation` (see file `custom-sqlite-for-rhel7.md`)

## File access and privileges

The API attempts `chmod`/`chown` natively first. If the process is not
permitted to perform the operation, it falls back to `sudo` for compatibility
with older deployments. The fallback can therefore be avoided entirely by
granting the service process two Linux capabilities:

- `CAP_FOWNER` — change permissions on files owned by other users
- `CAP_CHOWN` — change file ownership

For a systemd service, this can be configured as:

```ini
[Service]
User=file-api
AmbientCapabilities=CAP_CHOWN CAP_FOWNER
CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER
```

For containers, the exact mechanism depends on the runtime and whether the
container runs as root. If it runs as a non-root user, the capabilities must
also be present in the process's ambient set. This can be done with a startup
wrapper such as `setpriv` from `util-linux`, for example:

```console
setpriv --reuid=file-api --regid=file-api --init-groups \
  --inh-caps=+chown,+fowner --ambient-caps=+chown,+fowner \
  -- /app/bin/tsd-file-api
```

To make the API fail instead of falling back to `sudo`, set
`sudo_fallback: false` in the configuration file. This is recommended when
the capabilities above are granted and `sudo` should not be used at all.

Verify the effective capabilities of a running process with:

```console
grep Cap /proc/<pid>/status
capsh --print
```
