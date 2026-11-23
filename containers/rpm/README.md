# RPM packaging

RPMs are built with `rpmbuild` from `tsdfileapi.spec`. `Containerfile` is a
toolchain image only: the spec and source tree are mounted at build time, so
the same builder image is reused across releases.

The package is a self-contained virtualenv under `/opt/tsd-file-api`. The venv
is created with `virtualenv` (matching the previous packaging layout) and does
not ship precompiled bytecode.

## Container build

```console
make rpm EL_VERSION=9
```

Build all supported EL versions:

```console
make rpm-all
```

The builder image tag is derived from the EL version, the Python package and a
hash of `Containerfile`. `make rpm` builds the image locally when it is
missing. To use an image that was already published elsewhere:

```console
make rpm EL_VERSION=9 \
  RPM_BUILDER_IMAGE=ghcr.io/unioslo/tsd-file-api-rpm-builder:el9-python3.12-<hash> \
  RPM_BUILDER_PULL=1
```

CI publishes builder images to GHCR and pulls them when the tag already exists.
`make rpm-builder-build` and `make rpm-builder-push` are available separately.

## Host-native build

On a RHEL/Rocky host with the toolchain installed:

```console
make rpm-local EL_VERSION=9
```

This requires `rpm-build`, a C toolchain, `libpq-devel`, `openssl-devel`,
`libffi-devel`, the target Python toolchain (`python3.12` on EL8/EL9,
`python3` on EL10), Poetry 2.5.1 with `poetry-plugin-export` and
`poetry-dynamic-versioning`, and `virtualenv==20.35.4`.

## Overridable variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `CONTAINER_ENGINE` | `podman` | Container engine (`podman` or `docker`) |
| `EL_VERSION` | `9` | Target RHEL/Rocky version |
| `BASE_IMAGE` | `docker.io/rockylinux/rockylinux` | Base image repository |
| `PYTHON_PKG` | `python3.12` (`python3` on EL10) | Python package and interpreter |
| `PLATFORM` | host architecture | Container platform |
| `SRC_DIR` | repository root | Source tree to build from |
| `OUT_DIR` | `dist/` | Where built RPMs are written |
| `SRC_MOUNT` | `/src` | Source path inside the builder container |
| `OUT_MOUNT` | `/out` | Output path inside the builder container |
| `CONTAINER_RPMBUILD_DIR` | `/root/rpmbuild` | rpmbuild topdir inside the container |
| `LOCAL_RPMBUILD_DIR` | `~/rpmbuild` | rpmbuild topdir for host builds |
| `RPM_VERSION` | Poetry/git version | Version written into the RPM |
| `RPM_SPEC` | `containers/rpm/tsdfileapi.spec` | Spec file to build |
| `RPM_BUILDER_IMAGE` | derived tag | Builder image to use |
| `RPM_BUILDER_PULL` | empty | Set to pull `RPM_BUILDER_IMAGE` first |
| `PIP_INDEX_URL` | empty | Optional Python package index for the build |

## Upgrade test

```console
make rpm-test-upgrade EL_VERSION=8 \
  OLD_RPM=/path/to/tsd-file-api-2.23.1-1.el8.x86_64.rpm \
  NEW_RPM=dist/tsd-file-api-2.24.0-1.el8.x86_64.rpm
```

The test installs the old RPM in a container, upgrades to the new one and
asserts that `psycopg` resolves, `psycopg_pool` imports, and no stale
`*.dist-info` directories remain.

## Migration cleanup

The spec runs a `%posttrans` that removes empty `*.dist-info`/`*.egg-info`
skeletons left behind by the old fpm-built RPMs, which owned files but not
directories. It only deletes empty directories at or below Python metadata
directories. Once all installations have moved past the fpm packages, this
block can be removed.
