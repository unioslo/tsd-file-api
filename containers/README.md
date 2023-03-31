# Container files

## Running the production containers

Container images are automatically published to
[this repository's GitHub Packages registry](https://github.com/unioslo/tsd-file-api/pkgs/container/tsd-file-api).

## Build notes

All these containers expect the repository root as their build context, i.e.
the positional parameter you pass when building with `podman`/`docker`.

An example (with `$PWD` being the parent directory to this one):

```console
podman build -f containers/alpine/Dockerfile .
```

Another example (passing the repository URL as context):

```console
podman build -f containers/alpine/Dockerfile https://github.com/unioslo/tsd-file-api.git
```

## Container overview

### `Dockerfile`

Production ready service container using that is using
[`docker.io/python:3-slim`](https://hub.docker.com/_/python) as its base image.

### `alpine/Dockerfile`

Production ready service container using that is using
[`docker.io/python:3-alpine`](https://hub.docker.com/_/python) as its base
image.

### `rpm-el7/Dockerfile`

Builds an RPM of this package and all its (Python) dependencies on CentOS 7,
for deployment in RHEL7-like environments.

### `rpm/Dockerfile`

Builds an RPM of this package and all its (Python) dependencies on Rocky Linux
(default: 8), for deployment in RHEL-like environments.

### `test/Dockerfile`

Installs all of the package's dependencies, including development dependencies,
except for the tsdfileapi package itself (before runtime). Intended for use in
running the package's test suite and [local development](../DEVELOPMENT.md#alternative-container-based-development-setup).
