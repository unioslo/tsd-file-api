# Container files

## Running the production containers

Container images are automatically published to
[this repository's GitHub Packages registry](https://github.com/unioslo/tsd-file-api/pkgs/container/tsd-file-api).

## Build notes

All these containers expect the repository root as their build context, i.e.
the positional parameter you pass when building with `podman`/`docker`.

An example (with `$PWD` being the parent directory to this one):

```console
podman build -f containers/Dockerfile.alpine .
```

Another example (passing the repository URL as context):

```console
podman build -f containers/Dockerfile.alpine https://github.com/unioslo/tsd-file-api.git
```

## Container overview

### `Dockerfile`

Production ready service container using that is using
[`docker.io/python:3-slim`](https://hub.docker.com/_/python) as its base image.

### `Dockerfile.alpine`

Production ready service container using that is using
[`docker.io/python:3-alpine`](https://hub.docker.com/_/python) as its base
image.

### `Dockerfile.rpm`

Builds an RPM of this package and all its (Python) dependencies on CentOS 7,
for deployment in RHEL7-like environments.

### `Dockerfile.test`

Installs the package and all its dependencies (including development
dependencies). Intended for use in running the package's test suite.
