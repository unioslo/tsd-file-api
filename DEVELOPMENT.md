# tsd-file-api development

## Setting up the development environment

```console
pip install poetry pre-commit
poetry self add "poetry-dynamic-versioning[plugin]"
git clone https://github.com/unioslo/tsd-file-api.git
cd tsd-file-api
poetry install
pre-commit install
```

## Running the file API for local testing

```console
poetry run tsd-file-api
```

## Running tests locally

While the file API is running on your machine, run this in a separate terminal:

```console
poetry run pytest tsdfileapi/test_file_api.py
```

## Alternative container based development setup

### Running the file API in a container for local testing

The repository provided `Makefile` can be used to run a local server to develop
against:

```console
make run
```

The container engine used to build and run this container defaults to [Podman].
If you wish to use [Docker] instead, you can set `CONTAINER_ENGINE=docker`:

```console
make run CONTAINER_ENGINE=docker
```

This container image will include all dependencies needed to run the file API,
except for the file API itself. The repository root gets mapped to `/file-api`
inside of the container when ran.

You can develop normally on your host system, and the [Tornado Web Server]
process inside of the container will pick up changes and reload when needed.

The test container only needs to be rebuilt when project dependencies change,
so even though a build is triggered with every `make run`, container layer
caching will speed past this step unless any actual work is needed.

### Running tests in the container

The repository provided `Makefile` can be used to run through the package's
included test set in the running container:

```console
make tests
```

As when running the API, set `CONTAINER_ENGINE=docker` if using Docker.

## Reference API client

Installing the API will also install the reference command-line client,
[tsd-api-client] (`tacl`).

You can use it with the dev instance as such:

```console
tacl p11 --env dev
```

See `tacl --help` for more usage notes.

[Podman]: https://podman.io/
[Docker]: https://www.docker.com/
[Tornado Web Server]: https://www.tornadoweb.org/en/stable/
[tsd-api-client]: https://github.com/unioslo/tsd-api-client
