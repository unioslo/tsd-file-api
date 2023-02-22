
# tsd-file-api

A REST API for upload and download of files and JSON data.

## Running the service

We offer container images that can be used to deploy this service.

Example invocation with Docker:

```console
docker run -v /path/to/tsd-file-api-config.yaml:/config.yaml:ro ghcr.io/unioslo/tsd-file-api /config.yaml
```

This would map a configuration file from the path `/path/to/config.yaml` on your
host system to `/config.yaml` in the container, and pass it as a runtime
argument to the package's `tsd-file-api` entrypoint that starts the API service.

To see what tags are available, please refer to the repository's
[GitHub Packages registry]((https://github.com/unioslo/tsd-file-api/pkgs/container/tsd-file-api)).

For more information about the containers available in this repository, please
see the [containers README](containers/README.md) document.

## Development

Please see the [DEVELOPMENT](DEVELOPMENT.md) document for details on how to get
started with development of this software.
