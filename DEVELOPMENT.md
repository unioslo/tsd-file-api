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
poetry run python tsdfileapi/test_file_api.py
```

## Reference API client

Installing the API will install the reference command-line client,
[tacl](https://github.com/unioslo/tsd-api-client).

You can use it with the dev instance as such:

```console
tacl p11 --env dev
```

See `tacl --help` for more usage notes.
