ARG PYTHON_VERSION=3
FROM docker.io/python:${PYTHON_VERSION}-slim AS base

RUN apt-get update && apt-get install -y \
    libmagic1 \
    libpq5 \
    libsodium23 \
    sudo \
    && rm -rf /var/lib/apt/lists/*


FROM docker.io/python:${PYTHON_VERSION} AS build

RUN apt-get install libpq-dev

# install Poetry
ARG POETRY_VERSION="2.1.3"
ARG POETRY_DYNAMIC_VERSIONING_VERSION="1.8.2"
ARG POETRY_EXPORT_PLUGIN_VERSION="1.9.0"
RUN pip install poetry==${POETRY_VERSION} \
    poetry-dynamic-versioning[plugin]==${POETRY_DYNAMIC_VERSIONING_VERSION} \
    poetry-plugin-export==${POETRY_EXPORT_PLUGIN_VERSION}
ARG POETRY_DYNAMIC_VERSIONING_COMMANDS="build"

# create venv
RUN python -m venv /app --upgrade-deps

# add project definition and lockfile
WORKDIR /src
COPY pyproject.toml poetry.lock ./

# install dependencies
RUN poetry export -f requirements.txt -o requirements.txt
RUN PIP_NO_BINARY=:all: /app/bin/pip install -r requirements.txt

# add rest of the source files for building
COPY scripts ./scripts/
COPY tsdfileapi ./tsdfileapi/
COPY .git ./.git/

# build and install the file API
RUN poetry build --no-interaction
RUN /app/bin/pip install dist/*.whl


FROM base AS run

EXPOSE 3003
ENV FORCE_COLOR=1

COPY --from=build /app /app

ENTRYPOINT [ "/app/bin/tsd-file-api" ]
