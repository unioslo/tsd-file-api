ARG PYTHON_VERSION=3
FROM docker.io/python:${PYTHON_VERSION}-alpine AS base

RUN apk --no-cache add \
    libmagic \
    libpq \
    libsodium \
    sudo


FROM docker.io/python:${PYTHON_VERSION}-alpine AS build

# install system build requirements
RUN apk --no-cache add \
    alpine-sdk \
    libffi-dev \
    postgresql-dev

# install Poetry
ARG POETRY_VERSION="1.3.2"
RUN pip install poetry==${POETRY_VERSION}
ARG POETRY_DYNAMIC_VERSIONING_VERSION="0.21.3"
RUN poetry self add "poetry-dynamic-versioning[plugin]==${POETRY_DYNAMIC_VERSIONING_VERSION}"
RUN poetry config virtualenvs.in-project true

# add source files for building
WORKDIR /src
COPY pyproject.toml poetry.lock ./
COPY scripts ./scripts/
COPY tsdfileapi ./tsdfileapi/
COPY .git ./.git/

# create venv
RUN python -m venv /app --upgrade-deps
RUN /app/bin/pip install wheel

# install dependencies
RUN poetry export -f requirements.txt -o requirements.txt
RUN /app/bin/pip install -r requirements.txt

# build and install the file API
RUN poetry build --no-interaction
RUN /app/bin/pip install dist/*.whl


FROM base AS run

COPY --from=build /app /app

EXPOSE 3003

ENTRYPOINT [ "/app/bin/tsd-file-api" ]