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

EXPOSE 3003
ENV FORCE_COLOR=1

COPY --from=build /app /app

ENTRYPOINT [ "/app/bin/tsd-file-api" ]
