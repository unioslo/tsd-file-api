ARG PYTHON_VERSION=3
FROM docker.io/python:${PYTHON_VERSION}

RUN apt-get update
RUN apt-get install -y libsodium23 libmagic1 sudo
RUN pip install poetry
RUN poetry config virtualenvs.create false

RUN groupadd p11-member-group
RUN groupadd p12-member-group

COPY containers/test/entrypoint.sh ./
ENTRYPOINT [ "/entrypoint.sh" ]

EXPOSE 3003
VOLUME [ "/file-api" ]

WORKDIR /file-api

COPY pyproject.toml poetry.lock ./
RUN poetry install --no-interaction
