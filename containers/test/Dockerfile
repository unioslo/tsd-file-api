ARG PYTHON_VERSION=3
FROM docker.io/python:${PYTHON_VERSION}

RUN apt-get update
RUN apt-get install -y libsodium23 libmagic1 sudo
RUN pip install poetry==1.5.1
RUN poetry config virtualenvs.create false

RUN groupadd p11-member-group
RUN groupadd p12-member-group
RUN useradd p11-nobody --groups p11-member-group
RUN useradd p11-testing --groups p11-member-group

COPY containers/test/entrypoint.sh ./
ENTRYPOINT [ "/entrypoint.sh" ]

EXPOSE 3003
VOLUME [ "/file-api" ]
ENV FORCE_COLOR=1

WORKDIR /file-api

COPY pyproject.toml poetry.lock ./
RUN poetry install --no-interaction --no-root
