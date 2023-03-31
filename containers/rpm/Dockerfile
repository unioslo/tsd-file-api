ARG ROCKY_VERSION=8
FROM docker.io/rockylinux:${ROCKY_VERSION}

# Install required packages
RUN yum install -y epel-release
RUN yum install -y \
    gcc \
    git \
    libsodium \
    make \
    openssl \
    rpm-build \
    ruby \
    ruby-devel \
    sudo

# On >EL8 the default Python 3 distribution is new enough
RUN source /etc/os-release && \
    if [[ $PLATFORM_ID = "platform:el8" ]]; then \
        yum install -y \
            python39 \
            python39-devel ;\
    else \
        yum install -y \
            python3 \
            python3-devel ;\
    fi

# Install the fpm packaging utility
# https://fpm.readthedocs.io/en/latest/index.html
RUN gem install fpm

# Install virtualenv with Python 3
RUN python3 -m pip install virtualenv virtualenv-tools3

# Install poetry
ARG POETRY_VERSION=1.4.0
ARG POETRY_DYNAMIC_VERSIONING_VERSION="0.21.4"
RUN python3 -m venv /opt/poetry &&\
    source /opt/poetry/bin/activate &&\
    python -m pip install poetry==${POETRY_VERSION} &&\
    poetry self add "poetry-dynamic-versioning[plugin]==${POETRY_DYNAMIC_VERSIONING_VERSION}" &&\
    ln -s /opt/poetry/bin/poetry /usr/bin/poetry

# Get ready for building RPM
WORKDIR /file-api

COPY pyproject.toml poetry.lock ./
COPY scripts ./scripts/
COPY tsdfileapi ./tsdfileapi/
COPY .git ./.git/

# Export dependencies to requirements.txt for fpm
RUN poetry export --without-hashes --format requirements.txt --output requirements.txt

# Add tsd-file-api to requirements.txt for installation in venv RPM
RUN echo "." >> requirements.txt

# Build RPM of the dependencies virtual environment
RUN mkdir -p /file-api/rpm && \
    fpm --verbose \
        -s virtualenv \
        -p /file-api/rpm \
        -t rpm \
        --name tsd-file-api \
        --version $(poetry version --short --no-ansi) \
        --rpm-dist $(rpm --eval "%dist" | sed "s/\.//") \
        --prefix /opt/tsd-file-api \
        requirements.txt