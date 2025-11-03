ARG ROCKY_VERSION=8
FROM docker.io/rockylinux/rockylinux:${ROCKY_VERSION}

# Install required packages
RUN yum install -y epel-release
RUN yum install -y \
    gcc \
    git \
    libpq-devel \
    libsodium \
    make \
    openssl \
    rpm-build \
    ruby \
    ruby-devel \
    sudo

RUN touch /build-env /build-options
RUN echo "--depends libsodium --depends sudo " >> /build-options

# On >=EL10 the default Python 3 distribution is new enough
RUN source /etc/os-release && \
    if [[ $PLATFORM_ID == "platform:el8" || $PLATFORM_ID == "platform:el9" ]]; then \
        yum install -y \
            python3.12 \
            python3.12-pip \
            python3.12-devel && \
            alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 99 && \
            echo "--depends python3.12 " >> /build-options && \
            echo "export VIRTUALENV_PYTHON=/usr/bin/python3.12" >> /build-env ;\
    else \
        yum install -y \
            python3 \
            python3-devel && \
            echo "--depends python3 " >> /build-options ;\
    fi

# Install the fpm packaging utility
# https://fpm.readthedocs.io/en/latest/index.html
COPY containers/rpm/Gemfile* ./
RUN source /etc/os-release && \
    if [[ $PLATFORM_ID == "platform:el8" || $PLATFORM_ID == "platform:el9" ]]; then \
        mv Gemfile.lock.1.17.2 Gemfile.lock && \
        gem install bundler -v 1.17.2 ;\
    else \
        gem install bundler ;\
    fi
RUN bundle install --system

# Install virtualenv with Python 3
RUN python3 -m pip install virtualenv virtualenv-tools3

# Install poetry
RUN python3 -m venv /opt/poetry &&\
    source /opt/poetry/bin/activate &&\
    python -m pip install "poetry>=2.2,<3" "poetry-plugin-export>=1,<2" &&\
    poetry self add "poetry-dynamic-versioning[plugin]>=1,<2" &&\
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
    source /build-env && \
    fpm --verbose \
        -s virtualenv \
        -p /file-api/rpm \
        -t rpm \
        --name tsd-file-api \
        --version $(poetry version --short --no-ansi) \
        --rpm-dist $(rpm --eval "%dist" | sed "s/\.//") \
        --prefix /opt/tsd-file-api \
        $(cat /build-options) \
        requirements.txt
