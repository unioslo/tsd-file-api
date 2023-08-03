FROM docker.io/centos:7 as base

ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8

# Install required packages
RUN yum -y install epel-release
RUN yum -y install gcc\
                   git\
                   libsodium\
                   openssl\
                   sudo

##########################################################################################
FROM base as rpm

RUN yum -y install \
    make \
    rpm-build
# Workaround to get ruby2.3:
# ERROR:  Error installing fpm:
#       ffi requires Ruby version >= 2.3.
RUN yum -y install centos-release-scl-rh centos-release-scl
RUN yum --enablerepo=centos-sclo-rh -y install rh-ruby30 rh-ruby30-ruby-devel
RUN source /opt/rh/rh-ruby30/enable && \
    gem install --no-document fpm --version 1.15.1

# install Python 3.8 from SCL
RUN yum install -y rh-python38 rh-python38-python-devel

# install virtualenv with Python 3.8
RUN source /opt/rh/rh-python38/enable &&\
    pip3 install virtualenv virtualenv-tools3

# install poetry
ARG POETRY_VERSION=1.3.2
ARG POETRY_DYNAMIC_VERSIONING_VERSION="0.21.3"
RUN source /opt/rh/rh-python38/enable &&\
    python -m venv /opt/poetry &&\
    source /opt/poetry/bin/activate &&\
    python -m pip install poetry==${POETRY_VERSION} &&\
    poetry self add "poetry-dynamic-versioning[plugin]==${POETRY_DYNAMIC_VERSIONING_VERSION}" &&\
    ln -s /opt/poetry/bin/poetry /usr/bin/poetry

# build rpms
WORKDIR /file-api

COPY pyproject.toml poetry.lock ./
COPY scripts ./scripts/
COPY tsdfileapi ./tsdfileapi/
COPY .git ./.git/

# export dependencies to requirements.txt for fpm
RUN poetry export --without-hashes --format requirements.txt --output requirements.txt

# add tsd-file-api to requirements.txt for installation in venv RPM
RUN echo "." >> requirements.txt

# build RPM of the dependencies virtual environment
RUN source /opt/rh/rh-ruby30/enable &&\
    source /opt/rh/rh-python38/enable &&\
    mkdir -p /file-api/rpm && \
    fpm --verbose -s virtualenv -p /file-api/rpm \
    -t rpm --name tsd-file-api --version $(poetry version --short --no-ansi) \
    --rpm-dist $(rpm --eval "%dist" | sed "s/\.//") \
    --depends libsodium --depends sudo \
    --prefix /opt/tsd-file-api requirements.txt
