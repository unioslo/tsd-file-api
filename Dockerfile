FROM centos:7 as base

ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8

# install required packages
RUN yum -y install epel-release
RUN yum -y install \
        autoconf           \
        automake           \
        gcc                \
        gcc-c++            \
        git                \
        libpqxx-devel      \
        libsodium          \
        libtool            \
        make               \
        man                \
        openssl            \
        openssl-devel      \
        postgresql-devel   \
        python3-devel      \
        python3-pip        \
        python3-setuptools \
        rpm-build          \
        ruby-devel         \
        rubygems           \
        sudo


##########################################################################################
FROM base as rpm

RUN pip3 install virtualenv virtualenv-tools3

# Workaround to get ruby2.3:
# ERROR:  Error installing fpm:
# 	ffi requires Ruby version >= 2.3.
RUN yum -y install centos-release-scl-rh centos-release-scl
RUN yum --enablerepo=centos-sclo-rh -y install rh-ruby23 rh-ruby23-ruby-devel
RUN source /opt/rh/rh-ruby23/enable && gem install --no-ri --no-rdoc fpm

# build rpms
WORKDIR /file-api
COPY requirements.txt ./
RUN mkdir -p dist

RUN source /opt/rh/rh-ruby23/enable && \
     fpm --verbose -s virtualenv -p /file-api/dist  \
     -t rpm --name tsd-file-api-venv --version 2.7  \
     --prefix /opt/tsd-file-api-venv/virtualenv requirements.txt
COPY . ./

RUN python3 setup.py bdist --format=rpm

##########################################################################################
FROM base as dev

ADD . /opt/tsd-file-api

# Install dependencies
RUN cd /opt/tsd-file-api && pip-3 install -r requirements.txt

RUN cd /opt/tsd-file-api && python3 setup.py develop

WORKDIR /opt

EXPOSE 3003

ENTRYPOINT ["python3", "/opt/tsd-file-api/tsdfileapi/api.py"]

##########################################################################################
FROM base as run

ADD . /opt/tsd-file-api

# Install dependencies
RUN cd /opt/tsd-file-api && pip-3 install -r requirements.txt

RUN cd /opt/tsd-file-api && \
    python3 setup.py install --prefix /usr/ --single-version-externally-managed --root=/

RUN    groupadd tsd \
    &&  useradd  -g tsd tsd

# RUN chown tsd:tsd $TSD_FILE_API_CONFIG

USER tsd

EXPOSE 3003

ENTRYPOINT python3 /usr//lib/python3.6/site-packages/tsdfileapi/api.py "$TSD_FILE_API_CONFIG"
