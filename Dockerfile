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

RUN yum -y install make\
                   rpm-build\
                   rpmrebuild
# Workaround to get ruby2.3:
# ERROR:  Error installing fpm:
#       ffi requires Ruby version >= 2.3.
RUN yum -y install centos-release-scl-rh centos-release-scl
RUN yum --enablerepo=centos-sclo-rh -y install rh-ruby23 rh-ruby23-ruby-devel
RUN source /opt/rh/rh-ruby23/enable && gem install --no-ri --no-rdoc fpm

# install Python 3.8 from SCL
RUN yum install -y rh-python38 rh-python38-python-devel

# install virtualenv with Python 3.8
RUN source /opt/rh/rh-python38/enable &&\
    pip3 install virtualenv virtualenv-tools3

# build rpms
WORKDIR /file-api
RUN mkdir -p dist

COPY requirements.txt ./
COPY scripts ./scripts/
COPY tsdfileapi ./tsdfileapi/
COPY setup.py setup.cfg ./

# get package version for use in RPM creation
RUN source /opt/rh/rh-python38/enable && \
    python -c 'from tsdfileapi import __version__; print(__version__)' > ./VERSION

# add tsd-file-api to requirements.txt for installation in venv RPM
RUN echo "." >> requirements.txt

# build RPM of the dependencies virtual environment
RUN source /opt/rh/rh-ruby23/enable &&\
    source /opt/rh/rh-python38/enable &&\
    fpm --verbose -s virtualenv -p /file-api/dist\
    -t rpm --name tsd-file-api-venv --version $(cat VERSION)\
    --prefix /opt/tsd-file-api-venv/virtualenv requirements.txt
