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

# hack needed because brp-python-bytecompile has hardcoded path to Python
# used as part of bdist_rpm build below
RUN ln -s /opt/rh/rh-python38/root/usr/bin/python /usr/bin/python3.8

# install virtualenv with Python 3.8
RUN source /opt/rh/rh-python38/enable &&\
    pip3 install virtualenv virtualenv-tools3

# build rpms
WORKDIR /file-api
COPY requirements.txt ./
RUN mkdir -p dist

# build RPM of the dependencies virtual environment
RUN source /opt/rh/rh-ruby23/enable &&\
    source /opt/rh/rh-python38/enable &&\
    fpm --verbose -s virtualenv -p /file-api/dist\
    -t rpm --name tsd-file-api-venv --version 2.19\
    --prefix /opt/tsd-file-api-venv/virtualenv requirements.txt

COPY scripts ./scripts/
COPY tsdfileapi ./tsdfileapi/
COPY setup.py setup.cfg ./

RUN source /opt/rh/rh-python38/enable && \
    python setup.py bdist_rpm --no-autoreq
