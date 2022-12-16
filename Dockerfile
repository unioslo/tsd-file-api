FROM centos:7 as base

ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8

# Install required packages
RUN yum -y install epel-release
RUN yum -y install gcc\
                   git\
                   libsodium\
                   openssl\
                   python3-devel\
                   python3-pip\
                   sudo
RUN pip3 install pip --upgrade

##########################################################################################
FROM base as rpm

RUN yum -y install make\
                   rpm-build
# Workaround to get ruby2.3:
# ERROR:  Error installing fpm:
#       ffi requires Ruby version >= 2.3.
RUN yum -y install centos-release-scl-rh centos-release-scl
RUN yum --enablerepo=centos-sclo-rh -y install rh-ruby23 rh-ruby23-ruby-devel
RUN source /opt/rh/rh-ruby23/enable && gem install --no-ri --no-rdoc fpm

RUN pip3 install virtualenv virtualenv-tools3

# build rpms
WORKDIR /file-api
COPY requirements.txt ./
RUN mkdir -p dist

RUN source /opt/rh/rh-ruby23/enable &&\
    fpm --verbose -s virtualenv -p /file-api/dist\
    -t rpm --name tsd-file-api-venv --version 2.18\
    --prefix /opt/tsd-file-api-venv/virtualenv requirements.txt

COPY . ./

RUN python3 setup.py bdist --format=rpm
