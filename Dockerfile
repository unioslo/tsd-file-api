FROM centos:7

ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8

# install required packages
RUN yum -y install epel-release
RUN yum -y install python3-devel python3-pip python3-setuptools\
    postgresql-devel rpm-build man gcc-c++ \
    libpqxx-devel \
    sudo rpm-build git \
    openssl openssl-devel \
    ruby-devel gcc make rubygems \
    autoconf automake libtool
RUN pip3 install virtualenv virtualenv-tools3
RUN gem install --no-ri --no-rdoc fpm
# build rpms
WORKDIR /file-api
COPY requirements.txt ./
RUN mkdir -p dist
RUN fpm --verbose -s virtualenv -p /file-api/dist -t rpm --name tsd-file-api-venv --version 2.2 --prefix /opt/tsd-file-api-venv/virtualenv requirements.txt
COPY . ./
RUN python3 setup.py bdist --format=rpm
