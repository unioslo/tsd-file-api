# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|

  config.vm.box = "centos/7"

  config.vm.provision "shell", inline: <<-SHELL
    sudo yum -y install emacs rpm-build git
    sudo yum -y install python-devel openssl openssl-devel postgresql-devel

    #sudo yum -y install scl-utils scl-utils-build centos-release-scl.noarch
    #sudo yum -y install rh-python36-python.x86_64 rh-python36-python-pip.noarch rh-python36-python-virtualenv.noarch

    #sudo echo '#!/bin/bash' | sudo tee --append /etc/profile.d/rh-python36.sh > /dev/null
    #sudo echo 'source scl_source enable rh-python36'| sudo tee --append /etc/profile.d/rh-python36.sh > /dev/null
    #sudo source /etc/profile.d/rh-python36.sh

    #pip3 install --upgrade pip
    #pip3 install virtualenv-tools3 ecdsa

    sudo yum -y install ruby-devel gcc make rpm-build rubygems
    sudo gem install --no-ri --no-rdoc fpm

    # sudo fpm --verbose -v 2.1 -s virtualenv -p /vagrant -t rpm --name tsd-file-api-venv --prefix /opt/tsd-file-api-venv/virtualenv /vagrant/requirements.txt
    # sudo fpm -s python -p /vagrant -t rpm /vagrant/setup.py
  SHELL

end
