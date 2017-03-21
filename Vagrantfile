# -*- mode: ruby -*-
# vi: set ft=ruby :

# The "2" in Vagrant.configure
# configures the configuration version
Vagrant.configure(2) do |config|

  # Complete reference
  # https://docs.vagrantup.com.

  # More boxes at https://atlas.hashicorp.com/search.
  config.vm.box = "puppetlabs/centos-7.0-64-puppet"

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine. In the example below,
  # accessing "localhost:8080" will access port 80 on the guest machine.
  # config.vm.network "forwarded_port", guest: 80, host: 8080

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  # config.vm.network "private_network", ip: "192.168.33.10"

  # Create a public network, which generally matched to bridged network.
  # Bridged networks make the machine appear as another physical device on
  # your network.
  # config.vm.network "public_network"

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  # config.vm.synced_folder "../data", "/vagrant_data"

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:
  #
  # config.vm.provider "virtualbox" do |vb|
  #   # Display the VirtualBox GUI when booting the machine
  #   vb.gui = true
  #
  #   # Customize the amount of memory on the VM:
  #   vb.memory = "1024"
  # end
  #

  # Build the rpm
  # rpm -Uvh <name>.rpm to install
  # rom -e <name> to remove
  config.vm.provision "shell", inline: <<-SHELL
    sudo yum -y install python-devel rpm-build git
    sudo easy_install pip
    git clone https://github.com/leondutoit/virtualenv
    sudo pip install ./virtualenv
    git clone https://github.com/leondutoit/rpmvenv
    sudo pip install ./rpmvenv
    sudo rm /vagrant/tsd-file-api-0.1.0-1.x86_64.rpm
    sudo rpmvenv --verbose /vagrant/config.json --destination /vagrant
    sudo rpm -e tsd-file-api-0.1.0-1.x86_64
    rpm -Uvh /vagrant/tsd-file-api-0.1.0-1.x86_64.rpm
  SHELL

end
