# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
#  config.vm.box_check_update = false

  config.vm.define :relay do |relay|
    relay.vm.box = "debian/bullseye64"
    relay.vm.hostname = "relay"

    relay.vm.network "public_network", bridge: "enp47s0f0"
    relay.vm.network :private_network, ip: "192.168.0.1", virtualbox__intnet: true

    relay.vm.provider :virtualbox do |vb, config|
      # TODO - make EFI work
      vb.customize ['modifyvm', :id, '--boot1', 'disk']
    end
  end

# TODO: empty booting client
  config.vm.define :client, autostart: false do |client|
    client.vm.box = 'sridhav/empty'
    client.vm.box_version = "1.0"
    client.vm.hostname = "pxe-client"

    client.vm.network :private_network, type: 'dhcp', virtualbox__intnet: true

    client.vm.provider :virtualbox do |vb, config|
      # make sure this vm has enough memory to load the root fs into memory.
      vb.memory = 2048

      # let vagrant known that the guest does not have the guest additions nor a functional vboxsf or shared folders.
      vb.check_guest_additions = false
      vb.functional_vboxsf = false
      config.vm.synced_folder '.', '/vagrant', disabled: true

      # configure for PXE boot.
      vb.customize ["modifyvm", :id, "--firmware", "bios"]
      vb.customize ['modifyvm', :id, '--boot1', 'net']
      vb.customize ['modifyvm', :id, '--boot2', 'none']
      vb.customize ['modifyvm', :id, '--biospxedebug', 'on']
      vb.customize ['modifyvm', :id, '--cableconnected2', 'on']
      vb.customize ['modifyvm', :id, '--nicbootprio2', '1']
      vb.customize ['modifyvm', :id, "--nictype2", '82540EM'] # Must be an Intel card (as-of VB 5.1 we cannot Intel PXE boot from a virtio-net card).
    end
  end
end
