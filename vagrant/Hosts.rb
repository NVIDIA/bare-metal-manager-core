class NGC
  attr_accessor :network, :netmask, :hosts

  def initialize(network, netmask, hosts)
    self.network = network
    self.netmask = netmask
    self.hosts = []
  end
    
end

# At the moment there is no difference between lbvirt and virtualbox hosts
module Host
  attr_accessor :name, :image, :ipv4, :ipv6, :efi, :shellcmds, :volumes, :provider

  def libvirt?
    self.provider == "libvirt"
  end

  def virtualbox?
    self.provider == "virtualbox":
  end

  def pxe_boot?
    self.image == nil || self.image = ""
  end
end

class VirtualBoxHost
  include Host

end

class LibvirtHost
  include Host
end

class Hosts
  require 'yaml'

  attr_accessor :hosts

  def initialize
    self.hosts = []
  end

  def self.load_yaml(data)
    hosts = Hosts.new

    cfg = YAML.load(data)
    ngc = NGC.new(cfg['ngc']['network'], cfg['ngc']['netmask'])

      cfg['ngc']['hosts'].each do |hostcfg|
        if hostcfg.virtualbox?
          host = LibvirtHost.new
        elsif hostcfg.libvirt?
          host = VirtualBoxHost.new
        else raise("should not happen")
        end

        host.name = hostcfg["name"]
        host.image = hostcfg["image"]
      end

      ngc.hosts << host
    end
  Hosts.hosts << host
end
