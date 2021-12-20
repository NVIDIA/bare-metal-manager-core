# Tenant.
#
# A Tenant contains all hosts and networks which use a specific vagrant provider.
#
# @example
#
# t = Tenant.new('ngc', 'libvirt', '192.l68.0.0', '24')
#
# @param [String] name What is the name of this tenant
# @param [String] provider What vagrant provider does this tenant utilize
# @param [String] network What network should be created for this tenant to use
# @param [String] netmask What is the netmask of @param network

class Tenant
  attr_accessor :name, :network, :netmask, :hosts, :provider

  def initialize(name, provider, network, netmask)
    self.name = name
    self.provider = provider
    self.network = network
    self.netmask = netmask
    self.hosts = []
  end

  def libvirt?
    self.provider == "libvirt"
  end

  def virtualbox?
    self.provider == "virtualbox"
  end

    
end

# Host.
#
# Used to model components which are common to all vagrant providers
#
# @example
# TODO
#
#
module Host
  attr_accessor :name, :image, :cpu_count, :ipv4, :ipv6, :shellcmds, :memory, :volumes, :userdata


  def ipv4?
    self.ipv4 != nil
  end

  def ipv6?
    self.ipv6 != nil
  end

  def dhcp?
    self.ipv4 == nil && self.ipv6 == nil
  end

  def pxe_boot?
    self.image == nil || self.image = ""
  end

  def is_relay?
    self.name != nil && self.name.start_with?("relay")
  end

  def is_client?
    self.name != nil && self.name.start_with?("client")
  end

  def userdata?
    self.userdata != nil && self.userdata != ""
  end

end

# VirtualBoxHost
#
# Virtualbox specific host settings
class VirtualBoxHost
  include Host
  DEFAULT_IMAGE = "ubuntu/impish64"

end


# LibvirtHost
#
# Libvirt specific host settings
class LibvirtHost
  include Host

  DEFAULT_IMAGE = "ubuntu/empty"

end

# Carburize
#
# Carburize handles loading the yaml data from carburize.yaml which describes
# the layout of each Tenant. 
#
# After the yaml has been loaded, host objects are instantiated and appended 
# to the hosts array specific to each tenant.  Each tenant is then appended to
# the carburize tenants array.
#
# This data consumed in the Vagrantfile which handles actual provisioning of 
# host and network resources
#
# @example
# TODO
#
class Carburize
  require 'yaml'

  attr_accessor :tenants

  def initialize
    self.tenants = []
  end

  def self.load_yaml(data)
    carburize = Carburize.new

    tenants = YAML.load(data)
    tenants.each do |t, tcfg|
        tenant = Tenant.new(t, tcfg['provider'], tcfg['network'], tcfg['netmask'])

        tcfg['hosts'].each do |hostcfg|

          #host.name = hostcfg['name']

          if tenant.virtualbox?
            host = VirtualBoxHost.new
          elsif tenant.libvirt?
            host = LibvirtHost.new
          else
            # default to virtualbox
            # todo - once libvirt is complete remove
            host = VirtualBoxHost.new
          end

          host.name = hostcfg["name"]
          host.image = hostcfg['image']

          if hostcfg['userdata']
            host.userdata = hostcfg['userdata']
          end
         
          unless hostcfg['memory']
            host.memory = 512
          end

          unless hostcfg['cpu_count']
            host.cpu_count = 1
          end

          if hostcfg['ipv4']
            host.ipv4 == hostcfg['ipv4']
          else
            host.ipv4 == "dhcp"
          end

          if hostcfg['ipv6']
            # Todo get ipv6 working
            return
          end

          tenant.hosts << host
        end
      carburize.tenants << tenant
      end
      carburize
    end
  end
