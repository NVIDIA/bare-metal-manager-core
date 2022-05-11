#!/usr/bin/env python3
from dc_parameters import *
from netaddr import *

class Tenant(object):

    
    def __init__(self):
        pass
    
    ##This function is getting ip addresses. It's taking aggregate subnet
    ##Split it to subnet.
    ##It's returning back ip address. 
    def getIPAddress( index, subnet,number):
        npu_ip_aggr_sub = IPNetwork(subnet)
        npu_ip_addresses = list(npu_ip_aggr_sub.subnet(31))
        ip_addresses = list(npu_ip_addresses[number - 1])
        return str(ip_addresses[index])

    ###This function is initializing all parameters for tenant
    ###It's taking number from tenant and autogenerate
    ##all relevant information. 
    def initialize(self, name):
        self.name = name
        self.vdom = name
        self.number = int(name[len(TENANT_PREFIX)+len(TENANT_DELIMITER):])
        self.npu_vlan = int(TENANT_NPU_VLAN_START) + int(self.number)
        self.firewall_fabric_vlan = int(TENANT_FIREWALL_FABRIC_VLAN_START) + int(self.number)
        self.fabric_vlan = int(TENANT_FABRIC_VLAN_START) + int(self.number)
        #Generation of the subnets from summary ip address (supernet)
        #They will be used for npu link
        # need to change names to tenant_sub
        self.npu_address_tenant_ip = Tenant.getIPAddress(TENANT_SUBNET_INDEX, NPU_IP_SUBNET, self.number) 
        self.npu_address_root_ip = Tenant.getIPAddress(ROOT_SUBNET_INDEX, NPU_IP_SUBNET, self.number)
        self.npu_address_tenant = Tenant.getIPAddress(TENANT_SUBNET_INDEX, NPU_IP_SUBNET, self.number) + "/31" 
        self.npu_address_root   = Tenant.getIPAddress(ROOT_SUBNET_INDEX, NPU_IP_SUBNET, self.number) + "/31"
        #####Get ip addresses for the firewal link to fabric
        self.tenant_fabric_ip_address = Tenant.getIPAddress(ROOT_SUBNET_INDEX, FIREWAL_IP_SUBNET, self.number) + "/31"
        self.tenant_fabric_ip_address_no_sub = Tenant.getIPAddress(ROOT_SUBNET_INDEX, FIREWAL_IP_SUBNET, self.number)
        self.fabric_ip_address = Tenant.getIPAddress(FABRIC_SUBNET_INDEX, FIREWAL_IP_SUBNET, self.number) 
        ####Interface name to fabric####
        self.int_name_to_fabric = self.name +  str(self.firewall_fabric_vlan)
        self.int_name_to_npu = "to_" + self.name 
        self.int_name_from_npu = "out_" + self.name
        ###defining vpc###
        self.vpc =  []
        self.vip =  []

    def addVPC(self, inVPC):
        vpc = { "name": inVPC["name"],
                 "type": inVPC["type"], 
                 "public_start": inVPC["public_start"], 
                 "public_end": inVPC["public_end"], 
                 "public_subnet" : inVPC["public_subnet"],
                 "private_subnet" : inVPC["private_subnet"],
                 "private_start" : inVPC["private_start"],
                 "private_end" : inVPC["private_end"],
                 "poolname" : IP_POOL_NAME_PREFIX + inVPC["name"],
                 "poolrouteseq": "", 
                 "vpcrouteseq" : "" ,
                 "rootpolicyid" : "", 
                 "tenantpolicyid" : "" } 
        self.vpc.append(vpc)
   
    def createVIP(self, vip):
        self.vip =  vip
    
    def getVPCIndex(self, name):
        index = 0
        for vpc in self.vpc:
            if vpc["name"] == name:
                return index
        return -1

