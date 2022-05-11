#!/usr/bin/env python3
import argparse
import paramiko
import json
import requests
import time
import urllib3 # disable security warning for SSL certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # disable security warning for SSL certificate
import filecmp
import time
import difflib
from netaddr import *
from credentials import * 
from dc_parameters import *
from cumulus import *
from tenant import *
from oam_ip_addresses import *
from concurrent.futures import ThreadPoolExecutor
from fortigate import *
DEBUG = False 
from devices import *

def createAddress(vdom):
    uri = f'https://{ipaddr}/api/v2/cmdb/firewall/address'
    params= {'vdom': vdom}
    data={'name': "address1",
      'subnet': "1.1.1.0 255.255.255.0"}
    sendCreateCommand(uri, data, params) 


def deleteVPC(firewall, tenant, vpcName):
    index = tenant.getVPCIndex(vpcName)
    firewall.deletePolicy("root", "300")
    firewall.deletePolicy(tenant.vdom, "100")
    firewall.deleteIPPool(tenant.vdom, tenant.vpc[index]["poolname"])    
    firewall.deleteStaticRoute(tenant.vdom, "20")
    firewall.deleteStaticRoute("root", "1001")

def createVPC(firewall, tenant, vpcName):

    index = tenant.getVPCIndex(vpcName)
    firewall.createIPPool(tenant.vdom, 
                          tenant.vpc[index]["poolname"], 
                          tenant.vpc[index]["type"],
                          tenant.vpc[index]["public_start"], 
                          tenant.vpc[index]["public_end"], 
                          ARP_STATUS,
                          tenant.vpc[index]["public_start"],
                          tenant.vpc[index]["public_end"])
    ##Creating route from VDOM:
    firewall.createStaticRoute("root", 
                               tenant.vpc[index]["public_subnet"], 
                               Tenant.npu_address_tenant_ip,
                               Tenant.int_name_from_npu, 
                               "1001")
    ##Creating route to FABRIC
    firewall.createStaticRoute(tenant.vdom, 
                               tenant.vpc[index]["private_subnet"],
                               tenant.fabric_ip_address, 
                               Tenant.int_name_to_fabric, 
                               "20")
    firewall.createRootPolicy("root", 
                              "300", 
                              "to_tenant5",
                              [{ "name": Tenant.int_name_from_npu  }],  
                              "disable", 
                              "disable", 
                              ""  )
    dstintf = [{ "name": tenant.int_name_to_npu }]
    srcintf = [{ "name": tenant.int_name_to_fabric }]
    firewall.createTenantPolicy(tenant.vdom, 
                                "100", 
                               "to_internet", 
                                srcintf, 
                                dstintf, 
                               "enable", 
                               "enable", 
                               tenant.vpc[index]["poolname"])

def createTenant(firewall, tenant):
   
    ##Create VDOM#####
    #firewall.createVdom(tenant1)
    ###Create Interface to Fabric
    firewall.createFabricInt(tenant1)
    ##Create NPU links
    #firewall.createNPUIntTenant(tenant1)
    #firewall.createNPUIntRoot(tenant1)
    #firewall.createStaticRoute(tenant.vdom, DEFAULT_ROUTE, tenant.npu_address_root_ip, tenant.int_name_to_npu, DEFAULT_ROUTE_SEQ_NUM)

def deleteTenant(firewall, tenant):
    firewall.deleteInt(tenant.int_name_to_fabric)
    firewall.deleteInt(tenant.int_name_to_npu)
    firewall.deleteInt(tenant.int_name_from_npu)
    firewall.deleteStaticRoute(tenant.vdom, DEFAULT_ROUTE_SEQ_NUM)

##This function initialize values of tenants.
def initializeTenant(start, end):
    ##Initializing all tenants######
    tenants = []
    i = int(start) - 1
    end = int(end) - 1
    index = 0
    while i <= end:
        tenantName = TENANT_PREFIX + "_"
        #Adding 0 to tenant name. Need to make like this: TENANT_0001
        j = len(str(i))
        while (j < TENANT_NUMBER_OF_DIGITS):
             tenantName = tenantName + "0"
             j += 1
        tenantName += str(i+1)
        tenants.append(Tenant())
        tenants[index].initialize(tenantName)
        i += 1
        index += 1
    return tenants

def deleteCumulusTenant(tor, tenants):
   
   tor.createRevision() 
   print("tor " + tor.name + " revision: " + tor.rev)
   #Iterations via tenants in the same tor
   for tenant in tenants:
       print("tor " + tor.name + " vrf removal: " + tenant.name)
       status = tor.deleteVRFLO(tenant.name)
       print(tenant.name + " delete loopback: " + str(status))
       #nv unset vrf TENANT_0001
       #tor.deleteVRF(tenant.name)
       status = tor.deleteVRFROUTER(tenant.name)
       print(tenant.name + " delete router: " + str(status))
       status = tor.deleteEVPN(tenant.name)
       print(tenant.name + " delete evpn: " + str(status))
       #nv unset vrf TENANT_0001
       status = tor.deleteVRF(tenant.name)
       print(tenant.name + " delete vrf " + str(status))
   tor.applyRev()

def createIntToFirewall(edge, tenant):

    subnet = tenant.tenant_fabric_ip_address
    vlanNUM = str(tenant.fabric_vlan)
    ##1. Creating vlan
    #nv set  bridge domain br_default vlan $vlan_id 
    print("edge " + edge.name + " vlan creation: " + vlanNUM, end = '')
    rep = edge.createVLAN(vlanNUM, "")
    printResult(rep)

    ##2. Creating IP address
    #nv set interface vlan10 ip address 1.1.1.1/32
    print("edge " + edge.name + " vlan  " + vlanNUM + " ip creation: " + subnet, end = '')
    rep = edge.createIP("vlan" + vlanNUM, subnet);
    printResult(rep)
    ##3. Assigning to VRF
    # nv set interface vlan60 ip vrf TENANT_0001
    print("edge " + edge.name + " assigning vlan to VRF: " + tenant.name, end = '')
    rep = edge.assignIntToVRF("vlan" + str(vlanNUM), tenant.name)
    printResult(rep)

def createCumulusTenant(tor, tenants):
   
   #nv show interface lo
   # We need to get loopback. This lo will be used
   # to create bgp with lo
   lo = tor.getLO()
   tor.createRevision()
   #bgpAS = tor.getBGPAS()
   #printResult(bgpAS)
   #print("tor " + tor.name + " revision: " + tor.rev)
   #Iterations via tenants in the same tor
   for tenant in tenants:
       #tor.createRevision()
       bgpASNum = int(bgpAS[tor.name])
       print("tor " + tor.name + " vrf creation: " + tenant.name)
       #nv set vrf TENANT_0001
       tor.createVRF(tenant.name)
      
       #nv set vrf TENANT_0001 evpn vni 3001
       print("tor " + tor.name + "evpn creation: " + str(tenant.fabric_vlan))
       tor.createEVPN(tenant.fabric_vlan, tenant.name)
      
       #nv set vrf TENANT_0001 router bgp autonomous-system 65510
       #nv set vrf TENANT_0001 router bgp address-family ipv4-unicast enable on
       #nv set vrf TENANT_0001 router bgp address-family ipv4-unicast redistribute connected
       print("tor " + tor.name +"bgp creation: " + tenant.name)
       tor.createVRFBGP(tenant.name, bgpASNum)

       #nv set vrf TENANT_0001 router bgp peer-group underlay address-family l3vpn-evpn enable on
       print("tor " + tor.name +"bgp evnp creation: " + tenant.name)
       tor.createVRFEVPN(tenant.name)
       
       #nv set vrf TENANT_0001 router bgp address-family ipv4-unicast enable on
       #nv set vrf TENANT_0001 router bgp address-family ipv4-unicast redistribute connected
       tor.createVRFIPV4ADDRFAMILY(tenant.name)
       
       #nv set vrf TENANT_0001 router bgp address-family ipv4-unicast route-export to-evpn enable on
       tor.activateEVPN(tenant.name)
       
       #nv set vrf TENANT_0001 loopback ip address 192.168.100.1/32
       tor.createVRFLO(tenant.name, lo)
       # Creating interface to firewall
       if tor.type == "edge":
               createIntToFirewall(tor, tenant)
   tor.applyRev()       

#This functions create all fortigate VDOM 
def manageFortinetVRF(argc):
    tenants = initializeTenant(argc.start, argc.end)
    firewall = Fortigate()
    firewall.login("192.168.200.2",firewallUser,firewallPassword)


#This functions create all Cumulus VRF
def manageCumulusVRF(argc):
    tenants = initializeTenant(argc.start, argc.end)
    tors = []
    edges = []
    ####Initializing all routers    
    ##This procedure will create cumulus object
    ##And fill ip addr, username and password
    i = 0
    for tor in tor_ip_addresses:
         tors.append(Cumulus())
         tors[i].initialize(tor, tor_ip_addresses[tor], cumulusUser, cumulusPassword)
         tors[i].type = "tor"
         i += 1
    
    for edge in edge_ip_addresses:
         tors.append(Cumulus())
         tors[i].initialize(edge, edge_ip_addresses[edge], cumulusUser, cumulusPassword)
         tors[i].type = "edge"
         i += 1
    executor = ThreadPoolExecutor(100)   
   #####Iterations via tors
    for tor in tors:
        if argc.action == "create_tenant": 
           future = executor.submit(createCumulusTenant, tor, tenants) 
        if argc.action == "delete_tenant":
            deleteCumulusTenant(tor, tenants)   

def executePing(tor, tenant, edge, ipDst,  command):

    lines = tor.sendSSHCommand(command)
    if len(lines) > RECV_LOCATION_POS:
        result = lines[RECV_LOCATION_POS]
        receivedPos = result.find(RECV_STRING )
        receivedNum = result[receivedPos - POS_START: receivedPos - POS_END]
        print(tor.name + "(" + tor.ip + ") " + tenant.name + " ping to " + edge.name + "("+ ipDst + ")" + " received: " + receivedNum)
    else:
            print(tor.name + "(" + tor.ip + ") command has failed: " + command)
            print(lines)

def sendSSHPing(tor, tenants, edges):
    for tenant in tenants:
       for edge in edges:
           ipDst = edge.lo 
           command = "ping " + ipDst + " -I "  + tenant.name + " -c 5" + " -i 0.2" 
           executePing(tor, tenant, edge, ipDst,   command)
           ipDst = tenant.tenant_fabric_ip_address_no_sub 
           command = "ping " + ipDst + " -I "  + tenant.name + " -c 5" + " -i 0.2" 
           executePing(tor, tenant, edge, ipDst,   command)


##This function is printing result of the request:
def printResult(rep):
    js = rep.json()
    DEBUG = True
    if DEBUG:
         print(js)
    else:
        print(" :" + str(rep.status_code))

# This function is assigning vlan to interface
# and it's assigning vlan to vrf
def assignResToVPC(tor, argc, interfaces):
   
    print(interfaces)
    tenant = argc.vpc_vrf
    vlan = argc.vpc_vlan
    tor.createRevision()
    for interface in interfaces:
        ##1. Assigning vlan to interface
        #nv set interface swp4 bridge domain br_default access 60
        print("tor " + tor.name + " assigning vlan " +vlan
            + " to interface " + interface, end = '')
        rep = tor.assignVlanTOINT(interface, vlan);
        printResult(rep)

    ##2. Assigning vlan to VRF
    # nv set interface vlan60 ip vrf TENANT_0001
    print("tor " + tor.name + " assigning vlan to VRF: " + tenant, end = '')
    rep = tor.assignIntToVRF("vlan" + str(vlan), tenant)
    printResult(rep)

    tor.applyRev()
   


def deleteVLAN(tor, vlanNUM, subnet):

    print("tor " + tor.name + " revision creation: ")
    rep = tor.createRevision()
   
    # delete IP:
    print("tor " + tor.name + " ip deletion: vlan" + vlanNUM, end = '')
    rep = tor.deleteVLANIP("vlan" + str(vlanNUM))
    #rep = tor.getIP("vlan" + str(vlanNUM))
    #rep = tor.getINT("vlan100")
    printResult(rep)


    # deleteVLAN
    print("tor " + tor.name + " vlan deletion: " + vlanNUM, end = '')
    rep = tor.deleteVLAN(vlanNUM)
    printResult(rep)
    tor.applyRev()

def createVLAN(tor, vlanNUM, subnet):
   
    print("tor " + tor.name + " revision creation: ")
    rep = tor.createRevision()
    lo = tor.getLO()
    ##1. Creating vlan
    #nv set  bridge domain br_default vlan $vlan_id 
    print("tor " + tor.name + " vlan creation: " + vlanNUM, end = '')
    rep = tor.createVLAN(vlanNUM, vlanNUM, lo)
    printResult(rep)
    # 2. Creating VNI 
    #print("tor " + tor.name + " vni creation: " + vlanNUM, end = '')
    #rep = tor.createVNI(vlanNUM, vlanNUM, lo)
    #printResult(rep)
    ##3. Creating IP address
    #nv set interface $vlan_id ip address $ip_address 
    print("tor " + tor.name + " vlan  " + vlanNUM + " ip creation: " + subnet, end = '')
    rep = tor.createIP("vlan" + vlanNUM, subnet);
    printResult(rep)
    
    tor.applyRev()


# This is helping function to get all tor routers and interfaces
# This function is needed to understand which interfaces must be 
# used to assigned vlan
def getRoutersAndInterfaces(argc):
    routers = {}
    # getting list with assigned computes
    assignedComputes = [p for p in argc.vpc_res.split(',') if p] if argc.vpc_res else []
    # iterations via all assigned computes to find all tor routers
    # and interfaces
    for assignedCompute in assignedComputes:
       for router in device_int:
          was_found = False 
          for interface in device_int[router]:
              if device_int[router][interface] == assignedCompute:
                  was_found = True
                  if router in routers:
                      routers[router].append(interface)
                  else:
                      routers[router] = [interface]
    #      if not was_found:
         #        print("Critical: " + " compute " + assignedCompute + " was not found!")
    return routers

# This is common function to manage all VPC.
def manageVPC( argc):

    subnet = argc.vpc_sub
    vlan = argc.vpc_vlan
    routers = {}
    #if subnet == "" or vlan == "":
    #    exit(1)
    #tenants = initializeTenant(argc.start, argc.end)
    tors = []
    ####Initializing all routers    
    ##This procedure will create cumulus object
    ##And fill ip addr, username and password
    if argc.action == "assign_res":
       routers = getRoutersAndInterfaces(argc)
    
    i = 0
    for tor in tor_ip_addresses:
         if (argc.scope == 'cumulus' or tor in routers): 
             tors.append(Cumulus())
             tors[i].initialize(tor, tor_ip_addresses[tor], cumulusUser, cumulusPassword)
             i += 1
   #####Iterations via tors
    for tor in tors:
        if argc.action == "create_vpc": 
            createVLAN(tor, vlan, subnet)
        elif argc.action == "delete_vpc":
             deleteVLAN(tor, vlan, subnet)
        elif argc.action == "assign_res":
             assignResToVPC(tor, argc, routers[tor.name])

def getCumulusHostname(tor):
   
    rep = tor.getHostame()
    repJson = rep.json()
    hostname = repJson['value']
    if (rep.status_code == 200):
       print("Connection to " + tor.name + " is OK. Hostname is " + hostname)
    
    if (hostname.lower() != tor.name.lower()):
            print("Critical: Hostname is different from name in the file")

# This function is performing tests 
# test of connectivity
def verifyCumulusConnection():
    tors = []
    i = 0
    ####Initializing all routers    
    ##This procedure will create cumulus object
    ##And fill ip addr, username and password
    for tor in tor_ip_addresses:
       tors.append(Cumulus())
       tors[i].initialize(tor, tor_ip_addresses[tor], cumulusUser, cumulusPassword)
       i += 1
   
    for edge in edge_ip_addresses:
       tors.append(Cumulus())
       tors[i].initialize(edge, edge_ip_addresses[edge], cumulusUser, cumulusPassword)
       tors[i].type = "edge"
       i += 1


    executor = ThreadPoolExecutor(100)
    for tor in tors:
        future = executor.submit(getCumulusHostname, tor)



def verify(argc):

    tenants = initializeTenant(argc.start, argc.end)
    tors = []
    edges = []
    i = 0
    ####Initializing all routers    
    ##This procedure will create cumulus object
    ##And fill ip addr, username and password
    for tor in tor_ip_addresses:
       tors.append(Cumulus())
       tors[i].initialize(tor, tor_ip_addresses[tor], cumulusUser, cumulusPassword)
       tors[i].connectSSH()
       i += 1
    i = 0 
    for edge in edge_ip_addresses:
       edges.append(Cumulus())
       edges[i].initialize(edge, edge_ip_addresses[edge], cumulusUser, cumulusPassword)
       edges[i].getLO()
       print(edges[i].lo)
       i += 1
    
    executor = ThreadPoolExecutor(100)
    #####Iterations via tors
    for tor in tors:
        future = executor.submit(sendSSHPing, tor, tenants, edges)

###Main code starts here.
if __name__ == "__main__":

    p = argparse.ArgumentParser()
    p.add_argument('--action', help='create_tenant, delete_tenant, create_vpc, assign_res')
    p.add_argument('--start', help='First Tenant Number')
    p.add_argument('--end', help='Last Tenant Number')
    p.add_argument('--scope', help='cumulus, fortinet')
    p.add_argument('--vpc_sub', help='ip subnet')
    p.add_argument('--vpc_vlan', help='vlan')
    p.add_argument('--vpc_res', help='compute names')
    p.add_argument('--vpc_vrf', help='vpc vrf')
    argc = p.parse_args() 
    if ((argc.action == "create_tenant" or argc.action == "delete_tenant") and argc.scope == "cumulus"):
        manageCumulusVRF(argc)
    
    if (argc.action == "verify"):
        verify(argc)

    # Verification of access to routers
    if (argc.action == "verify_con_to_routers" and argc.scope == "cumulus"):
        verifyCumulusConnection()


    if (argc.action == "create_vpc" or argc.action == "delete_vpc" or argc.action == "assign_res"): 
        manageVPC(argc)
    
    if ((argc.action == "create_tenant" or argc.action == "delete_tenant") and argc.scope == "fortinet"):
        manageFortinetVRF(argc)

    #createCumulusVRF()
    #firewall = Fortigate()
    #firewall.login("10.0.15.240",firewallUser,firewallPassword)
    #tenant1 = Tenant()
    #tenantName = firewall.getIdleVdom()
    #print(tenantName)
    #if tenantName != "None": 
    #    tenant1.initialize(tenantName)
    #    vpc = { "name" : "L2_OVERLAY", "type": "overload", "public_start": "24.51.5.214","public_end" : "24.51.5.214", 
    #        "private_subnet": "192.168.200.1/32", "public_subnet": "24.51.5.214/32", 
    #        "private_start" : "192.168.200.1", 
    #        "private_end" : "192.168.200.1",
    #        } 
    #    tenant1.addVPC(vpc)
    #deleteVPC(firewall, tenant1, "L2_OVERLAY")
    #createVPC(firewall, tenant1, "L2_OVERLAY")
    #firewall.purgeVdomStaticRoute(tenant1.vdom)
    #firewall.purgeRootStaticRoute(tenant1.int_name_from_npu)
    #firewall.purgeIPPOOL(tenant1.vdom)
    #firewall.purgeAllTenantPolicy(tenant1.vdom)
    #createTenant(firewall, tenant1)
    #deleteVPC(firewall, tenant1, "L2_OVERLAY")
    #deleteTenant(firewall, tenant1)a
    #    print("Idle vdom: " + firewall.getIdleVdom())
    #firewall.getVdom(tenant1)
    #firewall.reserveVdom(tenant1.vdom, 1)
    #firewall.putVdomComment(tenant1.vdom, "idle1")
