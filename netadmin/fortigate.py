#!/usr/bin/env python3
import json
import requests
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



class Fortigate(object):
    
    def __init__(self):
        pass

    def logout(self):
        uri = 'https://' + self.ip + "/" + LOGOUT_URI  
        postResult = self.session.post(uri , self.cookies, verify=False)

    def login(self, ipaddr, firewallUser, firewallPassword):
        self.session = requests.Session()
        self.base_url = 'https://' + ipaddr + '/api/v2/'
        uri = 'https://' + ipaddr + "/" + LOGIN_URI 
        self.ip = ipaddr
        try: 
             postResult = self.session.post(uri , data={"username": firewallUser, "secretkey": firewallPassword}, verify=False)
        except: 
            data = "CRITICAL: Connection to firewall " + uri + " was not established"
            print(data)
            exit(1)
        print(postResult.text)
        self.cookies = postResult.cookies
        self.ccsrftoken = postResult.cookies.get_dict()['ccsrftoken'].strip('"')
        self.headers = {"X-CSRFTOKEN": self.ccsrftoken } 

#######VDOM################    
    def getAllVdom(self ):
        uri = GET_VDOM_URI 
        params = {'scope': 'global'}
        return self.sendShowCommand(uri, params)

    def putVdomComment(self, vdom, comments ):
        uri = URI_SYSTEM_SET 
        params = { 'vdom': vdom }
        data = { 'vdom': vdom,
                 'comments' : comments
                 }
        print(data)
        return self.sendPutCommand(uri, data,  params)


    def getVdomComment(self, vdom ):
        uri = URI_SYSTEM_SET + "/"
        params = {
                'scope': 'global'
                }
        data = { 'name': vdom }
        return self.sendShowCommand(uri, params)

    def getVdomFlag(self, vdom ):
        uri = URI_SYSTEM_SET + "/"
        params = {
                'scope': 'global'
                }
        data = { 'name': vdom }
        return self.sendShowCommand(uri, params)

    def getIdleVdom(self):
       rep = self.getAllVdom()
       jsonResp = rep.json()
       for vdom in jsonResp['results']:
           if vdom['flag'] == IDLE_TENANT:
               return vdom['name']


    def getVdom(self, tenant):
        uri = GET_VDOM_URI + tenant.vdom
        params = {'scope': 'global'}
        self.sendShowCommand(uri, params)

    def deleteVdom(self, tenant):
        uri = self.base_url + GET_VDOM_URI + tenant.vdom 
        params = {
               # 'vdom': "root"
                }
        data = { 'name': tenant.vdom, }
        self.sendDeleteCommand(uri, data, params)

    def createVdom(self, tenant):
        uri = self.base_url + GET_VDOM_URI 
        params = { 'vdom': "root", }
        print(tenant.vdom)
        data = { 'name': tenant.vdom, }
        self.sendCreateCommand(uri, data, params)

    def reserveVdom(self, vdom, flag ):
        uri =  GET_VDOM_URI + vdom 
        params = {
                'scope': 'global'
                }
        data = { 'name': vdom,
                 'flag' : flag}
        print(data)
        print(uri)
        return self.sendPutCommand(uri, data,  params)
############################
#######Interfaces##########
    def deleteInt(self, name):
        uri = self.base_url + URI_INTERFACE + "/"  + name 
        params = {
               # 'vdom': "root"
                }
        data = { 'name': name, }
        self.sendDeleteCommand(uri, data, params)
    
    def createFabricInt(self, tenant):
        uri = self.base_url + URI_INTERFACE
        params = { 'vdom': "root", }
        data = {  "name": tenant.int_name_to_fabric,
                  "vdom": tenant.vdom, 
                  "ip": tenant.tenant_fabric_ip_address,
                  "vlanid": tenant.firewall_fabric_vlan,
                  "allowaccess": "ping",
                  "type": "vlan",
                  "role": "lan",
                  "mode": "static",
                  "interface": FIREWALL_LINK_TO_FABRIC["spine1"],
               }
        self.sendCreateCommand(uri, data, params)

    def createNPUIntTenant(self, tenant):
        uri = self.base_url + URI_INTERFACE
        npu_link = tenant.number % NPU_NUMBER_OF_LINKS
        npu_link = 5
        port = NPU_INT_NAME["pref"] + str(npu_link) + NPU_INT_NAME["end"] + "0"
        params = { 'vdom': "root", }
        data = {  "name": tenant.int_name_to_npu,
                  "vdom": tenant.vdom,
                  "ip": tenant.npu_address_tenant,
                  "vlanid": tenant.npu_vlan,
                  "allowaccess": "ping",
                  "type": "vlan",
                  "role": "lan",
                  "mode": "static",
                  "interface": port,
               }
        print(data)
        self.sendCreateCommand(uri, data, params)

    def createNPUIntRoot(self, tenant):
        uri = self.base_url + URI_INTERFACE
        npu_link = tenant.number % NPU_NUMBER_OF_LINKS
        npu_link = 5
        port = NPU_INT_NAME["pref"] + str(npu_link) + NPU_INT_NAME["end"] + "1"
        params = { 'vdom': "root", }
        data = {  "name": tenant.int_name_from_npu,
                  "vdom": "root",
                  "ip": tenant.npu_address_root,
                  "vlanid": tenant.npu_vlan,
                  "allowaccess": "ping",
                  "type": "vlan",
                  "role": "lan",
                  "mode": "static",
                  "interface": port,
               }
        print(data)
        self.sendCreateCommand(uri, data, params)

    
    def getAllInterfaces(self):
        uri = URI_INTERFACE 
        print(uri)
        params = { 'vdom': "root", }
        self.sendShowCommand(uri, params)
 
    def getInterface(self, tenant):
        uri = URI_INTERFACE + "/" + tenant.name 
        params = { 'vdom': "root", }
        self.sendShowCommand(uri, params)

######Firewall Policy####
    def deletePolicy(self, vdom, seq):
        uri = self.base_url + URI_FIREWALL_POLICY + "/" + seq
        params = {
                'vdom': vdom
                }
        data = {  }
        self.sendDeleteCommand(uri, data, params)


    def getALLPolicy(self, vdom, ):
        uri = URI_FIREWALL_POLICY 
        params = {'scope': 'global',
                  'vdom': vdom}
        return self.sendShowCommand(uri, params)

    def createRootPolicy(self, vdom, policyid, name,  srcintf,  ippool, nat, poolname  ):
        uri = self.base_url + URI_FIREWALL_POLICY
        params = { 'vdom': vdom }
        data = {
                  "policyid": policyid,
                  "name"    : name,
                  "srcintf" : srcintf,
                  "dstintf" : FIREWALL_UPLINK,
                  "srcaddr" :[
                               {
                                  "name": SRC_ADDR 
                                }
                             ],
                  "dstaddr" : [
                               {
                                   "name": DST_ADDR 
                               }
                               ],
                  "action"  : DEF_ACTION,
                  "service" :  [
                                {
                                   "name": SERVICE,
                                }
                               ],
                  "nat"     : nat,
                  "poolname"  : [
                                {
                                   "name": poolname,
                                }
                              ],
                  "ippool": ippool,
                  "status": DEF_STATUS,
                  "logtraffic": LOGTRAFFIC,
                  "schedule": SCHEDULE,
                  "schedule-timeout": SCHEDULE_TIMEOUT,
               }
        print(data)
        self.sendCreateCommand(uri, data, params)


    def createTenantPolicy(self, vdom, policyid, name,  srcintf, dstintf,  ippool, nat, poolname  ):
        uri = self.base_url + URI_FIREWALL_POLICY 
        params = { 'vdom': vdom }
        data = {
                  "policyid": policyid,
                  "name"    : name,
                  "srcintf" : srcintf,
                  "dstintf" : dstintf,
                  "srcaddr" :[ 
                               { 
                                  "name": SRC_ADDR 
                                }
                             ],   
                  "dstaddr" : [
                               { 
                                   "name": DST_ADDR
                               }
                               ],                                     
                  "action"  : DEF_ACTION,
                  "service" :  [
                                {
                                   "name": SERVICE,
                                }
                               ],                                   
                  "nat"     : nat,
                  "poolname"  : [
                                {
                                   "name": poolname,
                                }
                              ],                                   
                  "ippool": ippool,
                  "status": DEF_STATUS,
                  "logtraffic": LOGTRAFFIC,
                  "schedule": SCHEDULE,
                  "schedule-timeout": SCHEDULE_TIMEOUT,   
            }
        print(data)
        self.sendCreateCommand(uri, data, params)

    def purgeAllTenantPolicy(self, vdom):
       rep = self.getALLPolicy(vdom)
       jsonResp = rep.json()
       for policy in jsonResp['results']:
          self.deletePolicy(vdom, str(policy['policyid']))

########STATIC ROUTE#####
    def createStaticRoute(self, vdom, dst, gateway, device, seqnum):
        uri = self.base_url + URI_STATIC_ROUTE
        params = { 'vdom': vdom }
        data = {  
                  "dst": dst,
                  "gateway": gateway,
                  "device": device,
                  "seq-num": seqnum,
               }
        print(data)
        print(params)
        self.sendCreateCommand(uri, data, params)

    def getStaticRoute(self,vdom, seq):
        uri = URI_STATIC_ROUTE + "/" + seq
        print(uri)
        params = { 'vdom': vdom }
        self.sendShowCommand(uri, params)

    def getALLStaticRoute(self,vdom):
        uri = URI_STATIC_ROUTE + "/"
        print(uri)
        params = { 'vdom': vdom }
        return self.sendShowCommand(uri, params)

    def deleteStaticRoute(self, vdom, name):
        uri = self.base_url + URI_STATIC_ROUTE + "/" + name
        params = {
                'vdom': vdom
                }
        data = { 'name': name, }
        self.sendDeleteCommand(uri, data, params)

    def purgeRootStaticRoute(self, device ):
        rep = self.getALLStaticRoute("root")
        jsonResp = rep.json()
        for route in jsonResp['results']:
            if route['device'] == device:
                print("Deleting: " + str(route['seq-num']))
                self.deleteStaticRoute("root", str(route['seq-num']))   
    
    def purgeVdomStaticRoute(self, vdom):
        rep = self.getALLStaticRoute(vdom)
        jsonResp = rep.json()
        for route in jsonResp['results']:
            if route['seq-num'] == 1:
                continue
            else:
                print("Deleting: " + str(route['seq-num']))
                self.deleteStaticRoute(vdom, str(route['seq-num']))


####IP POOL COMMANDS#####

    def deleteIPPool(self, vdom, name):
        uri = self.base_url + URI_IPPOOL + "/" + name 
        params = {
                'vdom': vdom 
                }
        data = { 'name': name, }
        self.sendDeleteCommand(uri, data, params)
    
    def getIPPool(self, vdom, name):
        uri = URI_IPPOOL + "/" + name 
        params = { 'vdom': vdom }
        self.sendShowCommand(uri, params)

    def getALLIPPool(self, vdom):
        uri = URI_IPPOOL #+ "/" 
        params = { 'vdom': vdom }
        return self.sendShowCommand(uri, params)

    def createIPPool(self, vdom, name, nattype, startip, endip, arpreply, sourcestartip, sourceendip): 
        uri = self.base_url + URI_IPPOOL  
        params = { 'vdom': vdom }
        data = {  "name": name,
                  "vdom": vdom,
                  "type": nattype ,
                  "startip": startip,
                  "endip": endip,
                  "arp-reply": arpreply,
                  "source-startip": sourcestartip,
                  "source-endip": sourceendip, 
               }
        print(data)
        self.sendCreateCommand(uri, data, params)

    def purgeIPPOOL(self, vdom):
        rep = self.getALLIPPool(vdom)
        jsonResp = rep.json()
        for ippool in jsonResp['results']:
            print(ippool['name'])
            self.deleteIPPool(vdom, ippool['name'])

########### STATIC ROUTE CONFIG###########


###########Create, Delete, Show commands
    def sendCreateCommand(self, uri, data, params):
        print(uri)
        try:
             rep = requests.post(uri, cookies=self.cookies,headers=self.headers, data=json.dumps(data), params=params, verify=False)
        except:
            data = "CRITICAL: Connection to router " + url + " was not established"
            print(data)
            print(rep.text)
            exit(1)

        if (rep.status_code != 200):
             data = "Command: " + reqType + ". Router: " + url + " has returned: " + str(rep.status_code)
             print("CRITICAL: ", data)
             print(rep.text)
             exit(1)
        print(rep.text)
    
    def sendDeleteCommand(self, uri, data, params):
        try:
            rep = requests.delete(uri, cookies=self.cookies,headers=self.headers, data=json.dumps(data), params=params, verify=False)
        except:
            data = "CRITICAL: Connection to router " + url + " was not established"
            print(data)
            print(rep.text)
            exit(1)

        if (rep.status_code != 200):
             data = "Command: " + reqType + ". Router: " + url + " has returned: " + str(rep.status_code)
             print("CRITICAL: ", data)
             print(rep.text)
             exit(1)
        print(rep.text)
    

    def sendShowCommand(self, uri, params):
        print(self.base_url + uri)
        rep = requests.get(self.base_url + uri, cookies=self.cookies,  headers=self.headers, params=params, verify=False)
        #print("Show command: " + rep.text)
        return rep

    def sendPutCommand(self, uri, data, params):
        print(self.base_url + uri)
        try:
             rep = requests.put(self.base_url + uri, cookies=self.cookies,  headers=self.headers, data=json.dumps(data), params=params, verify=False)
        except:
            data = "CRITICAL: Connection to router " + url + " was not established"
            print(data)
            print(rep.text)
            exit(1)

        if (rep.status_code != 200):
             data = "Command: " + reqType + ". Router: " + url + " has returned: " + str(rep.status_code)
             print("CRITICAL: ", data)
             print(rep.text)
             exit(1)

        print("Put command: " + rep.text)
        return rep

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
