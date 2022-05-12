import paramiko
import json
import requests
import urllib3 # disable security warning for SSL certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # disable security warning for SSL certificate
import filecmp
import time
import difflib
from credentials import *
from dc_parameters import *


class Cumulus(object):

    def __init__(self):
        pass
   
    def initialize(self,name, ip, login, password):
        self.base_url = BASE_URL_START + ip + BASE_URL_DEL + BASE_URL_PORT + BASE_URL_END
        self.cumulusUser = login
        self.cumulusPassword = password
        self.name = name
        self.ip = ip
        self.lo = ""
        self.type = ""
        self.session = requests.Session()

    def getConfig(self):
       url = self.base_url + 'nvue_v1/vrf/default/router?rev=applied'
       rep = self.sendGET(url, "")
       return rep
   
   ##This function creates revision and return it back.
    def createRevision(self):
        url = self.base_url + URL_REV 
        rep = Cumulus.sendPost(self, url)
        jsonResp = rep.json()
        #Return value is dictionariy and not list
        #Size of dic is 1
        #So it will have only 1 iterations.
        for key in jsonResp :
            rev = key
        self.rev = rev 

    ## This function apply revision 
    def applyRev(self):
        rev_url =  self.rev
        rev_url_new = rev_url.replace("/", "%2F")
        url = self.base_url + URL_REV +"/" + rev_url_new
        data = {'state':'apply',
                "auto-prompt": {
                "ays": "ays_yes",
                "confirm": "confirm_yes"
                },
                }
        params = { 'rev': self.rev }
        self.sendPatch(url, data, params)
    
    #nv set vrf TENANT_0001
    def createVRF(self, vrf):
        url = self.base_url + URL_VRF + vrf
        params = { 'rev': self.rev,
                'vrf-id' : vrf,
                 }
        data  = {
                "loopback": {
                "ip": {
                    "address": {}
                 }
                 },
                 "router": {},
                 }
        self.sendPatch(url, data, params)

    #nv delete vrf TENANT_0001
    def deleteVRF(self, vrf):
        url = self.base_url + 'nvue_v1/vrf'  
        params = { 'rev': self.rev,
                  # 'vrf-id' : vrf
                }
        
        data  = {
                "TENANT_0001" : None 
                 }
        print(vrf)
        rep = self.sendPatch(url, data, params)
        return rep.status_code 

    #nv set vrf TENANT_0001 evpn vni 3001
    def  createEVPN(self, vni, vrf ):
         url = self.base_url + 'cue_v1/vrf/' + vrf + '/evpn'
         params = { 'rev': self.rev,
                    'vrf-id' : vrf,
                  }
         data  = { "enable" : "on",
                   "vni": {
                    vni: {}
                    },
                 }
         self.sendPatch(url, data, params)
     
     # nv unset vrf TENANT_0001 evpn
    def deleteEVPN(self, vrf ):
         url = self.base_url + 'cue_v1/vrf/' + vrf + '/evpn'
         params = { 'rev': self.rev,
                    'vrf-id' : vrf,
                  }

         rep = self.sendDELETE(url, params)
         return rep

    ##get vrf###
    def getBGPAS(self ):
        url = self.base_url + 'nvue_v1/vrf/default/router'
        params = { 'rev': 'applied',
                  }
        rep = self.sendGET( url, params)
        return rep

    ###Create BGP########
    #nv set vrf TENANT_0001 router bgp autonomous-system 65420
    #nv set vrf TENANT_0001 router bgp address-family ipv4-unicast redistribute connected enable on
    def createVRFBGP(self, vrf, bgpAS):
        #####Post###
        url = self.base_url + 'cue_v1/vrf/' + vrf + '/router/bgp'
        params = { 'rev': self.rev,
                 'vrf-id' : vrf,
            }

        data  = { "enable" : "on",
                  "autonomous-system": bgpAS,
                }
        self.sendPatch(url, data, params)

    ###Create BGP L2EVPN########
    #nv set vrf TENANT_0001 router bgp peer-group underlay address-family l2vpn-evpn enable on
    def createVRFEVPN(self, vrf):
        #####Post###
        url = self.base_url + 'cue_v1/vrf/' + vrf + '/router/bgp/address-family/l2vpn-evpn'
        params = { 'rev': self.rev,
                 'vrf-id' : vrf,
            }

        data  = { "enable" : "on",
                }
        self.sendPatch(url, data, params)

    ###Create BGP L2EVPN########
    #nv set vrf TENANT_0007 router bgp address-family ipv4-unicast enable on
    #nv set vrf TENANT_0007 router bgp address-family ipv4-unicast redistribute connected
    def createVRFIPV4ADDRFAMILY(self, vrf):
        #####Post###
        url = self.base_url + 'cue_v1/vrf/' + vrf + '/router/bgp/address-family/ipv4-unicast'
        params = { 'rev': self.rev,
                 'vrf-id' : vrf,
            }

        data  = {  "enable": "on",
                  "redistribute": {
                  "static": {
                      "enable": "on",
                       "metric": "auto",
                       "route-map": "none"
                  },
                 "connected": {
                      "enable": "on",
                      "metric": "auto",
                      "route-map": "none"
                 }, 
                  }
                }  
        self.sendPatch(url, data, params)

    ##DELETE ROUTER########
    def deleteVRFROUTER(self, vrf):
        #####Post###
        url = self.base_url + 'cue_v1/vrf/' + vrf + '/router'
        params = { 'rev': self.rev,
                 'vrf-id' : vrf,
            }

        ret = self.sendDELETE(url, params)
        return(ret.status_code)

    ###Activate EVPN#
    #nv set vrf TENANT_0001 router bgp address-family ipv4-unicast route-export to-evpn
    def activateEVPN(self, vrf):
        #####Post###
        url = self.base_url + 'cue_v1/vrf/' + vrf + '/router/bgp/address-family/ipv4-unicast/route-export/to-evpn'
        params = { 'rev': self.rev,
                 'vrf-id' : vrf,
            }

        data  = {  "enable": "on",
                }
        self.sendPatch(url, data, params)

    ###Create VRF Loopback########
    #nv set vrf TENANT_0001 loopback ip address 192.168.100.1/32
    def createVRFLO(self,vrf, lo):
        #####Post###
        url = self.base_url + 'cue_v1/vrf/' + vrf + '/loopback'
        params = { 'rev': self.rev,
                 'vrf-id' : vrf,
            }

        data  = {  
                  "ip": {
                      "address": {
                          lo: {},
                      }
                   }
                }
        rep = self.sendPatch(url, data, params)

    #nv unset vrf TENANT_0001 loopback ip address 192.168.100.1/32
    def deleteVRFLO(self, vrf):
        #####Post###
        url = self.base_url + 'cue_v1/vrf/' + vrf + '/loopback'
        params = { 'rev': self.rev,
                 'vrf-id' : vrf,
            }

        rep = self.sendDELETE(url, params)
        return rep.status_code

   
    def getLO(self):
       url = self.base_url + 'cue_v1/interface/lo' 
       rep = self.sendGET(url, "")
       lo = rep.json()
       loIPADDR = lo['ip']['address']
       for ip in loIPADDR:
           if ("/32") in ip:
              pos = ip.find("/32")
              self.lo = ip[:pos] 
              return ip 

    ###Create BGP########
    def createVRFBGP(self, vrf, bgpAS):
        #####Post###
        url = self.base_url + 'cue_v1/vrf/' + vrf + '/router/bgp'
        params = { 'rev': self.rev,
                 'vrf-id' : vrf,
            }

        data  = { "enable" : "on",
                  "autonomous-system": bgpAS,
                }
        self.sendPatch(url, data, params)

#########ALL SSH Commands#########3
    def connectSSH(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try: 
            self.ssh.connect(self.ip, SSH_PORT, self.cumulusUser, self.cumulusPassword)
        except: 
            data = "CRITICAL: Connection to router " + self.ip + " was not established"
            print(data)
        

    def sendSSHCommand(self, command):
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
        except:
            data = "CRITICAL: Command " + command + " to router " + tor + " had failed"
            print(data)
        res = stdout.readlines()
        return res

#####VLANS creation and assigment ####
    # nv set interface swp4 bridge domain br_default access 60
    # command N3  to execute. 
    def assignVlanTOINT(self, interface, vlan):
        url = self.base_url + 'cue_v1/interface/' + interface + '/bridge'
        params = { 'rev': self.rev,
                 'interface-id' : interface,
            }
        data  = { 'domain': {'br_default': {'access': int(vlan), 'learning': 'on', 'stp': {'admin-edge': 'off', 'auto-edge': 'on', 'bpdu-filter': 'off', 'bpdu-guard': 'off', 'network': 'off', 'restrrole': 'off'}}}
                }
        rep = self.sendPatch(url, data, params)
        return rep


    #nv set interface vlan60 ip vrf TENANT_0001
    def assignIntToVRF(self, interface, vrf):
        url = self.base_url + 'cue_v1/interface/' + interface + '/ip'
        params = { 'rev': self.rev,
                 'interface-id' : interface,
            }
        data  = { 'vrf': vrf }
        rep = self.sendPatch(url, data, params)
        return rep

    # This function is used to get access vlan from interface.
    # {'domain': {'br_default': {'access': 60, 'learning': 'on', i
    # 'stp': {'admin-edge': 'off', 'auto-edge': 'on', 'bpdu-filter': 'off',
    # 'bpdu-guard': 'off', 'network': 'off', 'restrrole': 'off'}}}}
    def getIntBridge(self, interface):
        url = self.base_url + 'cue_v1/interface/' + interface + '/bridge'
        rep = self.sendGET(url, "")
        return rep

    # This function is getting vlan:
    # {'10': {'multicast': {'snooping': {'querier': {'source-ip': '0.0.0.0'}}}, 
    #'ptp': {'enable': 'on'}, 'vni': {}}, } 
    def getVLAN(self, vlan):
        url = self.base_url + 'cue_v1/bridge/domain/br_default/vlan'
        rep = self.sendGET(url, "")
        return rep

    def getVNI(self, vlan):
        url = self.base_url + 'cue_v1/bridge/domain/br_default/vlan/' + vlan + '/vni'
        rep = self.sendGET(url, "")
        return rep    

    def createVNI(self, vlan, vni, lo):
        url = self.base_url + 'cue_v1/bridge/domain/br_default/vlan/' + vlan + '/vni'
        params = { 'rev': self.rev,
                 'domain-id' : 'br_default',
                 'vid' : vlan,
                  }

        data  = {vni : {'flooding': {'enable': 'auto', 'head-end-replication': {lo: {}}}, 'mac-learning': 'off'}
                }
        rep = self.sendPatch(url, data, params)
        return rep

    # show interface ip
    def getINTIP(self, interface ):
        #####Post###
        url = self.base_url + 'cue_v1/interface/' + interface + '/ip'
        #params = { 
        #         'interface-id' : vlan,
        #         }
        rep = self.sendGET(url, "")
        return rep

    # show interface ip
    def getINT(self, interface ):
        #####Post###
        url = self.base_url + 'cue_v1/interface/' + interface
        #params = {
        #         'interface-id' : vlan,
        #         }
        rep = self.sendGET(url, "")
        return rep


    # nv set bridge domain br_default vlan 10
    # command N1 to create vlan
    def createVLAN(self, vlan, vni, lo):
        #####Post###
        url = self.base_url + 'cue_v1/bridge/domain/br_default'
        params = { 'rev': self.rev,
                 'domain-id' : 'br_default',
            }
        vni_dic  = {vni : {'flooding': {'enable': 'auto', 'head-end-replication': {lo: {}}}, 'mac-learning': 'off'}
                }

#'vni': {}
        data  = { 'vlan' : 
                {vlan: {'multicast': {'snooping': {'querier': {'source-ip': '0.0.0.0'}}}, 'ptp': {'enable': 'on'},'vni': vni_dic }}
                }
        rep = self.sendPatch(url, data, params)
        return rep

    def deleteVLAN(self, vlan):
        #####Post###
        url = self.base_url + 'cue_v1/bridge/domain/br_default/vlan/' + str(vlan)
        params = { 'rev': self.rev,
                  'domain-id' : 'br_default',
            }

        rep = self.sendDELETE(url, params)
        return rep

    def deleteVLANIP(self, interface):
        #####Post###
        url = self.base_url + 'cue_v1/interface'  
        params = { 'rev': self.rev,
                   interface : 'null',
            }

        rep = self.sendDELETE(url, params)
        return rep


    #nv set interface vlan10 ip address 1.1.1.1/32
    # command N2 to create IP vlan
    def createIP(self, vlan, ip): 
        url = self.base_url + 'cue_v1/interface/' + vlan + '/ip'
        params = { 'rev': self.rev,
                 'domain-id' : 'br_default',
                 }

        data  = { 'address': { ip: {} } }
        
        rep = self.sendPatch(url, data, params)
        return rep

    # Getting IP address from interface
    def getIP(self, vlan):
        url = self.base_url + 'cue_v1/interface/' + vlan + '/ip'
        rep = self.sendGET(url, "")
        return rep

   # Getting hostname 
    def getHostame(self):
        url = self.base_url + 'cue_v1/platform/hostname' 
        rep = self.sendGET(url, "")
        return rep

    

####### ALL requests functions are here######
    ## This function sends post requests
    def sendPost(self, url):
        try:
            rep = self.session.post(url, auth=(self.cumulusUser,self.cumulusPassword),  verify=False)
        except:
            data = "CRITICAL: Connection to router " + url + " was not established"
            print(data)
            print(rep.text)
        if (rep.status_code != 200):
             data = "router " + rep + " has returned: " + rep.status_code
             print("CRITICAL: ", data)
             exit(1)
        return rep

    ### This function sends patch requests
    def sendPatch(self, url, data, params):
        rep = self.reqCommand("patch", url, data, params)
        return rep

        ### This function sends patch requests
    def sendGET(self, url, params):
        rep = self.reqCommand("get", url, "", params)
        return rep
        
        ### This function sends patch requests
    def sendDELETE(self, url, params):
        rep = self.reqCommand("delete", url, "", params)
        return rep
    
    def reqCommand(self, reqType, url, data, params):
        #print(url)
        try:
            if (reqType == "patch"):
                rep = self.session.patch(url, auth=(self.cumulusUser,self.cumulusPassword),headers=HEADERS, data=json.dumps(data), params=params,  verify=False)
            elif (reqType == "post"):
                rep = self.session.post(url, auth=(self.cumulusUser,self.cumulusPassword),  verify=False)
            elif (reqType == "get"):
                rep = self.session.get(url, auth=(self.cumulusUser,self.cumulusPassword), params=params, verify=False)
            elif (reqType == "delete"): 
                rep = self.session.delete(url, auth=(self.cumulusUser,self.cumulusPassword), params=params, verify=False)
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
        return rep
