##Static parameters for Cumulus
###URL DEFINITIONS####
URL_REV = 'cue_v1/revision'
URL_BASE = 'cue_v1/revision'
URL_VRF = 'cue_v1/vrf/'
HEADERS = {'content-type': 'application/json'}
BASE_URL_START = 'https://'
BASE_URL_PORT = '8765'
BASE_URL_DEL = ":"
BASE_URL_END = "/"
LOOPBACK_TOR = "192.168.100.0/24"
LOOPBACK_EDGE = "192.168.100.0/24"
###Login URI:
LOGIN_URI = 'logincheck'
LOGOUT_URI = 'logout'
GET_VDOM_URI = 'cmdb/system/vdom/'
URI_INTERFACE = 'cmdb/system/interface'
URI_IPPOOL = 'cmdb/firewall/ippool'
URI_STATIC_ROUTE = 'cmdb/router/static'
URI_FIREWALL_POLICY = 'cmdb/firewall/policy'
URI_SYSTEM_SET =  'cmdb/system/settings'
###Tenant Name########
TENANT_PREFIX = "TENANT"
TENANT_DELIMITER = "-"
IDLE_TENANT = 1
ACTIVE_TENANT = 0
TENANT_NUMBER_OF_DIGITS = 4
###Tenant VLAN#######
TENANT_NPU_VLAN_START = 1001
TENANT_FIREWALL_FABRIC_VLAN_START = 2001
TENANT_FABRIC_VLAN_START = 3000
###NPU Name config####
NPU_INT_NAME = { "pref": "npu" , "end": "_vlink"} # example: npu5_vlink0 
NPU_UPLINK = 0
NPU_DOWNLINK = 1
NPU_NUMBER_OF_LINKS = 5
######################
FIREWALL_UPLINK = [{ "name": "port19" }, { "name": "port20" }, { "name": "vlan225" }, { "name": "vlan226" }]
FIREWALL_LINK_TO_FABRIC = { "spine1": "port23" ,  "spine2": "port24" }
####IP Addresses#######
TENANT_SUBNET_INDEX = 1
ROOT_SUBNET_INDEX = 0
FABRIC_SUBNET_INDEX = 1
NPU_IP_SUBNET = "172.24.182.0/24"
FIREWAL_IP_SUBNET = "172.24.181.0/24"
####
TYPE_OVERLOAD = "overload"
ARP_STATUS = "disable"
IP_POOL_NAME_PREFIX = "IP_POOL_"
#####Static routes#####
DEFAULT_ROUTE = "0.0.0.0/0"
DEFAULT_ROUTE_SEQ_NUM = "1"
#####Magic number#####
SRC_ADDR = "all", 
DST_ADDR = "all", 
SERVICE  = "ALL"
DEF_ACTION = "accept"
DEF_STATUS = "enable"
LOGTRAFFIC = "all",
SCHEDULE = "always",
SCHEDULE_TIMEOUT = "disable",
#####Magic numbers for ping
SSH_PORT = 22
RECV_LOCATION_POS = 9
RECV_STRING = "received"
POS_START = 2
POS_END = 1
