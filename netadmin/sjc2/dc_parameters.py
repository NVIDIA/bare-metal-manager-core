##Static parameters
###Login URI:
LOGIN_URI = 'logincheck'
LOGOUT_URI = 'logout'
GET_VDOM_URI = 'cmdb/system/vdom/'
URI_INTERFACE = 'cmdb/system/interface'
URI_IPPOOL = 'cmdb/firewall/ippool'
URI_STATIC_ROUTE = 'cmdb/router/static'
URI_FIREWALL_POLICY = 'cmdb/firewall/policy'
###Tenant Name########
TENANT_PREFIX = "TENANT"
TENANT_DELIMITER = "-"
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



