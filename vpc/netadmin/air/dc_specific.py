##Static parameters for Cumulus
LOOPBACK_TOR = "192.168.100.0/24"
LOOPBACK_EDGE = "192.168.100.0/24"
###Tenant VLAN#######
FIREWALL_UPLINK = [{ "name": "port19" }, { "name": "port20" }, { "name": "vlan225" }, { "name": "vlan226" }]
FIREWALL_LINK_TO_FABRIC = { "spine1": "port23" ,  "spine2": "port24" }
EDGE_LINK_TO_FIREWALL = "swp1"
####IP Addresses#######
NPU_IP_SUBNET = "172.24.182.0/24"
FIREWAL_IP_SUBNET = "172.24.181.0/24"
####
#####Static routes#####
#####Magic number#####
