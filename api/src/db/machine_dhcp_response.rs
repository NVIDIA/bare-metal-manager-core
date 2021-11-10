use crate::{CarbideError, CarbideResult};
use log::{debug, info, warn};

use eui48::MacAddress;
use std::net::{Ipv4Addr, Ipv6Addr};

///
/// A machine dhcp response is a representation of some booting interface by Mac Address or DUID
/// (not implemented) that returns the network information for that interface on that node, and
/// contains everything necessary to return a DHCP response
///
#[derive(Debug)]
pub struct DhcpResponse {
    machine_id: uuid::Uuid,
    segment_id: uuid::Uuid,

    mac_address: MacAddress,

    address_ipv4: Option<Ipv4Addr>,
    address_ipv6: Option<Ipv6Addr>,

    fqdn: String,
    subdomain: String,
    mtu: i32,

    gateway_ipv4: Option<Ipv4Addr>,
}

pub type Duid = String;

pub struct Dhcpv4Request {
    pub mac_address: MacAddress,
    pub relay_address: String,
    pub vendor_string: String,
}

pub enum DhcpRequest {
    DHCPv4(Dhcpv4Request),
}

impl DhcpResponse {}
