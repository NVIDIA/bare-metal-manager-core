/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use gtmpl_derive::Gtmpl;
use serde::Deserialize;

pub const PATH: &str = "etc/nvue.d/startup.yaml";

const TMPL_FULL: &str = include_str!("../templates/nvue_startup.conf");

pub fn build(conf: NvueConfig) -> eyre::Result<String> {
    let mut l3_domains = Vec::with_capacity(conf.l3_domains.len());
    for d in conf.l3_domains {
        l3_domains.push(TmplL3Domain {
            Name: d.name,
            Services: d.services.clone(),
        });
    }
    let infra = vec![TmplInfra {
        L3Domains: l3_domains,
    }];

    let mut port_configs = Vec::with_capacity(conf.ct_port_configs.len());
    for network in conf.ct_port_configs {
        port_configs.push(TmplConfigPort {
            Name: network.interface_name.clone(),
            VlanID: network.vlan,
            L2VNI: network.vni,
            IP: network.gateway_cidr.clone(),
            SviIP: "".to_string(),  // FNN only
            VrrMAC: "".to_string(), // FNN only
        });
    }

    let params = TmplNvue {
        IsFNN: false,
        LoopbackIP: conf.loopback_ip,
        ASN: conf.asn,
        DPUHostname: conf.dpu_hostname,
        Uplinks: conf.uplinks.clone(),
        RouteServers: conf.route_servers.clone(),
        DHCPServers: conf.dhcp_servers.clone(),
        Infrastructure: infra,
        ComputeTENANTs: vec![TmplComputeTenant {
            Name: conf.ct_name,
            L3VNI: conf.ct_l3_vni,
            VRFloopback: conf.ct_vrf_loopback,
            PortConfigs: port_configs,
            ExternalAccess: conf.ct_external_access,
        }],
    };
    gtmpl::template(TMPL_FULL, params).map_err(|e| e.into())
}

// What we need to configure NVUE
pub struct NvueConfig {
    pub loopback_ip: String,
    pub asn: u32,
    pub dpu_hostname: String,
    pub uplinks: Vec<String>,
    pub route_servers: Vec<String>,
    pub dhcp_servers: Vec<String>,
    pub l3_domains: Vec<L3Domain>,

    // Currently we have a single tenant. Later this will be Vec<ComputeTenant>
    pub ct_name: String,
    pub ct_l3_vni: String,
    pub ct_vrf_loopback: String,
    pub ct_port_configs: Vec<PortConfig>,
    pub ct_external_access: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct L3Domain {
    pub name: String,
    pub services: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct PortConfig {
    pub interface_name: String,
    pub vlan: u16,
    pub vni: u32,
    pub gateway_cidr: String,
}

//
// Go template objects, hence allow(non_snake_case)
//

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplNvue {
    IsFNN: bool,
    LoopbackIP: String,
    ASN: u32,
    DPUHostname: String,
    Uplinks: Vec<String>,
    RouteServers: Vec<String>,

    /// Format: IPv4 address of (per tenant) dhcp server
    DHCPServers: Vec<String>, // Previously 'Servers'

    // A structure to hold infra wide information to be used in the configuration. It would need
    // to hold multiple levels.
    Infrastructure: Vec<TmplInfra>,

    /// For when we have more than one tenant
    ComputeTENANTs: Vec<TmplComputeTenant>,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplComputeTenant {
    /// Tenant name/id with a max of 15 chars, because it's also used for the interface name.
    /// Linux is limited to 15 chars for interface names.
    Name: String,
    L3VNI: String,
    VRFloopback: String,
    PortConfigs: Vec<TmplConfigPort>,

    /// Per tenant access to external networks needs to be defined. Based on this route leaking
    /// will occur to the specific tenant VRFs.
    /// Format: Slice with strings equal to {{ .L3domain }}
    ExternalAccess: Vec<String>,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplConfigPort {
    Name: String,
    VlanID: u16,

    /// Format: 24bit integer (usable range: 4096 to 16777215).
    L2VNI: u32, // Previously called VNIDevice
    IP: String, // with mask, 1.1.1.1/20

    /// In a symmetrical EVPN configuration, an SVI (vlan interfaces) requires a separate IP that
    /// is not the gateway address. Typically the 2nd usable ip in the prefix is being used,
    /// e.g 10.1.1.2 in the 10.1.1.0/24 prefix.
    /// Format: Standard IPv4 notation
    SviIP: String,

    /// VRR, the distributed gateway, needs a manually defined mac address. This can be overlapping
    /// on the different VTEPs, but it is very convenient to be unique on the same VTEP.
    /// Format: 48bit mac address in standard hex notation, e.g: 00:00:00:00:00:10
    VrrMAC: String,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplInfra {
    /// Information to configure L3VNIs and the details of it
    L3Domains: Vec<TmplL3Domain>,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplL3Domain {
    Name: String,
    Services: Vec<String>,
}
