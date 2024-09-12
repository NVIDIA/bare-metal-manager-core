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

use std::fs;
use std::path::Path;

use eyre::WrapErr;
use forge_network::{sanitized_mac, virtualization::VpcVirtualizationType};
use gtmpl_derive::Gtmpl;
use mac_address::MacAddress;
use serde::Deserialize;

pub const PATH: &str = "var/support/nvue_startup.yaml";
pub const SAVE_PATH: &str = "etc/nvue.d/startup.yaml";
pub const PATH_ACL: &str = "etc/cumulus/acl/policy.d/70-forge_nvue.rules";

const TMPL_ETV_WITH_NVUE: &str = include_str!("../templates/nvue_startup_etv.conf");
const TMPL_FNN_CLASSIC: &str = include_str!("../templates/nvue_startup_fnn_classic.conf");
const TMPL_FNN_L3: &str = include_str!("../templates/nvue_startup_fnn_l3.conf");

pub fn build(conf: NvueConfig) -> eyre::Result<String> {
    if !conf.vpc_virtualization_type.supports_nvue() {
        return Err(eyre::eyre!(
            "cannot nvue::build. provided virtualizaton type does not support nvue: {}",
            conf.vpc_virtualization_type,
        ));
    }

    let mut l3_domains = Vec::with_capacity(conf.l3_domains.len());
    for d in conf.l3_domains {
        l3_domains.push(TmplL3Domain {
            L3DomainName: d.l3_domain_name,
            Services: d.services.clone(),
        });
    }
    let infra = vec![TmplInfra {
        L3Domains: l3_domains,
    }];

    let mut port_configs = Vec::with_capacity(conf.ct_port_configs.len());

    for (base_i, network) in conf.ct_port_configs.into_iter().enumerate() {
        let svi_mac = vni_to_svi_mac(network.vni.unwrap_or(0))?.to_string();
        port_configs.push(TmplConfigPort {
            InterfaceName: network.interface_name.clone(),
            Index: format!("{}", (base_i + 1) * 10),
            VlanID: network.vlan,
            L2VNI: network.vni.map(|x| x.to_string()).unwrap_or("".to_string()),
            IP: network.gateway_cidr.clone(),
            SviIP: network.svi_ip.unwrap_or("".to_string()), // FNN only
            SviMAC: svi_mac,
            VrfLoopback: network.tenant_vrf_loopback_ip.unwrap_or_default(),
            VpcPrefixes: network
                .vpc_prefixes
                .iter()
                .enumerate()
                .map(|(i, prefix)| Prefix {
                    Index: format!("{}", (base_i + 1) * 10 + i),
                    Prefix: prefix.to_string(),
                })
                .collect(),
            StorageTarget: false, // XXX (Classic, L3)
        });
    }

    // TODO(chet): So the VrfLoopback comes from a /30 interface allocation,
    // which should be in `PortConfigs`, but in the template its one level
    // up. Basically what this is saying is L3 templates can only support
    // a single "address" right now, and a customer can't configure Additional
    // Subnets. This needs to be addressed before we actually launch FNN,
    // but for now, just pluck port_configs[0].
    let vrf_loopback = match conf.vpc_virtualization_type {
        VpcVirtualizationType::FnnL3 => {
            if port_configs.is_empty() {
                return Err(eyre::eyre!(
                    "cannot configure VrfLoopback; no address allocations",
                ));
            }
            if port_configs.len() > 1 {
                return Err(eyre::eyre!(
                    "cannot configure VrfLoopback; expected only one address allocation",
                ));
            }
            port_configs[0].VrfLoopback.clone()
        }
        // TODO(chet): We need to figure out where this IP will come from.
        VpcVirtualizationType::FnnClassic => "FNN".to_string(),
        // unused by other virtualization types
        _ => "".to_string(),
    };

    let params = TmplNvue {
        UseAdminNetwork: conf.use_admin_network,
        LoopbackIP: conf.loopback_ip,
        ASN: conf.asn,
        DPUHostname: conf.dpu_hostname,
        SearchDomain: conf.dpu_search_domain,
        Uplinks: conf.uplinks.clone(),
        RouteServers: conf.route_servers.clone(),
        UseLocalDHCP: conf.use_local_dhcp,
        DHCPServers: conf.dhcp_servers.clone(),
        DenyPrefixes: conf
            .deny_prefixes
            .iter()
            .enumerate()
            .map(|(i, s)| Prefix {
                Index: format!("{}", 1000 + i),
                Prefix: s.to_string(),
            })
            .collect(),
        Infrastructure: infra,
        HbnVersion: conf.hbn_version,
        ComputeTENANTs: vec![TmplComputeTenant {
            VrfName: conf.ct_vrf_name,
            L3VNI: conf.ct_l3_vni.unwrap_or_default().to_string(),
            l3vniVLAN: 0, // unused -- TODO(chet): unique per DPU within a VPC
            VrfLoopback: vrf_loopback,
            PortConfigs: port_configs,
            ExternalAccess: conf.ct_external_access,
            AccessVLANs: conf
                .ct_access_vlans
                .into_iter()
                .map(|vl| TmplConfigVLAN {
                    ID: vl.vlan_id,
                    HostIP: vl.ip,
                    HostRoute: vl.network,
                })
                .collect(),
        }],
        InternetL3VNI: conf.ct_internet_l3_vni.unwrap_or_default(),
        // XXX: Unused placeholders for later.
        StorageTarget: false,                         // XXX (Classic, L3)
        StorageDpuIP: "127.9.9.9".to_string(),        // XXX (Classic, L3)
        l3vnistorageVLAN: "vlan1337".to_string(),     // XXX (Classic, L3)
        StorageL3VNI: 0,                              // XXX (Classic, L3)
        StorageLoopback: "127.8.8.8".to_string(),     // XXX (Classic, L3)
        DPUstorageprefix: "127.7.7.7/32".to_string(), // XXX (Classic, L3)
    };

    // Returns the full content of the nvue template for the forge-dpu-agent
    // to load for the given virtualization type. Since `EthernetVirtualizer`
    // (non-nvue) is still in the mix, this is an Option<String>. However, once
    // we're fully moved away from ETV (and everything is nvue), this can simply
    // become a String.
    let virtualization_template = match conf.vpc_virtualization_type {
        VpcVirtualizationType::EthernetVirtualizer => None,
        VpcVirtualizationType::EthernetVirtualizerWithNvue => Some(TMPL_ETV_WITH_NVUE),
        VpcVirtualizationType::FnnClassic => Some(TMPL_FNN_CLASSIC),
        VpcVirtualizationType::FnnL3 => Some(TMPL_FNN_L3),
    };

    if let Some(template) = virtualization_template {
        gtmpl::template(template, params).map_err(|e| {
            println!("ERR filling template: {}", e,);
            e.into()
        })
    } else {
        Err(eyre::eyre!(
            "cannot nvue::build. no nvue template configured for virtualization type: {}",
            conf.vpc_virtualization_type
        ))
    }
}

// Apply the config at `config_path`.
pub async fn apply(hbn_root: &Path, config_path: &super::FPath) -> eyre::Result<()> {
    match run_apply(hbn_root, &config_path.0).await {
        Ok(_) => {
            config_path.del("BAK");
            Ok(())
        }
        Err(err) => {
            tracing::error!("update_nvue post command failed: {err:#}");

            // If the config apply failed, we won't be using it, so move it out
            // of the way to an .error file for others to enjoy (while attempting
            // to remove any previous .error file in the process).
            let path_error = config_path.with_ext(".error");
            if path_error.exists() {
                if let Err(e) = fs::remove_file(path_error.clone()) {
                    tracing::warn!(
                        "Failed to remove previous error file ({}): {e}",
                        path_error.display()
                    );
                }
            }

            if let Err(err) = fs::rename(config_path, &path_error) {
                eyre::bail!(
                    "rename {config_path} to {} on error: {err:#}",
                    path_error.display()
                );
            }
            // .. and copy the old one back.
            // This also ensures that we retry writing the config on subsequent runs.
            let path_bak = config_path.backup();
            if path_bak.exists() {
                if let Err(err) = fs::rename(&path_bak, config_path) {
                    eyre::bail!(
                        "rename {} to {config_path}, reverting on error: {err:#}",
                        path_bak.display(),
                    );
                }
            }

            Err(err)
        }
    }
}

// Ask NVUE to use the config at `path`
async fn run_apply(hbn_root: &Path, path: &Path) -> eyre::Result<()> {
    let mut in_container_path = path
        .strip_prefix(hbn_root)
        .wrap_err("Stripping hbn_root prefix from path to make in-container path")?
        .to_path_buf();
    // If hbn_root ends with "/", the stripped path will have it removed from start. Add back.
    if !in_container_path.has_root() {
        in_container_path = Path::new("/").join(in_container_path);
    }
    let container_id = super::hbn::get_hbn_container_id().await?;

    // Set this config as the pending one. This is where we'd get yaml parse errors and
    // other validation errors. Stores the pending config internally somewhere.
    let stdout = super::hbn::run_in_container(
        &container_id,
        &[
            "nv",
            "config",
            "replace",
            &in_container_path.to_string_lossy(),
        ],
        true,
    )
    .await?;
    if !stdout.is_empty() {
        tracing::info!("nv config replace: {stdout}");
    }

    // Apply the pending config.
    //
    // - Writes:
    //   . /etc/frr/frr.conf
    //   . /etc/network/interfaces
    //   . /etc/frr/daemons
    //   . /etc/supervisor/conf.d/isc-dhcp-relay-default
    //   . and others (acls, nginx, ...)
    // - Restarts necessary services.
    // - Log is in /var/lib/hbn/var/lib/nvue/config/apply_log.txt
    // Once this returns networking should be ready to use.
    let stdout =
        super::hbn::run_in_container(&container_id, &["nv", "config", "apply", "-y"], true).await?;
    if !stdout.is_empty() {
        tracing::info!("nv config apply: {stdout}");
    }

    Ok(())
}

/// vni_to_svimac takes an VNI (which is a 24 bit integer whose range
/// is 0-16777215), pads it with zeroes (so its 12 characters long), and
/// then turns it into a MAC address for the purpose of having a consistent
/// SVI MAC address value for all DPUs in a given VPC.
///
/// e.g, an L2VNI of 1637817 would result in an SviMAC of 00:00:01:63:78:17
/// for all DPUs in the VPC.
fn vni_to_svi_mac(vni: u32) -> eyre::Result<MacAddress> {
    sanitized_mac(format!("{:012}", vni))
}

// What we need to configure NVUE
pub struct NvueConfig {
    pub is_fnn: bool,
    pub vpc_virtualization_type: VpcVirtualizationType,
    pub use_admin_network: bool,
    pub loopback_ip: String,
    pub asn: u32,
    pub dpu_hostname: String,
    pub dpu_search_domain: String,
    pub hbn_version: Option<String>,
    pub uplinks: Vec<String>,
    pub route_servers: Vec<String>,
    pub dhcp_servers: Vec<String>,
    pub l3_domains: Vec<L3Domain>,
    pub use_local_dhcp: bool,
    pub deny_prefixes: Vec<String>,

    // Currently we have a single tenant, hence the single ct_ prefix.
    // Later this will be Vec<ComputeTenant>.

    // ct_vrf_name is the VRF name. This value needs to be 15 characters
    // or less, somehow derived from the VPC, and is the same for all
    // DPUs in a VPC. To achieve this, we currently take the L3VNI of the
    // VPC, and assign this as "vrf_<l3vni>". This ensures we keep the
    // character count below 15, and by using the L3VNI, we're able to
    // directly correlate that back to the VPC.
    pub ct_vrf_name: String,
    pub ct_l3_vni: Option<u32>,
    pub ct_vrf_loopback: String,
    pub ct_port_configs: Vec<PortConfig>,
    pub ct_external_access: Vec<String>,
    pub ct_access_vlans: Vec<VlanConfig>,
    pub ct_internet_l3_vni: Option<u32>,
}

pub struct VlanConfig {
    pub vlan_id: u32,
    pub network: String,
    pub ip: String,
}

#[derive(Deserialize, Debug)]
pub struct L3Domain {
    pub l3_domain_name: String,
    pub services: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct PortConfig {
    pub interface_name: String,
    pub vlan: u16,
    pub vni: Option<u32>,    // admin network doesn't have one
    pub l3_vni: Option<u32>, // admin network doesn't have one
    pub gateway_cidr: String,
    pub vpc_prefixes: Vec<String>,
    pub svi_ip: Option<String>,
    pub tenant_vrf_loopback_ip: Option<String>,
}

//
// Go template objects, hence allow(non_snake_case)
//

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplNvue {
    UseAdminNetwork: bool, // akak service network
    LoopbackIP: String,
    ASN: u32,
    DPUHostname: String,  // The first part of the FQDN
    SearchDomain: String, // The rest of the FQDN
    Uplinks: Vec<String>,
    RouteServers: Vec<String>,

    // true to use dhcp-server in HBN container (new)
    // false to use dhcp-relay (old)
    UseLocalDHCP: bool,

    /// Format: IPv4 address of (per tenant) dhcp server
    DHCPServers: Vec<String>, // Previously 'Servers'

    /// Format: CIDR of the infastructure prefixes to block. Origin is carbide-api config file.
    DenyPrefixes: Vec<Prefix>,

    HbnVersion: Option<String>,

    // A structure to hold infra wide information to be used in the configuration. It would need
    // to hold multiple levels.
    Infrastructure: Vec<TmplInfra>,

    /// For when we have more than one tenant
    ComputeTENANTs: Vec<TmplComputeTenant>,

    // InternetL3VNI is the side-wide GNI-supplied VNI to use so VPCs
    // can access the Internet. This is sent down via the internet_l3_vni
    // field from the ManagedHostNetworkConfigResponse as an optional
    // value, and defaults to 0 if unset.
    InternetL3VNI: u32,

    // XXX: These are unused placeholders for later.
    // StorageDpuIP is an interface that should exist on
    // client nodes that are NOT storage targets, so in the
    // case where StorageTarget is false, we would expect
    // there to be a StorageDpuIP.
    StorageTarget: bool,      // XXX (Classic, L3)
    StorageDpuIP: String,     // XXX (Classic, L3)
    l3vnistorageVLAN: String, // XXX (Classic, L3)
    StorageL3VNI: u32,        // XXX (Classic, L3)
    StorageLoopback: String,  // XXX (Classic, L3)
    DPUstorageprefix: String, // XXX (Classic, L3)
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplComputeTenant {
    /// Tenant name/id with a max of 15 chars, because it's also used for the interface name.
    /// Linux is limited to 15 chars for interface names.
    VrfName: String,

    /// L3VNI VPC-specifc VNI, which is globally unique. GNI allocates us
    /// a pool of VNIs to assign as we see fit, so we carve out blocks
    /// per-site, and then manage them via the VPC_VNI (vpc-vni) resource
    /// pool.
    ///
    // TODO(chet): Does this need to be a string?
    L3VNI: String,

    /// XXX: unused placeholder for later. In the template, this
    /// will go right within an `evpn` block next to the `vni`
    /// config as `vlan: {{ .l3vniVLAN }}`.
    l3vniVLAN: u32,

    /// VrfLoopback is the tenant loopback IP assigned to each DPU,
    /// which is allocated from the interface-specific /30 (it's the
    /// first IP in the allocation).
    VrfLoopback: String, // XXX: This is in the Classic template -- where does the IP come from?

    PortConfigs: Vec<TmplConfigPort>,

    /// Per tenant access to external networks needs to be defined. Based on this route leaking
    /// will occur to the specific tenant VRFs.
    /// Format: Slice with strings equal to {{ .L3domain }}
    ExternalAccess: Vec<String>,

    AccessVLANs: Vec<TmplConfigVLAN>,
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Gtmpl)]
struct TmplConfigVLAN {
    ID: u32,
    HostIP: String,

    // HostRoute in the context of FNN-L3 is the /30 prefix allocation.
    // This used to be populated as the HostIP + "/32", but then with
    // the advent of interface prefix allocations (where ETV is just a /32,
    // and FNN-L3 is a /30), HostRoute became the allocation (which was
    // a drop-in replacement for ETV/Classic environments).
    HostRoute: String,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplConfigPort {
    InterfaceName: String,
    Index: String,
    VlanID: u16,

    /// Format: 24bit integer (usable range: 4096 to 16777215).
    /// Empty string if no tenant
    L2VNI: String, // Previously called VNIDevice
    IP: String, // with mask, 1.1.1.1/20

    /// In a symmetrical EVPN configuration, an SVI (vlan interfaces) requires a separate IP that
    /// is not the gateway address. Typically the 2nd usable ip in the prefix is being used,
    /// e.g 10.1.1.2 in the 10.1.1.0/24 prefix.
    /// Format: Standard IPv4 notation
    SviIP: String,

    /// VRR, the distributed gateway, needs a manually defined MAC address. This can be overlapping
    /// on the different VTEPs, but it is very convenient to be unique on the same VTEP.
    ///
    /// In other words, this is the same value for all DPUs in a given VPC.
    ///
    /// TO MAKE THIS THE SAME FOR A GIVEN VPC, we take the L2VNI (which is a 24bit integer),
    /// pad it with zeroes so its 12 characters long, and then shove some colons in there.
    ///
    /// For example, for a VPC with an L2VNI of 1683714, the SviMAC would
    /// be configured as 00:00:01:68:37:14.
    ///
    /// Format: 48bit mac address in standard hex notation, e.g: 00:00:00:00:00:10
    SviMAC: String,

    VrfLoopback: String,

    /// Tenant VPCs we should allow them to access
    VpcPrefixes: Vec<Prefix>,

    // XXX: all of these added so the L3 template can build, need
    // to really actually wire them up.
    StorageTarget: bool, // XXX (Classic, L3)
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
    L3DomainName: String,
    Services: Vec<String>,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct Prefix {
    Index: String,
    Prefix: String,
}
