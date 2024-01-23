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
            L2VNI: network.vni.map(|x| x.to_string()).unwrap_or("".to_string()),
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

// Apply the config at `config_path`.
pub async fn apply(
    hbn_root: &Path,
    config_path: &Path,
    path_bak: &Path,
    path_tmp: &Path,
) -> eyre::Result<()> {
    match run_apply(hbn_root, config_path).await {
        Ok(_) => {
            if path_bak.exists() {
                if let Err(err) = fs::remove_file(path_bak) {
                    eyre::bail!("remove .BAK on success {}: {err:#}", path_bak.display());
                }
            }
            Ok(())
        }
        Err(err) => {
            tracing::error!("update_nvue post command failed: {err:#}");

            // If apply failed we won't be using the new config. Move it out of the way..
            if let Err(err) = fs::rename(config_path, path_tmp) {
                eyre::bail!(
                    "rename {} to {} on error: {err:#}",
                    config_path.display(),
                    path_tmp.display()
                );
            }
            // .. and copy the old one back.
            // This also ensures that we retry writing the config on subsequent runs.
            if path_bak.exists() {
                if let Err(err) = fs::rename(path_bak, config_path) {
                    eyre::bail!(
                        "rename {} to {}, reverting on error: {err:#}",
                        path_bak.display(),
                        config_path.display()
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
    // Set this config as the pending one. This is where we'd get yaml parse errors and
    // other validation errors.
    super::hbn::run_in_container_shell(&format!(
        "nv config replace {}",
        in_container_path.display()
    ))
    .await?;
    // Apply the pending config
    super::hbn::run_in_container_shell("nv config apply -y").await?;
    // Persist the config to disk
    super::hbn::run_in_container_shell("nv config save").await
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
    pub vni: Option<u32>, // admin network doens't haven one
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
    /// Empty string if no tenant
    L2VNI: String, // Previously called VNIDevice
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
