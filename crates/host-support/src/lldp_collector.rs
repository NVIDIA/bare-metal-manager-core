use crate::hardware_enumeration::PCI_SUBCLASS;
use ::rpc::machine_discovery as rpc_discovery;
use carbide_utils::cmd::Cmd;
use libudev::Device;
use serde::{Deserialize, Serialize};
use serde_with::{OneOrMany, serde_as};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use tracing::{debug, warn};

#[derive(thiserror::Error, Debug)]
pub enum LldpCollectorError {
    #[error("Udev failed with error: {0}")]
    Udev(#[from] libudev::Error),
    #[error("LLDP collection failed reading '{0}': {1}")]
    Read(&'static str, String),
    #[error("LLDP error: {0}")]
    Lldp(String),
}

pub type LldpCollectorResult<T> = Result<T, LldpCollectorError>;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpCapabilityData {
    #[serde(rename = "type")]
    pub capability_type: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpIdData {
    #[serde(rename = "type")]
    pub id_type: String,
    pub value: String,
}

#[serde_as]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpChassisData {
    pub id: LldpIdData,
    pub descr: String,
    #[serde(rename = "mgmt-ip", default)]
    #[serde_as(as = "OneOrMany<_>")]
    pub management_ip_address: Vec<IpAddr>, // we get an array with ipv4 and ipv6 addresses
    #[serde(default)]
    pub capability: Vec<LldpCapabilityData>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpPortData {
    pub id: LldpIdData,
    pub descr: Option<String>,
    pub ttl: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpQueryData {
    pub age: String,
    pub chassis: HashMap<String, LldpChassisData>, // the key in this hash is the tor name
    pub port: LldpPortData,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpInterface {
    pub interface: HashMap<String, LldpQueryData>, // the key in this hash is the port #, eg. p0
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpResponse {
    pub lldp: LldpInterface,
}

/// Lightweight per-interface LLDP snapshot for periodic reporting (host + DPU).
///
/// Enumerates Ethernet net interfaces and returns `(local_mac, neighbor)` pairs
/// for every interface that currently has an LLDP neighbor. Interfaces without a
/// neighbor (or when lldpd is unavailable) are omitted, (todo loopback omit) so a full-snapshot report
/// lets the server reconcile (drop) interfaces whose neighbor disappeared.
///
/// This is intentionally cheap so it can run on a short interval.
pub fn collect_lldp_neighbors() -> LldpCollectorResult<Vec<(String, rpc_discovery::LldpSwitchData)>>
{
    let context = libudev::Context::new()?;
    let mut enumerator = libudev::Enumerator::new(&context)?;
    enumerator.match_subsystem("net")?;

    let mut out = Vec::new();
    for device in enumerator.scan_devices()? {
        let Ok(pci_subclass) =
            crate::hardware_enumeration::convert_property_to_string(PCI_SUBCLASS, "", &device)
        else {
            continue;
        };
        if !pci_subclass.eq_ignore_ascii_case("Ethernet controller") {
            continue;
        }
        let Some(ifname) = device.sysname().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(mac) = read_interface_mac(ifname) else {
            continue;
        };
        if let Some(lldp) = lldp_for_device(&device) {
            out.push((mac, lldp));
        }
    }
    Ok(out)
}

/// Collect the LLDP neighbors visible on this host and print them. Purely local
/// interrogation for troubleshooting: no API integration, mirrors what
/// `report_lldp_neighbors` would send to carbide-api.
pub fn print_lldp_neighbors() -> Result<(), eyre::Report> {
    let pairs = collect_lldp_neighbors().map_err(|e| eyre::eyre!("lldp collect: {e}"))?;

    if pairs.is_empty() {
        println!("No LLDP neighbors found.");
        return Ok(());
    }

    for (mac_address, lldp) in pairs {
        println!("{mac_address}: {lldp:#?}");
    }
    Ok(())
}

fn read_interface_mac(ifname: &str) -> Option<String> {
    let mac = fs::read_to_string(format!("/sys/class/net/{ifname}/address")).ok()?;
    let mac = mac.trim();
    if mac.is_empty() {
        return None;
    }
    Some(mac.to_string())
}

/// Best-effort LLDP neighbor for a net device's kernel interface name.
///
/// Returns `None` when the device has no kernel name, `lldpd`/`lldpcli` is
/// unavailable, or no neighbor is advertised on the port. Never blocks (a single
/// `lldpcli` query per interface, unlike `wait_until_all_ports_available`).
fn lldp_for_device(device: &Device) -> Option<rpc_discovery::LldpSwitchData> {
    let ifname = device.sysname()?.to_str()?;
    match get_port_lldp_info(ifname) {
        Ok(lldp) => lldp,
        Err(e) => {
            tracing::debug!(ifname, "no LLDP neighbor: {e}");
            None
        }
    }
}

/// Get LLDP port info.
pub fn get_lldp_port_info(port: &str) -> LldpCollectorResult<String> {
    if cfg!(test) {
        const TEST_DATA: &str = "test/lldp_query.json";
        std::fs::read_to_string(TEST_DATA).map_err(|e| {
            warn!("Could not read LLDP json: {e}");
            LldpCollectorError::Read(TEST_DATA, e.to_string())
        })
    } else {
        let lldp_cmd = format!("lldpcli -f json show neighbors ports {port}");
        Cmd::new("bash")
            .args(vec!["-c", lldp_cmd.as_str()])
            .output()
            .map_err(|e| {
                warn!("Could not discover LLDP peer for {port}, {e}");
                LldpCollectorError::Lldp(e.to_string())
            })
    }
}

/// query lldp info for a port, translate to simpler tor struct for discovery info.
///
/// Returns `Ok(None)` when the port advertises no LLDP neighbor.
pub fn get_port_lldp_info(
    port: &str,
) -> LldpCollectorResult<Option<rpc_discovery::LldpSwitchData>> {
    let lldp_json: String = get_lldp_port_info(port)?;

    // deserialize
    let lldp_resp: LldpResponse = match serde_json::from_str(lldp_json.as_str()) {
        Ok(x) => x,
        Err(e) => {
            warn!("Could not deserialize LLDP response {lldp_json}, {e}");
            return Err(LldpCollectorError::Lldp(e.to_string()));
        }
    };

    let mut lldp_info: rpc_discovery::LldpSwitchData = Default::default();
    // copy over useful fields
    if let Some(lldp_data) = lldp_resp.lldp.interface.get(port) {
        for (tor, tor_data) in lldp_data.chassis.iter() {
            lldp_info.name = tor.to_string();
            lldp_info.id = format!("{}={}", tor_data.id.id_type, tor_data.id.value);
            lldp_info.description = tor_data.descr.to_string();
            lldp_info.local_port = port.to_string();

            // management_ip_address if missing we just replace it with empty list.
            lldp_info.ip_address = tor_data
                .management_ip_address
                .iter()
                .map(|ip| ip.to_string())
                .collect();
        }
        lldp_info.remote_port =
            format!("{}={}", lldp_data.port.id.id_type, lldp_data.port.id.value);
    } else {
        debug!("No LLDP switch data for port {port}");
        return Ok(None);
    }

    Ok(Some(lldp_info))
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::scenarios;

    use super::get_port_lldp_info;

    // `get_port_lldp_info` reads the `test/lldp_query.json` fixture (in `cfg(test)`
    // it ignores the live `lldpcli` command) and then looks the requested port up
    // in `lldp.interface`. The lookup, the `OneOrMany` mgmt-ip flattening, and the
    // tor/port field formatting are all pure given that fixture, so we pin the
    // facts each known port produces and the not-found rejection path.
    //
    // The yielded value for each row is `(first_ip, ip_count, name, remote_port)`.
    #[test]
    fn get_port_lldp_info_translates_fixture() {
        scenarios!(
            run = |port| {
                let info = get_port_lldp_info(port).map_err(drop)?.ok_or(())?;
                let first_ip = info.ip_address.first().cloned().unwrap_or_default();
                Ok::<_, ()>((first_ip, info.ip_address.len(), info.name, info.remote_port))
            };
            "oob_net0: single (scalar) mgmt-ip" {
                "oob_net0" => Yields((
                    "10.180.253.66".to_string(),
                    1,
                    "RNO1-M03-B17-IPMI-01".to_string(),
                    "ifname=swp7".to_string(),
                )),
            }

            "p0: array mgmt-ip keeps first (v4) and counts both" {
                "p0" => Yields((
                    "10.180.253.67".to_string(),
                    2,
                    "RNO1-M03-B17-IPMI-01".to_string(),
                    "ifname=swp7".to_string(),
                )),
            }

            "p1: distinct array mgmt-ip, first is v4" {
                "p1" => Yields((
                    "10.180.253.66".to_string(),
                    2,
                    "RNO1-M03-B17-IPMI-01".to_string(),
                    "ifname=swp7".to_string(),
                )),
            }

            "unknown port: not present in the fixture interface map" {
                "p99" => Fails,
            }

            "empty port name: also absent" {
                "" => Fails,
            }
        );
    }

    // The tor-id and description formatting on the resolved switch is its own
    // contract: `id` is rendered `"{id_type}={value}"` and `description`/`local_port`
    // are copied verbatim. Token-contains keeps this robust to fixture churn.
    //
    // The yielded value is whether every expected token appears in the rendered field.
    #[test]
    fn get_port_lldp_info_formats_fields() {
        scenarios!(
            run = |(port, tokens): (&str, &[&str])| {
                let info = get_port_lldp_info(port).map_err(drop)?.ok_or(())?;
                // Concatenate the formatted fields this row may inspect; every token
                // must appear somewhere across id / description / local_port.
                let haystack = format!("{} {} {}", info.id, info.description, info.local_port);
                Ok::<_, ()>(tokens.iter().all(|t| haystack.contains(t)))
            };
            "id renders mac type=value for oob_net0" {
                ("oob_net0", &["mac=", "0c:29:ef:d9:1c:20"][..]) => Yields(true),
            }

            "description carried verbatim for p0" {
                ("p0", &["Cumulus Linux", "DELL S3048ON"][..]) => Yields(true),
            }

            "local_port echoes the requested port" {
                ("p1", &["p1"][..]) => Yields(true),
            }
        );
    }
}
