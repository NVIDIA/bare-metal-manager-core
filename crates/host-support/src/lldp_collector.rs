use std::fs;

use ::rpc::machine_discovery as rpc_discovery;
use carbide_utils::cmd::Cmd;
use libudev::Device;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::hardware_enumeration::PCI_SUBCLASS;

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

// `lldpcli -f json0` renders every field as a JSON array of objects: simple values
// become `{ "value": "..." }`, typed ids become `{ "type": "...", "value": "..." }`,
// and — crucially — each LLDP neighbor is emitted as its own `interface` array entry
// (even multiple neighbors sharing one physical port), which (the older) map-keyed
// `-f json` format could not represent.

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpValue {
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpId {
    #[serde(rename = "type")]
    pub id_type: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct LldpChassis {
    #[serde(default)]
    pub id: Vec<LldpId>,
    #[serde(default)]
    pub name: Vec<LldpValue>,
    #[serde(default)]
    pub descr: Vec<LldpValue>,
    #[serde(rename = "mgmt-ip", default)]
    pub mgmt_ip: Vec<LldpValue>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct LldpPort {
    #[serde(default)]
    pub id: Vec<LldpId>,
    #[serde(default)]
    pub descr: Vec<LldpValue>,
    #[serde(default)]
    pub ttl: Vec<LldpValue>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpInterfaceEntry {
    pub name: String, // local interface name (host side)
    #[serde(default)]
    pub chassis: Vec<LldpChassis>,
    #[serde(default)]
    pub port: Vec<LldpPort>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct LldpRoot {
    #[serde(default)]
    pub interface: Vec<LldpInterfaceEntry>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct LldpResponse {
    #[serde(default)]
    pub lldp: Vec<LldpRoot>,
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
        out.extend(
            lldp_for_device(&device)
                .into_iter()
                .map(|lldp| (mac.clone(), lldp)),
        );
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

/// Best-effort LLDP neighbors for a net device's kernel interface name.
///
/// Returns an empty vec when the device has no kernel name, `lldpd`/`lldpcli` is
/// unavailable, or no neighbor is advertised on the port. A single physical port
/// may report several neighbors, hence a `Vec`. Never blocks (a single `lldpcli`
/// query per interface, unlike `wait_until_all_ports_available`).
fn lldp_for_device(device: &Device) -> Vec<rpc_discovery::LldpSwitchData> {
    let Some(ifname) = device.sysname().and_then(|s| s.to_str()) else {
        return Vec::new();
    };
    match get_port_lldp_info(ifname) {
        Ok(lldp) => lldp,
        Err(e) => {
            tracing::debug!(ifname, "no LLDP neighbor: {e}");
            Vec::new()
        }
    }
}

/// Get raw `lldpcli -f json0` output for a port.
pub fn get_lldp_port_info(port: &str) -> LldpCollectorResult<String> {
    let lldp_cmd = format!("lldpcli -f json0 show neighbors ports {port}");
    Cmd::new("bash")
        .args(vec!["-c", lldp_cmd.as_str()])
        .output()
        .map_err(|e| {
            warn!("Could not discover LLDP peer for {port}, {e}");
            LldpCollectorError::Lldp(e.to_string())
        })
}

/// query lldp info for a port, translate to simpler tor structs for discovery info.
///
/// Returns an empty vec when the port advertises no LLDP neighbor.
pub fn get_port_lldp_info(port: &str) -> LldpCollectorResult<Vec<rpc_discovery::LldpSwitchData>> {
    parse_port_lldp(&get_lldp_port_info(port)?)
}

/// Parse `lldpcli -f json0` output into one `LldpSwitchData` per neighbor.
///
/// Each `lldp[].interface[]` entry is a distinct neighbor. Entries advertising no
/// chassis are skipped; missing id/description/mgmt-ip degrade to empty values.
fn parse_port_lldp(lldp_json: &str) -> LldpCollectorResult<Vec<rpc_discovery::LldpSwitchData>> {
    let lldp_resp: LldpResponse = serde_json::from_str(lldp_json).map_err(|e| {
        warn!("Could not deserialize LLDP response {lldp_json}, {e}");
        LldpCollectorError::Lldp(e.to_string())
    })?;

    let mut neighbors = Vec::new();
    for entry in lldp_resp.lldp.iter().flat_map(|root| root.interface.iter()) {
        let Some(chassis) = entry.chassis.first() else {
            debug!("No LLDP chassis data for port {}", entry.name);
            continue;
        };

        let (id_type, id_value) = chassis
            .id
            .first()
            .map(|id| (id.id_type.clone(), id.value.clone()))
            .unwrap_or_default();
        let (remote_port_type, remote_port_value) = entry
            .port
            .first()
            .and_then(|port| port.id.first())
            .map(|id| (id.id_type.clone(), id.value.clone()))
            .unwrap_or_default();

        // The `deprecated` allow keeps the legacy combined `id`/`remote_port`
        // strings populated for backward compatibility until consumers migrate
        // to the split *_type/*_value fields.
        #[allow(deprecated)]
        neighbors.push(rpc_discovery::LldpSwitchData {
            name: chassis
                .name
                .first()
                .map(|n| n.value.clone())
                .unwrap_or_default(),
            id: format!("{id_type}={id_value}"),
            description: chassis
                .descr
                .first()
                .map(|d| d.value.clone())
                .unwrap_or_default(),
            local_port: entry.name.clone(),
            ip_address: chassis.mgmt_ip.iter().map(|ip| ip.value.clone()).collect(),
            remote_port: format!("{remote_port_type}={remote_port_value}"),
            id_type,
            id_value,
            remote_port_type,
            remote_port_value,
        });
    }

    Ok(neighbors)
}

#[cfg(test)]
mod tests {
    use super::parse_port_lldp;

    // Three LLDP neighbors on a single physical port (`vlldp`). `-f json0` emits
    // each as its own `interface` array entry, so `parse_port_lldp` must yield one
    // `LldpSwitchData` per entry, in order, with no mgmt-ip or description.
    const MULTI_NEIGHBOR: &str = r#"{
      "lldp": [
        { "interface": [
          { "name": "vlldp", "chassis": [
              { "id": [{"type":"local","value":"host-00"}], "name": [{"value":"neighbor-00"}] }],
            "port": [{ "id": [{"type":"ifname","value":"port-00"}], "ttl": [{"value":"120"}] }] },
          { "name": "vlldp", "chassis": [
              { "id": [{"type":"local","value":"host-01"}], "name": [{"value":"neighbor-01"}] }],
            "port": [{ "id": [{"type":"ifname","value":"port-01"}], "ttl": [{"value":"120"}] }] },
          { "name": "vlldp", "chassis": [
              { "id": [{"type":"local","value":"host-02"}], "name": [{"value":"neighbor-02"}] }],
            "port": [{ "id": [{"type":"ifname","value":"port-02"}], "ttl": [{"value":"120"}] }] }
        ] }
      ]
    }"#;

    // Single neighbor carrying two mgmt-ips (v4 + v6) and a description — the shape
    // of a real `lldpcli -f json0 show neighbors ports p0`.
    const SINGLE_NEIGHBOR: &str = r#"{
      "lldp": [
        { "interface": [
          { "name": "p0", "chassis": [
              { "id": [{"type":"mac","value":"00:11:22:33:44:55"}],
                "name": [{"value":"example-switch-01"}],
                "descr": [{"value":"Cumulus Linux version 5.11.1 running on Mellanox switch"}],
                "mgmt-ip": [{"value":"192.0.2.10"},{"value":"2001:db8::10"}] }],
            "port": [{ "id": [{"type":"ifname","value":"swp2"}], "ttl": [{"value":"120"}] }] }
        ] }
      ]
    }"#;

    #[test]
    #[allow(deprecated)]
    fn parses_multiple_neighbors_on_one_port() {
        let neighbors = parse_port_lldp(MULTI_NEIGHBOR).expect("parse");
        assert_eq!(neighbors.len(), 3);
        for (i, n) in neighbors.iter().enumerate() {
            assert_eq!(n.name, format!("neighbor-0{i}"));
            // split fields plus the legacy combined strings
            assert_eq!(n.id_type, "local");
            assert_eq!(n.id_value, format!("host-0{i}"));
            assert_eq!(n.id, format!("local=host-0{i}"));
            assert_eq!(n.remote_port_type, "ifname");
            assert_eq!(n.remote_port_value, format!("port-0{i}"));
            assert_eq!(n.remote_port, format!("ifname=port-0{i}"));
            assert_eq!(n.local_port, "vlldp");
            assert!(n.ip_address.is_empty());
            assert!(n.description.is_empty());
        }
    }

    #[test]
    #[allow(deprecated)]
    fn parses_single_neighbor_with_mgmt_ips() {
        let neighbors = parse_port_lldp(SINGLE_NEIGHBOR).expect("parse");
        assert_eq!(neighbors.len(), 1);
        let n = &neighbors[0];
        assert_eq!(n.name, "example-switch-01");
        assert_eq!(n.id_type, "mac");
        assert_eq!(n.id_value, "00:11:22:33:44:55");
        assert_eq!(n.id, "mac=00:11:22:33:44:55");
        assert_eq!(n.local_port, "p0");
        assert_eq!(n.remote_port_type, "ifname");
        assert_eq!(n.remote_port_value, "swp2");
        assert_eq!(n.remote_port, "ifname=swp2");
        assert_eq!(n.ip_address, vec!["192.0.2.10", "2001:db8::10"]);
        assert!(n.description.contains("Cumulus Linux"));
    }

    #[test]
    fn parses_no_neighbors_as_empty() {
        let neighbors = parse_port_lldp(r#"{"lldp":[{"interface":[]}]}"#).expect("parse");
        assert!(neighbors.is_empty());
    }
}
