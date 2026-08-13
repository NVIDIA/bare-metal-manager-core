//! Collects the LLDP neighbors this host/DPU sees by shelling out to `lldpcli`,
//! parsing its JSON, and dropping self-loopback entries.

use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ::rpc::machine_discovery as rpc_discovery;
use carbide_utils::cmd::Cmd;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

#[derive(thiserror::Error, Debug)]
pub enum LldpCollectorError {
    #[error("LLDP error: {0}")]
    Lldp(String),
}

pub type LldpCollectorResult<T> = Result<T, LldpCollectorError>;

const LLDP_SNAPSHOT_ROOT: &str = "/data/lldp";
const LLDP_SNAPSHOT_MAX_AGE: Duration = Duration::from_secs(5 * 60);

/// One LLDP neighbor plus the MAC of the local interface that sees it.
#[derive(Debug, Clone)]
pub struct LldpNeighbor {
    pub local_mac: String,
    pub switch: rpc_discovery::LldpSwitchData,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpValue {
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
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

/// LLDP-MED inventory (`lldp-med[].inventory[]`), advertised by some neighbors
/// (e.g. BlueField DPUs). Every field is optional.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct LldpInventory {
    #[serde(default)]
    pub serial: Vec<LldpValue>,
    #[serde(default)]
    pub manufacturer: Vec<LldpValue>,
    #[serde(default)]
    pub model: Vec<LldpValue>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct LldpMed {
    #[serde(default)]
    pub inventory: Vec<LldpInventory>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpInterfaceEntry {
    pub name: String, // local interface name (host side)
    #[serde(default)]
    pub chassis: Vec<LldpChassis>,
    #[serde(default)]
    pub port: Vec<LldpPort>,
    #[serde(rename = "lldp-med", default)]
    pub lldp_med: Vec<LldpMed>,
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

/// Returns one `LldpNeighbor` per LLDP neighbor, filtering out self-loopback ones.
pub fn collect_lldp_neighbors() -> LldpCollectorResult<Vec<LldpNeighbor>> {
    let local_chassis_id = get_local_chassis_id();

    build_lldp_neighbors(
        get_all_lldp_neighbors()?,
        local_chassis_id.as_ref(),
        |ifname| Ok(read_interface_mac(ifname)),
    )
}

/// Returns LLDP neighbors captured by the sidecar for a containerized DPU agent.
///
/// A successful empty result means the validated snapshot contains no reportable
/// neighbors. Missing, stale, malformed, or incomplete snapshots return an error,
/// except malformed chassis data, which disables self-loop filtering.
pub fn collect_lldp_neighbors_from_snapshot() -> LldpCollectorResult<Vec<LldpNeighbor>> {
    collect_lldp_neighbors_from_snapshot_at(
        Path::new(LLDP_SNAPSHOT_ROOT),
        SystemTime::now(),
        LLDP_SNAPSHOT_MAX_AGE,
    )
}

fn collect_lldp_neighbors_from_snapshot_at(
    snapshot_root: &Path,
    now: SystemTime,
    max_age: Duration,
) -> LldpCollectorResult<Vec<LldpNeighbor>> {
    let snapshot_dir = resolve_current_snapshot(snapshot_root)?;
    validate_snapshot_age(&snapshot_dir, now, max_age)?;

    let neighbors_json = read_snapshot_file(&snapshot_dir.join("neighbors.json"))?;
    let chassis_json = read_snapshot_file(&snapshot_dir.join("chassis.json"))?;
    let local_chassis_id = parse_local_chassis_id(&chassis_json);
    let interface_macs = snapshot_dir.join("interface-macs");
    validate_snapshot_directory(&interface_macs)?;

    let neighbors = parse_lldp_neighbors(&neighbors_json)?;
    let mut local_macs: HashMap<String, String> = HashMap::new();
    build_lldp_neighbors(neighbors, local_chassis_id.as_ref(), |ifname| {
        if let Some(mac) = local_macs.get(ifname) {
            return Ok(Some(mac.clone()));
        }

        let mac = read_snapshot_interface_mac(&interface_macs, ifname)?;
        local_macs.insert(ifname.to_string(), mac.clone());
        Ok(Some(mac))
    })
}

fn resolve_current_snapshot(snapshot_root: &Path) -> LldpCollectorResult<PathBuf> {
    validate_snapshot_directory(snapshot_root)?;
    let current_path = snapshot_root.join("current");
    let target = fs::read_link(&current_path).map_err(|error| {
        LldpCollectorError::Lldp(format!(
            "could not resolve LLDP snapshot {}: {error}",
            current_path.display()
        ))
    })?;
    let mut components = target.components();
    let valid_target = matches!(components.next(), Some(Component::Normal(part)) if part == "snapshots")
        && matches!(components.next(), Some(Component::Normal(part)) if part.to_string_lossy().starts_with("snapshot-"))
        && components.next().is_none();
    if !valid_target {
        return Err(LldpCollectorError::Lldp(format!(
            "sidecar LLDP snapshot target {} is not a generated relative snapshot",
            target.display()
        )));
    }
    let snapshots_dir = snapshot_root.join("snapshots");
    validate_snapshot_directory(&snapshots_dir)?;
    let snapshot_dir = snapshot_root.join(target);
    validate_snapshot_directory(&snapshot_dir)?;
    Ok(snapshot_dir)
}

fn validate_snapshot_directory(path: &Path) -> LldpCollectorResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LldpCollectorError::Lldp(format!(
            "could not inspect LLDP snapshot directory {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(LldpCollectorError::Lldp(format!(
            "LLDP snapshot path {} is not a directory",
            path.display()
        )));
    }
    Ok(())
}

fn validate_snapshot_age(
    snapshot_dir: &Path,
    now: SystemTime,
    max_age: Duration,
) -> LldpCollectorResult<()> {
    let captured_at_path = snapshot_dir.join("captured-at");
    let captured_at = read_snapshot_file(&captured_at_path)?;
    let captured_at = captured_at.trim().parse::<u64>().map_err(|error| {
        LldpCollectorError::Lldp(format!(
            "invalid LLDP snapshot timestamp in {}: {error}",
            captured_at_path.display()
        ))
    })?;
    let captured_at = UNIX_EPOCH
        .checked_add(Duration::from_secs(captured_at))
        .ok_or_else(|| {
            LldpCollectorError::Lldp("sidecar LLDP snapshot timestamp overflowed".into())
        })?;
    let age = now.duration_since(captured_at).map_err(|_| {
        LldpCollectorError::Lldp(format!(
            "sidecar LLDP snapshot {} is dated in the future",
            snapshot_dir.display()
        ))
    })?;
    if age > max_age {
        return Err(LldpCollectorError::Lldp(format!(
            "sidecar LLDP snapshot {} is {} seconds old; maximum age is {} seconds",
            snapshot_dir.display(),
            age.as_secs(),
            max_age.as_secs()
        )));
    }
    Ok(())
}

fn read_snapshot_file(path: &Path) -> LldpCollectorResult<String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LldpCollectorError::Lldp(format!(
            "could not inspect LLDP snapshot file {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(LldpCollectorError::Lldp(format!(
            "LLDP snapshot path {} is not a regular file",
            path.display()
        )));
    }
    fs::read_to_string(path).map_err(|error| {
        LldpCollectorError::Lldp(format!(
            "could not read LLDP snapshot file {}: {error}",
            path.display()
        ))
    })
}

fn read_snapshot_interface_mac(interface_macs: &Path, ifname: &str) -> LldpCollectorResult<String> {
    let interface_name = Path::new(ifname);
    let mut components = interface_name.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(LldpCollectorError::Lldp(format!(
            "invalid LLDP snapshot interface name {ifname}"
        )));
    }
    let path = interface_macs.join(interface_name);
    let mac = read_snapshot_file(&path)?;
    let mac = mac.trim();
    let octets = mac.split(':').collect::<Vec<_>>();
    if octets.len() != 6
        || octets.iter().any(|octet| {
            octet.len() != 2 || !octet.chars().all(|character| character.is_ascii_hexdigit())
        })
    {
        return Err(LldpCollectorError::Lldp(format!(
            "invalid MAC address in LLDP snapshot file {}",
            path.display()
        )));
    }
    Ok(mac.to_string())
}

fn build_lldp_neighbors(
    neighbors: Vec<rpc_discovery::LldpSwitchData>,
    local_chassis_id: Option<&LldpId>,
    mut interface_mac: impl FnMut(&str) -> LldpCollectorResult<Option<String>>,
) -> LldpCollectorResult<Vec<LldpNeighbor>> {
    let mut result = Vec::new();
    for neighbor in neighbors {
        // Unknown local chassis id -> filter nothing: a spurious self-entry
        // beats a lost fabric link.
        if local_chassis_id.is_some_and(|own| is_self_loopback(&neighbor, own)) {
            continue;
        }
        let Some(local_mac) = interface_mac(&neighbor.local_port)? else {
            continue;
        };
        result.push(LldpNeighbor {
            local_mac,
            switch: neighbor,
        });
    }
    Ok(result)
}

/// Every LLDP neighbor across all interfaces lldpd monitors.
///
/// Returns an empty vec when no neighbor is advertised.
fn get_all_lldp_neighbors() -> LldpCollectorResult<Vec<rpc_discovery::LldpSwitchData>> {
    let out = Cmd::new("lldpcli")
        .args(vec!["-f", "json0", "show", "neighbors", "details"])
        .output()
        .map_err(|e| {
            warn!(error = %e, "Could not discover LLDP neighbors");
            LldpCollectorError::Lldp(e.to_string())
        })?;
    parse_lldp_neighbors(&out)
}

/// True when a neighbor's chassis id (type + value) matches our own local
/// chassis id, i.e. the "neighbor" is this box itself via an internal loopback
/// (e.g. a DPU e-switch representor pair).
fn is_self_loopback(neighbor: &rpc_discovery::LldpSwitchData, own: &LldpId) -> bool {
    let is_self = neighbor.id_type == own.id_type && neighbor.id_value == own.value;
    if is_self {
        debug!(
            local_port = neighbor.local_port,
            "dropping self-loopback LLDP neighbor"
        );
    }
    is_self
}

/// Chassis id this host's lldpd advertises (`lldpcli -f json0 show chassis`).
///
/// `None` when lldpd is unavailable or the output is malformed.
fn get_local_chassis_id() -> Option<LldpId> {
    let out = Cmd::new("lldpcli")
        .args(vec!["-f", "json0", "show", "chassis"])
        .output()
        .map_err(|e| warn!(error = %e, "Could not read local LLDP chassis"))
        .ok()?;
    parse_local_chassis_id(&out)
}

/// Parse `lldpcli -f json0 show chassis` output down to the first chassis id.
fn parse_local_chassis_id(json: &str) -> Option<LldpId> {
    parse_local_chassis_id_result(json)
        .map_err(|error| warn!(json, error = %error, "Could not deserialize local LLDP chassis"))
        .ok()
        .flatten()
}

fn parse_local_chassis_id_result(json: &str) -> LldpCollectorResult<Option<LldpId>> {
    #[derive(Deserialize, Default)]
    struct LocalChassisEntry {
        #[serde(default)]
        chassis: Vec<LldpChassis>,
    }
    #[derive(Deserialize, Default)]
    struct LocalChassisRoot {
        #[serde(rename = "local-chassis", default)]
        local_chassis: Vec<LocalChassisEntry>,
    }

    let root: LocalChassisRoot =
        serde_json::from_str(json).map_err(|error| LldpCollectorError::Lldp(error.to_string()))?;
    Ok(root
        .local_chassis
        .into_iter()
        .flat_map(|entry| entry.chassis)
        .find_map(|chassis| chassis.id.into_iter().next()))
}

fn read_interface_mac(ifname: &str) -> Option<String> {
    let mac = fs::read_to_string(format!("/sys/class/net/{ifname}/address")).ok()?;
    let mac = mac.trim();
    if mac.is_empty() {
        return None;
    }
    Some(mac.to_string())
}

/// Parse `lldpcli -f json0` output into one `LldpSwitchData` per neighbor.
///
/// Each `lldp[].interface[]` entry is a distinct neighbor. Entries advertising no
/// chassis are skipped; every other field is optional — missing chassis/port
/// fields degrade to empty values, absent LLDP-MED inventory to `None`.
fn parse_lldp_neighbors(
    lldp_json: &str,
) -> LldpCollectorResult<Vec<rpc_discovery::LldpSwitchData>> {
    let lldp_resp: LldpResponse = serde_json::from_str(lldp_json).map_err(|e| {
        warn!(lldp_json, error = %e, "Could not deserialize LLDP response");
        LldpCollectorError::Lldp(e.to_string())
    })?;

    let mut neighbors = Vec::new();
    for entry in lldp_resp.lldp.iter().flat_map(|root| root.interface.iter()) {
        let Some(chassis) = entry.chassis.first() else {
            debug!(port = entry.name, "No LLDP chassis data");
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

        let med_inventory = entry
            .lldp_med
            .first()
            .and_then(|med| med.inventory.first())
            .map(|inv| {
                let field = |vals: &[LldpValue]| vals.first().map(|v| v.value.clone());
                rpc_discovery::LldpMedInventory {
                    serial: field(&inv.serial),
                    manufacturer: field(&inv.manufacturer),
                    model: field(&inv.model),
                }
            });

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
            med_inventory,
        });
    }

    Ok(neighbors)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use carbide_test_support::Outcome::{Fails, Yields};
    use tempfile::TempDir;

    use super::{
        Duration, LldpId, UNIX_EPOCH, collect_lldp_neighbors_from_snapshot_at, fs,
        is_self_loopback, parse_lldp_neighbors, parse_local_chassis_id, rpc_discovery,
    };

    // Three LLDP neighbors on a single physical port (`vlldp`). `-f json0` emits
    // each as its own `interface` array entry, so `parse_lldp_neighbors` must yield one
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
        let neighbors = parse_lldp_neighbors(MULTI_NEIGHBOR).expect("parse");
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
        let neighbors = parse_lldp_neighbors(SINGLE_NEIGHBOR).expect("parse");
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

    // Neighbor advertising LLDP-MED inventory (a BlueField DPU). serial /
    // manufacturer / model live under `lldp-med[].inventory[]`.
    const INVENTORY_NEIGHBOR: &str = r#"{
      "lldp": [
        { "interface": [
          { "name": "enp1s0np0", "chassis": [
              { "id": [{"type":"mac","value":"00:11:22:33:44:55"}],
                "name": [{"value":"example-dpu-01"}] }],
            "port": [{ "id": [{"type":"mac","value":"00:11:22:33:44:66"}], "ttl": [{"value":"120"}] }],
            "lldp-med": [{ "inventory": [{
                "serial": [{"value":"SN0123456789"}],
                "manufacturer": [{"value":"https://example.com"}],
                "model": [{"value":"BlueField-3 DPU"}] }] }] }
        ] }
      ]
    }"#;

    #[test]
    fn parses_lldp_med_inventory() {
        let neighbors = parse_lldp_neighbors(INVENTORY_NEIGHBOR).expect("parse");
        assert_eq!(neighbors.len(), 1);
        let inv = neighbors[0].med_inventory.as_ref().expect("inventory");
        assert_eq!(inv.serial.as_deref(), Some("SN0123456789"));
        assert_eq!(inv.manufacturer.as_deref(), Some("https://example.com"));
        assert_eq!(inv.model.as_deref(), Some("BlueField-3 DPU"));
    }

    #[test]
    fn parses_missing_inventory_as_none() {
        let neighbors = parse_lldp_neighbors(SINGLE_NEIGHBOR).expect("parse");
        assert_eq!(neighbors.len(), 1);
        assert!(neighbors[0].med_inventory.is_none());
    }

    #[test]
    fn parses_no_neighbors_as_empty() {
        let neighbors = parse_lldp_neighbors(r#"{"lldp":[{"interface":[]}]}"#).expect("parse");
        assert!(neighbors.is_empty());
    }

    // Shape of `lldpcli -f json0 show chassis` on a DPU.
    const LOCAL_CHASSIS: &str = r#"{
      "local-chassis": [
        { "chassis": [
            { "id": [{"type":"mac","value":"58:a2:e1:54:6f:ae"}],
              "name": [{"value":"10-213-2-193.forge.local"}],
              "descr": [{"value":"Forge-SRE"}] }] }
      ]
    }"#;

    fn write_snapshot(
        root: &std::path::Path,
        captured_at: &str,
        neighbors: &str,
        chassis: &str,
        interface_mac: Option<&str>,
    ) {
        let snapshot = root.join("snapshots/snapshot-test");
        fs::create_dir_all(snapshot.join("interface-macs")).unwrap();
        fs::write(snapshot.join("captured-at"), captured_at).unwrap();
        fs::write(snapshot.join("neighbors.json"), neighbors).unwrap();
        fs::write(snapshot.join("chassis.json"), chassis).unwrap();
        if let Some(mac) = interface_mac {
            fs::write(snapshot.join("interface-macs/p0"), mac).unwrap();
        }
        symlink("snapshots/snapshot-test", root.join("current")).unwrap();
    }

    #[derive(Clone, Copy, Debug)]
    enum SnapshotState {
        Valid,
        Empty,
        MissingMac,
        EmptyMac,
        MalformedMac,
        UnreadableMac,
        SelfLoop,
        SelfLoopMissingMac,
        Stale,
        Future,
        MalformedTimestamp,
        MalformedNeighbors,
        MalformedChassis,
        MissingMacDirectory,
        MissingCurrent,
        InvalidCurrent,
    }

    fn snapshot_for_state(state: SnapshotState) -> TempDir {
        let root = TempDir::new().unwrap();
        match state {
            SnapshotState::MissingCurrent => {}
            SnapshotState::InvalidCurrent => {
                symlink("../outside", root.path().join("current")).unwrap();
            }
            _ => {
                let (captured_at, neighbors, chassis, mac) = match state {
                    SnapshotState::Valid => (
                        "900",
                        SINGLE_NEIGHBOR,
                        LOCAL_CHASSIS,
                        Some("00:11:22:33:44:00\n"),
                    ),
                    SnapshotState::Empty => {
                        ("900", r#"{"lldp":[{"interface":[]}]}"#, LOCAL_CHASSIS, None)
                    }
                    SnapshotState::MissingMac => ("900", SINGLE_NEIGHBOR, LOCAL_CHASSIS, None),
                    SnapshotState::EmptyMac => ("900", SINGLE_NEIGHBOR, LOCAL_CHASSIS, Some("")),
                    SnapshotState::MalformedMac => {
                        ("900", SINGLE_NEIGHBOR, LOCAL_CHASSIS, Some("not-a-mac\n"))
                    }
                    SnapshotState::UnreadableMac => ("900", SINGLE_NEIGHBOR, LOCAL_CHASSIS, None),
                    SnapshotState::SelfLoop => (
                        "900",
                        SINGLE_NEIGHBOR,
                        r#"{"local-chassis":[{"chassis":[{"id":[{"type":"mac","value":"00:11:22:33:44:55"}]}]}]}"#,
                        Some("00:11:22:33:44:00\n"),
                    ),
                    SnapshotState::SelfLoopMissingMac => (
                        "900",
                        SINGLE_NEIGHBOR,
                        r#"{"local-chassis":[{"chassis":[{"id":[{"type":"mac","value":"00:11:22:33:44:55"}]}]}]}"#,
                        None,
                    ),
                    SnapshotState::Stale => (
                        "699",
                        SINGLE_NEIGHBOR,
                        LOCAL_CHASSIS,
                        Some("00:11:22:33:44:00\n"),
                    ),
                    SnapshotState::Future => (
                        "1001",
                        SINGLE_NEIGHBOR,
                        LOCAL_CHASSIS,
                        Some("00:11:22:33:44:00\n"),
                    ),
                    SnapshotState::MalformedTimestamp => (
                        "not-a-timestamp",
                        SINGLE_NEIGHBOR,
                        LOCAL_CHASSIS,
                        Some("00:11:22:33:44:00\n"),
                    ),
                    SnapshotState::MalformedNeighbors => (
                        "900",
                        "not-json",
                        LOCAL_CHASSIS,
                        Some("00:11:22:33:44:00\n"),
                    ),
                    SnapshotState::MalformedChassis => (
                        "900",
                        SINGLE_NEIGHBOR,
                        "not-json",
                        Some("00:11:22:33:44:00\n"),
                    ),
                    SnapshotState::MissingMacDirectory => {
                        ("900", SINGLE_NEIGHBOR, LOCAL_CHASSIS, None)
                    }
                    SnapshotState::MissingCurrent | SnapshotState::InvalidCurrent => unreachable!(),
                };
                write_snapshot(root.path(), captured_at, neighbors, chassis, mac);
                if matches!(state, SnapshotState::MissingMacDirectory) {
                    fs::remove_dir(root.path().join("snapshots/snapshot-test/interface-macs"))
                        .unwrap();
                }
                if matches!(state, SnapshotState::UnreadableMac) {
                    fs::create_dir(
                        root.path()
                            .join("snapshots/snapshot-test/interface-macs/p0"),
                    )
                    .unwrap();
                }
            }
        }
        root
    }

    #[test]
    fn containerized_snapshot_cases() {
        carbide_test_support::scenarios!(run = |state: SnapshotState| {
            let root = snapshot_for_state(state);
            collect_lldp_neighbors_from_snapshot_at(
                root.path(),
                UNIX_EPOCH + Duration::from_secs(1000),
                Duration::from_secs(300),
            )
            .map(|neighbors| neighbors.len())
            .map_err(drop)
        };
            "valid snapshots are collected" {
                SnapshotState::Valid => Yields(1),
                SnapshotState::Empty => Yields(0),
                SnapshotState::MalformedChassis => Yields(1),
            }

            "neighbors representing this chassis are dropped" {
                SnapshotState::SelfLoop => Yields(0),
                SnapshotState::SelfLoopMissingMac => Yields(0),
            }

            "invalid snapshots are rejected" {
                SnapshotState::MissingMac => Fails,
                SnapshotState::EmptyMac => Fails,
                SnapshotState::MalformedMac => Fails,
                SnapshotState::UnreadableMac => Fails,
                SnapshotState::Stale => Fails,
                SnapshotState::Future => Fails,
                SnapshotState::MalformedTimestamp => Fails,
                SnapshotState::MalformedNeighbors => Fails,
                SnapshotState::MissingMacDirectory => Fails,
                SnapshotState::MissingCurrent => Fails,
                SnapshotState::InvalidCurrent => Fails,
            }
        );
    }

    #[test]
    fn parses_local_chassis_id() {
        let id = parse_local_chassis_id(LOCAL_CHASSIS).expect("chassis id");
        assert_eq!(id.id_type, "mac");
        assert_eq!(id.value, "58:a2:e1:54:6f:ae");
    }

    #[test]
    fn parses_local_chassis_id_absent() {
        assert!(parse_local_chassis_id(r#"{"local-chassis":[{"chassis":[{}]}]}"#).is_none());
        assert!(parse_local_chassis_id("not json").is_none());
    }

    // Representor pairs on a DPU report the DPU's own chassis as the neighbor;
    // only a matching (type, value) pair marks the loopback — a genuinely
    // different switch must be kept.
    #[test]
    fn self_loopback_detected_by_chassis_id() {
        let own = LldpId {
            id_type: "mac".into(),
            value: "58:a2:e1:54:6f:ae".into(),
        };
        let neighbor = |id_type: &str, id_value: &str| rpc_discovery::LldpSwitchData {
            id_type: id_type.into(),
            id_value: id_value.into(),
            ..Default::default()
        };

        assert!(is_self_loopback(
            &neighbor("mac", "58:a2:e1:54:6f:ae"),
            &own
        ));
        // different chassis value -> genuine external link
        assert!(!is_self_loopback(
            &neighbor("mac", "24:8a:07:b4:41:aa"),
            &own
        ));
        // same string value but different id type -> not self
        assert!(!is_self_loopback(
            &neighbor("local", "58:a2:e1:54:6f:ae"),
            &own
        ));
    }
}
