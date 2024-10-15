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

use health_report::HealthProbeId;
use serde::Deserialize;
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;

use std::time::{Duration, Instant};
use std::{collections::HashMap, fmt, path::Path, str::FromStr};

use crate::hbn;

const HBN_DAEMONS_FILE: &str = "etc/frr/daemons";
const DHCP_RELAY_FILE: &str = "etc/supervisor/conf.d/default-isc-dhcp-relay.conf";
const DHCP_SERVER_FILE: &str = "etc/supervisor/conf.d/default-forge-dhcp-server.conf";
// const NVUE_FILE: &str = "etc/nvue.d/startup.yaml";

const EXPECTED_FILES: [&str; 5] = [
    "etc/frr/frr.conf",
    "etc/network/interfaces",
    DHCP_RELAY_FILE,
    DHCP_SERVER_FILE,
    HBN_DAEMONS_FILE,
];

const EXPECTED_SERVICES: [&str; 3] = ["frr", "nl2doca", "rsyslog"];
const DHCP_RELAY_SERVICE: &str = "isc-dhcp-relay-default";
const DHCP_SERVER_SERVICE: &str = "forge-dhcp-server-default";

fn failed(
    health_report: &mut health_report::HealthReport,
    probe_id: impl Into<HealthProbeId>,
    probe_target: Option<String>,
    message: String,
) {
    health_report
        .alerts
        .push(make_alert(probe_id, probe_target, message, true));
}

fn make_alert(
    probe_id: impl Into<HealthProbeId>,
    probe_target: Option<String>,
    message: String,
    is_critical: bool,
) -> health_report::HealthProbeAlert {
    let classifications = match is_critical {
        true => vec![
            health_report::HealthAlertClassification::prevent_allocations(),
            health_report::HealthAlertClassification::prevent_host_state_changes(),
        ],
        false => vec![],
    };
    health_report::HealthProbeAlert {
        id: probe_id.into(),
        target: probe_target,
        in_alert_since: None,
        message,
        tenant_message: None,
        classifications,
    }
}

fn passed(
    health_report: &mut health_report::HealthReport,
    probe_id: impl Into<HealthProbeId>,
    probe_target: Option<String>,
) {
    health_report
        .successes
        .push(health_report::HealthProbeSuccess {
            id: probe_id.into(),
            target: probe_target,
        })
}

/// Is enough of HBN ready so that we can configure it?
pub fn is_up(health_report: &health_report::HealthReport) -> bool {
    let has_failed_services = health_report
        .alerts
        .iter()
        .any(|a| a.id == *probe_ids::ServiceRunning);
    health_report
        .successes
        .iter()
        .any(|s| s.id == *probe_ids::ContainerExists)
        && health_report
            .successes
            .iter()
            .any(|s| s.id == *probe_ids::SupervisorctlStatus)
        && !has_failed_services
}

/// Check the health of HBN
pub async fn health_check(
    hbn_root: &Path,
    host_routes: &[&str],
    _process_started_at: Instant,
    has_changed_configs: bool,
    min_healthy_links: u32,
    route_servers: &[String],
) -> health_report::HealthReport {
    let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());

    // Check whether HBN is up
    let container_id = match hbn::get_hbn_container_id().await {
        Ok(id) => id,
        Err(err) => {
            failed(
                &mut hr,
                probe_ids::ContainerExists.clone(),
                None,
                err.to_string(),
            );
            return hr;
        }
    };
    passed(&mut hr, probe_ids::ContainerExists.clone(), None);
    check_hbn_services_running(&mut hr, &container_id, &EXPECTED_SERVICES).await;

    // We want these checks whether HBN is up or not
    check_restricted_mode(&mut hr).await;

    // We only want these checks if HBN is up
    if !is_up(&hr) {
        return hr;
    }
    check_dhcp_relay_and_server(&mut hr, &container_id).await;
    check_ifreload(&mut hr, &container_id).await;
    let hbn_daemons_file = hbn_root.join(HBN_DAEMONS_FILE);
    check_bgp_daemon_enabled(&mut hr, &hbn_daemons_file.to_string_lossy());
    check_network_stats(
        &mut hr,
        &container_id,
        host_routes,
        min_healthy_links,
        route_servers,
    )
    .await;
    check_files(&mut hr, hbn_root, &EXPECTED_FILES);

    if has_changed_configs {
        failed(
            &mut hr,
            probe_ids::PostConfigCheckWait.clone(),
            None,
            "Post-config waiting period".to_string(),
        );
    }

    hr
}

// HBN processes should be running
async fn check_hbn_services_running(
    hr: &mut health_report::HealthReport,
    container_id: &str,
    expected_services: &[&str],
) {
    // `supervisorctl status` has exit code 3 if there are stopped processes (which we expect),
    // so final param is 'false' here.
    // https://github.com/Supervisor/supervisor/issues/1223
    let sctl = match hbn::run_in_container(container_id, &["supervisorctl", "status"], false).await
    {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!("check_hbn_services_running supervisorctl status: {err}");
            failed(
                hr,
                probe_ids::SupervisorctlStatus.clone(),
                None,
                err.to_string(),
            );
            return;
        }
    };
    let st = match parse_status(&sctl) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!("check_hbn_services_running supervisorctl status parse: {err}");
            failed(
                hr,
                probe_ids::SupervisorctlStatus.clone(),
                None,
                err.to_string(),
            );
            return;
        }
    };
    passed(hr, probe_ids::SupervisorctlStatus.clone(), None);

    for service in expected_services.iter().map(|x| x.to_string()) {
        match st.status_of(&service) {
            SctlState::Running => passed(hr, probe_ids::ServiceRunning.clone(), Some(service)),
            status => {
                tracing::warn!("check_hbn_services_running {service}: {status}");
                failed(
                    hr,
                    probe_ids::ServiceRunning.clone(),
                    Some(service.clone()),
                    format!("{service} is {status}, need {}", SctlState::Running),
                );
            }
        }
    }
}

// dhcp relay should be running
// Very similar to check_hbn_services_running, except it happens _after_ we start configuring.
// The other services must be up before we start configuring.
// Out of relay and dhcp server, only and only one should be up.
async fn check_dhcp_relay_and_server(hr: &mut health_report::HealthReport, container_id: &str) {
    // `supervisorctl status` has exit code 3 if there are stopped processes (which we expect),
    // so final param is 'false' here.
    // https://github.com/Supervisor/supervisor/issues/1223
    let sctl = match hbn::run_in_container(container_id, &["supervisorctl", "status"], false).await
    {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!("check_hbn_services_running supervisorctl status: {err}");
            failed(
                hr,
                probe_ids::SupervisorctlStatus.clone(),
                None,
                err.to_string(),
            );
            return;
        }
    };
    let st = match parse_status(&sctl) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!("check_hbn_services_running supervisorctl status parse: {err}");
            failed(
                hr,
                probe_ids::SupervisorctlStatus.clone(),
                None,
                err.to_string(),
            );
            return;
        }
    };

    let relay_status = match st.status_of(DHCP_RELAY_SERVICE) {
        SctlState::Running => {
            passed(hr, probe_ids::DhcpRelay.clone(), None);
            None
        }
        status => Some(status),
    };

    let dhcp_server_status = match st.status_of(DHCP_SERVER_SERVICE) {
        SctlState::Running => {
            passed(hr, probe_ids::DhcpServer.clone(), None);
            None
        }
        status => Some(status),
    };

    match (relay_status, dhcp_server_status) {
        (None, None) => {
            tracing::warn!("check_dhcp_relay_and_server: Both can not be running together.");
            failed(
                hr,
                probe_ids::DhcpRelay.clone(),
                None,
                "Dhcp relay and server are running together".to_string(),
            );
            failed(
                hr,
                probe_ids::DhcpServer.clone(),
                None,
                "Dhcp relay and server are running together".to_string(),
            );
        }
        (Some(a), Some(b)) => {
            tracing::warn!("check_dhcp_relay: {a}");
            failed(hr, probe_ids::DhcpRelay.clone(), None, a.to_string());

            tracing::warn!("check_dhcp_server: {b}");
            failed(hr, probe_ids::DhcpRelay.clone(), None, b.to_string());
        }
        (Some(_), None) => {
            // Relay is running, not dhcp-server. DPU is configured in relay mode. All good.
        }
        (None, Some(_)) => {
            // Dhcp-server is running, not relay. DPU is configured in dhcp-server mode. All good.
        }
    }
}

// Check HBN BGP stats
async fn check_network_stats(
    hr: &mut health_report::HealthReport,
    container_id: &str,
    host_routes: &[&str],
    min_healthy_links: u32,
    route_servers: &[String],
) {
    // If BGP daemon is not enabled, we will get a bunch of bogus alerts shown
    // that are not helpful to anyone. Since showing `BgpDaemonEnabled` already
    // covers the core problem - don't bother with the remaining checks.
    if hr
        .alerts
        .iter()
        .any(|alert| alert.id == *probe_ids::BgpDaemonEnabled)
    {
        return;
    }

    let mut health_data = BgpHealthData::default();

    // `vtysh` is the Free Range Routing (FRR) shell.
    match hbn::run_in_container(
        container_id,
        &["vtysh", "-c", "show bgp summary json"],
        true,
    )
    .await
    {
        Ok(bgp_json) => check_bgp(
            &mut health_data,
            &bgp_json,
            host_routes,
            min_healthy_links,
            route_servers,
        ),
        Err(err) => {
            tracing::warn!("check_network_stats show bgp summary: {err}");
            health_data.other_errors.push(err.to_string());
        }
    };

    health_data.into_health_report(hr);
}

// `ifreload` should exit code 0 and have no output
async fn check_ifreload(hr: &mut health_report::HealthReport, container_id: &str) {
    match hbn::run_in_container(container_id, &["ifreload", "--all", "--syntax-check"], true).await
    {
        Ok(stdout) => {
            if stdout.is_empty() {
                passed(hr, probe_ids::Ifreload.clone(), None);
            } else {
                tracing::warn!("check_ifreload: {stdout}");
                failed(hr, probe_ids::Ifreload.clone(), None, stdout);
            }
        }
        Err(err) => {
            tracing::warn!("check_ifreload: {err}");
            failed(hr, probe_ids::Ifreload.clone(), None, err.to_string());
        }
    }
}

// The files VPC creates should exist
fn check_files(hr: &mut health_report::HealthReport, hbn_root: &Path, expected_files: &[&str]) {
    const MIN_SIZE: u64 = 100;
    let mut dhcp_relay_size = 0;
    let mut dhcp_server_size = 0;
    for filename in expected_files {
        let path = hbn_root.join(filename);
        if path.exists() {
            passed(
                hr,
                probe_ids::FileExists.clone(),
                Some(path.display().to_string()),
            );
        } else {
            failed(
                hr,
                probe_ids::FileExists.clone(),
                Some(path.display().to_string()),
                "Not found".to_string(),
            );
            continue;
        }
        let stat = match std::fs::metadata(path) {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!("check_files {filename}: {err}");
                failed(
                    hr,
                    probe_ids::FileIsValid.clone(),
                    Some(filename.to_string()),
                    err.to_string(),
                );
                continue;
            }
        };
        if filename == &DHCP_SERVER_FILE {
            dhcp_server_size = stat.len();
        } else if filename == &DHCP_RELAY_FILE {
            dhcp_relay_size = stat.len();
        } else if stat.len() < MIN_SIZE {
            tracing::warn!(
                "check_files {filename}: Too small {} < {MIN_SIZE} bytes",
                stat.len()
            );
            failed(
                hr,
                probe_ids::FileIsValid.clone(),
                Some(filename.to_string()),
                "Too small".to_string(),
            );
        }
        passed(
            hr,
            probe_ids::FileIsValid.clone(),
            Some(filename.to_string()),
        );
    }

    if dhcp_relay_size < MIN_SIZE && dhcp_server_size < MIN_SIZE {
        tracing::warn!("check_files {DHCP_RELAY_FILE} and {DHCP_SERVER_FILE}: Too small");
        failed(
            hr,
            probe_ids::FileIsValid.clone(),
            Some(format!("{DHCP_RELAY_FILE} and {DHCP_SERVER_FILE}")),
            "Too small".to_string(),
        );
    }
    if dhcp_relay_size > MIN_SIZE && dhcp_server_size > MIN_SIZE {
        tracing::warn!("check_files {DHCP_RELAY_FILE} and {DHCP_SERVER_FILE}: Both are valid. Only one can be valid.");
        failed(
            hr,
            probe_ids::FileIsValid.clone(),
            Some(format!("{DHCP_RELAY_FILE} and {DHCP_SERVER_FILE}")),
            "Both can not be valid together.".to_string(),
        );
    }
}

fn check_bgp_daemon_enabled(hr: &mut health_report::HealthReport, hbn_daemons_file: &str) {
    let daemons = match std::fs::read_to_string(hbn_daemons_file) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!("check_bgp_daemon_enabled: {err}");
            failed(
                hr,
                probe_ids::BgpDaemonEnabled.clone(),
                None,
                format!("Trying to open and read {hbn_daemons_file}: {err}"),
            );
            return;
        }
    };

    if daemons.contains("bgpd=no") {
        failed(
            hr,
            probe_ids::BgpDaemonEnabled.clone(),
            None,
            format!("BGP daemon is disabled - {hbn_daemons_file} contains 'bgpd=no'"),
        );
        return;
    }
    if !daemons.contains("bgpd=yes") {
        failed(
            hr,
            probe_ids::BgpDaemonEnabled.clone(),
            None,
            format!("BGP daemon is not enabled - {hbn_daemons_file} does not contain 'bgpd=yes'"),
        );
        return;
    }

    passed(hr, probe_ids::BgpDaemonEnabled.clone(), None);
}

fn check_bgp(
    health_data: &mut BgpHealthData,
    bgp_json: &str,
    host_routes: &[&str],
    min_healthy_links: u32,
    route_servers: &[String],
) {
    let networks: BgpNetworks = match serde_json::from_str(bgp_json) {
        Ok(networks) => networks,
        Err(e) => {
            health_data.other_errors.push(format!(
                "failed to deserialize bgp_json: {bgp_json} with error: {e}"
            ));
            return;
        }
    };

    check_bgp_stats_ipv4_unicast(
        "ipv4_unicast",
        &networks.ipv4_unicast,
        health_data,
        host_routes,
        min_healthy_links,
    );
    check_bgp_stats_l2_vpn_evpn(
        "l2_vpn_evpn",
        &networks.l2_vpn_evpn,
        health_data,
        route_servers,
        min_healthy_links,
    );
}

fn check_bgp_tor_routes(s: &BgpStats, health_data: &mut BgpHealthData, min_healthy_links: u32) {
    for port_id in 0..min_healthy_links {
        let port_name = format!("p{port_id}_sf");

        let session_data = s.peers.get(&port_name);
        let mut message = None;
        match session_data {
            Some(session) => {
                if session.state != "Established" {
                    message = Some(format!(
                        "Session {port_name} is not Established, but in state {}",
                        session.state
                    ));
                }
            }
            None => {
                message = Some(format!(
                    "Expected session for {port_name} was not found in BGP peer data"
                ));
            }
        }

        if let Some(message) = message {
            health_data.unhealthy_tor_peers.insert(port_name, message);
        }
    }
}

fn check_bgp_stats_ipv4_unicast(
    name: &str,
    s: &BgpStats,
    health_data: &mut BgpHealthData,
    host_routes: &[&str],
    min_healthy_links: u32,
) {
    check_bgp_tor_routes(s, health_data, min_healthy_links);

    // We ignore the BPG sessions pointing towards tenant Machines
    // Tenants can choose to use or not use them.
    // However no other sessions are expected
    for (peer_name, _peer) in s.other_peers() {
        if !host_routes.contains(&peer_name.as_str()) {
            health_data
                .unexpected_peers
                .push((name.to_string(), peer_name.clone()));
        }
    }

    if s.dynamic_peers != 0 {
        health_data.other_errors.push(format!(
            "{name}.dynamic_peers is {} should be 0",
            s.dynamic_peers
        ));
    }
}

fn check_bgp_stats_l2_vpn_evpn(
    name: &str,
    s: &BgpStats,
    health_data: &mut BgpHealthData,
    route_servers: &[String],
    min_healthy_links: u32,
) {
    // In case Route servers are not specified, the peer list should contain only
    // TORs. Otherwise we expect it to contain the route servers.
    if route_servers.is_empty() {
        check_bgp_tor_routes(s, health_data, min_healthy_links);

        for (peer_name, _peer) in s.other_peers() {
            health_data
                .unexpected_peers
                .push((name.to_string(), peer_name.clone()));
        }
    } else {
        let mut other_peers: HashMap<&String, &BgpPeer> = s.other_peers().collect();
        for route_server in route_servers {
            let session_data = other_peers.remove(route_server);
            let mut message = None;
            match session_data {
                Some(session) => {
                    if session.state != "Established" {
                        message = Some(format!(
                            "Session {route_server} is not Established, but in state {}",
                            session.state
                        ));
                    }
                }
                None => {
                    message = Some(format!(
                        "Expected session for {route_server} was not found in BGP peer data"
                    ));
                }
            }

            if let Some(message) = message {
                health_data
                    .unhealthy_route_server_peers
                    .push((route_server.to_string(), message));
            }
        }

        for (peer_name, _peer) in other_peers {
            health_data
                .unexpected_peers
                .push((name.to_string(), peer_name.clone()));
        }
    }

    if s.dynamic_peers != 0 {
        health_data.other_errors.push(format!(
            "{name}.dynamic_peers is {} should be 0",
            s.dynamic_peers
        ));
    }
}

#[derive(Clone, Debug, Default)]
struct BgpHealthData {
    // Note that these are HashMaps because we check TOR connections in 2 places
    // and dedup the messages using the HashMap
    pub unhealthy_tor_peers: HashMap<String, String>,
    pub unhealthy_route_server_peers: Vec<(String, String)>,
    pub unexpected_peers: Vec<(String, String)>,
    pub other_errors: Vec<String>,
}

impl BgpHealthData {
    pub fn into_health_report(mut self, hr: &mut health_report::HealthReport) {
        if self.other_errors.is_empty() {
            passed(hr, probe_ids::BgpStats.clone(), None);
        } else {
            self.other_errors
                .insert(0, "Failures while gathering BGP health data:".to_string());
            let err_msg = self.other_errors.join("\n");
            failed(hr, probe_ids::BgpStats.clone(), None, err_msg);
        }

        for (port_name, message) in self.unhealthy_tor_peers.into_iter() {
            hr.alerts.push(make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some(port_name),
                message,
                true,
            ));
        }

        for (route_server, message) in self.unhealthy_route_server_peers.into_iter() {
            hr.alerts.push(make_alert(
                probe_ids::BgpPeeringRouteServer.clone(),
                Some(route_server.to_string()),
                message,
                true,
            ));
        }

        for (group, peer_name) in self.unexpected_peers.into_iter() {
            hr.alerts.push(make_alert(
                probe_ids::UnexpectedBgpPeer.clone(),
                Some(peer_name.clone()),
                format!("Unexpected BGP session referencing peer {peer_name} was found in {group}"),
                true,
            ));
        }
    }
}

// A DPU should be in restricted mode
async fn check_restricted_mode(hr: &mut health_report::HealthReport) {
    const EXPECTED_PRIV_LEVEL: &str = "RESTRICTED";
    let mut cmd = TokioCommand::new("bash");
    cmd.arg("-c")
        .arg("mlxprivhost -d /dev/mst/mt*_pciconf0 query");
    cmd.kill_on_drop(true);

    let cmd_str = super::pretty_cmd(cmd.as_std());
    let Ok(cmd_res) = timeout(Duration::from_secs(10), cmd.output()).await else {
        failed(
            hr,
            probe_ids::RestrictedMode.clone(),
            None,
            format!("Timeout running '{cmd_str}'."),
        );
        return;
    };
    let out = match cmd_res {
        Ok(out) => out,
        Err(err) => {
            failed(
                hr,
                probe_ids::RestrictedMode.clone(),
                None,
                format!("Error running '{cmd_str}'. {err}"),
            );
            return;
        }
    };
    if !out.status.success() {
        tracing::debug!(
            "STDERR {}: {}",
            super::pretty_cmd(cmd.as_std()),
            String::from_utf8_lossy(&out.stderr)
        );
        failed(
            hr,
            probe_ids::RestrictedMode.clone(),
            None,
            format!(
                "{} for cmd '{}'",
                out.status,
                super::pretty_cmd(cmd.as_std())
            ),
        );
        return;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    match parse_mlxprivhost(s.as_ref()) {
        Ok(priv_level) if priv_level == EXPECTED_PRIV_LEVEL => {
            passed(hr, probe_ids::RestrictedMode.clone(), None);
        }
        Ok(priv_level) => {
            failed(
                hr,
                probe_ids::RestrictedMode.clone(),
                None,
                format!(
                    "mlxprivhost reports level '{priv_level}', expected '{EXPECTED_PRIV_LEVEL}'"
                ),
            );
        }
        Err(err) => {
            failed(
                hr,
                probe_ids::RestrictedMode.clone(),
                None,
                format!("parse_mlxprivhost: {err}"),
            );
        }
    }
}

fn parse_mlxprivhost(s: &str) -> eyre::Result<String> {
    let Some(level_line) = s.lines().find(|line| line.contains("level")) else {
        eyre::bail!("Invalid mlxprivhost output, missing 'level' line:\n{s}");
    };
    // Example ouput:
    // level                         : RESTRICTED
    let Some(level) = level_line.split(':').nth(1).map(|level| level.trim()) else {
        eyre::bail!("Invalid level line, needs a single colon: '{level_line}'");
    };
    Ok(level.to_string())
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BgpNetworks {
    ipv4_unicast: BgpStats,
    l2_vpn_evpn: BgpStats,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BgpStats {
    dynamic_peers: u32,
    peers: HashMap<String, BgpPeer>,
}

impl BgpStats {
    /// Returns the list of peers that are mapped connected to TORs, as indicated
    /// by session names like p0_sf
    #[allow(dead_code)]
    pub fn tor_peers(&self) -> impl Iterator<Item = (&String, &BgpPeer)> {
        lazy_static::lazy_static! {
            static ref TOR_SESSION_RE: regex::Regex = regex::Regex::new(r"^p[0-9]+_sf$").unwrap();
        }

        self.peers
            .iter()
            .filter(|(name, _peer)| TOR_SESSION_RE.is_match(name))
    }

    /// Returns the list of peers that are not connected to TORs
    pub fn other_peers(&self) -> impl Iterator<Item = (&String, &BgpPeer)> {
        lazy_static::lazy_static! {
            static ref TOR_SESSION_RE: regex::Regex = regex::Regex::new(r"^p[0-9]+_sf$").unwrap();
        }

        self.peers
            .iter()
            .filter(|(name, _peer)| !TOR_SESSION_RE.is_match(name))
    }
}

// We don't currently check the two pfx values because they depend on how many correctly
// configured instances we have right now, and dpu-agent doesn't know that.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BgpPeer {
    state: String,
    #[allow(dead_code)]
    pfx_rcd: Option<u32>,
    #[allow(dead_code)]
    pfx_snt: Option<u32>,
}

pub mod probe_ids {
    use health_report::HealthProbeId;

    lazy_static::lazy_static! {
        pub static ref ContainerExists: HealthProbeId = "ContainerExists".parse().unwrap();
        pub static ref SupervisorctlStatus: HealthProbeId = "SupervisorctlStatus".parse().unwrap();
        pub static ref ServiceRunning: HealthProbeId = "ServiceRunning".parse().unwrap();
        pub static ref DhcpRelay: HealthProbeId = "DhcpRelay".parse().unwrap();
        pub static ref DhcpServer: HealthProbeId = "DhcpServer".parse().unwrap();
        pub static ref BgpStats: HealthProbeId = "BgpStats".parse().unwrap();
        pub static ref BgpPeeringTor: HealthProbeId = "BgpPeeringTor".parse().unwrap();
        pub static ref BgpPeeringRouteServer: HealthProbeId = "BgpPeeringRouteServer".parse().unwrap();
        pub static ref UnexpectedBgpPeer: HealthProbeId = "UnexpectedBgpPeer".parse().unwrap();
        pub static ref Ifreload: HealthProbeId = "Ifreload".parse().unwrap();
        pub static ref FileExists: HealthProbeId = "FileExists".parse().unwrap();
        pub static ref FileIsValid: HealthProbeId = "FileIsValid".parse().unwrap();
        pub static ref BgpDaemonEnabled: HealthProbeId = "BgpDaemonEnabled".parse().unwrap();
        pub static ref RestrictedMode: HealthProbeId = "RestrictedMode".parse().unwrap();
        pub static ref PostConfigCheckWait: HealthProbeId = "PostConfigCheckWait".parse().unwrap();
    }
}

fn parse_status(status_out: &str) -> eyre::Result<SctlStatus> {
    let mut m = HashMap::new();
    for line in status_out.lines() {
        let parts: Vec<&str> = line.split_ascii_whitespace().collect();
        if parts.len() < 2 {
            tracing::warn!("supervisorctl status line too short: '{line}'");
            continue;
        }
        let state: SctlState = match parts[1].parse() {
            Ok(s) => s,
            Err(_err) => {
                // unreachable but future proof. SctlState::from_str is currently infallible.
                tracing::warn!(
                    "supervisorctl status invalid state '{}' in line '{line}'",
                    parts[1]
                );
                continue;
            }
        };
        m.insert(parts[0].to_string(), state);
    }
    Ok(SctlStatus { m })
}

struct SctlStatus {
    m: HashMap<String, SctlState>,
}

impl SctlStatus {
    fn status_of(&self, process: &str) -> SctlState {
        *self.m.get(process).unwrap_or(&SctlState::Unknown)
    }
}

impl FromStr for SctlState {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "STOPPED" => Self::Stopped,
            "STARTING" => Self::Starting,
            "RUNNING" => Self::Running,
            "BACKOFF" => Self::Backoff,
            "STOPPING" => Self::Stopping,
            "EXITED" => Self::Exited,
            "FATAL" => Self::Fatal,
            _ => {
                tracing::warn!("Unknown supervisorctl status '{s}'");
                Self::Unknown
            }
        })
    }
}

impl fmt::Display for SctlState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Stopped => "STOPPED",
                Self::Starting => "STARTING",
                Self::Running => "RUNNING",
                Self::Backoff => "BACKOFF",
                Self::Stopping => "STOPPING",
                Self::Exited => "EXITED",
                Self::Fatal => "FATAL",
                Self::Unknown => "UNKNOWN",
            }
        )
    }
}

// Supervisorctl process states
// https://supervisord.org/subprocess.html?#process-states
#[derive(PartialEq, Debug, Copy, Clone, Default)]
enum SctlState {
    #[default]
    Unknown,
    Stopped,
    Starting,
    Running,
    Backoff,
    Stopping,
    Exited,
    Fatal,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Should these gaps be tabs? Yes. Are they tabs? No. `supervisorctl` outputs spaces.
    const SUPERVISORCTL_STATUS_OUT: &str = r#"
cron                             RUNNING   pid 15, uptime 4:18:47
decrypt-user-add                 EXITED    Mar 06 06:24 PM
frr                              RUNNING   pid 17, uptime 4:18:47
frr-reload                       STOPPED   Not started
ifreload                         EXITED    Mar 06 06:24 PM
isc-dhcp-relay-default           RUNNING   pid 19, uptime 4:18:47
neighmgr                         RUNNING   pid 21, uptime 4:18:47
nginx                            RUNNING   pid 22, uptime 4:18:47
nl2doca                          RUNNING   pid 23, uptime 4:18:47
nvued                            STOPPED   Mar 06 06:24 PM
nvued-startup                    EXITED    Mar 06 06:24 PM
rsyslog                          RUNNING   pid 27, uptime 4:18:47
sysctl-apply                     EXITED    Mar 06 06:24 PM
"#;

    const MLXPRIVHOST_OUT: &str = r#"Host configurations
-------------------
level                         : RESTRICTED

Port functions status:
-----------------------
disable_rshim                 : TRUE
disable_tracer                : TRUE
disable_port_owner            : TRUE
disable_counter_rd            : TRUE

"#;

    const BGP_SUMMARY_JSON_NO_ROUTE_SERVER_SUCCESS: &str =
        include_str!("hbn_bgp_summary_no_route_server_success.json");
    const BGP_SUMMARY_JSON_NO_ROUTE_SERVER_FAILED_TOR_PEERS: &str =
        include_str!("hbn_bgp_summary_no_route_server_failed_tor_peers.json");
    const BGP_SUMMARY_JSON_NO_ROUTE_SERVER_SINGLE_FAILED_TOR_PEER: &str =
        include_str!("hbn_bgp_summary_no_route_server_single_failed_tor_peer.json");
    const BGP_SUMMARY_JSON_NO_ROUTE_SERVER_WITH_TENANT_ROUTES: &str =
        include_str!("hbn_bgp_summary_no_route_server_with_tenant_routes.json");
    const BGP_SUMMARY_JSON_WITH_ROUTE_SERVER_AND_TENANT_ROUTES: &str =
        include_str!("hbn_bgp_summary_with_route_server_and_tenant_routes.json");
    const BGP_SUMMARY_JSON_WITH_ROUTE_SERVER_FAILED_ALL_PEERS: &str =
        include_str!("hbn_bgp_summary_with_route_server_failed_all_peers.json");

    #[test]
    fn test_parse_supervisorctl_status() -> eyre::Result<()> {
        let st = parse_status(SUPERVISORCTL_STATUS_OUT)?;
        assert_eq!(st.status_of("frr"), SctlState::Running);
        assert_eq!(st.status_of("ifreload"), SctlState::Exited);
        assert_eq!(st.status_of("nvued"), SctlState::Stopped);
        Ok(())
    }

    #[test]
    fn test_check_bgp_success() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();
        check_bgp(
            &mut health_data,
            BGP_SUMMARY_JSON_NO_ROUTE_SERVER_SUCCESS,
            &[],
            2,
            &[],
        );
        health_data.into_health_report(&mut hr);
        assert!(hr.alerts.is_empty());
        Ok(())
    }

    #[test]
    fn test_check_bgp_no_route_server_failed_tor_peers() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();
        check_bgp(
            &mut health_data,
            BGP_SUMMARY_JSON_NO_ROUTE_SERVER_FAILED_TOR_PEERS,
            &[],
            2,
            &[],
        );
        health_data.into_health_report(&mut hr);
        assert_eq!(hr.alerts.len(), 2);
        hr.alerts
            .sort_by(|alert1, alert2| alert1.target.cmp(&alert2.target));

        assert_eq!(
            hr.alerts[0],
            make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some("p0_sf".to_string()),
                "Session p0_sf is not Established, but in state Idle".to_string(),
                true
            )
        );
        assert_eq!(
            hr.alerts[1],
            make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some("p1_sf".to_string()),
                "Session p1_sf is not Established, but in state Idle".to_string(),
                true
            )
        );
        Ok(())
    }

    #[test]
    fn test_check_bgp_no_route_server_single_failed_tor_peer() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();

        check_bgp(
            &mut health_data,
            BGP_SUMMARY_JSON_NO_ROUTE_SERVER_SINGLE_FAILED_TOR_PEER,
            &[],
            2,
            &[],
        );
        health_data.into_health_report(&mut hr);
        assert_eq!(hr.alerts.len(), 1);
        hr.alerts
            .sort_by(|alert1, alert2| alert1.target.cmp(&alert2.target));

        assert_eq!(
            hr.alerts[0],
            make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some("p0_sf".to_string()),
                "Session p0_sf is not Established, but in state Idle".to_string(),
                true
            )
        );
        Ok(())
    }

    #[test]
    fn test_check_bgp_no_route_server_with_tenant_routes() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();
        check_bgp(
            &mut health_data,
            BGP_SUMMARY_JSON_NO_ROUTE_SERVER_WITH_TENANT_ROUTES,
            &["10.217.4.78"],
            2,
            &[],
        );
        health_data.into_health_report(&mut hr);
        assert!(hr.alerts.is_empty());
        Ok(())
    }

    #[test]
    fn test_check_bgp_no_route_server_unexpected_tenant_route() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();
        check_bgp(
            &mut health_data,
            BGP_SUMMARY_JSON_NO_ROUTE_SERVER_WITH_TENANT_ROUTES,
            &[],
            2,
            &[],
        );
        health_data.into_health_report(&mut hr);
        assert_eq!(hr.alerts.len(), 1);
        assert_eq!(
            hr.alerts[0],
            make_alert(
                probe_ids::UnexpectedBgpPeer.clone(),
                Some("10.217.4.78".to_string()),
                "Unexpected BGP session referencing peer 10.217.4.78 was found in ipv4_unicast"
                    .to_string(),
                true
            )
        );
        Ok(())
    }

    #[test]
    fn test_check_bgp_unexpected_route_server() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();
        check_bgp(
            &mut health_data,
            BGP_SUMMARY_JSON_WITH_ROUTE_SERVER_AND_TENANT_ROUTES,
            &["10.217.19.211"],
            2,
            &[],
        );
        health_data.into_health_report(&mut hr);
        hr.alerts.sort_by(|alert1, alert2| {
            (&alert1.id, &alert1.target).cmp(&(&alert2.id, &alert2.target))
        });

        assert_eq!(
            hr.alerts[0],
            make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some("p0_sf".to_string()),
                "Expected session for p0_sf was not found in BGP peer data".to_string(),
                true
            )
        );
        assert_eq!(
            hr.alerts[1],
            make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some("p1_sf".to_string()),
                "Expected session for p1_sf was not found in BGP peer data".to_string(),
                true
            )
        );
        assert_eq!(
            hr.alerts[2],
            make_alert(
                probe_ids::UnexpectedBgpPeer.clone(),
                Some("10.217.126.67".to_string()),
                "Unexpected BGP session referencing peer 10.217.126.67 was found in l2_vpn_evpn"
                    .to_string(),
                true
            )
        );

        Ok(())
    }

    #[test]
    fn test_check_bgp_with_route_server_and_tenant_routes() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();
        check_bgp(
            &mut health_data,
            BGP_SUMMARY_JSON_WITH_ROUTE_SERVER_AND_TENANT_ROUTES,
            &["10.217.19.211"],
            2,
            &["10.217.126.67".to_string()],
        );
        health_data.into_health_report(&mut hr);
        assert!(hr.alerts.is_empty());
        Ok(())
    }

    #[test]
    fn test_check_bgp_with_route_server_failed_all_peers() -> eyre::Result<()> {
        let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());
        let mut health_data = BgpHealthData::default();
        check_bgp(
            &mut health_data,
            BGP_SUMMARY_JSON_WITH_ROUTE_SERVER_FAILED_ALL_PEERS,
            &[],
            2,
            &["10.217.126.67".to_string()],
        );
        health_data.into_health_report(&mut hr);
        assert_eq!(hr.alerts.len(), 3);
        hr.alerts
            .sort_by(|alert1, alert2| alert1.target.cmp(&alert2.target));

        assert_eq!(
            hr.alerts[0],
            make_alert(
                probe_ids::BgpPeeringRouteServer.clone(),
                Some("10.217.126.67".to_string()),
                "Session 10.217.126.67 is not Established, but in state Active".to_string(),
                true
            )
        );
        assert_eq!(
            hr.alerts[1],
            make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some("p0_sf".to_string()),
                "Session p0_sf is not Established, but in state Idle".to_string(),
                true
            )
        );
        assert_eq!(
            hr.alerts[2],
            make_alert(
                probe_ids::BgpPeeringTor.clone(),
                Some("p1_sf".to_string()),
                "Session p1_sf is not Established, but in state Idle".to_string(),
                true
            )
        );
        Ok(())
    }

    #[test]
    fn test_parse_mlxprivhost() {
        assert_eq!(
            super::parse_mlxprivhost(MLXPRIVHOST_OUT).unwrap(),
            "RESTRICTED"
        );
    }
}
