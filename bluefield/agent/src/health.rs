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
    health_report.alerts.push(health_report::HealthProbeAlert {
        id: probe_id.into(),
        target: probe_target,
        in_alert_since: None,
        message,
        tenant_message: None,
        classifications: vec![
            health_report::HealthAlertClassification::prevent_allocations(),
            health_report::HealthAlertClassification::prevent_host_state_changes(),
        ],
    })
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
    min_healthy_links: Option<u32>,
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
    check_network_stats(&mut hr, &container_id, host_routes, min_healthy_links).await;
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
    min_healthy_links: Option<u32>,
) {
    // `vtysh` is HBN's shell.
    let bgp_stats = match hbn::run_in_container(
        container_id,
        &["vtysh", "-c", "show bgp summary json"],
        true,
    )
    .await
    {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!("check_network_stats show bgp summary: {err}");
            failed(hr, probe_ids::BgpStats.clone(), None, err.to_string());
            return;
        }
    };
    match check_bgp(&bgp_stats, host_routes, min_healthy_links) {
        Ok(_) => passed(hr, probe_ids::BgpStats.clone(), None),
        Err(err) => {
            tracing::warn!("check_network_stats bgp: {err}");
            failed(hr, probe_ids::BgpStats.clone(), None, err.to_string());
        }
    }
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
    bgp_json: &str,
    host_routes: &[&str],
    min_healthy_links: Option<u32>,
) -> eyre::Result<()> {
    let networks: BgpNetworks = serde_json::from_str(bgp_json)
        .map_err(|e| eyre::eyre!("failed to deserialize bgp_json: {bgp_json} with error: {e}"))?;
    check_bgp_stats(
        "ipv4_unicast",
        &networks.ipv4_unicast,
        host_routes,
        min_healthy_links,
    )?;
    check_bgp_stats("l2_vpn_evpn", &networks.l2_vpn_evpn, &[], min_healthy_links)
}

//when min_healthy_links is not specified, all links must be up and connected for the DPU to be considered healthy
//otherwise, we will only require this number of connected links to be considered healthy.
fn check_bgp_stats(
    name: &str,
    s: &BgpStats,
    ignored_peers: &[&str],
    min_healthy_links: Option<u32>,
) -> eyre::Result<()> {
    let num_ignored = ignored_peers.len() as u32;
    let max_unhealthy_peers =
        num_ignored + (s.total_peers - min_healthy_links.unwrap_or(s.total_peers));
    if s.failed_peers > max_unhealthy_peers {
        return Err(eyre::eyre!(
            "{name} failed peers is {} should be at most {}",
            s.failed_peers,
            ignored_peers.len(),
        ));
    }
    let (min_peers, max_peers): (u32, u32) = (1, 2 + num_ignored);
    if s.total_peers < min_peers || max_peers < s.total_peers {
        // One, two (+ ignored_peers) depending on uplink configuration
        return Err(eyre::eyre!(
            "{name} total peers is {} but should be between {min_peers} and {max_peers}",
            s.total_peers
        ));
    }
    if s.dynamic_peers != 0 {
        return Err(eyre::eyre!(
            "{name} dynamic peers is {} should be 0",
            s.dynamic_peers
        ));
    }
    type NamePeer<'a> = (&'a String, &'a BgpPeer);
    let (not_established_links, established_links): (Vec<NamePeer>, Vec<NamePeer>) =
        s.peers.iter().partition(|(peer_name, peer)| {
            !ignored_peers.contains(&peer_name.as_str()) && peer.state != "Established"
        });

    if (established_links.len() as u32) < min_healthy_links.unwrap_or(s.total_peers) {
        return Err(eyre::eyre!(
            "{name} has the following peer(s) with state not \"Established\":  '{:?}'",
            not_established_links,
        ));
    }

    Ok(())
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
    failed_peers: u32,
    total_peers: u32,
    dynamic_peers: u32,
    peers: HashMap<String, BgpPeer>,
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
    use super::{check_bgp, parse_status, SctlState};

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

    const BGP_SUMMARY_JSON_SUCCESS: &str = include_str!("hbn_bgp_summary.json");
    const BGP_SUMMARY_JSON_FAIL: &str = include_str!("hbn_bgp_summary_fail.json");
    const BGP_SUMMARY_JSON_WITH_IGNORE: &str = include_str!("hbn_bgp_summary_with_ignore.json");

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
        check_bgp(BGP_SUMMARY_JSON_SUCCESS, &[], None)
    }

    #[test]
    fn test_check_bgp_fail() -> eyre::Result<()> {
        let out = check_bgp(BGP_SUMMARY_JSON_FAIL, &[], None);
        assert!(out.is_err());

        let s_err = out.unwrap_err().to_string();
        let expected = "ipv4_unicast failed peers";
        assert!(
            s_err.starts_with(expected),
            "Expected '{expected}', got '{s_err}'"
        );
        Ok(())
    }

    #[test]
    fn test_check_bgp_with_ignore() -> eyre::Result<()> {
        check_bgp(BGP_SUMMARY_JSON_WITH_IGNORE, &["10.217.4.78"], None)
    }

    #[test]
    fn test_parse_mlxprivhost() {
        assert_eq!(
            super::parse_mlxprivhost(MLXPRIVHOST_OUT).unwrap(),
            "RESTRICTED"
        );
    }
}
