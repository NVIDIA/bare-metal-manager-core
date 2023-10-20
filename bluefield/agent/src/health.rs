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

use std::{collections::HashMap, fmt, path::Path, process::Command, str::FromStr};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::hbn;

const HBN_DAEMONS_FILE: &str = "etc/frr/daemons";
const EXPECTED_FILES: [&str; 4] = [
    "etc/frr/frr.conf",
    "etc/network/interfaces",
    "etc/supervisor/conf.d/default-isc-dhcp-relay.conf",
    HBN_DAEMONS_FILE,
];

const EXPECTED_SERVICES: [&str; 3] = ["frr", "nl2doca", "rsyslog"];
const DHCP_RELAY_SERVICE: &str = "isc-dhcp-relay-default";

/// Check the health of HBN
pub fn health_check(hbn_root: &Path, host_routes: &[&str]) -> HealthReport {
    let mut hr = HealthReport::new();

    let container_id = match hbn::get_hbn_container_id() {
        Ok(id) => id,
        Err(err) => {
            hr.failed(HealthCheck::ContainerExists, err.to_string());
            return hr;
        }
    };
    hr.passed(HealthCheck::ContainerExists);

    check_hbn_services_running(&mut hr, &container_id, &EXPECTED_SERVICES);

    // At this point HBN is up so we can configure it

    check_dhcp_relay(&mut hr, &container_id);
    check_ifreload(&mut hr, &container_id);
    let hbn_daemons_file = hbn_root.join(HBN_DAEMONS_FILE);
    check_bgp_daemon_enabled(&mut hr, &hbn_daemons_file.to_string_lossy());
    check_network_stats(&mut hr, &container_id, host_routes);
    check_files(&mut hr, hbn_root, &EXPECTED_FILES);
    check_restricted_mode(&mut hr);

    hr
}

// HBN processes should be running
fn check_hbn_services_running(
    hr: &mut HealthReport,
    container_id: &str,
    expected_services: &[&str],
) {
    // `supervisorctl status` has exit code 3 if there are stopped processes (which we expect),
    // so final param is 'false' here.
    // https://github.com/Supervisor/supervisor/issues/1223
    let sctl = match run_in_container(container_id, &["supervisorctl", "status"], false) {
        Ok(s) => s,
        Err(err) => {
            warn!("check_hbn_services_running supervisorctl status: {err}");
            hr.failed(HealthCheck::SupervisorctlStatus, err.to_string());
            return;
        }
    };
    let st = match parse_status(&sctl) {
        Ok(s) => s,
        Err(err) => {
            warn!("check_hbn_services_running supervisorctl status parse: {err}");
            hr.failed(HealthCheck::SupervisorctlStatus, err.to_string());
            return;
        }
    };
    hr.passed(HealthCheck::SupervisorctlStatus);

    for service in expected_services.iter().map(|x| x.to_string()) {
        match st.status_of(&service) {
            SctlState::Running => hr.passed(HealthCheck::ServiceRunning(service)),
            status => {
                warn!("check_hbn_services_running {service}: {status}");
                hr.failed(
                    HealthCheck::ServiceRunning(service.clone()),
                    status.to_string(),
                );
            }
        }
    }
}

// dhcp relay should be running
// Very similar to check_hbn_services_running, except it happens _after_ we start configuring.
// The other services must be up before we start configuring.
fn check_dhcp_relay(hr: &mut HealthReport, container_id: &str) {
    // `supervisorctl status` has exit code 3 if there are stopped processes (which we expect),
    // so final param is 'false' here.
    // https://github.com/Supervisor/supervisor/issues/1223
    let sctl = match run_in_container(container_id, &["supervisorctl", "status"], false) {
        Ok(s) => s,
        Err(err) => {
            warn!("check_hbn_services_running supervisorctl status: {err}");
            hr.failed(HealthCheck::SupervisorctlStatus, err.to_string());
            return;
        }
    };
    let st = match parse_status(&sctl) {
        Ok(s) => s,
        Err(err) => {
            warn!("check_hbn_services_running supervisorctl status parse: {err}");
            hr.failed(HealthCheck::SupervisorctlStatus, err.to_string());
            return;
        }
    };

    match st.status_of(DHCP_RELAY_SERVICE) {
        SctlState::Running => hr.passed(HealthCheck::DhcpRelay),
        status => {
            warn!("check_dhcp_relay: {status}");
            hr.failed(HealthCheck::DhcpRelay, status.to_string());
        }
    }
}

// Check HBN BGP stats
fn check_network_stats(hr: &mut HealthReport, container_id: &str, host_routes: &[&str]) {
    // `vtysh` is HBN's shell.
    let bgp_stats = match run_in_container(
        container_id,
        &["vtysh", "-c", "show bgp summary json"],
        true,
    ) {
        Ok(s) => s,
        Err(err) => {
            warn!("check_network_stats show bgp summary: {err}");
            hr.failed(HealthCheck::BgpStats, err.to_string());
            return;
        }
    };
    match check_bgp(&bgp_stats, host_routes) {
        Ok(_) => hr.passed(HealthCheck::BgpStats),
        Err(err) => {
            warn!("check_network_stats bgp: {err}");
            hr.failed(HealthCheck::BgpStats, err.to_string());
        }
    }
}

// `ifreload` should exit code 0 and have no output
fn check_ifreload(hr: &mut HealthReport, container_id: &str) {
    match run_in_container(container_id, &["ifreload", "--all", "--syntax-check"], true) {
        Ok(stdout) => {
            if stdout.is_empty() {
                hr.passed(HealthCheck::Ifreload);
            } else {
                warn!("check_ifreload: {stdout}");
                hr.failed(HealthCheck::Ifreload, stdout);
            }
        }
        Err(err) => {
            warn!("check_ifreload: {err}");
            hr.failed(HealthCheck::Ifreload, err.to_string());
        }
    }
}

// The files VPC creates should exist
fn check_files(hr: &mut HealthReport, hbn_root: &Path, expected_files: &[&str]) {
    for filename in expected_files {
        let path = hbn_root.join(filename);
        if path.exists() {
            hr.passed(HealthCheck::FileExists(path.display().to_string()));
        } else {
            hr.failed(
                HealthCheck::FileExists(path.display().to_string()),
                "Not found".to_string(),
            );
            continue;
        }
        let stat = match std::fs::metadata(path) {
            Ok(s) => s,
            Err(err) => {
                warn!("check_files {filename}: {err}");
                hr.failed(
                    HealthCheck::FileIsValid(filename.to_string()),
                    err.to_string(),
                );
                continue;
            }
        };
        if stat.len() < 100 {
            warn!("check_files {filename}: Too small");
            hr.failed(
                HealthCheck::FileIsValid(filename.to_string()),
                "Too small".to_string(),
            );
        }
        hr.passed(HealthCheck::FileIsValid(filename.to_string()));
    }
}

fn check_bgp_daemon_enabled(hr: &mut HealthReport, hbn_daemons_file: &str) {
    let daemons = match std::fs::read_to_string(hbn_daemons_file) {
        Ok(s) => s,
        Err(err) => {
            warn!("check_bgp_daemon_enabled: {err}");
            hr.failed(
                HealthCheck::BgpDaemonEnabled,
                format!("Trying to open and read {hbn_daemons_file}: {err}"),
            );
            return;
        }
    };

    if daemons.contains("bgpd=no") {
        hr.failed(
            HealthCheck::BgpDaemonEnabled,
            format!("BGP daemon is disabled - {hbn_daemons_file} contains 'bgpd=no'"),
        );
        return;
    }
    if !daemons.contains("bgpd=yes") {
        hr.failed(
            HealthCheck::BgpDaemonEnabled,
            format!("BGP daemon is not enabled - {hbn_daemons_file} does not contain 'bgpd=yes'"),
        );
        return;
    }

    hr.passed(HealthCheck::BgpDaemonEnabled);
}

fn check_bgp(bgp_json: &str, host_routes: &[&str]) -> eyre::Result<()> {
    let networks: BgpNetworks = serde_json::from_str(bgp_json)?;
    check_bgp_stats("ipv4_unicast", &networks.ipv4_unicast, host_routes)?;
    check_bgp_stats("l2_vpn_evpn", &networks.l2_vpn_evpn, &[])
}

fn check_bgp_stats(name: &str, s: &BgpStats, ignored_peers: &[&str]) -> eyre::Result<()> {
    let num_ignored = ignored_peers.len() as u32;
    if s.failed_peers > num_ignored {
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
    for (peer_name, peer) in s.peers.iter() {
        if ignored_peers.contains(&peer_name.as_str()) {
            continue;
        }
        if peer.state != "Established" {
            return Err(eyre::eyre!(
                "{name} {peer_name} state is '{}' should be 'Established'",
                peer.state
            ));
        }
    }

    Ok(())
}

// A DPU should be in restricted mode
fn check_restricted_mode(hr: &mut HealthReport) {
    const EXPECTED_PRIV_LEVEL: &str = "RESTRICTED";
    let mut cmd = Command::new("bash");
    cmd.arg("-c")
        .arg("mlxprivhost -d /dev/mst/mt*_pciconf0 query");
    let out = match cmd.output() {
        Ok(out) => out,
        Err(err) => {
            hr.failed(
                HealthCheck::RestrictedMode,
                format!("Error running {}. {err}", super::pretty_cmd(&cmd)),
            );
            return;
        }
    };
    if !out.status.success() {
        tracing::debug!(
            "STDERR {}: {}",
            super::pretty_cmd(&cmd),
            String::from_utf8_lossy(&out.stderr)
        );
        hr.failed(
            HealthCheck::RestrictedMode,
            format!("{} for cmd '{}'", out.status, super::pretty_cmd(&cmd)),
        );
        return;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    match parse_mlxprivhost(s.as_ref()) {
        Ok(priv_level) if priv_level == EXPECTED_PRIV_LEVEL => {
            hr.passed(HealthCheck::RestrictedMode);
        }
        Ok(priv_level) => {
            hr.failed(
                HealthCheck::RestrictedMode,
                format!(
                    "mlxprivhost reports level '{priv_level}', expected '{EXPECTED_PRIV_LEVEL}'"
                ),
            );
        }
        Err(err) => {
            hr.failed(
                HealthCheck::RestrictedMode,
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
    let Some(level) = level_line.split(":").skip(1).next().map(|level| level.trim()) else {
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

// Health of HBN
#[derive(Debug, Default, Serialize)]
pub struct HealthReport {
    pub checks_passed: Vec<HealthCheck>,
    pub checks_failed: Vec<HealthCheck>,
    pub message: Option<String>,
}

impl HealthReport {
    fn new() -> HealthReport {
        Default::default()
    }

    fn passed(&mut self, hc: HealthCheck) {
        self.checks_passed.push(hc);
    }

    fn failed(&mut self, hc: HealthCheck, msg: String) {
        self.checks_failed.push(hc);
        if self.message.is_none() {
            self.message = Some(msg);
        }
    }

    /// Is enough of HBN ready so that we can configure it?
    pub fn is_up(&self) -> bool {
        let has_failed_services = self
            .checks_failed
            .iter()
            .any(|c| matches!(c, HealthCheck::ServiceRunning(_)));
        self.checks_passed.contains(&HealthCheck::ContainerExists)
            && self
                .checks_passed
                .contains(&HealthCheck::SupervisorctlStatus)
            && !has_failed_services
    }

    /// Is networking in the expected healthy normal connected state?
    pub fn is_healthy(&self) -> bool {
        !self.checks_passed.is_empty() && self.checks_failed.is_empty()
    }
}

// The things we check on an HBN to ensure it's in good health
#[derive(Debug, Serialize, PartialEq)]
pub enum HealthCheck {
    ContainerExists,
    SupervisorctlStatus,
    ServiceRunning(String),
    DhcpRelay,
    BgpStats,
    Ifreload,
    FileExists(String),
    FileIsValid(String),
    BgpDaemonEnabled,
    RestrictedMode,
}

impl fmt::Display for HealthReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_healthy() {
            write!(f, "OK")
        } else {
            write!(
                f,
                "Checks passed: {}, Checks failed: {}, First failure: {}",
                self.checks_passed
                    .iter()
                    .map(|hc| hc.to_string())
                    .collect::<Vec<String>>()
                    .join(","),
                self.checks_failed
                    .iter()
                    .map(|hc| hc.to_string())
                    .collect::<Vec<String>>()
                    .join(","),
                self.message.as_deref().unwrap_or_default()
            )
        }
    }
}

impl fmt::Display for HealthCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContainerExists => write!(f, "ContainerExists"),
            Self::SupervisorctlStatus => write!(f, "SupervisorctlStatus"),
            Self::ServiceRunning(service_name) => write!(f, "ServiceRunning({})", service_name),
            Self::DhcpRelay => write!(f, "DhcpRelay"),
            Self::BgpStats => write!(f, "BgpStats"),
            Self::Ifreload => write!(f, "Ifreload"),
            Self::FileExists(file_name) => write!(f, "FileExists({})", file_name),
            Self::FileIsValid(file_name) => write!(f, "FileIsValid({})", file_name),
            Self::BgpDaemonEnabled => write!(f, "BgpDaemonEnabled"),
            Self::RestrictedMode => write!(f, "RestrictedMode"),
        }
    }
}

fn run_in_container(
    container_id: &str,
    command: &[&str],
    need_success: bool,
) -> eyre::Result<String> {
    let mut crictl = Command::new("crictl");
    let mut args = vec!["exec", container_id];
    args.extend_from_slice(command);

    let cmd = crictl.args(args);
    let out = cmd.output()?;
    if need_success && !out.status.success() {
        debug!(
            "STDERR {}: {}",
            super::pretty_cmd(cmd),
            String::from_utf8_lossy(&out.stderr)
        );
        return Err(eyre::eyre!(
            "{} for cmd '{}'",
            out.status, // includes the string "exit status"
            super::pretty_cmd(cmd)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn parse_status(status_out: &str) -> eyre::Result<SctlStatus> {
    let mut m = HashMap::new();
    for line in status_out.lines() {
        let parts: Vec<&str> = line.split_ascii_whitespace().collect();
        if parts.len() < 2 {
            warn!("supervisorctl status line too short: '{line}'");
            continue;
        }
        let state: SctlState = match parts[1].parse() {
            Ok(s) => s,
            Err(_err) => {
                // unreachable but future proof. SctlState::from_str is currently infallible.
                warn!(
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
            _ => Self::Unknown,
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
        check_bgp(BGP_SUMMARY_JSON_SUCCESS, &[])
    }

    #[test]
    fn test_check_bgp_fail() -> eyre::Result<()> {
        let out = check_bgp(BGP_SUMMARY_JSON_FAIL, &[]);
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
        check_bgp(BGP_SUMMARY_JSON_WITH_IGNORE, &["10.217.4.78"])
    }

    #[test]
    fn test_parse_mlxprivhost() {
        assert_eq!(
            super::parse_mlxprivhost(MLXPRIVHOST_OUT).unwrap(),
            "RESTRICTED"
        );
    }
}
