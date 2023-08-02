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

use std::{collections::HashMap, fmt, path::PathBuf, process::Command, str::FromStr};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::hbn;

const HBN_DAEMONS_FILE: &str = "/var/lib/hbn/etc/frr/daemons";
const EXPECTED_FILES: [&str; 4] = [
    "/var/lib/hbn/etc/frr/frr.conf",
    "/var/lib/hbn/etc/network/interfaces",
    "/var/lib/hbn/etc/supervisor/conf.d/default-isc-dhcp-relay.conf",
    HBN_DAEMONS_FILE,
];

const EXPECTED_SERVICES: [&str; 4] = ["frr", "isc-dhcp-relay-default", "nl2doca", "rsyslog"];

/// Check the health of HBN
pub fn health_check() -> HealthReport {
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
    check_bgp_daemon_enabled(&mut hr);
    check_network_stats(&mut hr, &container_id);
    check_ifreload(&mut hr, &container_id);
    check_files(&mut hr, &EXPECTED_FILES);

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

// Check HBN BGP stats
fn check_network_stats(hr: &mut HealthReport, container_id: &str) {
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
    match check_bgp(&bgp_stats) {
        Ok(_) => hr.passed(HealthCheck::BgpStats),
        Err(err) => {
            warn!("check_network_stats bgp: {err}");
            hr.failed(HealthCheck::BgpStats, err.to_string());
        }
    }
}

// `ifreload -a` should exit code 0 and have no output
fn check_ifreload(hr: &mut HealthReport, container_id: &str) {
    match run_in_container(container_id, &["ifreload", "-a"], true) {
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
fn check_files(hr: &mut HealthReport, expected_files: &[&str]) {
    for filename in expected_files {
        let path = PathBuf::from(filename);
        if path.exists() {
            hr.passed(HealthCheck::FileExists(filename.to_string()));
        } else {
            hr.failed(
                HealthCheck::FileExists(filename.to_string()),
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

fn check_bgp_daemon_enabled(hr: &mut HealthReport) {
    let daemons = match std::fs::read_to_string(HBN_DAEMONS_FILE) {
        Ok(s) => s,
        Err(err) => {
            warn!("check_bgp_daemon_enabled: {err}");
            hr.failed(
                HealthCheck::BgpDaemonEnabled,
                format!("Trying to open and read {HBN_DAEMONS_FILE}: {err}"),
            );
            return;
        }
    };

    if daemons.contains("bgpd=no") {
        hr.failed(
            HealthCheck::BgpDaemonEnabled,
            format!("BGP daemon is disabled - {HBN_DAEMONS_FILE} contains 'bgpd=no'"),
        );
        return;
    }
    if !daemons.contains("bgpd=yes") {
        hr.failed(
            HealthCheck::BgpDaemonEnabled,
            format!("BGP daemon is not enabled - {HBN_DAEMONS_FILE} does not contain 'bgpd=yes'"),
        );
        return;
    }

    hr.passed(HealthCheck::BgpDaemonEnabled);
}

fn check_bgp(bgp_json: &str) -> eyre::Result<()> {
    let networks: BgpNetworks = serde_json::from_str(bgp_json)?;
    check_bgp_stats("ipv4_unicast", &networks.ipv4_unicast)?;
    check_bgp_stats("l2_vpn_evpn", &networks.l2_vpn_evpn)
}

fn check_bgp_stats(name: &str, s: &BgpStats) -> eyre::Result<()> {
    if s.failed_peers != 0 {
        return Err(eyre::eyre!(
            "{name} failed peers is {} should be 0",
            s.failed_peers
        ));
    }
    if s.total_peers != 1 && s.total_peers != 2 {
        // One or two depending on uplink configuration
        return Err(eyre::eyre!(
            "{name} total peers is {} should be 1 or 2",
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
        if peer.state != "Established" {
            return Err(eyre::eyre!(
                "{name} {peer_name} state is '{}' should be 'Established'",
                peer.state
            ));
        }
    }

    Ok(())
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
    BgpStats,
    Ifreload,
    FileExists(String),
    FileIsValid(String),
    BgpDaemonEnabled,
}

impl fmt::Display for HealthReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_healthy() {
            write!(f, "OK")
        } else {
            write!(
                f,
                "Passed: {}, failed: {}, first failure: {}",
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
            Self::BgpStats => write!(f, "BgpStats"),
            Self::Ifreload => write!(f, "Ifreload"),
            Self::FileExists(file_name) => write!(f, "FileExists({})", file_name),
            Self::FileIsValid(file_name) => write!(f, "FileIsValid({})", file_name),
            Self::BgpDaemonEnabled => write!(f, "BgpDaemonEnabled"),
        }
    }
}

fn run_in_container(
    container_id: &str,
    command: &[&str],
    need_success: bool,
) -> eyre::Result<String> {
    let mut args = vec!["crictl", "exec", container_id];
    args.extend_from_slice(command);

    let mut sudo = Command::new("sudo");
    let cmd = sudo.args(args);
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

    const BGP_SUMMARY_JSON_SUCCESS: &str = include_str!("hbn_bgp_summary.json");
    const BGP_SUMMARY_JSON_FAIL: &str = include_str!("hbn_bgp_summary_fail.json");

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
        check_bgp(BGP_SUMMARY_JSON_SUCCESS)
    }

    #[test]
    fn test_check_bgp_fail() -> eyre::Result<()> {
        let out = check_bgp(BGP_SUMMARY_JSON_FAIL);
        assert!(out.is_err());

        let err = out.unwrap_err();
        assert!(err
            .to_string()
            .starts_with("ipv4_unicast failed peers is 2 should be 0"));
        Ok(())
    }
}
