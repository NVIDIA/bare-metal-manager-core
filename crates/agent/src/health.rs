/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, Instant};

use health_report::HealthProbeId;
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;

use crate::{HBNDeviceNames, hbn};
mod bgp;
pub mod probe_ids;

const HBN_DAEMONS_FILE: &str = "etc/frr/daemons";
const DHCP_SERVER_FILE: &str = "etc/supervisor/conf.d/default-forge-dhcp-server.conf";
// const NVUE_FILE: &str = "etc/nvue.d/startup.yaml";

const EXPECTED_FILES: [&str; 4] = [
    "etc/frr/frr.conf",
    "etc/network/interfaces",
    DHCP_SERVER_FILE,
    HBN_DAEMONS_FILE,
];

const EXPECTED_SERVICES: [&str; 3] = ["frr", "nl2doca", "rsyslog"];
const DHCP_SERVER_SERVICE: &str = "forge-dhcp-server-default";
/// Maximum allowed disk utilization in % before the DpuDiskUtilizationCritical health alert will be sent
const MAX_DISK_UTILIZATION: u32 = 85;

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
    hbn_device_names: HBNDeviceNames,
) -> health_report::HealthReport {
    let mut hr = health_report::HealthReport::empty("forge-dpu-agent".to_string());

    // Check whether the disk is full
    check_disk_utilization(&mut hr).await;

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
    check_dhcp_server(&mut hr, &container_id).await;
    check_ifreload(&mut hr, &container_id).await;
    let hbn_daemons_file = hbn_root.join(HBN_DAEMONS_FILE);
    bgp::check_daemon_enabled(&mut hr, &hbn_daemons_file.to_string_lossy());
    bgp::check_bgp_stats(
        &mut hr,
        &container_id,
        host_routes,
        min_healthy_links,
        route_servers,
        hbn_device_names,
    )
    .await;
    check_files(&mut hr, hbn_root, &EXPECTED_FILES);

    // If we just applied a new network config report network as unhealthy.
    // This gives HBN / BGP time to act on the config.
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
async fn check_dhcp_server(hr: &mut health_report::HealthReport, container_id: &str) {
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

    let dhcp_server_status = match st.status_of(DHCP_SERVER_SERVICE) {
        SctlState::Running => {
            passed(hr, probe_ids::DhcpServer.clone(), None);
            None
        }
        status => Some(status),
    };

    if let Some(x) = dhcp_server_status {
        tracing::warn!("check_dhcp_server: Not running.");
        failed(
            hr,
            probe_ids::DhcpServer.clone(),
            None,
            format!("Dhcp-server is not running. Status: {x}"),
        );
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

    if dhcp_server_size < MIN_SIZE {
        tracing::warn!("check_files {DHCP_SERVER_FILE}: Too small");
        failed(
            hr,
            probe_ids::FileIsValid.clone(),
            Some(DHCP_SERVER_FILE.to_string()),
            "Too small".to_string(),
        );
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

// Checks whether the disk is not full
async fn check_disk_utilization(hr: &mut health_report::HealthReport) {
    let mut cmd = TokioCommand::new("bash");
    cmd.arg("-c").arg("df -HP");
    cmd.kill_on_drop(true);

    let cmd_str = super::pretty_cmd(cmd.as_std());
    let Ok(cmd_res) = timeout(Duration::from_secs(10), cmd.output()).await else {
        failed(
            hr,
            probe_ids::DpuDiskUtilizationCheck.clone(),
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
                probe_ids::DpuDiskUtilizationCheck.clone(),
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
            probe_ids::DpuDiskUtilizationCheck.clone(),
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
    match parse_disk_utilization(s.as_ref()) {
        Ok(utilization) => match utilization.utilizations.get("/") {
            Some(u) => {
                if u.utilization > MAX_DISK_UTILIZATION {
                    failed(
                        hr,
                        probe_ids::DpuDiskUtilizationCritical.clone(),
                        None,
                        format!(
                            "Disk utilization for root path / is {} (bigger than 85%):\nTotal:{}\nUsed:{}\nAvailable:{}",
                            u.utilization, u.size, u.used, u.available
                        ),
                    );
                } else {
                    passed(hr, probe_ids::DpuDiskUtilizationCheck.clone(), None);
                }
            }
            None => {
                failed(
                    hr,
                    probe_ids::DpuDiskUtilizationCheck.clone(),
                    None,
                    format!(
                        "Disk utilization for rootfs is unknown. Gathered utilizations by mountpoint: {:?}",
                        utilization.utilizations
                    ),
                );
            }
        },
        Err(err) => {
            failed(
                hr,
                probe_ids::DpuDiskUtilizationCheck.clone(),
                None,
                format!("Failed to parse Disk utilization output: {err}"),
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiskUtilization {
    device: String,
    utilization: u32,
    available: String,
    used: String,
    size: String,
}

struct DiskUtilizations {
    /// Maps from mount point name to disk utilization
    utilizations: HashMap<String, DiskUtilization>,
}

/// Parses the output of df -HP
fn parse_disk_utilization(df_out: &str) -> eyre::Result<DiskUtilizations> {
    let mut u = HashMap::new();
    for line in df_out.lines().skip(1) {
        let parts: Vec<&str> = line.split_ascii_whitespace().collect();
        if parts.len() < 6 {
            tracing::warn!("du status line too short: '{line}'");
            continue;
        }

        let device = parts[0].to_string();
        let size = parts[1].to_string();
        let used = parts[2].to_string();
        let available = parts[3].to_string();
        let utilization = parts[4].trim_end_matches('%');
        let mount_point = parts[5].to_string();

        let utilization: u32 = match utilization.parse() {
            Ok(u) => u,
            Err(_) => {
                tracing::warn!("Can not parse disk utilization in line '{line}'");
                continue;
            }
        };

        u.insert(
            mount_point,
            DiskUtilization {
                utilization,
                available,
                used,
                size,
                device,
            },
        );
    }

    Ok(DiskUtilizations { utilizations: u })
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

    const DISKUTIL_OUT: &str = r#"Filesystem      Size  Used Avail Use% Mounted on
tmpfs            17G  4.1k   17G   1% /dev/shm
tmpfs           6.8G   17M  6.7G   1% /run
tmpfs           5.3M  8.2k  5.3M   1% /run/lock
/dev/mmcblk0p2   41G   12G   27G  31% /
/dev/mmcblk0p1   52M  9.0M   43M  18% /boot/efi
shm              68M     0   68M   0% /run/containerd/io.containerd.grpc.v1.cri/sandboxes/3c9db06a2021f14b6cb98d0583ae43909f282c6d670dd9da071bddf333caaa4e/shm
overlay          41G   12G   27G  31% /run/containerd/io.containerd.runtime.v2.task/k8s.io/3c9db06a2021f14b6cb98d0583ae43909f282c6d670dd9da071bddf333caaa4e/rootfs
shm              68M  8.2k   68M   1% /run/containerd/io.containerd.grpc.v1.cri/sandboxes/5e38cefc8507fcf3b872fa12f21bdbcc09244832c24a34871ef9d8d519fa37b9/shm
overlay          41G   12G   27G  31% /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e38cefc8507fcf3b872fa12f21bdbcc09244832c24a34871ef9d8d519fa37b9/rootfs
tmpfs           3.4G     0  3.4G   0% /run/user/1002
"#;

    #[test]
    fn test_parse_disk_utilization() {
        let utilizations = super::parse_disk_utilization(DISKUTIL_OUT).unwrap();

        assert_eq!(
            utilizations.utilizations,
            HashMap::from_iter([(
                "/dev/shm".to_string(),
                DiskUtilization {
                    device: "tmpfs".to_string(),
                    utilization: 1,
                    available: "17G".to_string(),
                    used: "4.1k".to_string(),
                    size: "17G".to_string()
                }
            ),
            (
                "/run".to_string(),
                DiskUtilization {
                    device: "tmpfs".to_string(),
                    utilization: 1,
                    available: "6.7G".to_string(),
                    used: "17M".to_string(),
                    size: "6.8G".to_string()
                }
            ),(
                "/run/lock".to_string(),
                DiskUtilization {
                    device: "tmpfs".to_string(),
                    utilization: 1,
                    available: "5.3M".to_string(),
                    used: "8.2k".to_string(),
                    size: "5.3M".to_string()
                }
            ),(
                "/".to_string(),
                DiskUtilization {
                    device: "/dev/mmcblk0p2".to_string(),
                    utilization: 31,
                    available: "27G".to_string(),
                    used: "12G".to_string(),
                    size: "41G".to_string()
                }
            ),(
                "/boot/efi".to_string(),
                DiskUtilization {
                    device: "/dev/mmcblk0p1".to_string(),
                    utilization: 18,
                    available: "43M".to_string(),
                    used: "9.0M".to_string(),
                    size: "52M".to_string()
                }
            ),(
                "/run/containerd/io.containerd.grpc.v1.cri/sandboxes/3c9db06a2021f14b6cb98d0583ae43909f282c6d670dd9da071bddf333caaa4e/shm".to_string(),
                DiskUtilization {
                    device: "shm".to_string(),
                    utilization: 0,
                    available: "68M".to_string(),
                    used: "0".to_string(),
                    size: "68M".to_string()
                }
            ),(
                "/run/containerd/io.containerd.runtime.v2.task/k8s.io/3c9db06a2021f14b6cb98d0583ae43909f282c6d670dd9da071bddf333caaa4e/rootfs".to_string(),
                DiskUtilization {
                    device: "overlay".to_string(),
                    utilization: 31,
                    available: "27G".to_string(),
                    used: "12G".to_string(),
                    size: "41G".to_string()
                }
            ),(
                "/run/containerd/io.containerd.grpc.v1.cri/sandboxes/5e38cefc8507fcf3b872fa12f21bdbcc09244832c24a34871ef9d8d519fa37b9/shm".to_string(),
                DiskUtilization {
                    device: "shm".to_string(),
                    utilization: 1,
                    available: "68M".to_string(),
                    used: "8.2k".to_string(),
                    size: "68M".to_string()
                }
            ),(
                "/run/containerd/io.containerd.runtime.v2.task/k8s.io/5e38cefc8507fcf3b872fa12f21bdbcc09244832c24a34871ef9d8d519fa37b9/rootfs".to_string(),
                DiskUtilization {
                    device: "overlay".to_string(),
                    utilization: 31,
                    available: "27G".to_string(),
                    used: "12G".to_string(),
                    size: "41G".to_string()
                }
            ),(
                "/run/user/1002".to_string(),
                DiskUtilization {
                    device: "tmpfs".to_string(),
                    utilization: 0,
                    available: "3.4G".to_string(),
                    used: "0".to_string(),
                    size: "3.4G".to_string()
                }
            )])
        );
    }

    #[test]
    fn test_parse_supervisorctl_status() -> eyre::Result<()> {
        let st = parse_status(SUPERVISORCTL_STATUS_OUT)?;
        assert_eq!(st.status_of("frr"), SctlState::Running);
        assert_eq!(st.status_of("ifreload"), SctlState::Exited);
        assert_eq!(st.status_of("nvued"), SctlState::Stopped);
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
