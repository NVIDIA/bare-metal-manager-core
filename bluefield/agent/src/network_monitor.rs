use std::cmp::max;
use std::fmt;
use std::hash::Hash;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use ::rpc::forge::{self as rpc};
use ::rpc::forge_tls_client::{ApiConfig, ForgeClientConfig, ForgeTlsClient};
use axum::async_trait;
use chrono::Utc;
use clap::ValueEnum;
use eyre::{Context, Result};
use futures::future::join_all;
use futures::{stream, StreamExt};
use regex::Regex;
use serde::Serialize;
use serde_json::json;
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use tokio::sync::{mpsc, watch};
use tokio::task;
use tokio::time::{self, Duration, Instant};

use crate::hbn;
use crate::instrumentation::MetricsState;

// @TODO: this should be able to be configured
const MAX_PINGS_PER_DPU: u32 = 5; // Number of pings for each DPU in each check cycle
const DPU_LIST_FETCH_INTERVAL: u64 = 30 * 60; // Interval in seconds for fetching DPU list from API

/// Structure to store peer DPU information
#[derive(Debug, Eq, PartialEq, Hash, Clone, Serialize)]
pub struct DpuInfo {
    pub id: String,
    pub ip: IpAddr,
}

impl fmt::Display for DpuInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DpuInfo {{ id: {}, ip: {} }}", self.id, self.ip)
    }
}

impl TryFrom<rpc::DpuInfo> for DpuInfo {
    type Error = std::net::AddrParseError;

    fn try_from(rpc_info: rpc::DpuInfo) -> Result<Self, Self::Error> {
        let ip = IpAddr::from_str(&rpc_info.loopback_ip)?;
        Ok(DpuInfo {
            id: rpc_info.id,
            ip,
        })
    }
}

/// Structure to store ping results for one DPU in one cycle
pub struct DpuPingResult {
    pub dpu_info: DpuInfo,
    pub success_count: u32, // Number of successful pings, <= MAX_PINGS_PER_DPU
    pub average_latency: Option<Duration>, // None if ping not successful, i.e. success_count = 0
}

impl DpuPingResult {
    pub fn loss_percent(&self) -> f64 {
        let max_pings = MAX_PINGS_PER_DPU as f64;
        (max_pings - (self.success_count as f64)) / max_pings
    }

    pub fn reachable(&self) -> bool {
        self.success_count > 0
    }
}

/// Network monitor struct handles network connectivity checks
pub struct NetworkMonitor {
    machine_id: String,                 // DPU id
    metrics: Option<Arc<MetricsState>>, // Metrics for monitoring
    pinger: Arc<dyn Ping>,              // Pinger that help ping DPUs and get results
}

impl NetworkMonitor {
    pub fn new(
        machine_id: String,
        metrics: Option<Arc<MetricsState>>,
        pinger: Arc<dyn Ping>,
    ) -> Self {
        Self {
            machine_id,
            metrics,
            pinger,
        }
    }

    pub async fn run(
        &mut self,
        forge_api: &str,
        client_config: ForgeClientConfig,
        close_receiver: &mut watch::Receiver<bool>,
    ) {
        // Initial fetch peer dpu list from API
        let mut peer_dpus = Vec::new();
        let mut loopback_ip: Option<IpAddr> = None;

        match self
            .find_peer_dpu_machines(&self.machine_id, forge_api, client_config.clone())
            .await
        {
            Ok((dpu_info, new_peer_dpus)) => {
                peer_dpus = new_peer_dpus;
                loopback_ip = Some(dpu_info.ip);
            }
            Err(e) => {
                tracing::debug!("Network monitor failed to get dpu info list from API {}", e);
            }
        }

        let mut peer_dpus_fetch_interval =
            tokio::time::interval(Duration::from_secs(DPU_LIST_FETCH_INTERVAL));
        let mut next_monitor_time = Instant::now();

        loop {
            tokio::select! {
                _ = close_receiver.changed() => {
                    tracing::info!("Network monitor stopped");
                    break;
                }
                _ = peer_dpus_fetch_interval.tick() => {
                    match self.find_peer_dpu_machines(&self.machine_id, forge_api, client_config.clone()).await {
                        Ok((dpu_info, new_peer_dpus)) => {
                            peer_dpus = new_peer_dpus;
                            loopback_ip = Some(dpu_info.ip);
                        }
                        Err(e) => {
                            tracing::debug!("Network monitor failed to get dpu info list from API {}", e);
                            peer_dpus = Vec::new();
                            loopback_ip = None;
                        }
                    }
                }
                _ = time::sleep_until(next_monitor_time) => {
                    // Run the monitoring task and dynamically adjust the interval
                    let elapsed_time = self.run_monitor(&peer_dpus, loopback_ip).await;
                    let interval = self.set_loop_interval(&elapsed_time);
                    next_monitor_time = Instant::now() + interval;
                }
            }
        }
    }

    /// Handle periodic monitor cycles
    pub async fn run_monitor(
        &mut self,
        peer_dpus: &Vec<DpuInfo>,
        loopback_ip: Option<IpAddr>,
    ) -> Duration {
        let mut elapsed_time = Duration::from_secs(0);
        if let (Some(ip), false) = (loopback_ip, peer_dpus.is_empty()) {
            let start_time = Instant::now();
            if let Err(e) = self.monitor_concurrent(peer_dpus, ip, false).await {
                tracing::error!("Failed to run network check: {}", e);
            }
            elapsed_time = start_time.elapsed();
        }

        elapsed_time
    }

    /// Adjust loop period based on check duration, cap to next multiple of 30 seconds
    pub fn set_loop_interval(&self, elapsed_time: &Duration) -> Duration {
        // @TODO: make interval configurable
        Duration::from_secs(max(((elapsed_time.as_secs() + 29) / 30) * 30, 30))
    }

    /// Handle one time network check request from commandline
    /// Fetches new list from
    pub async fn run_onetime(&mut self, forge_api: &str, client_config: ForgeClientConfig) {
        let (loopback_ip, peer_dpus) = match self
            .find_peer_dpu_machines(&self.machine_id, forge_api, client_config.clone())
            .await
        {
            Ok((dpu_info, new_peer_dpus)) => (dpu_info.ip, new_peer_dpus),
            Err(e) => {
                tracing::error!("Network monitor failed to get dpu info list from API {}", e);
                return;
            }
        };

        match self.monitor_concurrent(&peer_dpus, loopback_ip, true).await {
            Ok(Some(results)) => self.format_results(&results, loopback_ip.to_string()),
            Ok(None) => tracing::info!("No results found"),
            Err(e) => tracing::error!("Failed to run network check: {}", e),
        }
    }

    /// Concurrently ping and record result for monitoring network status to peer DPUs
    /// Only log information here
    pub async fn monitor_concurrent(
        &self,
        peer_dpus: &Vec<DpuInfo>,
        loopback_ip: IpAddr,
        enable_record_result: bool,
    ) -> Result<Option<Vec<DpuPingResult>>, eyre::Report> {
        let concurrent_limit = 20; // Important for not overwhelming hbn container exec

        let (tx, mut rx) = mpsc::channel(100);

        let recv_task = enable_record_result.then(|| {
            task::spawn(async move {
                let mut results = Vec::new();
                while let Some(result) = rx.recv().await {
                    results.push(result);
                }
                results
            })
        });

        // Concurrent jobs to ping DPUs and get results
        stream::iter(peer_dpus)
            .for_each_concurrent(concurrent_limit, |peer_dpu| {
                let metrics = self.metrics.clone();
                let machine_id = self.machine_id.clone();
                let peer_dpu_id = peer_dpu.id.clone();
                let tx_clone = tx.clone();
                async move {
                    match self.pinger.ping_dpu(peer_dpu.clone(), loopback_ip).await {
                        Ok(ping_result) => {
                            // Export metrics if metadata service enabled
                            if let Some(metrics) = &metrics {
                                metrics.record_metrics(
                                    machine_id.clone(),
                                    ping_result.dpu_info.id.clone(),
                                    ping_result.average_latency,
                                    ping_result.reachable(),
                                    ping_result.loss_percent(),
                                );
                            }

                            if enable_record_result {
                                if let Err(e) = tx_clone.send(ping_result).await {
                                    tracing::error!(
                                        "Failed to record result for dpu {}: {}",
                                        peer_dpu.id,
                                        e
                                    );
                                }
                            }
                        }
                        Err((error_type, _report)) => {
                            self.record_error_metrics(error_type, Some(peer_dpu_id.clone()));
                        }
                    }
                }
            })
            .await;

        drop(tx);

        if let Some(task) = recv_task {
            let results = task.await?;
            Ok(Some(results))
        } else {
            Ok(None)
        }
    }

    /// Format check results into JSON format
    fn format_results(&self, results: &[DpuPingResult], loopback_ip: String) {
        let mut formatted_results: Vec<_> = results
            .iter()
            .map(|result| {
                let mut json_result = json!({
                    "peer_dpu_id": result.dpu_info.id.clone(),
                    "loopback_ip": result.dpu_info.ip.clone(),
                    "reachable": result.reachable(),
                    "loss_percent": result.loss_percent(),
                });

                if let Some(latency) = result.average_latency {
                    json_result["average_latency"] = json!(latency.as_secs_f64());
                } else {
                    json_result["average_latency"] = json!("N/A".to_string());
                }
                json_result
            })
            .collect();

        // Sort the result based on peer_dpu_id lexicographically
        formatted_results.sort_by(|a, b| a["peer_dpu_id"].as_str().cmp(&b["peer_dpu_id"].as_str()));

        let final_result = json!({
            "dpu_id": self.machine_id,
            "loopback_ip": if loopback_ip.is_empty() { "Unknown".to_string() } else { loopback_ip} ,
            "results": formatted_results,
            "timestamp": Utc::now().timestamp(),
        });

        match serde_json::to_string_pretty(&final_result) {
            Ok(json) => println!("{}", json),
            Err(e) => tracing::error!("Failed to serialize results to JSON: {}", e),
        }
    }

    /// Finds peer DPUs
    pub async fn find_peer_dpu_machines(
        &self,
        dpu_machine_id: &str,
        forge_api: &str,
        client_config: ForgeClientConfig,
    ) -> Result<(DpuInfo, Vec<DpuInfo>), eyre::Report> {
        // Get list of DPU information from API
        let dpu_info_list = fetch_dpu_info_list(forge_api, client_config)
            .await
            .map_err(|e| {
                self.record_error_metrics(NetworkMonitorError::ApiRpcCallError, None);
                e
            })?;

        // Get this DPU loopback IP
        let dpu_info: DpuInfo = dpu_info_list
            .dpu_list
            .iter()
            .find(|dpu_info| dpu_info.id == dpu_machine_id)
            .ok_or_else(|| eyre::eyre!("DPU with id {} not found", dpu_machine_id))?
            .clone()
            .try_into()
            .map_err(|error| {
                self.record_error_metrics(NetworkMonitorError::DpuNotFound, None);
                error
            })?;

        // Remove this DPU from the list
        let peer_dpus: Vec<DpuInfo> = dpu_info_list
            .dpu_list
            .into_iter()
            .filter(|dpu_info| dpu_info.id != dpu_machine_id)
            .filter_map(|dpu_info| dpu_info.try_into().ok())
            .collect();

        Ok((dpu_info, peer_dpus))
    }

    fn record_error_metrics(&self, error_type: NetworkMonitorError, dest_dpu_id: Option<String>) {
        if let Some(metrics) = &self.metrics.clone() {
            match dest_dpu_id {
                Some(dest_dpu_id) => metrics.record_communication_error(
                    self.machine_id.clone(),
                    dest_dpu_id,
                    error_type.to_string(),
                ),
                None => {
                    metrics.record_monitor_error(self.machine_id.clone(), error_type.to_string())
                }
            };
        }
    }
}

/// Fetches the list of DPU information from the API
pub(crate) async fn fetch_dpu_info_list(
    forge_api: &str,
    client_config: ForgeClientConfig,
) -> Result<rpc::GetDpuInfoListResponse, eyre::Report> {
    let api_config = ApiConfig::new(forge_api, client_config);
    let mut client = ForgeTlsClient::retry_build(&api_config)
        .await
        .map_err(|err| {
            eyre::Report::new(err).wrap_err(format!(
                "Could not connect to Forge API server at {forge_api}"
            ))
        })?;

    let request = tonic::Request::new(rpc::GetDpuInfoListRequest {});
    let response: tonic::Response<rpc::GetDpuInfoListResponse> =
        client.get_dpu_info_list(request).await.map_err(|err| {
            eyre::Report::new(err)
                .wrap_err(format!("forge_api: {forge_api}"))
                .wrap_err("Error while executing the GetDpuInfoList gRPC call")
        })?;

    Ok(response.into_inner())
}

#[async_trait]
pub trait Ping: Send + Sync {
    /// Ping a DPU and return the ping result
    async fn ping_dpu(
        &self,
        dpu_info: DpuInfo,
        loopback_ip: IpAddr,
    ) -> Result<DpuPingResult, (NetworkMonitorError, eyre::Report)>;
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum NetworkPingerType {
    HbnExec,
    OobNetBind,
}

impl fmt::Display for NetworkPingerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Clone)]
pub struct ParseNetworkPingerTypeError;

impl TryFrom<i32> for NetworkPingerType {
    type Error = ParseNetworkPingerTypeError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(NetworkPingerType::HbnExec),
            1 => Ok(NetworkPingerType::OobNetBind),
            _ => Err(ParseNetworkPingerTypeError),
        }
    }
}

impl FromStr for NetworkPingerType {
    type Err = ParseNetworkPingerTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "HbnExec" => Ok(NetworkPingerType::HbnExec),
            "OobNetBind" => Ok(NetworkPingerType::OobNetBind),
            _ => Err(ParseNetworkPingerTypeError),
        }
    }
}

impl From<NetworkPingerType> for Arc<dyn Ping> {
    fn from(ping_type: NetworkPingerType) -> Self {
        match ping_type {
            NetworkPingerType::HbnExec => Arc::new(HbnExecPinger),
            NetworkPingerType::OobNetBind => Arc::new(OobNetBindPinger),
        }
    }
}

/// Pinger that binds to the oob_net0 interface
pub struct OobNetBindPinger;

#[async_trait]
impl Ping for OobNetBindPinger {
    /// Pings a dpu from oob_net0 interface
    ///
    /// # Parameters
    /// - `dpu_info`: the peer dpu that is pinged
    /// - `_interface`: not used
    ///
    /// # Returns
    /// - `Ok(DpuPingResult)`: If is successful or if all pings fail with a timeout but no other errors.
    /// - `Err(eyre::Report)`: If fails with an unexpected error.
    async fn ping_dpu(
        &self,
        dpu_info: DpuInfo,
        _loopback_ip: IpAddr,
    ) -> Result<DpuPingResult, (NetworkMonitorError, eyre::Report)> {
        let interface = "oob_net0";
        let config = Config::builder().interface(interface).build();
        let client = Client::new(&config).map_err(|e| {
            let error_message = format!("Unable to build pinger with interface {interface}: {}", e);
            (
                NetworkMonitorError::PingInterfaceError,
                eyre::eyre!(error_message),
            )
        })?;

        // For each IP, ping MAX_PINGS_PER_DPU times
        let ping_futures = (0..MAX_PINGS_PER_DPU)
            .map(|seq_num| {
                let client_clone = client.clone();
                let ip_inner = dpu_info.ip;
                task::spawn(async move {
                    let mut pinger = client_clone
                        .pinger(ip_inner, PingIdentifier(rand::random()))
                        .await;
                    // Set each ping to have timeout of 1 second
                    pinger.timeout(Duration::from_secs(1));
                    pinger
                        .ping(PingSequence(seq_num.try_into().unwrap()), &[])
                        .await
                })
            })
            .collect::<Vec<_>>();

        // Get averaged result over all pings
        let results = join_all(ping_futures).await;
        let mut total_duration = Duration::new(0, 0);
        let mut success_count = 0;
        for (_packet, duration) in results.into_iter().flatten().flatten() {
            total_duration += duration;
            success_count += 1;
        }

        let average_latency = (success_count > 0).then(|| total_duration / success_count);

        let ping_result: DpuPingResult = DpuPingResult {
            dpu_info,
            success_count,
            average_latency,
        };

        Ok(ping_result)
    }
}

/// Pinger that uses crictl to execute ping command inside HBN container
/// from the loopback interface.  
pub struct HbnExecPinger;
#[async_trait]
impl Ping for HbnExecPinger {
    /// Pings a dpu from loopback interface inside HBN container.
    ///
    /// # Parameters
    /// - `dpu_info`: the peer dpu that is pinged
    /// - `interface`: IP address of loopback interface of HBN container that we are pinging from
    ///
    /// # Returns
    /// - `Ok(DpuPingResult)`: If is successful or if all pings fail with a timeout but no other errors.
    /// - `Err(eyre::Report)`: If fails with an unexpected error.
    async fn ping_dpu(
        &self,
        dpu_info: DpuInfo,
        loopback_ip: IpAddr,
    ) -> Result<DpuPingResult, (NetworkMonitorError, eyre::Report)> {
        let container_id: String = hbn::get_hbn_container_id()
            .await
            .wrap_err("Failed to get hbn container id")
            .map_err(|e| (NetworkMonitorError::HbnContainerIdNotFound, e))?;

        match hbn::run_in_container(
            &container_id,
            &[
                "ping",
                "-W",
                "1",
                "-c",
                &MAX_PINGS_PER_DPU.to_string(),
                "-I",
                &loopback_ip.to_string(),
                &dpu_info.ip.to_string(),
            ],
            true,
        )
        .await
        {
            Ok(stdout) => parse_ping_stdout(dpu_info, &stdout)
                .map_err(|e| (NetworkMonitorError::PingOutputParseError, e)),
            Err(err) => {
                // Ping fail could be 100% loss or error, 100% loss is treated as unreachable but not error
                let err_string = format!("{err}");
                let err_re = Regex::new(
                    r"(?s)cmd \'(.+)\' failed with status: (.+), stderr: (.+), stdout: (.+)",
                )
                .map_err(|regex_err| {
                    (
                        NetworkMonitorError::PingOutputParseError,
                        eyre::eyre!(
                            "Unexpected parse error for container ping result: {}",
                            regex_err.to_string()
                        ),
                    )
                })?;

                let stdout = err_re
                    .captures(&err_string)
                    .and_then(|caps| caps.get(4).map(|m| m.as_str()))
                    .ok_or_else(|| {
                        (
                            NetworkMonitorError::HbnContainerCommandExecError,
                            eyre::eyre!("Error running ping in container: {}", err),
                        )
                    })?;

                parse_ping_stdout(dpu_info, stdout)
                    .map_err(|e| (NetworkMonitorError::PingOutputParseError, e))
            }
        }
    }
}

/// Parse ping standard output to valid dpu ping result,
/// including number of successful pings and average latency.
pub fn parse_ping_stdout(dpu_info: DpuInfo, stdout: &str) -> Result<DpuPingResult, eyre::Report> {
    let summary_re = Regex::new(r"(\d+) packets transmitted, (\d+) received, (\d+)% packet loss")?;
    let rtt_re = Regex::new(r"rtt min/avg/max/mdev = [\d\.]+/([\d\.]+)/[\d\.]+/[\d\.]+ ms")?;

    let mut lines_iter = stdout.lines().rev();
    let rtt_line = lines_iter
        .next()
        .ok_or_else(|| eyre::eyre!("Failed to find RTT line"))?;
    let summary_line = lines_iter
        .next()
        .ok_or_else(|| eyre::eyre!("Failed to find summary line"))?;

    let success_count = summary_re
        .captures(summary_line)
        .and_then(|caps| caps.get(2).and_then(|m| m.as_str().parse::<u32>().ok()))
        .ok_or_else(|| eyre::eyre!("Failed to parse number of success packets"))?;

    if success_count == 0 {
        return Ok(DpuPingResult {
            dpu_info,
            success_count,
            average_latency: None,
        });
    }

    let latency = rtt_re
        .captures(rtt_line)
        .and_then(|caps| caps.get(1).and_then(|m| m.as_str().parse::<f64>().ok()))
        .ok_or_else(|| eyre::eyre!("Failed to average latency"))?;

    Ok(DpuPingResult {
        dpu_info,
        success_count,
        average_latency: Some(Duration::from_secs_f64(latency / 1000.0)),
    })
}

#[derive(Debug)]
pub enum NetworkMonitorError {
    ApiRpcCallError,
    DpuNotFound,
    HbnContainerIdNotFound,
    HbnContainerCommandExecError,
    PingError,
    PingInterfaceError,
    PingOutputParseError,
    UnknownError,
}

impl fmt::Display for NetworkMonitorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
