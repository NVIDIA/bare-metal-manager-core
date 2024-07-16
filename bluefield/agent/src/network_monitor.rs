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
use eyre::Result;
use futures::future::join_all;
use futures::{stream, StreamExt};
use serde::Serialize;
use serde_json::json;
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use tokio::sync::{mpsc, watch};
use tokio::task;
use tokio::time::{self, Duration, Instant};
use tracing::{error, warn};

use crate::instrumentation::MetricsState;

const MAX_PINGS_PER_DPU: u32 = 5;
const PING_INTERFACE: &str = "oob_net0"; // @TODO(Felicity): Change to use loopback interface
const DPU_LIST_FETCH_INTERVAL: u64 = 30 * 60;

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

/// Structure to store ping results for one DPU in one cycle
pub struct DpuPingResult {
    pub dpu_info: DpuInfo,
    pub success_count: u32,
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
pub struct NetworkMonitor<Pinger: Ping> {
    machine_id: String,                 // DPU id
    peer_dpus: Vec<DpuInfo>,            // List of peer DPUs to monitor
    metrics: Option<Arc<MetricsState>>, // Metrics for monitoring
    pinger: Arc<Pinger>,                // Pinger that help ping DPUs and get results
}

impl<Pinger: Ping> NetworkMonitor<Pinger> {
    pub fn new(
        machine_id: String,
        peer_dpus: Vec<DpuInfo>,
        metrics: Option<Arc<MetricsState>>,
        pinger: Arc<Pinger>,
    ) -> Self {
        Self {
            machine_id,
            peer_dpus,
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
        let mut peer_dpus_fetch_interval =
            tokio::time::interval(Duration::from_secs(DPU_LIST_FETCH_INTERVAL));
        let mut next_monitor_time = Instant::now();

        loop {
            tokio::select! {
                _ = close_receiver.changed() => {
                    break;
                }
                _ = peer_dpus_fetch_interval.tick() => {
                    match find_peer_dpu_machines(&self.machine_id, forge_api, client_config.clone()).await {
                        Ok(new_peer_dpus) => {
                            self.peer_dpus = new_peer_dpus;
                        }
                        Err(e) => {
                            error!("Failed to fetch list of peer DPUs: {}", e);
                            self.peer_dpus = Vec::new();
                        }
                    }
                }
                _ = time::sleep_until(next_monitor_time) => {
                    // Run the monitoring task and dynamically adjust the interval
                    let elapsed_time = self.run_monitor().await;
                    let interval = self.set_loop_interval(&elapsed_time);
                    next_monitor_time = Instant::now() + interval;
                }
            }
        }
    }

    /// Handle periodic monitor cycles
    pub async fn run_monitor(&mut self) -> Duration {
        let mut elapsed_time = Duration::from_secs(0);
        if self.peer_dpus.is_empty() {
            warn!("List of peer dpu is empty");
        } else {
            let start_time = Instant::now();
            self.run_onetime(false).await;
            elapsed_time = start_time.elapsed();
        }

        elapsed_time
    }

    /// Adjust loop period based on check duration, cap to next multiple of 30 seconds
    pub fn set_loop_interval(&self, elapsed_time: &Duration) -> Duration {
        Duration::from_secs(max(((elapsed_time.as_secs() + 29) / 30) * 30, 30))
    }

    /// Handle one time network check request from commandline
    pub async fn run_onetime(&mut self, enable_record_result: bool) {
        match self.monitor_concurrent(enable_record_result).await {
            Ok(Some(results)) => {
                if enable_record_result {
                    self.format_results(&results);
                }
            }
            Ok(None) => {
                if enable_record_result {
                    error!("Failed to enable record result");
                }
            }
            Err(e) => {
                error!("Failed to run network check: {}", e);
            }
        }
    }

    /// Concurrently ping and record result for monitoring network status to peer DPUs
    pub async fn monitor_concurrent(
        &self,
        enable_record_result: bool,
    ) -> Result<Option<Vec<DpuPingResult>>, eyre::Report> {
        let concurrent_limit = 100;

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
        stream::iter(&self.peer_dpus)
            .for_each_concurrent(concurrent_limit, |peer_dpu| {
                let metrics = self.metrics.clone();
                let machine_id = self.machine_id.clone();
                let tx_clone = tx.clone();
                async move {
                    match self.pinger.ping_dpu(peer_dpu.clone()).await {
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
                                    error!(
                                        "Failed to record result for dpu {}: {}",
                                        peer_dpu.id, e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to ping dpu {}: {}", peer_dpu.id, e);
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
    fn format_results(&self, results: &[DpuPingResult]) {
        let formatted_results: Vec<_> = results
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

        let final_result = json!({
            "dpu id": self.machine_id,
            "results": formatted_results,
            "timestamp": Utc::now().timestamp(),
        });

        match serde_json::to_string_pretty(&final_result) {
            Ok(json) => println!("{}", json),
            Err(e) => error!("Failed to serialize results to JSON: {}", e),
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

/// Finds peer DPUs
pub async fn find_peer_dpu_machines(
    dpu_machine_id: &str,
    forge_api: &str,
    client_config: ForgeClientConfig,
) -> Result<Vec<DpuInfo>, eyre::Report> {
    // Get list of DPU information from API
    let dpu_info_list = fetch_dpu_info_list(forge_api, client_config).await?;

    // Remove this DPU from the list
    let peer_dpus: Vec<DpuInfo> = dpu_info_list
        .dpu_list
        .into_iter()
        .filter(|dpu_info| dpu_info.id != dpu_machine_id)
        .filter_map(|dpu_info| {
            IpAddr::from_str(&dpu_info.loopback_ip)
                .ok()
                .map(|ip| DpuInfo {
                    id: dpu_info.id,
                    ip,
                })
        })
        .collect();

    Ok(peer_dpus)
}

#[async_trait]
pub trait Ping {
    /// Ping a DPU and return the result
    async fn ping_dpu(&self, dpu_info: DpuInfo) -> Result<DpuPingResult>;
}

pub struct Pinger;

#[async_trait]
impl Ping for Pinger {
    async fn ping_dpu(&self, dpu_info: DpuInfo) -> Result<DpuPingResult> {
        // Bind pinger to the admin interface
        // @TODO(Felicity): bind to the loopback interface
        let config = Config::builder().interface(PING_INTERFACE).build();
        let client = Client::new(&config)?;

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
        for result in results {
            match result {
                Ok(res) => match res {
                    Ok((_packet, duration)) => {
                        total_duration += duration;
                        success_count += 1;
                    }
                    Err(e) => {
                        warn!("Ping error on {}: {}", dpu_info.ip, e);
                    }
                },
                Err(e) => {
                    warn!("Task join error: {:?}", e);
                }
            }
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
