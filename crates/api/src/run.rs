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

use std::sync::Arc;

use eyre::WrapErr;
use forge_secrets::forge_vault;
use forge_secrets::forge_vault::VaultConfig;
use tokio::sync::oneshot;
use tokio::sync::oneshot::{Receiver, Sender};
use tracing::subscriber::NoSubscriber;
use utils::HostPortPair;

use crate::logging::metrics_endpoint::{MetricsEndpointConfig, run_metrics_endpoint};
use crate::logging::setup::{
    Logging, create_metric_for_spancount_reader, create_metrics, setup_logging,
};
use crate::redfish::RedfishClientPoolImpl;
use crate::{CarbideError, dynamic_settings, setup};

pub async fn run(
    debug: u8,
    config_str: String,
    site_config_str: Option<String>,
    vault_config: VaultConfig,
    skip_logging_setup: bool,
    stop_channel: Receiver<()>,
    ready_channel: Sender<()>,
) -> eyre::Result<()> {
    let carbide_config = setup::parse_carbide_config(config_str, site_config_str)?;

    // Reject config that contains overlaps between deny_prefixes and site_fabric_prefixes.
    // deny_prefixes are IPv4-only; only check against IPv4 site fabric prefixes.
    for deny_prefix in carbide_config.deny_prefixes.iter() {
        for site_fabric_prefix in carbide_config.site_fabric_prefixes.iter() {
            if let ipnetwork::IpNetwork::V4(site_v4) = site_fabric_prefix
                && deny_prefix.overlaps(*site_v4)
            {
                return Err(eyre::eyre!(
                    "overlap found in deny_prefixes `{}` and site_fabric_prefixes `{}`",
                    deny_prefix,
                    site_fabric_prefix,
                ));
            }
        }
    }

    let tconf = if skip_logging_setup {
        Logging::default()
    } else {
        setup_logging(
            debug,
            crate::state_controller::machine::extra_logfmt_logging_fields(),
            None::<NoSubscriber>,
        )
        .wrap_err("setup_telemetry")?
    };

    // Redact credentials before printing the config
    let print_config = carbide_config.redacted();

    tracing::info!("Using configuration: {:#?}", print_config);
    tracing::info!(
        "Tokio worker thread count: {} (num_cpus::get()={}, TOKIO_WORKER_THREADS={})",
        tokio::runtime::Handle::current().metrics().num_workers(),
        num_cpus::get(),
        std::env::var("TOKIO_WORKER_THREADS").unwrap_or_else(|_| "UNSET".to_string())
    );

    let metrics = create_metrics()?;
    create_metric_for_spancount_reader(&metrics.meter, tconf.spancount_reader);

    // Spin up the webserver which servers `/metrics` requests
    let (metrics_stop_tx, metrics_stop_rx) = oneshot::channel();
    if let Some(metrics_address) = carbide_config.metrics_endpoint {
        // If a replacement prefix for "carbide_" is configured, also emit metrics under that
        let additional_prefix = carbide_config
            .alt_metric_prefix
            .clone()
            .map(|alt_prefix| ("carbide_".to_string(), alt_prefix));
        tokio::task::Builder::new()
            .name("metrics_endpoint")
            .spawn(async move {
                if let Err(e) = run_metrics_endpoint(
                    &MetricsEndpointConfig {
                        address: metrics_address,
                        registry: metrics.registry,
                        additional_prefix,
                    },
                    metrics_stop_rx,
                )
                .await
                {
                    tracing::error!("Metrics endpoint failed with error: {}", e);
                }
            })?;
    }

    let dynamic_settings = crate::dynamic_settings::DynamicSettings {
        log_filter: tconf.filter.clone(),
        create_machines: carbide_config.site_explorer.create_machines.clone(),
        bmc_proxy: carbide_config.site_explorer.bmc_proxy.clone(),
        tracing_enabled: tconf.tracing_enabled,
    };
    dynamic_settings.start_reset_task(dynamic_settings::RESET_PERIOD);

    tracing::info!(
        address = carbide_config.listen.to_string(),
        build_version = carbide_version::v!(build_version),
        build_date = carbide_version::v!(build_date),
        rust_version = carbide_version::v!(rust_version),
        "Start carbide-api",
    );

    let vault_client = forge_vault::create_vault_client(&vault_config, metrics.meter.clone())?;
    let redfish_pool = {
        let rf_pool = libredfish::RedfishClientPool::builder()
            .build()
            .map_err(CarbideError::from)?;

        // Support deprecated configuration for site_explorer.override_target_ip and override_target_port. Configuration should migrate to site_explorer.bmc_proxy.
        match (
            &carbide_config.site_explorer.override_target_ip,
            carbide_config.site_explorer.override_target_port,
            carbide_config.site_explorer.bmc_proxy.load().as_ref(),
        ) {
            (Some(_), _, Some(_)) => {
                tracing::warn!(
                    "Ignoring deprecated config site_explorer.override_target_ip, since site_explorer.bmc_proxy is also set. Please delete override_target_ip from site_explorer config."
                );
            }
            (Some(ip), maybe_target_port, None) => {
                tracing::warn!(
                    "Deprecated site_explorer.override_target_ip in carbide config. Setting site_explorer.bmc_proxy instead. Please migrate configuration."
                );
                if let Some(port) = maybe_target_port {
                    carbide_config.site_explorer.bmc_proxy.store(Arc::new(Some(
                        HostPortPair::HostAndPort(ip.to_string(), port),
                    )));
                } else {
                    carbide_config
                        .site_explorer
                        .bmc_proxy
                        .store(Arc::new(Some(HostPortPair::HostOnly(ip.to_string()))));
                }
            }
            (None, Some(port), None) => {
                tracing::warn!(
                    "Deprecated site_explorer.override_target_port in carbide config. Setting site_explorer.bmc_proxy instead. Please migrate configuration."
                );
                carbide_config
                    .site_explorer
                    .bmc_proxy
                    .store(Arc::new(Some(HostPortPair::PortOnly(port))));
            }
            (None, Some(_), Some(_)) => {
                tracing::warn!(
                    "Ignoring deprecated config site_explorer.override_target_port, since site_explorer.bmc_proxy is also set. Please delete override_target_port from site_explorer config."
                );
            }
            (None, None, _) => {} // leave bmc_proxy untouched
        }
        let redfish_pool = RedfishClientPoolImpl::new(
            vault_client.clone(),
            rf_pool,
            carbide_config.site_explorer.bmc_proxy.clone(),
        );
        Arc::new(redfish_pool)
    };

    // Split stop_channel into a task which will stop both the API server and metrics server
    let (api_stop_tx, api_stop_rx) = oneshot::channel();
    tokio::spawn(async move {
        stop_channel.await.inspect_err(|error| {
            tracing::error!(%error, "error waiting on stop channel");
        })?;
        _ = metrics_stop_tx.send(()).inspect_err(|_| {
            tracing::error!("could not send stop signal to metrics server. already stopped?");
        });
        _ = api_stop_tx.send(()).inspect_err(|_| {
            tracing::error!("could not send stop signal to api server. already stopped?");
        });
        Ok::<(), eyre::Report>(())
    });

    setup::start_api(
        carbide_config,
        metrics.meter,
        dynamic_settings,
        redfish_pool,
        vault_client,
        api_stop_rx,
        ready_channel,
    )
    .await
}
