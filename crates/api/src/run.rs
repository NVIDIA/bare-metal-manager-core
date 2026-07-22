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

use std::path::PathBuf;

use carbide_api_core::AdminUiRoutesBuilder;
use carbide_api_core::bootstrap::{CoreRunInputs, Logging, run_core};
use carbide_secrets::CredentialConfig;
use eyre::WrapErr;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::subscriber::NoSubscriber;

use crate::logging::setup_logging;
use crate::metrics::{Metrics, setup_metrics};

/// Run the carbide-api server until `cancel_token` is cancelled.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    debug: u8,
    config_path: PathBuf,
    site_config_path: Option<PathBuf>,
    credential_config: CredentialConfig,
    skip_logging_setup: bool,
    admin_ui_routes_builder: Option<AdminUiRoutesBuilder>,
    cancel_token: CancellationToken,
    ready_channel: Sender<()>,
) -> eyre::Result<()> {
    let carbide_config = carbide_api_core::cfg::load::parse_carbide_config(
        &config_path,
        site_config_path.as_deref(),
    )?;

    // If `CarbideConfig.initial_objects_file` is set, load it into an
    // `InitialObjectsConfig` so that `start_api` can reconcile its contents
    // against the database on first startup.
    let initial_objects = if let Some(path) = carbide_config.initial_objects_file.as_deref() {
        Some(carbide_api_core::cfg::load::parse_initial_objects_config(
            path,
        )?)
    } else {
        None
    };

    validate_network_prefixes(&carbide_config)?;

    let log_history_max_bytes = carbide_config
        .log_history
        .max_megabytes
        .saturating_mul(1024 * 1024);
    let logging = if skip_logging_setup {
        Logging::default()
    } else {
        setup_logging(
            debug,
            carbide_machine_controller::extra_logfmt_logging_fields(),
            None::<NoSubscriber>,
            log_history_max_bytes,
            carbide_config.enable_admin_ui,
            &carbide_config.tracing,
        )
        .wrap_err("setup_telemetry")?
    };

    let Metrics {
        registry,
        meter,
        _meter_provider,
    } = setup_metrics(logging.spancount_reader.clone())?;

    // All background tasks that run "forever" (until canceled) are added to this JoinSet. When
    // initialization is complete, we use [`JoinSet::join_all`] to wait for them all to complete,
    // while propagating any panics to the current task.
    let mut join_set = JoinSet::new();
    start_metrics_endpoint(
        &mut join_set,
        &carbide_config,
        registry,
        cancel_token.clone(),
    )?;
    let per_object_metrics =
        start_per_object_metrics_endpoint(&mut join_set, &carbide_config, cancel_token.clone())?;

    run_core(CoreRunInputs {
        carbide_config,
        initial_objects,
        credential_config,
        logging,
        meter,
        per_object_metrics,
        join_set: &mut join_set,
        admin_ui_routes_builder,
        cancel_token,
        ready_channel,
    })
    .await?;

    // Block forever until all spawned tasks complete. Any panics in spawned tasks will be
    // propagated here.
    join_set.join_all().await;
    Ok(())
}

fn start_metrics_endpoint(
    join_set: &mut JoinSet<()>,
    carbide_config: &carbide_api_core::cfg::file::CarbideConfig,
    registry: prometheus::Registry,
    cancel_token: CancellationToken,
) -> eyre::Result<()> {
    let Some(metrics_address) = carbide_config.metrics_endpoint else {
        return Ok(());
    };

    // Spin up the web server which serves `/metrics` requests
    // If a replacement prefix for "carbide_" is configured, also emit metrics under that
    let additional_prefix =
        carbide_config
            .alt_metric_prefix
            .clone()
            .map(|alt| metrics_endpoint::PrefixMigration {
                old: "carbide_".to_string(),
                new: alt,
            });
    join_set
        .build_task()
        .name("metrics_endpoint")
        .spawn(async move {
            if let Err(error) = metrics_endpoint::run_metrics_endpoint_with_cancellation(
                &metrics_endpoint::MetricsEndpointConfig {
                    address: metrics_address,
                    registry,
                    health_controller: None,
                    additional_prefix,
                },
                cancel_token,
            )
            .await
            {
                tracing::error!(
                    metrics_address = %metrics_address,
                    error = %error,
                    "Metrics endpoint failed",
                );
            }
        })?;

    Ok(())
}

/// Starts the dedicated listener for the opt-in per-object state metrics and
/// returns their bare Prometheus registry (`None` when disabled). Per-object
/// series are native pull collectors on their own registry — not
/// OpenTelemetry instruments, whose per-stream cardinality limit a per-object
/// fleet vastly exceeds — and their own endpoint, so operators can scrape (or
/// skip) them independently. No alt-prefix mirroring here: it would double
/// every per-object family.
fn start_per_object_metrics_endpoint(
    join_set: &mut JoinSet<()>,
    carbide_config: &carbide_api_core::cfg::file::CarbideConfig,
    cancel_token: CancellationToken,
) -> eyre::Result<Option<prometheus::Registry>> {
    let per_object_config = &carbide_config.observability.per_object_state_metrics;
    if per_object_config.enabled && per_object_config.object_types.is_empty() {
        tracing::warn!(
            "observability.per_object_state_metrics.enabled is set but object_types is empty; \
             not starting the per-object metrics endpoint"
        );
    }
    let per_object_metrics = (per_object_config.enabled
        && !per_object_config.object_types.is_empty())
    .then(prometheus::Registry::new);
    if let Some(registry) = &per_object_metrics {
        let address = per_object_config.listen_address;
        join_set
            .build_task()
            .name("per_object_metrics_endpoint")
            .spawn({
                let registry = registry.clone();
                async move {
                    if let Err(error) = metrics_endpoint::run_metrics_endpoint_with_cancellation(
                        &metrics_endpoint::MetricsEndpointConfig {
                            address,
                            registry,
                            health_controller: None,
                            additional_prefix: None,
                        },
                        cancel_token,
                    )
                    .await
                    {
                        tracing::error!(
                            per_object_metrics_address = %address,
                            error = %error,
                            "Per-object metrics endpoint failed",
                        );
                    }
                }
            })?;
    }
    Ok(per_object_metrics)
}

fn validate_network_prefixes(
    carbide_config: &carbide_api_core::cfg::file::CarbideConfig,
) -> eyre::Result<()> {
    // Reject config that contains overlaps between deny_prefixes and site_fabric_prefixes.
    // deny_prefixes are IPv4-only; only check against IPv4 site fabric prefixes.
    for deny_prefix in &carbide_config.deny_prefixes {
        for site_fabric_prefix in &carbide_config.site_fabric_prefixes {
            if let ipnetwork::IpNetwork::V4(site_v4) = site_fabric_prefix
                && deny_prefix.overlaps(*site_v4)
            {
                return Err(eyre::eyre!(
                    "overlap found in deny_prefixes `{deny_prefix}` and site_fabric_prefixes \
                     `{site_fabric_prefix}`",
                ));
            }
        }
    }
    Ok(())
}
