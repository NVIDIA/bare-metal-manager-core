/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::Instrument;

use crate::{
    cfg::IbFabricMonitorConfig,
    ib::{IBFabricManager, IBFabricManagerType, DEFAULT_IB_FABRIC_NAME},
    CarbideError, CarbideResult,
};

mod metrics;
use metrics::IbFabricMonitorMetrics;

use self::metrics::FabricMetrics;

/// `IbFabricMonitor` monitors the health of all connected InfiniBand fabrics in periodic intervals
pub struct IbFabricMonitor {
    config: IbFabricMonitorConfig,
    metric_holder: Arc<metrics::MetricHolder>,
    /// API for interaction with Forge IBFabricManager
    fabric_manager: Arc<dyn IBFabricManager>,
}

impl IbFabricMonitor {
    /// Create a IbFabricMonitor
    pub fn new(
        config: IbFabricMonitorConfig,
        meter: opentelemetry::metrics::Meter,
        fabric_manager: Arc<dyn IBFabricManager>,
    ) -> Self {
        // We want to hold metrics for longer than the iteration interval, so there is continuity
        // in emitting metrics. However we want to avoid reporting outdated metrics in case
        // reporting gets stuck. Therefore round up the iteration interval by 1min.
        let hold_period = config
            .run_interval
            .saturating_add(std::time::Duration::from_secs(60));

        let metric_holder = Arc::new(metrics::MetricHolder::new(meter, hold_period));
        metric_holder.register_callback();

        IbFabricMonitor {
            config,
            metric_holder,
            fabric_manager,
        }
    }

    /// Start the IbFabricMonitor and return a [sending channel](tokio::sync::oneshot::Sender) that will stop the IbFabricMonitor when dropped.
    pub fn start(self) -> eyre::Result<oneshot::Sender<i32>> {
        let (stop_sender, stop_receiver) = oneshot::channel();

        if self.config.enabled {
            tokio::task::Builder::new()
                .name("ib_fabric_monitor")
                .spawn(async move { self.run(stop_receiver).await })?;
        }

        Ok(stop_sender)
    }

    async fn run(&self, mut stop_receiver: oneshot::Receiver<i32>) {
        loop {
            if let Err(e) = self.run_single_iteration().await {
                tracing::warn!("IbFabricMonitor error: {}", e);
            }

            tokio::select! {
                _ = tokio::time::sleep(self.config.run_interval) => {},
                _ = &mut stop_receiver => {
                    tracing::info!("IbFabricMonitor stop was requested");
                    return;
                }
            }
        }
    }

    pub async fn run_single_iteration(&self) -> CarbideResult<()> {
        let mut metrics = IbFabricMonitorMetrics::new();

        let span_id: String = format!("{:#x}", u64::from_le_bytes(rand::random::<[u8; 8]>()));

        let check_ib_fabrics_span = tracing::span!(
            tracing::Level::INFO,
            "check_ib_fabrics",
            span_id,
            otel.status_code = tracing::field::Empty,
            otel.status_message = tracing::field::Empty,
            num_fabrics = 0,
        );

        let res = self
            .check_ib_fabrics(&mut metrics)
            .instrument(check_ib_fabrics_span.clone())
            .await;
        check_ib_fabrics_span.record("num_fabrics", metrics.num_fabrics);
        check_ib_fabrics_span.record(
            "fabric_metrics",
            serde_json::to_string(&metrics.fabrics).unwrap_or_default(),
        );

        match &res {
            Ok(()) => {
                check_ib_fabrics_span.record("otel.status_code", "ok");
            }
            Err(e) => {
                tracing::error!("IbFabricMonitor run failed due to: {:?}", e);
                check_ib_fabrics_span.record("otel.status_code", "error");
                // Writing this field will set the span status to error
                // Therefore we only write it on errors
                check_ib_fabrics_span.record("otel.status_message", format!("{:?}", e));
            }
        }

        // Cache all other metrics that have been captured in this iteration.
        // Those will be queried by OTEL on demand
        self.metric_holder.update_metrics(metrics);

        res
    }

    async fn check_ib_fabrics(&self, metrics: &mut IbFabricMonitorMetrics) -> CarbideResult<()> {
        if self.fabric_manager.get_config().manager_type == IBFabricManagerType::Disable {
            return Ok(());
        }

        for fabric in &[DEFAULT_IB_FABRIC_NAME] {
            metrics.num_fabrics += 1;
            let fabric_metrics = metrics.fabrics.entry(fabric.to_string()).or_default();
            if let Err(e) =
                check_ib_fabric(self.fabric_manager.as_ref(), fabric, fabric_metrics).await
            {
                fabric_metrics.fabric_error = error_as_metric_label(e);
            }
        }

        Ok(())
    }
}

/// Checks the status of a single IB fabric
async fn check_ib_fabric(
    fabric_manager: &dyn IBFabricManager,
    fabric: &str,
    metrics: &mut FabricMetrics,
) -> Result<(), CarbideError> {
    let conn = fabric_manager.connect(fabric).await?;

    let mut result = Ok(());
    match conn.versions().await {
        Ok(version) => metrics.ufm_version = version.ufm_version,
        Err(e) => {
            result = Err(e);
        }
    };

    result
}

fn error_as_metric_label(error: CarbideError) -> String {
    const MAX_LEN: usize = 20;

    // TODO: This isn't efficient because we will get a lot of different dimensions
    // We need to have better defined errors from the UFM APIs, so we can convert
    // those into a smaller set of labels
    let mut err = error.to_string();

    let upto = err
        .char_indices()
        .map(|(i, _)| i)
        .nth(MAX_LEN)
        .unwrap_or(err.len());
    err.truncate(upto);
    err
}
