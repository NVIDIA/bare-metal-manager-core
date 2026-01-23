/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use arc_swap::ArcSwap;
use utils::HostPortPair;

use super::logging::level_filter::ActiveLevel;

pub struct DynamicSettings {
    /// RUST_LOG level
    pub log_filter: Arc<ActiveLevel>,

    /// Should site-explorer create machines
    pub create_machines: Arc<AtomicBool>,

    /// Use a proxy for talking to BMC's
    pub bmc_proxy: Arc<ArcSwap<Option<HostPortPair>>>,

    /// Whether log tracing should be enabled
    pub tracing_enabled: Arc<AtomicBool>,
}

/// How often to check if the log filter (RUST_LOG) needs resetting
pub(crate) const RESET_PERIOD: Duration = Duration::from_secs(15 * 60); // 1/4 hour

impl DynamicSettings {
    /// The background task that resets dynamic features to their startup values when the override expires
    pub(crate) fn start_reset_task(&self, period: Duration) {
        let log_filter = self.log_filter.clone();
        let _ = tokio::task::Builder::new()
            .name("dynamic_feature_reset")
            .spawn(async move {
                loop {
                    tokio::time::sleep(period).await;

                    if let Err(err) = log_filter.reset_if_expired() {
                        tracing::error!("Failed resetting log level: {err}");
                    }
                }
            })
            .map_err(|err| {
                tracing::error!("dynamic_feature_reset task aborted: {err}");
            });
    }
}

pub fn bmc_proxy(s: Option<HostPortPair>) -> Arc<ArcSwap<Option<HostPortPair>>> {
    Arc::new(ArcSwap::new(Arc::new(s)))
}
