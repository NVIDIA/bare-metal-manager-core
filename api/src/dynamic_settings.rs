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
use std::time::Duration;

use arc_swap::ArcSwap;

use super::logging::level_filter::ActiveLevel;

pub struct DynamicSettings {
    // RUST_LOG
    pub log_filter: Arc<ArcSwap<ActiveLevel>>,

    // Should site-explorer create machines
    pub create_machines: Arc<ArcSwap<bool>>,
}

/// How often to check if the log filter (RUST_LOG) needs resetting
pub const RESET_PERIOD: Duration = Duration::from_secs(15 * 60); // 1/4 hour

impl DynamicSettings {
    /// The background task that resets dynamic features to their startup values when the override expires
    pub fn start_reset_task(&self, period: Duration) {
        let log_filter = self.log_filter.clone();
        let _ = tokio::task::Builder::new()
            .name("dynamic_feature_reset")
            .spawn(async move {
                loop {
                    tokio::time::sleep(period).await;

                    let f = log_filter.load();
                    if f.has_expired() {
                        match f.reset_from() {
                            Ok(next) => {
                                log_filter.store(Arc::new(next));
                            }
                            Err(err) => {
                                tracing::error!("Failed resetting log level: {err}");
                            }
                        }
                    }
                }
            })
            .map_err(|err| {
                tracing::error!("dynamic_feature_reset task aborted: {err}");
            });
    }
}

pub fn create_machines(b: bool) -> Arc<ArcSwap<bool>> {
    Arc::new(ArcSwap::new(Arc::new(b)))
}
