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

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};

use super::logging::level_filter::ActiveLevel;

pub struct DynamicSettings {
    // RUST_LOG
    pub log_filter: Arc<ArcSwap<ActiveLevel>>,

    // Should site-explorer create machines
    pub create_machines: Arc<ArcSwap<Setting<bool>>>,
}

/// How often to check if the log filter (RUST_LOG) needs resetting
pub const RESET_PERIOD: Duration = Duration::from_secs(15 * 60); // 1/4 hour

impl DynamicSettings {
    /// The background task that resets dynamic features to their startup values when the override expires
    pub fn start_reset_task(&self, period: Duration) {
        let log_filter = self.log_filter.clone();
        let create_machines = self.create_machines.clone();
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

                    let f = create_machines.load();
                    if f.has_expired() {
                        let next = f.reset_from();
                        create_machines.store(Arc::new(next));
                    }
                }
            })
            .map_err(|err| {
                tracing::error!("dynamic_feature_reset task aborted: {err}");
            });
    }
}

pub fn create_machines(b: bool) -> Arc<ArcSwap<Setting<bool>>> {
    Arc::new(ArcSwap::new(Arc::new(Setting::new(b))))
}

/// Immutable. Owner holds it in an ArcSwap and replaces the whole object using one of `with_base` or
/// `reset_from`.
///
/// TODO: This is similar to api/src/logging/level_filter.rs ActiveLevel, but EnvFilter is not Clone
#[derive(Debug, Default, PartialEq)]
pub struct Setting<T> {
    // Is create_machines enabled?
    pub current: T,

    // The value we had on startup
    pub base: T,

    /// When to switch back to the value we had on startup
    expiry: Option<DateTime<Utc>>,
}

impl<T: std::fmt::Display + Clone> Setting<T> {
    pub fn new(v: T) -> Self {
        Self {
            base: v.clone(),
            expiry: None,
            current: v,
        }
    }

    // Build new with the same 'base' as caller
    pub fn with_base(&self, value: T, until: Option<DateTime<Utc>>) -> Self {
        Self {
            current: value,
            expiry: until,
            base: self.base.clone(),
        }
    }

    // Build new with value reset to base
    pub fn reset_from(&self) -> Self {
        Self {
            current: self.base.clone(),
            expiry: None,
            base: self.base.clone(),
        }
    }

    pub fn has_expired(&self) -> bool {
        if let Some(expiry) = self.expiry.as_ref() {
            *expiry < chrono::Utc::now()
        } else {
            false
        }
    }
}

impl<T: std::fmt::Display> fmt::Display for Setting<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let current = self.current.to_string();
        match self.expiry {
            None => write!(f, "{current}"),
            Some(exp) => write!(f, "{current} until {exp}"),
        }
    }
}
