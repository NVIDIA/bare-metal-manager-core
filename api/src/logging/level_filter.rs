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

use chrono::{DateTime, Utc};
use tracing_subscriber::EnvFilter;

/// The current RUST_LOG setting.
/// Immutable. Owner holds it in an ArcSwap and replaces the whole object using one of `with_base` or
/// `reset_from`.
#[derive(Debug)]
pub struct ActiveLevel {
    /// The current filter that logging uses
    pub current: EnvFilter,

    /// The RUST_LOG we had on startup
    pub base: String,

    /// When to switch back to the RUST_LOG we had on startup
    expiry: Option<DateTime<Utc>>,
}

impl ActiveLevel {
    pub fn new(f: EnvFilter) -> Self {
        Self {
            base: f.to_string(),
            expiry: None,
            current: f,
        }
    }

    // Build a new ActiveLevel with the same 'base' as caller
    pub fn with_base(&self, filter: &str, until: Option<DateTime<Utc>>) -> eyre::Result<Self> {
        let current = EnvFilter::builder().parse(filter)?;
        Ok(Self {
            current,
            expiry: until,
            base: self.base.clone(),
        })
    }

    // Build a new ActiveLevel use 'base' as the RUST_LOG
    pub fn reset_from(&self) -> eyre::Result<Self> {
        let current = EnvFilter::builder().parse(&self.base)?;
        Ok(Self {
            current,
            expiry: None,
            base: self.base.clone(),
        })
    }

    pub fn has_expired(&self) -> bool {
        if let Some(expiry) = self.expiry.as_ref() {
            *expiry < chrono::Utc::now()
        } else {
            false
        }
    }
}

impl fmt::Display for ActiveLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let current = self.current.to_string();
        match self.expiry {
            None => write!(f, "{current}"),
            Some(exp) => write!(f, "{current} until {exp}"),
        }
    }
}
