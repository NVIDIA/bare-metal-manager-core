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

//! `carbide-ipmitool` — a pure-Rust IPMI v2.0 RMCP+ client library and CLI.
//!
//! Provides [`IpmiClient`] for connecting to BMCs over IPMI RMCP+ (lanplus)
//! and executing commands like chassis power control, sensor readings, FRU
//! inventory, and more.
//!
//! # Example
//!
//! ```no_run
//! use ipmitool::{IpmiClient, ConnectionConfig};
//!
//! # async fn example() -> ipmitool::error::Result<()> {
//! let config = ConnectionConfig {
//!     host: "10.0.1.42".to_owned(),
//!     username: "admin".to_owned(),
//!     password: "password".to_owned(),
//!     ..Default::default()
//! };
//! let mut client = IpmiClient::connect(config).await?;
//! let status = client.chassis_power_status().await?;
//! println!("Power is {status}");
//! # Ok(())
//! # }
//! ```

pub mod cmd;
pub mod crypto;
pub mod error;
pub mod transport;
pub mod types;

// TODO: implement IpmiClient and ConnectionConfig in Phase 3
// Re-exports will be added as modules are implemented.

/// Configuration for connecting to a BMC.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// BMC hostname or IP address.
    pub host: String,
    /// UDP port for RMCP+ (default: 623).
    pub port: u16,
    /// IPMI username.
    pub username: String,
    /// IPMI password.
    pub password: String,
    /// Cipher suite ID (default: 17).
    pub cipher_suite: u8,
    /// Per-request timeout in seconds (default: 15).
    pub timeout_secs: u64,
    /// Number of retries per request (default: 3).
    pub retries: u32,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 623,
            username: String::new(),
            password: String::new(),
            cipher_suite: 17,
            timeout_secs: 15,
            retries: 3,
        }
    }
}

/// High-level IPMI client. Wraps a transport and provides typed command methods.
///
/// Created via [`IpmiClient::connect`], which establishes an RMCP+ session.
// TODO: Phase 3 — flesh out with transport field and command methods
pub struct IpmiClient;

impl IpmiClient {
    /// Connect to a BMC and establish an RMCP+ session.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or RAKP authentication fails.
    pub async fn connect(_config: ConnectionConfig) -> error::Result<Self> {
        // TODO: Phase 2/3 — implement session establishment
        // Await a no-op future to suppress unused_async lint until implemented.
        tokio::task::yield_now().await;
        Err(error::IpmitoolError::Transport(
            "not yet implemented".to_owned(),
        ))
    }

    /// Query the current chassis power status.
    ///
    /// # Errors
    ///
    /// Returns an error if the IPMI command fails.
    pub async fn chassis_power_status(&mut self) -> error::Result<String> {
        // TODO: Phase 3 — implement via cmd::chassis
        tokio::task::yield_now().await;
        Err(error::IpmitoolError::Transport(
            "not yet implemented".to_owned(),
        ))
    }
}
