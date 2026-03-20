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

//! IPMI transport layer — defines the trait and transport implementations.

pub mod lan;
pub mod lanplus;
pub mod http;
#[cfg(test)]
pub mod mock;

use crate::error::Result;
use crate::types::{IpmiRequest, IpmiResponse};

/// Trait for sending IPMI commands over a transport (lanplus, lan, etc.).
///
/// Implementations handle session management, encryption, and framing.
/// The transport is async because it performs UDP I/O.
pub trait IpmiTransport: Send {
    /// Send an IPMI request and wait for the response.
    fn send_recv(
        &mut self,
        req: &IpmiRequest,
    ) -> impl std::future::Future<Output = Result<IpmiResponse>> + Send;

    /// Close the session and release resources.
    fn close(&mut self) -> impl std::future::Future<Output = Result<()>> + Send;
}

// ==============================================================================
// Transport Enum Wrapper
// ==============================================================================

/// Transport enum dispatching to the concrete transport implementation.
///
/// [`IpmiTransport`] uses RPITIT (`impl Future` in return position), so it
/// is not dyn-safe. This enum provides runtime dispatch between the LAN
/// (IPMI v1.5) and LANPLUS (IPMI v2.0 RMCP+) transports.
pub enum Transport {
    /// IPMI v1.5 LAN transport (no encryption, MD5 or no auth).
    Lan(lan::LanTransport),
    /// IPMI v2.0 RMCP+ transport (encrypted + integrity-checked).
    Lanplus(lanplus::LanplusTransport),
    /// IPMI-over-HTTPS transport for testing against bmc-mock.
    Http(http::HttpTransport),
}

impl IpmiTransport for Transport {
    async fn send_recv(&mut self, req: &IpmiRequest) -> Result<IpmiResponse> {
        match self {
            Self::Lan(t) => t.send_recv(req).await,
            Self::Lanplus(t) => t.send_recv(req).await,
            Self::Http(t) => t.send_recv(req).await,
        }
    }

    async fn close(&mut self) -> Result<()> {
        match self {
            Self::Lan(t) => t.close().await,
            Self::Lanplus(t) => t.close().await,
            Self::Http(t) => t.close().await,
        }
    }
}
