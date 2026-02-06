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
use std::net::SocketAddrV4;
use std::sync::Arc;

use lru::LruCache;
use rpc::forge::{DhcpDiscovery, DhcpRecord};
use tokio::sync::Mutex;
use tonic::async_trait;

use crate::Config;
use crate::cache::CacheEntry;
use crate::errors::DhcpError;
use crate::packet_handler::{DecodedPacket, Packet};

pub mod controller;
pub mod dpu;

#[async_trait]
pub trait DhcpMode: Send + Sync + std::fmt::Debug {
    /// Method to determine IP address to be returned to client.
    async fn discover_dhcp(
        &self,
        discovery_request: DhcpDiscovery,
        config: &Config,
        machine_cache: &mut Arc<Mutex<LruCache<String, CacheEntry>>>,
    ) -> Result<DhcpRecord, DhcpError>;
    /// And at what address?
    fn get_destination_address(&self, packet: &Packet) -> SocketAddrV4 {
        packet.dst_address()
    }
    /// Get circuit id. For dpu-with-relay, circuit id is interface name.
    fn get_circuit_id(&self, packet: &DecodedPacket, _circuit_id: &str) -> Option<String> {
        packet.get_circuit_id()
    }
    /// Should be relayed? A controller mode will accept on relayed packet, while dpu with relay
    /// mode will never get a relayed packet.
    fn should_be_relayed(&self) -> bool {
        true
    }
}
