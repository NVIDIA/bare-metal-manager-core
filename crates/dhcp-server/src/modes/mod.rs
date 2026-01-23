/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
