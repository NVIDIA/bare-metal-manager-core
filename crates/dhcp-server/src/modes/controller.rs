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
use std::net::IpAddr;
use std::str::FromStr;

use ::rpc::forge::DhcpDiscovery;
use lru::LruCache;
use rpc::forge::DhcpRecord;
use tokio::sync::Mutex;
use tonic::async_trait;

use super::DhcpMode;
use crate::Config;
use crate::cache::{self, CacheEntry};
use crate::errors::DhcpError;
use crate::rpc::client::discover_dhcp;
use crate::vendor_class::VendorClass;

#[derive(Debug)]
pub struct Controller {}

#[async_trait]
impl DhcpMode for Controller {
    async fn discover_dhcp(
        &self,
        discovery_request: DhcpDiscovery,
        config: &Config,
        machine_cache: &mut std::sync::Arc<Mutex<LruCache<String, CacheEntry>>>,
    ) -> Result<DhcpRecord, DhcpError> {
        // check if entry present in cache.
        let link_address = IpAddr::from_str(
            discovery_request
                .link_address
                .as_ref()
                .unwrap_or(&discovery_request.relay_address),
        )?;

        let vendor_class = if let Some(vendor_string) = &discovery_request.vendor_string {
            Some(VendorClass::from_str(vendor_string).map_err(|e| {
                DhcpError::VendorClassParseError(format!("Vendor string parse error: {e:?}"))
            })?)
        } else {
            None
        };

        let vendor_id = match &vendor_class {
            Some(vc) => vc.id.as_str(),
            None => "",
        };

        {
            let mut machine_cache = machine_cache.lock().await;
            if let Some(cache_entry) = cache::get(
                &discovery_request.mac_address,
                link_address,
                &discovery_request.circuit_id,
                &discovery_request.remote_id,
                vendor_id,
                &mut machine_cache,
            ) {
                tracing::info!(
                    "returning cached response for (mac: {}, link(or relay)_address: {}, circuit_id: {:?}, remote: {:?}, vendor: {})",
                    discovery_request.mac_address,
                    link_address,
                    &discovery_request.circuit_id,
                    &discovery_request.remote_id,
                    &vendor_id,
                );

                return Ok(cache_entry.dhcp_record);
            }
        }

        let record = discover_dhcp(discovery_request.clone(), config).await?;
        let mut machine_cache = machine_cache.lock().await;
        cache::put(
            &discovery_request.mac_address,
            link_address,
            discovery_request.circuit_id,
            discovery_request.remote_id,
            vendor_id,
            record.clone(),
            &mut machine_cache,
        );

        Ok(record)
    }
}
