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
use super::DhcpMode;
use std::{net::IpAddr, str::FromStr};

use ::rpc::forge::DhcpDiscovery;
use lru::LruCache;
use rpc::forge::DhcpRecord;
use tonic::async_trait;

use crate::{
    cache::{self, CacheEntry},
    errors::DhcpError,
    rpc::client::discover_dhcp,
    vendor_class::VendorClass,
    Config, HostConfig,
};

#[derive(Debug)]
pub struct Controller {}

#[async_trait]
impl DhcpMode for Controller {
    async fn discover_dhcp(
        &self,
        discovery_request: DhcpDiscovery,
        config: &Config,
        machine_cache: &mut LruCache<String, CacheEntry>,
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
                DhcpError::VendorClassParseError(format!("Vendor string parse error: {:?}", e))
            })?)
        } else {
            None
        };

        let vendor_id = match &vendor_class {
            Some(vc) => vc.id.as_str(),
            None => "",
        };

        if let Some(cache_entry) = cache::get(
            &discovery_request.mac_address,
            link_address,
            &discovery_request.circuit_id,
            &discovery_request.remote_id,
            vendor_id,
            machine_cache,
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

        let record = discover_dhcp(discovery_request.clone(), config).await?;
        cache::put(
            &discovery_request.mac_address,
            link_address,
            discovery_request.circuit_id,
            discovery_request.remote_id,
            vendor_id,
            record.clone(),
            machine_cache,
        );

        Ok(record)
    }

    async fn get_remote_id(
        &self,
        _host_config: &Option<HostConfig>,
    ) -> Result<Option<String>, DhcpError> {
        Ok(None)
    }
}
