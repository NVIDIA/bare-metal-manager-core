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

use mac_address::MacAddress;
use rpc::forge as rpc;
use tonic::{Request, Response};

use crate::api::Api;
use crate::errors::CarbideError;

pub async fn expire_dhcp_lease(
    api: &Api,
    request: Request<rpc::ExpireDhcpLeaseRequest>,
) -> Result<Response<rpc::ExpireDhcpLeaseResponse>, CarbideError> {
    let rpc::ExpireDhcpLeaseRequest {
        ip_address,
        mac_address,
    } = request.into_inner();
    let ip_address: IpAddr = ip_address.parse()?;
    let mac_address: Option<MacAddress> = mac_address
        .as_deref()
        .map(|m| m.parse::<MacAddress>().map_err(CarbideError::from))
        .transpose()?;

    let mut txn = api.txn_begin().await?;
    // When the caller provides the MAC, scope the delete to the (ip, mac)
    // pair. Otherwise, just call the address-only variant, which would
    // be something we would see from an admin-cli call used for deleting
    // a specific IP allocation.
    let deleted = match mac_address {
        Some(mac) => {
            db::machine_interface_address::delete_by_address_and_mac(
                &mut txn,
                ip_address,
                mac,
                model::allocation_type::AllocationType::Dhcp,
            )
            .await?
        }
        None => {
            db::machine_interface_address::delete_by_address(
                &mut txn,
                ip_address,
                model::allocation_type::AllocationType::Dhcp,
            )
            .await?
        }
    };
    txn.commit().await?;

    let status = if deleted {
        tracing::info!(
            %ip_address,
            ?mac_address,
            "Released expired DHCP lease allocation"
        );
        rpc::ExpireDhcpLeaseStatus::Released
    } else {
        tracing::debug!(
            %ip_address,
            ?mac_address,
            "No allocation found for expired DHCP lease"
        );
        rpc::ExpireDhcpLeaseStatus::NotFound
    };

    Ok(Response::new(rpc::ExpireDhcpLeaseResponse {
        ip_address: ip_address.to_string(),
        status: status.into(),
    }))
}
