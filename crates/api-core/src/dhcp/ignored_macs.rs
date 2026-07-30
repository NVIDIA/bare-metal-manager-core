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

use ::rpc::forge as rpc;
use mac_address::MacAddress;
use std::str::FromStr;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::Api;

pub(crate) async fn get_suppressed_dhcp_macs(
    api: &Api,
    _request: Request<rpc::GetSuppressedDhcpMacsRequest>,
) -> Result<Response<rpc::GetSuppressedDhcpMacsResponse>, Status> {
    let pool = api.pg_pool();
    let rows = db::ignored_bmc_mac::load_all(pool)
        .await
        .map_err(CarbideError::from)?;

    let bmc_mac_addresses = rows
        .into_iter()
        .filter(|r| r.suppress_dhcp)
        .map(|r| r.bmc_mac_address.to_string())
        .collect();

    Ok(Response::new(rpc::GetSuppressedDhcpMacsResponse {
        bmc_mac_addresses,
    }))
}

pub(crate) async fn record_dhcp_discover_suppressed(
    api: &Api,
    request: Request<rpc::RecordDhcpDiscoverSuppressedRequest>,
) -> Result<Response<rpc::RecordDhcpDiscoverSuppressedResponse>, Status> {
    let mac_str = request.into_inner().bmc_mac_address;
    let mac = MacAddress::from_str(&mac_str).map_err(|e| {
        Status::invalid_argument(format!("invalid bmc_mac_address {mac_str:?}: {e}"))
    })?;

    let mut txn = api.txn_begin().await?;
    db::ignored_bmc_mac::record_dhcp_discover_suppressed(&mut txn, &mac)
        .await
        .map_err(CarbideError::from)?;
    txn.commit().await?;

    tracing::info!(bmc_mac_address = %mac, "Recorded DHCP discover suppressed");

    Ok(Response::new(rpc::RecordDhcpDiscoverSuppressedResponse {}))
}
