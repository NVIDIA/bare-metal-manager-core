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

use ::rpc::forge as rpc;
use db::WithTransaction;
use futures_util::FutureExt;
use itertools::Itertools;
use model::machine_interface::InterfaceType;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

pub(crate) async fn find_interfaces(
    api: &Api,
    request: Request<rpc::InterfaceSearchQuery>,
) -> Result<Response<rpc::InterfaceList>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin().await?;

    let rpc::InterfaceSearchQuery { id, ip } = request.into_inner();

    let interfaces: Vec<rpc::MachineInterface> = match (id, ip) {
        (Some(id), _) => vec![db::machine_interface::find_one(&mut txn, id).await?.into()],
        (None, Some(ip)) => match IpAddr::from_str(ip.as_ref()) {
            Ok(ip) => match db::machine_interface::find_by_ip(&mut txn, ip).await? {
                Some(interface) => vec![interface.into()],
                None => {
                    return Err(CarbideError::internal(format!(
                        "No machine interface with IP {ip} was found"
                    ))
                    .into());
                }
            },
            Err(_) => {
                return Err(CarbideError::internal(
                    "could not marshall an IP from the request".to_string(),
                )
                .into());
            }
        },
        (None, None) => match db::machine_interface::find_all(&mut txn).await {
            Ok(machine_interfaces) => machine_interfaces
                .into_iter()
                .map(|i| i.into())
                .collect_vec(),
            Err(error) => return Err(error.into()),
        },
    };

    txn.commit().await?;

    Ok(Response::new(rpc::InterfaceList { interfaces }))
}

pub(crate) async fn delete_interface(
    api: &Api,
    request: Request<rpc::InterfaceDeleteQuery>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin().await?;

    let rpc::InterfaceDeleteQuery { id } = request.into_inner();
    let Some(id) = id else {
        return Err(CarbideError::MissingArgument("delete interface.interface_id").into());
    };

    let interface = db::machine_interface::find_one(&mut txn, id).await?;

    // There should not be any machine associated with this interface.
    if let Some(machine_id) = interface.machine_id {
        if interface.interface_type == InterfaceType::Bmc {
            return Err(CarbideError::InvalidArgument(format!(
                "This looks like a BMC interface and attached with machine: {machine_id}. Delete that first."
            ))
            .into());
        }
        return Err(CarbideError::InvalidArgument(format!(
            "Already a machine {machine_id} is attached to this interface. Delete that first."
        ))
        .into());
    }

    // There should not be any BMC information associated with any machine.
    for address in interface.addresses.iter() {
        let machine_id =
            db::machine_topology::find_machine_id_by_bmc_ip(txn.as_pgconn(), &address.to_string())
                .await?;

        if let Some(machine_id) = machine_id {
            return Err(CarbideError::InvalidArgument(format!(
                "This looks like a BMC interface and attached with machine: {machine_id}. Delete that first."
            ))
            .into());
        }
    }

    db::machine_interface::delete(&interface.id, &mut txn).await?;

    txn.commit().await?;

    Ok(Response::new(()))
}

pub(crate) async fn find_mac_address_by_bmc_ip(
    api: &Api,
    request: Request<rpc::BmcIp>,
) -> Result<Response<rpc::MacAddressBmcIp>, Status> {
    log_request_data(&request);

    let req = request.into_inner();
    let bmc_ip = req.bmc_ip;

    let interface = db::machine_interface::find_by_ip(
        &api.database_connection,
        bmc_ip
            .parse()
            .map_err(|e| CarbideError::InvalidArgument(format!("Invalid IP address: {e}")))?,
    )
    .await?
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "machine_interface",
        id: bmc_ip.clone(),
    })?;

    Ok(Response::new(rpc::MacAddressBmcIp {
        bmc_ip,
        mac_address: interface.mac_address.to_string(),
    }))
}

pub(crate) async fn find_bmc_ips(
    api: &Api,
    request: Request<rpc::FindBmcIpsRequest>,
) -> Result<Response<rpc::BmcIpList>, Status> {
    use rpc::find_bmc_ips_request::LookupBy;

    log_request_data(&request);

    let req = request.into_inner();

    let bmc_ips = match req.lookup_by {
        Some(LookupBy::MacAddress(mac_address)) => {
            db::machine_interface::lookup_bmc_ip_by_mac_address(
                &api.database_connection,
                mac_address.parse().map_err(|e| {
                    CarbideError::InvalidArgument(format!("Invalid MAC address: {e}"))
                })?,
            )
            .await?
        }
        Some(LookupBy::Serial(serial)) => {
            // Get the machine ID for this serial
            let machine_ids =
                db::machine_topology::find_by_serial(&api.database_connection, &serial).await?;
            if machine_ids.len() > 1 {
                tracing::warn!(
                    serial,
                    "Multiple machines match serial number, cannot resolve to BMC IP"
                );
                return Ok(Response::new(rpc::BmcIpList::default()));
            }
            let Some(machine_id) = machine_ids.into_iter().next() else {
                return Ok(Response::new(rpc::BmcIpList::default()));
            };

            // Resolve the BMC IP from the live interface, not the discovery topology
            // snapshot, so a released or changed lease can't surface a stale IP.
            let Some(bmc_ip) = api
                .with_txn(|txn| {
                    async move {
                        db::machine_topology::find_machine_bmc_pairs_by_machine_id(
                            txn,
                            vec![machine_id],
                        )
                        .await
                    }
                    .boxed()
                })
                .await??
                .into_iter()
                .find_map(|(_, ip)| ip)
            else {
                return Ok(Response::new(rpc::BmcIpList::default()));
            };

            // The address comes from a Postgres `inet` column, so it parses today --
            // but don't silently swallow the error if that ever changes: warn and skip.
            match bmc_ip.parse::<IpAddr>() {
                Ok(ip) => vec![ip],
                Err(e) => {
                    tracing::warn!(
                        bmc_ip_address = %bmc_ip,
                        error = %e,
                        "BMC IP from machine_interfaces did not parse; skipping"
                    );
                    return Ok(Response::new(rpc::BmcIpList::default()));
                }
            }
        }
        None => return Err(CarbideError::MissingArgument("lookup_by").into()),
    };

    Ok(Response::new(rpc::BmcIpList {
        bmc_ips: bmc_ips.into_iter().map(|ip| ip.to_string()).collect(),
    }))
}
