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

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use ::rpc::forge as rpc;
use carbide_uuid::machine::MachineType;
use db::WithTransaction;
use futures_util::FutureExt;
use itertools::Itertools;
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

    let mut interfaces: Vec<rpc::MachineInterface> = match (id, ip) {
        (Some(id), _) => vec![db::machine_interface::find_one(&mut txn, id).await?.into()],
        (None, Some(ip)) => match Ipv4Addr::from_str(ip.as_ref()) {
            Ok(ip) => match db::machine_interface::find_by_ip(&mut txn, IpAddr::V4(ip)).await? {
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
                    "Could not marshall an IP from the request".to_string(),
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

    // Link BMC interface to its machine, for carbide-web and admin-cli.
    // Don't link if the search returned multiple, in case perf is an issue.
    if interfaces.len() == 1 {
        let interface = interfaces.get_mut(0).unwrap();
        let not_linked_yet = interface.machine_id.is_none();
        let maybe_a_bmc_interface = interface.primary_interface && interface.address.len() == 1;
        if not_linked_yet && maybe_a_bmc_interface {
            let Some(ip) = interface.address.first() else {
                return Err(Status::internal(
                    "Impossible interface.address array length",
                ));
            };
            match db::machine_topology::find_machine_id_by_bmc_ip(&mut txn, ip).await {
                Ok(Some(machine_id)) => {
                    let rpc_machine_id = Some(machine_id);
                    interface.is_bmc = Some(true);
                    match machine_id.machine_type() {
                        MachineType::Dpu => interface.attached_dpu_machine_id = rpc_machine_id,
                        MachineType::Host | MachineType::PredictedHost => {
                            interface.machine_id = rpc_machine_id
                        }
                    }
                }
                Ok(None) => {} // expected, not a BMC interface
                Err(err) => {
                    tracing::warn!(%err, %ip, "db::machine_topology::find_machine_id_by_bmc_ip error");
                }
            }
        }
    }

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
        return Err(Status::invalid_argument(format!(
            "Already a machine {machine_id} is attached to this interface. Delete that first."
        )));
    }

    // There should not be any BMC information associated with any machine.
    for address in interface.addresses.iter() {
        let machine_id =
            db::machine_topology::find_machine_id_by_bmc_ip(&mut txn, &address.to_string()).await?;

        if let Some(machine_id) = machine_id {
            return Err(Status::invalid_argument(format!(
                "This looks like a BMC interface and attached with machine: {machine_id}. Delete that first."
            )));
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

    let interface = api
        .with_txn(|txn| db::machine_interface::find_by_ip(txn, bmc_ip.parse().unwrap()).boxed())
        .await??
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "machine_interface",
            id: bmc_ip.clone(),
        })?;

    Ok(Response::new(rpc::MacAddressBmcIp {
        bmc_ip,
        mac_address: interface.mac_address.to_string(),
    }))
}
