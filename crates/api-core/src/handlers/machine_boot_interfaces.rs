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

//! One machine's boot-interface view, gathered from every store that records
//! it. This is a read-only troubleshooting projection: it reports the four
//! places a host's boot interface can live -- owned `machine_interfaces` rows,
//! `predicted_machine_interfaces`, the `explored_endpoints` default, and the
//! post-deletion `retained_boot_interfaces` pairs -- alongside the effective
//! boot interface the system would select via `pick_boot_interface`, and a
//! divergence flag for when the stores disagree about which NIC boots.

use std::collections::BTreeSet;

use ::rpc::forge as rpc;
use mac_address::MacAddress;
use tonic::{Request, Response, Status};

use crate::api::{Api, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

/// Gather the boot-interface view for one machine across all four stores.
///
/// All four stores are read within a single read transaction. The effective
/// boot interface is the same
/// `pick_boot_interface` selection every other flow acts on, applied to the
/// owned `machine_interfaces` rows.
pub(crate) async fn get_machine_boot_interfaces(
    api: &Api,
    request: Request<rpc::GetMachineBootInterfacesRequest>,
) -> Result<Response<rpc::GetMachineBootInterfacesResponse>, Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;

    let mut txn = api.txn_begin().await?;

    // Store 1: owned interface rows -- the authoritative store for a machine
    // that exists. `find_by_machine_ids` returns a per-machine map.
    let owned_interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[machine_id])
        .await?
        .remove(&machine_id)
        .unwrap_or_default();

    // Store 2: predictions -- the boot candidates a host offers before its
    // first DHCP lease creates an owned row.
    let predicted_interfaces =
        db::predicted_machine_interface::find_by_machine_id(txn.as_mut(), &machine_id).await?;

    // Store 3: the explored endpoint default. The machine's BMC IP(s) map it to
    // the explored endpoints site-explorer recorded a default against.
    let bmc_pairs =
        db::machine_topology::find_machine_bmc_pairs_by_machine_id(txn.as_mut(), vec![machine_id])
            .await?;
    let bmc_ips: Vec<std::net::IpAddr> = bmc_pairs
        .into_iter()
        .filter_map(|(_, ip)| ip)
        .filter_map(|ip| ip.parse().ok())
        .collect();
    let explored_endpoints = if bmc_ips.is_empty() {
        Vec::new()
    } else {
        // `find_by_ips` takes `impl DbReader`; the wrapping transaction
        // implements it directly (a bare `&mut PgConnection` would need a
        // coercion that generic bound can't perform).
        db::explored_endpoints::find_by_ips(&mut txn, bmc_ips).await?
    };

    // Store 4: the retained post-deletion pairs. Collect the MACs the machine
    // knows about and read their raw retained rows -- un-window-filtered, so
    // stale records show up in the troubleshooting view. Owned (store 1) and
    // predicted (store 2) MACs, plus each explored endpoint's recorded boot MAC
    // (store 3): a retained record keyed on the explored boot MAC is surfaced
    // too, even when no owned/predicted row carries that MAC.
    let macs: Vec<MacAddress> = owned_interfaces
        .iter()
        .map(|i| i.mac_address)
        .chain(predicted_interfaces.iter().map(|p| p.mac_address))
        .chain(
            explored_endpoints
                .iter()
                .filter_map(|e| e.boot_interface_mac),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let retained_records = if macs.is_empty() {
        Vec::new()
    } else {
        db::retained_boot_interface::find_records_by_macs(&mut txn, &macs).await?
    };

    txn.commit().await?;

    // The effective boot interface: `pick_boot_interface` over the owned rows
    // (primary wins, else the lowest-MAC non-underlay NIC). This is what the
    // controller and admin actions resolve.
    let effective = model::machine::pick_boot_interface(&owned_interfaces);
    let effective_mac = effective.map(|i| i.mac_address);
    let effective_boot_interface = effective.and_then(|i| i.boot_interface());

    // Divergence: do the stores agree on which MAC boots this machine? We
    // compare the boot-MAC signals each store offers -- the effective owned
    // pick, every explored endpoint's recorded default, and any predicted NIC
    // flagged primary -- and flag a disagreement when more than one distinct
    // MAC turns up. (Retained rows are post-deletion history, shown for context
    // but not part of the agreement check.) A single signal, or none, is not a
    // divergence.
    let mut boot_macs: BTreeSet<MacAddress> = BTreeSet::new();
    if let Some(mac) = effective_mac {
        boot_macs.insert(mac);
    }
    for endpoint in &explored_endpoints {
        if let Some(mac) = endpoint.boot_interface_mac {
            boot_macs.insert(mac);
        }
    }
    for prediction in &predicted_interfaces {
        if prediction.primary_interface {
            boot_macs.insert(prediction.mac_address);
        }
    }
    let divergent = boot_macs.len() > 1;

    Ok(Response::new(rpc::GetMachineBootInterfacesResponse {
        machine_id: Some(machine_id),
        machine_interfaces: owned_interfaces
            .iter()
            .map(|i| rpc::MachineInterfaceBootInterface {
                mac_address: i.mac_address.to_string(),
                primary_interface: i.primary_interface,
                boot_interface_id: i.boot_interface_id.clone(),
                network_segment_type: i.network_segment_type.map(|t| t.to_string()),
            })
            .collect(),
        predicted_interfaces: predicted_interfaces
            .iter()
            .map(|p| rpc::PredictedBootInterface {
                mac_address: p.mac_address.to_string(),
                primary_interface: p.primary_interface,
                boot_interface_id: p.boot_interface_id.clone(),
                network_segment_type: Some(p.expected_network_segment_type.to_string()),
            })
            .collect(),
        explored_endpoints: explored_endpoints
            .iter()
            .map(|e| rpc::ExploredBootInterface {
                address: e.address.to_string(),
                boot_interface_mac: e.boot_interface_mac.map(|m| m.to_string()),
                boot_interface_id: e.boot_interface_id.clone(),
            })
            .collect(),
        retained_interfaces: retained_records
            .iter()
            .map(|r| rpc::RetainedBootInterface {
                mac_address: r.mac_address.to_string(),
                boot_interface_id: r.boot_interface_id.clone(),
                recorded_at: Some(r.recorded_at.into()),
            })
            .collect(),
        effective_boot_interface_mac: effective_mac.map(|m| m.to_string()),
        effective_boot_interface_id: effective_boot_interface.map(|b| b.interface_id),
        divergent,
    }))
}
