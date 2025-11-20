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
use std::net::IpAddr;
use std::str::FromStr;

use ::rpc::forge as rpc;
use db::dhcp_entry::DhcpEntry;
use db::{self, expected_machine, machine_interface};
use mac_address::MacAddress;
use model::expected_machine::ExpectedHostNic;
use tonic::{Request, Response};

use crate::CarbideError;
use crate::api::Api;

pub async fn discover_dhcp(
    api: &Api,
    request: Request<rpc::DhcpDiscovery>,
    rack_level_service: Option<bool>,
) -> Result<Response<rpc::DhcpRecord>, CarbideError> {
    let mut txn = api.txn_begin("discover_dhcp").await?;

    let rpc::DhcpDiscovery {
        mac_address,
        relay_address,
        link_address,
        vendor_string,
        ..
    } = request.into_inner();

    // Use link address if present, else relay address. Link address represents subnet address at
    // first router.
    let address_to_use_for_dhcp = link_address.as_ref().unwrap_or(&relay_address);
    let parsed_relay = address_to_use_for_dhcp.parse()?;
    let relay_ip = IpAddr::from_str(&relay_address)?;
    let mut host_nic: Option<ExpectedHostNic> = None;

    let parsed_mac: MacAddress = mac_address.parse()?;

    let existing_machine_id =
        match db::machine::find_existing_machine(&mut txn, parsed_mac, parsed_relay).await? {
            Some(existing_machine) => Some(existing_machine),
            None => {
                if let Some(expected_interface) =
                    db::predicted_machine_interface::find_by_mac_address(&mut txn, parsed_mac)
                        .await?
                {
                    machine_interface::move_predicted_machine_interface_to_machine(
                        &mut txn,
                        &expected_interface,
                        relay_ip,
                    )
                    .await?;
                    Some(expected_interface.machine_id)
                } else {
                    if let Some(x) = rack_level_service {
                        // check expected machines. all mac addresses we should respond to should be
                        // added in there for unknown machines that have not been discovered yet.
                        // TODO: fix for dpu with VF nics, they will currently not get IPs
                        if x {
                            let expected_machine =
                                expected_machine::find_by_host_mac_address(&mut txn, parsed_mac)
                                    .await
                                    .map_err(CarbideError::from)?;
                            if let Some(m) = expected_machine {
                                // select ip segment from Underlay for BMC, Admin for BF3/Onboard
                                for nic in m.data.host_nics {
                                    if nic.mac_address == parsed_mac {
                                        host_nic = Some(nic);
                                    }
                                }
                            } else {
                                // in the rack mode, we don't vend IPs to unknown MACs
                                return Err(CarbideError::NotFoundError {
                                    kind: "host mac address",
                                    id: parsed_mac.to_string(),
                                });
                            }
                        }
                    }
                    None
                }
            }
        };

    let machine_interface = db::machine_interface::find_or_create_machine_interface(
        &mut txn,
        existing_machine_id,
        parsed_mac,
        parsed_relay,
        host_nic,
    )
    .await?;

    if let Some(machine_id) = machine_interface.machine_id {
        // Can't block host's DHCP handling completely to support Zero-DPU.
        if machine_id.machine_type().is_host()
            && let Some(instance_id) =
                db::instance::find_id_by_machine_id(&mut txn, &machine_id).await?
        {
            // An instance is associated with machine id. DPU must process it.
            return Err(CarbideError::internal(format!(
                "DHCP request received for instance: {instance_id}. Ignoring."
            )));
        }
    }

    // Save vendor string, this is allowed to fail due to dhcp happening more than once on the same machine/vendor string
    if let Some(vendor) = vendor_string {
        let res = db::dhcp_entry::persist(
            DhcpEntry {
                machine_interface_id: machine_interface.id,
                vendor_string: vendor,
            },
            &mut txn,
        )
        .await;
        match res {
            Ok(()) => {} // do nothing on ok result
            Err(error) => {
                tracing::error!(%error, "Could not persist dhcp entry")
            } // This should not fail the discover call, dhcp happens many times
        }
    }

    db::machine_interface::update_last_dhcp(&mut txn, machine_interface.id, None).await?;

    txn.commit().await?;

    let mut txn = api.txn_begin("discover_dhcp 2").await?;

    let record: rpc::DhcpRecord =
        db::dhcp_record::find_by_mac_address(&mut txn, &parsed_mac, &machine_interface.segment_id)
            .await?
            .into();

    txn.commit().await?;
    Ok(Response::new(record))
}
