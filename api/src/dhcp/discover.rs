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
use mac_address::MacAddress;
use tonic::{Request, Response};

use crate::db::{machine_interface, predicted_machine_interface::PredictedMachineInterface};
use crate::{
    CarbideError,
    db::{self, DatabaseError, dhcp_entry::DhcpEntry, dhcp_record::DhcpRecord, instance::Instance},
};

pub async fn discover_dhcp(
    database_connection: &sqlx::PgPool,
    request: Request<rpc::DhcpDiscovery>,
) -> Result<Response<rpc::DhcpRecord>, CarbideError> {
    const DB_TXN_NAME: &str = "discover_dhcp";
    let mut txn = database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

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

    let parsed_mac: MacAddress = mac_address.parse()?;

    let existing_machine_id =
        match db::machine::find_existing_machine(&mut txn, parsed_mac, parsed_relay).await? {
            Some(existing_machine) => Some(existing_machine),
            None => {
                if let Some(expected_interface) =
                    PredictedMachineInterface::find_by_mac_address(&mut txn, parsed_mac).await?
                {
                    machine_interface::move_predicted_machine_interface_to_machine(
                        &mut txn,
                        &expected_interface,
                        relay_ip,
                    )
                    .await?;
                    Some(expected_interface.machine_id)
                } else {
                    None
                }
            }
        };

    let machine_interface = db::machine_interface::find_or_create_machine_interface(
        &mut txn,
        existing_machine_id,
        parsed_mac,
        parsed_relay,
    )
    .await?;

    if let Some(machine_id) = machine_interface.machine_id {
        // Can't block host's DHCP handling completely to support Zero-DPU.
        if machine_id.machine_type().is_host() {
            if let Some(instance_id) =
                Instance::find_id_by_machine_id(&mut txn, &machine_id).await?
            {
                // An instance is associated with machine id. DPU must process it.
                return Err(CarbideError::internal(format!(
                    "DHCP request received for instance: {instance_id}. Ignoring."
                )));
            }
        }
    }

    // Save vendor string, this is allowed to fail due to dhcp happening more than once on the same machine/vendor string
    if let Some(vendor) = vendor_string {
        let res = DhcpEntry {
            machine_interface_id: machine_interface.id,
            vendor_string: vendor,
        }
        .persist(&mut txn)
        .await;
        match res {
            Ok(()) => {} // do nothing on ok result
            Err(error) => {
                tracing::error!(%error, "Could not persist dhcp entry")
            } // This should not fail the discover call, dhcp happens many times
        }
    }

    db::machine_interface::update_last_dhcp(&mut txn, machine_interface.id, None).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    const DB_TXN_NAME_2: &str = "discover_dhcp 2";
    let mut txn = database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME_2, e))?;

    let record: rpc::DhcpRecord =
        DhcpRecord::find_by_mac_address(&mut txn, &parsed_mac, &machine_interface.segment_id)
            .await?
            .into();

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME_2, e))?;
    Ok(Response::new(record))
}
