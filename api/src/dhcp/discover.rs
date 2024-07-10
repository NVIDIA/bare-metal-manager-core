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

pub use ::rpc::forge as rpc;
use mac_address::MacAddress;
use tonic::{Request, Response};

use crate::{
    db::{
        dhcp_entry::DhcpEntry,
        dhcp_record::{DhcpRecord, InstanceDhcpRecord},
        instance::Instance,
        machine::Machine,
        machine_interface::MachineInterface,
        DatabaseError,
    },
    dhcp::allocation::DhcpError,
    model::machine::machine_id::MachineId,
    state_controller::snapshot_loader::{DbSnapshotLoader, MachineStateSnapshotLoader},
    CarbideError, CarbideResult,
};

/// dhcrelay adds remote_id to each dhcp request sent by host.
/// In case of instance, remote_id should be matched with attached dpu_id.
/// If remote id is not matched, it should be assumed spoofed packet and must be dropped.
async fn validate_dhcp_request(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    remote_id: Option<String>,
    host_machine_id: &MachineId,
) -> CarbideResult<()> {
    let snapshot = DbSnapshotLoader {}
        .load_machine_snapshot(txn, host_machine_id)
        .await
        .map_err(CarbideError::from)?
        .ok_or(CarbideError::NotFoundError {
            kind: "machine",
            id: host_machine_id.to_string(),
        })?;

    let Some(remote_id) = remote_id else {
        tracing::error!(
            host_machine_id = %host_machine_id,
            "Remote id missing for instance.",
        );
        return Ok(());
    };

    for dpu_snapshot in snapshot.dpu_snapshots {
        let expected_remote_id = dpu_snapshot.machine_id.remote_id();

        if expected_remote_id == remote_id {
            return Ok(());
        }
    }
    Err(CarbideError::InvalidArgument(format!(
        "Mismatch in remote id. Remote id: {} is not matching with any DPU.",
        remote_id,
    )))
}

async fn handle_dhcp_for_instance(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    relay_ip: IpAddr,
    circuit_id: Option<String>,
    remote_id: Option<String>,
    parsed_mac: MacAddress,
) -> CarbideResult<Option<Response<rpc::DhcpRecord>>> {
    if let Some(instance) = Instance::find_by_relay_ip(txn, relay_ip).await? {
        validate_dhcp_request(txn, remote_id, &instance.machine_id).await?;
        let circuit_id_parsed = circuit_id
            .as_ref()
            .ok_or(DhcpError::MissingCircuitId(instance.id))
            .map_err(CarbideError::from)?;
        let record: rpc::DhcpRecord = InstanceDhcpRecord::find_for_instance(
            txn,
            parsed_mac,
            circuit_id_parsed.clone(),
            instance.clone(),
        )
        .await
        .map_err(|error| {
            tracing::error!(
                %instance.id,
                ?circuit_id,
                %error,
                "DHCP request failed",
            );
            CarbideError::from(DhcpError::InvalidInterface(
                instance.id,
                circuit_id_parsed.clone(),
            ))
        })?
        .try_into()?;

        tracing::info!(
            instance_id = %instance.id,
            circuit_id = circuit_id_parsed,
            ?record,
            "Returning DHCP response for instance",
        );
        return Ok(Some(Response::new(record)));
    }
    Ok(None)
}

pub async fn discover_dhcp(
    database_connection: &sqlx::PgPool,
    request: Request<rpc::DhcpDiscovery>,
) -> Result<Response<rpc::DhcpRecord>, CarbideError> {
    let mut txn = database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin discover_dhcp", e))?;

    let rpc::DhcpDiscovery {
        mac_address,
        relay_address,
        link_address,
        vendor_string,
        circuit_id,
        remote_id,
        ..
    } = request.into_inner();

    // Use link address if present, else relay address. Link address represents subnet address at
    // first router.
    let address_to_use_for_dhcp = link_address.as_ref().unwrap_or(&relay_address);
    let parsed_relay = address_to_use_for_dhcp
        .parse()
        .map_err(CarbideError::from)?;
    let relay_ip = IpAddr::from_str(&relay_address).map_err(CarbideError::from)?;

    let parsed_mac: MacAddress = mac_address
        .parse::<MacAddress>()
        .map_err(CarbideError::from)?;

    let existing_machine = Machine::find_existing_machine(&mut txn, parsed_mac, parsed_relay)
        .await
        .map_err(CarbideError::from)?;

    // Instance handling. None means no instance found matching with dhcp request.
    if let Some(response) =
        handle_dhcp_for_instance(&mut txn, relay_ip, circuit_id, remote_id, parsed_mac).await?
    {
        txn.commit()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "commit discover_dhcp", e))?;
        return Ok(response);
    }

    let machine_interface = MachineInterface::find_or_create_machine_interface(
        &mut txn,
        existing_machine,
        parsed_mac,
        parsed_relay,
    )
    .await?;

    // Save vendor string, this is allowed to fail due to dhcp happening more than once on the same machine/vendor string
    if let Some(vendor) = vendor_string {
        let res = DhcpEntry {
            machine_interface_id: *machine_interface.id(),
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

    MachineInterface::update_last_dhcp(&mut txn, machine_interface.id).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "commit discover_dhcp", e))?;

    let mut txn = database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin discover_dhcp 2", e))?;

    let record: rpc::DhcpRecord =
        DhcpRecord::find_by_mac_address(&mut txn, &parsed_mac, &machine_interface.segment_id())
            .await
            .map_err(CarbideError::from)?
            .into();

    txn.commit()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "commit discover_dhcp 2", e))?;
    Ok(Response::new(record))
}
