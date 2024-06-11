/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

/*!
 *  Code for working the machine_topologies table in the
 *  database, leveraging the machine-specific record types.
*/

use crate::measured_boot::dto::records::{
    CandidateMachineRecord, MeasurementJournalRecord, MeasurementMachineState,
};
use crate::measured_boot::interface::common;
use crate::model::machine::machine_id::MachineId;
use sqlx::{Postgres, Transaction};
use std::collections::HashMap;

/// get_discovery_attributes returns a hashmap of values from
/// the DiscoveryInfo + HardwareInfo data used for matching to
/// a machine profile.
pub async fn get_discovery_attributes(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
) -> eyre::Result<HashMap<String, String>> {
    let attrs = get_machine_attrs_for_machine_id(txn, machine_id).await?;
    common::filter_machine_discovery_attrs(&attrs)
}

/// get_candidate_machine_state figures out the current state of the given
/// machine ID by checking its most recent bundle (or lack thereof), and
/// using that result to give it a corresponding MeasurementMachineState.
pub async fn get_candidate_machine_state(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
) -> eyre::Result<MeasurementMachineState> {
    Ok(
        match get_latest_journal_for_id(&mut *txn, machine_id).await? {
            Some(record) => record.state,
            None => MeasurementMachineState::Discovered,
        },
    )
}

/// get_latest_journal_for_id returns the latest journal record for the
/// provided machine ID.
pub async fn get_latest_journal_for_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
) -> eyre::Result<Option<MeasurementJournalRecord>> {
    let query = "select distinct on (machine_id) * from measurement_journal where machine_id = $1 order by machine_id,ts desc";
    Ok(sqlx::query_as::<_, MeasurementJournalRecord>(query)
        .bind(machine_id)
        .fetch_optional(&mut **txn)
        .await?)
}

/// get_machine_attrs_for_machine_id returns all machine attribute
/// records associated with the provided MachineId.
pub async fn get_machine_attrs_for_machine_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
) -> eyre::Result<HashMap<String, String>> {
    let record = get_candidate_machine_record_by_id(txn, machine_id).await?;
    match &record.topology.discovery_data.info.dmi_data {
        Some(dmi_data) => Ok(HashMap::from([
            (String::from("sys_vendor"), dmi_data.sys_vendor.clone()),
            (String::from("product_name"), dmi_data.product_name.clone()),
            (String::from("bios_version"), dmi_data.bios_version.clone()),
        ])),
        None => Err(eyre::eyre!("machine missing dmi data")),
    }
}

/// get_candidate_machine_record_by_id returns a CandidateMachineRecord row.
pub async fn get_candidate_machine_record_by_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
) -> eyre::Result<CandidateMachineRecord> {
    let record: Option<CandidateMachineRecord> = common::get_object_for_id(txn, machine_id).await?;
    match record {
        Some(record) => Ok(record),
        None => Err(eyre::eyre!("cannot find machine with id")),
    }
}

/// get_candidate_machine_records returns all MockMachineRecord rows,
/// primarily for the purpose of `mock-machine list`.
pub async fn get_candidate_machine_records(
    txn: &mut Transaction<'_, Postgres>,
) -> eyre::Result<Vec<CandidateMachineRecord>> {
    common::get_all_objects(txn).await
}
