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
 *  Code for working the measuremment_reports and measurement_reports_values
 *  tables in the database, leveraging the report-specific record types.
*/

use crate::measured_boot::dto::keys::{
    MeasurementBundleId, MeasurementReportId, MeasurementSystemProfileId, UuidEmptyStringError,
};
use crate::measured_boot::dto::records::{
    MeasurementApprovedType, MeasurementBundleState, MeasurementMachineState,
    MeasurementReportRecord, MeasurementReportValueRecord,
};
use crate::measured_boot::interface::common;
use crate::measured_boot::interface::common::{parse_pcr_index_input, PcrRegisterValue, ToTable};
use crate::measured_boot::interface::{
    report::{
        delete_report_for_id, delete_report_values_for_id,
        get_latest_measurement_report_records_by_machine_id, get_measurement_report_record_by_id,
        get_measurement_report_values_for_report_id, insert_measurement_report_record,
        insert_measurement_report_value_records,
    },
    site::{
        get_approval_for_machine_id, get_approval_for_profile_id,
        remove_from_approved_machines_by_approval_id, remove_from_approved_profiles_by_approval_id,
    },
};
use crate::measured_boot::model::machine::bundle_state_to_machine_state;
use crate::measured_boot::model::{
    bundle::MeasurementBundle, journal::MeasurementJournal, machine::CandidateMachine,
    profile::MeasurementSystemProfile,
};
use crate::model::machine::machine_id::MachineId;
use rpc::protos::measured_boot::MeasurementReportPb;
use serde::Serialize;
use sqlx::types::chrono::Utc;
use sqlx::{Pool, Postgres, Transaction};
use std::collections::HashMap;
use std::str::FromStr;

///////////////////////////////////////////////////////////////////////////////
/// MeasurementReport is a composition of a MeasurementReportRecord,
/// whose attributes are essentially copied directly it, as well as
/// the associated attributes (which are complete instances of
/// MeasurementReportValueRecord, along with its UUID and timestamp).
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Serialize, Clone)]
pub struct MeasurementReport {
    pub report_id: MeasurementReportId,
    pub machine_id: MachineId,
    pub ts: chrono::DateTime<Utc>,
    pub values: Vec<MeasurementReportValueRecord>,
}

impl From<MeasurementReport> for MeasurementReportPb {
    fn from(val: MeasurementReport) -> Self {
        Self {
            report_id: Some(val.report_id.into()),
            machine_id: val.machine_id.to_string(),
            values: val
                .values
                .iter()
                .map(|value| value.clone().into())
                .collect(),
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<MeasurementReportPb> for MeasurementReport {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: MeasurementReportPb) -> Result<Self, Box<dyn std::error::Error>> {
        if msg.machine_id.is_empty() {
            return Err(UuidEmptyStringError {}.into());
        }
        let values: eyre::Result<Vec<MeasurementReportValueRecord>> = msg
            .values
            .iter()
            .map(
                |value| match MeasurementReportValueRecord::try_from(value.clone()) {
                    Ok(worked) => Ok(worked),
                    Err(failed) => Err(eyre::eyre!("attr conversion failed: {}", failed)),
                },
            )
            .collect();

        Ok(Self {
            report_id: MeasurementReportId::try_from(msg.report_id)?,
            machine_id: MachineId::from_str(&msg.machine_id)?,
            values: values?,
            ts: chrono::DateTime::<chrono::Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

impl MeasurementReport {
    ////////////////////////////////////////////////////////////
    /// new creates a new measurement report in the database.
    ////////////////////////////////////////////////////////////

    pub async fn new(
        db_conn: &Pool<Postgres>,
        machine_id: MachineId,
        values: &[common::PcrRegisterValue],
    ) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        let report = Self::new_with_txn(&mut txn, machine_id, values).await?;
        txn.commit().await?;
        Ok(report)
    }

    pub async fn new_with_txn(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: MachineId,
        values: &[common::PcrRegisterValue],
    ) -> eyre::Result<Self> {
        create_measurement_report(txn, machine_id, values).await
    }

    ////////////////////////////////////////////////////////////
    /// from_grpc takes an optional protobuf (as populated in a
    /// proto response from the API) and attempts to convert it
    /// to the backing model.
    ////////////////////////////////////////////////////////////

    pub fn from_grpc(some_pb: Option<&MeasurementReportPb>) -> eyre::Result<Self> {
        some_pb
            .ok_or(eyre::eyre!("report is unexpectedly empty"))
            .and_then(|pb| {
                Self::try_from(pb.clone())
                    .map_err(|e| eyre::eyre!("report failed pb->model conversion: {}", e))
            })
    }

    ////////////////////////////////////////////////////////////
    /// from_id populates an existing MeasurementReport
    /// instance from data in the database for the given
    /// report ID.
    ////////////////////////////////////////////////////////////

    pub async fn from_id(
        db_conn: &Pool<Postgres>,
        report_id: MeasurementReportId,
    ) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        Self::from_id_with_txn(&mut txn, report_id).await
    }

    pub async fn from_id_with_txn(
        txn: &mut Transaction<'_, Postgres>,
        report_id: MeasurementReportId,
    ) -> eyre::Result<Self> {
        get_measurement_report_by_id_with_txn(txn, report_id).await
    }

    /// delete_for_id deletes a MeasurementReport and associated
    /// MeasurementReportValues, returning a fully populated instance of
    /// MeasurementReport of the data that was deleted for `report_id`.
    pub async fn delete_for_id(
        db_conn: &Pool<Postgres>,
        report_id: MeasurementReportId,
    ) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        let values = delete_report_values_for_id(&mut txn, report_id).await?;
        let info = delete_report_for_id(&mut txn, report_id).await?;
        txn.commit().await?;
        Ok(Self {
            report_id: info.report_id,
            machine_id: info.machine_id,
            ts: info.ts,
            values,
        })
    }

    pub fn pcr_values(&self) -> Vec<common::PcrRegisterValue> {
        let borrowed = &self.values;
        borrowed.iter().map(|rec| rec.clone().into()).collect()
    }

    pub async fn get_all_for_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: MachineId,
    ) -> eyre::Result<Vec<Self>> {
        get_measurement_reports_for_machine_id(txn, machine_id).await
    }

    pub async fn get_all(txn: &mut Transaction<'_, Postgres>) -> eyre::Result<Vec<Self>> {
        get_all_measurement_reports(txn).await
    }

    ////////////////////////////////////////////////////////////
    /// create_bundle_with_state creates a new measurement bundle
    /// out of a measurement report with the given state, with
    /// the option to provide a range of PCR register values to
    /// specifically select from the report's bundle (e.g. maybe
    /// the report has registers 0-12, but we only want to
    /// create a new bundle with registers 0-6).
    ////////////////////////////////////////////////////////////

    async fn create_bundle_with_state(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        state: MeasurementBundleState,
        pcr_set: &Option<common::PcrSet>,
    ) -> eyre::Result<MeasurementBundle> {
        create_bundle_with_state(txn, self, state, pcr_set).await
    }

    ////////////////////////////////////////////////////////////
    /// create_active_bundle creates a new, active
    /// measurement_bundle out of a measurement report.
    ////////////////////////////////////////////////////////////

    pub async fn create_active_bundle(
        &self,
        db_conn: &Pool<Postgres>,
        pcr_set: &Option<common::PcrSet>,
    ) -> eyre::Result<MeasurementBundle> {
        let mut txn = db_conn.begin().await?;
        self.create_active_bundle_with_txn(&mut txn, pcr_set).await
    }

    pub async fn create_active_bundle_with_txn(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        pcr_set: &Option<common::PcrSet>,
    ) -> eyre::Result<MeasurementBundle> {
        self.create_bundle_with_state(txn, MeasurementBundleState::Active, pcr_set)
            .await
    }

    ////////////////////////////////////////////////////////////
    /// create_revoked_bundle creates a new, revoked
    /// measurement_bundle out of a measurement report.
    ////////////////////////////////////////////////////////////

    pub async fn create_revoked_bundle(
        &self,
        db_conn: &Pool<Postgres>,
        pcr_set: &Option<common::PcrSet>,
    ) -> eyre::Result<MeasurementBundle> {
        let mut txn = db_conn.begin().await?;
        self.create_revoked_bundle_with_txn(&mut txn, pcr_set).await
    }

    pub async fn create_revoked_bundle_with_txn(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        pcr_set: &Option<common::PcrSet>,
    ) -> eyre::Result<MeasurementBundle> {
        self.create_bundle_with_state(txn, MeasurementBundleState::Revoked, pcr_set)
            .await
    }
}

///////////////////////////////////////////////////////////////////////////////
// When `report show <report-id>` gets called, and the output format is
// the default table view, this gets used to print a pretty table.
///////////////////////////////////////////////////////////////////////////////

impl ToTable for MeasurementReport {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        let mut values_table = prettytable::Table::new();
        values_table.add_row(prettytable::row!["pcr_register", "value"]);
        for value_record in self.values.iter() {
            values_table.add_row(prettytable::row![
                value_record.pcr_register,
                value_record.sha256
            ]);
        }
        table.add_row(prettytable::row!["report_id", self.report_id]);
        table.add_row(prettytable::row!["machine_id", self.machine_id]);
        table.add_row(prettytable::row!["created_ts", self.ts]);
        table.add_row(prettytable::row!["values", values_table]);
        Ok(table.to_string())
    }
}

///////////////////////////////////////////////////////////////////////////////
// When `report show` gets called (for all entries), and the output format
// is the default table view, this gets used to print a pretty table.
///////////////////////////////////////////////////////////////////////////////

impl ToTable for Vec<MeasurementReport> {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["report_id", "details", "values"]);
        for report in self.iter() {
            let mut details_table = prettytable::Table::new();
            details_table.add_row(prettytable::row!["report_id", report.report_id]);
            details_table.add_row(prettytable::row!["machine_id", report.machine_id]);
            details_table.add_row(prettytable::row!["created_ts", report.ts]);
            let mut values_table = prettytable::Table::new();
            values_table.add_row(prettytable::row!["pcr_register", "value"]);
            for value_record in report.values.iter() {
                values_table.add_row(prettytable::row![
                    value_record.pcr_register,
                    value_record.sha256
                ]);
            }
            table.add_row(prettytable::row![
                report.report_id,
                details_table,
                values_table
            ]);
        }
        Ok(table.to_string())
    }
}

///////////////////////////////////////////////////////////////////////////////
/// create_measurement_report handles the work of creating a new
/// measurement report as well as all associated value records.
///////////////////////////////////////////////////////////////////////////////

pub async fn create_measurement_report(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
    values: &[common::PcrRegisterValue],
) -> eyre::Result<MeasurementReport> {
    let info = insert_measurement_report_record(txn, machine_id).await?;
    let values = insert_measurement_report_value_records(txn, info.report_id, values).await?;
    let report = MeasurementReport {
        report_id: info.report_id,
        machine_id: info.machine_id,
        ts: info.ts,
        values,
    };

    let journal_data =
        JournalData::new_from_values(txn, report.machine_id.clone(), &report.pcr_values()).await?;
    // Now that the bundle_id and profile_id bits have been sorted, its
    // time to make a new journal entry that captures the [possible]
    // bundle_id, the profile_id, and the values to log to the journal.
    let journal = MeasurementJournal::new_with_txn(
        txn,
        report.machine_id.clone(),
        report.report_id,
        journal_data.profile_id,
        journal_data.bundle_id,
        journal_data.state,
    )
    .await?;

    // TODO(chet): Now that profiles are auto-created if a matching one
    // doesn't exist, maybe this can go, but i'm keeping it here as a
    // placeholder, just incase we want to turn off auto-creation of
    // profiles (or make it configurable).
    if journal.profile_id.is_none() {
        return Err(eyre::eyre!("profile id shouldn't be none"));
    }

    // And, finally, if there's no bundle_id associated with the journal entry,
    // see if any sort of auto-approve is configured for the current machine ID.
    // If it is, then convert the journal into an active bundle, and then create
    // a second journal entry backed by the new active bundle.
    //
    // Machine auto-approvals take priority over profile auto-approvals.
    if journal.bundle_id.is_none() && !maybe_auto_approve_machine(txn, &report).await? {
        maybe_auto_approve_profile(txn, &journal, &report).await?;
    }

    Ok(report)
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_reports returns all MeasurementReport
/// instances in the database. This leverages the generic get_all_objects
/// function since its a simple/common pattern.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_all_measurement_reports(
    txn: &mut Transaction<'_, Postgres>,
) -> eyre::Result<Vec<MeasurementReport>> {
    let report_records: Vec<MeasurementReportRecord> = common::get_all_objects(txn).await?;
    let mut report_values: Vec<MeasurementReportValueRecord> = common::get_all_objects(txn).await?;

    let mut values_by_report_id: HashMap<MeasurementReportId, Vec<MeasurementReportValueRecord>> =
        HashMap::new();

    for report_value in report_values.drain(..) {
        values_by_report_id
            .entry(report_value.report_id)
            .or_default()
            .push(report_value);
    }

    let mut res = Vec::<MeasurementReport>::new();
    for report_record in report_records.iter() {
        let values = match values_by_report_id.remove(&report_record.report_id) {
            Some(vals) => vals,
            None => Vec::<MeasurementReportValueRecord>::new(),
        };
        res.push(MeasurementReport {
            report_id: report_record.report_id,
            machine_id: report_record.machine_id.clone(),
            ts: report_record.ts,
            values: values.to_vec(),
        });
    }
    Ok(res)
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_report_by_id does the work of populating a full
/// MeasurementReport instance, with values and all.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_report_by_id_with_txn(
    txn: &mut Transaction<'_, Postgres>,
    report_id: MeasurementReportId,
) -> eyre::Result<MeasurementReport> {
    match get_measurement_report_record_by_id(txn, report_id).await? {
        Some(info) => {
            let values = get_measurement_report_values_for_report_id(txn, info.report_id).await?;
            Ok(MeasurementReport {
                report_id: info.report_id,
                machine_id: info.machine_id,
                ts: info.ts,
                values,
            })
        }
        None => Err(eyre::eyre!("no report found with that ID")),
    }
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_reports_for_machine_id returns all fully populated
/// report instances for a given machine ID, which is used by the
/// `report show` CLI option.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_reports_for_machine_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
) -> eyre::Result<Vec<MeasurementReport>> {
    let report_records: Vec<MeasurementReportRecord> =
        common::get_objects_where_id(txn, machine_id).await?;
    let mut res = Vec::<MeasurementReport>::new();
    for report_record in report_records.iter() {
        let values =
            get_measurement_report_values_for_report_id(txn, report_record.report_id).await?;
        res.push(MeasurementReport {
            report_id: report_record.report_id,
            machine_id: report_record.machine_id.clone(),
            ts: report_record.ts,
            values,
        });
    }
    Ok(res)
}

///////////////////////////////////////////////////////////////////////////////
/// get_latest_measurement_reports_by_machine_id returns the most
/// recent measurement reports sent by each machine.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_latest_measurement_reports_by_machine_id(
    txn: &mut Transaction<'_, Postgres>,
) -> eyre::Result<Vec<MeasurementReport>> {
    let report_records = get_latest_measurement_report_records_by_machine_id(txn).await?;
    let mut res = Vec::<MeasurementReport>::new();
    for report_record in report_records.iter() {
        let values =
            get_measurement_report_values_for_report_id(txn, report_record.report_id).await?;
        res.push(MeasurementReport {
            report_id: report_record.report_id,
            machine_id: report_record.machine_id.clone(),
            ts: report_record.ts,
            values,
        });
    }
    Ok(res)
}

///////////////////////////////////////////////////////////////////////////////
/// JournalData is just a small struct used to store data collected as
/// part of attestation work when forming a new journal entry.
///////////////////////////////////////////////////////////////////////////////

struct JournalData {
    state: MeasurementMachineState,
    bundle_id: Option<MeasurementBundleId>,
    profile_id: Option<MeasurementSystemProfileId>,
}

impl JournalData {
    pub async fn new_from_values(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: MachineId,
        values: &[PcrRegisterValue],
    ) -> eyre::Result<Self> {
        let state: MeasurementMachineState;
        let bundle_id: Option<MeasurementBundleId>;

        let machine = CandidateMachine::from_id_with_txn(txn, machine_id).await?;
        let profile = MeasurementSystemProfile::match_from_attrs_or_new_with_txn(
            txn,
            &machine.discovery_attributes()?,
        )
        .await?;

        match MeasurementBundle::match_from_values(txn, profile.profile_id, values).await? {
            Some(bundle) => {
                state = bundle_state_to_machine_state(&bundle.state);
                bundle_id = Some(bundle.bundle_id);
            }
            None => {
                state = MeasurementMachineState::PendingBundle;
                bundle_id = None;
            }
        }

        Ok(Self {
            state,
            bundle_id,
            profile_id: Some(profile.profile_id),
        })
    }
}

///////////////////////////////////////////////////////////////////////////////
/// maybe_auto_approve_machine will check to see if an auto-approve config
/// exists for the current machine ID. If it does, it will make a new
/// measurement bundle using the selected report registers per the auto
/// approve config.
///
/// It's worth mentioning that this in and of itself will create an additional
/// journal entry, should a new bundle be created.
///////////////////////////////////////////////////////////////////////////////

async fn maybe_auto_approve_machine(
    txn: &mut Transaction<'_, Postgres>,
    report: &MeasurementReport,
) -> eyre::Result<bool> {
    match get_approval_for_machine_id(txn, report.machine_id.clone()).await? {
        Some(approval) => {
            let pcr_set = match approval.pcr_registers {
                Some(pcr_registers) => Some(parse_pcr_index_input(pcr_registers.as_str())?),
                None => None,
            };
            let _ = report.create_active_bundle_with_txn(txn, &pcr_set).await?;

            // If this is a oneshot approval, then remove the approval
            // entry after this automatic journal promotion.
            if approval.approval_type == MeasurementApprovedType::Oneshot {
                remove_from_approved_machines_by_approval_id(txn, approval.approval_id).await?;
            }
            Ok(true)
        }
        None => Ok(false),
    }
}

///////////////////////////////////////////////////////////////////////////////
/// maybe_auto_approve_profile will check to see if an auto-approve config
/// exists for the current machine's system profile. If it does, it will make
/// a new measurement bundle using the selected report registers per the auto
/// approve config.
///
/// It's worth mentioning that this in and of itself will create an additional
/// journal entry, should a new bundle be created.
///////////////////////////////////////////////////////////////////////////////

async fn maybe_auto_approve_profile(
    txn: &mut Transaction<'_, Postgres>,
    journal: &MeasurementJournal,
    report: &MeasurementReport,
) -> eyre::Result<bool> {
    match get_approval_for_profile_id(txn, journal.profile_id.unwrap()).await? {
        Some(approval) => {
            let pcr_set = match approval.pcr_registers {
                Some(pcr_registers) => Some(parse_pcr_index_input(pcr_registers.as_str())?),
                None => None,
            };
            let _ = report.create_active_bundle_with_txn(txn, &pcr_set).await?;

            // If this is a oneshot approval, then remove the approval
            // entry after this automatic journal promotion.
            if approval.approval_type == MeasurementApprovedType::Oneshot {
                remove_from_approved_profiles_by_approval_id(txn, approval.approval_id).await?;
            }
            Ok(true)
        }
        None => Ok(false),
    }
}

///////////////////////////////////////////////////////////////////////////////
/// create_bundle_with_state takes a report entry and creates a new measurement
/// bundle for it with the provided state, optionally restricting only certain
/// PCR register values per pcr_set.
///////////////////////////////////////////////////////////////////////////////

pub async fn create_bundle_with_state(
    txn: &mut Transaction<'_, Postgres>,
    report: &MeasurementReport,
    state: MeasurementBundleState,
    pcr_set: &Option<common::PcrSet>,
) -> eyre::Result<MeasurementBundle> {
    // Get machine + profile information for the journal entry
    // that needs to be associated with the bundle change.
    let machine = CandidateMachine::from_id_with_txn(txn, report.machine_id.clone()).await?;
    let profile = MeasurementSystemProfile::match_from_attrs_or_new_with_txn(
        txn,
        &machine.discovery_attributes()?,
    )
    .await?;

    // Convert the input MeasurementReportValueRecord entries
    // into a list of PcrRegisterValue entries for the purpose
    // of creating a new bundle.
    let register_map = common::pcr_register_values_to_map(&report.pcr_values())?;

    let values: Vec<common::PcrRegisterValue> = match pcr_set {
        // If a pcr_range is provided, make sure its a valid range,
        // and then attempt to pluck out a pcr_register value from
        // the register_map for each index in the range.
        Some(pcr_set) => {
            let filtered: eyre::Result<Vec<common::PcrRegisterValue>> = pcr_set
                .iter()
                .map(|pcr_register| match register_map.get(pcr_register) {
                    Some(register_val) => Ok(register_val.clone()),
                    None => Err(eyre::eyre!(
                        "could not find pcr_register value {} in range",
                        pcr_register
                    )),
                })
                .collect();
            filtered?
        }
        // If no pcr_range is provided, then just take all measurement
        // journal values from here and turn them into a new bundle.
        None => report.pcr_values(),
    };

    MeasurementBundle::new_with_txn(txn, profile.profile_id, None, &values, Some(state)).await
}
