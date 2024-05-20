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

/*
///////////////////////////////////////////////////////////////////////////////
/// db/interface/bundle.rs
///
/// Code for working the measurement_bundles and measurement_bundles_values
/// tables in the database, leveraging the bundle-specific record types.
///////////////////////////////////////////////////////////////////////////////
*/

use crate::measured_boot::dto::keys::{MeasurementBundleId, MeasurementSystemProfileId};
use crate::measured_boot::dto::records::{
    MeasurementBundleRecord, MeasurementBundleState, MeasurementBundleValueRecord,
};
use crate::measured_boot::interface::bundle::{
    delete_bundle_for_id, delete_bundle_values_for_id, get_measurement_bundle_by_id,
    get_measurement_bundle_for_name, get_measurement_bundle_records_for_profile_id,
    get_measurement_bundle_records_with_txn, get_measurement_bundle_values_for_bundle_id,
    insert_measurement_bundle_record, insert_measurement_bundle_value_records,
    rename_bundle_for_bundle_id, rename_bundle_for_bundle_name, set_state_for_bundle_id,
};
use crate::measured_boot::interface::common;
use crate::measured_boot::interface::common::ToTable;
use crate::measured_boot::interface::report::match_latest_reports_with_txn;
use crate::measured_boot::model::machine::{bundle_state_to_machine_state, MockMachine};
use crate::measured_boot::model::profile::MeasurementSystemProfile;
use rpc::protos::measured_boot::{MeasurementBundlePb, MeasurementBundleStatePb};
use serde::Serialize;
use sqlx::types::chrono::Utc;
use sqlx::{Pool, Postgres, Transaction};

use crate::measured_boot::model::journal::MeasurementJournal;

///////////////////////////////////////////////////////////////////////////////
/// MeasurementBundle is a composition of a MeasurementBundleRecord,
/// whose attributes are essentially copied directly it, as well as
/// the associated attributes (which are complete instances of
/// MeasurementBundleValueRecord, along with its UUID and timestamp).
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Serialize)]
pub struct MeasurementBundle {
    // bundle_id is the auto-generated UUID for a measurement bundle,
    // and is used as a reference ID for all measurement_bundle_value
    // records.
    pub bundle_id: MeasurementBundleId,

    // profile_id is the system profile this bundle is associated
    // with, allowing us to track bundles per profile.
    pub profile_id: MeasurementSystemProfileId,

    // name is the [db-enforced] unique, human-friendly name for the
    // bundle. for manually-created bundles, it is expected that
    // a name is provided. for auto-created bundles, some sort of
    // derived name is generated.
    pub name: String,

    // state is the state of this bundle.
    // See the MeasurementBundleState enum for more info,
    // including all states, and what they mean.
    pub state: MeasurementBundleState,

    // values are all of the bundle measurement values,
    // which includes all of the PCR registers and their
    // values.
    pub values: Vec<MeasurementBundleValueRecord>,

    // ts is the timestamp this bundle was created.
    pub ts: chrono::DateTime<Utc>,
}

impl From<MeasurementBundle> for MeasurementBundlePb {
    fn from(val: MeasurementBundle) -> Self {
        let pb_state: MeasurementBundleStatePb = val.state.into();
        Self {
            bundle_id: Some(val.bundle_id.into()),
            profile_id: Some(val.profile_id.into()),
            name: val.name,
            state: pb_state.into(),
            values: val
                .values
                .iter()
                .map(|value| value.clone().into())
                .collect(),
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<MeasurementBundlePb> for MeasurementBundle {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: MeasurementBundlePb) -> Result<Self, Box<dyn std::error::Error>> {
        let state = msg.state();
        let values: eyre::Result<Vec<MeasurementBundleValueRecord>> = msg
            .values
            .iter()
            .map(
                |attr| match MeasurementBundleValueRecord::try_from(attr.clone()) {
                    Ok(worked) => Ok(worked),
                    Err(failed) => Err(eyre::eyre!("attr conversion failed: {}", failed)),
                },
            )
            .collect();

        Ok(Self {
            bundle_id: MeasurementBundleId::try_from(msg.bundle_id)?,
            profile_id: MeasurementSystemProfileId::try_from(msg.profile_id)?,
            name: msg.name.clone(),
            state: MeasurementBundleState::from(state),
            values: values?,
            ts: chrono::DateTime::<chrono::Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

impl MeasurementBundle {
    /// new creates a new instance of a MeasurementBundle directly
    /// into the measurement_bundles + measurement_bundles_values
    /// tables, returning a complete instance of a MeasurementBundle,
    /// along with the newly-minted UUID and timestamp (ts) values.
    pub async fn new(
        db_conn: &Pool<Postgres>,
        profile_id: MeasurementSystemProfileId,
        name: Option<String>,
        values: &[common::PcrRegisterValue],
        state: Option<MeasurementBundleState>,
    ) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        let bundle = Self::new_with_txn(&mut txn, profile_id, name, values, state).await?;
        txn.commit().await?;
        Ok(bundle)
    }

    pub async fn new_with_txn(
        txn: &mut Transaction<'_, Postgres>,
        profile_id: MeasurementSystemProfileId,
        name: Option<String>,
        values: &[common::PcrRegisterValue],
        state: Option<MeasurementBundleState>,
    ) -> eyre::Result<Self> {
        if MeasurementBundle::has_exact_from_values(txn, profile_id, values).await? {
            return Err(eyre::eyre!("matching bundle already exists"));
        }

        let bundle_name = match name {
            Some(name) => name,
            None => common::generate_name()?,
        };

        let info = insert_measurement_bundle_record(txn, profile_id, bundle_name, state).await?;
        let bundle_values =
            insert_measurement_bundle_value_records(txn, info.bundle_id, values).await?;
        let bundle = MeasurementBundle::from_info_and_values(info, bundle_values)?;
        bundle.update_journal(txn).await?;

        Ok(bundle)
    }

    ////////////////////////////////////////////////////////////
    /// from_grpc takes an optional protobuf (as populated in a
    /// proto response from the API) and attempts to convert it
    /// to the backing model.
    ////////////////////////////////////////////////////////////

    pub fn from_grpc(some_pb: Option<&MeasurementBundlePb>) -> eyre::Result<Self> {
        some_pb
            .ok_or(eyre::eyre!("bundle is unexpectedly empty"))
            .and_then(|pb| {
                Self::try_from(pb.clone())
                    .map_err(|e| eyre::eyre!("bundle failed pb->model conversion: {}", e))
            })
    }

    /// from_info_and_values creates a new bundle from the
    /// base record and its values.
    pub fn from_info_and_values(
        info: MeasurementBundleRecord,
        values: Vec<MeasurementBundleValueRecord>,
    ) -> eyre::Result<Self> {
        Ok(Self {
            bundle_id: info.bundle_id,
            profile_id: info.profile_id,
            name: info.name,
            ts: info.ts,
            state: info.state,
            values,
        })
    }

    /// from_id returns a fully populated instance of
    /// MeasurementBundle for the provided `bundle_id`.
    pub async fn from_id(
        db_conn: &Pool<Postgres>,
        bundle_id: MeasurementBundleId,
    ) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        MeasurementBundle::from_id_with_txn(&mut txn, bundle_id).await
    }

    /// from_id_with_txn returns a fully populated instance of
    /// MeasurementBundle for the provided `bundle_id`.
    pub async fn from_id_with_txn(
        txn: &mut Transaction<'_, Postgres>,
        bundle_id: MeasurementBundleId,
    ) -> eyre::Result<Self> {
        match get_measurement_bundle_by_id(txn, bundle_id).await? {
            Some(info) => {
                let values =
                    get_measurement_bundle_values_for_bundle_id(txn, info.bundle_id).await?;
                Ok(MeasurementBundle::from_info_and_values(info, values)?)
            }
            None => Err(eyre::eyre!("could not find bundle with that ID")),
        }
    }

    /// from_name returns a fully populated instance of
    /// MeasurementBundle for the provided `bundle_name`.
    pub async fn from_name(db_conn: &Pool<Postgres>, bundle_name: String) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        Self::from_name_with_txn(&mut txn, bundle_name.clone()).await
    }

    /// from_name_with_txn returns a fully populated instance of
    /// MeasurementBundle for the provided `bundle_name`.
    pub async fn from_name_with_txn(
        txn: &mut Transaction<'_, Postgres>,
        bundle_name: String,
    ) -> eyre::Result<Self> {
        match get_measurement_bundle_for_name(txn, bundle_name.clone()).await? {
            Some(info) => {
                let values =
                    get_measurement_bundle_values_for_bundle_id(txn, info.bundle_id).await?;
                Ok(Self::from_info_and_values(info, values)?)
            }
            None => Err(eyre::eyre!("could not find bundle with that name")),
        }
    }

    /////////////////////////////////////////////////////
    /// set_state_for_id sets the bundle state for
    /// the given bundle ID.
    /////////////////////////////////////////////////////

    pub async fn set_state_for_id(
        txn: &mut Transaction<'_, Postgres>,
        bundle_id: MeasurementBundleId,
        state: MeasurementBundleState,
    ) -> eyre::Result<Self> {
        let info = set_state_for_bundle_id(txn, bundle_id, state).await?;
        let values = get_measurement_bundle_values_for_bundle_id(txn, info.bundle_id).await?;
        let bundle = Self::from_info_and_values(info, values)?;
        bundle.update_journal(txn).await?;
        Ok(bundle)
    }

    /////////////////////////////////////////////////////
    /// get_all returns all populated MeasurementBundle
    /// models from records in the database.
    /////////////////////////////////////////////////////

    pub async fn get_all(txn: &mut Transaction<'_, Postgres>) -> eyre::Result<Vec<Self>> {
        let mut res: Vec<MeasurementBundle> = Vec::new();
        let mut bundle_records = get_measurement_bundle_records_with_txn(txn).await?;
        for bundle_record in bundle_records.drain(..) {
            let values =
                get_measurement_bundle_values_for_bundle_id(txn, bundle_record.bundle_id).await?;
            res.push(Self::from_info_and_values(bundle_record, values)?);
        }
        Ok(res)
    }

    /////////////////////////////////////////////////////
    /// get_all_for_profile_id returns all populated
    /// MeasurementBundle models for a given profile ID.
    /////////////////////////////////////////////////////

    pub async fn get_all_for_profile_id(
        txn: &mut Transaction<'_, Postgres>,
        profile_id: MeasurementSystemProfileId,
    ) -> eyre::Result<Vec<Self>> {
        let mut res: Vec<MeasurementBundle> = Vec::new();
        let mut bundle_records =
            get_measurement_bundle_records_for_profile_id(txn, profile_id).await?;
        for bundle_record in bundle_records.drain(..) {
            let values =
                get_measurement_bundle_values_for_bundle_id(txn, bundle_record.bundle_id).await?;
            res.push(Self::from_info_and_values(bundle_record, values)?);
        }
        Ok(res)
    }

    /// has_exact_from_values is just a wrapper to make things
    /// a little cleaner for potential callers of exact_from_values.
    pub async fn has_exact_from_values(
        txn: &mut Transaction<'_, Postgres>,
        profile_id: MeasurementSystemProfileId,
        values: &[common::PcrRegisterValue],
    ) -> eyre::Result<bool> {
        match Self::exact_from_values(txn, profile_id, values).await? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    /// exact_from_values returns a fully populated instance of
    /// MeasurementBundle that exactly matches the provided `values`.
    pub async fn exact_from_values(
        txn: &mut Transaction<'_, Postgres>,
        profile_id: MeasurementSystemProfileId,
        values: &[common::PcrRegisterValue],
    ) -> eyre::Result<Option<Self>> {
        match Self::match_from_values(txn, profile_id, values).await? {
            Some(bundle) => {
                if bundle.values.len() == values.len() {
                    return Ok(Some(bundle));
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// match_from_values returns a fully populated instance of
    /// MeasurementBundle that matches the provided `values`.
    pub async fn match_from_values(
        txn: &mut Transaction<'_, Postgres>,
        profile_id: MeasurementSystemProfileId,
        values: &[common::PcrRegisterValue],
    ) -> eyre::Result<Option<Self>> {
        let bundle_id = match match_bundle(txn, profile_id, values).await? {
            Some(bundle_id) => bundle_id,
            None => {
                return Ok(None);
            }
        };
        Ok(Some(Self::from_id_with_txn(txn, bundle_id).await?))
    }

    /// delete deletes this bundle.
    pub async fn delete(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        purge_journals: bool,
    ) -> eyre::Result<MeasurementBundle> {
        Self::delete_for_id_with_txn(txn, self.bundle_id, purge_journals).await
    }

    /// delete_for_id deletes a MeasurementBundle and associated
    /// MeasurementBundleValues, returning a fully populated instance of
    /// MeasurementBundle of the data that was deleted for `bundle_id`.
    pub async fn delete_for_id(
        db_conn: &Pool<Postgres>,
        bundle_id: MeasurementBundleId,
        purge_journals: bool,
    ) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        let bundle = Self::delete_for_id_with_txn(&mut txn, bundle_id, purge_journals).await?;
        txn.commit().await?;
        Ok(bundle)
    }

    pub async fn delete_for_id_with_txn(
        txn: &mut Transaction<'_, Postgres>,
        bundle_id: MeasurementBundleId,
        purge_journals: bool,
    ) -> eyre::Result<Self> {
        // Note that due to relational constraints, values must be
        // deleted before the parent record.
        if purge_journals {
            return Err(eyre::eyre!("journal purge not supported -- TODO"));
        }
        let values = delete_bundle_values_for_id(txn, bundle_id).await?;
        let info = delete_bundle_for_id(txn, bundle_id).await?;
        Self::from_info_and_values(info, values)
    }

    /// rename_for_id renames a MeasurementBundle based on its ID.
    pub async fn rename_for_id(
        txn: &mut Transaction<'_, Postgres>,
        bundle_id: MeasurementBundleId,
        new_bundle_name: String,
    ) -> eyre::Result<Self> {
        Self::from_info_and_values(
            rename_bundle_for_bundle_id(txn, bundle_id, new_bundle_name.clone()).await?,
            get_measurement_bundle_values_for_bundle_id(txn, bundle_id).await?,
        )
    }

    /// rename_for_name renames a MeasurementBundle based on its name.
    pub async fn rename_for_name(
        txn: &mut Transaction<'_, Postgres>,
        bundle_name: String,
        new_bundle_name: String,
    ) -> eyre::Result<Self> {
        let info = rename_bundle_for_bundle_name(txn, bundle_name.clone(), new_bundle_name.clone())
            .await?;
        let values = get_measurement_bundle_values_for_bundle_id(txn, info.bundle_id).await?;
        Self::from_info_and_values(info, values)
    }

    /// delete_for_name deletes a MeasurementBundle and associated
    /// MeasurementBundleValues, returning a fully populated instance of
    /// MeasurementBundle of the data that was deleted for `bundle_id`.
    pub async fn delete_for_name(
        db_conn: &Pool<Postgres>,
        bundle_name: String,
        purge_journals: bool,
    ) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        // Note that due to relational constraints, values must be
        // deleted before the parent record.
        if purge_journals {
            return Err(eyre::eyre!("journal purge not supported -- TODO"));
        }
        let bundle = Self::from_name_with_txn(&mut txn, bundle_name.clone())
            .await?
            .delete(&mut txn, purge_journals)
            .await?;
        txn.commit().await?;
        Ok(bundle)
    }

    pub fn pcr_values(&self) -> Vec<common::PcrRegisterValue> {
        let borrowed = &self.values;
        borrowed.iter().map(|rec| rec.clone().into()).collect()
    }

    async fn update_journal(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> eyre::Result<Vec<MeasurementJournal>> {
        let machine_state = bundle_state_to_machine_state(&self.state);

        let reports = match_latest_reports_with_txn(txn, &self.pcr_values()).await?;
        let mut updates: Vec<MeasurementJournal> = Vec::new();
        for report in reports.iter() {
            let machine = MockMachine::from_id_with_txn(txn, report.machine_id.clone()).await?;
            let profile = MeasurementSystemProfile::match_from_attrs_or_new_with_txn(
                txn,
                &machine.discovery_attributes()?,
            )
            .await?;

            // Don't update journal entries for profiles
            // that aren't mine, since, in theory, two
            // different profiles could have the same
            // golden measurement bundles.
            if profile.profile_id != self.profile_id {
                continue;
            }
            updates.push(
                MeasurementJournal::new_with_txn(
                    txn,
                    report.machine_id.clone(),
                    report.report_id,
                    Some(profile.profile_id),
                    Some(self.bundle_id),
                    machine_state,
                )
                .await?,
            );
        }
        Ok(updates)
    }

    pub fn intersects(&self, values: &[common::PcrRegisterValue]) -> eyre::Result<bool> {
        let register_map = common::pcr_register_values_to_map(values)?;
        Ok(self.values.iter().all(|value_record| {
            if let Some(register_value) = register_map.get(&value_record.pcr_register) {
                register_value.sha256 == value_record.sha256
            } else {
                false
            }
        }))
    }
}

///////////////////////////////////////////////////////////////////////////////
// When `bundle show <bundle-id>` gets called, and the output format is
// the default table view, this gets used to print a pretty table.
///////////////////////////////////////////////////////////////////////////////

impl ToTable for MeasurementBundle {
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
        table.add_row(prettytable::row!["bundle_id", self.bundle_id]);
        table.add_row(prettytable::row!["profile_id", self.profile_id]);
        table.add_row(prettytable::row!["name", self.name]);
        table.add_row(prettytable::row!["state", self.state]);
        table.add_row(prettytable::row!["created_ts", self.ts]);
        table.add_row(prettytable::row!["values", values_table]);
        Ok(table.to_string())
    }
}

///////////////////////////////////////////////////////////////////////////////
// When `bundle show` gets called (for all entries), and the output format
// is the default table view, this gets used to print a pretty table.
///////////////////////////////////////////////////////////////////////////////

impl ToTable for Vec<MeasurementBundle> {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["bundle_id", "details", "values"]);
        for bundle in self.iter() {
            let mut details_table = prettytable::Table::new();
            details_table.add_row(prettytable::row!["profile_id", bundle.profile_id]);
            details_table.add_row(prettytable::row!["name", bundle.name]);
            details_table.add_row(prettytable::row!["state", bundle.state]);
            details_table.add_row(prettytable::row!["created_ts", bundle.ts]);
            let mut values_table = prettytable::Table::new();
            values_table.add_row(prettytable::row!["pcr_register", "value"]);
            for value_record in bundle.values.iter() {
                values_table.add_row(prettytable::row![
                    value_record.pcr_register,
                    value_record.sha256
                ]);
            }
            table.add_row(prettytable::row![
                bundle.bundle_id,
                details_table,
                values_table
            ]);
        }
        Ok(table.to_string())
    }
}

///////////////////////////////////////////////////////////////////////////////
/// match_bundle takes a map of k/v pairs and returns a singular matching
/// bundle ID based on the exact k/v pairs and the number of pairs, should
/// one exist.
///
/// The code is written as such to only allow one bundle to match, so if two
/// matching bundles end up matching, it's because someone was messing around
/// in the tables (or there's a bug).
///////////////////////////////////////////////////////////////////////////////

async fn match_bundle(
    txn: &mut Transaction<'_, Postgres>,
    profile_id: MeasurementSystemProfileId,
    values: &[common::PcrRegisterValue],
) -> eyre::Result<Option<MeasurementBundleId>> {
    // NOTE(chet): Here is a story!
    //
    // Just for reference, when there was a fixed set of values throughout
    // the codebase (e.g. PCR_VALUE_LENGTH was fixed at 7), this function
    // used to be as simple as the single line of code below. But, once it
    // was decided that the client could send a variable journal size, and
    // that an operator could approve which values to pull into a bundle,
    // it became slightly more complex, since then it went from matching a
    // journal -> bundle to finding bundles which intersected with the
    // provided journal.
    //
    // Ok(get_measurement_bundle_ids_by_values(txn, values).await?)
    //
    // The reason is I could just do where values in ((0,v1), (1,v2), ...),
    // and know there was always a distinct match against 7 values, easy
    // peasy. It's not like that anymore, and that's ok, but it does result
    // in a little more code.

    // Get all bundles, and figure out which *active* bundles intersect
    // with the provided journal. After that, we'll attempt to find the
    // most specific match (if there are multiple matches).
    let mut all_bundles = MeasurementBundle::get_all_for_profile_id(txn, profile_id).await?;

    // TODO(chet): This could be moved somewhere more formal.
    let allowed_states = [
        MeasurementBundleState::Active,
        MeasurementBundleState::Obsolete,
    ];

    let mut matching: Vec<MeasurementBundle> = Vec::new();
    for bundle in all_bundles.drain(..) {
        if allowed_states.contains(&bundle.state) && bundle.intersects(values)? {
            matching.push(bundle);
        }
    }

    // If there are no matching bundles, or a single matching
    // bundle, it's simple to handle here.
    if matching.is_empty() {
        return Ok(None);
    } else if matching.len() == 1 {
        return Ok(Some(matching[0].bundle_id));
    }

    // Otherwise, sort by the number of bundle values
    // in the bundle, and return the most specific bundle
    // match (as in, the most unique values, if there is
    // one). If there's a conflict, then return an error.
    matching.sort_by(|a, b| b.values.len().cmp(&a.values.len()));
    if matching[0].values.len() == matching[1].values.len() {
        return Err(eyre::eyre!("cannot determine most specific bundle match"));
    }

    Ok(Some(matching[0].bundle_id))
}
