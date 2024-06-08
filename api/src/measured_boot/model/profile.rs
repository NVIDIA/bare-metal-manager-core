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
 *  Code for working the measurement_system_profiles and measurement_system_profiles_attrs
 *  tables in the database, leveraging the profile-specific record types.
*/

use crate::measured_boot::dto::keys::MeasurementSystemProfileId;
use crate::measured_boot::dto::records::{
    MeasurementSystemProfileAttrRecord, MeasurementSystemProfileRecord,
};
use crate::measured_boot::interface::common;
use crate::measured_boot::interface::common::ToTable;
use crate::measured_boot::interface::profile::{
    delete_profile_attr_records_for_id, delete_profile_record_for_id,
    get_all_measurement_profile_records, get_measurement_profile_attrs_for_profile_id,
    get_measurement_profile_record_by_attrs, get_measurement_profile_record_by_id,
    get_measurement_profile_record_by_name, insert_measurement_profile_attr_records,
    insert_measurement_profile_record, rename_profile_for_profile_id,
    rename_profile_for_profile_name,
};
use chrono::{DateTime, Utc};
use rpc::protos::measured_boot::MeasurementSystemProfilePb;
use serde::Serialize;
// use sqlx::types::chrono::Utc;
use sqlx::{Pool, Postgres, Transaction};
use std::collections::HashMap;
use std::convert::{Into, TryFrom};

///////////////////////////////////////////////////////////////////////////////
/// MeasurementSystemProfile is a composition of a MeasurementSystemProfileRecord,
/// whose attributes are essentially copied directly it, as well as
/// the associated attributes (which are complete instances of
/// MeasurementSystemProfileAttrRecord, along with its UUID and timestamp).
///
/// Included are ToTable implementations, which are used by the CLI for
/// doing prettytable-formatted output.
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Serialize)]
pub struct MeasurementSystemProfile {
    pub profile_id: MeasurementSystemProfileId,
    pub name: String,
    pub ts: chrono::DateTime<Utc>,
    pub attrs: Vec<MeasurementSystemProfileAttrRecord>,
}

impl From<MeasurementSystemProfile> for MeasurementSystemProfilePb {
    fn from(val: MeasurementSystemProfile) -> Self {
        Self {
            profile_id: Some(val.profile_id.into()),
            name: val.name,
            ts: Some(val.ts.into()),
            attrs: val.attrs.iter().map(|attr| attr.clone().into()).collect(),
        }
    }
}

impl TryFrom<MeasurementSystemProfilePb> for MeasurementSystemProfile {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: MeasurementSystemProfilePb) -> Result<Self, Box<dyn std::error::Error>> {
        let attrs: eyre::Result<Vec<MeasurementSystemProfileAttrRecord>> = msg
            .attrs
            .iter()
            .map(
                |attr| match MeasurementSystemProfileAttrRecord::try_from(attr.clone()) {
                    Ok(worked) => Ok(worked),
                    Err(failed) => Err(eyre::eyre!("attr conversion failed: {}", failed)),
                },
            )
            .collect();

        Ok(Self {
            profile_id: MeasurementSystemProfileId::try_from(msg.profile_id)?,
            name: msg.name.clone(),
            attrs: attrs?,
            ts: DateTime::<Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

impl MeasurementSystemProfile {
    ////////////////////////////////////////////////////////////////
    /// new creates a new MeasurementSystemProfile in the database,
    /// if it doesn't exist, populating the corresponding table(s),
    /// and returning the newly-inserted data.
    ////////////////////////////////////////////////////////////////
    pub async fn new(
        db_conn: &Pool<Postgres>,
        name: Option<String>,
        attrs: &HashMap<String, String>,
    ) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        let profile = Self::new_with_txn(&mut txn, name, attrs).await?;
        txn.commit().await?;
        Ok(profile)
    }

    pub async fn new_with_txn(
        txn: &mut Transaction<'_, Postgres>,
        name: Option<String>,
        attrs: &HashMap<String, String>,
    ) -> eyre::Result<Self> {
        let profile_name = match name {
            Some(name) => name,
            None => common::generate_name()?,
        };
        create_measurement_profile(txn, profile_name, attrs).await
    }

    /// from_info_and_attrs creates a new system profile
    /// from the base record and its values.
    pub fn from_info_and_attrs(
        info: MeasurementSystemProfileRecord,
        attrs: Vec<MeasurementSystemProfileAttrRecord>,
    ) -> eyre::Result<Self> {
        Ok(Self {
            profile_id: info.profile_id,
            name: info.name,
            ts: info.ts,
            attrs,
        })
    }

    ////////////////////////////////////////////////////////////
    /// from_grpc takes an optional protobuf (as populated in a
    /// proto response from the API) and attempts to convert it
    /// to the backing model.
    ////////////////////////////////////////////////////////////

    pub fn from_grpc(some_pb: Option<&MeasurementSystemProfilePb>) -> eyre::Result<Self> {
        some_pb
            .ok_or(eyre::eyre!("profile is unexpectedly empty"))
            .and_then(|pb| {
                Self::try_from(pb.clone())
                    .map_err(|e| eyre::eyre!("profile failed pb->model conversion: {}", e))
            })
    }

    ////////////////////////////////////////////////////////////////
    /// match_from_attrs_or_new attempts to match the attrs to the
    /// closest profile, and, should none exist, will create a new
    /// profile with the provided attrs.
    ////////////////////////////////////////////////////////////////

    pub async fn match_from_attrs_or_new(
        db_conn: &Pool<Postgres>,
        attrs: &HashMap<String, String>,
    ) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        let profile = Self::match_from_attrs_or_new_with_txn(&mut txn, attrs).await?;
        txn.commit().await?;
        Ok(profile)
    }

    pub async fn match_from_attrs_or_new_with_txn(
        txn: &mut Transaction<'_, Postgres>,
        attrs: &HashMap<String, String>,
    ) -> eyre::Result<Self> {
        match match_profile(txn, attrs).await? {
            Some(profile_id) => {
                Ok(MeasurementSystemProfile::load_from_id_with_txn(txn, profile_id).await?)
            }
            None => Ok(MeasurementSystemProfile::new_with_txn(txn, None, attrs).await?),
        }
    }

    pub async fn match_from_attrs(
        txn: &mut Transaction<'_, Postgres>,
        attrs: &HashMap<String, String>,
    ) -> eyre::Result<Option<Self>> {
        match match_profile(txn, attrs).await? {
            Some(info) => Ok(Some(
                MeasurementSystemProfile::load_from_id_with_txn(txn, info).await?,
            )),
            None => Ok(None),
        }
    }

    ////////////////////////////////////////////////////////////////
    /// load_from_attrs_or_new loads an existing measurement profile
    /// (and its attributes), or creates a new one should they not
    /// exist. In both cases it returns a MeasurementSystemProfile.
    ///
    /// This is used specifically as part of machine attestation,
    /// where, if a matching profile cannot be found for the
    /// provided machine attributes, a new one is automatically
    /// created and assigned. This allows for ease of dynamically
    /// adjusting how profiles are defined, with subsequent calls
    /// to create bundles following suit.
    ////////////////////////////////////////////////////////////////
    pub async fn load_from_attrs_or_new(
        db_conn: &Pool<Postgres>,
        attrs: &HashMap<String, String>,
    ) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        match MeasurementSystemProfile::load_from_attrs(&mut txn, attrs).await? {
            Some(info) => Ok(info),
            None => Ok(MeasurementSystemProfile::new(db_conn, None, attrs).await?),
        }
    }

    ////////////////////////////////////////////////////////////////
    /// load_from_id loads an existing measurement profile (and its
    /// attributes), returning a MeasurementSystemProfile instance.
    ////////////////////////////////////////////////////////////////
    pub async fn load_from_id(
        db_conn: &Pool<Postgres>,
        profile_id: MeasurementSystemProfileId,
    ) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        Self::load_from_id_with_txn(&mut txn, profile_id).await
    }

    pub async fn load_from_id_with_txn(
        txn: &mut Transaction<'_, Postgres>,
        profile_id: MeasurementSystemProfileId,
    ) -> eyre::Result<Self> {
        get_measurement_profile_by_id(txn, profile_id).await
    }

    ////////////////////////////////////////////////////////////////
    /// load_from_name loads an existing measurement profile (and its
    /// attributes), returning a MeasurementSystemProfile instance.
    ////////////////////////////////////////////////////////////////
    pub async fn load_from_name(db_conn: &Pool<Postgres>, name: String) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        get_measurement_profile_by_name(&mut txn, name).await
    }

    ////////////////////////////////////////////////////////////////
    /// load_from_attrs loads an existing measurement profile (and
    /// its attributes), returning a MeasurementSystemProfile instance.
    ////////////////////////////////////////////////////////////////
    pub async fn load_from_attrs(
        txn: &mut Transaction<'_, Postgres>,
        attrs: &HashMap<String, String>,
    ) -> eyre::Result<Option<Self>> {
        let info = get_measurement_profile_record_by_attrs(txn, attrs).await?;
        match info {
            Some(info) => {
                let attrs =
                    get_measurement_profile_attrs_for_profile_id(txn, info.profile_id).await?;
                Ok(Some(Self {
                    profile_id: info.profile_id,
                    name: info.name,
                    ts: info.ts,
                    attrs,
                }))
            }
            None => Ok(None),
        }
    }

    ////////////////////////////////////////////////////////////////
    /// intersects_with is used to check if the current
    /// MeasurementSystemProfile intersects with the provided attrs.
    ////////////////////////////////////////////////////////////////
    pub fn intersects_with(&self, machine_attrs: &HashMap<String, String>) -> eyre::Result<bool> {
        if self.attrs.len() > machine_attrs.len() {
            return Ok(false);
        }
        Ok(self.attrs.iter().all(|record| {
            if let Some(machine_attr_value) = machine_attrs.get(&record.key) {
                machine_attr_value == &record.value
            } else {
                false
            }
        }))
    }

    ////////////////////////////////////////////////////////////////
    /// intersects_from is used to check if the provided input
    /// attrs intersect with the current profile.
    ////////////////////////////////////////////////////////////////
    pub fn intersects_from(&self, machine_attrs: &HashMap<String, String>) -> eyre::Result<bool> {
        if machine_attrs.len() > self.attrs.len() {
            return Ok(false);
        }
        let profile_attrs_map = profile_attr_records_to_map(&self.attrs)?;
        Ok(machine_attrs
            .iter()
            .all(|(machine_attr_key, machine_attr_value)| {
                if let Some(profile_attr_value) = profile_attrs_map.get(machine_attr_key) {
                    profile_attr_value == machine_attr_value
                } else {
                    false
                }
            }))
    }

    pub async fn delete_for_id(
        db_conn: &Pool<Postgres>,
        profile_id: MeasurementSystemProfileId,
    ) -> eyre::Result<Option<MeasurementSystemProfile>> {
        delete_profile_for_id(db_conn, profile_id).await
    }

    pub async fn delete_for_name(
        db_conn: &Pool<Postgres>,
        name: String,
    ) -> eyre::Result<Option<MeasurementSystemProfile>> {
        delete_profile_for_name(db_conn, name).await
    }

    /// rename_for_id renames a MeasurementSystemProfile based on its ID.
    pub async fn rename_for_id(
        txn: &mut Transaction<'_, Postgres>,
        system_profile_id: MeasurementSystemProfileId,
        new_system_profile_name: String,
    ) -> eyre::Result<Self> {
        MeasurementSystemProfile::from_info_and_attrs(
            rename_profile_for_profile_id(txn, system_profile_id, new_system_profile_name.clone())
                .await?,
            get_measurement_profile_attrs_for_profile_id(txn, system_profile_id).await?,
        )
    }

    /// rename_for_name renames a MeasurementSystemProfile based on its name.
    pub async fn rename_for_name(
        txn: &mut Transaction<'_, Postgres>,
        system_profile_name: String,
        new_system_profile_name: String,
    ) -> eyre::Result<Self> {
        let info = rename_profile_for_profile_name(
            txn,
            system_profile_name.clone(),
            new_system_profile_name.clone(),
        )
        .await?;
        let attrs = get_measurement_profile_attrs_for_profile_id(txn, info.profile_id).await?;
        MeasurementSystemProfile::from_info_and_attrs(info, attrs)
    }

    pub async fn get_all(db_conn: &Pool<Postgres>) -> eyre::Result<Vec<MeasurementSystemProfile>> {
        get_measurement_system_profiles(db_conn).await
    }
}

///////////////////////////////////////////////////////////////////////////////
// When `profile show <profile-id>` gets called, and the output format is
// the default table view, this gets used to print a pretty table.
///////////////////////////////////////////////////////////////////////////////

impl ToTable for MeasurementSystemProfile {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        let mut attrs_table = prettytable::Table::new();
        attrs_table.add_row(prettytable::row!["name", "value"]);
        for attr_record in self.attrs.iter() {
            attrs_table.add_row(prettytable::row![attr_record.key, attr_record.value]);
        }
        table.add_row(prettytable::row!["profile_id", self.profile_id]);
        table.add_row(prettytable::row!["name", self.name]);
        table.add_row(prettytable::row!["created_ts", self.ts]);
        table.add_row(prettytable::row!["attrs", attrs_table]);
        Ok(table.to_string())
    }
}

///////////////////////////////////////////////////////////////////////////////
// When `profile show` gets called (for all entries), and the output format
// is the default table view, this gets used to print a pretty table.
///////////////////////////////////////////////////////////////////////////////

impl ToTable for Vec<MeasurementSystemProfile> {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row![
            "profile_id",
            "name",
            "created_ts",
            "attributes"
        ]);
        for profile in self.iter() {
            let mut attrs_table = prettytable::Table::new();
            attrs_table.add_row(prettytable::row!["name", "value"]);
            for attr_record in profile.attrs.iter() {
                attrs_table.add_row(prettytable::row![attr_record.key, attr_record.value]);
            }
            table.add_row(prettytable::row![
                profile.profile_id,
                profile.name,
                profile.ts,
                attrs_table
            ]);
        }
        Ok(table.to_string())
    }
}

///////////////////////////////////////////////////////////////////////////////
/// profile_attr_records_to_map turns the vector of
/// MeasurementSystemProfileAttrRecord into a hashmap of strings.
///////////////////////////////////////////////////////////////////////////////

pub fn profile_attr_records_to_map(
    values: &[MeasurementSystemProfileAttrRecord],
) -> eyre::Result<HashMap<String, String>> {
    let total_values = values.len();
    let value_map: HashMap<String, String> = values
        .iter()
        .map(|rec| (rec.key.clone(), rec.value.clone()))
        .collect();
    if total_values != value_map.len() {
        return Err(eyre::eyre!(
            "detected key name collision in input attribute list"
        ));
    }
    Ok(value_map)
}

///////////////////////////////////////////////////////////////////////////////
/// match_profile takes a map of k/v pairs and returns a singular matching
/// profile based on the exact k/v pairs and the number of pairs, should
/// one exist.
///
/// The code is written as such to only allow one profile with the same set
/// of attributes, so if two matching profiles end up existing, it's because
/// someone was messing around in the tables (or there's a bug).
///////////////////////////////////////////////////////////////////////////////

async fn match_profile(
    txn: &mut Transaction<'_, Postgres>,
    attrs: &HashMap<String, String>,
) -> eyre::Result<Option<MeasurementSystemProfileId>> {
    // Get all profiles, and figure out which one intersects
    // with the provided attrs. After that, we'll attempt to find the
    // most specific match (if there are multiple matches).
    let mut all_profiles = get_measurement_system_profiles_with_txn(txn).await?;

    let match_attempts: eyre::Result<Vec<MeasurementSystemProfile>> = all_profiles
        .drain(..)
        .filter_map(|profile| match profile.intersects_with(attrs) {
            Ok(true) => Some(Ok(profile)),
            Ok(false) => None,
            Err(e) => Some(Err(e)),
        })
        .collect();

    let mut matching = match match_attempts {
        Ok(matched) => matched,
        Err(e) => return Err(e),
    };

    // If there are no matching bundles, or a single matching
    // bundle, it's simple to handle here.
    if matching.is_empty() {
        return Ok(None);
    } else if matching.len() == 1 {
        return Ok(Some(matching[0].profile_id));
    }

    // Otherwise, sort by the number of bundle values
    // in the bundle, and return the most specific bundle
    // match (as in, the most unique values, if there is
    // one). If there's a conflict, then return an error.
    matching.sort_by(|a, b| b.attrs.len().cmp(&a.attrs.len()));
    if matching[0].attrs.len() == matching[1].attrs.len() {
        return Err(eyre::eyre!("cannot determine most specific profile match"));
    }

    Ok(Some(matching[0].profile_id))
}

///////////////////////////////////////////////////////////////////////////////
/// create_measurement_profile creates a new measurement profile
/// and corresponding measurement profile attributes. The transaction
/// is created here, and is used for corresponding insert statements
/// into both the measurement_system_profiles and measurement_system_profiles_attrs
/// tables.
///////////////////////////////////////////////////////////////////////////////

pub async fn create_measurement_profile(
    txn: &mut Transaction<'_, Postgres>,
    name: String,
    attrs: &HashMap<String, String>,
) -> eyre::Result<MeasurementSystemProfile> {
    if let Some(existing) = MeasurementSystemProfile::load_from_attrs(txn, attrs).await? {
        return Err(eyre::eyre!(
            "profile with attrs already exists: {:?}",
            existing
        ));
    }

    let info = insert_measurement_profile_record(txn, name).await?;
    let attrs = insert_measurement_profile_attr_records(txn, info.profile_id, attrs).await?;
    Ok(MeasurementSystemProfile {
        profile_id: info.profile_id,
        name: info.name,
        ts: info.ts,
        attrs,
    })
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_profile_by_id returns a MeasurementSystemProfile
/// for the given MeasurementSystemProfileId.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_profile_by_id(
    txn: &mut Transaction<'_, Postgres>,
    profile_id: MeasurementSystemProfileId,
) -> eyre::Result<MeasurementSystemProfile> {
    match get_measurement_profile_record_by_id(txn, profile_id).await? {
        Some(info) => {
            let attrs = get_measurement_profile_attrs_for_profile_id(txn, info.profile_id).await?;
            Ok(MeasurementSystemProfile {
                profile_id: info.profile_id,
                name: info.name,
                ts: info.ts,
                attrs,
            })
        }
        None => Err(eyre::eyre!("no profile found with that ID")),
    }
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_profile_by_name returns a MeasurementSystemProfile
/// for the given name.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_profile_by_name(
    txn: &mut Transaction<'_, Postgres>,
    name: String,
) -> eyre::Result<MeasurementSystemProfile> {
    match get_measurement_profile_record_by_name(txn, name).await? {
        Some(info) => {
            let attrs = get_measurement_profile_attrs_for_profile_id(txn, info.profile_id).await?;
            Ok(MeasurementSystemProfile {
                profile_id: info.profile_id,
                name: info.name,
                ts: info.ts,
                attrs,
            })
        }
        None => Err(eyre::eyre!("no profile found with that name")),
    }
}

///////////////////////////////////////////////////////////////////////////////
/// delete_profile_for_id deletes a complete profile, including
/// its attributes, by ID. It returns the deleted profile for display.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete_profile_for_id(
    db_conn: &Pool<Postgres>,
    profile_id: MeasurementSystemProfileId,
) -> eyre::Result<Option<MeasurementSystemProfile>> {
    let mut txn = db_conn.begin().await?;
    let attrs = delete_profile_attr_records_for_id(&mut txn, profile_id).await?;
    match delete_profile_record_for_id(&mut txn, profile_id).await? {
        Some(info) => {
            txn.commit().await?;
            Ok(Some(MeasurementSystemProfile {
                name: info.name,
                profile_id: info.profile_id,
                ts: info.ts,
                attrs,
            }))
        }
        None => Ok(None),
    }
}

///////////////////////////////////////////////////////////////////////////////
/// delete_profile_for_name deletes a complete profile, including
/// its attributes, by name. It returns the deleted profile for display.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete_profile_for_name(
    db_conn: &Pool<Postgres>,
    name: String,
) -> eyre::Result<Option<MeasurementSystemProfile>> {
    let profile = MeasurementSystemProfile::load_from_name(db_conn, name).await?;
    delete_profile_for_id(db_conn, profile.profile_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_system_profiles returns all MeasurementSystemProfile
/// instances in the database.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_system_profiles(
    db_conn: &Pool<Postgres>,
) -> eyre::Result<Vec<MeasurementSystemProfile>> {
    let mut txn = db_conn.begin().await?;
    get_measurement_system_profiles_with_txn(&mut txn).await
}

pub async fn get_measurement_system_profiles_with_txn(
    txn: &mut Transaction<'_, Postgres>,
) -> eyre::Result<Vec<MeasurementSystemProfile>> {
    let mut res: Vec<MeasurementSystemProfile> = Vec::new();
    let mut infos = get_all_measurement_profile_records(txn).await?;
    for info in infos.drain(..) {
        let attrs = get_measurement_profile_attrs_for_profile_id(txn, info.profile_id).await?;
        res.push(MeasurementSystemProfile {
            profile_id: info.profile_id,
            name: info.name,
            ts: info.ts,
            attrs,
        });
    }
    Ok(res)
}
