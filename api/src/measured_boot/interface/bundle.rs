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

use crate::measured_boot::dto::keys::{
    MeasurementBundleId, MeasurementSystemProfileId, MockMachineId,
};
use crate::measured_boot::dto::records::{
    MeasurementBundleRecord, MeasurementBundleState, MeasurementBundleStateRecord,
    MeasurementBundleValueRecord, MeasurementReportRecord,
};
use crate::measured_boot::dto::traits::{DbPrimaryUuid, DbTable};
use crate::measured_boot::interface::common;
use sqlx::{Pool, Postgres, Transaction};

///////////////////////////////////////////////////////////////////////////////
/// insert_measurement_bundle_record is a very basic insert of a
/// new row into the measurement_bundles table, where only a profile_id
/// needs to be provided. Is it expected that this is wrapped by
/// a more formal call (where a transaction is initialized).
///////////////////////////////////////////////////////////////////////////////

pub async fn insert_measurement_bundle_record(
    txn: &mut Transaction<'_, Postgres>,
    profile_id: MeasurementSystemProfileId,
    name: String,
    state: Option<MeasurementBundleState>,
) -> eyre::Result<MeasurementBundleRecord> {
    let bundle = match state {
        Some(set_state) => {
            let query = "insert into measurement_bundles(profile_id, name, state) values($1, $2, $3) returning *";
            sqlx::query_as::<_, MeasurementBundleRecord>(query)
                .bind(profile_id)
                .bind(name.clone())
                .bind(set_state)
                .fetch_one(&mut **txn)
                .await
        }
        None => {
            let query =
                "insert into measurement_bundles(profile_id, name) values($1, $2) returning *";
            sqlx::query_as::<_, MeasurementBundleRecord>(query)
                .bind(profile_id)
                .bind(name.clone())
                .fetch_one(&mut **txn)
                .await
        }
    }.map_err(|sqlx_err| {
        let is_db_err = sqlx_err.as_database_error();
        match is_db_err {
            Some(db_err) => match db_err.kind() {
                sqlx::error::ErrorKind::UniqueViolation => {
                    eyre::eyre!("bundle already exists: {} (msg: {})", name.clone(), db_err)
                }
                sqlx::error::ErrorKind::NotNullViolation => {
                    eyre::eyre!(
                        "bundle missing required value: {} (msg: {})",
                        name.clone(),
                        db_err
                    )
                }
                _ => {
                    eyre::eyre!(
                        "db error creating bundle record: {} (msg: {})",
                        name.clone(),
                        db_err
                    )
                }
            },
            None => eyre::eyre!(
                "general error creating bundle record: {} (msg: {})",
                name.clone(),
                sqlx_err
            ),
        }
    })?;

    Ok(bundle)
}

///////////////////////////////////////////////////////////////////////////////
/// insert_measurement_values takes a vec of PcrRegisterValues and
/// subsequently calls an individual insert for each. It is assumed this is
/// called by a parent wrapper where a transaction was created.
///////////////////////////////////////////////////////////////////////////////

pub async fn insert_measurement_bundle_value_records(
    txn: &mut Transaction<'_, Postgres>,
    bundle_id: MeasurementBundleId,
    values: &[common::PcrRegisterValue],
) -> eyre::Result<Vec<MeasurementBundleValueRecord>> {
    let mut records: Vec<MeasurementBundleValueRecord> = Vec::new();
    for value in values.iter() {
        records.push(
            insert_measurement_bundle_value_record(
                txn,
                bundle_id,
                value.pcr_register,
                &value.sha256,
            )
            .await?,
        );
    }
    Ok(records)
}

///////////////////////////////////////////////////////////////////////////////
/// insert_measurement_value inserts a single bundle value, returning the
/// complete inserted record, which includes its new UUID and insert timestamp.
///////////////////////////////////////////////////////////////////////////////

pub async fn insert_measurement_bundle_value_record(
    txn: &mut Transaction<'_, Postgres>,
    bundle_id: MeasurementBundleId,
    pcr_register: i16,
    value: &String,
) -> eyre::Result<MeasurementBundleValueRecord> {
    let query = "insert into measurement_bundles_values(bundle_id, pcr_register, sha256) values($1, $2, $3) returning *";

    Ok(sqlx::query_as::<_, MeasurementBundleValueRecord>(query)
        .bind(bundle_id)
        .bind(pcr_register)
        .bind(value)
        .fetch_one(&mut **txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// rename_bundle_for_bundle_id renames a bundle based on its bundle ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn rename_bundle_for_bundle_id(
    txn: &mut Transaction<'_, Postgres>,
    bundle_id: MeasurementBundleId,
    new_bundle_name: String,
) -> eyre::Result<MeasurementBundleRecord> {
    let query = format!(
        "update {} set name = $1 where {} = $2 returning *",
        MeasurementBundleRecord::db_table_name(),
        MeasurementBundleId::db_primary_uuid_name()
    );

    Ok(sqlx::query_as::<_, MeasurementBundleRecord>(&query)
        .bind(new_bundle_name)
        .bind(bundle_id)
        .fetch_one(&mut **txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// rename_bundle_for_bundle_name renames a bundle based on its bundle name.
///////////////////////////////////////////////////////////////////////////////

pub async fn rename_bundle_for_bundle_name(
    txn: &mut Transaction<'_, Postgres>,
    old_bundle_name: String,
    new_bundle_name: String,
) -> eyre::Result<MeasurementBundleRecord> {
    let query = format!(
        "update {} set name = $1 where name = $2 returning *",
        MeasurementBundleRecord::db_table_name(),
    );

    Ok(sqlx::query_as::<_, MeasurementBundleRecord>(&query)
        .bind(new_bundle_name)
        .bind(old_bundle_name)
        .fetch_one(&mut **txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// set_state_for_bundle_id sets a new state for a given bundle ID.
///
/// This is the last line of defense to make sure a bundle cant move
/// out of the revoked state. This might be able to move up to the
/// model layer, but putting it here seems good.
///
/// NOTE(chet): There may come a time when we want to introduce a `force`
/// boolean to force out of revoked, but lets see what mileage we can get
/// from this first.
///////////////////////////////////////////////////////////////////////////////

pub async fn set_state_for_bundle_id(
    txn: &mut Transaction<'_, Postgres>,
    bundle_id: MeasurementBundleId,
    state: MeasurementBundleState,
) -> eyre::Result<MeasurementBundleRecord> {
    // Attempt to do a single query to update the state. If no results
    // are returned, its because it was either already set to revoked,
    // or because the bundle ID doesn't exist -- do the subsequent
    // query then.
    let query = format!(
        "update {} set state = $1 where bundle_id = $2 and state != $3 returning *",
        MeasurementBundleRecord::db_table_name()
    );

    let updated_bundle_record = sqlx::query_as::<_, MeasurementBundleRecord>(&query)
        .bind(state)
        .bind(bundle_id)
        .bind(MeasurementBundleState::Revoked)
        .fetch_optional(&mut **txn)
        .await?;

    match updated_bundle_record {
        // Got a record back, which means the state was successfully
        // updated, so return it.
        Some(record) => Ok(record),

        // Didn't get one back, which means something happened, as in
        // either the bundle didn't exist, or the state is set to
        // revoked. If it's neither of those cases, that's fun.
        None => match get_measurement_bundle_by_id(txn, bundle_id).await? {
            None => Err(eyre::eyre!("bundle does not exist: {}", bundle_id)),
            Some(existing_bundle) => {
                if existing_bundle.state == MeasurementBundleState::Revoked {
                    Err(eyre::eyre!(
                        "bundle cannot be moved from revoked state: {}",
                        bundle_id
                    ))
                } else {
                    Err(eyre::eyre!(
                        "totally unknown reason why this happened for bundle: {}",
                        bundle_id
                    ))
                }
            }
        },
    }
}

///////////////////////////////////////////////////////////////////////////////
/// get_state_for_bundle_id gets the state for a given bundle ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_state_for_bundle_id(
    txn: &mut Transaction<'_, Postgres>,
    bundle_id: MeasurementBundleId,
) -> eyre::Result<MeasurementBundleState> {
    let query = format!(
        "select state from {} where bundle_id = $1",
        MeasurementBundleRecord::db_table_name()
    );
    let record = sqlx::query_as::<_, MeasurementBundleStateRecord>(&query)
        .bind(bundle_id)
        .fetch_one(&mut **txn)
        .await?;
    Ok(record.state)
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_bundle_by_id returns a populated MeasurementBundleRecord
/// for the given `bundle_id`, if it exists. This leverages the generic
/// get_object_for_id function since its a simple/common pattern.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_bundle_by_id(
    txn: &mut Transaction<'_, Postgres>,
    bundle_id: MeasurementBundleId,
) -> eyre::Result<Option<MeasurementBundleRecord>> {
    common::get_object_for_id(txn, bundle_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_bundle_for_name returns a populated MeasurementBundleRecord
/// for the given `bundle_name`, if it exists. This leverages the generic
/// get_object_for_id function since its a simple/common pattern.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_bundle_for_name(
    txn: &mut Transaction<'_, Postgres>,
    bundle_name: String,
) -> eyre::Result<Option<MeasurementBundleRecord>> {
    common::get_object_for_unique_column(txn, "name", bundle_name.clone()).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_bundle_records returns all MeasurementBundleRecord
/// instances in the database. This leverages the generic get_all_objects
/// function since its a simple/common pattern.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_bundle_records(
    db_conn: &Pool<Postgres>,
) -> eyre::Result<Vec<MeasurementBundleRecord>> {
    let mut txn = db_conn.begin().await?;
    common::get_all_objects(&mut txn).await
}

pub async fn get_measurement_bundle_records_with_txn(
    txn: &mut Transaction<'_, Postgres>,
) -> eyre::Result<Vec<MeasurementBundleRecord>> {
    common::get_all_objects(txn).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_bundle_records_for_profile_id returns all
/// MeasurementBundleRecord instances in the database with the given profile
/// ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_bundle_records_for_profile_id(
    txn: &mut Transaction<'_, Postgres>,
    profile_id: MeasurementSystemProfileId,
) -> eyre::Result<Vec<MeasurementBundleRecord>> {
    common::get_objects_where_id(txn, profile_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_bundles_values returns all MeasurementBundleValueRecord
/// instances in the database. This leverages the generic get_all_objects
/// function since its a simple/common pattern.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_bundles_values(
    db_conn: &Pool<Postgres>,
) -> eyre::Result<Vec<MeasurementBundleValueRecord>> {
    let mut txn = db_conn.begin().await?;
    common::get_all_objects(&mut txn).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_bundle_values_for_bundle_id returns
/// all of the measurement values associated with a given
/// `bundle_id`, where there should be PCR_VALUE_LENGTH
/// values returned. This call leverages the generic
/// get_objects_where_id, allowing a caller to get a list
/// of multiple objects matching a given PgUuid, where
/// the PgUuid is probably a reference/foreign key.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_bundle_values_for_bundle_id(
    txn: &mut Transaction<'_, Postgres>,
    bundle_id: MeasurementBundleId,
) -> eyre::Result<Vec<MeasurementBundleValueRecord>> {
    common::get_objects_where_id(txn, bundle_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_bundle_by_values returns a bundle
/// whose values match the input values.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_bundle_ids_by_values(
    txn: &mut Transaction<'_, Postgres>,
    values: &[common::PcrRegisterValue],
) -> eyre::Result<Vec<MeasurementBundleId>> {
    common::get_ids_for_bundle_values(txn, "measurement_bundles_values", values).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_journals_for_bundle_id returns all measurement journal
/// records that are associated with the given bundle ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_journals_for_bundle_id(
    txn: &mut Transaction<'_, Postgres>,
    bundle_id: MeasurementBundleId,
) -> eyre::Result<Vec<MeasurementReportRecord>> {
    common::get_objects_where_id(txn, bundle_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_machines_for_bundle_id returns a unique list of
/// all MockMachineId that leverage the given bundle.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_machines_for_bundle_id(
    db_conn: &Pool<Postgres>,
    bundle_id: MeasurementBundleId,
) -> eyre::Result<Vec<MockMachineId>> {
    let mut txn = db_conn.begin().await?;
    let query = "select distinct machine_id from measurement_journal where bundle_id = $1 order by machine_id";
    Ok(sqlx::query_as::<_, MockMachineId>(query)
        .bind(bundle_id)
        .fetch_all(&mut *txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// get_machines_for_bundle_name returns a unique list of all MockMachineId
/// that leverage the given profile.
///
/// This is specifically used by the `bundle list machines by-name` CLI call.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_machines_for_bundle_name(
    db_conn: &Pool<Postgres>,
    bundle_name: String,
) -> eyre::Result<Vec<MockMachineId>> {
    let mut txn = db_conn.begin().await?;
    let query =
        "select distinct machine_id from measurement_journal,measurement_bundles where measurement_journal.bundle_id=measurement_bundles.bundle_id and measurement_bundles.name = $1 order by machine_id";
    Ok(sqlx::query_as::<_, MockMachineId>(query)
        .bind(bundle_name)
        .fetch_all(&mut *txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// delete_bundle_for_id deletes a bundle record.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete_bundle_for_id(
    txn: &mut Transaction<'_, Postgres>,
    bundle_id: MeasurementBundleId,
) -> eyre::Result<MeasurementBundleRecord> {
    let record: Option<MeasurementBundleRecord> =
        common::delete_object_where_id(txn, bundle_id).await?;
    match record {
        Some(record) => Ok(record),
        None => Err(eyre::eyre!("could not find bundle for ID")),
    }
}

///////////////////////////////////////////////////////////////////////////////
/// delete_bundle_values_for_id deletes all bundle
/// value records for a bundle.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete_bundle_values_for_id(
    txn: &mut Transaction<'_, Postgres>,
    bundle_id: MeasurementBundleId,
) -> eyre::Result<Vec<MeasurementBundleValueRecord>> {
    common::delete_objects_where_id(txn, bundle_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// import_measurement_bundles is intended for doing "full site" imports,
/// taking a list of all measurement bundle records from one site, and
/// inserting them verbatim in another.
///
/// This should happen before import_measurement_bundles_values, since the
/// parent bundles must exist first.
///////////////////////////////////////////////////////////////////////////////

pub async fn import_measurement_bundles(
    txn: &mut Transaction<'_, Postgres>,
    bundles: &[MeasurementBundleRecord],
) -> eyre::Result<Vec<MeasurementBundleRecord>> {
    let mut committed = Vec::<MeasurementBundleRecord>::new();
    for bundle in bundles.iter() {
        committed.push(import_measurement_bundle(&mut *txn, bundle).await?);
    }
    Ok(committed)
}

///////////////////////////////////////////////////////////////////////////////
/// import_measurement_bundle takes a fully populated MeasurementBundleRecord
/// and inserts it into the measurement bundles table.
///////////////////////////////////////////////////////////////////////////////

pub async fn import_measurement_bundle(
    txn: &mut Transaction<'_, Postgres>,
    bundle: &MeasurementBundleRecord,
) -> eyre::Result<MeasurementBundleRecord> {
    let query = format!(
        "insert into {}(bundle_id, profile_id, name, ts, state) values($1, $2, $3, $4, $5) returning *",
        MeasurementBundleRecord::db_table_name()
    );
    Ok(sqlx::query_as::<_, MeasurementBundleRecord>(&query)
        .bind(bundle.bundle_id)
        .bind(bundle.profile_id)
        .bind(bundle.name.clone())
        .bind(bundle.ts)
        .bind(bundle.state)
        .fetch_one(&mut **txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// import_measurement_bundles_values is intended for doing "full site"
/// imports, taking a list of all measurement bundles from one site, and
/// inserting them verbatim in another.
///
/// This should happen after import_measurement_bundles, since the
/// parent bundles must exist first.
///////////////////////////////////////////////////////////////////////////////

pub async fn import_measurement_bundles_values(
    txn: &mut Transaction<'_, Postgres>,
    records: &[MeasurementBundleValueRecord],
) -> eyre::Result<Vec<MeasurementBundleValueRecord>> {
    let mut committed = Vec::<MeasurementBundleValueRecord>::new();
    for record in records.iter() {
        committed.push(import_measurement_bundles_value(&mut *txn, record).await?);
    }
    Ok(committed)
}

///////////////////////////////////////////////////////////////////////////////
/// import_measurement_bundles_value takes a fully populated
/// MeasurementBundleValueRecord and inserts it into the measurement bundles
/// values table.
///////////////////////////////////////////////////////////////////////////////

pub async fn import_measurement_bundles_value(
    txn: &mut Transaction<'_, Postgres>,
    bundle: &MeasurementBundleValueRecord,
) -> eyre::Result<MeasurementBundleValueRecord> {
    let query = format!(
        "insert into {}(value_id, bundle_id, pcr_register, sha256, ts) values($1, $2, $3, $4, $5) returning *",
        MeasurementBundleValueRecord::db_table_name()
    );
    Ok(sqlx::query_as::<_, MeasurementBundleValueRecord>(&query)
        .bind(bundle.value_id)
        .bind(bundle.bundle_id)
        .bind(bundle.pcr_register)
        .bind(bundle.sha256.clone())
        .bind(bundle.ts)
        .fetch_one(&mut **txn)
        .await?)
}
