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
/// db/interface/profile.rs
///
/// Code for working the measurement_system_profiles and measurement_system_profiles_attrs
/// tables in the database, leveraging the profile-specific record types.
///////////////////////////////////////////////////////////////////////////////
*/

use crate::measured_boot::dto::keys::{
    MeasurementBundleId, MeasurementSystemProfileId, MockMachineId,
};
use crate::measured_boot::dto::records::{
    MeasurementSystemProfileAttrRecord, MeasurementSystemProfileRecord,
};
use crate::measured_boot::dto::traits::{DbPrimaryUuid, DbTable};
use crate::measured_boot::interface::common;
use sqlx::query_builder::QueryBuilder;
use sqlx::{Pool, Postgres, Transaction};
use std::collections::HashMap;

///////////////////////////////////////////////////////////////////////////////
/// insert_measurement_profile_record is a very basic insert of a
/// new row into the measurement_system_profiles table, where only a name
/// needs to be provided.
///
/// Is it expected that this is wrapped by
/// a more formal call (where a transaction is initialized).
///////////////////////////////////////////////////////////////////////////////

pub async fn insert_measurement_profile_record(
    txn: &mut Transaction<'_, Postgres>,
    name: String,
) -> eyre::Result<MeasurementSystemProfileRecord> {
    let query = "insert into measurement_system_profiles(name) values($1) returning *";
    let profile = sqlx::query_as::<_, MeasurementSystemProfileRecord>(query)
        .bind(name.clone())
        .fetch_one(&mut **txn)
        .await
        .map_err(|sqlx_err| {
            let is_db_err = sqlx_err.as_database_error();
            match is_db_err {
                Some(db_err) => match db_err.kind() {
                    sqlx::error::ErrorKind::UniqueViolation => {
                        eyre::eyre!("profile already exists: {} (msg: {})", name.clone(), db_err)
                    }
                    sqlx::error::ErrorKind::NotNullViolation => {
                        eyre::eyre!(
                            "profile missing required value: {} (msg: {})",
                            name.clone(),
                            db_err
                        )
                    }
                    _ => {
                        eyre::eyre!(
                            "db error creating profile record: {} (msg: {})",
                            name.clone(),
                            db_err
                        )
                    }
                },
                None => eyre::eyre!(
                    "general error creating profile record: {} (msg: {})",
                    name.clone(),
                    sqlx_err
                ),
            }
        })?;
    Ok(profile)
}

///////////////////////////////////////////////////////////////////////////////
/// insert_measurement_profile_attr_records takes a hashmap of
/// k/v attributes and subsequently calls an individual insert
/// for each pair. It is assumed this is called by a parent
/// wrapper where a transaction is created.
///////////////////////////////////////////////////////////////////////////////

pub async fn insert_measurement_profile_attr_records(
    txn: &mut Transaction<'_, Postgres>,
    profile_id: MeasurementSystemProfileId,
    attrs: &HashMap<String, String>,
) -> eyre::Result<Vec<MeasurementSystemProfileAttrRecord>> {
    let mut attributes: Vec<MeasurementSystemProfileAttrRecord> = Vec::new();
    for (key, value) in attrs.iter() {
        attributes.push(insert_measurement_profile_attr_record(txn, profile_id, key, value).await?);
    }
    Ok(attributes)
}

///////////////////////////////////////////////////////////////////////////////
/// insert_measurement_profile_attr_record inserts a single
/// profile attribute (k/v) pair.
///////////////////////////////////////////////////////////////////////////////

async fn insert_measurement_profile_attr_record(
    txn: &mut Transaction<'_, Postgres>,
    profile_id: MeasurementSystemProfileId,
    key: &String,
    value: &String,
) -> eyre::Result<MeasurementSystemProfileAttrRecord> {
    let query = format!(
        "insert into {}(profile_id, key, value) values($1, $2, $3) returning *",
        MeasurementSystemProfileAttrRecord::db_table_name()
    );

    Ok(
        sqlx::query_as::<_, MeasurementSystemProfileAttrRecord>(&query)
            .bind(profile_id)
            .bind(key)
            .bind(value)
            .fetch_one(&mut **txn)
            .await?,
    )
}

///////////////////////////////////////////////////////////////////////////////
/// rename_profile_for_profile_id renames a profile based on its profile ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn rename_profile_for_profile_id(
    txn: &mut Transaction<'_, Postgres>,
    profile_id: MeasurementSystemProfileId,
    new_profile_name: String,
) -> eyre::Result<MeasurementSystemProfileRecord> {
    let query = format!(
        "update {} set name = $1 where {} = $2 returning *",
        MeasurementSystemProfileRecord::db_table_name(),
        MeasurementSystemProfileId::db_primary_uuid_name()
    );

    Ok(sqlx::query_as::<_, MeasurementSystemProfileRecord>(&query)
        .bind(new_profile_name)
        .bind(profile_id)
        .fetch_one(&mut **txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// rename_profile_for_profile_name renames a profile based on its profile name.
///////////////////////////////////////////////////////////////////////////////

pub async fn rename_profile_for_profile_name(
    txn: &mut Transaction<'_, Postgres>,
    old_profile_name: String,
    new_profile_name: String,
) -> eyre::Result<MeasurementSystemProfileRecord> {
    let query = format!(
        "update {} set name = $1 where name = $2 returning *",
        MeasurementSystemProfileRecord::db_table_name(),
    );

    Ok(sqlx::query_as::<_, MeasurementSystemProfileRecord>(&query)
        .bind(new_profile_name)
        .bind(old_profile_name)
        .fetch_one(&mut **txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// get_all_measurement_profile_records gets all system profile records.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_all_measurement_profile_records(
    txn: &mut Transaction<'_, Postgres>,
) -> eyre::Result<Vec<MeasurementSystemProfileRecord>> {
    common::get_all_objects(txn).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_all_measurement_profile_attr_records gets all system profile
/// attribute records.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_all_measurement_profile_attr_records(
    txn: &mut Transaction<'_, Postgres>,
) -> eyre::Result<Vec<MeasurementSystemProfileAttrRecord>> {
    common::get_all_objects(txn).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_profile_record_by_id returns a populated
/// MeasurementSystemProfileRecord for the given `profile_id`,
/// if it exists.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_profile_record_by_id(
    txn: &mut Transaction<'_, Postgres>,
    profile_id: MeasurementSystemProfileId,
) -> eyre::Result<Option<MeasurementSystemProfileRecord>> {
    common::get_object_for_id(txn, profile_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_profile_record_by_name returns a populated
/// MeasurementSystemProfileRecord for the given `name`,
/// if it exists.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_profile_record_by_name(
    txn: &mut Transaction<'_, Postgres>,
    val: String,
) -> eyre::Result<Option<MeasurementSystemProfileRecord>> {
    common::get_object_for_unique_column(txn, "name", val).await
}

///////////////////////////////////////////////////////////////////////////////
/// delete_profile_record_for_id deletes a profile record
/// with the given profile_id.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete_profile_record_for_id(
    txn: &mut Transaction<'_, Postgres>,
    profile_id: MeasurementSystemProfileId,
) -> eyre::Result<Option<MeasurementSystemProfileRecord>> {
    common::delete_object_where_id(txn, profile_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// delete_profile_attr_records_for_id deletes all profile
/// attribute records for a given profile ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete_profile_attr_records_for_id(
    txn: &mut Transaction<'_, Postgres>,
    profile_id: MeasurementSystemProfileId,
) -> eyre::Result<Vec<MeasurementSystemProfileAttrRecord>> {
    common::delete_objects_where_id(txn, profile_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_profile_record_by_attrs will attempt to get a single
/// MeasurementSystemProfileRecord for the given attrs.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_profile_record_by_attrs(
    txn: &mut Transaction<'_, Postgres>,
    attrs: &HashMap<String, String>,
) -> eyre::Result<Option<MeasurementSystemProfileRecord>> {
    match get_measurement_profile_id_by_attrs(txn, attrs).await? {
        Some(profile_id) => get_measurement_profile_record_by_id(txn, profile_id).await,
        None => Ok(None),
    }
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_profile_id_by_attrs attempts to return a profile
/// whose attributes match the input attributes.
///
/// It ultimately looks like this:
///
/// SELECT {t1}.{join_id}
/// FROM {t1}
/// JOIN (
///    SELECT {join_id}
///    FROM (
///      SELECT {join_id}, COUNT(DISTINCT key) AS key_count, COUNT(DISTINCT value) AS value_count
///      FROM {t1}
///      WHERE (key, value) IN ({attr_pairs})
///      GROUP BY {join_id}
///    ) AS possible_ids
///    WHERE key_count = {attrs_len} AND value_count = {attrs_len}
/// ) AS {t2} ON {t1}.{join_id} = {t2}.{join_id}
/// GROUP BY {t1}}.{join_id}
/// HAVING COUNT(*) = {attrs_len}"
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_profile_id_by_attrs(
    txn: &mut Transaction<'_, Postgres>,
    attrs: &HashMap<String, String>,
) -> eyre::Result<Option<MeasurementSystemProfileId>> {
    let t1 = "measurement_system_profiles_attrs";
    let t2 = "matched_ids";
    let join_id = MeasurementSystemProfileId::db_primary_uuid_name();
    let attrs_len = attrs.len() as i32;

    let mut query: QueryBuilder<'_, Postgres> = QueryBuilder::new(format!(
        "
    SELECT {t1}.{join_id}
    FROM {t1}
    JOIN (
        SELECT {join_id}
        FROM (
            SELECT {join_id}, COUNT(DISTINCT key) AS key_count, COUNT(DISTINCT value) AS value_count
            FROM {t1} ",
        t1 = t1,
        join_id = join_id
    ));
    where_attr_pairs(&mut query, attrs);

    query.push(format!(
        "
            GROUP BY {join_id}
        ) AS possible_ids ",
        join_id = join_id,
    ));

    query.push("WHERE key_count = ");
    query.push_bind(attrs_len);
    query.push(" AND value_count = ");
    query.push_bind(attrs_len);
    query.push(format!(
        ") AS {t2} ON {t1}.{join_id} = {t2}.{join_id}
    GROUP BY {t1}.{join_id}
    HAVING COUNT(*) = ",
        t1 = t1,
        t2 = t2,
        join_id = join_id
    ));
    query.push_bind(attrs_len);

    let query = query.build_query_as::<MeasurementSystemProfileId>();
    let ids = match query.fetch_optional(&mut **txn).await {
        Ok(ids) => ids,
        Err(e) => {
            return Err(e.into());
        }
    };

    Ok(ids)
}

fn where_attr_pairs(query: &mut QueryBuilder<'_, Postgres>, values: &HashMap<String, String>) {
    query.push("where (key, value) in (");
    for (index, (key, value)) in values.iter().enumerate() {
        query.push("(");
        query.push_bind(key.clone());
        query.push(",");
        query.push_bind(value.clone());
        query.push(")");
        if index < values.len() - 1 {
            query.push(", ");
        }
    }
    query.push(") ");
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_profile_attrs_for_profile_id returns all profile attribute
/// records associated with the provided MeasurementSystemProfileId.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_profile_attrs_for_profile_id(
    txn: &mut Transaction<'_, Postgres>,
    profile_id: MeasurementSystemProfileId,
) -> eyre::Result<Vec<MeasurementSystemProfileAttrRecord>> {
    common::get_objects_where_id(txn, profile_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_bundles_for_profile_id returns a unique list of all
/// MeasurementBundleId that leverage the given profile.
///
/// This is specifically used by the `profile list bundles for-id` CLI call.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_bundles_for_profile_id(
    db_conn: &Pool<Postgres>,
    profile_id: MeasurementSystemProfileId,
) -> eyre::Result<Vec<MeasurementBundleId>> {
    let mut txn = db_conn.begin().await?;
    let query =
        "select distinct bundle_id from measurement_bundles where profile_id = $1 order by bundle_id";
    Ok(sqlx::query_as::<_, MeasurementBundleId>(query)
        .bind(profile_id)
        .fetch_all(&mut *txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// get_bundles_for_profile_name returns a unique list of all
/// MeasurementBundleId that leverage the given profile.
///
/// This is specifically used by the `profile list bundles for-name` CLI call.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_bundles_for_profile_name(
    db_conn: &Pool<Postgres>,
    profile_name: String,
) -> eyre::Result<Vec<MeasurementBundleId>> {
    let mut txn = db_conn.begin().await?;
    let query =
        "select distinct bundle_id from measurement_bundles where name = $1 order by bundle_id";
    Ok(sqlx::query_as::<_, MeasurementBundleId>(query)
        .bind(profile_name)
        .fetch_all(&mut *txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// get_machines_for_profile_id returns a unique list of all MockMachineId
/// that leverage the given profile.
///
/// This is specifically used by the `profile list machines by-id` CLI call.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_machines_for_profile_id(
    db_conn: &Pool<Postgres>,
    profile_id: MeasurementSystemProfileId,
) -> eyre::Result<Vec<MockMachineId>> {
    let mut txn = db_conn.begin().await?;
    let query = "select distinct machine_id from measurement_journal where profile_id = $1 order by machine_id";
    Ok(sqlx::query_as::<_, MockMachineId>(query)
        .bind(profile_id)
        .fetch_all(&mut *txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// get_machines_for_profile_name returns a unique list of all MockMachineId
/// that leverage the given profile.
///
/// This is specifically used by the `profile list machines by-name` CLI call.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_machines_for_profile_name(
    db_conn: &Pool<Postgres>,
    profile_name: String,
) -> eyre::Result<Vec<MockMachineId>> {
    let mut txn = db_conn.begin().await?;
    let query =
        "select distinct machine_id from measurement_journal,measurement_system_profiles where measurement_journal.profile_id=measurement_system_profiles.profile_id and measurement_system_profiles.name = $1 order by machine_id";
    Ok(sqlx::query_as::<_, MockMachineId>(query)
        .bind(profile_name)
        .fetch_all(&mut *txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// import_measurement_system_profiles takes a vector of MeasurementSystemProfileRecord
/// and calls import_measurement_profile for each of them.
///
/// This is used for doing full site imports, and is wrapped in a transaction
/// such that, if any of it fails, none of it will be committed.
///////////////////////////////////////////////////////////////////////////////

pub async fn import_measurement_system_profiles(
    txn: &mut Transaction<'_, Postgres>,
    records: &[MeasurementSystemProfileRecord],
) -> eyre::Result<Vec<MeasurementSystemProfileRecord>> {
    let mut committed = Vec::<MeasurementSystemProfileRecord>::new();
    for record in records.iter() {
        committed.push(import_measurement_profile(&mut *txn, record).await?);
    }
    Ok(committed)
}

///////////////////////////////////////////////////////////////////////////////
/// import_measurement_profile inserts a single MeasurementSystemProfileRecord.
///
/// This is used for doing full site imports, and the intent is that this
/// is called by import_measurement_system_profiles as part of inserting a bunch
/// of measurement profiles.
///
/// After a MeasurementSystemProfileRecord gets inserted, its clear for having
/// all of its MeasurementSystemProfileAttrRecord records inserted.
///////////////////////////////////////////////////////////////////////////////

pub async fn import_measurement_profile(
    txn: &mut Transaction<'_, Postgres>,
    profile: &MeasurementSystemProfileRecord,
) -> eyre::Result<MeasurementSystemProfileRecord> {
    let query = format!(
        "insert into {}(profile_id, name, ts) values($1, $2, $3) returning *",
        MeasurementSystemProfileRecord::db_table_name()
    );

    Ok(sqlx::query_as::<_, MeasurementSystemProfileRecord>(&query)
        .bind(profile.profile_id)
        .bind(profile.name.clone())
        .bind(profile.ts)
        .fetch_one(&mut **txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// import_measurement_system_profiles_attrs inserts a bunch of measurement profile
/// attributes as part of doing a site import.
///
/// It is expected that the measurement profile itself (as in, the parent
/// MeasurementSystemProfileRecord) exists before the attributes are added, since
/// it would fail foreign key constraints otherwise.
///////////////////////////////////////////////////////////////////////////////

pub async fn import_measurement_system_profiles_attrs(
    txn: &mut Transaction<'_, Postgres>,
    records: &[MeasurementSystemProfileAttrRecord],
) -> eyre::Result<Vec<MeasurementSystemProfileAttrRecord>> {
    let mut committed = Vec::<MeasurementSystemProfileAttrRecord>::new();
    for record in records.iter() {
        committed.push(import_measurement_system_profiles_attr(&mut *txn, record).await?);
    }
    Ok(committed)
}

///////////////////////////////////////////////////////////////////////////////
/// import_measurement_system_profiles_attr imports a single measurement profile
/// attribute.
///
/// The idea is import_measurement_system_profiles_attrs has all of the attributes,
/// and then calls this for each attribute.
///////////////////////////////////////////////////////////////////////////////

pub async fn import_measurement_system_profiles_attr(
    txn: &mut Transaction<'_, Postgres>,
    bundle: &MeasurementSystemProfileAttrRecord,
) -> eyre::Result<MeasurementSystemProfileAttrRecord> {
    let query = format!(
        "insert into {}(attribute_id, profile_id, key, value, ts) values($1, $2, $3, $4, $5) returning *",
        MeasurementSystemProfileAttrRecord::db_table_name()
    );

    Ok(
        sqlx::query_as::<_, MeasurementSystemProfileAttrRecord>(&query)
            .bind(bundle.attribute_id)
            .bind(bundle.profile_id)
            .bind(bundle.key.clone())
            .bind(bundle.value.clone())
            .bind(bundle.ts)
            .fetch_one(&mut **txn)
            .await?,
    )
}

///////////////////////////////////////////////////////////////////////////////
/// export_measurement_profile_records returns all MeasurementSystemProfileRecord
/// instances in the database.
///
/// This is used by the site exporter, as well as for listing all profiles.
///////////////////////////////////////////////////////////////////////////////

pub async fn export_measurement_profile_records(
    db_conn: &Pool<Postgres>,
) -> eyre::Result<Vec<MeasurementSystemProfileRecord>> {
    let mut txn = db_conn.begin().await?;
    common::get_all_objects(&mut txn).await
}

///////////////////////////////////////////////////////////////////////////////
/// export_measurement_system_profiles_attrs returns all MeasurementSystemProfileAttrRecord
/// instances in the database.
///
/// This is specifically used by the site exporter, since we simply dump all
/// attributes when doing a site export.
///////////////////////////////////////////////////////////////////////////////

pub async fn export_measurement_system_profiles_attrs(
    db_conn: &Pool<Postgres>,
) -> eyre::Result<Vec<MeasurementSystemProfileAttrRecord>> {
    let mut txn = db_conn.begin().await?;
    common::get_all_objects(&mut txn).await
}
