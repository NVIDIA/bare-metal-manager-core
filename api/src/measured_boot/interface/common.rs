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
 *  Common code for working with the database. Provides constants and generics
 *  for making boilerplate copy-pasta code handled in a common way.
*/

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::{From, Into};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::DerefMut;
use std::vec::Vec;

use rpc::protos::measured_boot::PcrRegisterValuePb;
use sqlx::postgres::PgRow;
use sqlx::query_builder::QueryBuilder;
use sqlx::{Encode, Pool, Postgres, Transaction};

use crate::db::DatabaseError;
use crate::{CarbideError, CarbideResult};
use forge_uuid::{DbPrimaryUuid, DbTable};

// DISCOVERY_PROFILE_ATTRS are the attributes we pull
// from DiscoveryInfo for a given machine when
// auto-generating a SystemProfile. Obviously the actual
// data is buried somewhere in the JSON payload, but
// those values will be pulled and put into a HashMap
// with the following keys leveraging the below
// filter_machine_discovery_attrs function.
pub const DISCOVERY_PROFILE_ATTRS: [&str; 3] = ["sys_vendor", "product_name", "bios_version"];

/// filter_machine_discovery_attrs is used for taking
/// an input DiscoveryInfo and filtering the data out
/// into a HashMap keyed by DISCOVERY_PROFILE_ATTRS.
///
/// If you come across this before it's in production,
/// you'll notice it's mocked to take a HashMap as
/// input, and not a DiscoveryInfo, because I'm just
/// pulling values from the mock attributes table.
pub fn filter_machine_discovery_attrs(
    attrs: &HashMap<String, String>,
) -> CarbideResult<HashMap<String, String>> {
    let filtered: HashMap<String, String> = attrs
        .iter()
        .filter_map(|(k, v)| {
            if DISCOVERY_PROFILE_ATTRS.contains(&k.as_str()) {
                Some((k.clone(), v.clone()))
            } else {
                None
            }
        })
        .collect();
    Ok(filtered)
}

pub enum ConnType<'p, 'm, 't> {
    DbConn(&'p Pool<Postgres>),
    Txn(&'m Transaction<'t, Postgres>),
}

// PcrRange is a small struct used when parsing
// --pcr-register values from the CLI as part of
// the parse_pcr_index_input function.
#[derive(Clone, Debug)]
pub struct PcrRange {
    pub start: usize,
    pub end: usize,
}

impl fmt::Display for PcrRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

/// PcrSet is a list of PCR register indexes that are expected
/// to be targeted. For example: 0,1,2,5,6. With this PCR set,
/// an incoming list of PcrRegisterValues will have any values
/// whose indexes match the register numbers from the PcrSet.
///
/// This includes implementations for iterating.
#[derive(Clone, Debug)]
pub struct PcrSet(pub Vec<i16>);

impl Default for PcrSet {
    fn default() -> Self {
        Self::new()
    }
}

impl PcrSet {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn iter(&self) -> PcrSetIter {
        PcrSetIter {
            current_slice: &self.0,
        }
    }
}

impl fmt::Display for PcrSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let vals: Vec<String> = self.iter().map(|&val| val.to_string()).collect();
        write!(f, "{}", vals.join(","))
    }
}

impl IntoIterator for PcrSet {
    type Item = i16;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'p> IntoIterator for &'p PcrSet {
    type Item = &'p i16;
    type IntoIter = std::slice::Iter<'p, i16>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[derive(Clone, Debug)]
pub struct PcrSetIter<'i> {
    current_slice: &'i [i16],
}

impl<'i> Iterator for PcrSetIter<'i> {
    type Item = &'i i16;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.current_slice.is_empty() {
            let (first, rest) = self.current_slice.split_first().unwrap();
            self.current_slice = rest;
            Some(first)
        } else {
            None
        }
    }
}

pub fn parse_pcr_index_input(arg: &str) -> CarbideResult<PcrSet> {
    let groups: Vec<&str> = arg.split(',').collect();
    let mut index_set: HashSet<i16> = HashSet::new();
    for group in groups {
        if group.contains('-') {
            let pcr_range = parse_range(group)?;
            for index in pcr_range.start..=pcr_range.end {
                index_set.insert(index as i16);
            }
        } else {
            index_set.insert(group.parse::<i16>().map_err(|e| {
                CarbideError::GenericError(format!(
                    "parse_pcr_index_input group parse failed: {}, {}",
                    group, e
                ))
            })?);
        }
    }

    let mut vals: Vec<i16> = index_set.into_iter().collect();
    vals.sort();
    Ok(PcrSet(vals))
}

pub fn parse_range(arg: &str) -> CarbideResult<PcrRange> {
    let range: Vec<usize> = arg
        .split('-')
        .map(|s| {
            s.parse::<usize>()
                .map_err(|_| CarbideError::GenericError(format!("parse_range failed on {}", arg)))
        })
        .collect::<CarbideResult<Vec<usize>>>()?;

    if range.len() != 2 {
        return Err(CarbideError::GenericError(String::from(
            "parse_range range expected 2 values",
        )));
    }

    if range[0] > range[1] {
        return Err(CarbideError::GenericError(String::from(
            "end must be greater than start",
        )));
    }

    Ok(PcrRange {
        start: range[0],
        end: range[1],
    })
}

/// generate_name generates a unique name for the purpose
/// of auto-generated {profile, bundle} names.
pub fn generate_name() -> CarbideResult<String> {
    let mut generate = names::Generator::default();
    Ok(generate.next().unwrap())
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct PcrRegisterValue {
    pub pcr_register: i16,
    pub sha256: String,
}

pub struct PcrRegisterValueVec(Vec<PcrRegisterValue>);

impl PcrRegisterValueVec {
    pub fn into_inner(self) -> Vec<PcrRegisterValue> {
        self.0
    }
}

impl PcrRegisterValue {
    pub fn from_pb_vec(pbs: &[PcrRegisterValuePb]) -> Vec<Self> {
        pbs.iter().map(|value| value.clone().into()).collect()
    }

    pub fn to_pb_vec(values: &[Self]) -> Vec<PcrRegisterValuePb> {
        values.iter().map(|value| value.clone().into()).collect()
    }
}

impl From<PcrRegisterValue> for PcrRegisterValuePb {
    fn from(val: PcrRegisterValue) -> Self {
        Self {
            pcr_register: val.pcr_register as i32,
            sha256: val.sha256.clone(),
        }
    }
}

impl From<PcrRegisterValuePb> for PcrRegisterValue {
    fn from(msg: PcrRegisterValuePb) -> Self {
        Self {
            pcr_register: msg.pcr_register as i16,
            sha256: msg.sha256,
        }
    }
}

impl From<Vec<String>> for PcrRegisterValueVec {
    fn from(pcr_strings: Vec<String>) -> Self {
        let pcr_register_values = pcr_strings
            .into_iter()
            .enumerate()
            .map(|(pcr_index, pcr_val)| PcrRegisterValue {
                pcr_register: pcr_index as i16,
                sha256: pcr_val,
            })
            .collect();
        PcrRegisterValueVec(pcr_register_values)
    }
}

pub fn pcr_register_values_to_map(
    values: &[PcrRegisterValue],
) -> CarbideResult<HashMap<i16, PcrRegisterValue>> {
    let total_values = values.len();
    let value_map: HashMap<i16, PcrRegisterValue> = values
        .iter()
        .map(|rec| (rec.pcr_register, rec.clone()))
        .collect();
    if total_values != value_map.len() {
        return Err(CarbideError::GenericError(String::from(
            "detected pcr_register collision in input bundle values",
        )));
    }
    Ok(value_map)
}

/// get_object_for_id provides a generic for getting a fully populated
/// struct (which derives sqlx::FromRow) for a given "ID", where an ID is a
/// struct which derives from a sqlx::types::Uuid (type = UUID).
///
/// See db/model/keys.rs for all of the UUIDs, and db/model/records for all
/// of the structs which derive FromRow.
///
/// And to reduce string literal use even further, both of those implement
/// the DbPrimaryUuid and DbTable traits (which are traits defined in this
/// crate) to build the query.
pub async fn get_object_for_id<T, R>(
    txn: &mut Transaction<'_, Postgres>,
    id: T,
) -> Result<Option<R>, DatabaseError>
where
    T: for<'t> Encode<'t, Postgres> + Send + sqlx::Type<sqlx::Postgres> + DbPrimaryUuid,
    R: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin + DbTable,
{
    get_object_for_unique_column(txn, T::db_primary_uuid_name(), id)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "get_object_for_id", e.source))
}

/// get_object_for_unique_column provides a generic for getting a fully
/// populated struct (which derives sqlx::FromRow) for a given uniquely
/// constrained column, where the value derives from an sqlx::types::*.
//
/// And to reduce string literal use even further, both of those implement
/// the DbPrimaryUuid and DbTable traits (which are traits defined in this
/// crate) to build the query.
pub async fn get_object_for_unique_column<T, R>(
    txn: &mut Transaction<'_, Postgres>,
    col_name: &str,
    value: T,
) -> Result<Option<R>, DatabaseError>
where
    T: for<'t> Encode<'t, Postgres> + Send + sqlx::Type<sqlx::Postgres>,
    R: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin + DbTable,
{
    let query = format!(
        "select * from {} where {} = $1",
        R::db_table_name(),
        col_name,
    );
    let result = sqlx::query_as::<_, R>(&query)
        .bind(value)
        .fetch_optional(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "get_object_for_unique_column", e))?;
    Ok(result)
}

/// get_objects_where_id returns a vector of records who share a similar
/// `id` in common. The idea here is there is a child table with a foreign key
/// containing a UUID, and we want to get all records mapping back to that
/// UUID in the parent table.
///
/// Similar to get_object_for_id above, this leverages a mixture of sqlx-based
/// derive + traits to reduce the use of copy-pasta code + string literals.
pub async fn get_objects_where_id<T, R>(
    txn: &mut Transaction<'_, Postgres>,
    id: T,
) -> Result<Vec<R>, DatabaseError>
where
    T: for<'t> Encode<'t, Postgres> + Send + sqlx::Type<sqlx::Postgres> + DbPrimaryUuid,
    R: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin + DbTable,
{
    let query = format!(
        "select * from {} where {} = $1",
        R::db_table_name(),
        T::db_primary_uuid_name()
    );
    let result = sqlx::query_as::<_, R>(&query)
        .bind(id)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "get_objects_where_id", e))?;
    Ok(result)
}

/// get_all_objects provides a generic way to return populated structs
/// for all records of the given type. Similar to the comments in the two
/// above generics, this leverages structs deriving sqlx::FromRow and
/// implementing the crate-specific DbName trait to make this possible,
/// with the idea of reducing very boilerplate copy-pasta code and string
/// literals.
pub async fn get_all_objects<R>(
    txn: &mut Transaction<'_, Postgres>,
) -> Result<Vec<R>, DatabaseError>
where
    R: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin + DbTable,
{
    let query = format!("select * from {}", R::db_table_name());
    let result = sqlx::query_as::<_, R>(&query)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "get_all_objects", e))?;
    Ok(result)
}

/// get_ids_for_bundle_values is a common mechanism for matching a
/// set of input values to either a measurement bundle or journal
///
/// This builds something similar to:
///
/// let query = format!("select {} from {} where (pcr_register, sha256) in ((0,$1), (1,$2), (2,$3), (3,$4), (4,$5), (5,$6), (6,$7)) group by {} having count(distinct pcr_register) = $8",
///    R::db_primary_uuid_name(),
///   table_name,
///    R::db_primary_uuid_name());
pub async fn get_ids_for_bundle_values<R>(
    txn: &mut Transaction<'_, Postgres>,
    table_name: &str,
    values: &[PcrRegisterValue],
) -> Result<Vec<R>, DatabaseError>
where
    R: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin + DbPrimaryUuid,
{
    let mut query: QueryBuilder<'_, Postgres> = QueryBuilder::new(format!(
        "select {} from {} where (pcr_register, sha256) in (",
        R::db_primary_uuid_name(),
        table_name
    ));

    for (value_index, value) in values.iter().enumerate() {
        query.push(format!("({},", value.pcr_register));
        query.push_bind(value.sha256.clone());
        query.push(")");
        if value_index < values.len() - 1 {
            query.push(", ");
        }
    }
    query.push(") ");

    query.push(format!("group by {}", R::db_primary_uuid_name()));
    query.push(" having count(distinct pcr_register) = ");
    query.push_bind(values.len() as i32);

    let query = query.build_query_as::<R>();
    let ids = query
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "get_ids_for_bundle_values", e))?;

    Ok(ids)
}

/// delete_objects_where_id provides a generic way to delete one or more
/// records of a given type, based on a key, and will return the record(s) of
/// what was deleted.
///
/// Similar to the comments in the two above generics, this leverages structs
/// deriving sqlx::FromRow and implementing the crate-specific DbName trait to
/// make this possible, with the idea of reducing very boilerplate copy-pasta
/// code and string literals.
pub async fn delete_objects_where_id<T, R>(
    txn: &mut Transaction<'_, Postgres>,
    id: T,
) -> Result<Vec<R>, DatabaseError>
where
    T: for<'t> Encode<'t, Postgres> + Send + sqlx::Type<sqlx::Postgres> + DbPrimaryUuid,
    R: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin + DbTable,
{
    delete_objects_where_unique_column(txn, T::db_primary_uuid_name(), id)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "delete_objects_where_id", e.source))
}

pub async fn delete_objects_where_unique_column<T, R>(
    txn: &mut Transaction<'_, Postgres>,
    col_name: &str,
    value: T,
) -> Result<Vec<R>, DatabaseError>
where
    T: for<'t> Encode<'t, Postgres> + Send + sqlx::Type<sqlx::Postgres>,
    R: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin + DbTable,
{
    let query = format!(
        "delete from {} where {} = $1 returning *",
        R::db_table_name(),
        col_name,
    );
    let result = sqlx::query_as::<_, R>(&query)
        .bind(value)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| {
            DatabaseError::new(file!(), line!(), "delete_objects_where_unique_column", e)
        })?;
    Ok(result)
}

/// delete_object_where_id is used for cases where only a single record
/// is expected to be deleted.
pub async fn delete_object_where_id<T, R>(
    txn: &mut Transaction<'_, Postgres>,
    id: T,
) -> Result<Option<R>, DatabaseError>
where
    T: for<'t> Encode<'t, Postgres> + Send + sqlx::Type<sqlx::Postgres> + DbPrimaryUuid,
    R: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin + DbTable,
{
    delete_object_where_unique_column(txn, T::db_primary_uuid_name(), id)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "delete_object_where_id", e.source))
}

pub async fn delete_object_where_unique_column<T, R>(
    txn: &mut Transaction<'_, Postgres>,
    col_name: &str,
    value: T,
) -> Result<Option<R>, DatabaseError>
where
    T: for<'t> Encode<'t, Postgres> + Send + sqlx::Type<sqlx::Postgres>,
    R: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin + DbTable,
{
    let query = format!(
        "delete from {} where {} = $1 returning *",
        R::db_table_name(),
        col_name,
    );
    let result = sqlx::query_as::<_, R>(&query)
        .bind(value)
        .fetch_optional(txn.deref_mut())
        .await
        .map_err(|e| {
            DatabaseError::new(file!(), line!(), "delete_object_where_unique_column", e)
        })?;
    Ok(result)
}

/// acquire_advisory_txn_lock acquires, as you'd expect,
/// an advisory lock, which is primarily used for the
/// purpose of ensuring unique/atomic creation of both
/// measurement profiles and measurement bundles. Since
/// bundles and profiles are comprised of multiple rows,
/// we can't really do unique constraints, and I didn't
/// really want to lock the entire table(s), so this is
/// a nice option. The code here is generic, so we could
/// also use it in other places that end up needing it.
///
/// This will block if the lock is currently held, and
/// will wait until it it is released. If you don't want
/// blocking behavior, use try_advisory_lock instead.
///
/// This will also automatically release at the end of
/// the transaction (either commit or rollback), so you
/// don't need to explicitly release the lock when
/// you're done. If you want more control, you can
/// use acquire_advisory_lock + release_advisory_lock.
pub async fn acquire_advisory_txn_lock(
    txn: &mut Transaction<'_, Postgres>,
    key: &str,
) -> Result<(), DatabaseError> {
    let hash_key = advisory_lock_key_to_hash(key);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(hash_key)
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "acquire_advisory_txn_lock", e))?;
    Ok(())
}

/// acquire_advisory_lock is the same as acquire_advisory_txn_lock
/// above, except it doesn't automatically release on commit
/// or rollback. If you don't want to worry about explicitly
/// calling release_advisory_lock when you're done, then use
/// that.
pub async fn acquire_advisory_lock(
    txn: &mut Transaction<'_, Postgres>,
    key: &str,
) -> Result<(), DatabaseError> {
    let hash_key = advisory_lock_key_to_hash(key);
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(hash_key)
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "acquire_advisory_lock", e))?;
    Ok(())
}

/// release_advisory_lock releases an advisory lock once
/// we're done with whatever operation required acquiring
/// an advisory lock. See the acquire_advisory_lock docstring
/// for more information about why these are used.
pub async fn release_advisory_lock(
    txn: &mut Transaction<'_, Postgres>,
    key: &str,
) -> CarbideResult<()> {
    let hash_key = advisory_lock_key_to_hash(key);
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(hash_key)
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "release_advisory_lock", e))?;
    Ok(())
}

/// try_advisory_lock tries to get an advisory lock
/// for the given key. If the lock is not held, it
/// will acquire and return true. If the lock is already
/// held, it will immediately return false. If an error
/// occurs, it will return an error.
pub async fn try_advisory_lock(
    txn: &mut Transaction<'_, Postgres>,
    key: &str,
) -> CarbideResult<bool> {
    let hash_key = advisory_lock_key_to_hash(key);
    let acquired = sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
        .bind(hash_key)
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "try_advisory_lock", e))?;
    Ok(acquired)
}

/// advisory_lock_key_to_hash takes an advisory lock key and
/// converts it into an i64 for the purpose of acquiring or
/// releasing an advisory lock.
fn advisory_lock_key_to_hash(key: &str) -> i64 {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish() as i64
}

#[cfg(test)]
mod tests {
    use super::{
        acquire_advisory_lock, acquire_advisory_txn_lock, release_advisory_lock, try_advisory_lock,
    };

    #[sqlx::test]
    pub async fn test_advisory_txn_locking(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // First, make sure that a txn scoped within the same scope
        // as the txn lock can't acquire it.
        {
            let mut txn1 = pool.begin().await?;
            acquire_advisory_txn_lock(&mut txn1, "my_lock").await?;
            let mut scoped_txn2 = pool.begin().await?;
            let scoped_txn2_acquired = try_advisory_lock(&mut scoped_txn2, "my_lock").await?;
            assert!(!scoped_txn2_acquired);
        }

        // And now that we've fallen out of scope, txn1 will have been rolled back,
        // so now txn2 can get the lock.
        let mut txn2 = pool.begin().await?;
        let txn2_acquired = try_advisory_lock(&mut txn2, "my_lock").await?;
        assert!(txn2_acquired);

        Ok(())
    }

    #[sqlx::test]
    pub async fn test_acquire_release_locking(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn1 = pool.begin().await?;
        acquire_advisory_lock(&mut txn1, "my_lock").await?;

        // txn1 is holding a lock, so this will fail
        let mut txn2 = pool.begin().await?;
        let txn2_acquired = try_advisory_lock(&mut txn2, "my_lock").await?;
        assert!(!txn2_acquired);

        // And now explicitly release the lock.
        release_advisory_lock(&mut txn1, "my_lock").await?;

        // ...and now txn2 can get the lock.
        let txn2_acquired = try_advisory_lock(&mut txn2, "my_lock").await?;
        assert!(txn2_acquired);

        Ok(())
    }
}
