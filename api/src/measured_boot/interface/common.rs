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
/// db/interface/common.rs
///
/// Common code for working with the database. Provides constants and generics
/// for making boilerplate copy-pasta code handled in a common way.
///////////////////////////////////////////////////////////////////////////////
*/

use crate::measured_boot::dto::traits::{DbPrimaryUuid, DbTable};
use rpc::protos::measured_boot::PcrRegisterValuePb;
use sqlx::postgres::PgRow;
use sqlx::query_builder::QueryBuilder;
use sqlx::{Encode, Pool, Postgres, Transaction};
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::{From, Into};
use std::error::Error;
use std::fmt;

// DISCOVERY_PROFILE_ATTRS are the attributes we pull
// from DiscoveryInfo for a given machine when
// auto-generating a SystemProfile. Obviously the actual
// data is buried somewhere in the JSON payload, but
// those values will be pulled and put into a HashMap
// with the following keys leveraging the below
// filter_machine_discovery_attrs function.
pub const DISCOVERY_PROFILE_ATTRS: [&str; 4] = ["vendor", "product", "uefi", "tpm"];

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
) -> eyre::Result<HashMap<String, String>> {
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

///////////////////////////////////////////////////////////////////////////////
/// ToTable is a trait which is used alongside the cli_output command
/// and being able to prettytable print results.
///////////////////////////////////////////////////////////////////////////////

pub trait ToTable {
    fn to_table(&self) -> eyre::Result<String> {
        Ok("not implemented".to_string())
    }
}

pub fn convert_to_table<T: ToTable>(input: &T) -> eyre::Result<String> {
    input.to_table()
}

///////////////////////////////////////////////////////////////////////////////
// PcrRange is a small struct used when parsing
// --pcr-register values from the CLI as part of
// the parse_pcr_index_input function.
///////////////////////////////////////////////////////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////
/// PcrSet is a list of PCR register indexes that are expected
/// to be targeted. For example: 0,1,2,5,6. With this PCR set,
/// an incoming list of PcrRegisterValues will have any values
/// whose indexes match the register numbers from the PcrSet.
///
/// This includes implementations for iterating.
///////////////////////////////////////////////////////////////////////////////

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

pub fn parse_pcr_index_input(arg: &str) -> eyre::Result<PcrSet> {
    let groups: Vec<&str> = arg.split(',').collect();
    let mut index_set: HashSet<i16> = HashSet::new();
    for group in groups {
        if group.contains('-') {
            let pcr_range = parse_range(group)?;
            for index in pcr_range.start..=pcr_range.end {
                index_set.insert(index as i16);
            }
        } else {
            index_set.insert(group.parse::<i16>()?);
        }
    }

    let mut vals: Vec<i16> = index_set.into_iter().collect();
    vals.sort();
    Ok(PcrSet(vals))
}

pub fn parse_range(arg: &str) -> eyre::Result<PcrRange> {
    let range: Vec<usize> = arg
        .split('-')
        .map(|s| {
            s.parse::<usize>()
                .map_err(|_| eyre::eyre!("failed parsing"))
        })
        .collect::<eyre::Result<Vec<usize>>>()?;

    if range.len() != 2 {
        return Err(eyre::eyre!("expected two values"));
    }

    if range[0] > range[1] {
        return Err(eyre::eyre!("end must be greater than start"));
    }

    Ok(PcrRange {
        start: range[0],
        end: range[1],
    })
}

/// generate_name generates a unique name for the purpose
/// of auto-generated {profile, bundle} names.
pub fn generate_name() -> eyre::Result<String> {
    let mut generate = names::Generator::default();
    Ok(generate.next().unwrap())
}

#[derive(Debug)]
pub struct PcrValueParseError {
    msg: String,
}

impl fmt::Display for PcrValueParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse PCR value input: {}", self.msg,)
    }
}

impl Error for PcrValueParseError {}

#[derive(Debug, Clone)]
pub struct PcrRegisterValue {
    pub pcr_register: i16,
    pub sha256: String,
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

pub fn pcr_register_values_to_map(
    values: &[PcrRegisterValue],
) -> eyre::Result<HashMap<i16, PcrRegisterValue>> {
    let total_values = values.len();
    let value_map: HashMap<i16, PcrRegisterValue> = values
        .iter()
        .map(|rec| (rec.pcr_register, rec.clone()))
        .collect();
    if total_values != value_map.len() {
        return Err(eyre::eyre!(
            "detected pcr_register collision in input bundle values"
        ));
    }
    Ok(value_map)
}

///////////////////////////////////////////////////////////////////////////////
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
///////////////////////////////////////////////////////////////////////////////

pub async fn get_object_for_id<T, R>(
    txn: &mut Transaction<'_, Postgres>,
    id: T,
) -> eyre::Result<Option<R>>
where
    T: for<'t> Encode<'t, Postgres> + Send + sqlx::Type<sqlx::Postgres> + DbPrimaryUuid,
    R: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin + DbTable,
{
    get_object_for_unique_column(txn, T::db_primary_uuid_name(), id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_object_for_unique_column provides a generic for getting a fully
/// populated struct (which derives sqlx::FromRow) for a given uniquely
/// constrained column, where the value derives from an sqlx::types::*.
//
/// And to reduce string literal use even further, both of those implement
/// the DbPrimaryUuid and DbTable traits (which are traits defined in this
/// crate) to build the query.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_object_for_unique_column<T, R>(
    txn: &mut Transaction<'_, Postgres>,
    col_name: &str,
    value: T,
) -> eyre::Result<Option<R>>
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
        .fetch_optional(&mut **txn)
        .await?;
    Ok(result)
}

///////////////////////////////////////////////////////////////////////////////
/// get_objects_where_id returns a vector of records who share a similar
/// `id` in common. The idea here is there is a child table with a foreign key
/// containing a UUID, and we want to get all records mapping back to that
/// UUID in the parent table.
///
/// Similar to get_object_for_id above, this leverages a mixture of sqlx-based
/// derive + traits to reduce the use of copy-pasta code + string literals.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_objects_where_id<T, R>(
    txn: &mut Transaction<'_, Postgres>,
    id: T,
) -> eyre::Result<Vec<R>>
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
        .fetch_all(&mut **txn)
        .await?;
    Ok(result)
}

///////////////////////////////////////////////////////////////////////////////
/// get_all_objects provides a generic way to return populated structs
/// for all records of the given type. Similar to the comments in the two
/// above generics, this leverages structs deriving sqlx::FromRow and
/// implementing the crate-specific DbName trait to make this possible,
/// with the idea of reducing very boilerplate copy-pasta code and string
/// literals.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_all_objects<R>(txn: &mut Transaction<'_, Postgres>) -> eyre::Result<Vec<R>>
where
    R: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin + DbTable,
{
    let query = format!("select * from {}", R::db_table_name());
    let result = sqlx::query_as::<_, R>(&query).fetch_all(&mut **txn).await?;
    Ok(result)
}

///////////////////////////////////////////////////////////////////////////////
/// get_ids_for_bundle_values is a common mechanism for matching a
/// set of input values to either a measurement bundle or journal
///
/// This builds something similar to:
///
/// let query = format!("select {} from {} where (pcr_register, sha256) in ((0,$1), (1,$2), (2,$3), (3,$4), (4,$5), (5,$6), (6,$7)) group by {} having count(distinct pcr_register) = $8",
///    R::db_primary_uuid_name(),
///   table_name,
///    R::db_primary_uuid_name());
///////////////////////////////////////////////////////////////////////////////

pub async fn get_ids_for_bundle_values<R>(
    txn: &mut Transaction<'_, Postgres>,
    table_name: &str,
    values: &[PcrRegisterValue],
) -> eyre::Result<Vec<R>>
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
    let ids = match query.fetch_all(&mut **txn).await {
        Ok(ids) => ids,
        Err(e) => {
            return Err(e.into());
        }
    };

    Ok(ids)
}

///////////////////////////////////////////////////////////////////////////////
/// delete_objects_where_id provides a generic way to delete one or more
/// records of a given type, based on a key, and will return the record(s) of
/// what was deleted.
///
/// Similar to the comments in the two above generics, this leverages structs
/// deriving sqlx::FromRow and implementing the crate-specific DbName trait to
/// make this possible, with the idea of reducing very boilerplate copy-pasta
/// code and string literals.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete_objects_where_id<T, R>(
    txn: &mut Transaction<'_, Postgres>,
    id: T,
) -> eyre::Result<Vec<R>>
where
    T: for<'t> Encode<'t, Postgres> + Send + sqlx::Type<sqlx::Postgres> + DbPrimaryUuid,
    R: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin + DbTable,
{
    delete_objects_where_unique_column(txn, T::db_primary_uuid_name(), id).await
}

pub async fn delete_objects_where_unique_column<T, R>(
    txn: &mut Transaction<'_, Postgres>,
    col_name: &str,
    value: T,
) -> eyre::Result<Vec<R>>
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
        .fetch_all(&mut **txn)
        .await?;
    Ok(result)
}

///////////////////////////////////////////////////////////////////////////////
/// delete_object_where_id is used for cases where only a single record
/// is expected to be deleted.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete_object_where_id<T, R>(
    txn: &mut Transaction<'_, Postgres>,
    id: T,
) -> eyre::Result<Option<R>>
where
    T: for<'t> Encode<'t, Postgres> + Send + sqlx::Type<sqlx::Postgres> + DbPrimaryUuid,
    R: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin + DbTable,
{
    delete_object_where_unique_column(txn, T::db_primary_uuid_name(), id).await
}

pub async fn delete_object_where_unique_column<T, R>(
    txn: &mut Transaction<'_, Postgres>,
    col_name: &str,
    value: T,
) -> eyre::Result<Option<R>>
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
        .fetch_optional(&mut **txn)
        .await?;
    Ok(result)
}
