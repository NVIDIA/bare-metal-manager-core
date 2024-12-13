use std::error::Error;
use std::fmt;

pub mod domain;
pub mod infiniband;
pub mod instance;
pub mod instance_type;
pub mod machine;
pub mod measured_boot;
pub mod network;
pub mod typed_uuids;
pub mod vpc;

#[derive(Debug)]
pub struct UuidEmptyStringError;

impl fmt::Display for UuidEmptyStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "input UUID string cannot be empty",)
    }
}

impl Error for UuidEmptyStringError {}

/// DbPrimaryUuid is a trait intended for primary keys which
/// derive the sqlx UUID type. The intent is the db_primary_uuid_name
/// function should return the name of the column for the primary
/// UUID-typed key, which allows dynamic compositon of a SQL query.
///
/// This was originally introduced as part of the measured boot
/// generics (and lived in src/measured_boot/), but moved here.
pub trait DbPrimaryUuid {
    fn db_primary_uuid_name() -> &'static str;
}

/// DbTable is a trait intended for table records which derive
/// sqlx FromRow. The intent here is db_table_name() will return
/// the actual name of the table the records are in, allowing for
/// dynamic composition of an SQL query for that table.
///
/// This was originally introduced as part of the measured boot
/// generics (and lived in src/measured_boot/), but moved here.
pub trait DbTable {
    fn db_table_name() -> &'static str;
}
