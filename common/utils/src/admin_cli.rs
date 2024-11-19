/*

/// admin_cli.rs
///
/// General utility code for working with and displaying data
/// with the admin CLI.

*/

use ::rpc::common::MachineId;
use ::rpc::forge::MachineType;
use clap::ValueEnum;
use serde::Serialize;
use std::env;
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "sqlx")]
use sqlx::{Pool, Postgres};

/// SUMMARY is a global variable that is being used by a few structs which
/// implement serde::Serialize with skip_serialization_if.
///
/// I had wanted the ability to have summarized or extended versions of
/// serialized output, and decided I could use skip_serialization_if along with
/// a function that looks at a global variable.
///
/// You set --extended on the CLI, which controls whether or not to summarized
/// (default is summarized).
static SUMMARY: AtomicBool = AtomicBool::new(false);

pub fn serde_just_print_summary<T>(_: &T) -> bool {
    SUMMARY.load(Ordering::SeqCst)
}

pub fn just_print_summary() -> bool {
    SUMMARY.load(Ordering::SeqCst)
}

pub fn set_summary(val: bool) {
    SUMMARY.store(val, Ordering::SeqCst);
}

/// get_db_url returns the full DB URL to use for connecting (and resetting,
/// if requested).
pub fn get_db_url(db_url: &str, db_name: &str) -> String {
    // Attempt to grab the DATABASE_URL first.
    // If it doesn't exist, fall back to args.db_url.
    let db_base = match env::var("DATABASE_URL") {
        Ok(val) => val,
        Err(_) => db_url.to_string(),
    };
    db_base + "/" + db_name
}

#[cfg(feature = "sqlx")]
/// connect connects to the database for the provided db_url, which probably
/// comes from get_db_url.
pub async fn connect(db_url: &str) -> eyre::Result<Pool<Postgres>> {
    let pool = sqlx::Pool::<sqlx::postgres::Postgres>::connect(db_url).await?;
    Ok(pool)
}

#[derive(thiserror::Error, Debug)]
pub enum CarbideCliError {
    #[error("Unable to connect to carbide API: {0}")]
    ApiConnectFailed(String),

    #[error("The API call to the Forge API server returned {0}")]
    ApiInvocationError(tonic::Status),

    #[error("Error while writing into string: {0}")]
    StringWriteError(#[from] std::fmt::Error),

    #[error("Generic Error: {0}")]
    GenericError(String),

    #[error("Segment not found.")]
    SegmentNotFound,

    #[error("Domain not found.")]
    DomainNotFound,

    #[error("Uuid not found.")]
    UuidNotFound,

    #[error("MAC not found.")]
    MacAddressNotFound,

    #[error("Serial number not found.")]
    SerialNumberNotFound,

    #[error("Error while handling json: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Error while handling yaml: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("Unexpected machine type.  expected {0:?} but found {1:?}")]
    UnexpectedMachineType(MachineType, MachineType),

    #[error("Host machine with id {0} not found")]
    MachineNotFound(MachineId),

    #[error("I/O error. Does the file exist? {0}")]
    IOError(#[from] std::io::Error),

    /// For when you expected some values but the response was empty.
    /// If empty is acceptable don't use this.
    #[error("No results returned")]
    Empty,
}

pub type CarbideCliResult<T> = Result<T, CarbideCliError>;

/// ToTable is a trait which is used alongside the cli_output command
/// and being able to prettytable print results.
pub trait ToTable {
    fn to_table(&self) -> eyre::Result<String> {
        Ok("not implemented".to_string())
    }
}

/// Destination is an enum used to determine whether CLI output is going
/// to a file path or stdout.
pub enum Destination {
    Path(String),
    Stdout(),
}

#[derive(PartialEq, Eq, ValueEnum, Clone, Debug)]
#[clap(rename_all = "kebab_case")]
pub enum OutputFormat {
    Json,
    Csv,
    AsciiTable,
    Yaml,
}

/// convert_to_table leverages input instances which
/// implement the ToTable trait for the purpose of
/// printing themselves as a prettytable.
pub fn convert_to_table<T: ToTable>(input: &T) -> eyre::Result<String> {
    input.to_table()
}

/// cli_output is the generic function implementation used by the OutputResult
/// trait, allowing callers to pass a Serialize-derived struct and have it
/// print in either JSON or YAML.
pub fn cli_output<T: Serialize + ToTable>(
    input: T,
    format: &OutputFormat,
    destination: Destination,
) -> CarbideCliResult<()> {
    let output = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&input)?,
        OutputFormat::Yaml => serde_yaml::to_string(&input)?,
        OutputFormat::AsciiTable => {
            convert_to_table(&input).map_err(|e| CarbideCliError::GenericError(e.to_string()))?
        }
        OutputFormat::Csv => {
            return Err(CarbideCliError::GenericError(String::from(
                "CSV not supported for measurement commands (yet)",
            )))
        }
    };

    match destination {
        Destination::Path(path) => {
            let mut file = File::create(path)?;
            file.write_all(output.as_bytes())?
        }
        Destination::Stdout() => println!("{}", output),
    }

    Ok(())
}
