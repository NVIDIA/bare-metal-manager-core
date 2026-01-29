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

/// admin_cli.rs
///
/// General utility code for working with and displaying data
/// with the admin CLI.

*/

use std::env;
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

use carbide_uuid::dpu_remediations::RemediationId;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::{MachineId, MachineIdParseError};
pub use output::{Destination, OutputFormat};
use serde::Serialize;
#[cfg(feature = "sqlx")]
use sqlx::{Pool, Postgres};

use crate::errors;
use crate::forge::MachineType;
use crate::forge_tls_client::ForgeTlsClientError;

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
    ApiConnectFailed(#[from] ForgeTlsClientError),

    #[error("The API call to the Forge API server returned {0}")]
    ApiInvocationError(#[from] tonic::Status),

    #[error("Error while writing into string: {0}")]
    StringWriteError(#[from] std::fmt::Error),

    #[error("Generic Error: {0}")]
    GenericError(String),

    #[error("Invalid datetime format: {0}. Use 'YYYY-MM-DD HH:MM:SS' or 'HH:MM:SS'")]
    InvalidDateTimeFromUserInput(String),

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

    #[error("Error while handling csv: {0}")]
    CsvError(#[from] csv::Error),

    #[error("Unexpected machine type.  expected {0:?} but found {1:?}")]
    UnexpectedMachineType(MachineType, MachineType),

    #[error("Host machine with id {0} not found")]
    MachineNotFound(MachineId),

    #[error("Remediation with id {0} not found")]
    RemediationNotFound(RemediationId),

    #[error("Instance with id {0} not found")]
    InstanceNotFound(InstanceId),

    #[error("Tenant with id {0} not found")]
    TenantNotFound(String),

    #[error("I/O error. Does the file exist? {0}")]
    IOError(#[from] std::io::Error),

    /// For when you expected some values but the response was empty.
    /// If empty is acceptable don't use this.
    #[error("No results returned")]
    Empty,

    #[error("Not Implemented {0}")]
    NotImplemented(String),

    #[error("Invalid Machine ID: {0}")]
    InvalidMachineId(#[from] MachineIdParseError),

    #[error("RPC data conversion error: {0}")]
    RpcDataConversionError(#[from] errors::RpcDataConversionError),

    #[error("Invalid Routing Profile Type: {0}")]
    InvalidRoutingProfileType(String),

    #[error(transparent)]
    EyreReport(eyre::Report),
}

impl From<eyre::Report> for CarbideCliError {
    // For commands that are [still] returning an eyre::Report,
    // and not a CarbideCliError, preserve the full report and
    // error chain for complete context.
    fn from(err: eyre::Report) -> Self {
        CarbideCliError::EyreReport(err)
    }
}

pub type CarbideCliResult<T> = Result<T, CarbideCliError>;

/// ToTable is a trait which is used alongside the cli_output command
/// and being able to prettytable print results.
pub trait ToTable {
    fn into_table(self) -> eyre::Result<String>
    where
        Self: Sized,
    {
        Ok("not implemented".to_string())
    }
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
        OutputFormat::AsciiTable => input
            .into_table()
            .map_err(|e| CarbideCliError::GenericError(e.to_string()))?,
        OutputFormat::Csv => {
            return Err(CarbideCliError::GenericError(String::from(
                "CSV not supported for measurement commands (yet)",
            )));
        }
    };

    match destination {
        Destination::Path(path) => {
            let mut file = File::create(path)?;
            file.write_all(output.as_bytes())?
        }
        Destination::Stdout() => println!("{output}"),
    }

    Ok(())
}

pub mod output {
    use std::fs::File;
    use std::io::{Write, stdout};

    use clap::ValueEnum;
    use serde::Serialize;
    pub use table::IntoTable;
    use table::{render_ascii_table, render_csv_table};

    /// Destination is an enum used to determine whether CLI output is going
    /// to a file path or stdout.
    pub enum Destination {
        Path(String),
        Stdout(),
    }

    #[derive(Default, PartialEq, Eq, ValueEnum, Clone, Copy, Debug)]
    #[clap(rename_all = "kebab_case")]
    pub enum OutputFormat {
        #[default]
        AsciiTable,
        Csv,
        Json,
        Yaml,
    }

    /// The FormattedOutput trait allows you to handle CLI output for a data
    /// structure. It has no required methods, however you do need to implement
    /// serde::Serialize and our own IntoTable trait, as this is a supertrait of
    /// those two.
    pub trait FormattedOutput: Serialize + IntoTable {
        /// Format the output data as bytes (probably UTF-8 text).
        fn format_output(&self, format: OutputFormat) -> Vec<u8> {
            match format {
                OutputFormat::Json => {
                    serde_json::to_vec_pretty(self).expect("Could not serialize as JSON")
                }
                OutputFormat::Yaml => {
                    let mut out = Vec::new();
                    serde_yaml::to_writer(&mut out, self).expect("Could not serialize as YAML");
                    out
                }
                OutputFormat::AsciiTable => render_ascii_table(self),
                OutputFormat::Csv => render_csv_table(self),
            }
        }

        /// Format the output data and write it to the specified destination.
        fn write_output(
            &self,
            format: OutputFormat,
            destination: Destination,
        ) -> std::io::Result<()> {
            let output = self.format_output(format);
            match destination {
                Destination::Stdout() => {
                    let mut stdout_guard = stdout().lock();
                    stdout_guard.write_all(output.as_slice())
                }
                Destination::Path(path) => {
                    File::create(path).and_then(|mut file| file.write_all(output.as_slice()))
                }
            }
        }
    }

    pub mod table {
        use std::borrow::Cow;

        use prettytable::{Row, Table};

        /// The IntoTable trait is used to help the AsciiTable and CSV
        /// formatters turn a data structure into tabular data.
        pub trait IntoTable: Sized {
            type Row;

            /// Return the header with the titles for each column. These should
            /// be ordered the same as in the `.row_values()` implementation.
            fn header(&self) -> &[&str];

            /// Return a slice spanning all of the rows.
            fn all_rows(&self) -> &[Self::Row];

            /// Return a Vec with the text values for this row, in the same
            /// order as `.header()`. If the Row's internal fields contain
            /// values represented as strings, these values can be returned as
            /// Cow::Borrowed, and if not you will need to string-format them
            /// and return these as Cow::Owned.
            fn row_values(row: &'_ Self::Row) -> Vec<Cow<'_, str>>;

            // fn render_text_table(&self) -> String {
            //     let table = make_table(self);
            //     format!("{table}")
            // }
        }

        // This is not a trait method in order to keep the `prettytable` types
        // out of the public API.
        fn make_table<T>(data_source: &T) -> Table
        where
            T: IntoTable,
        {
            let mut table = Table::new();
            let header = Row::from(data_source.header());
            table.set_titles(header);
            let rows = data_source.all_rows();
            rows.iter().for_each(|row| {
                let values = T::row_values(row);
                let row = Row::from(values);
                table.add_row(row);
            });

            table
        }

        pub fn render_ascii_table<T>(data_source: &T) -> Vec<u8>
        where
            T: IntoTable,
        {
            let mut out = Vec::new();
            let table = make_table(data_source);
            table.print(&mut out).expect("Couldn't render ASCII table");
            out
        }

        pub fn render_csv_table<T>(data_source: &T) -> Vec<u8>
        where
            T: IntoTable,
        {
            let mut out = Vec::new();
            let table = make_table(data_source);
            table.to_csv(&mut out).expect("Couldn't render CSV table");
            out
        }
    }
}
