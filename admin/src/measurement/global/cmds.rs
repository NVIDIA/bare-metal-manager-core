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

//!
//! Global commands at the root of the CLI, as well as some helper
//! functions used by main.
//!

use crate::cfg::carbide_options::OutputFormat;
use crate::cfg::measurement::GlobalOptions;
use crate::{CarbideCliError, CarbideCliResult};
use ::rpc::forge_tls_client::{ApiConfig, ForgeClientT, ForgeTlsClient};
use carbide::measured_boot::interface::common::{convert_to_table, ToTable};

use serde::Serialize;
use serde_json;
use serde_yaml;
use std::fs::File;
use std::io::Write;

pub async fn get_forge_client<'a>(api_config: &ApiConfig<'a>) -> CarbideCliResult<ForgeClientT> {
    ForgeTlsClient::retry_build(api_config)
        .await
        .map_err(|err| CarbideCliError::ApiConnectFailed(err.to_string()))
}

/// CliData is a simple struct containing the single database connection
/// and parsed arguments, which is passed down to all subcommands.

pub struct CliData<'g, 'a> {
    pub grpc_conn: &'g mut ForgeClientT,
    pub args: &'a GlobalOptions,
}

/// IdentifierType is a enum that stores the identifer
/// type when providing a name or ID-based option via the
/// CLI.
pub trait IdNameIdentifier {
    fn is_id(&self) -> bool;
    fn is_name(&self) -> bool;
}

pub enum IdentifierType {
    ForId,
    ForName,
    Detect,
}

pub fn get_identifier<T>(args: &T) -> eyre::Result<IdentifierType>
where
    T: IdNameIdentifier,
{
    if args.is_id() && args.is_name() {
        return Err(eyre::eyre!(
            "identifier cant be an ID *and* a name, u so silly"
        ));
    }

    if args.is_id() {
        return Ok(IdentifierType::ForId);
    }
    if args.is_name() {
        return Ok(IdentifierType::ForName);
    }
    Ok(IdentifierType::Detect)
}

/// Destination is an enum used to determine whether CLI output is going
/// to a file path or stdout.
pub enum Destination {
    Path(String),
    Stdout(),
}

/// cli_output is the generic function implementation used by the OutputResult
/// trait, allowing callers to pass a Serialize-derived struct and have it
/// print in either JSON or YAML.
pub fn cli_output<T: Serialize + ToTable>(
    input: T,
    format: &OutputFormat,
    destination: Destination,
) -> eyre::Result<()> {
    let output = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&input)?,
        OutputFormat::Yaml => serde_yaml::to_string(&input)?,
        OutputFormat::AsciiTable => convert_to_table(&input)?,
        OutputFormat::Csv => {
            return Err(eyre::eyre!(
                "CSV not supported for measurement commands (yet)"
            ))
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
