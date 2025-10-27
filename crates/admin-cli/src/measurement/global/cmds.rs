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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};

use crate::cfg::measurement::GlobalOptions;
use crate::rpc::ApiClient;

/// CliData is a simple struct containing the single database connection
/// and parsed arguments, which is passed down to all subcommands.
pub struct CliData<'g, 'a> {
    pub grpc_conn: &'g ApiClient,
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

pub fn get_identifier<T>(args: &T) -> CarbideCliResult<IdentifierType>
where
    T: IdNameIdentifier,
{
    if args.is_id() && args.is_name() {
        return Err(CarbideCliError::GenericError(String::from(
            "identifier cant be an ID *and* a name, u so silly",
        )));
    }

    if args.is_id() {
        return Ok(IdentifierType::ForId);
    }
    if args.is_name() {
        return Ok(IdentifierType::ForName);
    }
    Ok(IdentifierType::Detect)
}
