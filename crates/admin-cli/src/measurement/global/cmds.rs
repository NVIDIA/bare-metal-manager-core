/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
