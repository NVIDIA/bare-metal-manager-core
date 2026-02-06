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

/*!
 *  Measured Boot CLI arguments for the `measurement bundle` subcommand.
 *
 * This provides the CLI subcommands and arguments for:
 *  - `bundle create`: Create a new measurement bundle.
 *  - `bundle delete`: Delete an existing measurement bundle.
 *  - `bundle rename`: Rename an existing measurement bundle.
 *  - `bundle set-state`: Change the state of a measurement bundle.
 *  - `bundle show`: Show all details about measurement bundle(s).
 *  - `bundle list all`: List high level metadata about all bundles.
 *  - `bundle list machines`: List all matchines matching a given bundle.
*/

use carbide_uuid::measured_boot::{
    MeasurementBundleId, MeasurementReportId, MeasurementSystemProfileId,
};
use clap::Parser;
use measured_boot::pcr::PcrRegisterValue;
use measured_boot::records::MeasurementBundleState;

use crate::cfg::measurement::parse_pcr_register_values;
use crate::measurement::global::cmds::IdNameIdentifier;

/// CmdBundle provides a container for the `bundle` subcommand, which itself
/// contains other subcommands for working with profiles.
#[derive(Parser, Debug)]
pub enum CmdBundle {
    #[clap(
        about = "Create a new bundle with a given values, for a given profile ID.",
        visible_alias = "c"
    )]
    Create(Create),

    #[clap(about = "Delete a bundle based on ID", visible_alias = "d")]
    Delete(Delete),

    #[clap(about = "Rename a bundle.", visible_alias = "r")]
    Rename(Rename),

    #[clap(about = "Set a new state for a bundle.", visible_alias = "u")]
    SetState(SetState),

    #[clap(about = "Show a bundle (or all).", visible_alias = "s")]
    Show(Show),

    #[clap(
        subcommand,
        about = "Get closest bundle to a report.",
        visible_alias = "g"
    )]
    FindClosestMatch(FindClosestMatch),

    #[clap(
        subcommand,
        about = "List bundles by various ways.",
        visible_alias = "l"
    )]
    List(List),
}

/// Create is used to create a new bundle, associated with a given profile ID
/// or profile name, with provided PCR values and an optional
/// MeasurementBundleState (the default is 'active').
#[derive(Parser, Debug)]
pub struct Create {
    #[clap(help = "A human-readable name to give this bundle.")]
    pub name: String,

    #[clap(help = "The profile ID of the profile to associate this bundle with.")]
    pub profile_id: MeasurementSystemProfileId,

    #[clap(
        required = true,
        use_value_delimiter = true,
        value_delimiter = ',',
        help = "Comma-separated list of {pcr_register:value,...} to associate with this bundle."
    )]
    #[arg(value_parser = parse_pcr_register_values)]
    pub values: Vec<PcrRegisterValue>,

    // state is optional, and if unset, the database itself
    // is configured to default to 'active'.
    #[clap(
        long,
        value_enum,
        help = "The state for this bundle (default: active)."
    )]
    pub state: Option<MeasurementBundleState>,
}

/// Delete will delete a bundle for the given ID.
#[derive(Parser, Debug)]
pub struct Delete {
    #[clap(help = "The bundle ID.")]
    pub bundle_id: MeasurementBundleId,

    #[clap(long, help = "Also purge any journal records for this bundle.")]
    pub purge_journals: bool,
}

/// Rename will rename a bundle for the given ID or name.
/// A parser will parse the `identifier` to determine if
/// the API should be called w/ an ID or name selector.
#[derive(Parser, Debug)]
pub struct Rename {
    #[clap(help = "The existing bundle ID or name.")]
    pub identifier: String,

    #[clap(help = "The new bundle name.")]
    pub new_bundle_name: String,

    #[clap(long, help = "Explicitly say the identifier is bundle ID.")]
    pub is_id: bool,

    #[clap(long, help = "Explicitly say the identifier is a bundle name.")]
    pub is_name: bool,
}

impl IdNameIdentifier for Rename {
    fn is_id(&self) -> bool {
        self.is_id
    }

    fn is_name(&self) -> bool {
        self.is_name
    }
}

/// Show will get + display a bundle for the given ID, or, if not ID is set,
/// it will display all bundles and their information.
#[derive(Parser, Debug)]
pub struct Show {
    #[clap(help = "The optional bundle ID or name.")]
    pub identifier: Option<String>,

    #[clap(long, help = "Explicitly say the identifier is bundle ID.")]
    pub is_id: bool,

    #[clap(long, help = "Explicitly say the identifier is a bundle name.")]
    pub is_name: bool,
}

impl IdNameIdentifier for Show {
    fn is_id(&self) -> bool {
        self.is_id
    }

    fn is_name(&self) -> bool {
        self.is_name
    }
}

/// SetState is used to set the state of the bundle (e.g. active, obsolete,
/// retired, revoked).
#[derive(Parser, Debug)]
pub struct SetState {
    #[clap(help = "The bundle ID or name to update.")]
    pub identifier: String,

    #[clap(
        required = true,
        value_enum,
        help = "The state to set for this bundle."
    )]
    pub state: MeasurementBundleState,

    #[clap(long, help = "Explicitly say the identifier is bundle ID.")]
    pub is_id: bool,

    #[clap(long, help = "Explicitly say the identifier is a bundle name.")]
    pub is_name: bool,
}

impl IdNameIdentifier for SetState {
    fn is_id(&self) -> bool {
        self.is_id
    }

    fn is_name(&self) -> bool {
        self.is_name
    }
}

/// List provides a few ways to list things.
#[derive(Parser, Debug)]
pub enum List {
    #[clap(about = "List all bundles", visible_alias = "a")]
    All(ListAll),

    #[clap(
        about = "List all machines for a given bundle ID.",
        visible_alias = "m"
    )]
    Machines(ListMachines),
}

/// ListAll will list all bundles.
#[derive(Parser, Debug)]
pub struct ListAll {}

/// ListMachines lists all machines for a given bundle (by bundle name or ID).
#[derive(Parser, Debug)]
pub struct ListMachines {
    #[clap(help = "The existing bundle ID or name.")]
    pub identifier: String,

    #[clap(long, help = "Explicitly say the identifier is bundle ID.")]
    pub is_id: bool,

    #[clap(long, help = "Explicitly say the identifier is a bundle name.")]
    pub is_name: bool,
}

impl IdNameIdentifier for ListMachines {
    fn is_id(&self) -> bool {
        self.is_id
    }

    fn is_name(&self) -> bool {
        self.is_name
    }
}

#[derive(Parser, Debug)]
pub enum FindClosestMatch {
    #[clap(about = "The existing report ID.")]
    Report(ReportId),
}

#[derive(Parser, Debug)]
pub struct ReportId {
    #[clap(help = "Report ID.")]
    pub id: MeasurementReportId,
}
