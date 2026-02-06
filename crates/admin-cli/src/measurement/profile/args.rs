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
 *  Measured Boot CLI arguments for the `measurement profile` subcommand.
 *
 * This provides the CLI subcommands and arguments for:
 *  - `profile create`: Create a new system profile.
 *  - `profile delete`: Delete an existing system profile.
 *  - `profile rename`: Rename an existing system profile.
 *  - `profile show`: Show all info about system profile(s).
 *  - `profile list all`: List high level info about all profiles.
 *  - `profile list bundles`: List all bundles for a given profile.
 *  - `profile list machines`: List all machines for a given profile.
*/

use clap::Parser;

use crate::cfg::measurement::{KvPair, parse_colon_pairs};
use crate::measurement::global::cmds::IdNameIdentifier;

// CmdProfile provides a container for the `profile`
// subcommand, which itself contains other subcommands
// for working with profiles.
#[derive(Parser, Debug)]
pub enum CmdProfile {
    #[clap(
        about = "Create a new profile with a given config.",
        visible_alias = "c"
    )]
    Create(Create),

    #[clap(about = "Delete a profile by ID or name.", visible_alias = "d")]
    Delete(Delete),

    #[clap(about = "Rename a profile.", visible_alias = "r")]
    Rename(Rename),

    #[clap(about = "Show profiles in different ways.", visible_alias = "s")]
    Show(Show),

    #[clap(
        subcommand,
        about = "List profiles by various ways.",
        visible_alias = "l"
    )]
    List(List),
}

/// Create is used for creating profiles.
#[derive(Parser, Debug)]
pub struct Create {
    #[clap(required = true, help = "Every profile gets a name.")]
    pub name: String,

    #[clap(required = true, help = "The hardware vendor (e.g. dell).")]
    pub vendor: String,

    #[clap(required = true, help = "The hardware product (e.g. poweredge_r750).")]
    pub product: String,

    /// extra_attrs are extra k:v,... attributes to be
    /// assigned to the profile. Currently the only
    /// formal attributes are vendor and product, and
    /// this is intended for testing purposes only.
    #[clap(
        long,
        use_value_delimiter = true,
        value_delimiter = ',',
        help = "A comma-separated list of additional k:v,k:v,... attributes to set."
    )]
    #[arg(value_parser = parse_colon_pairs)]
    pub extra_attrs: Vec<KvPair>,
}

/// Delete a profile by ID or name.
#[derive(Parser, Debug)]
pub struct Delete {
    #[clap(help = "The profile ID or name.")]
    pub identifier: String,

    #[clap(long, help = "Explicitly say the identifier is profile ID.")]
    pub is_id: bool,

    #[clap(long, help = "Explicitly say the identifier is a profile name.")]
    pub is_name: bool,
}

impl IdNameIdentifier for Delete {
    fn is_id(&self) -> bool {
        self.is_id
    }

    fn is_name(&self) -> bool {
        self.is_name
    }
}

/// Rename will rename a profile for the given ID or name.
/// A parser will parse the `identifier` to determine if
/// the API should be called w/ an ID or name selector.
#[derive(Parser, Debug)]
pub struct Rename {
    #[clap(help = "The existing profile ID or name.")]
    pub identifier: String,

    #[clap(help = "The new profile name.")]
    pub new_profile_name: String,

    #[clap(long, help = "Explicitly say the identifier is profile ID.")]
    pub is_id: bool,

    #[clap(long, help = "Explicitly say the identifier is a profile name.")]
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

/// Show will get + display a profile for the given ID or name, or, if not set,
/// it will display all profiles and their information.
#[derive(Parser, Debug)]
pub struct Show {
    #[clap(help = "The optional profile ID or name.")]
    pub identifier: Option<String>,

    #[clap(long, help = "Explicitly say the identifier is profile ID.")]
    pub is_id: bool,

    #[clap(long, help = "Explicitly say the identifier is a profile name.")]
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

/// List provides a few ways to list things.
#[derive(Parser, Debug)]
pub enum List {
    #[clap(about = "List all profiles", visible_alias = "a")]
    All(ListAll),

    #[clap(
        about = "List all bundles for a given profile ID or name.",
        visible_alias = "b"
    )]
    Bundles(ListBundles),

    #[clap(
        about = "List all machines for a given profile ID or name.",
        visible_alias = "m"
    )]
    Machines(ListMachines),
}

/// ListAll will list all profiles.
#[derive(Parser, Debug)]
pub struct ListAll {}

/// List all bundles for a given profile (by profile name or ID).
#[derive(Parser, Debug)]
pub struct ListBundles {
    #[clap(help = "The profile ID or name.")]
    pub identifier: String,

    #[clap(long, help = "Explicitly say the identifier is profile ID.")]
    pub is_id: bool,

    #[clap(long, help = "Explicitly say the identifier is a profile name.")]
    pub is_name: bool,
}

impl IdNameIdentifier for ListBundles {
    fn is_id(&self) -> bool {
        self.is_id
    }

    fn is_name(&self) -> bool {
        self.is_name
    }
}

/// List all machines for a given profile (by profile name or ID).
#[derive(Parser, Debug)]
pub struct ListMachines {
    #[clap(help = "The profile ID or name.")]
    pub identifier: String,

    #[clap(long, help = "Explicitly say the identifier is profile ID.")]
    pub is_id: bool,

    #[clap(long, help = "Explicitly say the identifier is a profile name.")]
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
