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
 *  Measured Boot CLI arguments for the `measurement journal` subcommand.
 *
 * This provides the CLI subcommands and arguments for:
 *  - `journal delete`: Delete a journal entry.
 *  - `journal show`: Show all info about journal entr(ies).
 *  - `journal list`: List all journal entries.
 *  - `journal promote`: Promote the report from a journal entry into a bundle.
*/

use carbide_uuid::machine::MachineId;
use carbide_uuid::measured_boot::MeasurementJournalId;
use clap::Parser;
use measured_boot::pcr::{PcrSet, parse_pcr_index_input};

/// CmdJournal provides a container for the `journal` subcommand, which itself
/// contains other subcommands for working with journals.
#[derive(Parser, Debug)]
pub enum CmdJournal {
    #[clap(about = "Delete a journal entry.", visible_alias = "d")]
    Delete(Delete),

    #[clap(about = "Show a journal entry by ID, or all.", visible_alias = "s")]
    Show(Show),

    #[clap(about = "List all journal IDs and machines.", visible_alias = "l")]
    List(List),

    #[clap(
        about = "Promote a journal entry report to a bundle.",
        visible_alias = "p"
    )]
    Promote(Promote),
}

/// Delete is used to delete an existing journal entry.
#[derive(Parser, Debug)]
pub struct Delete {
    #[clap(help = "The journal ID to delete.")]
    pub journal_id: MeasurementJournalId,
}

/// List is used to list all journal entry IDs.
#[derive(Parser, Debug)]
pub struct List {
    #[clap(help = "List journal entries for a machine ID.")]
    pub machine_id: Option<MachineId>,
}

/// Show is used to show a journal entry based on ID, or all entries
/// if no ID is provided.
#[derive(Parser, Debug)]
pub struct Show {
    #[clap(help = "The optional journal entry ID.")]
    pub journal_id: Option<MeasurementJournalId>,
}

/// Promote is used to promote a journal entry's report
/// into a measurement bundle.
#[derive(Parser, Debug)]
pub struct Promote {
    #[clap(help = "The journal entry ID to promote a report from.")]
    pub journal_id: MeasurementJournalId,

    #[clap(
        long,
        help = "Select specific PCR range(s) to use for the promoted bundle."
    )]
    #[arg(value_parser = parse_pcr_index_input)]
    pub pcr_registers: Option<PcrSet>,
}
