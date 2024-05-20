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
/// cli/args/journal.rs
/// Measured Boot CLI arguments for the `journal` subcommand.
///
/// - journal delete
/// - journal show
/// - journal list
///////////////////////////////////////////////////////////////////////////////
*/

use carbide::measured_boot::dto::keys::{MeasurementJournalId, MockMachineId};
use clap::Parser;

///////////////////////////////////////////////////////////////////////////////
/// CmdJournal provides a container for the `journal` subcommand, which itself
/// contains other subcommands for working with journals.
///////////////////////////////////////////////////////////////////////////////

#[derive(Parser, Debug)]
pub enum CmdJournal {
    #[clap(about = "Delete a journal entry.", visible_alias = "d")]
    Delete(Delete),

    #[clap(about = "Show a journal entry by ID, or all.", visible_alias = "s")]
    Show(Show),

    #[clap(about = "List all journal IDs and machines.", visible_alias = "l")]
    List(List),
}

///////////////////////////////////////////////////////////////////////////////
/// Delete is used to delete an existing journal entry.
///////////////////////////////////////////////////////////////////////////////

#[derive(Parser, Debug)]
pub struct Delete {
    #[clap(help = "The journal ID to delete.")]
    pub journal_id: MeasurementJournalId,
}

///////////////////////////////////////////////////////////////////////////////
/// List is used to list all journal entry IDs.
///////////////////////////////////////////////////////////////////////////////

#[derive(Parser, Debug)]
pub struct List {
    #[clap(help = "List journal entries for a machine ID.")]
    pub machine_id: Option<MockMachineId>,
}

///////////////////////////////////////////////////////////////////////////////
/// Show is used to show a journal entry based on ID, or all entries
/// if no ID is provided.
///////////////////////////////////////////////////////////////////////////////

#[derive(Parser, Debug)]
pub struct Show {
    #[clap(help = "The optional journal entry ID.")]
    pub journal_id: Option<MeasurementJournalId>,
}
