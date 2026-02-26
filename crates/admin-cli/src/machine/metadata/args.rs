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

use carbide_uuid::machine::MachineId;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub enum Args {
    #[clap(about = "Set the Name or Description of the Machine")]
    Set(MachineMetadataCommandSet),
    #[clap(about = "Show the Metadata of the Machine")]
    Show(MachineMetadataCommandShow),
    #[clap(about = "Adds a label to the Metadata of a Machine")]
    AddLabel(MachineMetadataCommandAddLabel),
    #[clap(about = "Removes labels from the Metadata of a Machine")]
    RemoveLabels(MachineMetadataCommandRemoveLabels),
    #[clap(about = "Copy Machine Metadata from Expected-Machine to Machine")]
    FromExpectedMachine(MachineMetadataCommandFromExpectedMachine),
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandShow {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: MachineId,
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandSet {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: MachineId,
    #[clap(long, help = "The updated name of the Machine")]
    pub name: Option<String>,
    #[clap(long, help = "The updated description of the Machine")]
    pub description: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandAddLabel {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: MachineId,
    #[clap(long, help = "The key to add")]
    pub key: String,
    #[clap(long, help = "The optional value to add")]
    pub value: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandRemoveLabels {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: MachineId,
    #[clap(long, help = "The keys to remove")]
    pub keys: Vec<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandFromExpectedMachine {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: MachineId,
    /// Whether to fully replace the Metadata that is currently stored on the Machine.
    /// - If not set, existing Metadata on the Machine will not be touched by executing
    ///   the command:
    ///   - The existing Name will not be changed if the Name is not equivalent
    ///     to the Machine ID or Empty.
    ///   - The existing Description will not be changed if it is not empty.
    ///   - Existing Labels and their values will not be changed. Only labels which
    ///     do not exist on the Machine will be added.
    /// - If set, the Machines Metadata will be set to the same values as
    ///   they would if the Machine would get freshly ingested.
    ///   Metadata that is currently set on the Machine will be overridden.
    #[clap(long, verbatim_doc_comment)]
    pub replace_all: bool,
}
