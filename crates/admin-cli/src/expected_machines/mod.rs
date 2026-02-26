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

mod add;
pub(crate) mod common;
mod delete;
mod erase;
mod patch;
mod replace_all;
mod show;
mod update;

#[cfg(test)]
mod tests;

use clap::Parser;

use crate::cfg::dispatch::Dispatch;

#[derive(Parser, Debug, Dispatch)]
pub enum Cmd {
    #[clap(about = "Show expected machine data")]
    Show(show::Args),
    #[clap(about = "Add expected machine")]
    Add(add::Args),
    #[clap(about = "Delete expected machine")]
    Delete(delete::Args),
    /// Patch expected machine (partial update, preserves unprovided fields).
    ///
    /// Only the fields provided in the command will be updated. All other fields remain unchanged.
    ///
    /// Examples:
    ///   # Update only SKU, preserve all other fields including metadata
    ///   forge-admin-cli expected-machine patch --bmc-mac-address 1a:1b:1c:1d:1e:1f --sku-id new_sku
    ///
    ///   # Update only labels, preserve name and description
    ///   forge-admin-cli expected-machine patch --bmc-mac-address 1a:1b:1c:1d:1e:1f \
    ///     --sku-id sku123 --label env:prod --label team:platform
    #[clap(verbatim_doc_comment)]
    Patch(patch::Args),
    /// Update expected machine from JSON file (full replacement, consistent with API).
    ///
    /// All fields from the JSON file will completely replace the existing record.
    /// This allows clearing metadata fields by providing empty values.
    ///
    /// Example json file:
    ///    {
    ///        "bmc_mac_address": "1a:1b:1c:1d:1e:1f",
    ///        "bmc_username": "user",
    ///        "bmc_password": "pass",
    ///        "chassis_serial_number": "sample_serial-1",
    ///        "fallback_dpu_serial_numbers": ["MT020100000003"],
    ///        "metadata": {
    ///            "name": "MyMachine",
    ///            "description": "My Machine",
    ///            "labels": [{"key": "ABC", "value": "DEF"}]
    ///        },
    ///        "sku_id": "sku_id_123"
    ///    }
    ///
    /// Usage:
    ///   forge-admin-cli expected-machine update --filename machine.json
    #[clap(verbatim_doc_comment)]
    Update(update::Args),
    /// Replace all entries in the expected machines table with the entries from an inputted json file.
    ///
    /// Example json file:
    ///    {
    ///        "expected_machines":
    ///        [
    ///            {
    ///                "bmc_mac_address": "1a:1b:1c:1d:1e:1f",
    ///                "bmc_username": "user",
    ///                "bmc_password": "pass",
    ///                "chassis_serial_number": "sample_serial-1"
    ///            },
    ///            {
    ///                "bmc_mac_address": "2a:2b:2c:2d:2e:2f",
    ///                "bmc_username": "user",
    ///                "bmc_password": "pass",
    ///                "chassis_serial_number": "sample_serial-2",
    ///                "fallback_dpu_serial_numbers": ["MT020100000003"],
    ///                "metadata": {
    ///                    "name": "MyMachine",
    ///                    "description": "My Machine",
    ///                    "labels": [{"key": "ABC", "value": "DEF"}]
    ///                }
    ///            }
    ///        ]
    ///    }
    #[clap(verbatim_doc_comment)]
    ReplaceAll(replace_all::Args),
    #[clap(about = "Erase all expected machines")]
    Erase(erase::Args),
}
