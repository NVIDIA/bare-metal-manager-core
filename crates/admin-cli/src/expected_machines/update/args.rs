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

use clap::Parser;

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
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct Args {
    #[clap(
        short,
        long,
        help = "Path to JSON file containing the expected machine data"
    )]
    pub filename: String,
}
