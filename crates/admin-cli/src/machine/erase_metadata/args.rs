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
use rpc::forge::EraseHostMetadataByBmcMacRequest;

/// Erase all NICo-owned site records for a server BMC MAC address.
#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

Preview which records exist for a BMC MAC (nothing is deleted):
    $ nico-admin-cli machine erase-metadata --bmc-mac 00:11:22:33:44:55 --dry-run

Erase all lingering records for a BMC MAC to prepare for re-ingestion:
    $ nico-admin-cli machine erase-metadata --bmc-mac 00:11:22:33:44:55 --confirm

")]
pub struct Args {
    #[clap(
        long,
        required(true),
        help = "Server BMC MAC address whose lingering site records should be erased"
    )]
    pub bmc_mac: String,

    #[clap(
        long,
        action,
        help = "Report the records that would be erased without deleting anything"
    )]
    pub dry_run: bool,

    #[clap(
        long,
        action,
        help = "Confirm you want to erase these records. Required for a real run (ignored with --dry-run)."
    )]
    pub confirm: bool,
}

impl From<&Args> for EraseHostMetadataByBmcMacRequest {
    fn from(args: &Args) -> Self {
        Self {
            bmc_mac: args.bmc_mac.clone(),
            dry_run: args.dry_run,
        }
    }
}
