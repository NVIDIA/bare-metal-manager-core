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

use ::rpc::forge::EraseHostMetadataByBmcMacRequest;

use super::args::Args;
use crate::errors::{CarbideCliError, CarbideCliResult};
use crate::rpc::ApiClient;

pub async fn erase_metadata(api_client: &ApiClient, args: Args) -> CarbideCliResult<()> {
    // Guard the destructive path: a real run must be explicitly confirmed. --dry-run
    // is always safe, so it does not require --confirm. Return an error (non-zero
    // exit) so scripts can distinguish a refused run from a completed one.
    if !args.dry_run && !args.confirm {
        return Err(CarbideCliError::GenericError(format!(
            "Refusing to erase records for BMC MAC {} without confirmation. \
             Re-run with --dry-run to preview, or add --confirm to proceed.",
            args.bmc_mac
        )));
    }

    let req: EraseHostMetadataByBmcMacRequest = (&args).into();
    let response = api_client.0.erase_host_metadata_by_bmc_mac(req).await?;

    if response.dry_run {
        println!("DRY RUN -- no records were deleted. The following would be erased:");
    } else {
        println!("Erased the following records for BMC MAC {}:", args.bmc_mac);
    }
    println!("{}", serde_json::to_string_pretty(&response)?);

    Ok(())
}
