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

use crate::errors::CarbideCliResult;
use crate::rpc::ApiClient;

use super::args::{MachineArgs, SiteArgs};

pub async fn decommission_machine(args: MachineArgs, api_client: &ApiClient) -> CarbideCliResult<()> {
    let req = rpc::forge::AdminDecommissionMachineRequest::from(&args);
    let response = api_client.0.admin_decommission_machine(req).await?;
    println!(
        "Decommission initiated for machine {}. The machine will progress through BMC reset, \
         credential deletion, and MAC blocking before being removed.",
        response.machine_id,
    );
    Ok(())
}

pub async fn decommission_site(args: SiteArgs, api_client: &ApiClient) -> CarbideCliResult<()> {
    let req = rpc::forge::AdminDecommissionSiteRequest::from(&args);
    let response = api_client.0.admin_decommission_site(req).await?;
    println!(
        "Site decommission initiated.\n  \
         Machines immediately decommissioned (were Ready): {}\n  \
         Machines pending decommission (PreventAllocations applied): {}",
        response.machines_started, response.machines_pending,
    );
    Ok(())
}
