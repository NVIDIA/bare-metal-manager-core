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

use ::rpc::forge::DpuReprovisioningRequest;

use super::args::Args;
use crate::errors::CarbideCliResult;
use crate::machine::{HealthReportTemplates, get_health_report};
use crate::rpc::ApiClient;

pub(super) async fn reset(api_client: &ApiClient, args: Args) -> CarbideCliResult<()> {
    // The server requires a HostUpdateInProgress (PreventAllocations) alert before
    // it accepts a reprovision; apply it here when a message is provided.
    if let Some(update_message) = &args.update_message {
        let report =
            get_health_report(HealthReportTemplates::HostUpdate, Some(update_message.clone()));
        api_client
            .machine_insert_health_report_override(args.machine, report.into(), false)
            .await?;
    }

    let req: DpuReprovisioningRequest = (&args).into();
    api_client.0.trigger_dpu_reprovisioning(req).await?;
    Ok(())
}
