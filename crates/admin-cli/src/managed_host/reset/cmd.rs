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
use crate::errors::{CarbideCliError, CarbideCliResult};
use crate::machine::{HealthReportTemplates, get_health_report};
use crate::rpc::ApiClient;

pub(super) async fn reset(api_client: &ApiClient, args: Args) -> CarbideCliResult<()> {
    // Fail closed: refuse a reset that would disrupt a live instance unless acknowledged (the server also enforces this).
    if !args.allow_reset_with_instance {
        match api_client.0.find_instance_by_machine_id(args.machine).await {
            Ok(list) if !list.instances.is_empty() => {
                return Err(CarbideCliError::GenericError(
                    "machine is assigned to a live instance; pass --allow-reset-with-instance to acknowledge disrupting it".to_string(),
                ));
            }
            Ok(_) => {}
            Err(e) => {
                return Err(CarbideCliError::GenericError(format!(
                    "could not verify whether machine has a live instance ({e}); pass --allow-reset-with-instance to proceed anyway"
                )));
            }
        }
    }

    // Server requires a HostUpdateInProgress alert; add it only if absent so we never clobber an operator's.
    let update_message = args
        .update_message
        .clone()
        .unwrap_or_else(|| "reset triggered by admin-cli".to_string());
    let host_had_alert = api_client
        .get_machines_by_ids(&[args.machine])
        .await?
        .machines
        .into_iter()
        .next()
        .and_then(|m| m.status)
        .is_some_and(|s| {
            s.health_sources
                .iter()
                .any(|src| src.source == "host-update")
        });
    if !host_had_alert {
        let mut report = get_health_report(HealthReportTemplates::HostUpdate, Some(update_message));
        // Tag the alert reset-owned so completion cleanup removes only reset's alert, not an operator's.
        report.alerts[0].target =
            Some(model::machine_update_module::RESET_UPDATE_TARGET.to_string());
        api_client
            .machine_insert_health_report_override(args.machine, report.into(), false)
            .await?;
    }

    let req: DpuReprovisioningRequest = (&args).into();
    if let Err(e) = api_client.0.trigger_dpu_reprovisioning(req).await {
        // Roll back only the alert we added; leave a pre-existing operator alert untouched.
        if !host_had_alert {
            let _ = api_client
                .machine_remove_health_report(args.machine, "host-update".to_string())
                .await;
        }
        return Err(e.into());
    }
    Ok(())
}
