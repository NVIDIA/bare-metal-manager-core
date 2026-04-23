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

use ::rpc::admin_cli::CarbideCliResult;
use ::rpc::forge as rpc;

use super::args::MaintenanceOptions;
use crate::rpc::ApiClient;

pub async fn on_demand_rack_maintenance(
    api_client: &ApiClient,
    args: MaintenanceOptions,
) -> CarbideCliResult<()> {
    use rpc::maintenance_activity_config::Activity as ProtoActivity;

    let firmware_version = args.firmware_version.unwrap_or_default();
    let components = args.components.unwrap_or_default();

    let activities: Vec<rpc::MaintenanceActivityConfig> = args
         .activities
         .unwrap_or_default()
         .iter()
         .map(|s| {
             let activity = match s.as_str() {
                 "firmware-upgrade" => Ok(ProtoActivity::FirmwareUpgrade(
                     rpc::FirmwareUpgradeActivity {
                         firmware_version: firmware_version.clone(),
                         components: components.clone(),
                     },
                 )),
                 "configure-nmx-cluster" => Ok(ProtoActivity::ConfigureNmxCluster(
                     rpc::ConfigureNmxClusterActivity {},
                 )),
                 "power-sequence" => Ok(ProtoActivity::PowerSequence(
                     rpc::PowerSequenceActivity {},
                 )),
                 other => Err(eyre::eyre!(
                     "Unknown activity '{}'. Valid values: firmware-upgrade, configure-nmx-cluster, power-sequence",
                     other
                 )),
             }?;
            Ok::<_, eyre::Report>(rpc::MaintenanceActivityConfig {
                activity: Some(activity),
            })
         })
         .collect::<Result<Vec<_>, _>>()?;

    api_client
        .on_demand_rack_maintenance(
            args.rack,
            args.machine_ids.unwrap_or_default(),
            args.switch_ids.unwrap_or_default(),
            args.power_shelf_ids.unwrap_or_default(),
            activities,
        )
        .await?;
    println!("On-demand rack maintenance scheduled successfully.");
    Ok(())
}
