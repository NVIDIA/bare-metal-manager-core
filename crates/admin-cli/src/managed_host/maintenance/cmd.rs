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
use ::rpc::forge as forgerpc;

use super::args::{Args, MaintenanceOff, MaintenanceOn};
use crate::rpc::ApiClient;

pub async fn maintenance_on(api_client: &ApiClient, args: MaintenanceOn) -> CarbideCliResult<()> {
    let req = forgerpc::MaintenanceRequest {
        operation: forgerpc::MaintenanceOperation::Enable.into(),
        host_id: Some(args.host),
        reference: Some(args.reference),
    };
    api_client.0.set_maintenance(req).await?;
    Ok(())
}

pub async fn maintenance_off(api_client: &ApiClient, args: MaintenanceOff) -> CarbideCliResult<()> {
    let req = forgerpc::MaintenanceRequest {
        operation: forgerpc::MaintenanceOperation::Disable.into(),
        host_id: Some(args.host),
        reference: None,
    };
    api_client.0.set_maintenance(req).await?;
    Ok(())
}

pub async fn maintenance(api_client: &ApiClient, action: Args) -> CarbideCliResult<()> {
    match action {
        Args::On(args) => maintenance_on(api_client, args).await,
        Args::Off(args) => maintenance_off(api_client, args).await,
    }
}
