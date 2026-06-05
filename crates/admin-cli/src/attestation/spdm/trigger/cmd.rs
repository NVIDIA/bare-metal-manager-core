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

use ::rpc::forge::SpdmMachineAttestationTriggerRequest;

use crate::attestation::spdm::trigger::Args;
use crate::errors::CarbideCliResult;
use crate::rpc::ApiClient;

pub async fn trigger(args: Args, api_client: &ApiClient) -> CarbideCliResult<()> {
    let res = api_client
        .0
        .trigger_machine_attestation(SpdmMachineAttestationTriggerRequest {
            machine_id: Some(args.machine_id),
            redfish_timeout_secs: args.redfish_timeout_secs,
        })
        .await?;

    println!(
        "Attestation triggered for machine {}",
        res.machine_id
            .map(|e| e.to_string())
            .unwrap_or("No MachineId returned".to_string())
    );

    Ok(())
}
