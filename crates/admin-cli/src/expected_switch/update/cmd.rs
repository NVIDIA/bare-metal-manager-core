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

use ::rpc::admin_cli::CarbideCliError;

use super::args::Args;
use crate::metadata::parse_rpc_labels;
use crate::rpc::ApiClient;

pub async fn update(data: Args, api_client: &ApiClient) -> color_eyre::Result<()> {
    if let Err(e) = data.validate() {
        eprintln!("{e}");
        return Ok(());
    }
    let metadata = rpc::forge::Metadata {
        name: data.meta_name.unwrap_or_default(),
        description: data.meta_description.unwrap_or_default(),
        labels: parse_rpc_labels(data.labels.unwrap_or_default()),
    };

    let get_req = match (data.bmc_mac_address, data.id.map(|id| id.to_string())) {
        (Some(_), Some(_)) => {
            return Err(CarbideCliError::GenericError(
                "Cannot specify both BMC MAC address and --id. Please provide only one."
                    .to_string(),
            )
            .into());
        }
        (None, None) => {
            return Err(CarbideCliError::GenericError(
                "Must specify either a BMC MAC address or --id.".to_string(),
            )
            .into());
        }
        (_, Some(id)) => rpc::forge::ExpectedSwitchRequest {
            bmc_mac_address: String::new(),
            expected_switch_id: Some(::rpc::common::Uuid { value: id }),
        },
        (Some(mac), None) => rpc::forge::ExpectedSwitchRequest {
            bmc_mac_address: mac.to_string(),
            expected_switch_id: None,
        },
    };

    let existing = api_client.0.get_expected_switch(get_req).await?;
    let mac_str = data
        .bmc_mac_address
        .map(|m| m.to_string())
        .unwrap_or(existing.bmc_mac_address.clone());

    let request = rpc::forge::ExpectedSwitch {
        expected_switch_id: existing.expected_switch_id.clone(),
        bmc_mac_address: mac_str,
        bmc_username: data.bmc_username.unwrap_or(existing.bmc_username),
        bmc_password: data.bmc_password.unwrap_or(existing.bmc_password),
        switch_serial_number: data
            .switch_serial_number
            .unwrap_or(existing.switch_serial_number),
        metadata: Some(metadata),
        rack_id: data.rack_id,
        nvos_username: data.nvos_username.or(existing.nvos_username),
        nvos_password: data.nvos_password.or(existing.nvos_password),
    };

    api_client
        .0
        .update_expected_switch(request)
        .await
        .map_err(CarbideCliError::ApiInvocationError)?;

    Ok(())
}
