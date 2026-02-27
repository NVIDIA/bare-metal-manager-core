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
    api_client
        .update_expected_power_shelf(
            data.bmc_mac_address,
            data.bmc_username,
            data.bmc_password,
            data.shelf_serial_number,
            data.rack_id,
            data.ip_address,
            metadata,
        )
        .await?;
    Ok(())
}
