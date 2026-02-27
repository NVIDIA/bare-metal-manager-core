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

use std::fs;
use std::pin::Pin;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge as forgerpc;
use carbide_uuid::machine::MachineId;

use super::args::MachineHardwareInfoGpus;
use crate::rpc::ApiClient;

pub async fn handle_update_machine_hardware_info_gpus(
    api_client: &ApiClient,
    gpus: MachineHardwareInfoGpus,
) -> CarbideCliResult<()> {
    let gpu_file_contents = fs::read_to_string(gpus.gpu_json_file)?;
    let gpus_from_json: Vec<::rpc::machine_discovery::Gpu> =
        serde_json::from_str(&gpu_file_contents)?;
    api_client
        .update_machine_hardware_info(
            gpus.machine,
            forgerpc::MachineHardwareInfoUpdateType::Gpus,
            gpus_from_json,
        )
        .await
}

pub fn handle_show_machine_hardware_info(
    _api_client: &ApiClient,
    _output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    _output_format: &OutputFormat,
    _machine_id: MachineId,
) -> CarbideCliResult<()> {
    Err(CarbideCliError::NotImplemented(
        "machine hardware output".to_string(),
    ))
}
