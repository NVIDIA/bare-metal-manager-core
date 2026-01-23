/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::forge as rpc;
use carbide_uuid::machine::MachineId;
use regex::Regex;
use tokio::process::Command;

use crate::CarbideClientError;
use crate::cfg::Options;
use crate::client::create_forge_client;

pub(crate) async fn completed(
    config: &Options,
    machine_id: &MachineId,
    uuid: String,
    machine_validation_error: Option<String>,
) -> Result<(), CarbideClientError> {
    let mut client = create_forge_client(config).await?;
    let request = tonic::Request::new(rpc::MachineValidationCompletedRequest {
        machine_id: Some(*machine_id),
        machine_validation_error,
        validation_id: Some(::rpc::common::Uuid { value: uuid }),
    });
    client.machine_validation_completed(request).await?;
    tracing::info!("sending machine validation completed");
    Ok(())
}

pub async fn get_system_manufacturer_name() -> String {
    let command_string = "dmidecode -s system-sku-number".to_string();

    match Command::new("sh")
        .arg("-c")
        .arg(&command_string)
        .output()
        .await
    {
        Ok(output) => {
            if output.stdout.is_empty() {
                "default".to_string()
            } else {
                let sku = String::from_utf8_lossy(&output.stdout)
                    .to_string()
                    .replace('\n', "");

                let re = Regex::new(r"[ =;:@#\!?\-]").unwrap();
                re.replace_all(&sku, "_").to_string().to_ascii_lowercase()
            }
            // let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();
        }
        Err(_) => "default".to_string(),
    }
}

pub(crate) async fn run(
    cmd_config: &Options,
    machine_id: &MachineId,
    uuid: String,
    context: String,
    machine_validation_filter: machine_validation::MachineValidationFilter,
) -> Result<(), CarbideClientError> {
    let platform_name = get_system_manufacturer_name().await;
    let options = machine_validation::MachineValidationOptions {
        api: cmd_config.api.clone(),
        root_ca: cmd_config.root_ca.clone(),
        client_cert: cmd_config.client_cert.clone(),
        client_key: cmd_config.client_key.clone(),
    };
    machine_validation::MachineValidationManager::run(
        machine_id,
        platform_name,
        options,
        context,
        uuid,
        machine_validation_filter,
    )
    .await
    .map_err(|e| CarbideClientError::GenericError(format!("{e}")))?;
    Ok(())
}
