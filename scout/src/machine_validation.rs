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

use std::io::Write as _;
use std::time::Duration;

use ::rpc::forge as rpc;
use futures_util::StreamExt;
use std::cmp::min;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::{cfg::Options, client::create_forge_client, CarbideClientError};

pub const MACHINE_VALIDATION_SERVER: &str = "carbide-pxe.forge";
pub const SCHME: &str = "https";
pub const MACHINE_VALIDATION_CONFIG_PATH: &str =
    "/public/blobs/internal/machine-validation/config/";
pub const MACHINE_VALIDATION_CONFIG_FILE: &str = "/tmp/config.yaml";

pub(crate) async fn completed(
    config: &Options,
    machine_id: &str,
    uuid: String,
    machine_validation_error: Option<String>,
) -> Result<(), CarbideClientError> {
    let mut client = create_forge_client(config).await?;
    let request = tonic::Request::new(rpc::MachineValidationCompletedRequest {
        machine_id: Some(machine_id.to_string().into()),
        machine_validation_error,
        validation_id: Some(::rpc::common::Uuid { value: uuid }),
    });
    client.machine_validation_completed(request).await?;
    tracing::info!("sending machine validation completed");
    Ok(())
}

pub(crate) async fn persist(
    config: &Options,
    data: Option<rpc::MachineValidationResult>,
) -> Result<(), CarbideClientError> {
    tracing::info!("{}", data.clone().unwrap().name);
    let mut client = create_forge_client(config).await?;
    let request = tonic::Request::new(rpc::MachineValidationResultPostRequest { result: data });
    client.persist_validation_result(request).await?;
    Ok(())
}

pub async fn get_system_manufacturer_name() -> String {
    let command_string = "dmidecode -s system-manufacturer".to_string();

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
                return String::from_utf8_lossy(&output.stdout)
                    .to_string()
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();
            }
            // let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();
        }
        Err(_) => "default".to_string(),
    }
}

pub async fn get_machine_validation_config_file() -> Result<String, CarbideClientError> {
    let platform_name = get_system_manufacturer_name().await;
    tracing::info!(platform_name);
    let url: String = format!(
        "{}://{}{}{}.yaml",
        SCHME, MACHINE_VALIDATION_SERVER, MACHINE_VALIDATION_CONFIG_PATH, platform_name
    );
    tracing::info!(url);

    let client = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| CarbideClientError::GenericError(format!("Machine Validation: {e}")))?;

    let res = client
        .get(url.clone())
        .send()
        .await
        .or(Err(CarbideClientError::GenericError(format!(
            "Machine Validation: Failed to GET from '{}'",
            &url
        ))))?;
    let total_size = res
        .content_length()
        .ok_or(CarbideClientError::GenericError(format!(
            "Failed to get content length from '{}'",
            &url
        )))?;

    let mut file = std::fs::File::create(MACHINE_VALIDATION_CONFIG_FILE).or(Err(
        CarbideClientError::GenericError(format!(
            "Machine Validation: Failed to create file '{}'",
            MACHINE_VALIDATION_CONFIG_FILE
        )),
    ))?;
    let mut buffer: u64 = 0;
    let mut stream = res.bytes_stream();

    while let Some(item) = stream.next().await {
        let chunk = item.or(Err(CarbideClientError::GenericError(
            "Machine Validation: Error while reading stream".to_string(),
        )))?;
        file.write_all(&chunk)
            .or(Err(CarbideClientError::GenericError(
                "Machine Validation: Error while writing to file".to_string(),
            )))?;
        let new = min(buffer + (chunk.len() as u64), total_size);
        buffer = new;
    }

    Ok(MACHINE_VALIDATION_CONFIG_FILE.to_string())
}

pub struct MachineValidationManager {
    config: Options,
    receiver_rx: Receiver<Option<rpc::MachineValidationResult>>,
}

impl MachineValidationManager {
    pub fn new(
        in_config: &Options,
        uuid: String,
        context: String,
    ) -> (Self, machine_validation::MachineValidation) {
        let config = Options {
            version: in_config.version,
            mode: in_config.mode,
            machine_interface_id: in_config.machine_interface_id,
            api: in_config.api.clone(),
            root_ca: in_config.root_ca.clone(),
            client_cert: in_config.client_cert.clone(),
            client_key: in_config.client_key.clone(),
            discovery_retry_secs: in_config.discovery_retry_secs,
            discovery_retries_max: in_config.discovery_retries_max,
            subcmd: in_config.subcmd.clone(),
            tpm_path: in_config.tpm_path.clone(),
        };

        let (sender_tx, receiver_rx): (
            Sender<Option<rpc::MachineValidationResult>>,
            Receiver<Option<rpc::MachineValidationResult>>,
        ) = mpsc::channel(5000);

        (
            MachineValidationManager {
                config,
                receiver_rx,
            },
            machine_validation::MachineValidation {
                uuid,
                context,
                sender_tx,
            },
        )
    }

    pub async fn receive_results(&mut self) {
        loop {
            match self.receiver_rx.recv().await {
                Some(data) => {
                    if data.is_none() {
                        tracing::info!("Terminating receiver");
                        break;
                    }
                    match persist(&self.config, data).await {
                        Ok(()) => tracing::info!("Successfully sent to api server"),
                        Err(e) => tracing::error!("{}", e.to_string()),
                    }
                }
                None => {
                    tracing::error!("channel is closed");
                    break;
                }
            }
        }
    }
}

pub(crate) async fn run(
    cmd_config: &Options,
    uuid: String,
    context: String,
) -> Result<(), CarbideClientError> {
    let config_file = get_machine_validation_config_file().await?;

    let (mut manager, config) = MachineValidationManager::new(cmd_config, uuid, context);
    let suite = machine_validation::MachineValidation::read_yaml_data(&config_file)
        .map_err(|e| CarbideClientError::GenericError(format!("Machine Validation: {e}")))?;

    let sender_task = tokio::spawn(async move { config.run(suite, true).await });
    let _ = sender_task.await.unwrap();
    manager.receive_results().await;
    Ok(())
}
