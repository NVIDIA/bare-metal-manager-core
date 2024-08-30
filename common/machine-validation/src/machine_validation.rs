/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use forge_tls::client_config::ClientCert;
use rpc::forge_tls_client;
use rpc::forge_tls_client::ApiConfig;
use rpc::forge_tls_client::ForgeClientConfig;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::io::Write;
use std::path::Path;
use tracing::error;
use tracing::info;
use tracing::trace;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::MachineValidation;
use crate::MachineValidationError;
use crate::MachineValidationManager;
use crate::MachineValidationOptions;
use crate::IMAGE_LIST_FILE;
use crate::MACHINE_VALIDATION_IMAGE_FILE;
use crate::MACHINE_VALIDATION_IMAGE_PATH;
use crate::MACHINE_VALIDATION_RUNNER_BASE_PATH;
use crate::MACHINE_VALIDATION_RUNNER_TAG;
use crate::MACHINE_VALIDATION_SERVER;
use crate::SCHME;

pub const MAX_STRING_STD_SIZE: usize = 1024 * 1024; // 1MB in bytes;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Suite {
    #[serde(flatten)]
    components: HashMap<String, Component>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Component {
    #[serde(flatten)]
    subcategories: HashMap<String, HashMap<String, ExecCommand>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecCommand {
    #[serde(rename = "ContainerImageName")]
    img_name: Option<String>,
    #[serde(rename = "ExecuteInHost")]
    execute_in_host: Option<bool>,
    #[serde(rename = "ContainerArg")]
    container_arg: Option<String>,
    #[serde(rename = "Command")]
    command: String,
    #[serde(rename = "Args")]
    args: String,
    #[serde(rename = "ExtraOutputFile")]
    extra_output_file: Option<String>,
    #[serde(rename = "ExtraErrFile")]
    extra_err_file: Option<String>,
    #[serde(rename = "RequiredExternalConfigFile")]
    required_external_config_file: Option<String>,
    #[serde(rename = "Desc")]
    description: String,
    #[serde(rename = "Contexts")]
    contexts: Vec<String>,
}

impl MachineValidation {
    pub fn new(options: MachineValidationOptions) -> Self {
        MachineValidation { options }
    }
    pub(crate) async fn download_external_config(
        self,
        external_config: Option<Vec<String>>,
    ) -> Result<(), MachineValidationError> {
        let Some(config_names) = external_config else {
            return Ok(());
        };
        for name in config_names {
            let file_name = format!("/tmp/machine_validation/external_config/{}", name.clone());
            tracing::info!("{}", file_name);
            let mut client = self.clone().create_forge_client().await?;
            let request =
                tonic::Request::new(rpc::forge::GetMachineValidationExternalConfigRequest { name });
            let response = match client.get_machine_validation_external_config(request).await {
                Ok(res) => res,
                Err(err) => {
                    error!("{}", err.to_string());
                    continue;
                }
            };

            let config = response.into_inner().config.unwrap().config;

            let mut file = File::create(file_name.clone())
                .map_err(|e| MachineValidationError::File(file_name.clone(), e.to_string()))?;
            let s = String::from_utf8(config).expect("Found invalid UTF-8");
            file.write_all(s.as_bytes())
                .map_err(|e| MachineValidationError::File(file_name.clone(), e.to_string()))?;
        }
        Ok(())
    }
    pub(crate) async fn create_forge_client(
        self,
    ) -> Result<forge_tls_client::ForgeClientT, MachineValidationError> {
        let api_config = ApiConfig::new(
            &self.options.api,
            ForgeClientConfig::new(
                self.options.root_ca.clone(),
                Some(ClientCert {
                    cert_path: self.options.client_cert.clone(),
                    key_path: self.options.client_key.clone(),
                }),
            ),
        );

        let client = forge_tls_client::ForgeTlsClient::retry_build(&api_config)
            .await
            .map_err(|err| MachineValidationError::Generic(err.to_string()))?;
        Ok(client)
    }
    pub(crate) async fn persist(
        self,
        data: Option<rpc::forge::MachineValidationResult>,
    ) -> Result<(), MachineValidationError> {
        tracing::info!("{}", data.clone().unwrap().name);
        let mut client = self.create_forge_client().await?;
        let request =
            tonic::Request::new(rpc::forge::MachineValidationResultPostRequest { result: data });
        client
            .persist_validation_result(request)
            .await
            .map_err(|e| {
                MachineValidationError::ApiClient(
                    "persist_validation_result".to_owned(),
                    e.to_string(),
                )
            })?;
        Ok(())
    }

    pub async fn get_container_images() -> Result<(), MachineValidationError> {
        let url: String = format!(
            "{}://{}{}{}",
            SCHME, MACHINE_VALIDATION_SERVER, MACHINE_VALIDATION_IMAGE_PATH, "list.json"
        );
        tracing::info!(url);
        MachineValidationManager::download_file(&url, IMAGE_LIST_FILE).await?;

        let json_file_path = Path::new("/tmp/list.json");
        let reader = BufReader::new(File::open(json_file_path).map_err(|e| {
            MachineValidationError::File(
                format!(
                    "File {} open error",
                    json_file_path.to_str().unwrap_or_default()
                ),
                e.to_string(),
            )
        })?);

        #[derive(Debug, Serialize, Deserialize)]
        struct ImageList {
            images: Vec<String>,
        }

        let list: ImageList = serde_json::from_reader(reader)
            .map_err(|e| MachineValidationError::Generic(format!("Json read error: {e}")))?;
        for image_name in list.images {
            match Self::import_container(&image_name, MACHINE_VALIDATION_RUNNER_TAG).await {
                Ok(data) => {
                    trace!("Import successfull '{}'", data)
                }
                Err(e) => error!("Failed to import '{}'", e.to_string()),
            };
        }
        Ok(())
    }

    pub async fn import_container(
        image_name: &str,
        image_tag: &str,
    ) -> Result<String, MachineValidationError> {
        tracing::info!(image_name);
        let url: String = format!(
            "{}://{}{}{}.tar",
            SCHME, MACHINE_VALIDATION_SERVER, MACHINE_VALIDATION_IMAGE_PATH, image_name
        );
        tracing::info!(url);
        MachineValidationManager::download_file(&url, MACHINE_VALIDATION_IMAGE_FILE).await?;

        let command_string = format!(" ctr images import {}", MACHINE_VALIDATION_IMAGE_FILE);
        info!("Executing command '{}'", command_string);
        match Command::new("sh")
            .arg("-c")
            .arg(&command_string)
            .output()
            .await
        {
            Ok(_data) => Ok(format!(
                "{}{}:{}",
                MACHINE_VALIDATION_RUNNER_BASE_PATH, image_name, image_tag
            )),
            Err(e) => Err(MachineValidationError::Generic(format!(
                "Failed to import container {} '{}'",
                image_name, e
            ))),
        }
    }

    pub async fn pull_container(image_name: &str) {
        tracing::info!(image_name);

        let command_string = format!(" ctr  image pull {}", image_name);
        info!("Executing command '{}'", command_string);
        match Command::new("sh")
            .arg("-c")
            .arg(&command_string)
            .output()
            .await
        {
            Ok(_data) => {
                info!("pulled {}", image_name);
            }
            Err(e) => {
                error!("Failed to image pull{} '{}'", image_name, e);
            }
        }
    }
    async fn execute_machinevalidation_command(
        name: String,
        cmd: ExecCommand,
        in_context: String,
        uuid: rpc::common::Uuid,
    ) -> Option<rpc::forge::MachineValidationResult> {
        let mut command_string = format!("{} {}", cmd.command, cmd.args);
        if cmd.required_external_config_file.is_some() {
            let file_name = format!(
                "/tmp/machine_validation/external_config/{}",
                cmd.required_external_config_file.unwrap_or_default()
            );
            //TODO in future, the test case editing per site will change this logic,
            // This is stop gap solution
            if std::fs::metadata(file_name.clone()).is_err() {
                let start_time = Utc::now();
                let end_time = Utc::now();

                return Some(rpc::forge::MachineValidationResult {
                    name,
                    description: cmd.description.clone(),
                    command: cmd.command.clone(),
                    args: cmd.args.clone(),
                    std_out: format!("{} doesnt exist", file_name.clone()),
                    std_err: format!("{} doesnt exist", file_name),
                    context: in_context,
                    exit_code: 0,
                    start_time: Some(start_time.into()),
                    end_time: Some(end_time.into()),
                    validation_id: Some(uuid),
                });
            }
        }
        if cmd.img_name.is_some() {
            if cmd.execute_in_host.unwrap_or(false) {
                command_string = format!("chroot /host /bin/bash -c \"{}\"", command_string);
            }
            Self::pull_container(&cmd.img_name.clone().unwrap_or_default()).await;
            let ctr_arg = cmd.container_arg.unwrap_or("".to_string());
            command_string = format!(
                "ctr run --rm --privileged --no-pivot \
                --mount type=bind,src=/,dst=/host,options=rbind:rw {} \
                {} runner {}",
                ctr_arg,
                cmd.img_name.unwrap_or_default(),
                command_string
            );
        };
        info!("Executing command '{}'", command_string);
        let start_time = Utc::now();
        match Command::new("sh")
            .arg("-c")
            .arg(&command_string)
            .output()
            .await
        {
            Ok(output) => {
                let mut stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
                let mut stderr_str = String::from_utf8_lossy(&output.stderr).to_string();
                let mut exit_code = if output.status.success() { 0 } else { -1 };

                let end_time = Utc::now();
                if cmd.extra_output_file.is_some() {
                    let message: String =
                        match tokio::fs::read_to_string(cmd.extra_output_file.unwrap_or_default())
                            .await
                        {
                            Ok(data) => data,
                            Err(_) => "".to_owned(),
                        };
                    stdout_str = stdout_str + &message;
                }
                if cmd.extra_err_file.is_some() {
                    let message: String =
                        match tokio::fs::read_to_string(cmd.extra_err_file.unwrap_or_default())
                            .await
                        {
                            Ok(data) => data,
                            Err(_) => "".to_owned(),
                        };
                    if !message.is_empty() {
                        exit_code = 0;
                    }
                    stderr_str = stderr_str + &message;
                }
                info!("exit code {}", exit_code);
                Some(rpc::forge::MachineValidationResult {
                    name,
                    description: cmd.description.clone(),
                    command: cmd.command.clone(),
                    args: cmd.args.clone(),
                    std_out: if stdout_str.len() > MAX_STRING_STD_SIZE {
                        stdout_str[..MAX_STRING_STD_SIZE].to_string()
                    } else {
                        stdout_str
                    },
                    std_err: if stderr_str.len() > MAX_STRING_STD_SIZE {
                        stderr_str[..MAX_STRING_STD_SIZE].to_string()
                    } else {
                        stderr_str
                    },
                    context: in_context,
                    exit_code,
                    start_time: Some(start_time.into()),
                    end_time: Some(end_time.into()),
                    validation_id: Some(uuid),
                })
            }
            Err(e) => {
                error!("Error {}", e);
                let end_time = Utc::now();
                Some(rpc::forge::MachineValidationResult {
                    name,
                    description: cmd.description.clone(),
                    command: cmd.command.clone(),
                    args: cmd.args.clone(),
                    std_out: e.to_string(),
                    std_err: e.to_string(),
                    context: in_context,
                    exit_code: -1,
                    start_time: Some(start_time.into()),
                    end_time: Some(end_time.into()),
                    validation_id: Some(uuid),
                })
            }
        }
    }

    pub async fn run(
        self,
        s: Suite,
        context: String,
        uuid: String,
        execute_tests_sequentially: bool,
    ) -> Result<(), MachineValidationError> {
        Self::get_container_images().await?;
        if execute_tests_sequentially {
            for (suite_name, components) in s.components {
                info!("-Suite {}", suite_name);
                for (category_name, category) in components.subcategories {
                    info!("-- Category {}", category_name);
                    for (test_name, command) in category {
                        if !command.contexts.contains(&context) {
                            continue;
                        }
                        let result = MachineValidation::execute_machinevalidation_command(
                            test_name.clone(),
                            command,
                            context.to_string(),
                            rpc::common::Uuid {
                                value: uuid.clone(),
                            },
                        )
                        .await;
                        match self.clone().persist(result).await {
                            Ok(_) => info!("Successfully send to api server - {}", test_name),
                            Err(e) => error!("{}", e.to_string()),
                        }
                    }
                }
            }
        } else {
            info!("To be implemented");
        }
        Ok(())
    }
}
