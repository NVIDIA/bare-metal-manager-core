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
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;

use carbide_uuid::machine::MachineId;
use chrono::Utc;
use forge_tls::client_config::ClientCert;
use rpc::forge_tls_client;
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use serde::{Deserialize, Serialize};
use tracing::{error, info, trace};
use utils::cmd::TokioCmd;

use crate::{
    IMAGE_LIST_FILE, MACHINE_VALIDATION_IMAGE_FILE, MACHINE_VALIDATION_IMAGE_PATH,
    MACHINE_VALIDATION_RUNNER_BASE_PATH, MACHINE_VALIDATION_RUNNER_TAG, MACHINE_VALIDATION_SERVER,
    MachineValidation, MachineValidationError, MachineValidationFilter, MachineValidationManager,
    MachineValidationOptions, SCHME,
};
pub const MAX_STRING_STD_SIZE: usize = 1024 * 1024; // 1MB in bytes;
pub const DEFAULT_TIMEOUT: u64 = 3600;

impl MachineValidation {
    pub fn new(options: MachineValidationOptions) -> Self {
        MachineValidation { options }
    }
    pub(crate) async fn get_container_auth_config(self) -> Result<(), MachineValidationError> {
        let file_name = "/root/.docker/config.json".to_string();
        match self
            .get_external_config(file_name.clone(), Some("container_auth".to_string()))
            .await
        {
            Ok(()) => trace!("Fetched {} config", file_name),
            Err(e) => trace!("Error - {}", e.to_string()),
        }
        Ok(())
    }
    pub(crate) async fn get_external_config(
        self,
        external_config_file: String,
        external_config_name: Option<String>,
    ) -> Result<(), MachineValidationError> {
        tracing::info!("{}", external_config_file);

        let name = if let Some(name) = external_config_name {
            name
        } else {
            let path = Path::new(&external_config_file);
            path.file_name().unwrap().to_str().unwrap().to_string()
        };

        let mut client = self.create_forge_client().await?;

        let request =
            tonic::Request::new(rpc::forge::GetMachineValidationExternalConfigRequest { name });
        let response = match client.get_machine_validation_external_config(request).await {
            Ok(res) => res,
            Err(e) => {
                return Err(MachineValidationError::ApiClient(
                    "get_external_config".to_owned(),
                    e.to_string(),
                ));
            }
        };
        let config = response.into_inner().config.unwrap().config;
        let mut file = File::create(external_config_file.clone()).map_err(|e| {
            MachineValidationError::File(external_config_file.clone(), e.to_string())
        })?;
        let s = String::from_utf8(config)
            .map_err(|e| MachineValidationError::Generic(e.to_string()))?;
        file.write_all(s.as_bytes()).map_err(|e| {
            MachineValidationError::File(external_config_file.clone(), e.to_string())
        })?;
        Ok(())
    }
    pub(crate) async fn create_forge_client(
        self,
    ) -> Result<forge_tls_client::ForgeClientT, MachineValidationError> {
        let client_config = ForgeClientConfig::new(
            self.options.root_ca,
            Some(ClientCert {
                cert_path: self.options.client_cert,
                key_path: self.options.client_key,
            }),
        );
        let api_config = ApiConfig::new(&self.options.api, &client_config);

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

    pub(crate) async fn get_machine_validation_tests(
        self,
        test_request: rpc::forge::MachineValidationTestsGetRequest,
    ) -> Result<Vec<rpc::forge::MachineValidationTest>, MachineValidationError> {
        tracing::info!("{:?}", test_request);
        let mut client = self.create_forge_client().await?;
        let request = tonic::Request::new(test_request);
        let response = client
            .get_machine_validation_tests(request)
            .await
            .map_err(|e| {
                MachineValidationError::ApiClient(
                    "get_machine_validation_tests".to_owned(),
                    e.to_string(),
                )
            })?
            .into_inner();

        Ok(response.tests)
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
            "{SCHME}://{MACHINE_VALIDATION_SERVER}{MACHINE_VALIDATION_IMAGE_PATH}{image_name}.tar"
        );
        tracing::info!(url);
        MachineValidationManager::download_file(&url, MACHINE_VALIDATION_IMAGE_FILE).await?;

        let command_string = format!(" ctr images import {MACHINE_VALIDATION_IMAGE_FILE}");
        info!("Executing command '{}'", command_string);
        TokioCmd::new("sh")
            .args(vec!["-c".to_string(), command_string])
            .timeout(DEFAULT_TIMEOUT)
            .output_with_timeout()
            .await
            .map_err(|e| MachineValidationError::Generic(e.to_string()))?;
        Ok(format!(
            "{MACHINE_VALIDATION_RUNNER_BASE_PATH}{image_name}:{image_tag}"
        ))
    }

    pub async fn pull_container(image_name: &str) {
        tracing::info!(image_name);
        let command_string = format!(" nerdctl -n default pull {image_name}");
        tracing::info!(command_string);
        match TokioCmd::new("sh")
            .args(vec!["-c".to_string(), command_string])
            .timeout(DEFAULT_TIMEOUT)
            .output_with_timeout()
            .await
        {
            Ok(result) => info!("pulled: {}", result.stdout),
            Err(e) => error!("Failed to image pull{} '{}'", image_name, e),
        }
    }
    async fn execute_machinevalidation_command(
        self,
        machine_id: &MachineId,
        test: &rpc::forge::MachineValidationTest,
        in_context: String,
        uuid: rpc::common::Uuid,
    ) -> Option<rpc::forge::MachineValidationResult> {
        let mut mc_result = rpc::forge::MachineValidationResult {
            test_id: Some(test.test_id.clone()),
            name: test.name.clone(),
            description: test.description.clone().unwrap_or_default(),
            command: test.command.clone(),
            args: test.args.clone(),
            context: in_context.clone(),
            validation_id: Some(uuid.clone()),
            ..rpc::forge::MachineValidationResult::default()
        };
        if test.external_config_file.is_some() {
            let file_name = test.external_config_file.clone().unwrap_or_default();
            match self.get_external_config(file_name.clone(), None).await {
                Ok(()) => trace!("Fetched {} config", file_name),
                Err(e) => {
                    mc_result.start_time = Some(Utc::now().into());
                    mc_result.end_time = Some(Utc::now().into());
                    mc_result.std_err = format!("Error {e}");
                    mc_result.std_out = format!("Skipped: Error {e}");
                    mc_result.exit_code = 0;
                    return Some(mc_result);
                }
            }
        }

        // Check pre_condition
        if test.pre_condition.is_some() {
            match TokioCmd::new(test.pre_condition.clone().unwrap_or("/bin/true".to_owned()))
                .timeout(DEFAULT_TIMEOUT)
                .env("CONTEXT".to_owned(), in_context.clone())
                .env("MACHINE_VALIDATION_RUN_ID".to_owned(), uuid.to_string())
                .env("MACHINE_ID".to_owned(), machine_id.to_string())
                .output_with_timeout()
                .await
            {
                Ok(result) => {
                    let exit_code = result.exit_code;
                    if exit_code != 0 {
                        mc_result.start_time = Some(result.start_time.into());
                        mc_result.end_time = Some(result.end_time.into());
                        mc_result.std_err = result.stderr;
                        mc_result.std_out = "Skipped : Pre condition failed".to_owned();
                        mc_result.exit_code = 0;
                        return Some(mc_result);
                    }
                }
                Err(e) => {
                    mc_result.start_time = Some(Utc::now().into());
                    mc_result.end_time = Some(Utc::now().into());
                    mc_result.std_err = e.to_string();
                    mc_result.std_out = "Skipped : Pre condition failed".to_owned();
                    mc_result.exit_code = 0;
                    return Some(mc_result);
                }
            }
        }
        // Execute command
        let mut command_string = format!("{} {}", test.command, test.args);
        // Check if container
        if test.img_name.is_some() {
            if test.execute_in_host.unwrap_or(false) {
                // Execute command in host
                command_string = format!("chroot /host /bin/bash -c \"{command_string}\"");
            }
            Self::pull_container(&test.img_name.clone().unwrap_or_default()).await;
            let ctr_arg = test.container_arg.clone().unwrap_or("".to_string());
            command_string = format!(
                "ctr run --rm --privileged --no-pivot \
                --mount type=bind,src=/,dst=/host,options=rbind:rw {} \
                {} runner {}",
                ctr_arg,
                test.img_name.clone().unwrap_or_default(),
                command_string
            );
        };
        info!("Executing command '{}'", command_string);

        let _ = std::fs::remove_file("/tmp/forge_env_variables");
        match File::create("/tmp/forge_env_variables") {
            Ok(mut file) => {
                let mut envs = HashMap::new();
                envs.insert("CONTEXT".to_owned(), in_context.clone());
                envs.insert("MACHINE_VALIDATION_RUN_ID".to_owned(), uuid.to_string());
                envs.insert("MACHINE_ID".to_owned(), machine_id.to_string());
                let env_vars = envs
                    .iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect::<Vec<String>>()
                    .join("\n");
                file.write_all(env_vars.as_bytes()).expect("write failed");
            }
            Err(_) => error!("Failed to create file"),
        }

        match TokioCmd::new("sh")
            .args(vec!["-c".to_string(), command_string])
            .timeout(test.timeout.unwrap_or(7200).try_into().unwrap())
            .env("CONTEXT".to_owned(), in_context.clone())
            .env("MACHINE_VALIDATION_RUN_ID".to_owned(), uuid.to_string())
            .env("MACHINE_ID".to_owned(), machine_id.to_string())
            .output_with_timeout()
            .await
        {
            Ok(result) => {
                let mut stdout_str = result.stdout;
                let mut stderr_str = result.stderr;
                if test.extra_output_file.is_some() {
                    let message: String = match tokio::fs::read_to_string(
                        test.extra_output_file.clone().unwrap_or_default(),
                    )
                    .await
                    {
                        Ok(data) => data,
                        Err(_) => "".to_owned(),
                    };
                    stdout_str = stdout_str + &message;
                }
                if test.extra_err_file.is_some() {
                    let message: String = match tokio::fs::read_to_string(
                        test.extra_err_file.clone().unwrap_or_default(),
                    )
                    .await
                    {
                        Ok(data) => data,
                        Err(_) => "".to_owned(),
                    };
                    stderr_str = stderr_str + &message;
                }

                mc_result.start_time = Some(result.start_time.into());
                mc_result.end_time = Some(result.end_time.into());
                mc_result.std_err = if stderr_str.len() > MAX_STRING_STD_SIZE {
                    stderr_str[..MAX_STRING_STD_SIZE].to_string()
                } else {
                    stderr_str
                };
                mc_result.std_out = if stdout_str.len() > MAX_STRING_STD_SIZE {
                    stdout_str[..MAX_STRING_STD_SIZE].to_string()
                } else {
                    stdout_str
                };
                mc_result.exit_code = result.exit_code;
                Some(mc_result)
            }
            Err(e) => {
                mc_result.start_time = Some(Utc::now().into());
                mc_result.end_time = Some(Utc::now().into());
                mc_result.std_err = e.to_string();
                mc_result.std_out = e.to_string();
                mc_result.exit_code = -1;
                Some(mc_result)
            }
        }
    }

    pub(crate) async fn update_machine_validation_run(
        self,
        data: rpc::forge::MachineValidationRunRequest,
    ) -> Result<(), MachineValidationError> {
        tracing::info!("{:?}", data.clone());
        let mut client = self.create_forge_client().await?;
        let request = tonic::Request::new(data);
        let _response = client
            .update_machine_validation_run(request)
            .await
            .map_err(|e| {
                MachineValidationError::ApiClient(
                    "update_machine_validation_run".to_owned(),
                    e.to_string(),
                )
            })?;
        Ok(())
    }
    pub async fn run(
        self,
        machine_id: &MachineId,
        tests: Vec<rpc::forge::MachineValidationTest>,
        context: String,
        uuid: String,
        execute_tests_sequentially: bool,
        machine_validation_filter: MachineValidationFilter,
    ) -> Result<(), MachineValidationError> {
        self.clone().get_container_auth_config().await?;
        match Self::get_container_images().await {
            Ok(_) => info!("Successfully fetched container images"),
            Err(e) => error!("{}", e.to_string()),
        }
        if execute_tests_sequentially {
            for test in tests {
                if !machine_validation_filter.allowed_tests.is_empty()
                    && !machine_validation_filter
                        .allowed_tests
                        .contains(&test.test_id)
                {
                    continue;
                }
                let result = self
                    .clone()
                    .execute_machinevalidation_command(
                        machine_id,
                        &test,
                        context.to_string(),
                        rpc::common::Uuid {
                            value: uuid.clone(),
                        },
                    )
                    .await;
                match self.clone().persist(result).await {
                    Ok(_) => info!("Successfully sent to api server - {}", test.name),
                    Err(e) => error!("{}", e.to_string()),
                }
            }
        } else {
            info!("To be implemented");
        }
        Ok(())
    }
}
