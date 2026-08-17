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
#[cfg(unix)]
use std::{ffi::CString, os::unix::ffi::OsStrExt};

use carbide_instrument::{Event, LabelValue, Outcome, emit};
use carbide_utils::cmd::TokioCmd;
use carbide_uuid::machine::MachineId;
use carbide_uuid::machine_validation::MachineValidationId;
use chrono::Utc;
use forge_tls::client_config::ClientCert;
use rpc::forge_tls_client;
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::task::JoinHandle;
use tracing::{error, info, trace};

use crate::{
    IMAGE_LIST_FILE, MACHINE_VALIDATION_IMAGE_FILE, MACHINE_VALIDATION_IMAGE_PATH,
    MACHINE_VALIDATION_RUNNER_BASE_PATH, MACHINE_VALIDATION_RUNNER_TAG, MACHINE_VALIDATION_SERVER,
    MachineValidation, MachineValidationError, MachineValidationFilter, MachineValidationManager,
    SCHME,
};
const MAX_STRING_STD_SIZE: usize = 1024 * 1024; // 1MB in bytes;
const DEFAULT_TIMEOUT: u64 = 3600;
const MAX_PLUGIN_RESULT_SIZE: u64 = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginResult {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    outcome: String,
    summary: String,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    findings: Vec<PluginFinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginFinding {
    name: String,
    message: String,
}

fn read_plugin_result(path: &Path) -> Result<PluginResult, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("plugin did not write result.json: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("plugin result must be a regular file, not a symlink".to_owned());
    }
    if metadata.len() > MAX_PLUGIN_RESULT_SIZE {
        return Err("plugin result exceeds the 64 KiB limit".to_owned());
    }
    parse_plugin_result(
        &std::fs::read(path).map_err(|error| format!("failed to read plugin result: {error}"))?,
    )
}

fn parse_plugin_result(contents: &[u8]) -> Result<PluginResult, String> {
    let result: PluginResult = serde_json::from_slice(contents)
        .map_err(|error| format!("invalid plugin result: {error}"))?;
    if result.api_version != "machinevalidation.nvidia.com/v1" {
        return Err("plugin result has an unsupported apiVersion".to_owned());
    }
    if result.kind != "MachineValidationPluginResult" {
        return Err("plugin result has an unsupported kind".to_owned());
    }
    if !matches!(result.outcome.as_str(), "pass" | "fail" | "error") {
        return Err("plugin result has an unsupported outcome".to_owned());
    }
    if result.summary.len() > 4096 {
        return Err("plugin result summary exceeds the 4 KiB limit".to_owned());
    }
    if let Some(severity) = &result.severity
        && !matches!(
            severity.as_str(),
            "info" | "warning" | "critical" | "unknown"
        )
    {
        return Err("plugin result has an unsupported severity".to_owned());
    }
    if result.findings.len() > 100 {
        return Err("plugin result has more than 100 findings".to_owned());
    }
    if result
        .findings
        .iter()
        .any(|finding| finding.name.is_empty() || finding.message.len() > 4096)
    {
        return Err("plugin result contains an invalid finding".to_owned());
    }
    Ok(result)
}

fn truncate_plugin_output(output: String) -> String {
    if output.len() <= MAX_STRING_STD_SIZE {
        return output;
    }
    let end = output
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= MAX_STRING_STD_SIZE)
        .last()
        .unwrap_or(0);
    output[..end].to_owned()
}

#[cfg(unix)]
fn prepare_plugin_directories(
    attempt_dir: &Path,
    input_dir: &Path,
    output_dir: &Path,
) -> Result<(), String> {
    const PLUGIN_UID: libc::uid_t = 65532;
    const PLUGIN_GID: libc::gid_t = 65532;

    std::fs::create_dir_all(attempt_dir)
        .map_err(|error| format!("failed to create plugin attempt directory: {error}"))?;
    std::fs::set_permissions(
        attempt_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o711),
    )
    .map_err(|error| format!("failed to restrict plugin attempt directory: {error}"))?;

    for directory in [input_dir, output_dir] {
        std::fs::create_dir(directory)
            .map_err(|error| format!("failed to create plugin directory: {error}"))?;
        let path = CString::new(directory.as_os_str().as_bytes())
            .map_err(|_| "plugin directory path contains a null byte".to_owned())?;
        // Scout runs as root and creates these directories for the fixed
        // non-root container identity. A 0700 directory prevents another host
        // user from pre-seeding or replacing the plugin result.
        if unsafe { libc::chown(path.as_ptr(), PLUGIN_UID, PLUGIN_GID) } != 0 {
            return Err(format!(
                "failed to grant plugin directory access: {}",
                std::io::Error::last_os_error()
            ));
        }
        std::fs::set_permissions(
            directory,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .map_err(|error| format!("failed to restrict plugin directory: {error}"))?;
    }
    Ok(())
}

fn plugin_process_succeeded(exit_code: Option<i32>) -> bool {
    exit_code == Some(0)
}

fn plugin_runtime_args(
    input_dir: &Path,
    output_dir: &Path,
    container_name: String,
    image: String,
    plugin: &rpc::forge::MachineValidationPlugin,
) -> Vec<String> {
    // The API admits only approved plugin revisions into an enabled run plan.
    // Scout therefore receives immutable execution settings, not a request to
    // decide whether full-host access is permitted.
    let mut args = vec![
        "-n".to_owned(),
        "default".to_owned(),
        "run".to_owned(),
        "--rm".to_owned(),
        "--network".to_owned(),
        "none".to_owned(),
        "--mount".to_owned(),
        format!(
            "type=bind,src={},dst=/opt/nico/mv/input,options=rbind:ro",
            input_dir.display()
        ),
        "--mount".to_owned(),
        format!(
            "type=bind,src={},dst=/opt/nico/mv/output,options=rbind:rw",
            output_dir.display()
        ),
    ];
    if plugin.privileged {
        args.push("--privileged".to_owned());
    } else {
        args.extend([
            "--user".to_owned(),
            "65532:65532".to_owned(),
            "--cap-drop".to_owned(),
            "ALL".to_owned(),
            "--security-opt".to_owned(),
            "no-new-privileges".to_owned(),
        ]);
    }
    if plugin.host_access_full {
        args.extend([
            "--mount".to_owned(),
            "type=bind,src=/,dst=/host,options=rbind:rw".to_owned(),
        ]);
    }
    args.extend(["--name".to_owned(), container_name]);
    args.push(image);
    args.extend(plugin.entrypoint.iter().cloned());
    args
}

// The API manager clamps heartbeat-based stale reconciliation to at least three missed beats, so
// low stale_run_timeout config values cannot fail healthy runs between these heartbeat updates.
const MACHINE_VALIDATION_HEARTBEAT_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
enum MachineValidationHeartbeatStage {
    Initial,
    Periodic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
enum MachineValidationHeartbeatFailureReason {
    Rejected,
    Rpc,
}

/// A machine-validation heartbeat did not land. Each variant is one
/// (stage, reason) pair; only the RPC cases have an error to report.
#[derive(Event)]
#[event(
    event_name = "machine_validation_heartbeat_failed",
    metric_name = "carbide_machine_validation_heartbeat_failures_total",
    component = "nico-scout",
    metric = counter,
    log = error,
    describe = "Number of machine validation heartbeat failures, by stage and reason.",
    labels(
        stage: MachineValidationHeartbeatStage,
        reason: MachineValidationHeartbeatFailureReason,
    ),
)]
enum MachineValidationHeartbeatFailed {
    #[event(
        labels(
            stage = MachineValidationHeartbeatStage::Initial,
            reason = MachineValidationHeartbeatFailureReason::Rejected
        ),
        message = "initial machine validation heartbeat was rejected"
    )]
    InitialRejected {
        #[context]
        machine_validation_id: MachineValidationId,
        #[context]
        test_id: String,
    },

    #[event(
        labels(
            stage = MachineValidationHeartbeatStage::Periodic,
            reason = MachineValidationHeartbeatFailureReason::Rejected
        ),
        message = "machine validation heartbeat was rejected because run or attempt is no longer active"
    )]
    PeriodicRejected {
        #[context]
        machine_validation_id: MachineValidationId,
        #[context]
        test_id: String,
    },

    #[event(
        labels(
            stage = MachineValidationHeartbeatStage::Initial,
            reason = MachineValidationHeartbeatFailureReason::Rpc
        ),
        message = "failed to send initial machine validation heartbeat"
    )]
    InitialRpc {
        #[context]
        machine_validation_id: MachineValidationId,
        #[context]
        test_id: String,
        #[context]
        error: String,
    },

    #[event(
        labels(
            stage = MachineValidationHeartbeatStage::Periodic,
            reason = MachineValidationHeartbeatFailureReason::Rpc
        ),
        message = "failed to send machine validation heartbeat"
    )]
    PeriodicRpc {
        #[context]
        machine_validation_id: MachineValidationId,
        #[context]
        test_id: String,
        #[context]
        error: String,
    },
}

impl MachineValidationHeartbeatFailed {
    /// A heartbeat the server declined; there is no transport error.
    fn rejected(
        stage: MachineValidationHeartbeatStage,
        machine_validation_id: MachineValidationId,
        test_id: String,
    ) -> Self {
        match stage {
            MachineValidationHeartbeatStage::Initial => Self::InitialRejected {
                machine_validation_id,
                test_id,
            },
            MachineValidationHeartbeatStage::Periodic => Self::PeriodicRejected {
                machine_validation_id,
                test_id,
            },
        }
    }

    /// A heartbeat that never reached the server.
    fn rpc(
        stage: MachineValidationHeartbeatStage,
        machine_validation_id: MachineValidationId,
        test_id: String,
        error: impl std::fmt::Display,
    ) -> Self {
        let error = error.to_string();
        match stage {
            MachineValidationHeartbeatStage::Initial => Self::InitialRpc {
                machine_validation_id,
                test_id,
                error,
            },
            MachineValidationHeartbeatStage::Periodic => Self::PeriodicRpc {
                machine_validation_id,
                test_id,
                error,
            },
        }
    }
}
/// One machine-validation result write. Each variant is the result.
#[derive(Event)]
#[event(
    event_name = "machine_validation_result_persistence_finished",
    metric_name = "carbide_machine_validation_result_persistence_attempts_total",
    component = "nico-scout",
    metric = counter,
    describe = "Number of machine validation result persistence attempts, by outcome.",
    labels(outcome: Outcome),
)]
enum MachineValidationResultPersistenceFinished {
    #[event(
        labels(outcome = Outcome::Ok),
        log = info,
        message = "Sent machine validation result to API server"
    )]
    Ok {
        #[context]
        machine_validation_id: MachineValidationId,
        #[context]
        test_id: String,
        #[context]
        test_name: String,
    },

    #[event(
        labels(outcome = Outcome::Error),
        log = error,
        message = "Failed to send machine validation result to API server"
    )]
    Error {
        #[context]
        machine_validation_id: MachineValidationId,
        #[context]
        test_id: String,
        #[context]
        test_name: String,
        #[context]
        error: String,
    },
}

impl MachineValidationResultPersistenceFinished {
    /// Which case a persist attempt landed in. `Ok` has no error to report, so
    /// the failure text exists only on `Error`.
    fn from_result<E>(
        machine_validation_id: MachineValidationId,
        test_id: String,
        test_name: String,
        result: &Result<(), E>,
    ) -> Self
    where
        E: std::fmt::Display,
    {
        match result {
            Result::Ok(()) => Self::Ok {
                machine_validation_id,
                test_id,
                test_name,
            },
            Result::Err(error) => Self::Error {
                machine_validation_id,
                test_id,
                test_name,
                error: error.to_string(),
            },
        }
    }
}
struct MachineValidationExecution {
    result: rpc::forge::MachineValidationResult,
    heartbeat: Option<MachineValidationHeartbeatGuard>,
}

impl MachineValidationExecution {
    fn without_heartbeat(result: rpc::forge::MachineValidationResult) -> Self {
        Self {
            result,
            heartbeat: None,
        }
    }

    fn with_heartbeat(
        result: rpc::forge::MachineValidationResult,
        heartbeat: MachineValidationHeartbeatGuard,
    ) -> Self {
        Self {
            result,
            heartbeat: Some(heartbeat),
        }
    }
}

struct MachineValidationHeartbeatGuard {
    task: Option<JoinHandle<()>>,
}

impl MachineValidationHeartbeatGuard {
    fn new(task: JoinHandle<()>) -> Self {
        Self { task: Some(task) }
    }

    async fn stop(mut self) {
        let Some(task) = self.task.take() else {
            return;
        };

        task.abort();
        match task.await {
            Ok(()) => {}
            Err(e) if e.is_cancelled() => {}
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => error!(error = %e, "machine validation heartbeat task failed"),
        }
    }
}

impl Drop for MachineValidationHeartbeatGuard {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl MachineValidation {
    pub(crate) async fn get_container_auth_config(self) -> Result<(), MachineValidationError> {
        let file_name = "/root/.docker/config.json".to_string();
        match self
            .get_external_config(file_name.clone(), Some("container_auth".to_string()))
            .await
        {
            Ok(()) => trace!(
                external_config_file = %file_name,
                "Fetched external machine validation config",
            ),
            Err(e) => trace!(
                error = %e,
                "Failed to fetch container authentication config",
            ),
        }
        Ok(())
    }
    pub(crate) async fn get_external_config(
        self,
        external_config_file: String,
        external_config_name: Option<String>,
    ) -> Result<(), MachineValidationError> {
        tracing::info!(
            external_config_file = %external_config_file,
            "Fetching external machine validation config",
        );

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
        &self,
    ) -> Result<forge_tls_client::ForgeClientT, MachineValidationError> {
        let client_config = ForgeClientConfig::new(
            self.options.root_ca.clone(),
            Some(ClientCert {
                cert_path: self.options.client_cert.clone(),
                key_path: self.options.client_key.clone(),
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
        tracing::info!(
            validation_name = %data.as_ref().expect("validation result").name,
            "Persisting machine validation result",
        );
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

    pub(crate) async fn heartbeat_machine_validation_run(
        self,
        validation_id: MachineValidationId,
        test_id: Option<String>,
    ) -> Result<bool, MachineValidationError> {
        let mut client = self.create_forge_client().await?;
        let response = client
            .heartbeat_machine_validation_run(tonic::Request::new(
                rpc::forge::MachineValidationHeartbeatRequest {
                    validation_id: Some(validation_id),
                    target: test_id
                        .map(rpc::forge::machine_validation_heartbeat_request::Target::TestId),
                },
            ))
            .await
            .map_err(|e| {
                MachineValidationError::ApiClient(
                    "heartbeat_machine_validation_run".to_owned(),
                    e.to_string(),
                )
            })?
            .into_inner();
        Ok(response.accepted)
    }

    async fn heartbeat_machine_validation_run_item(
        self,
        validation_id: MachineValidationId,
        run_item_id: rpc::common::Uuid,
    ) -> Result<bool, MachineValidationError> {
        // A test ID is not enough once a catalog entry can change over time.
        // The run-item ID binds this heartbeat to the exact selected revision.
        let mut client = self.create_forge_client().await?;
        let response = client
            .heartbeat_machine_validation_run(tonic::Request::new(
                rpc::forge::MachineValidationHeartbeatRequest {
                    validation_id: Some(validation_id),
                    target: Some(
                        rpc::forge::machine_validation_heartbeat_request::Target::RunItemId(
                            run_item_id,
                        ),
                    ),
                },
            ))
            .await
            .map_err(|e| {
                MachineValidationError::ApiClient(
                    "heartbeat_machine_validation_run".to_owned(),
                    e.to_string(),
                )
            })?
            .into_inner();
        Ok(response.accepted)
    }

    fn spawn_machine_validation_run_item_heartbeat(
        self,
        validation_id: MachineValidationId,
        run_item_id: rpc::common::Uuid,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(MACHINE_VALIDATION_HEARTBEAT_INTERVAL);
            loop {
                interval.tick().await;
                match self
                    .clone()
                    .heartbeat_machine_validation_run_item(validation_id, run_item_id.clone())
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => return,
                    Err(e) => {
                        error!(machine_validation_id = %validation_id, run_item_id = %run_item_id.value, error = %e, "failed to heartbeat machine validation run item")
                    }
                }
            }
        })
    }

    async fn get_machine_validation_run_items(
        self,
        validation_id: MachineValidationId,
    ) -> Result<Vec<rpc::forge::MachineValidationRunItem>, MachineValidationError> {
        // The API creates these records before Scout starts. Fetching them here
        // makes the persisted selection, timeout, and plugin config the source
        // of truth for this execution.
        let mut client = self.create_forge_client().await?;
        let ids = client
            .find_machine_validation_run_item_ids(tonic::Request::new(
                rpc::forge::MachineValidationRunItemSearchFilter {
                    validation_id: Some(validation_id),
                },
            ))
            .await
            .map_err(|e| {
                MachineValidationError::ApiClient(
                    "find_machine_validation_run_item_ids".to_owned(),
                    e.to_string(),
                )
            })?
            .into_inner()
            .run_item_ids;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        Ok(client
            .find_machine_validation_run_items_by_ids(tonic::Request::new(
                rpc::forge::MachineValidationRunItemsByIdsRequest { run_item_ids: ids },
            ))
            .await
            .map_err(|e| {
                MachineValidationError::ApiClient(
                    "find_machine_validation_run_items_by_ids".to_owned(),
                    e.to_string(),
                )
            })?
            .into_inner()
            .run_items)
    }

    fn spawn_machine_validation_heartbeat(
        self,
        validation_id: MachineValidationId,
        test_id: String,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(MACHINE_VALIDATION_HEARTBEAT_INTERVAL);
            loop {
                interval.tick().await;
                match self
                    .clone()
                    .heartbeat_machine_validation_run(validation_id, Some(test_id.clone()))
                    .await
                {
                    Ok(true) => {
                        trace!(machine_validation_id = %validation_id, test_id = %test_id, "sent machine validation heartbeat")
                    }
                    Ok(false) => {
                        emit(MachineValidationHeartbeatFailed::rejected(
                            MachineValidationHeartbeatStage::Periodic,
                            validation_id,
                            test_id,
                        ));
                        return;
                    }
                    Err(e) => {
                        emit(MachineValidationHeartbeatFailed::rpc(
                            MachineValidationHeartbeatStage::Periodic,
                            validation_id,
                            test_id.clone(),
                            e,
                        ));
                    }
                }
            }
        })
    }

    pub(crate) async fn get_machine_validation_tests(
        self,
        test_request: rpc::forge::MachineValidationTestsGetRequest,
    ) -> Result<Vec<rpc::forge::MachineValidationTest>, MachineValidationError> {
        tracing::info!(
            request = ?test_request,
            "Fetching machine validation tests",
        );
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
        tracing::info!(url = %url, "Fetching machine validation image list");
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
                    trace!(
                        image_reference = %data,
                        "Imported machine validation container image",
                    )
                }
                Err(e) => error!(
                    error = %e,
                    "Failed to import machine validation container image",
                ),
            };
        }
        Ok(())
    }

    pub async fn import_container(
        image_name: &str,
        image_tag: &str,
    ) -> Result<String, MachineValidationError> {
        tracing::info!(%image_name, "Importing machine validation image");
        let url: String = format!(
            "{SCHME}://{MACHINE_VALIDATION_SERVER}{MACHINE_VALIDATION_IMAGE_PATH}{image_name}.tar"
        );
        tracing::info!(url = %url, "Fetching machine validation image");
        MachineValidationManager::download_file(&url, MACHINE_VALIDATION_IMAGE_FILE).await?;

        let command_string = format!(" ctr images import {MACHINE_VALIDATION_IMAGE_FILE}");
        info!(
            command = %command_string,
            "Executing machine validation command",
        );
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

    /// Resolve registry credentials for `image_name` from the Nico API.
    /// Returns `(username, password, registry)` when credentials are found,
    /// or `None` when the registry cannot be determined, no credential is
    /// stored, or the RPC fails — in all cases the pull proceeds without
    /// credentials.
    async fn resolve_registry_credential(
        &self,
        image_name: &str,
    ) -> Option<(String, String, String)> {
        let registry = match Self::extract_registry(image_name) {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, "Skipping registry credential lookup");
                return None;
            }
        };
        let mut client = match self.create_forge_client().await {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "Failed to build Forge client for registry credential lookup");
                return None;
            }
        };
        let response = client
            .get_container_registry_credential(tonic::Request::new(
                rpc::forge::GetContainerRegistryCredentialRequest {
                    registry: registry.to_string(),
                },
            ))
            .await;
        match response {
            Ok(resp) => {
                let r = resp.into_inner();
                Some((r.username, r.password, registry.to_string()))
            }
            Err(status) if status.code() == tonic::Code::NotFound => {
                // No credential registered — treat as public registry.
                None
            }
            Err(e) => {
                error!(registry = %registry, error = %e, "Failed to fetch registry credential");
                None
            }
        }
    }

    /// Extract the registry hostname from an OCI image reference.
    /// `"nvcr.io/foo/bar:tag"` → `Ok("nvcr.io")`.
    /// Returns an error for bare image names and Docker Hub path shorthands
    /// that carry no explicit registry hostname.
    fn extract_registry(image_name: &str) -> Result<&str, MachineValidationError> {
        // Without a slash the entire string is a bare image name or image:tag
        // (e.g. "ubuntu:22.04") — there is no registry component to extract.
        let Some(slash) = image_name.find('/') else {
            return Err(MachineValidationError::Generic(format!(
                "cannot determine registry from image reference {image_name:?}: \
                 no host component (no '/' found)"
            )));
        };
        let first = &image_name[..slash];
        // The first component is a registry hostname when it contains a dot
        // (e.g. "nvcr.io"), a colon for host:port (e.g. "localhost:5000"),
        // or is exactly "localhost" (port-less local registry).
        // Plain path prefixes like "library" are Docker Hub shorthands with no
        // explicit registry host.
        if first.contains('.') || first.contains(':') || first == "localhost" {
            Ok(first)
        } else {
            Err(MachineValidationError::Generic(format!(
                "cannot determine registry from image reference {image_name:?}: \
                 first component {first:?} is not a hostname"
            )))
        }
    }

    /// Pull `image_name` into the local containerd store via nerdctl.
    ///
    /// If the Nico API has a credential for the image's registry, logs in
    /// with `nerdctl login --password-stdin` before pulling so the password
    /// never appears in process arguments or logs.
    pub async fn pull_container(&self, image_name: &str) -> Result<(), MachineValidationError> {
        tracing::info!(%image_name, "Pulling machine validation image");

        if let Some((username, password, registry)) =
            self.resolve_registry_credential(image_name).await
        {
            let registry = registry.as_str();
            // Pipe the password via stdin so it never appears in process arguments.
            // stdout/stderr are discarded (null) — we only need the exit status, and
            // leaving them piped-but-unread risks a pipe-buffer deadlock if nerdctl
            // produces enough output before exiting.
            use std::process::Stdio;
            use std::time::Duration;

            use tokio::io::AsyncWriteExt;

            const LOGIN_TIMEOUT: Duration = Duration::from_secs(60);

            match tokio::process::Command::new("nerdctl")
                .args([
                    "-n",
                    "default",
                    "login",
                    registry,
                    "-u",
                    &username,
                    "--password-stdin",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(mut child) => {
                    if let Some(mut stdin) = child.stdin.take()
                        && let Err(e) = stdin.write_all(password.as_bytes()).await
                    {
                        error!(%registry, error = %e, "Failed to write password to nerdctl login stdin");
                    }
                    match tokio::time::timeout(LOGIN_TIMEOUT, child.wait()).await {
                        Ok(Ok(status)) if status.success() => {
                            info!(%registry, "Logged in to container registry")
                        }
                        Ok(Ok(status)) => {
                            error!(%registry, exit_code = ?status.code(), "nerdctl login failed")
                        }
                        Ok(Err(e)) => {
                            error!(%registry, error = %e, "Failed to wait for nerdctl login")
                        }
                        Err(_) => {
                            error!(%registry, "nerdctl login timed out");
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                        }
                    }
                }
                Err(e) => error!(%registry, error = %e, "Failed to spawn nerdctl login"),
            }
        }

        match TokioCmd::new("nerdctl")
            .args(["-n", "default", "pull", image_name])
            .timeout(DEFAULT_TIMEOUT)
            .output_with_timeout()
            .await
        {
            Ok(result) if result.exit_code == 0 => {
                info!(
                    %image_name,
                    stdout = %result.stdout,
                    "Pulled machine validation container image",
                );
                Ok(())
            }
            Ok(result) => Err(MachineValidationError::Generic(format!(
                "failed to pull plugin image {image_name}: {}",
                result.stderr
            ))),
            Err(error) => Err(MachineValidationError::Generic(format!(
                "failed to pull plugin image {image_name}: {error}"
            ))),
        }
    }
    async fn execute_machinevalidation_command(
        self,
        machine_id: &MachineId,
        test: &rpc::forge::MachineValidationTest,
        in_context: String,
        validation_id: MachineValidationId,
        platform_name: &str,
        run_item: Option<&rpc::forge::MachineValidationRunItem>,
    ) -> MachineValidationExecution {
        if test.plugin.is_some() {
            return self
                .execute_plugin(
                    machine_id,
                    test,
                    in_context,
                    validation_id,
                    platform_name,
                    run_item,
                )
                .await;
        }
        let mut mc_result = rpc::forge::MachineValidationResult {
            test_id: Some(test.test_id.clone()),
            name: test.name.clone(),
            description: test.description.clone().unwrap_or_default(),
            command: test.command.clone(),
            args: test.args.clone(),
            context: in_context.clone(),
            validation_id: Some(validation_id),
            ..rpc::forge::MachineValidationResult::default()
        };
        match self
            .clone()
            .heartbeat_machine_validation_run(validation_id, Some(test.test_id.clone()))
            .await
        {
            Ok(true) => trace!(
                machine_validation_id = %validation_id,
                test_id = %test.test_id,
                "sent initial machine validation heartbeat"
            ),
            Ok(false) => {
                let now = Utc::now();
                emit(MachineValidationHeartbeatFailed::rejected(
                    MachineValidationHeartbeatStage::Initial,
                    validation_id,
                    test.test_id.clone(),
                ));
                mc_result.start_time = Some(now.into());
                mc_result.end_time = Some(now.into());
                mc_result.std_err = "Machine validation heartbeat was rejected because run or attempt is no longer active".to_owned();
                mc_result.std_out = "Skipped: Machine validation heartbeat was rejected".to_owned();
                mc_result.exit_code = 0;
                return MachineValidationExecution::without_heartbeat(mc_result);
            }
            Err(e) => emit(MachineValidationHeartbeatFailed::rpc(
                MachineValidationHeartbeatStage::Initial,
                validation_id,
                test.test_id.clone(),
                e,
            )),
        }
        let heartbeat = MachineValidationHeartbeatGuard::new(
            self.clone()
                .spawn_machine_validation_heartbeat(validation_id, test.test_id.clone()),
        );
        if test.external_config_file.is_some() {
            let file_name = test.external_config_file.clone().unwrap_or_default();
            match self
                .clone()
                .get_external_config(file_name.clone(), None)
                .await
            {
                Ok(()) => trace!(
                    external_config_file = %file_name,
                    "Fetched external machine validation config",
                ),
                Err(e) => {
                    mc_result.start_time = Some(Utc::now().into());
                    mc_result.end_time = Some(Utc::now().into());
                    mc_result.std_err = format!("Error {e}");
                    mc_result.std_out = format!("Skipped: Error {e}");
                    mc_result.exit_code = 0;
                    return MachineValidationExecution::with_heartbeat(mc_result, heartbeat);
                }
            }
        }

        // Check pre_condition
        if test.pre_condition.is_some() {
            match TokioCmd::new(test.pre_condition.clone().unwrap_or("/bin/true".to_owned()))
                .timeout(DEFAULT_TIMEOUT)
                .env("CONTEXT".to_owned(), in_context.clone())
                .env(
                    "MACHINE_VALIDATION_RUN_ID".to_owned(),
                    validation_id.to_string(),
                )
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
                        return MachineValidationExecution::with_heartbeat(mc_result, heartbeat);
                    }
                }
                Err(e) => {
                    mc_result.start_time = Some(Utc::now().into());
                    mc_result.end_time = Some(Utc::now().into());
                    mc_result.std_err = e.to_string();
                    mc_result.std_out = "Skipped : Pre condition failed".to_owned();
                    mc_result.exit_code = 0;
                    return MachineValidationExecution::with_heartbeat(mc_result, heartbeat);
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
            if let Err(error) = self
                .pull_container(&test.img_name.clone().unwrap_or_default())
                .await
            {
                mc_result.start_time = Some(Utc::now().into());
                mc_result.end_time = Some(Utc::now().into());
                mc_result.std_err = error.to_string();
                mc_result.exit_code = -1;
                return MachineValidationExecution::with_heartbeat(mc_result, heartbeat);
            }
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
        info!(
            command = %command_string,
            "Executing machine validation command",
        );

        let _ = std::fs::remove_file("/tmp/forge_env_variables");
        match File::create("/tmp/forge_env_variables") {
            Ok(mut file) => {
                let mut envs = HashMap::new();
                envs.insert("CONTEXT".to_owned(), in_context.clone());
                envs.insert(
                    "MACHINE_VALIDATION_RUN_ID".to_owned(),
                    validation_id.to_string(),
                );
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

        let command_result = TokioCmd::new("sh")
            .args(vec!["-c".to_string(), command_string])
            .timeout(test.timeout.unwrap_or(7200).try_into().unwrap())
            .env("CONTEXT".to_owned(), in_context.clone())
            .env(
                "MACHINE_VALIDATION_RUN_ID".to_owned(),
                validation_id.to_string(),
            )
            .env("MACHINE_ID".to_owned(), machine_id.to_string())
            .output_with_timeout()
            .await;

        let result = match command_result {
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
                    stdout_str += message.as_str();
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
                    stderr_str += message.as_str();
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
                mc_result
            }
            Err(e) => {
                mc_result.start_time = Some(Utc::now().into());
                mc_result.end_time = Some(Utc::now().into());
                mc_result.std_err = e.to_string();
                mc_result.std_out = e.to_string();
                mc_result.exit_code = -1;
                mc_result
            }
        };

        MachineValidationExecution::with_heartbeat(result, heartbeat)
    }

    async fn execute_plugin(
        self,
        machine_id: &MachineId,
        test: &rpc::forge::MachineValidationTest,
        context: String,
        validation_id: MachineValidationId,
        platform_name: &str,
        run_item: Option<&rpc::forge::MachineValidationRunItem>,
    ) -> MachineValidationExecution {
        let mut result = rpc::forge::MachineValidationResult {
            test_id: Some(test.test_id.clone()),
            name: test.name.clone(),
            description: test.description.clone().unwrap_or_default(),
            command: "machine-validation-plugin".to_owned(),
            args: test
                .plugin
                .as_ref()
                .map(|plugin| plugin.entrypoint.join(" "))
                .unwrap_or_default(),
            context: context.clone(),
            validation_id: Some(validation_id),
            ..rpc::forge::MachineValidationResult::default()
        };
        // Prefer the plugin copied into the run item. The fallback preserves the
        // legacy execution path while runs created before run items are present
        // continue to be supported.
        let Some(plugin) = run_item
            .and_then(|item| item.plugin.as_ref())
            .or(test.plugin.as_ref())
        else {
            let now = Utc::now();
            result.start_time = Some(now.into());
            result.end_time = Some(now.into());
            result.std_err =
                "framework error: plugin execution requires plugin configuration".to_owned();
            result.exit_code = -1;
            return MachineValidationExecution::without_heartbeat(result);
        };

        // Claim the run item before pulling or starting the container. This also
        // prevents an expired or superseded run from being executed.
        let initial_heartbeat = match run_item.and_then(|item| item.run_item_id.clone()) {
            Some(run_item_id) => {
                self.clone()
                    .heartbeat_machine_validation_run_item(validation_id, run_item_id)
                    .await
            }
            None => {
                self.clone()
                    .heartbeat_machine_validation_run(validation_id, Some(test.test_id.clone()))
                    .await
            }
        };
        match initial_heartbeat {
            Ok(true) => {}
            Ok(false) => {
                let now = Utc::now();
                result.start_time = Some(now.into());
                result.end_time = Some(now.into());
                result.std_err = "Machine validation heartbeat was rejected because run or attempt is no longer active".to_owned();
                result.std_out = "Skipped: Machine validation heartbeat was rejected".to_owned();
                result.exit_code = 0;
                return MachineValidationExecution::without_heartbeat(result);
            }
            Err(error) => emit(MachineValidationHeartbeatFailed::rpc(
                MachineValidationHeartbeatStage::Initial,
                validation_id,
                test.test_id.clone(),
                error,
            )),
        }
        let heartbeat = MachineValidationHeartbeatGuard::new(
            match run_item.and_then(|item| item.run_item_id.clone()) {
                Some(run_item_id) => self
                    .clone()
                    .spawn_machine_validation_run_item_heartbeat(validation_id, run_item_id),
                None => self
                    .clone()
                    .spawn_machine_validation_heartbeat(validation_id, test.test_id.clone()),
            },
        );

        let attempt_dir = std::env::temp_dir()
            .join("nico-machine-validation")
            .join(uuid::Uuid::new_v4().to_string());
        let input_dir = attempt_dir.join("input");
        let output_dir = attempt_dir.join("output");
        let started_at = Utc::now();
        let execution = async {
            let timeout_seconds = run_item
                .and_then(|item| item.timeout.as_ref())
                .map(|timeout| timeout.seconds.max(0) as u64)
                .unwrap_or_else(|| test.timeout.unwrap_or(7200) as u64);
            let deadline =
                tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_seconds);
            // This is the same overall deadline used for both image acquisition
            // and container execution. Plugins can use it to stop their own
            // work before Scout terminates the attempt.
            let deadline_at = started_at + chrono::Duration::seconds(timeout_seconds as i64);
            tokio::time::timeout_at(deadline, self.pull_container(&plugin.image))
                .await
                .map_err(|_| {
                    format!("plugin image pull timed out after {timeout_seconds} seconds")
                })?
                .map_err(|error| error.to_string())?;
            #[cfg(unix)]
            prepare_plugin_directories(&attempt_dir, &input_dir, &output_dir)?;
            let parameters: Value = serde_json::from_str(&plugin.parameters_json)
                .map_err(|error| format!("invalid configured plugin parameters: {error}"))?;
            let input = serde_json::json!({
                "apiVersion": "machinevalidation.nvidia.com/v1",
                "kind": "MachineValidationPluginInput",
                "run": {
                    "id": validation_id.to_string(),
                    "itemId": run_item.and_then(|item| item.run_item_id.as_ref()).map(|id| id.value.clone()),
                    // The initial heartbeat claims the pending run item as attempt 1.
                    // The snapshot was fetched before that claim, so it can still show 0.
                    "attempt": run_item.map(|item| item.attempt.max(1)).unwrap_or(1),
                    "context": context,
                    "deadline": deadline_at.to_rfc3339(),
                },
                "machine": { "id": machine_id.to_string(), "platform": platform_name },
                "plugin": { "name": test.test_id, "revision": test.version.clone() },
                "parameters": parameters,
            });
            std::fs::write(
                input_dir.join("input.json"),
                serde_json::to_vec(&input).expect("plugin input is serializable"),
            )
            .map_err(|error| format!("failed to write plugin input: {error}"))?;

            let args = plugin_runtime_args(
                &input_dir,
                &output_dir,
                format!("mv-plugin-{}", uuid::Uuid::new_v4()),
                plugin.image.clone(),
                plugin,
            );
            let mut command = tokio::process::Command::new("nerdctl");
            command.args(args).kill_on_drop(true);
            match tokio::time::timeout(
                deadline.saturating_duration_since(tokio::time::Instant::now()),
                command.output(),
            )
            .await
            {
                Ok(Ok(output)) if plugin_process_succeeded(output.status.code()) => Ok((
                    String::from_utf8_lossy(&output.stdout).into_owned(),
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                )),
                Ok(Ok(_output)) => {
                    Err("plugin exited unsuccessfully; ignoring result.json".to_owned())
                }
                Ok(Err(error)) => Err(format!("failed to execute plugin: {error}")),
                Err(_) => Err(format!("plugin timed out after {timeout_seconds} seconds")),
            }
        }
        .await;

        let ended_at = Utc::now();
        result.start_time = Some(started_at.into());
        result.end_time = Some(ended_at.into());
        match execution {
            Ok((stdout, stderr)) => {
                result.std_out = truncate_plugin_output(stdout);
                result.std_err = truncate_plugin_output(stderr);
                match read_plugin_result(&output_dir.join("result.json")) {
                    Ok(plugin_result) => {
                        result.std_out = format!(
                            "{}\nplugin result: {}",
                            result.std_out, plugin_result.summary
                        );
                        result.exit_code = match plugin_result.outcome.as_str() {
                            "pass" => 0,
                            "fail" => 1,
                            "error" => -1,
                            _ => {
                                result.std_err = format!(
                                    "{}\nframework error: plugin result has an unsupported outcome",
                                    result.std_err
                                );
                                -1
                            }
                        };
                    }
                    Err(error) => {
                        result.std_err = format!("{}\nframework error: {error}", result.std_err);
                        result.exit_code = -1;
                    }
                }
            }
            Err(error) => {
                result.std_err = format!("framework error: {error}");
                result.exit_code = -1;
            }
        }
        if let Err(error) = std::fs::remove_dir_all(&attempt_dir) {
            tracing::warn!(path = %attempt_dir.display(), error = %error, "Failed to remove plugin attempt directory");
        }
        MachineValidationExecution::with_heartbeat(result, heartbeat)
    }

    pub(crate) async fn update_machine_validation_run(
        self,
        data: rpc::forge::MachineValidationRunRequest,
    ) -> Result<(), MachineValidationError> {
        tracing::info!(
            request = ?data,
            "Updating machine validation run",
        );
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
        validation_id: MachineValidationId,
        platform_name: String,
        execute_tests_sequentially: bool,
        machine_validation_filter: MachineValidationFilter,
    ) -> Result<(), MachineValidationError> {
        self.clone().get_container_auth_config().await?;
        // Re-read the selected execution plan after the API has materialized it.
        // Do not reconstruct plugin details from the catalog at run time.
        let run_items = match self
            .clone()
            .get_machine_validation_run_items(validation_id)
            .await
        {
            Ok(run_items) => run_items,
            Err(error) => {
                tracing::warn!(%validation_id, %error, "unable to load machine validation run items; continuing with legacy execution");
                Vec::new()
            }
        };
        let run_items_by_test = run_items
            .into_iter()
            .map(|item| (item.test_id.clone(), item))
            .collect::<HashMap<_, _>>();
        match Self::get_container_images().await {
            Ok(_) => info!("Successfully fetched container images"),
            Err(e) => error!(error = %e, "Failed to fetch container images"),
        }
        if execute_tests_sequentially {
            for test in tests {
                if !machine_validation_filter.allowed_tests.is_empty()
                    && !machine_validation_filter
                        .allowed_tests
                        .iter()
                        .any(|t| t.eq_ignore_ascii_case(&test.test_id))
                {
                    continue;
                }
                let execution = self
                    .clone()
                    .execute_machinevalidation_command(
                        machine_id,
                        &test,
                        context.to_string(),
                        validation_id,
                        &platform_name,
                        run_items_by_test.get(&test.test_id),
                    )
                    .await;
                let MachineValidationExecution { result, heartbeat } = execution;
                let persist_result = self.clone().persist(Some(result)).await;
                if let Some(heartbeat) = heartbeat {
                    heartbeat.stop().await;
                }
                emit(MachineValidationResultPersistenceFinished::from_result(
                    validation_id,
                    test.test_id.clone(),
                    test.name.clone(),
                    &persist_result,
                ));
            }
        } else {
            info!("To be implemented");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use carbide_instrument::testing::{MetricsCapture, capture_logs};
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases, value_scenarios};

    use super::*;

    #[derive(Clone, Copy)]
    enum InstrumentationCase {
        HeartbeatRejected(MachineValidationHeartbeatStage),
        HeartbeatRpc(MachineValidationHeartbeatStage),
        Persistence(Outcome),
    }

    #[test]
    fn plugin_result_contract_validation() {
        check_cases(
            [
                Case {
                    scenario: "valid pass result",
                    input: r#"{
                        "apiVersion":"machinevalidation.nvidia.com/v1",
                        "kind":"MachineValidationPluginResult",
                        "outcome":"pass",
                        "summary":"check completed",
                        "severity":"info",
                        "findings":[{"name":"gpu","message":"available"}]
                    }"#,
                    expect: Yields(()),
                },
                Case {
                    scenario: "unknown outcome",
                    input: r#"{
                        "apiVersion":"machinevalidation.nvidia.com/v1",
                        "kind":"MachineValidationPluginResult",
                        "outcome":"skipped",
                        "summary":"check completed"
                    }"#,
                    expect: Fails,
                },
                Case {
                    scenario: "unknown field",
                    input: r#"{
                        "apiVersion":"machinevalidation.nvidia.com/v1",
                        "kind":"MachineValidationPluginResult",
                        "outcome":"pass",
                        "summary":"check completed",
                        "extra":"not allowed"
                    }"#,
                    expect: Fails,
                },
            ],
            |contents| {
                parse_plugin_result(contents.as_bytes())
                    .map(|_| ())
                    .map_err(drop)
            },
        );
    }

    #[test]
    fn plugin_runtime_is_isolated_and_non_root() {
        let plugin = rpc::forge::MachineValidationPlugin {
            image: "registry.example/plugin@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            entrypoint: vec!["/plugin/entrypoint".to_owned(), "--check".to_owned()],
            parameters_json: "{}".to_owned(),
            privileged: false,
            host_access_full: false,
        };
        let args = plugin_runtime_args(
            Path::new("/tmp/input"),
            Path::new("/tmp/output"),
            "plugin-test".to_owned(),
            plugin.image.clone(),
            &plugin,
        );

        assert!(args.windows(2).any(|pair| pair == ["--network", "none"]));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--user", "65532:65532"])
        );
        assert!(args.windows(2).any(|pair| pair == ["--cap-drop", "ALL"]));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--security-opt", "no-new-privileges"])
        );
        assert!(args.iter().any(|arg| arg.contains("/opt/nico/mv/input")));
        assert!(args.iter().any(|arg| arg.contains("/opt/nico/mv/output")));
        assert!(!args.iter().any(|arg| arg == "--privileged"));
        assert!(!args.iter().any(|arg| arg.contains("dst=/host")));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--name", "plugin-test"])
        );
        assert_eq!(
            &args[args.len() - 3..],
            [plugin.image.as_str(), "/plugin/entrypoint", "--check",]
        );
    }

    #[test]
    fn full_host_plugin_uses_privileged_runtime_and_host_mount() {
        let plugin = rpc::forge::MachineValidationPlugin {
            image: "registry.example/plugin@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            entrypoint: vec!["/plugin/entrypoint".to_owned()],
            parameters_json: "{}".to_owned(),
            privileged: true,
            host_access_full: true,
        };
        let args = plugin_runtime_args(
            Path::new("/tmp/input"),
            Path::new("/tmp/output"),
            "plugin-test".to_owned(),
            plugin.image.clone(),
            &plugin,
        );

        assert!(args.iter().any(|arg| arg == "--privileged"));
        assert!(
            args.iter()
                .any(|arg| arg == "type=bind,src=/,dst=/host,options=rbind:rw")
        );
    }

    #[test]
    fn only_successful_plugin_exit_accepts_a_result() {
        assert!(plugin_process_succeeded(Some(0)));
        assert!(!plugin_process_succeeded(Some(1)));
        assert!(!plugin_process_succeeded(None));
    }

    #[test]
    fn plugin_output_truncation_preserves_utf8() {
        let output = format!("{}😀", "a".repeat(MAX_STRING_STD_SIZE - 1));
        let truncated = truncate_plugin_output(output);

        assert_eq!(truncated.len(), MAX_STRING_STD_SIZE - 1);
        assert!(truncated.is_char_boundary(truncated.len()));
    }

    #[derive(Debug, PartialEq)]
    struct InstrumentationObservation {
        level: tracing::Level,
        metadata_name: String,
        message: String,
        event_name: Option<String>,
        metric_name: Option<String>,
        stage: Option<String>,
        reason: Option<String>,
        outcome: Option<String>,
        machine_validation_id: Option<String>,
        test_id: Option<String>,
        test_name: Option<String>,
        error: Option<String>,
        counter_delta: f64,
    }

    fn observe_instrumentation(case: InstrumentationCase) -> InstrumentationObservation {
        const TEST_ID: &str = "validation-test";
        const TEST_NAME: &str = "Validation test";
        const RPC_ERROR: &str = "Forge API unavailable";

        let machine_validation_id = MachineValidationId::nil();
        let metrics = MetricsCapture::start();
        let logs = capture_logs(|| match case {
            InstrumentationCase::HeartbeatRejected(stage) => {
                emit(MachineValidationHeartbeatFailed::rejected(
                    stage,
                    machine_validation_id,
                    TEST_ID.to_string(),
                ));
            }
            InstrumentationCase::HeartbeatRpc(stage) => {
                emit(MachineValidationHeartbeatFailed::rpc(
                    stage,
                    machine_validation_id,
                    TEST_ID.to_string(),
                    RPC_ERROR,
                ));
            }
            InstrumentationCase::Persistence(Outcome::Ok) => {
                emit(MachineValidationResultPersistenceFinished::from_result(
                    machine_validation_id,
                    TEST_ID.to_string(),
                    TEST_NAME.to_string(),
                    &Result::<(), &str>::Ok(()),
                ));
            }
            InstrumentationCase::Persistence(Outcome::Error) => {
                emit(MachineValidationResultPersistenceFinished::from_result(
                    machine_validation_id,
                    TEST_ID.to_string(),
                    TEST_NAME.to_string(),
                    &Result::<(), &str>::Err(RPC_ERROR),
                ));
            }
        });

        assert_eq!(logs.len(), 1, "each Event should write one terminal record");
        let log = logs.first().expect("Event did not log");
        let counter_delta = match case {
            InstrumentationCase::HeartbeatRejected(stage) => metrics.counter_delta(
                "carbide_machine_validation_heartbeat_failures_total",
                &[
                    (
                        "stage",
                        match stage {
                            MachineValidationHeartbeatStage::Initial => "initial",
                            MachineValidationHeartbeatStage::Periodic => "periodic",
                        },
                    ),
                    ("reason", "rejected"),
                ],
            ),
            InstrumentationCase::HeartbeatRpc(stage) => metrics.counter_delta(
                "carbide_machine_validation_heartbeat_failures_total",
                &[
                    (
                        "stage",
                        match stage {
                            MachineValidationHeartbeatStage::Initial => "initial",
                            MachineValidationHeartbeatStage::Periodic => "periodic",
                        },
                    ),
                    ("reason", "rpc"),
                ],
            ),
            InstrumentationCase::Persistence(outcome) => metrics.counter_delta(
                "carbide_machine_validation_result_persistence_attempts_total",
                &[(
                    "outcome",
                    match outcome {
                        Outcome::Ok => "ok",
                        Outcome::Error => "error",
                    },
                )],
            ),
        };

        InstrumentationObservation {
            level: log.level,
            metadata_name: log.metadata_name.clone(),
            message: log.message.clone(),
            event_name: log.field("event_name").map(str::to_string),
            metric_name: log.field("metric_name").map(str::to_string),
            stage: log.field("stage").map(str::to_string),
            reason: log.field("reason").map(str::to_string),
            outcome: log.field("outcome").map(str::to_string),
            machine_validation_id: log.field("machine_validation_id").map(str::to_string),
            test_id: log.field("test_id").map(str::to_string),
            test_name: log.field("test_name").map(str::to_string),
            error: log.field("error").map(str::to_string),
            counter_delta,
        }
    }

    #[test]
    fn control_plane_delivery_events_log_and_count() {
        let machine_validation_id = Some(MachineValidationId::nil().to_string());
        value_scenarios!(
            run = observe_instrumentation;
            "heartbeat is rejected" {
                InstrumentationCase::HeartbeatRejected(MachineValidationHeartbeatStage::Initial) => InstrumentationObservation {
                    level: tracing::Level::ERROR,
                    metadata_name: "machine_validation_heartbeat_failed".to_string(),
                    message: "initial machine validation heartbeat was rejected".to_string(),
                    event_name: Some("machine_validation_heartbeat_failed".to_string()),
                    metric_name: Some("carbide_machine_validation_heartbeat_failures_total".to_string()),
                    stage: Some("initial".to_string()),
                    reason: Some("rejected".to_string()),
                    outcome: None,
                    machine_validation_id: machine_validation_id.clone(),
                    test_id: Some("validation-test".to_string()),
                    test_name: None,
                    // A rejected heartbeat has no transport error, so the key
                    // is absent from the line rather than blank.
                    error: None,
                    counter_delta: 1.0,
                },
                InstrumentationCase::HeartbeatRejected(MachineValidationHeartbeatStage::Periodic) => InstrumentationObservation {
                    level: tracing::Level::ERROR,
                    metadata_name: "machine_validation_heartbeat_failed".to_string(),
                    message: "machine validation heartbeat was rejected because run or attempt is no longer active".to_string(),
                    event_name: Some("machine_validation_heartbeat_failed".to_string()),
                    metric_name: Some("carbide_machine_validation_heartbeat_failures_total".to_string()),
                    stage: Some("periodic".to_string()),
                    reason: Some("rejected".to_string()),
                    outcome: None,
                    machine_validation_id: machine_validation_id.clone(),
                    test_id: Some("validation-test".to_string()),
                    test_name: None,
                    // A rejected heartbeat has no transport error, so the key
                    // is absent from the line rather than blank.
                    error: None,
                    counter_delta: 1.0,
                },
            }
            "heartbeat RPC fails" {
                InstrumentationCase::HeartbeatRpc(MachineValidationHeartbeatStage::Initial) => InstrumentationObservation {
                    level: tracing::Level::ERROR,
                    metadata_name: "machine_validation_heartbeat_failed".to_string(),
                    message: "failed to send initial machine validation heartbeat".to_string(),
                    event_name: Some("machine_validation_heartbeat_failed".to_string()),
                    metric_name: Some("carbide_machine_validation_heartbeat_failures_total".to_string()),
                    stage: Some("initial".to_string()),
                    reason: Some("rpc".to_string()),
                    outcome: None,
                    machine_validation_id: machine_validation_id.clone(),
                    test_id: Some("validation-test".to_string()),
                    test_name: None,
                    error: Some("Forge API unavailable".to_string()),
                    counter_delta: 1.0,
                },
                InstrumentationCase::HeartbeatRpc(MachineValidationHeartbeatStage::Periodic) => InstrumentationObservation {
                    level: tracing::Level::ERROR,
                    metadata_name: "machine_validation_heartbeat_failed".to_string(),
                    message: "failed to send machine validation heartbeat".to_string(),
                    event_name: Some("machine_validation_heartbeat_failed".to_string()),
                    metric_name: Some("carbide_machine_validation_heartbeat_failures_total".to_string()),
                    stage: Some("periodic".to_string()),
                    reason: Some("rpc".to_string()),
                    outcome: None,
                    machine_validation_id: machine_validation_id.clone(),
                    test_id: Some("validation-test".to_string()),
                    test_name: None,
                    error: Some("Forge API unavailable".to_string()),
                    counter_delta: 1.0,
                },
            }
            "result persistence finishes" {
                InstrumentationCase::Persistence(Outcome::Ok) => InstrumentationObservation {
                    level: tracing::Level::INFO,
                    metadata_name: "machine_validation_result_persistence_finished".to_string(),
                    message: "Sent machine validation result to API server".to_string(),
                    event_name: Some("machine_validation_result_persistence_finished".to_string()),
                    metric_name: Some("carbide_machine_validation_result_persistence_attempts_total".to_string()),
                    stage: None,
                    reason: None,
                    outcome: Some("ok".to_string()),
                    machine_validation_id: machine_validation_id.clone(),
                    test_id: Some("validation-test".to_string()),
                    test_name: Some("Validation test".to_string()),
                    // A successful persist has no error, so the key is absent
                    // from the line rather than blank.
                    error: None,
                    counter_delta: 1.0,
                },
                InstrumentationCase::Persistence(Outcome::Error) => InstrumentationObservation {
                    level: tracing::Level::ERROR,
                    metadata_name: "machine_validation_result_persistence_finished".to_string(),
                    message: "Failed to send machine validation result to API server".to_string(),
                    event_name: Some("machine_validation_result_persistence_finished".to_string()),
                    metric_name: Some("carbide_machine_validation_result_persistence_attempts_total".to_string()),
                    stage: None,
                    reason: None,
                    outcome: Some("error".to_string()),
                    machine_validation_id,
                    test_id: Some("validation-test".to_string()),
                    test_name: Some("Validation test".to_string()),
                    error: Some("Forge API unavailable".to_string()),
                    counter_delta: 1.0,
                },
            }
        );
    }

    #[test]
    fn extract_registry_parses_known_registries() {
        assert_eq!(
            MachineValidation::extract_registry("nvcr.io/foo/bar:latest").unwrap(),
            "nvcr.io"
        );
        assert_eq!(
            MachineValidation::extract_registry("docker.io/library/ubuntu:22.04").unwrap(),
            "docker.io"
        );
        assert_eq!(
            MachineValidation::extract_registry("ghcr.io/org/image:v1").unwrap(),
            "ghcr.io"
        );
    }

    #[test]
    fn extract_registry_handles_port_in_hostname() {
        assert_eq!(
            MachineValidation::extract_registry("localhost:5000/myimage:tag").unwrap(),
            "localhost:5000"
        );
    }

    #[test]
    fn extract_registry_handles_bare_localhost() {
        assert_eq!(
            MachineValidation::extract_registry("localhost/myrepo:tag").unwrap(),
            "localhost"
        );
    }

    #[test]
    fn extract_registry_errors_on_bare_image_name() {
        assert!(MachineValidation::extract_registry("ubuntu:22.04").is_err());
        assert!(MachineValidation::extract_registry("myimage:latest").is_err());
    }

    #[test]
    fn extract_registry_errors_on_docker_hub_shorthand() {
        // "library/ubuntu" has a slash but "library" is not a hostname
        assert!(MachineValidation::extract_registry("library/ubuntu").is_err());
    }
}
