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

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SCRIPT_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_MAX_RETRIES: u32 = 3;

// FirmwareUpgradeTask represents the JSON payload received from
// carbide-api via ForgeAgentControl when Action::FirmwareUpgrade is set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirmwareUpgradeTask {
    pub upgrade_task_id: String,
    pub component_type: String,
    pub target_version: String,
    pub script: FileArtifact,
    pub execution_timeout_seconds: u32,
    pub artifact_download_timeout_seconds: u32,
    pub file_artifacts: Vec<FileArtifact>,
}

// FileArtifact represents a file to download with its expected checksum.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileArtifact {
    pub url: String,
    pub sha256: String,
}

// FirmwareUpgradeResult captures the outcome of a firmware upgrade execution.
// Fields will be used when ReportScoutFirmwareUpgradeStatus RPC is implemented.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct FirmwareUpgradeResult {
    pub success: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub error: String,
}

// handle_firmware_upgrade downloads file artifacts and a script from carbide-api,
// then executes the script on the host.
pub async fn handle_firmware_upgrade(
    client: &reqwest::Client,
    task: &FirmwareUpgradeTask,
) -> FirmwareUpgradeResult {
    match run_firmware_upgrade(client, task).await {
        Ok(result) => result,
        Err(e) => FirmwareUpgradeResult {
            success: false,
            exit_code: -1,
            stdout: String::new(),
            stderr: String::new(),
            error: format!("firmware upgrade failed: {e}"),
        },
    }
}

async fn run_firmware_upgrade(
    client: &reqwest::Client,
    task: &FirmwareUpgradeTask,
) -> Result<FirmwareUpgradeResult, Box<dyn std::error::Error>> {
    tracing::info!(
        "[firmware_upgrade] starting for component={} version={}",
        task.component_type,
        task.target_version,
    );

    let work_dir = tempfile::tempdir()?;

    let download_timeout = Duration::from_secs(task.artifact_download_timeout_seconds.into());

    // Download the script and verify its checksum.
    let script_path = tokio::time::timeout(
        SCRIPT_DOWNLOAD_TIMEOUT,
        download_file_with_retries(client, &task.script.url, work_dir.path()),
    )
    .await
    .map_err(|_| {
        format!(
            "script download timed out after {} seconds",
            SCRIPT_DOWNLOAD_TIMEOUT.as_secs()
        )
    })??;
    let actual = sha256_file(&script_path).await?;
    if actual != task.script.sha256 {
        return Err(format!(
            "checksum mismatch for script {}: expected {}, got {actual}",
            task.script.url, task.script.sha256
        )
        .into());
    }
    tracing::info!(
        "[firmware_upgrade] script downloaded and verified: {:?}",
        script_path
    );

    // Download file artifacts and verify checksums.
    let download_dir = work_dir.path().join("downloads");
    tokio::fs::create_dir_all(&download_dir).await?;
    for artifact in &task.file_artifacts {
        let dest = tokio::time::timeout(
            download_timeout,
            download_file_with_retries(client, &artifact.url, &download_dir),
        )
        .await
        .map_err(|_| {
            format!(
                "download timed out for {} after {} seconds",
                artifact.url, task.artifact_download_timeout_seconds
            )
        })??;
        let actual = sha256_file(&dest).await?;
        if actual != artifact.sha256 {
            return Err(format!(
                "checksum mismatch for {}: expected {}, got {actual}",
                artifact.url, artifact.sha256
            )
            .into());
        }
        tracing::info!("[firmware_upgrade] checksum verified for {}", artifact.url);
    }

    tracing::info!(
        "[firmware_upgrade] files downloaded. Executing script {:?}",
        script_path,
    );

    // Execute the script with env vars for context.
    // kill_on_drop ensures the child process is terminated if the timeout fires,
    // preventing orphaned processes and races with tempdir cleanup.
    let child = tokio::process::Command::new("sh")
        .arg(&script_path)
        .env("DOWNLOAD_DIR", &download_dir)
        .env("COMPONENT_TYPE", &task.component_type)
        .env("TARGET_VERSION", &task.target_version)
        .current_dir(work_dir.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let timeout = std::time::Duration::from_secs(task.execution_timeout_seconds.into());
    let result = tokio::time::timeout(timeout, child.wait_with_output()).await;

    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8(output.stdout)
                .unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned());
            let stderr = String::from_utf8(output.stderr)
                .unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned());
            let exit_code = output.status.code().unwrap_or(-1);
            let success = output.status.success();

            if !stdout.is_empty() {
                tracing::info!("[firmware_upgrade] stdout: {stdout}");
            }
            if !stderr.is_empty() {
                tracing::warn!("[firmware_upgrade] stderr: {stderr}");
            }

            Ok(FirmwareUpgradeResult {
                success,
                exit_code,
                stdout,
                stderr,
                error: String::new(),
            })
        }
        Ok(Err(e)) => Err(format!("failed to execute script: {e}").into()),
        Err(_) => Ok(FirmwareUpgradeResult {
            success: false,
            exit_code: -1,
            stdout: String::new(),
            stderr: String::new(),
            error: format!(
                "script timed out after {} seconds",
                task.execution_timeout_seconds
            ),
        }),
    }
}

async fn download_file_with_retries(
    client: &reqwest::Client,
    url: &str,
    target_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let url_owned = url.to_string();
    let result = tryhard::retry_fn(|| download_file(client, &url_owned, target_dir))
        .retries(DOWNLOAD_MAX_RETRIES)
        .exponential_backoff(Duration::from_secs(1))
        .on_retry(|attempt, next_delay, error| {
            let delay = next_delay.unwrap_or_default();
            tracing::warn!(
                "[firmware_upgrade] download attempt {attempt} failed for {}: {error}, retrying in {delay:?}",
                url_owned
            );
            std::future::ready(())
        })
        .await?;
    Ok(result)
}

// download_file downloads a file from the given URL into the target directory,
// preserving the filename from the URL path.
async fn download_file(
    client: &reqwest::Client,
    url: &str,
    target_dir: &Path,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let parsed = reqwest::Url::parse(url)?;
    let segment = parsed
        .path_segments()
        .and_then(|mut s| s.next_back())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("cannot extract filename from URL: {url}"))?;

    let filename = Path::new(segment)
        .file_name()
        .ok_or_else(|| format!("invalid filename in URL: {url}"))?;

    let dest = target_dir.join(filename);

    tracing::info!("[firmware_upgrade] downloading {url} -> {dest:?}");

    let response = client.get(url).send().await?.error_for_status()?;
    let mut stream = response.bytes_stream();

    let mut file = tokio::fs::File::create(&dest).await?;
    while let Some(chunk) = stream.try_next().await? {
        file.write_all(&chunk).await?;
    }
    file.flush().await?;

    Ok(dest)
}

async fn sha256_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::routing::get;
    use tokio::net::TcpListener;

    use super::*;

    // start_file_server spins up a lightweight HTTP server that serves
    // static content at the given routes. Returns the base URL.
    async fn start_file_server(routes: Vec<(&'static str, &'static str)>) -> String {
        let mut app = Router::new();
        for (path, body) in routes {
            app = app.route(path, get(move || async move { body }));
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        format!("http://{addr}")
    }

    fn sha256_hex(data: &str) -> String {
        format!("{:x}", Sha256::digest(data.as_bytes()))
    }

    fn script_artifact(base: &str, path: &str, content: &str) -> FileArtifact {
        FileArtifact {
            url: format!("{base}{path}"),
            sha256: sha256_hex(content),
        }
    }

    #[tokio::test]
    async fn test_successful_upgrade() {
        let script = "#!/bin/sh\necho \"upgrade complete\"";
        let firmware_content = "binary-data";
        let base = start_file_server(vec![
            ("/scripts/upgrade.sh", script),
            ("/firmware/blob.bin", firmware_content),
        ])
        .await;

        let task = FirmwareUpgradeTask {
            upgrade_task_id: "test-upgrade-task-id".into(),
            component_type: "cpld".into(),
            target_version: "1.2.3".into(),
            script: script_artifact(&base, "/scripts/upgrade.sh", script),
            execution_timeout_seconds: 30,
            artifact_download_timeout_seconds: 30,
            file_artifacts: vec![FileArtifact {
                url: format!("{base}/firmware/blob.bin"),
                sha256: sha256_hex(firmware_content),
            }],
        };

        let result = handle_firmware_upgrade(&reqwest::Client::new(), &task).await;

        assert!(
            result.success,
            "expected success, got error: {}",
            result.error
        );
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("upgrade complete"));
        assert!(result.error.is_empty());
    }

    #[tokio::test]
    async fn test_script_failure_returns_exit_code() {
        let script = "#!/bin/sh\necho \"something went wrong\" >&2\nexit 42";
        let base = start_file_server(vec![("/scripts/fail.sh", script)]).await;

        let task = FirmwareUpgradeTask {
            upgrade_task_id: "test-upgrade-task-id".into(),
            component_type: "bios".into(),
            target_version: "2.0.0".into(),
            script: script_artifact(&base, "/scripts/fail.sh", script),
            execution_timeout_seconds: 30,
            artifact_download_timeout_seconds: 30,
            file_artifacts: vec![],
        };

        let result = handle_firmware_upgrade(&reqwest::Client::new(), &task).await;

        assert!(!result.success);
        assert_eq!(result.exit_code, 42);
        assert!(result.stderr.contains("something went wrong"));
    }

    #[tokio::test]
    async fn test_script_timeout() {
        let script = "#!/bin/sh\nsleep 60";
        let base = start_file_server(vec![("/scripts/slow.sh", script)]).await;

        let task = FirmwareUpgradeTask {
            upgrade_task_id: "test-upgrade-task-id".into(),
            component_type: "cpld".into(),
            target_version: "1.0.0".into(),
            script: script_artifact(&base, "/scripts/slow.sh", script),
            execution_timeout_seconds: 1,
            artifact_download_timeout_seconds: 30,
            file_artifacts: vec![],
        };

        let result = handle_firmware_upgrade(&reqwest::Client::new(), &task).await;

        assert!(!result.success);
        assert!(result.error.contains("timed out"));
    }

    #[tokio::test]
    async fn test_script_receives_env_vars() {
        let script =
            "#!/bin/sh\necho \"comp=$COMPONENT_TYPE ver=$TARGET_VERSION dir=$DOWNLOAD_DIR\"";
        let base = start_file_server(vec![("/scripts/env.sh", script)]).await;

        let task = FirmwareUpgradeTask {
            upgrade_task_id: "test-upgrade-task-id".into(),
            component_type: "cpldmb".into(),
            target_version: "3.4.5".into(),
            script: script_artifact(&base, "/scripts/env.sh", script),
            execution_timeout_seconds: 30,
            artifact_download_timeout_seconds: 30,
            file_artifacts: vec![],
        };

        let result = handle_firmware_upgrade(&reqwest::Client::new(), &task).await;

        assert!(result.success, "error: {}", result.error);
        assert!(result.stdout.contains("comp=cpldmb"));
        assert!(result.stdout.contains("ver=3.4.5"));
        assert!(result.stdout.contains("dir="));
    }

    #[tokio::test]
    async fn test_download_failure() {
        let base = start_file_server(vec![]).await;

        let task = FirmwareUpgradeTask {
            upgrade_task_id: "test-upgrade-task-id".into(),
            component_type: "cpld".into(),
            target_version: "1.0.0".into(),
            script: FileArtifact {
                url: format!("{base}/scripts/nonexistent.sh"),
                sha256: "doesntmatter".into(),
            },
            execution_timeout_seconds: 30,
            artifact_download_timeout_seconds: 30,
            file_artifacts: vec![],
        };

        let result = handle_firmware_upgrade(&reqwest::Client::new(), &task).await;

        assert!(!result.success);
        assert!(!result.error.is_empty());
    }

    #[tokio::test]
    async fn test_checksum_mismatch() {
        let script = "#!/bin/sh\necho ok";
        let base = start_file_server(vec![
            ("/scripts/upgrade.sh", script),
            ("/firmware/fw.bin", "actual-content"),
        ])
        .await;

        let task = FirmwareUpgradeTask {
            upgrade_task_id: "test-upgrade-task-id".into(),
            component_type: "cpld".into(),
            target_version: "1.0.0".into(),
            script: script_artifact(&base, "/scripts/upgrade.sh", script),
            execution_timeout_seconds: 30,
            artifact_download_timeout_seconds: 30,
            file_artifacts: vec![FileArtifact {
                url: format!("{base}/firmware/fw.bin"),
                sha256: "bad_checksum".to_string(),
            }],
        };

        let result = handle_firmware_upgrade(&reqwest::Client::new(), &task).await;

        assert!(!result.success);
        assert!(result.error.contains("checksum mismatch"));
    }

    #[tokio::test]
    async fn test_script_checksum_mismatch() {
        let script = "#!/bin/sh\necho ok";
        let base = start_file_server(vec![("/scripts/upgrade.sh", script)]).await;

        let task = FirmwareUpgradeTask {
            upgrade_task_id: "test-upgrade-task-id".into(),
            component_type: "cpld".into(),
            target_version: "1.0.0".into(),
            script: FileArtifact {
                url: format!("{base}/scripts/upgrade.sh"),
                sha256: "bad_checksum".into(),
            },
            execution_timeout_seconds: 30,
            artifact_download_timeout_seconds: 30,
            file_artifacts: vec![],
        };

        let result = handle_firmware_upgrade(&reqwest::Client::new(), &task).await;

        assert!(!result.success);
        assert!(result.error.contains("checksum mismatch for script"));
    }

    #[tokio::test]
    async fn test_task_json_ser_deser_roundtrip() {
        let task = FirmwareUpgradeTask {
            upgrade_task_id: "roundtrip-upgrade-task-id".into(),
            component_type: "cpld".into(),
            target_version: "1.2.3".into(),
            script: FileArtifact {
                url: "http://example.com/script.sh".into(),
                sha256: "scripthash".into(),
            },
            execution_timeout_seconds: 300,
            artifact_download_timeout_seconds: 120,
            file_artifacts: vec![FileArtifact {
                url: "http://example.com/fw.bin".into(),
                sha256: "abc123".into(),
            }],
        };

        let json = serde_json::to_string(&task).unwrap();
        let parsed: FirmwareUpgradeTask = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.component_type, "cpld");
        assert_eq!(parsed.upgrade_task_id, "roundtrip-upgrade-task-id");
        assert_eq!(parsed.target_version, "1.2.3");
        assert_eq!(parsed.script.url, "http://example.com/script.sh");
        assert_eq!(parsed.script.sha256, "scripthash");
        assert_eq!(parsed.execution_timeout_seconds, 300);
        assert_eq!(parsed.artifact_download_timeout_seconds, 120);
        assert_eq!(parsed.file_artifacts.len(), 1);
        assert_eq!(parsed.file_artifacts[0].url, "http://example.com/fw.bin");
        assert_eq!(parsed.file_artifacts[0].sha256, "abc123");
    }
}
