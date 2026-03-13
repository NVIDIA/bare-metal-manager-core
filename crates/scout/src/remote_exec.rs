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

use std::path::Path;

use futures_util::TryStreamExt;
use rpc::forge::{ScoutRemoteExecRequest, ScoutRemoteExecResponse};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

// handle_remote_exec downloads files and a script from carbide-api,
// then executes the script on the host.
pub async fn handle_remote_exec(
    client: &reqwest::Client,
    request: ScoutRemoteExecRequest,
) -> ScoutRemoteExecResponse {
    match run_remote_exec(client, &request).await {
        Ok(response) => response,
        Err(e) => ScoutRemoteExecResponse {
            success: false,
            exit_code: -1,
            stdout: String::new(),
            stderr: String::new(),
            error: format!("remote execution failed: {e}"),
        },
    }
}

async fn run_remote_exec(
    client: &reqwest::Client,
    request: &ScoutRemoteExecRequest,
) -> Result<ScoutRemoteExecResponse, Box<dyn std::error::Error>> {
    tracing::info!(
        "[remote_exec] starting for component={} version={}",
        request.component_type,
        request.target_version,
    );

    let work_dir = tempfile::tempdir()?;

    // Download the script.
    let script_path = download_file(client, &request.script_url, work_dir.path()).await?;
    tracing::info!("[remote_exec] script downloaded to {:?}", script_path);

    // Download files and verify checksums.
    let download_dir = work_dir.path().join("downloads");
    std::fs::create_dir_all(&download_dir)?;
    for (url, expected_sha256) in &request.download_files {
        let dest = download_file(client, url, &download_dir).await?;
        let actual = sha256_file(&dest).await?;
        if actual != *expected_sha256 {
            return Err(format!(
                "checksum mismatch for {url}: expected {expected_sha256}, got {actual}"
            )
            .into());
        }
        tracing::info!("[remote_exec] checksum verified for {url}");
    }

    tracing::info!(
        "[remote_exec] files downloaded. Executing script {:?}",
        script_path,
    );

    // Execute the script with env vars for context.
    // kill_on_drop ensures the child process is terminated if the timeout fires,
    // preventing orphaned processes and races with tempdir cleanup.
    let child = tokio::process::Command::new("sh")
        .arg(&script_path)
        .env("DOWNLOAD_DIR", &download_dir)
        .env("COMPONENT_TYPE", &request.component_type)
        .env("TARGET_VERSION", &request.target_version)
        .current_dir(work_dir.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let timeout = std::time::Duration::from_secs(request.timeout_seconds.into());
    let result = tokio::time::timeout(timeout, child.wait_with_output()).await;

    match result {
        Ok(Ok(output)) => {
            // from_utf8_lossy always allocates a new string from the stdout/stderr, even if it's valid utf8.
            // it's possible the stdout can get quite large, so it's probably best to avoid it in the happy path.
            let stdout = String::from_utf8(output.stdout)
                .unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned());
            let stderr = String::from_utf8(output.stderr)
                .unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned());
            let exit_code = output.status.code().unwrap_or(-1);
            let success = output.status.success();

            if !stdout.is_empty() {
                tracing::info!("[remote_exec] stdout: {stdout}");
            }
            if !stderr.is_empty() {
                tracing::warn!("[remote_exec] stderr: {stderr}");
            }

            Ok(ScoutRemoteExecResponse {
                success,
                exit_code,
                stdout,
                stderr,
                error: String::new(),
            })
        }
        Ok(Err(e)) => Err(format!("failed to execute script: {e}").into()),
        Err(_) => Ok(ScoutRemoteExecResponse {
            success: false,
            exit_code: -1,
            stdout: String::new(),
            stderr: String::new(),
            error: format!("script timed out after {} seconds", request.timeout_seconds),
        }),
    }
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

    tracing::info!("[remote_exec] downloading {url} -> {dest:?}");

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
    let bytes = tokio::fs::read(path).await?;
    let hash = Sha256::digest(&bytes);
    Ok(format!("{hash:x}"))
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

    #[tokio::test]
    async fn test_successful_upgrade() {
        let script = "#!/bin/sh\necho \"upgrade complete\"";
        let firmware_content = "binary-data";
        let base = start_file_server(vec![
            ("/scripts/upgrade.sh", script),
            ("/firmware/blob.bin", firmware_content),
        ])
        .await;

        let fw_url = format!("{base}/firmware/blob.bin");
        let request = ScoutRemoteExecRequest {
            component_type: "cpld".into(),
            target_version: "1.2.3".into(),
            script_url: format!("{base}/scripts/upgrade.sh"),
            timeout_seconds: 30,
            download_files: [(fw_url, sha256_hex(firmware_content))]
                .into_iter()
                .collect(),
        };

        let response = handle_remote_exec(&reqwest::Client::new(), request).await;

        assert!(
            response.success,
            "expected success, got error: {}",
            response.error
        );
        assert_eq!(response.exit_code, 0);
        assert!(response.stdout.contains("upgrade complete"));
        assert!(response.error.is_empty());
    }

    #[tokio::test]
    async fn test_script_failure_returns_exit_code() {
        let script = "#!/bin/sh\necho \"something went wrong\" >&2\nexit 42";
        let base = start_file_server(vec![("/scripts/fail.sh", script)]).await;

        let request = ScoutRemoteExecRequest {
            component_type: "bios".into(),
            target_version: "2.0.0".into(),
            script_url: format!("{base}/scripts/fail.sh"),
            timeout_seconds: 30,
            download_files: Default::default(),
        };

        let response = handle_remote_exec(&reqwest::Client::new(), request).await;

        assert!(!response.success);
        assert_eq!(response.exit_code, 42);
        assert!(response.stderr.contains("something went wrong"));
    }

    #[tokio::test]
    async fn test_script_timeout() {
        let script = "#!/bin/sh\nsleep 60";
        let base = start_file_server(vec![("/scripts/slow.sh", script)]).await;

        let request = ScoutRemoteExecRequest {
            component_type: "cpld".into(),
            target_version: "1.0.0".into(),
            script_url: format!("{base}/scripts/slow.sh"),
            timeout_seconds: 1,
            download_files: Default::default(),
        };

        let response = handle_remote_exec(&reqwest::Client::new(), request).await;

        assert!(!response.success);
        assert!(response.error.contains("timed out"));
    }

    #[tokio::test]
    async fn test_script_receives_env_vars() {
        let script =
            "#!/bin/sh\necho \"comp=$COMPONENT_TYPE ver=$TARGET_VERSION dir=$DOWNLOAD_DIR\"";
        let base = start_file_server(vec![("/scripts/env.sh", script)]).await;

        let request = ScoutRemoteExecRequest {
            component_type: "cpldmb".into(),
            target_version: "3.4.5".into(),
            script_url: format!("{base}/scripts/env.sh"),
            timeout_seconds: 30,
            download_files: Default::default(),
        };

        let response = handle_remote_exec(&reqwest::Client::new(), request).await;

        assert!(response.success, "error: {}", response.error);
        assert!(response.stdout.contains("comp=cpldmb"));
        assert!(response.stdout.contains("ver=3.4.5"));
        assert!(response.stdout.contains("dir="));
    }

    #[tokio::test]
    async fn test_download_failure() {
        // Point at a URL that will 404.
        let base = start_file_server(vec![]).await;

        let request = ScoutRemoteExecRequest {
            component_type: "cpld".into(),
            target_version: "1.0.0".into(),
            script_url: format!("{base}/scripts/nonexistent.sh"),
            timeout_seconds: 30,
            download_files: Default::default(),
        };

        let response = handle_remote_exec(&reqwest::Client::new(), request).await;

        assert!(!response.success);
        assert!(!response.error.is_empty());
    }

    #[tokio::test]
    async fn test_checksum_mismatch() {
        let script = "#!/bin/sh\necho ok";
        let base = start_file_server(vec![
            ("/scripts/upgrade.sh", script),
            ("/firmware/fw.bin", "actual-content"),
        ])
        .await;

        let fw_url = format!("{base}/firmware/fw.bin");
        let request = ScoutRemoteExecRequest {
            component_type: "cpld".into(),
            target_version: "1.0.0".into(),
            script_url: format!("{base}/scripts/upgrade.sh"),
            timeout_seconds: 30,
            download_files: [(fw_url, "bad_checksum".to_string())].into_iter().collect(),
        };

        let response = handle_remote_exec(&reqwest::Client::new(), request).await;

        assert!(!response.success);
        assert!(response.error.contains("checksum mismatch"));
    }
}
