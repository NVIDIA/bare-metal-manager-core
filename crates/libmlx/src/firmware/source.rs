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

// src/source.rs
// Defines the FirmwareSource enum for resolving firmware files from
// different locations: local filesystem, HTTPS, and SSH.

use std::path::{Path, PathBuf};

use forge_ssh::ssh_client::{AuthConfig, HostKeyVerification, SshClientConfig};
use tokio::io::AsyncWriteExt;
use tracing;

use crate::firmware::credentials::Credentials;
use crate::firmware::error::{FirmwareError, FirmwareResult};

// FirmwareSource represents a firmware binary location. Supported
// source types are local filesystem, HTTPS, and SSH/SCP.
pub enum FirmwareSource {
    // Local references a file on the local filesystem. Accepts
    // both absolute and relative paths, with or without a file://
    // prefix.
    Local {
        path: PathBuf,
    },
    // Http downloads firmware from an HTTPS (or HTTP) URL with
    // optional authentication credentials.
    Http {
        url: String,
        credentials: Option<Credentials>,
    },
    // Ssh fetches firmware from a remote host via SSH, using
    // key-based or agent authentication. Uses base64 encoding
    // for binary-safe transfer.
    Ssh(SshSource),
}

impl FirmwareSource {
    // local creates a Local source from a filesystem path.
    pub fn local(path: impl Into<PathBuf>) -> Self {
        Self::Local { path: path.into() }
    }

    // http creates an Http source for the given URL.
    pub fn http(url: impl Into<String>) -> Self {
        Self::Http {
            url: url.into(),
            credentials: None,
        }
    }

    // ssh creates an Ssh source with the given host and remote path.
    // Defaults to port 22 and the current user.
    pub fn ssh(host: impl Into<String>, remote_path: impl Into<String>) -> Self {
        Self::Ssh(SshSource {
            host: host.into(),
            port: 22,
            username: whoami().unwrap_or_else(|| "root".to_string()),
            remote_path: remote_path.into(),
            credentials: None,
        })
    }

    // from_url parses a URL string into a FirmwareSource. The URL
    // prefix determines the source type:
    //   - "https://" or "http://"  -> Http
    //   - "ssh://[user@]host:path" -> Ssh (SCP-style colon separator)
    //   - "file://path"            -> Local (strips the prefix)
    //   - anything else            -> Local (treated as a filesystem path)
    pub fn from_url(url: &str) -> FirmwareResult<Self> {
        if url.starts_with("https://") || url.starts_with("http://") {
            Ok(Self::http(url))
        } else if url.starts_with("ssh://") {
            let (host, username, remote_path) = parse_ssh_url(url)?;
            Ok(Self::Ssh(SshSource {
                host,
                port: 22,
                username,
                remote_path,
                credentials: None,
            }))
        } else if let Some(path) = url.strip_prefix("file://") {
            Ok(Self::local(path))
        } else {
            Ok(Self::local(url))
        }
    }

    // with_credentials sets the authentication credentials.
    // For Http sources, the credential must be an HTTP type
    // (BearerToken, BasicAuth, Header). For Ssh sources, it
    // must be an SSH type (SshKey, SshAgent). Validation happens
    // at resolve time.
    pub fn with_credentials(mut self, cred: Credentials) -> Self {
        match &mut self {
            Self::Http { credentials, .. } => *credentials = Some(cred),
            Self::Ssh(SshSource { credentials, .. }) => *credentials = Some(cred),
            Self::Local { .. } => {} // no-op for local sources
        }
        self
    }

    // with_port sets the SSH port. Only affects Ssh sources.
    pub fn with_port(mut self, p: u16) -> Self {
        if let Self::Ssh(SshSource { port, .. }) = &mut self {
            *port = p;
        }
        self
    }

    // with_username sets the SSH username. Only affects Ssh sources.
    pub fn with_username(mut self, user: impl Into<String>) -> Self {
        if let Self::Ssh(SshSource { username, .. }) = &mut self {
            *username = user.into();
        }
        self
    }

    // resolve resolves the firmware to a local file path, downloading
    // or copying as necessary. The work_dir is used as a staging area
    // for any files that need to be fetched from remote sources.
    pub async fn resolve(&self, work_dir: &Path) -> FirmwareResult<PathBuf> {
        match self {
            Self::Local { path } => resolve_local(path).await,
            Self::Http { url, credentials } => {
                resolve_http(url, credentials.as_ref(), work_dir).await
            }
            Self::Ssh(ssh_source) => resolve_ssh(ssh_source, work_dir, None).await,
        }
    }

    // description returns a human-readable description of the
    // firmware source location, suitable for logging.
    pub fn description(&self) -> String {
        match self {
            Self::Local { path } => format!("local:{}", path.display()),
            Self::Http { url, .. } => format!("http:{url}"),
            Self::Ssh(SshSource {
                host,
                port,
                username,
                remote_path,
                ..
            }) => format!("ssh://{username}@{host}:{port}:{remote_path}"),
        }
    }
}

// resolve_local validates that a local file exists and returns its path.
async fn resolve_local(path: &Path) -> FirmwareResult<PathBuf> {
    tracing::info!(path = %path.display(), "Resolving local source");
    if !path.exists() {
        return Err(FirmwareError::FileNotFound(path.to_path_buf()));
    }
    Ok(path.to_path_buf())
}

// resolve_http downloads firmware from an HTTP(S) URL with optional
// credentials to the work directory.
async fn resolve_http(
    url: &str,
    credentials: Option<&Credentials>,
    work_dir: &Path,
) -> FirmwareResult<PathBuf> {
    // Extract filename from URL, falling back to a generic name.
    let filename = url::Url::parse(url)
        .ok()
        .and_then(|u| {
            u.path_segments()
                .and_then(|mut s| s.next_back())
                .map(str::to_string)
        })
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "firmware.bin".to_string());

    let dest_path = work_dir.join(&filename);

    tracing::info!(url = %url, "Downloading via HTTP");
    if let Some(creds) = credentials {
        tracing::debug!(credential_type = %credential_type_name(creds), "Using HTTP credentials");
    }

    // Build the HTTP request with optional credentials.
    let client = reqwest::Client::new();
    let mut request = client.get(url);

    if let Some(creds) = credentials {
        creds.validate_http()?;
        request = match creds {
            Credentials::BearerToken { token } => request.bearer_auth(token),
            Credentials::BasicAuth { username, password } => {
                request.basic_auth(username, Some(password))
            }
            Credentials::Header { name, value } => request.header(name, value),
            _ => request, // validated above
        };
    }

    let response = request
        .send()
        .await
        .map_err(|e| FirmwareError::HttpError(format!("Failed to download from {url}: {e}")))?;

    if !response.status().is_success() {
        return Err(FirmwareError::HttpError(format!(
            "HTTP {} from {url}",
            response.status(),
        )));
    }

    // Stream the response body to disk.
    let bytes = response
        .bytes()
        .await
        .map_err(|e| FirmwareError::HttpError(format!("Failed to read response body: {e}")))?;

    let mut file = tokio::fs::File::create(&dest_path)
        .await
        .map_err(FirmwareError::Io)?;

    file.write_all(&bytes).await.map_err(FirmwareError::Io)?;
    file.flush().await.map_err(FirmwareError::Io)?;

    tracing::info!(
        dest = %dest_path.display(),
        bytes = bytes.len(),
        "HTTP download complete"
    );

    Ok(dest_path)
}

pub struct SshSource {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub remote_path: String,
    pub credentials: Option<Credentials>,
}

// resolve_ssh fetches firmware from a remote host via SSH using
// base64 encoding for binary-safe transfer.
async fn resolve_ssh(
    ssh_source: &SshSource,
    work_dir: &Path,
    known_hosts_file: Option<&Path>,
) -> FirmwareResult<PathBuf> {
    let SshSource {
        host,
        port,
        username,
        remote_path,
        credentials,
    } = ssh_source;

    let dest_path = work_dir.join(
        Path::new(remote_path)
            .file_name()
            .unwrap_or("firmware.bin".as_ref()),
    );

    tracing::info!(
        host = %host,
        port = %port,
        user = %username,
        path = %remote_path,
        "Downloading via SSH"
    );

    if let Some(creds) = credentials {
        tracing::debug!(credential_type = %credential_type_name(creds), "Using SSH credentials");
    }

    let auth = credentials.clone().map(AuthConfig::try_from).transpose()?;

    let host_key_verification = match known_hosts_file {
        Some(path) => HostKeyVerification::KnownHostsFile(path.to_path_buf()),
        None => HostKeyVerification::DefaultKnownHostsFile,
    };

    let client = SshClientConfig {
        host,
        port: *port,
        username,
        auth: auth.as_ref(),
        host_key_verification,
    }
    .make_authenticated_client()
    .await?;

    // Transfer the file over SSH using base64 encoding. Base64 keeps the
    // command output text-safe before we decode it back to bytes locally.
    // Use `cat | base64` for portability across Linux (coreutils) and
    // macOS (BSD). Positional file args and the -w0 flag are not portable.
    let command = format!("cat {} | base64", shell_escape(remote_path));
    let result = client.execute_ssh_command(&command).await?;

    if result.exit_status != 0 {
        return Err(FirmwareError::CommandFailed(format!(
            "Remote command failed (exit {}): {}",
            result.exit_status,
            result.stderr.trim()
        )));
    }

    // Decode the base64 output back to raw bytes. Strip all
    // whitespace first since both Linux and macOS base64 wrap
    // output at 76 characters by default.
    use base64::Engine;
    let mut b64 = result.stdout;
    b64.retain(|c| !c.is_whitespace());
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| {
            FirmwareError::CommandFailed(format!("Failed to decode base64 transfer: {e}"))
        })?;

    tokio::fs::write(&dest_path, &decoded)
        .await
        .map_err(FirmwareError::Io)?;

    tracing::info!(
        dest = %dest_path.display(),
        bytes = decoded.len(),
        "SSH download complete"
    );

    Ok(dest_path)
}

// credential_type_name returns a human-readable name for a credential
// type, safe for logging (never includes the actual secret).
fn credential_type_name(cred: &Credentials) -> &'static str {
    match cred {
        Credentials::BearerToken { .. } => "bearer_token",
        Credentials::BasicAuth { .. } => "basic_auth",
        Credentials::Header { .. } => "header",
        Credentials::SshKey { .. } => "ssh_key",
        Credentials::SshAgent => "ssh_agent",
    }
}

// parse_ssh_url parses an SCP-style SSH URL into its components.
// Format: ssh://[user@]host:path
//
// The colon separates host from path (SCP convention). This supports
// both relative and absolute remote paths:
//   ssh://user@host:relative/path   -> relative path from home dir
//   ssh://user@host:/absolute/path  -> absolute path
//
// User defaults to the current user if omitted.
fn parse_ssh_url(url: &str) -> FirmwareResult<(String, String, String)> {
    let stripped = url
        .strip_prefix("ssh://")
        .ok_or_else(|| FirmwareError::ConfigError(format!("Not an SSH URL: '{url}'")))?;

    let (host_part, remote_path) = stripped.split_once(':').ok_or_else(|| {
        FirmwareError::ConfigError(format!(
            "SSH URL must use ssh://[user@]host:path format, got: '{url}'"
        ))
    })?;

    if remote_path.is_empty() {
        return Err(FirmwareError::ConfigError(format!(
            "SSH URL missing remote file path: '{url}'"
        )));
    }

    let (username, host) = if let Some((user, h)) = host_part.split_once('@') {
        (user.to_string(), h.to_string())
    } else {
        (
            whoami().unwrap_or_else(|| "root".to_string()),
            host_part.to_string(),
        )
    };

    if host.is_empty() {
        return Err(FirmwareError::ConfigError(format!(
            "SSH URL missing host: '{url}'"
        )));
    }

    Ok((host, username, remote_path.to_string()))
}

// whoami returns the current username, if available.
fn whoami() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .ok()
}

// shell_escape performs basic shell escaping for a path string to
// prevent command injection in SSH commands.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use base64::Engine;
    use forge_ssh::ssh_client::tests::TestSshServer;
    use russh::keys::known_hosts::learn_known_hosts_path;
    use russh::keys::signature::digest::common::getrandom::SysRng;
    use russh::keys::ssh_key::LineEnding;
    use russh::keys::ssh_key::rand_core::UnwrapErr;
    use tempfile::tempdir;

    use super::*;

    #[tokio::test]
    async fn resolve_ssh_fetches_firmware_from_russh_server()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let work_dir = temp_dir.path().join("work");
        tokio::fs::create_dir(&work_dir).await?;

        let mut rng = SysRng;
        let client_key = russh::keys::PrivateKey::random(
            &mut UnwrapErr(&mut rng),
            russh::keys::Algorithm::Ed25519,
        )?;
        let client_key_path = temp_dir.path().join("id_ed25519");
        client_key.write_openssh_file(&client_key_path, LineEnding::LF)?;

        let remote_path = "/firmware/mlx-fw.bin".to_string();
        let firmware = b"firmware bytes\0with binary data\n".to_vec();
        let firmware_encoded = base64::engine::general_purpose::STANDARD.encode(&firmware);
        let server = TestSshServer::spawn(
            "firmware-user".to_string(),
            client_key.public_key().clone(),
            HashMap::from([(
                format!("cat {} | base64", shell_escape(&remote_path)),
                firmware_encoded,
            )]),
        )
        .await?;

        let known_hosts_path = temp_dir.path().join(".ssh").join("known_hosts");
        learn_known_hosts_path(
            "127.0.0.1",
            server.port,
            &server.host_public_key,
            &known_hosts_path,
        )?;

        let ssh_source = SshSource {
            host: "127.0.0.1".into(),
            port: server.port,
            username: "firmware-user".into(),
            remote_path,
            credentials: Some(Credentials::ssh_key(
                client_key_path.to_string_lossy().into_owned(),
            )),
        };

        let resolved_path =
            resolve_ssh(&ssh_source, &work_dir, Some(known_hosts_path.as_path())).await?;

        assert_eq!(resolved_path, work_dir.join("mlx-fw.bin"));
        assert_eq!(tokio::fs::read(resolved_path).await?, firmware);

        Ok(())
    }
}
