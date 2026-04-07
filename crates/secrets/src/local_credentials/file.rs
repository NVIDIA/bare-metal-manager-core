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
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use notify::{PollWatcher, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::CredentialSnapshot;
use crate::SecretsError;
use crate::credentials::{CredentialKey, CredentialReader, Credentials};

const DEFAULT_FILE_POLL_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_CREDENTIALS_FILE_PATH: &str = "secrets.yaml";

#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct FileCredentialsConfig {
    pub enabled: Option<bool>,
    pub path: Option<PathBuf>,
    pub poll_interval: Option<Duration>,
}

impl FileCredentialsConfig {
    pub fn enabled(&self) -> bool {
        self.enabled
            .or_else(|| {
                std::env::var("CARBIDE_CREDENTIALS_FILE_ENABLED")
                    .ok()
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(false)
    }

    pub fn path(&self) -> PathBuf {
        self.path
            .clone()
            .or_else(|| {
                std::env::var("CARBIDE_CREDENTIALS_FILE_PATH")
                    .ok()
                    .map(PathBuf::from)
            })
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CREDENTIALS_FILE_PATH))
    }

    pub fn poll_interval(&self) -> Duration {
        self.poll_interval.unwrap_or(DEFAULT_FILE_POLL_INTERVAL)
    }
}

pub struct FileCredentialsWatcher {
    credentials: Arc<ArcSwap<CredentialSnapshot>>,
    _primary_watcher: RecommendedWatcher,
    _secondary_watcher: PollWatcher,
}

impl FileCredentialsWatcher {
    pub async fn new(config: FileCredentialsConfig) -> Result<Self, SecretsError> {
        let path = config.path();
        let poll_interval = config.poll_interval();
        let credentials = Arc::new(ArcSwap::from_pointee(Self::load_file(&path).await?));
        let (tx, mut rx) = mpsc::channel(4);

        let tx_clone = tx.clone();
        let mut primary = RecommendedWatcher::new(
            move |res: notify::Result<notify::Event>| match res {
                Ok(ref event) if event.kind.is_create() || event.kind.is_modify() => {
                    if let Err(err) = tx_clone.blocking_send(res) {
                        tracing::warn!("failed to send static credential watch event: {err}");
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!("primary static credential watcher error: {err}");
                }
            },
            notify::Config::default(),
        )
        .map_err(|err| SecretsError::GenericError(err.into()))?;

        primary
            .watch(&path, RecursiveMode::NonRecursive)
            .map_err(|err| SecretsError::GenericError(err.into()))?;

        let mut secondary = PollWatcher::new(
            move |res| {
                if let Err(err) = tx.blocking_send(res) {
                    tracing::warn!("failed to send static credential poll event: {err}");
                }
            },
            notify::Config::default()
                .with_poll_interval(poll_interval)
                .with_compare_contents(true),
        )
        .map_err(|err| SecretsError::GenericError(err.into()))?;

        secondary
            .watch(&path, RecursiveMode::NonRecursive)
            .map_err(|err| SecretsError::GenericError(err.into()))?;

        let watched_path = path.clone();
        let credentials_clone = credentials.clone();
        tokio::spawn(async move {
            while let Some(event_result) = rx.recv().await {
                match event_result {
                    Ok(event) => {
                        if !event
                            .paths
                            .iter()
                            .any(|event_path| event_path.file_name() == watched_path.file_name())
                        {
                            continue;
                        }

                        match Self::load_file(&watched_path).await {
                            Ok(updated) => {
                                credentials_clone.store(Arc::new(updated));
                            }
                            Err(err) => {
                                tracing::warn!("failed to reload credentials file: {err}");
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!("credentials file watcher event error: {err}");
                    }
                }
            }
        });

        Ok(Self {
            credentials,
            _primary_watcher: primary,
            _secondary_watcher: secondary,
        })
    }

    async fn load_file(path: &Path) -> Result<CredentialSnapshot, SecretsError> {
        let content = tokio::fs::read(path)
            .await
            .map_err(|err| SecretsError::GenericError(err.into()))?;

        if let Ok(parsed) = serde_json::from_slice::<CredentialSnapshot>(&content) {
            return Ok(parsed);
        }

        let parsed = serde_yaml::from_slice::<CredentialSnapshot>(&content).map_err(|err| {
            SecretsError::GenericError(eyre::eyre!(
                "failed to parse static credential file as JSON or YAML: {err}"
            ))
        })?;
        Ok(parsed)
    }
}

#[async_trait]
impl CredentialReader for FileCredentialsWatcher {
    async fn get_credentials(
        &self,
        key: &CredentialKey,
    ) -> Result<Option<Credentials>, SecretsError> {
        self.credentials.load().get_credentials(key).await
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::credentials::{CredentialKey, CredentialType, Credentials};

    #[tokio::test]
    async fn loads_json_file_and_reloads_on_change() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("credentials.json");
        tokio::fs::write(
            &file_path,
            r#"{
  "dpu_uefi_site_default": {
    "username": "root",
    "password": "json1"
  }
}"#,
        )
        .await
        .expect("write initial json file");

        let provider = FileCredentialsWatcher::new(FileCredentialsConfig {
            path: Some(file_path.clone()),
            poll_interval: Some(Duration::from_secs(1)),
            ..Default::default()
        })
        .await
        .expect("create file provider");

        let key = CredentialKey::DpuUefi {
            credential_type: CredentialType::SiteDefault,
        };

        let first = provider
            .get_credentials(&key)
            .await
            .expect("load first value");
        assert_eq!(
            first,
            Some(Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "json1".to_string(),
            })
        );

        tokio::fs::write(
            &file_path,
            r#"{
  "dpu_uefi_site_default": {
    "username": "root",
    "password": "json2"
  }
}"#,
        )
        .await
        .expect("update json file");
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let second = provider
            .get_credentials(&key)
            .await
            .expect("load reloaded value");
        assert_eq!(
            second,
            Some(Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "json2".to_string(),
            })
        );
    }

    #[tokio::test]
    async fn missing_file_returns_error() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("does-not-exist.yaml");
        let result = FileCredentialsWatcher::new(FileCredentialsConfig {
            path: Some(file_path),
            ..Default::default()
        })
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn loads_yaml_file() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("credentials.yaml");
        tokio::fs::write(
            &file_path,
            r#"dpu_uefi_site_default:
  username: root
  password: yaml1
"#,
        )
        .await
        .expect("write yaml file");

        let provider = FileCredentialsWatcher::new(FileCredentialsConfig {
            path: Some(file_path.clone()),
            poll_interval: Some(Duration::from_secs(1)),
            ..Default::default()
        })
        .await
        .expect("create yaml file provider");

        let key = CredentialKey::DpuUefi {
            credential_type: CredentialType::SiteDefault,
        };

        let value = provider
            .get_credentials(&key)
            .await
            .expect("load yaml value");
        assert_eq!(
            value,
            Some(Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "yaml1".to_string(),
            })
        );
    }

    #[tokio::test]
    async fn loads_machine_identity_encryption_keys_yaml_format() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("credentials.yaml");
        tokio::fs::write(
            &file_path,
            r#"machine_identity:
  encryption_keys:
    v1: secret-1
    v2: secret-2
"#,
        )
        .await
        .expect("write yaml file");

        let provider = FileCredentialsWatcher::new(FileCredentialsConfig {
            path: Some(file_path),
            poll_interval: Some(Duration::from_secs(1)),
            ..Default::default()
        })
        .await
        .expect("create file provider");

        let v1 = CredentialKey::MachineIdentityEncryptionKey {
            key_id: "v1".to_string(),
        };
        let v2 = CredentialKey::MachineIdentityEncryptionKey {
            key_id: "v2".to_string(),
        };

        let value_v1 = provider.get_credentials(&v1).await.expect("load v1");
        let value_v2 = provider.get_credentials(&v2).await.expect("load v2");

        assert_eq!(
            value_v1,
            Some(Credentials::UsernamePassword {
                username: "v1".to_string(),
                password: "secret-1".to_string(),
            })
        );
        assert_eq!(
            value_v2,
            Some(Credentials::UsernamePassword {
                username: "v2".to_string(),
                password: "secret-2".to_string(),
            })
        );
    }
}
