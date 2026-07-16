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
use std::sync::atomic;
use std::sync::atomic::AtomicU32;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::credentials::{CredentialKey, Credentials};
use crate::{CredentialManager, CredentialReader, CredentialWriter, SecretsError};

#[derive(Default)]
pub struct TestCredentialManager {
    credentials: Mutex<HashMap<String, Credentials>>,
    fallback_credentials: Option<Credentials>,
    pub set_credentials_sleep_time_ms: AtomicU32,
}

impl TestCredentialManager {
    /// Construct a TestCredentialManager which falls back on a default set of credentials if we
    /// can't find matching ones set via set_credentials()
    pub fn new(fallback_credentials: Credentials) -> Self {
        Self {
            credentials: Mutex::new(HashMap::new()),
            fallback_credentials: Some(fallback_credentials),
            set_credentials_sleep_time_ms: Default::default(),
        }
    }
}

#[async_trait]
impl CredentialReader for TestCredentialManager {
    async fn get_credentials(
        &self,
        key: &CredentialKey,
    ) -> Result<Option<Credentials>, SecretsError> {
        let credentials = self.credentials.lock().await;
        let cred = credentials
            .get(key.to_key_str().as_ref())
            .or(self.fallback_credentials.as_ref());

        Ok(cred.cloned())
    }
}

#[async_trait]
impl CredentialWriter for TestCredentialManager {
    async fn set_credentials(
        &self,
        key: &CredentialKey,
        credentials: &Credentials,
    ) -> Result<(), SecretsError> {
        let sleep_ms = self
            .set_credentials_sleep_time_ms
            .load(atomic::Ordering::Acquire);
        if sleep_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(sleep_ms as _)).await;
        }
        let mut data = self.credentials.lock().await;
        data.insert(key.to_key_str().to_string(), credentials.clone());
        Ok(())
    }

    async fn create_credentials(
        &self,
        key: &CredentialKey,
        credentials: &Credentials,
    ) -> Result<(), SecretsError> {
        let sleep_ms = self
            .set_credentials_sleep_time_ms
            .load(atomic::Ordering::Acquire);
        if sleep_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(sleep_ms as _)).await;
        }
        let mut data = self.credentials.lock().await;
        let key_str = key.to_key_str();
        if data.contains_key(key_str.as_ref()) {
            return Err(SecretsError::GenericError(eyre::eyre!(
                "secret already exists with key {key_str}"
            )));
        }

        data.insert(key_str.to_string(), credentials.clone());
        Ok(())
    }

    async fn delete_credentials(&self, key: &CredentialKey) -> Result<(), SecretsError> {
        let mut data = self.credentials.lock().await;
        let _ = data.remove(key.to_key_str().as_ref());

        Ok(())
    }
}

impl CredentialManager for TestCredentialManager {}
