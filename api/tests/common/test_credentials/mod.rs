/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashMap;

use async_trait::async_trait;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, Credentials};
use tokio::sync::Mutex;

#[derive(Debug, Default)]
pub struct TestCredentialProvider {
    credentials: Mutex<HashMap<String, Credentials>>,
}

impl TestCredentialProvider {
    pub fn new() -> Self {
        Self {
            credentials: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl CredentialProvider for TestCredentialProvider {
    async fn get_credentials(&self, key: CredentialKey) -> Result<Credentials, eyre::Report> {
        let credentials = self.credentials.lock().await;
        let cred = credentials
            .get(key.to_key_str().as_str())
            .ok_or_else(|| eyre::eyre!("missing key in test credentials provider"))?;

        Ok(cred.clone())
    }

    async fn set_credentials(
        &self,
        key: CredentialKey,
        credentials: Credentials,
    ) -> Result<(), eyre::Report> {
        let mut data = self.credentials.lock().await;
        let _ = data.insert(key.to_key_str(), credentials);

        Ok(())
    }
}
