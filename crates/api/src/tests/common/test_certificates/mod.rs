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
use forge_secrets::SecretsError;
use forge_secrets::certificates::{Certificate, CertificateProvider};
use tokio::sync::Mutex;

#[derive(Debug, Default)]
pub struct TestCertificateProvider {
    pub certificates: Mutex<HashMap<String, Certificate>>,
}

impl TestCertificateProvider {
    pub fn new() -> Self {
        Self {
            certificates: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl CertificateProvider for TestCertificateProvider {
    async fn get_certificate(
        &self,
        unique_identifier: &str,
        _alt_names: Option<String>,
        _ttl: Option<String>,
    ) -> Result<Certificate, SecretsError> {
        let mut certificates = self.certificates.lock().await;
        let certificate = certificates
            .entry(unique_identifier.to_string())
            .or_insert(Certificate::default());

        Ok(certificate.clone())
    }
}
